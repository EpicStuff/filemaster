package fileaccess

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"
)

const (
	defaultRuleRetryMin   = 100 * time.Millisecond
	defaultRuleRetryMax   = 5 * time.Second
	defaultRuleWorkerIdle = 30 * time.Second
)

// RulePersistenceOptions makes retry timing deterministic for focused tests.
// It intentionally has no relationship to the droppable observation queue.
type RulePersistenceOptions struct {
	MinBackoff time.Duration
	MaxBackoff time.Duration
	After      func(time.Duration) <-chan time.Time
	// WorkerIdle bounds how long an idle per-profile writer stays resident.
	// It is injectable so focused tests do not need wall-clock delays.
	WorkerIdle time.Duration
}

// RulePersistenceDiagnostics exposes durable-rule health without making
// decision workers wait for storage I/O.
type RulePersistenceDiagnostics struct {
	DirtyCount        int
	Generation        uint64
	DirtyGenerations  []uint64
	RetryCount        uint64
	PersistentFailure bool
	LastError         error
}

type permanentRule struct {
	pattern    string
	verdict    Verdict
	operation  FileOp
	kind       ObjectKind
	entry      string
	generation uint64
}

// key identifies a permanent rule within its operation list: two rules with the
// same operation, object kind and path are the same learned rule. The
// operation is part of the key so an equivalent path learned for a different
// operation is tracked and deduplicated independently, never suppressing an
// equivalent rule belonging to another operation.
func (r permanentRule) key() string {
	return fmt.Sprintf("%d:%d:%s", r.operation, r.kind, r.pattern)
}

// overlayIdentity identifies a learned exact rule within a single operation
// list. The operation is not part of the identity: each operation's list is
// merged separately, so the identity only needs to distinguish rules inside one
// list.
type overlayIdentity struct {
	pattern string
	kind    ObjectKind
}

type dirtyRuleProfile struct {
	generation uint64
	dirty      map[string]permanentRule
	applied    map[string]permanentRule // writes known to have succeeded

	base           *DecisionSnapshot
	published      *DecisionSnapshot
	publishedBase  *DecisionSnapshot
	publishedEpoch uint64
	publishedRev   uint64
	policyEpoch    uint64

	wake    chan struct{}
	started bool
	retries uint64
	lastErr error
	failure bool
}

type ruleStoreBinding struct {
	store      RuleStore
	generation uint64
}

// RulePersistence owns the durable, per-profile permanent-rule overlay. Its
// mutex protects bookkeeping only: storage and observers always run unlocked.
type RulePersistence struct {
	mu        sync.Mutex
	profiles  map[string]*dirtyRuleProfile
	bindings  map[string]ruleStoreBinding
	observe   func(*DecisionSnapshot)
	min       time.Duration
	max       time.Duration
	after     func(time.Duration) <-chan time.Time
	idle      time.Duration
	lifecycle *PipelineLifecycle
	workers   sync.WaitGroup
	stop      chan struct{}
	stopOnce  sync.Once
	stopped   bool
}

func NewRulePersistence(observe func(*DecisionSnapshot), options RulePersistenceOptions) *RulePersistence {
	return newRulePersistence(observe, options, NewPipelineLifecycle())
}

func newRulePersistence(observe func(*DecisionSnapshot), options RulePersistenceOptions, lifecycle *PipelineLifecycle) *RulePersistence {
	if options.MinBackoff <= 0 {
		options.MinBackoff = defaultRuleRetryMin
	}
	if options.MaxBackoff < options.MinBackoff {
		options.MaxBackoff = defaultRuleRetryMax
		if options.MaxBackoff < options.MinBackoff {
			options.MaxBackoff = options.MinBackoff
		}
	}
	if options.After == nil {
		options.After = time.After
	}
	if options.WorkerIdle <= 0 {
		options.WorkerIdle = defaultRuleWorkerIdle
	}
	if lifecycle == nil {
		lifecycle = NewPipelineLifecycle()
	}
	return &RulePersistence{
		profiles:  make(map[string]*dirtyRuleProfile),
		bindings:  make(map[string]ruleStoreBinding),
		observe:   observe,
		min:       options.MinBackoff,
		max:       options.MaxBackoff,
		after:     options.After,
		idle:      options.WorkerIdle,
		lifecycle: lifecycle,
		stop:      make(chan struct{}),
	}
}

func profileSnapshotKey(snapshot *DecisionSnapshot) string {
	if snapshot == nil {
		return ""
	}
	return snapshot.Source + "/" + snapshot.ProfileID
}

func canonicalPermanentRule(pattern string, operation FileOp, _ bool, verdict Verdict) (permanentRule, bool) {
	pattern = filepath.Clean(pattern)
	if pattern == "." || !filepath.IsAbs(pattern) || (verdict != VerdictAllow && verdict != VerdictDeny) {
		return permanentRule{}, false
	}
	return permanentRule{
		pattern:   pattern,
		verdict:   verdict,
		operation: operation,
		kind:      ObjectKindAny,
		entry:     FormatLiteralRule(pattern, verdict),
	}, true
}

// Bind attaches the current writable profile object without changing any dirty
// generation. A rebinding waits for an old storage call to finish, so every
// later retry uses the replacement profile object.
func (p *RulePersistence) Bind(snapshot *DecisionSnapshot, store RuleStore) {
	if snapshot == nil || store == nil {
		return
	}
	p.BindStore(snapshot.Source, snapshot.ProfileID, store)
}

// BindStore updates an existing profile's current writer before a reload
// snapshot is constructed. It intentionally does not create overlay state for
// clean profiles.
func (p *RulePersistence) BindStore(source, profileID string, store RuleStore) {
	if store == nil {
		return
	}
	if p.lifecycle != nil {
		p.lifecycle.whileRunning(func() { p.bindStoreRunning(source, profileID, store) })
		return
	}
	p.bindStoreRunning(source, profileID, store)
}

func (p *RulePersistence) bindStoreRunning(source, profileID string, store RuleStore) {
	var wake chan struct{}
	p.mu.Lock()
	key := source + "/" + profileID
	binding := p.bindings[key]
	if !sameRuleStore(binding.store, store) {
		binding.store = store
		binding.generation++
		p.bindings[key] = binding
	}
	state := p.profiles[key]
	if state != nil && len(state.dirty) != 0 {
		wake = state.wake
	}
	p.mu.Unlock()
	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

// ensureStoreRunning captures the prompt's store only when no authoritative
// binding is known yet. It is called inside the shared lifecycle activity
// barrier, so a prompt accepted before Closing has a stable store for the final
// flush without allowing an older prompt to replace a newer binding.
func (p *RulePersistence) ensureStoreRunning(source, profileID string, store RuleStore) {
	if store == nil {
		return
	}
	p.mu.Lock()
	key := source + "/" + profileID
	if p.bindings[key].store == nil {
		p.bindings[key] = ruleStoreBinding{store: store, generation: 1}
	}
	p.mu.Unlock()
}

type ruleStoreIdentity interface{ ruleStoreIdentity() any }

type guardedRuleStore interface {
	AppendRuleIfCurrent(FileOp, string, func() bool) error
}

func sameRuleStore(left, right RuleStore) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftIdentity, leftOK := left.(ruleStoreIdentity)
	rightIdentity, rightOK := right.(ruleStoreIdentity)
	if leftOK && rightOK {
		leftValue := reflect.ValueOf(leftIdentity.ruleStoreIdentity())
		rightValue := reflect.ValueOf(rightIdentity.ruleStoreIdentity())
		return leftValue.IsValid() && rightValue.IsValid() && leftValue.Type() == rightValue.Type() && leftValue.Type().Comparable() && leftValue.Interface() == rightValue.Interface()
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	return leftValue.Type() == rightValue.Type() && leftValue.Type().Comparable() && leftValue.Interface() == rightValue.Interface()
}

// Apply makes an accepted Always decision visible before storage is attempted.
// The returned snapshot is immutable and any observer runs after unlocking. It
// is the open (Access) convenience for callers that do not carry an operation;
// the rule lands in the Access/Read list.
func (p *RulePersistence) Apply(snapshot *DecisionSnapshot, store RuleStore, pattern string, verdict Verdict) *DecisionSnapshot {
	merged := snapshot
	notify := false
	if !p.lifecycle.whileRunning(func() {
		merged, notify = p.apply(snapshot, store, pattern, OpOpen, false, verdict, true)
	}) {
		return merged
	}
	if notify && p.observe != nil {
		p.observe(merged)
	}
	return merged
}

// ApplyAccepted completes an Always action which won prompt ownership before
// Closing. Prompt shutdown waits for this call before starting the final flush.
func (p *RulePersistence) ApplyAccepted(snapshot *DecisionSnapshot, store RuleStore, pattern string, verdict Verdict) *DecisionSnapshot {
	merged, notify := p.apply(snapshot, store, pattern, OpOpen, false, verdict, false)
	if notify && p.observe != nil {
		p.observe(merged)
	}
	return merged
}

// ApplyAcceptedEvent persists an accepted Always decision into exactly one
// operation's list.
func (p *RulePersistence) ApplyAcceptedEvent(snapshot *DecisionSnapshot, store RuleStore, pattern string, operation FileOp, directory bool, verdict Verdict) *DecisionSnapshot {
	merged, notify := p.apply(snapshot, store, pattern, operation, directory, verdict, false)
	if notify && p.observe != nil {
		p.observe(merged)
	}
	return merged
}

func (p *RulePersistence) ApplyEvent(snapshot *DecisionSnapshot, store RuleStore, pattern string, operation FileOp, directory bool, verdict Verdict) *DecisionSnapshot {
	merged := snapshot
	notify := false
	if !p.lifecycle.whileRunning(func() {
		merged, notify = p.apply(snapshot, store, pattern, operation, directory, verdict, true)
	}) {
		return merged
	}
	if notify && p.observe != nil {
		p.observe(merged)
	}
	return merged
}

func (p *RulePersistence) apply(snapshot *DecisionSnapshot, store RuleStore, pattern string, operation FileOp, directory bool, verdict Verdict, allowBinding bool) (*DecisionSnapshot, bool) {
	// Route the operation to its governing list up front and fail closed on an
	// unsupported one, so an unroutable rule never enters the overlay (where it
	// would otherwise land in the read list and then loop forever in dirty
	// retries because storage rejects it). Opens fold to the read list.
	operation, ok := fileAccessListOp(operation)
	if !ok {
		return snapshot, false
	}
	rule, ok := canonicalPermanentRule(pattern, operation, directory, verdict)
	if !ok || snapshot == nil || store == nil {
		return snapshot, false
	}
	key := profileSnapshotKey(snapshot)
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return snapshot, false
	}
	state := p.profileLocked(key)
	base := state.baseForLocked(snapshot)
	if allowBinding && p.bindings[key].store == nil {
		p.bindings[key] = ruleStoreBinding{store: store, generation: 1}
	}
	if current, exists := state.dirty[rule.key()]; exists && current.verdict == rule.verdict {
		merged := state.publishLocked(base)
		p.mu.Unlock()
		return merged, false
	}
	if current, exists := state.applied[rule.key()]; exists && current.verdict == rule.verdict {
		merged := state.publishLocked(base)
		p.mu.Unlock()
		return merged, false
	}
	if len(state.dirty) == 0 && len(state.applied) == 0 && durableRuleAtPrecedence(base, rule) {
		p.mu.Unlock()
		return base, false
	}
	state.generation++
	rule.generation = state.generation
	state.dirty[rule.key()] = rule
	delete(state.applied, rule.key())
	state.policyEpoch++
	merged := state.publishLocked(base)
	start := !state.started
	if start {
		state.started = true
		// Register before releasing p.mu so Stop cannot begin Wait while an
		// accepted Apply is between deciding to start and launching its worker.
		p.workers.Add(1)
	}
	wake := state.wake
	p.mu.Unlock()
	if start {
		go p.runProfile(key, state)
	}
	select {
	case wake <- struct{}{}:
	default:
	}
	return merged, true
}

// Merge reapplies local dirty intent to a replacement profile snapshot. Dirty
// entries never become durable merely because an unsaved in-memory profile
// happened to expose the same rule; only an AppendRule success moves them out
// of dirty state.
func (p *RulePersistence) Merge(snapshot *DecisionSnapshot) *DecisionSnapshot {
	if snapshot == nil {
		return nil
	}
	p.mu.Lock()
	state := p.profiles[profileSnapshotKey(snapshot)]
	if state == nil {
		p.mu.Unlock()
		return snapshot
	}
	previousBase := state.base
	base := state.baseForLocked(snapshot)
	// Revisions are monotonic publication tokens, but callers may legitimately
	// present a replacement snapshot with the same revision. Treat equal
	// revisions as unchanged only when their complete decision content matches;
	// otherwise the replacement is authoritative for clean/applied policy.
	advancedBase := previousBase != nil && base != previousBase &&
		(base.Revision > previousBase.Revision ||
			(base.Revision == previousBase.Revision && !sameDecisionSnapshotPolicy(base, previousBase)))
	for pattern, rule := range state.applied {
		if durableRuleAtPrecedence(base, rule) {
			delete(state.applied, pattern)
			state.policyEpoch++
			continue
		}
		// A newer durable profile revision deliberately removed or replaced an
		// already-persisted Always rule. Applied overlays are confirmations, not
		// permanent policy, so do not silently restore the old rule.
		if advancedBase {
			delete(state.applied, pattern)
			state.policyEpoch++
		}
	}
	merged := state.publishLocked(base)
	p.mu.Unlock()
	return merged
}

func sameDecisionSnapshotPolicy(left, right *DecisionSnapshot) bool {
	if left == nil || right == nil {
		return left == right
	}
	if left.ProfileID != right.ProfileID || left.Source != right.Source || left.DefaultAction != right.DefaultAction {
		return false
	}
	return samePathRulesPolicy(left.Read, right.Read) &&
		samePathRulesPolicy(left.Write, right.Write) &&
		samePathRulesPolicy(left.Exec, right.Exec)
}

func samePathRulesPolicy(left, right PathRules) bool {
	if left.Default != right.Default || len(left.Rules) != len(right.Rules) {
		return false
	}
	for i, rule := range left.Rules {
		other := right.Rules[i]
		if rule.Pattern != other.Pattern || rule.Verdict != other.Verdict || rule.ObjectKind != other.ObjectKind {
			return false
		}
	}
	return true
}

func (p *RulePersistence) profileLocked(key string) *dirtyRuleProfile {
	state := p.profiles[key]
	if state != nil {
		return state
	}
	state = &dirtyRuleProfile{
		dirty:   make(map[string]permanentRule),
		applied: make(map[string]permanentRule),
		wake:    make(chan struct{}, 1),
	}
	p.profiles[key] = state
	return state
}

func (state *dirtyRuleProfile) baseForLocked(snapshot *DecisionSnapshot) *DecisionSnapshot {
	if snapshot == state.published && state.base != nil {
		return state.base
	}
	state.base = snapshot
	return snapshot
}

// durableRuleAtPrecedence confirms that the profile itself currently
// decides the canonical path with this canonical rule. Merely
// finding a matching rule below an opposite or broader first match is not
// durable confirmation.
func durableRuleAtPrecedence(snapshot *DecisionSnapshot, rule permanentRule) bool {
	if snapshot == nil {
		return false
	}
	rules, ok := snapshot.rulesFor(rule.operation)
	if !ok {
		return false
	}
	for _, existing := range rules.Rules {
		if !existing.Matches(rule.pattern) {
			continue
		}
		return existing.Pattern == escapePathPattern(rule.pattern) && existing.Verdict == rule.verdict && existing.ObjectKind == rule.kind
	}
	return false
}

func (state *dirtyRuleProfile) publishLocked(base *DecisionSnapshot) *DecisionSnapshot {
	if state.published != nil && state.publishedBase == base && state.publishedEpoch == state.policyEpoch {
		return state.published
	}
	rules := make([]permanentRule, 0, len(state.dirty)+len(state.applied))
	for _, rule := range state.dirty {
		rules = append(rules, rule)
	}
	for _, rule := range state.applied {
		rules = append(rules, rule)
	}
	// Newest-first: a later learned rule outranks an older one for the same path.
	sort.Slice(rules, func(i, j int) bool { return rules[i].generation > rules[j].generation })
	// Route each learned rule to its operation's overlay so it merges into that
	// list only, never suppressing an equivalent rule in another operation. Rules
	// with an unroutable operation are skipped defensively; apply rejects them
	// before they ever reach the overlay.
	var read, write, exec []permanentRule
	for _, rule := range rules {
		listOp, ok := fileAccessListOp(rule.operation)
		if !ok {
			continue
		}
		switch listOp {
		case OpWrite:
			write = append(write, rule)
		case OpExec:
			exec = append(exec, rule)
		default:
			read = append(read, rule)
		}
	}
	if state.publishedRev < base.Revision {
		state.publishedRev = base.Revision
	}
	state.publishedRev++
	state.published = &DecisionSnapshot{
		ProfileID:     base.ProfileID,
		Source:        base.Source,
		DefaultAction: base.DefaultAction,
		Read:          mergeOverlayList(base.Read, read),
		Write:         mergeOverlayList(base.Write, write),
		Exec:          mergeOverlayList(base.Exec, exec),
		Revision:      state.publishedRev,
	}
	state.publishedEpoch = state.policyEpoch
	state.publishedBase = base
	return state.published
}

// mergeOverlayList prepends one operation's learned rules (already sorted
// newest-first) onto that operation's base list, dropping any base rule an
// overlay rule supersedes (same path and object kind). The operation is
// implied by the list, so it is not part of the identity here.
func mergeOverlayList(base PathRules, overlayRules []permanentRule) PathRules {
	merged := make([]PathRule, 0, len(base.Rules)+len(overlayRules))
	covered := make(map[overlayIdentity]struct{}, len(overlayRules))
	for _, rule := range overlayRules {
		pattern := escapePathPattern(rule.pattern)
		merged = append(merged, PathRule{Pattern: pattern, Verdict: rule.verdict, ObjectKind: rule.kind})
		covered[overlayIdentity{pattern: pattern, kind: rule.kind}] = struct{}{}
	}
	for _, rule := range base.Rules {
		if _, ok := covered[overlayIdentity{pattern: rule.Pattern, kind: rule.ObjectKind}]; ok {
			continue
		}
		merged = append(merged, rule)
	}
	return PathRules{Rules: merged, Default: base.Default}
}

func (p *RulePersistence) runProfile(key string, state *dirtyRuleProfile) {
	defer p.workers.Done()
	for {
		select {
		case <-p.stop:
			return
		case <-state.wake:
		}
		for {
			select {
			case <-p.stop:
				return
			default:
			}
			rule, binding, ok := p.nextRule(key, state)
			if !ok {
				break
			}
			var err error
			if guarded, ok := binding.store.(guardedRuleStore); ok {
				err = guarded.AppendRuleIfCurrent(rule.operation, rule.entry, func() bool {
					return p.bindingCurrent(key, binding.generation, binding.store)
				})
			} else {
				err = binding.store.AppendRule(rule.operation, rule.entry)
			}
			if err == nil {
				p.persisted(key, state, rule, binding.generation)
				continue
			}
			if p.failed(key, state, rule, binding.generation, err) {
				select {
				case <-p.stop:
					return
				case <-p.after(p.backoff(state)):
				}
			}
		}

		idle := time.NewTimer(p.idle)
		select {
		case <-p.stop:
			if !idle.Stop() {
				<-idle.C
			}
			return
		case <-state.wake:
			if !idle.Stop() {
				<-idle.C
			}
			continue
		case <-idle.C:
		}
		p.mu.Lock()
		if p.profiles[key] == state && len(state.dirty) == 0 {
			state.started = false
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
	}
}

func (p *RulePersistence) bindingCurrent(key string, generation uint64, store RuleStore) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	binding := p.bindings[key]
	return binding.generation == generation && sameRuleStore(binding.store, store)
}

func (p *RulePersistence) nextRule(key string, expected *dirtyRuleProfile) (permanentRule, ruleStoreBinding, bool) {
	p.mu.Lock()
	state := p.profiles[key]
	binding := p.bindings[key]
	if state != expected || state == nil || binding.store == nil || len(state.dirty) == 0 {
		p.mu.Unlock()
		return permanentRule{}, ruleStoreBinding{}, false
	}
	var selected permanentRule
	for _, rule := range state.dirty {
		if selected.generation == 0 || rule.generation < selected.generation {
			selected = rule
		}
	}
	p.mu.Unlock()
	return selected, binding, true
}

func (p *RulePersistence) persisted(key string, expected *dirtyRuleProfile, rule permanentRule, bindingGeneration uint64) {
	p.mu.Lock()
	state := p.profiles[key]
	binding := p.bindings[key]
	if state != expected || state == nil || binding.generation != bindingGeneration {
		var wake chan struct{}
		if state == expected && state != nil && len(state.dirty) != 0 {
			wake = state.wake
		}
		p.mu.Unlock()
		if wake != nil {
			select {
			case wake <- struct{}{}:
			default:
			}
		}
		return
	}
	if current, ok := state.dirty[rule.key()]; ok && current.generation == rule.generation {
		delete(state.dirty, rule.key())
		state.applied[rule.key()] = rule
		// A successful write changes the durable base even before the next
		// profile reload. Retaining that canonical fact lets Merge distinguish an
		// equal-revision, content-identical reload from one that removed or
		// changed this accepted exact rule.
		state.base = snapshotWithDurableRule(state.base, rule)
		state.policyEpoch++
	}
	if len(state.dirty) == 0 {
		state.failure = false
		state.lastErr = nil
	}
	p.mu.Unlock()
}

func snapshotWithDurableRule(base *DecisionSnapshot, rule permanentRule) *DecisionSnapshot {
	if base == nil {
		return nil
	}
	listOp, ok := fileAccessListOp(rule.operation)
	if !ok {
		return base
	}
	updated := *base
	switch listOp {
	case OpWrite:
		updated.Write = pathRulesWithDurableRule(base.Write, rule)
	case OpExec:
		updated.Exec = pathRulesWithDurableRule(base.Exec, rule)
	default:
		updated.Read = pathRulesWithDurableRule(base.Read, rule)
	}
	return &updated
}

// pathRulesWithDurableRule prepends the durable-base marker for a persisted
// rule to its operation's list, replacing any equivalent existing
// rule (same path and object kind).
func pathRulesWithDurableRule(list PathRules, rule permanentRule) PathRules {
	rules := make([]PathRule, 0, len(list.Rules)+1)
	rules = append(rules, PathRule{Pattern: rule.pattern, Verdict: rule.verdict, ObjectKind: rule.kind})
	for _, existing := range list.Rules {
		if existing.Pattern == rule.pattern && existing.ObjectKind == rule.kind {
			continue
		}
		rules = append(rules, existing)
	}
	return PathRules{Rules: rules, Default: list.Default}
}

func (p *RulePersistence) failed(key string, expected *dirtyRuleProfile, rule permanentRule, bindingGeneration uint64, err error) bool {
	p.mu.Lock()
	state := p.profiles[key]
	binding := p.bindings[key]
	if state != expected || state == nil || binding.generation != bindingGeneration {
		p.mu.Unlock()
		return false
	}
	if current, ok := state.dirty[rule.key()]; ok && current.generation == rule.generation {
		state.retries++
		state.lastErr = err
		state.failure = true
		p.mu.Unlock()
		return true
	}
	p.mu.Unlock()
	return false
}

func (p *RulePersistence) backoff(state *dirtyRuleProfile) time.Duration {
	p.mu.Lock()
	retries := state.retries
	p.mu.Unlock()
	delay := p.min
	for retries > 1 && delay < p.max {
		delay *= 2
		retries--
	}
	if delay > p.max {
		return p.max
	}
	return delay
}

func (p *RulePersistence) Diagnostics() map[string]RulePersistenceDiagnostics {
	p.mu.Lock()
	defer p.mu.Unlock()
	diagnostics := make(map[string]RulePersistenceDiagnostics, len(p.profiles))
	for key, state := range p.profiles {
		dirtyGenerations := make([]uint64, 0, len(state.dirty))
		for _, rule := range state.dirty {
			dirtyGenerations = append(dirtyGenerations, rule.generation)
		}
		sort.Slice(dirtyGenerations, func(i, j int) bool { return dirtyGenerations[i] < dirtyGenerations[j] })
		diagnostics[key] = RulePersistenceDiagnostics{
			DirtyCount:        len(state.dirty),
			Generation:        state.generation,
			DirtyGenerations:  dirtyGenerations,
			RetryCount:        state.retries,
			PersistentFailure: state.failure,
			LastError:         state.lastErr,
		}
	}
	return diagnostics
}

// Flush requests durable writes and waits only until the supplied context
// expires. It deliberately does not change prompt or pipeline closing state.
func (p *RulePersistence) Flush(ctx context.Context) error {
	for {
		p.mu.Lock()
		remaining := make([]string, 0)
		wakes := make([]chan struct{}, 0)
		for key, state := range p.profiles {
			if len(state.dirty) != 0 {
				remaining = append(remaining, key)
				wakes = append(wakes, state.wake)
			}
		}
		p.mu.Unlock()
		if len(remaining) == 0 {
			return nil
		}
		for _, wake := range wakes {
			select {
			case wake <- struct{}{}:
			default:
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("permanent rule flush left %d dirty profiles: %v: %w", len(remaining), remaining, ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// StopAdmission rejects future persistence requests and signals every writer
// to exit once any in-progress store call returns. It does not discard dirty
// state and intentionally does not wait under p.mu.
func (p *RulePersistence) StopAdmission() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return
	}
	p.stopped = true
	p.stopOnce.Do(func() { close(p.stop) })
}

// WaitWorkers joins every per-profile writer. Store calls are not
// cancellable, so this is deliberately independent of a bounded flush/report
// context: final lifecycle closure must wait for real worker exit.
func (p *RulePersistence) WaitWorkers() {
	p.workers.Wait()
}

// Stop preserves the standalone convenience contract: flush with ctx, reject
// new work, then join workers even if the bounded flush deadline expired.
func (p *RulePersistence) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	flushErr := p.Flush(ctx)
	p.StopAdmission()
	p.WaitWorkers()
	return flushErr
}
