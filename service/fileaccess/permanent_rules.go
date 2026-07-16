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
	defaultRuleRetryMin = 100 * time.Millisecond
	defaultRuleRetryMax = 5 * time.Second
)

// RulePersistenceOptions makes retry timing deterministic for focused tests.
// It intentionally has no relationship to the droppable observation queue.
type RulePersistenceOptions struct {
	MinBackoff time.Duration
	MaxBackoff time.Duration
	After      func(time.Duration) <-chan time.Time
}

// RulePersistenceDiagnostics exposes durable-rule health without making
// decision workers wait for storage I/O.
type RulePersistenceDiagnostics struct {
	DirtyCount        int
	RetryCount        uint64
	PersistentFailure bool
	LastError         error
}

type permanentRule struct {
	pattern    string
	verdict    Verdict
	entry      string
	generation uint64
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
	mu       sync.Mutex
	profiles map[string]*dirtyRuleProfile
	bindings map[string]ruleStoreBinding
	observe  func(*DecisionSnapshot)
	min      time.Duration
	max      time.Duration
	after    func(time.Duration) <-chan time.Time
}

func NewRulePersistence(observe func(*DecisionSnapshot), options RulePersistenceOptions) *RulePersistence {
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
	return &RulePersistence{
		profiles: make(map[string]*dirtyRuleProfile),
		bindings: make(map[string]ruleStoreBinding),
		observe:  observe,
		min:      options.MinBackoff,
		max:      options.MaxBackoff,
		after:    options.After,
	}
}

func profileSnapshotKey(snapshot *DecisionSnapshot) string {
	if snapshot == nil {
		return ""
	}
	return snapshot.Source + "/" + snapshot.ProfileID
}

func canonicalPermanentRule(pattern string, verdict Verdict) (permanentRule, bool) {
	pattern = filepath.Clean(pattern)
	if pattern == "." || !filepath.IsAbs(pattern) || (verdict != VerdictAllow && verdict != VerdictDeny) {
		return permanentRule{}, false
	}
	return permanentRule{pattern: pattern, verdict: verdict, entry: FormatExactRule(pattern, verdict)}, true
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
	var wake chan struct{}
	bind := func() {
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
	}
	if synchronized, ok := store.(bindingSynchronizedRuleStore); ok {
		synchronized.SynchronizeBinding(bind)
	} else {
		bind()
	}
	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

type ruleStoreIdentity interface{ ruleStoreIdentity() any }

type guardedRuleStore interface {
	AppendRuleIfCurrent(string, func() bool) error
}

type bindingSynchronizedRuleStore interface {
	SynchronizeBinding(func())
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
// The returned snapshot is immutable and any observer runs after unlocking.
func (p *RulePersistence) Apply(snapshot *DecisionSnapshot, store RuleStore, pattern string, verdict Verdict) *DecisionSnapshot {
	rule, ok := canonicalPermanentRule(pattern, verdict)
	if !ok || snapshot == nil || store == nil {
		return snapshot
	}
	key := profileSnapshotKey(snapshot)
	p.mu.Lock()
	state := p.profileLocked(key)
	base := state.baseForLocked(snapshot)
	if p.bindings[key].store == nil {
		p.bindings[key] = ruleStoreBinding{store: store, generation: 1}
	}
	if current, exists := state.dirty[rule.pattern]; exists && current.verdict == rule.verdict {
		merged := state.publishLocked(base)
		p.mu.Unlock()
		return merged
	}
	if current, exists := state.applied[rule.pattern]; exists && current.verdict == rule.verdict {
		merged := state.publishLocked(base)
		p.mu.Unlock()
		return merged
	}
	if len(state.dirty) == 0 && len(state.applied) == 0 && durableExactRuleAtPrecedence(base, rule) {
		p.mu.Unlock()
		return base
	}
	state.generation++
	rule.generation = state.generation
	state.dirty[rule.pattern] = rule
	delete(state.applied, rule.pattern)
	state.policyEpoch++
	merged := state.publishLocked(base)
	start := !state.started
	if start {
		state.started = true
	}
	wake := state.wake
	p.mu.Unlock()
	if p.observe != nil {
		p.observe(merged)
	}
	if start {
		go p.runProfile(key, state)
	}
	select {
	case wake <- struct{}{}:
	default:
	}
	return merged
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
	base := state.baseForLocked(snapshot)
	for pattern, rule := range state.applied {
		if durableExactRuleAtPrecedence(base, rule) {
			delete(state.applied, pattern)
			state.policyEpoch++
		}
	}
	merged := state.publishLocked(base)
	p.mu.Unlock()
	return merged
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

// durableExactRuleAtPrecedence confirms that the profile itself currently
// decides the exact canonical path with this exact canonical rule. Merely
// finding a matching rule below an opposite or broader first match is not
// durable confirmation.
func durableExactRuleAtPrecedence(snapshot *DecisionSnapshot, rule permanentRule) bool {
	if snapshot == nil {
		return false
	}
	for _, existing := range snapshot.Rules.Rules {
		if !existing.Matches(rule.pattern) {
			continue
		}
		return existing.Exact && existing.Pattern == rule.pattern && existing.Verdict == rule.verdict
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
	sort.Slice(rules, func(i, j int) bool { return rules[i].generation > rules[j].generation })
	type overlayIdentity struct {
		pattern string
		exact   bool
	}
	overlay := make(map[overlayIdentity]permanentRule, len(rules))
	for _, rule := range rules {
		overlay[overlayIdentity{pattern: rule.pattern, exact: true}] = rule
	}
	mergedRules := make([]PathRule, 0, len(base.Rules.Rules)+len(rules))
	for _, rule := range rules {
		mergedRules = append(mergedRules, PathRule{Pattern: rule.pattern, Verdict: rule.verdict, Exact: true})
	}
	for _, rule := range base.Rules.Rules {
		if _, covered := overlay[overlayIdentity{pattern: rule.Pattern, exact: rule.Exact}]; !covered {
			mergedRules = append(mergedRules, rule)
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
		Rules:         PathRules{Rules: mergedRules, Default: base.Rules.Default},
		Revision:      state.publishedRev,
	}
	state.publishedEpoch = state.policyEpoch
	state.publishedBase = base
	return state.published
}

func (p *RulePersistence) runProfile(key string, state *dirtyRuleProfile) {
	for range state.wake {
		for {
			rule, binding, ok := p.nextRule(key, state)
			if !ok {
				break
			}
			var err error
			if guarded, ok := binding.store.(guardedRuleStore); ok {
				err = guarded.AppendRuleIfCurrent(rule.entry, func() bool {
					return p.bindingCurrent(key, binding.generation, binding.store)
				})
			} else {
				err = binding.store.AppendRule(rule.entry)
			}
			if err == nil {
				p.persisted(key, state, rule, binding.generation)
				continue
			}
			if p.failed(key, state, rule, binding.generation, err) {
				<-p.after(p.backoff(state))
			}
		}
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
	if current, ok := state.dirty[rule.pattern]; ok && current.generation == rule.generation {
		delete(state.dirty, rule.pattern)
		state.applied[rule.pattern] = rule
		state.policyEpoch++
	}
	if len(state.dirty) == 0 {
		state.failure = false
		state.lastErr = nil
	}
	p.mu.Unlock()
}

func (p *RulePersistence) failed(key string, expected *dirtyRuleProfile, rule permanentRule, bindingGeneration uint64, err error) bool {
	p.mu.Lock()
	state := p.profiles[key]
	binding := p.bindings[key]
	if state != expected || state == nil || binding.generation != bindingGeneration {
		p.mu.Unlock()
		return false
	}
	if current, ok := state.dirty[rule.pattern]; ok && current.generation == rule.generation {
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
		diagnostics[key] = RulePersistenceDiagnostics{DirtyCount: len(state.dirty), RetryCount: state.retries, PersistentFailure: state.failure, LastError: state.lastErr}
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
