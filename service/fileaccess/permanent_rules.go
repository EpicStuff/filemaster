package fileaccess

import (
	"context"
	"fmt"
	"path/filepath"
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
	store      RuleStore
	generation uint64
	dirty      map[string]permanentRule
	applied    map[string]permanentRule
	merged     *DecisionSnapshot
	mergedBase uint64
	mergedGen  uint64
	wake       chan struct{}
	started    bool
	retries    uint64
	lastErr    error
	failure    bool
}

// RulePersistence owns the durable, per-profile permanent-rule overlay. Its
// mutex protects only bookkeeping: profile storage and snapshot observers are
// always called after releasing it.
type RulePersistence struct {
	mu       sync.Mutex
	profiles map[string]*dirtyRuleProfile
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
	return permanentRule{pattern: pattern, verdict: verdict, entry: FormatRule(pattern, verdict)}, true
}

// Apply makes an accepted Always decision visible before storage is attempted.
// It returns the newly immutable merged snapshot and notifies observers only
// after all overlay locks have been released.
func (p *RulePersistence) Apply(snapshot *DecisionSnapshot, store RuleStore, pattern string, verdict Verdict) *DecisionSnapshot {
	rule, ok := canonicalPermanentRule(pattern, verdict)
	if !ok || snapshot == nil || store == nil {
		return snapshot
	}
	key := profileSnapshotKey(snapshot)
	p.mu.Lock()
	state := p.profileLocked(key)
	state.store = store
	if current, exists := state.dirty[rule.pattern]; exists && current.verdict == rule.verdict {
		merged := p.mergeLocked(snapshot, state)
		p.mu.Unlock()
		return merged
	}
	if current, exists := state.applied[rule.pattern]; exists && current.verdict == rule.verdict {
		merged := p.mergeLocked(snapshot, state)
		p.mu.Unlock()
		return merged
	}
	if rulePresent(snapshot, rule) && state.dirty[rule.pattern].generation == 0 && state.applied[rule.pattern].generation == 0 {
		p.mu.Unlock()
		return snapshot
	}
	state.generation++
	rule.generation = state.generation
	state.dirty[rule.pattern] = rule
	delete(state.applied, rule.pattern)
	state.merged = nil
	merged := p.mergeLocked(snapshot, state)
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

// Merge reapplies outstanding local intent to a replacement profile snapshot.
// It is used during reload before that snapshot reaches workers or prompts.
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
	merged := p.mergeLocked(snapshot, state)
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

func rulePresent(snapshot *DecisionSnapshot, rule permanentRule) bool {
	for _, existing := range snapshot.Rules.Rules {
		if existing.Pattern == rule.pattern && existing.Verdict == rule.verdict {
			return true
		}
	}
	return false
}

func (p *RulePersistence) mergeLocked(snapshot *DecisionSnapshot, state *dirtyRuleProfile) *DecisionSnapshot {
	// A reload that already contains the canonical local rule is durable
	// confirmation of that intent. Coalesce it instead of publishing or
	// writing a duplicate. A conflicting rule deliberately stays overlaid.
	coalesced := false
	if state.merged != snapshot {
		for pattern, rule := range state.dirty {
			if rulePresent(snapshot, rule) {
				delete(state.dirty, pattern)
				coalesced = true
			}
		}
		for pattern, rule := range state.applied {
			if rulePresent(snapshot, rule) {
				delete(state.applied, pattern)
				coalesced = true
			}
		}
	}
	if coalesced {
		state.merged = nil
		if len(state.dirty) == 0 {
			state.failure = false
			state.lastErr = nil
		}
	}
	if len(state.dirty) == 0 && len(state.applied) == 0 {
		return snapshot
	}
	if state.merged != nil && state.mergedBase == snapshot.Revision && state.mergedGen == state.generation {
		return state.merged
	}
	rules := make([]permanentRule, 0, len(state.dirty)+len(state.applied))
	for _, rule := range state.dirty {
		rules = append(rules, rule)
	}
	for _, rule := range state.applied {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].generation > rules[j].generation })
	overlay := make(map[string]permanentRule, len(rules))
	for _, rule := range rules {
		overlay[rule.pattern] = rule
	}
	mergedRules := make([]PathRule, 0, len(snapshot.Rules.Rules)+len(rules))
	for _, rule := range rules {
		mergedRules = append(mergedRules, PathRule{Pattern: rule.pattern, Verdict: rule.verdict})
	}
	for _, rule := range snapshot.Rules.Rules {
		if _, covered := overlay[rule.Pattern]; !covered {
			mergedRules = append(mergedRules, rule)
		}
	}
	state.merged = &DecisionSnapshot{
		ProfileID:     snapshot.ProfileID,
		Source:        snapshot.Source,
		DefaultAction: snapshot.DefaultAction,
		Rules:         PathRules{Rules: mergedRules, Default: snapshot.Rules.Default},
		Revision:      snapshot.Revision + state.generation,
	}
	state.mergedBase = snapshot.Revision
	state.mergedGen = state.generation
	return state.merged
}

func (p *RulePersistence) runProfile(key string, state *dirtyRuleProfile) {
	for range state.wake {
		for {
			rule, store, ok := p.nextRule(key, state)
			if !ok {
				break
			}
			err := store.AppendRule(rule.entry)
			if err == nil {
				p.persisted(key, state, rule)
				continue
			}
			p.failed(key, state, rule, err)
			<-p.after(p.backoff(state))
		}
	}
}

func (p *RulePersistence) nextRule(key string, expected *dirtyRuleProfile) (permanentRule, RuleStore, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.profiles[key]
	if state != expected || state == nil || state.store == nil || len(state.dirty) == 0 {
		return permanentRule{}, nil, false
	}
	var selected permanentRule
	for _, rule := range state.dirty {
		if selected.generation == 0 || rule.generation < selected.generation {
			selected = rule
		}
	}
	return selected, state.store, true
}

func (p *RulePersistence) persisted(key string, expected *dirtyRuleProfile, rule permanentRule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.profiles[key]
	if state != expected || state == nil {
		return
	}
	if current, ok := state.dirty[rule.pattern]; ok && current.generation == rule.generation {
		delete(state.dirty, rule.pattern)
		state.applied[rule.pattern] = rule
		state.merged = nil
	}
	if len(state.dirty) == 0 {
		state.failure = false
		state.lastErr = nil
	}
}

func (p *RulePersistence) failed(key string, expected *dirtyRuleProfile, rule permanentRule, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state := p.profiles[key]
	if state != expected || state == nil {
		return
	}
	if current, ok := state.dirty[rule.pattern]; ok && current.generation == rule.generation {
		state.retries++
		state.lastErr = err
		state.failure = true
	}
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
