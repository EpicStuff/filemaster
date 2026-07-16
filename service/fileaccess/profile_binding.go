package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/safing/portmaster/service/process"
	"github.com/safing/portmaster/service/profile"
)

// getProcessWithProfile is the indirection point for tests. Production
// code uses process.GetProcessWithProfile directly; the var lets tests
// inject a fake without bringing the profile DB up. Reuse means
// portmaster's auto-creation flow stays in-play whenever the var is
// the default.
var getProcessWithProfile = process.GetProcessWithProfile

var refreshProcessMapping = func(ctx context.Context, pid int) error {
	p, err := process.GetOrFindProcess(ctx, pid)
	if err != nil {
		return err
	}
	p.Delete()
	_, err = process.GetProcessWithProfile(ctx, pid)
	return err
}

// NewProcessProfileLookup returns a ProfileLookup that maps a PID to
// the matched portmaster Profile via process.GetProcessWithProfile.
// LookupResult.Store reads and writes CfgOptionFileAccessRulesKey
// ("fileaccess/rules") on the local Profile underneath the
// LayeredProfile, which transparently carries the existing persistence
// (profile database) and sync paths.
//
// Profile auto-creation for unknown processes is fully delegated to
// portmaster's existing code:
//
//	process.GetProcessWithProfile
//	  -> process.GetOrFindProcess   (reads /proc, builds *Process)
//	  -> process.GetProfile
//	    -> profile.GetLocalProfile  (with MatchingData from /proc)
//	      -> findProfile            (search-by-fingerprint)
//	      -> if no match: New(...)  (path-fingerprint default)
//
// A first-time-seen exe at /usr/bin/foo therefore lands a fresh local
// profile named "Foo" with a single path-equals fingerprint pointing
// at the exe. Verified live 2026-06-12 with cat against a watched
// directory: a previously-unseen process produced
// profiles/local/<scopedID> with Fingerprints = [{path, equals,
// /usr/bin/cat}] in the profile DB. We do NOT roll our own auto-
// creation logic -- if portmaster's code path changes, our behavior
// follows it.
func NewProcessProfileLookup() ProfileLookup {
	return &processProfileLookup{}
}

type processProfileLookup struct {
	// parseCache owns immutable snapshots. It is deliberately separate from
	// profileRuleStore so snapshots survive per-event store adapters.
	parseCache sync.Map // map[string]*ruleCacheEntry

	observerMu sync.RWMutex
	observer   func(*DecisionSnapshot)
	overlayMu  sync.RWMutex
	overlay    *RulePersistence
}

type ruleCacheEntry struct {
	mu       sync.Mutex
	rawRules []string
	revision uint64
	snapshot atomic.Pointer[DecisionSnapshot]
}

func (l *processProfileLookup) Lookup(ctx context.Context, pid int32) (LookupResult, error) {
	p, err := getProcessWithProfile(ctx, int(pid))
	if err != nil {
		return LookupResult{}, err
	}
	if p == nil {
		return LookupResult{Path: ""}, ErrNoProfile
	}

	res := LookupResult{Path: p.Path, DefaultAction: profile.DefaultActionAsk}
	if p.CreatedAt != 0 {
		res.ProcessIdentity = fmt.Sprintf("%d-%d", p.Pid, p.CreatedAt)
	}

	lp := p.Profile()
	if lp == nil {
		return res, nil
	}
	local := lp.LocalProfile()
	if local == nil {
		return res, nil
	}

	// Copy every profile-owned value while the profile lock is held. The
	// returned snapshot never retains the raw rule slice.
	local.RLock()
	id := local.ID
	rawRules := append([]string(nil), local.GetFileAccessRules()...)
	defaultAction := local.DefaultAction()
	source := string(local.Source)
	name := local.Name
	linkedPath := local.LinkedPath
	local.RUnlock()

	if defaultAction == profile.DefaultActionNotSet {
		defaultAction = profile.DefaultActionAsk
	}
	store := &profileRuleStore{p: local, source: profile.ProfileSource(source), id: id}
	l.bindPersistentStoreFor(source, id, store)
	snapshot := l.snapshotFor(id, source, defaultAction, rawRules)
	l.bindPersistentStore(snapshot, store)
	res.Store = store
	res.Snapshot = snapshot
	res.ParsedRules = snapshot.Rules
	res.DefaultAction = snapshot.DefaultAction
	res.ProfileSource = source
	res.ProfileName = name
	res.ProfileLinkedPath = linkedPath
	return res, nil
}

// parsedRulesFor returns the cached PathRules for id, re-parsing only
// when the raw rule count has changed.
func (l *processProfileLookup) parsedRulesFor(id string, raw []string) PathRules {
	return l.snapshotFor(id, "", profile.DefaultActionAsk, raw).Rules
}

func (l *processProfileLookup) snapshotFor(id, source string, defaultAction uint8, raw []string) *DecisionSnapshot {
	snapshot, replaced := l.snapshotForRunning(id, source, defaultAction, raw)
	if !replaced {
		return snapshot
	}
	l.observerMu.RLock()
	observer := l.observer
	l.observerMu.RUnlock()
	if observer != nil {
		observer(snapshot)
	}
	return snapshot
}

// snapshotForRunning updates the immutable cache without notifying the
// guarded observer. Callers holding the lifecycle activity barrier publish the
// returned snapshot through their corresponding Running path.
func (l *processProfileLookup) snapshotForRunning(id, source string, defaultAction uint8, raw []string) (*DecisionSnapshot, bool) {
	cacheKey := source + "/" + id
	value, _ := l.parseCache.LoadOrStore(cacheKey, &ruleCacheEntry{})
	entry := value.(*ruleCacheEntry)

	entry.mu.Lock()
	if snapshot := entry.snapshot.Load(); snapshot != nil &&
		snapshot.Source == source &&
		snapshot.DefaultAction == defaultAction &&
		sameRuleEntries(entry.rawRules, raw) {
		entry.mu.Unlock()
		return l.mergePersistentRules(snapshot), false
	}

	entry.rawRules = append(entry.rawRules[:0], raw...)
	entry.revision++
	snapshot := newDecisionSnapshot(id, source, defaultAction, entry.rawRules, entry.revision)
	entry.snapshot.Store(snapshot)
	entry.mu.Unlock()
	snapshot = l.mergePersistentRules(snapshot)
	return snapshot, true
}

func (l *processProfileLookup) setSnapshotObserver(observer func(*DecisionSnapshot)) {
	l.observerMu.Lock()
	l.observer = observer
	l.observerMu.Unlock()
}

func (l *processProfileLookup) setRulePersistence(overlay *RulePersistence) {
	l.overlayMu.Lock()
	l.overlay = overlay
	l.overlayMu.Unlock()
}

func (l *processProfileLookup) mergePersistentRules(snapshot *DecisionSnapshot) *DecisionSnapshot {
	l.overlayMu.RLock()
	overlay := l.overlay
	l.overlayMu.RUnlock()
	if overlay == nil {
		return snapshot
	}
	return overlay.Merge(snapshot)
}

func (l *processProfileLookup) bindPersistentStore(snapshot *DecisionSnapshot, store RuleStore) {
	l.overlayMu.RLock()
	overlay := l.overlay
	l.overlayMu.RUnlock()
	if overlay != nil {
		overlay.Bind(snapshot, store)
	}
}

func (l *processProfileLookup) bindPersistentStoreFor(source, id string, store RuleStore) {
	l.overlayMu.RLock()
	overlay := l.overlay
	l.overlayMu.RUnlock()
	if overlay != nil {
		overlay.BindStore(source, id, store)
	}
}

func sameRuleEntries(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// profileRuleStore is a thin adapter over *profile.Profile. All locking
// is delegated to the profile's own RWMutex / addEndpointEntry path.
func (l *processProfileLookup) RefreshProcessMapping(ctx context.Context, pid int32) error {
	return refreshProcessMapping(ctx, int(pid))
}

type profileRuleStore struct {
	p      *profile.Profile
	source profile.ProfileSource
	id     string
}

func (s *profileRuleStore) ID() string {
	return s.id
}

func (s *profileRuleStore) ruleStoreIdentity() any {
	return s.p
}

func (s *profileRuleStore) AppendRule(entry string) error {
	if entry == "" {
		return errors.New("empty rule entry")
	}
	return profile.PersistCurrentFileAccessRule(s.source, s.id, entry, nil)
}

func (s *profileRuleStore) AppendRuleIfCurrent(entry string, current func() bool) error {
	return profile.PersistCurrentFileAccessRule(s.source, s.id, entry, current)
}
