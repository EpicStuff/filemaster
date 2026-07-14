package fileaccess

import (
	"context"
	"errors"
	"sync"

	"github.com/safing/portmaster/service/process"
	"github.com/safing/portmaster/service/profile"
)

// getProcessWithProfile is the indirection point for tests. Production
// code uses process.GetProcessWithProfile directly; the var lets tests
// inject a fake without bringing the profile DB up. Reuse means
// portmaster's auto-creation flow stays in-play whenever the var is
// the default.
var getProcessWithProfile = process.GetProcessWithProfile

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
	// parseCache holds the most-recent ParseRules result per profile
	// ID. AddFileAccessRule only ever prepends, so we cheaply detect
	// staleness by comparing the raw-rule-list length: if it grew,
	// re-parse. Cache lives here (not on profileRuleStore) so it
	// survives across the per-event store instances.
	parseCache sync.Map // map[string]*ruleCacheEntry
}

type ruleCacheEntry struct {
	mu     sync.Mutex
	rawN   int // raw-rule count last time we parsed
	parsed PathRules
}

func (l *processProfileLookup) Lookup(ctx context.Context, pid int32) (LookupResult, error) {
	p, err := getProcessWithProfile(ctx, int(pid))
	if err != nil {
		return LookupResult{}, err
	}
	if p == nil {
		return LookupResult{Path: ""}, ErrNoProfile
	}

	// Always populate Path so the fallback handler can key by it even
	// when no profile resolved.
	res := LookupResult{
		Path:          p.Path,
		DefaultAction: profile.DefaultActionAsk,
	}

	lp := p.Profile()
	if lp == nil {
		return res, nil
	}
	local := lp.LocalProfile()
	if local == nil {
		return res, nil
	}

	// Snapshot what we need from the profile under a single read-lock.
	// Use the bare profile ID (not the scoped "source/id") because the
	// consumers — the filequery recorder and the prompt UI — build the
	// scoped key themselves as ProfileSource + "/" + ProfileID.
	local.RLock()
	id := local.ID
	rawRules := local.GetFileAccessRules()
	defAct := local.DefaultAction()
	source := string(local.Source)
	name := local.Name
	linkedPath := local.LinkedPath
	local.RUnlock()

	res.Store = &profileRuleStore{p: local, id: id}
	res.ParsedRules = l.parsedRulesFor(id, rawRules)
	res.ProfileSource = source
	res.ProfileName = name
	res.ProfileLinkedPath = linkedPath
	if defAct != profile.DefaultActionNotSet {
		res.DefaultAction = defAct
	}
	return res, nil
}

// parsedRulesFor returns the cached PathRules for id, re-parsing only
// when the raw rule count has changed.
func (l *processProfileLookup) parsedRulesFor(id string, raw []string) PathRules {
	v, _ := l.parseCache.LoadOrStore(id, &ruleCacheEntry{})
	entry := v.(*ruleCacheEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.rawN == len(raw) && entry.rawN > 0 {
		return entry.parsed
	}
	entry.parsed = ParseRules(raw)
	entry.rawN = len(raw)
	return entry.parsed
}

// profileRuleStore is a thin adapter over *profile.Profile. All locking
// is delegated to the profile's own RWMutex / addEndpointEntry path.
type profileRuleStore struct {
	p  *profile.Profile
	id string
}

func (s *profileRuleStore) ID() string {
	return s.id
}

func (s *profileRuleStore) AppendRule(entry string) error {
	if entry == "" {
		return errors.New("empty rule entry")
	}
	s.p.AddFileAccessRule(entry)
	return nil
}
