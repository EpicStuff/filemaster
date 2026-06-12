package fileaccess

import (
	"context"
	"errors"

	"github.com/safing/portmaster/service/process"
	"github.com/safing/portmaster/service/profile"
)

// NewProcessProfileLookup returns a ProfileLookup that maps a PID to
// the matched portmaster Profile via process.GetProcessWithProfile.
// The returned RuleStore reads and writes
// CfgOptionFileAccessRulesKey ("fileaccess/rules") on the local
// Profile underneath the LayeredProfile, which transparently carries
// the existing persistence (profile database) and sync paths.
func NewProcessProfileLookup() ProfileLookup {
	return processProfileLookup{}
}

type processProfileLookup struct{}

func (processProfileLookup) Lookup(ctx context.Context, pid int32) (RuleStore, error) {
	p, err := process.GetProcessWithProfile(ctx, int(pid))
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrNoProfile
	}
	lp := p.Profile()
	if lp == nil {
		return nil, ErrNoProfile
	}
	local := lp.LocalProfile()
	if local == nil {
		return nil, ErrNoProfile
	}
	return &profileRuleStore{p: local}, nil
}

// profileRuleStore is a thin adapter over *profile.Profile. All locking
// is delegated to the profile's own RWMutex / addEndpointEntry path.
type profileRuleStore struct {
	p *profile.Profile
}

func (s *profileRuleStore) ID() string {
	s.p.RLock()
	defer s.p.RUnlock()
	return s.p.ScopedID()
}

func (s *profileRuleStore) Rules() []string {
	s.p.RLock()
	defer s.p.RUnlock()
	return s.p.GetFileAccessRules()
}

func (s *profileRuleStore) AppendRule(entry string) error {
	if entry == "" {
		return errors.New("empty rule entry")
	}
	s.p.AddFileAccessRule(entry)
	return nil
}
