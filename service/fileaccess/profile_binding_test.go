package fileaccess

import (
	"context"
	"errors"
	"testing"

	"github.com/safing/portmaster/service/process"
	"github.com/safing/portmaster/service/profile"
)

func TestProcessProfileLookupUsesUnidentifiedProfileWhenProcessIsMissing(t *testing.T) {
	origLookup := getProcessWithProfile
	origUnidentified := getUnidentifiedProcess
	origProfile := processLayeredProfile
	t.Cleanup(func() {
		getProcessWithProfile = origLookup
		getUnidentifiedProcess = origUnidentified
		processLayeredProfile = origProfile
	})

	local := profile.New(&profile.Profile{
		ID:     profile.UnidentifiedProfileID,
		Source: profile.SourceLocal,
		Config: map[string]interface{}{profile.CfgOptionDefaultActionKey: profile.DefaultActionPermitValue},
	})
	layered := profile.NewLayeredProfile(local)
	unknown := &process.Process{Path: "unknown"}
	var calledWith int
	getProcessWithProfile = func(_ context.Context, pid int) (*process.Process, error) {
		calledWith = pid
		return nil, errors.New("proc lookup failed")
	}
	getUnidentifiedProcess = func(context.Context) *process.Process { return unknown }
	processLayeredProfile = func(*process.Process) *profile.LayeredProfile { return layered }

	result, err := (&processProfileLookup{}).Lookup(context.Background(), 42)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.Store == nil || result.Snapshot == nil {
		t.Fatalf("Lookup result = %+v, want profile store and snapshot", result)
	}
	if result.Store.ID() != profile.UnidentifiedProfileID {
		t.Fatalf("Lookup profile = %s, want %s", result.Store.ID(), profile.UnidentifiedProfileID)
	}
	if result.Snapshot.DefaultAction == profile.DefaultActionAsk {
		t.Fatalf("unidentified snapshot default action = ask, want layered policy")
	}
	if calledWith != 42 {
		t.Fatalf("process lookup saw pid=%d, want 42", calledWith)
	}
}

func TestProcessProfileLookupReusesPortmasterIdentityStore(t *testing.T) {
	orig := getProcessWithProfile
	t.Cleanup(func() { getProcessWithProfile = orig })

	processRecord := &process.Process{Path: "/usr/bin/reused"}
	calls := 0
	getProcessWithProfile = func(context.Context, int) (*process.Process, error) {
		calls++
		return processRecord, nil
	}

	lookup := &processProfileLookup{}
	for range 2 {
		result, err := lookup.Lookup(context.Background(), 42)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if result.Path != processRecord.Path {
			t.Fatalf("Lookup path = %q, want %q", result.Path, processRecord.Path)
		}
	}
	if calls != 2 {
		t.Fatalf("portmaster process store calls = %d, want 2 without a fileaccess PID cache", calls)
	}
}

func TestDecisionSnapshotReplacementCopiesRulesAndDetectsEqualLengthEdits(t *testing.T) {
	lookup := &processProfileLookup{}
	rules := []string{"+ /tmp/rule"}
	first := lookup.snapshotFor("profile", "local", profile.DefaultActionAsk, ruleLists{read: rules})
	rules[0] = "- /tmp/rule"
	if verdict, ok := first.Read.Lookup("/tmp/rule"); !ok || verdict != VerdictAllow {
		t.Fatalf("first snapshot changed after source mutation: verdict=%s ok=%v", verdict, ok)
	}

	second := lookup.snapshotFor("profile", "local", profile.DefaultActionAsk, ruleLists{read: rules})
	if same := lookup.snapshotFor("profile", "local", profile.DefaultActionAsk, ruleLists{read: rules}); same != second {
		t.Fatal("unchanged profile rules replaced their immutable snapshot")
	}
	if second == first || second.Revision <= first.Revision {
		t.Fatalf("snapshot replacement = %#v -> %#v, want newer immutable snapshot", first, second)
	}
	if verdict, ok := second.Read.Lookup("/tmp/rule"); !ok || verdict != VerdictDeny {
		t.Fatalf("equal-length rule edit verdict=%s ok=%v, want deny", verdict, ok)
	}
}

func TestProcessProfileLookupRefreshesExistingProcessMapping(t *testing.T) {
	orig := refreshProcessMapping
	t.Cleanup(func() { refreshProcessMapping = orig })

	calledWith := 0
	refreshProcessMapping = func(_ context.Context, pid int) error {
		calledWith = pid
		return nil
	}

	if err := (&processProfileLookup{}).RefreshProcessMapping(context.Background(), 73); err != nil {
		t.Fatalf("RefreshProcessMapping: %v", err)
	}
	if calledWith != 73 {
		t.Fatalf("refresh pid = %d, want 73", calledWith)
	}
}
