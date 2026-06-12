package fileaccess

import (
	"context"
	"errors"
	"testing"

	"github.com/safing/portmaster/service/process"
)

// TestProcessProfileLookupGoesThroughPortmasterHook asserts the
// binding actually delegates to the package-level
// getProcessWithProfile var, which is the indirection point the
// production path resolves to process.GetProcessWithProfile. If a
// future change accidentally calls something else (a local search,
// a parallel cache), this regression test would fail.
//
// The test deliberately does not construct a real *process.Process
// (that requires the profile DB and /proc), it just verifies the
// call site delegates and that an error from the hook flows out.
func TestProcessProfileLookupGoesThroughPortmasterHook(t *testing.T) {
	orig := getProcessWithProfile
	t.Cleanup(func() { getProcessWithProfile = orig })

	var calledWith int
	wantErr := errors.New("portmaster hook ran")
	getProcessWithProfile = func(_ context.Context, pid int) (*process.Process, error) {
		calledWith = pid
		return nil, wantErr
	}

	l := &processProfileLookup{}
	_, err := l.Lookup(context.Background(), 42)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v -- binding bypassed the portmaster hook", err, wantErr)
	}
	if calledWith != 42 {
		t.Fatalf("hook saw pid=%d, want 42", calledWith)
	}
}

// TestProcessProfileLookupNilProcessIsErrNoProfile pins the
// "process gone between event and lookup" branch -- portmaster
// returns (nil, nil) in some failure modes; the binding must surface
// ErrNoProfile so the fallback handler fires instead of the daemon
// crashing on a nil deref.
func TestProcessProfileLookupNilProcessIsErrNoProfile(t *testing.T) {
	orig := getProcessWithProfile
	t.Cleanup(func() { getProcessWithProfile = orig })

	getProcessWithProfile = func(context.Context, int) (*process.Process, error) {
		return nil, nil
	}

	l := &processProfileLookup{}
	_, err := l.Lookup(context.Background(), 1)
	if !errors.Is(err, ErrNoProfile) {
		t.Fatalf("err = %v, want ErrNoProfile", err)
	}
}
