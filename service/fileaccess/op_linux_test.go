//go:build linux

package fileaccess

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestOpFromMask covers the three perm-event variants we decode + the
// EVENT_ON_CHILD bit that always rides along and must not change the
// op.
func TestOpFromMask(t *testing.T) {
	cases := []struct {
		name string
		mask uint64
		want FileOp
	}{
		{"open", unix.FAN_OPEN_PERM, OpOpen},
		{"read", unix.FAN_ACCESS_PERM, OpRead},
		{"exec", unix.FAN_OPEN_EXEC_PERM, OpExec},
		{
			"exec+open both set (exec wins)",
			unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM,
			OpExec,
		},
		{
			"open+child child bit doesn't affect op",
			unix.FAN_OPEN_PERM | unix.FAN_EVENT_ON_CHILD,
			OpOpen,
		},
		{"no perm bits -> Open default", 0, OpOpen},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := opFromMask(c.mask); got != c.want {
				t.Fatalf("opFromMask(0x%x) = %s, want %s", c.mask, got, c.want)
			}
		})
	}
}

// TestResolveMarkMaskDefault confirms the default mask is open+exec
// (no reads) when the InterceptReads option is off. The config option
// pointer is nil in the test process because we don't bring up the
// config module; resolveMarkMask must handle that gracefully.
func TestResolveMarkMaskDefault(t *testing.T) {
	// Force-nil to simulate a freshly-loaded test binary.
	prev := cfgOptionInterceptReads
	cfgOptionInterceptReads = nil
	defer func() { cfgOptionInterceptReads = prev }()

	mask := resolveMarkMask()
	if mask&uint64(unix.FAN_OPEN_PERM) == 0 {
		t.Errorf("default mask missing FAN_OPEN_PERM (got 0x%x)", mask)
	}
	if mask&uint64(unix.FAN_OPEN_EXEC_PERM) == 0 {
		t.Errorf("default mask missing FAN_OPEN_EXEC_PERM (got 0x%x)", mask)
	}
	if mask&uint64(unix.FAN_ACCESS_PERM) != 0 {
		t.Errorf("default mask should not include FAN_ACCESS_PERM (got 0x%x)", mask)
	}
}

// TestResolveMarkMaskWithReads flips the option on and confirms
// FAN_ACCESS_PERM is added.
func TestResolveMarkMaskWithReads(t *testing.T) {
	prev := cfgOptionInterceptReads
	cfgOptionInterceptReads = func() bool { return true }
	defer func() { cfgOptionInterceptReads = prev }()

	mask := resolveMarkMask()
	if mask&uint64(unix.FAN_ACCESS_PERM) == 0 {
		t.Fatalf("expected FAN_ACCESS_PERM in mask, got 0x%x", mask)
	}
}
