//go:build linux

package fileaccess

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestOpFromMask covers file and directory variants of the permission
// event operations decoded by the reader.
func TestOpFromMask(t *testing.T) {
	cases := []struct {
		name string
		mask uint64
		want FileOp
	}{
		{"file open", unix.FAN_OPEN_PERM, OpOpen},
		{"directory open", unix.FAN_OPEN_PERM | unix.FAN_ONDIR, OpOpen},
		{"file read", unix.FAN_ACCESS_PERM, OpRead},
		{"directory read", unix.FAN_ACCESS_PERM | unix.FAN_ONDIR, OpRead},
		{"exec", unix.FAN_OPEN_EXEC_PERM, OpExec},
		{
			"exec+open both set (exec wins)",
			unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM,
			OpExec,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := opFromMask(tc.mask); got != tc.want {
				t.Fatalf("opFromMask(0x%x) = %v, want %v", tc.mask, got, tc.want)
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
	if mask&uint64(unix.FAN_ONDIR) == 0 {
		t.Errorf("default mask missing FAN_ONDIR (got 0x%x)", mask)
	}
	if mask&uint64(unix.FAN_ACCESS_PERM) != 0 {
		t.Errorf("default mask should not include FAN_ACCESS_PERM (got 0x%x)", mask)
	}
	if mask&uint64(unix.FAN_EVENT_ON_CHILD) != 0 {
		t.Errorf("mount mask should not include FAN_EVENT_ON_CHILD (got 0x%x)", mask)
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
	if mask&uint64(unix.FAN_ONDIR) == 0 {
		t.Fatalf("directory reads require FAN_ONDIR in mask, got 0x%x", mask)
	}
}
