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
		{"access decodes as open", unix.FAN_ACCESS_PERM, OpOpen},
		{"directory access decodes as open", unix.FAN_ACCESS_PERM | unix.FAN_ONDIR, OpOpen},
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

// TestResolveMarkMaskDefault confirms the mask is always open+exec+ondir
// and never includes FAN_ACCESS_PERM (reads) or FAN_EVENT_ON_CHILD.
func TestResolveMarkMaskDefault(t *testing.T) {
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
