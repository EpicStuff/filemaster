package fileaccess

import "testing"

// TestFileOpString locks the user-facing op strings down -- the
// EventID prefix and JSON payload both include them, so renames would
// be a wire break.
func TestFileOpString(t *testing.T) {
	cases := []struct {
		op   FileOp
		want string
	}{
		{OpOpen, "open"},
		{OpRead, "read"},
		{OpWrite, "write"},
		{OpExec, "exec"},
		{FileOp(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.op.String(); got != c.want {
			t.Errorf("FileOp(%d).String() = %q, want %q", c.op, got, c.want)
		}
	}
}
