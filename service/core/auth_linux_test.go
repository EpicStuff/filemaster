//go:build linux

package core

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/safing/portmaster/service/process"
)

// TestPidFromLoopbackConn verifies that the /proc-based lookup (which replaced
// the deleted network-stack connection→PID attribution) resolves a live
// loopback client socket back to the owning process.
func TestPidFromLoopbackConn(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close() //nolint:errcheck

	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer server.Close() //nolint:errcheck

	// The server sees the client's ephemeral address; that socket is owned by
	// this test process.
	host, portStr, err := net.SplitHostPort(server.RemoteAddr().String())
	if err != nil {
		t.Fatalf("split remote addr: %v", err)
	}
	ip := net.ParseIP(host)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	pid := pidFromLoopbackConn(ip, uint16(port))
	if pid != os.Getpid() {
		t.Fatalf("pidFromLoopbackConn = %d, want this process %d", pid, os.Getpid())
	}

	// The identified process must resolve to this test binary's real path, which
	// is what the trusted-directory check compares against.
	proc, err := process.GetOrFindProcess(context.Background(), pid)
	if err != nil {
		t.Fatalf("GetOrFindProcess(%d): %v", pid, err)
	}
	if proc.Path == "" {
		t.Fatalf("resolved process has empty path")
	}
	if _, err := os.Stat(proc.Path); err != nil {
		t.Fatalf("resolved process path %q does not exist: %v", proc.Path, err)
	}
}

// TestPidFromLoopbackConnUnknown verifies an unresolvable address returns -1
// (which the authenticator treats as "failed to identify" → deny).
func TestPidFromLoopbackConnUnknown(t *testing.T) {
	t.Parallel()

	// Port 0 with no matching socket row must not resolve to a process.
	if pid := pidFromLoopbackConn(net.ParseIP("127.0.0.1"), 0); pid != -1 {
		t.Fatalf("pidFromLoopbackConn for unknown socket = %d, want -1", pid)
	}
}
