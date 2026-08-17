//go:build linux

package core

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close() //nolint:errcheck

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close() //nolint:errcheck

	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	pid, err := peerPID(conn)
	if err != nil {
		t.Fatalf("peerPID: %v", err)
	}
	if pid != os.Getpid() {
		t.Fatalf("peerPID = %d, want this process %d", pid, os.Getpid())
	}
}

func TestWithAPIPeerPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close() //nolint:errcheck

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close() //nolint:errcheck

	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	pid, ok := peerPIDFromContext(withAPIPeerPID(context.Background(), conn))
	if !ok || pid != os.Getpid() {
		t.Fatalf("peer PID context = (%d, %t), want (%d, true)", pid, ok, os.Getpid())
	}
}

func TestListenAPISocketPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	listener, err := listenAPISocket(path)
	if err != nil {
		t.Fatalf("listenAPISocket: %v", err)
	}
	defer listener.Close() //nolint:errcheck

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o666 {
		t.Fatalf("socket permissions = %o, want 666", got)
	}
}
