//go:build linux && filemaster_test

package fileaccess

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestSocketSource(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "fileaccess.sock")
	source, err := newSocketSource(socketPath, nopLogger{})
	if err != nil {
		t.Fatalf("newSocketSource: %v", err)
	}
	defer source.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan FileEvent, 1)
	done := make(chan error, 1)
	go func() {
		done <- source.Run(ctx, HandlerFunc(func(ctx context.Context, event *FileEvent) Verdict {
			events <- *event
			return VerdictDeny
		}))
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial socket source: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintln(conn, `{"pid":123,"exe":"/usr/bin/cat","path":"/tmp/secret.txt","op":"read"}`); err != nil {
		t.Fatalf("write event: %v", err)
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read verdict: %v", err)
	}
	if line != "deny\n" {
		t.Fatalf("verdict line = %q, want %q", line, "deny\n")
	}

	select {
	case event := <-events:
		// The socket source mirrors the real kernel source: PID, Path and
		// Op come off the wire, but Exe is left empty (resolved from the
		// PID downstream). Any "exe" key in the JSON is ignored.
		if event.PID != 123 || event.Exe != "" || event.Path != "/tmp/secret.txt" || event.Op != OpRead {
			t.Fatalf("event = %+v, want pid/path/op from socket JSON and empty exe", event)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not receive socket event")
	}

	cancel()
	if err := source.Close(); err != nil {
		t.Fatalf("close source: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}

func TestSocketSourceCloseFromHandler(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "fileaccess.sock")
	source, err := newSocketSource(socketPath, nopLogger{})
	if err != nil {
		t.Fatalf("newSocketSource: %v", err)
	}
	defer source.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- source.Run(ctx, HandlerFunc(func(ctx context.Context, event *FileEvent) Verdict {
			if err := source.Close(); err != nil {
				t.Errorf("close from handler: %v", err)
			}
			return VerdictAllow
		}))
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial socket source: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintln(conn, `{"pid":456,"exe":"/usr/bin/tee","path":"/tmp/out.txt","op":"write"}`); err != nil {
		t.Fatalf("write event: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read verdict: %v", err)
	}
	if line != "allow\n" {
		t.Fatalf("verdict line = %q, want %q", line, "allow\n")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after handler closed source")
	}
}

func TestNewPlatformSourceUsesSocketSourceWhenFakeSocketIsSet(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "fileaccess.sock")
	t.Setenv("FM_FAKE_SOCKET", socketPath)

	source, err := newPlatformSource(nopLogger{})
	if err != nil {
		t.Fatalf("newPlatformSource: %v", err)
	}
	defer source.Close()

	if _, ok := source.(*socketSource); !ok {
		t.Fatalf("newPlatformSource returned %T, want *socketSource", source)
	}
}
