package fileaccess

import (
	"context"
	"testing"
	"time"
)

// TestHandlerRouting drives a fake source through a custom handler and
// checks that every event reaches the handler and every verdict comes
// back to the source. This is the minimum proof that the Source/Handler
// abstraction is wired up correctly without involving fanotify.
func TestHandlerRouting(t *testing.T) {
	events := []FileEvent{
		{PID: 100, Exe: "/usr/bin/cat", Path: "/etc/passwd", Op: OpOpen},
		{PID: 101, Exe: "/usr/bin/vim", Path: "/etc/shadow", Op: OpOpen},
		{PID: 102, Exe: "/usr/bin/cat", Path: "/tmp/ok", Op: OpOpen},
	}

	// Deny anything touching /etc, allow everything else.
	h := HandlerFunc(func(_ context.Context, e FileEvent) Verdict {
		if hasPrefix(e.Path, "/etc/") {
			return VerdictDeny
		}
		return VerdictAllow
	})

	src := newFakeSource(events)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- src.Run(ctx, h) }()

	// Wait for the source to chew through all events before closing.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(src.Decisions()) == len(events) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = src.Close()
	if err := <-done; err != nil {
		t.Fatalf("source.Run: %v", err)
	}

	got := src.Decisions()
	if len(got) != len(events) {
		t.Fatalf("got %d decisions, want %d", len(got), len(events))
	}

	want := []Verdict{VerdictDeny, VerdictDeny, VerdictAllow}
	for i, d := range got {
		if d.Event != events[i] {
			t.Errorf("decision %d: event = %+v, want %+v", i, d.Event, events[i])
		}
		if d.Verdict != want[i] {
			t.Errorf("decision %d: verdict = %s, want %s", i, d.Verdict, want[i])
		}
	}
}

// TestAllowAll is a sanity check that the phase-1 default handler does
// what it says on the tin.
func TestAllowAll(t *testing.T) {
	v := allowAll.Decide(context.Background(), FileEvent{PID: 1, Path: "/anything"})
	if v != VerdictAllow {
		t.Fatalf("allowAll returned %s, want allow", v)
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
