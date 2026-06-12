package fileaccess

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSaveLoadRoundTrip exercises the basic persistence path: persist
// some rules via SetPersistPath + Decide, construct a fresh handler,
// Load, and verify the rules are intact and applied.
func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")

	p1 := &scriptedPrompter{responses: map[string]string{
		"/etc/shadow":           ActionDenyAlways,
		"/home/alice/notes.txt": ActionAllowAlways,
	}}
	h1 := NewPromptHandler(p1, nil, time.Second)
	if err := h1.SetPersistPath(rulesPath); err != nil {
		t.Fatalf("SetPersistPath on empty file: %v", err)
	}

	if v := h1.Decide(context.Background(), FileEvent{Exe: "/usr/bin/cat", Path: "/etc/shadow"}); v != VerdictDeny {
		t.Fatalf("cat /etc/shadow: %s, want deny", v)
	}
	if v := h1.Decide(context.Background(), FileEvent{Exe: "/usr/bin/vim", Path: "/home/alice/notes.txt"}); v != VerdictAllow {
		t.Fatalf("vim notes.txt: %s, want allow", v)
	}

	// New handler, load.
	p2 := &scriptedPrompter{}
	h2 := NewPromptHandler(p2, nil, time.Second)
	if err := h2.SetPersistPath(rulesPath); err != nil {
		t.Fatalf("SetPersistPath on existing file: %v", err)
	}

	// Both rules should now apply without any prompt.
	if v := h2.Decide(context.Background(), FileEvent{Exe: "/usr/bin/cat", Path: "/etc/shadow"}); v != VerdictDeny {
		t.Errorf("after reload: cat /etc/shadow: %s, want deny", v)
	}
	if v := h2.Decide(context.Background(), FileEvent{Exe: "/usr/bin/vim", Path: "/home/alice/notes.txt"}); v != VerdictAllow {
		t.Errorf("after reload: vim notes.txt: %s, want allow", v)
	}
	if p2.called != 0 {
		t.Errorf("prompter called %d times after reload, want 0 (rules should be loaded)", p2.called)
	}

	// Per-exe scope must survive too: cat asking about notes.txt is
	// still a prompt (rule was for vim only).
	p2.responses = map[string]string{"/home/alice/notes.txt": ActionDeny}
	if v := h2.Decide(context.Background(), FileEvent{Exe: "/usr/bin/cat", Path: "/home/alice/notes.txt"}); v != VerdictDeny {
		t.Errorf("cat notes.txt after reload: %s, want deny (per-exe scope held)", v)
	}
	if p2.called != 1 {
		t.Errorf("prompter called %d times, want 1 (cat needed its own prompt)", p2.called)
	}
}

// TestLoadMissingFileIsNotError: starting fresh against a path that
// doesn't exist should succeed with an empty rule map.
func TestLoadMissingFileIsNotError(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "does-not-exist.json")

	h := NewPromptHandler(&scriptedPrompter{}, nil, time.Second)
	if err := h.SetPersistPath(rulesPath); err != nil {
		t.Fatalf("SetPersistPath on missing file: %v", err)
	}
	if got := h.RulesFor("/anything"); got != nil {
		t.Errorf("rules should be empty after load of missing file: %v", got)
	}
}

// TestLoadWrongVersionRejected: a file with the wrong schema version
// is an error, not silently dropped.
func TestLoadWrongVersionRejected(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "wrong.json")

	if err := os.WriteFile(rulesPath, []byte(`{"version": 99, "rules": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	h := NewPromptHandler(&scriptedPrompter{}, nil, time.Second)
	err := h.SetPersistPath(rulesPath)
	if err == nil {
		t.Fatal("SetPersistPath on wrong-version file: got nil error, want non-nil")
	}
}
