package fileaccess

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFakeFanotifyEventsFromEnvParsesJSONL(t *testing.T) {
	t.Setenv(envFakeFanotifyEvents, filepath.Join(t.TempDir(), "events.jsonl"))
	err := os.WriteFile(
		os.Getenv(envFakeFanotifyEvents),
		[]byte("# comment\n\n{\"PID\":42,\"Exe\":\"/usr/bin/code\",\"Path\":\"/tmp/demo.txt\",\"Op\":\"read\",\"Delay\":\"5ms\",\"ProfileName\":\"Code\"}\n"),
		0o600,
	)
	if err != nil {
		t.Fatal(err)
	}

	events, err := fakeFanotifyEventsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].fileEvent().Op != OpRead {
		t.Fatalf("expected read op, got %s", events[0].fileEvent().Op)
	}
	if events[0].ProfileName != "Code" {
		t.Fatalf("expected profile name Code, got %q", events[0].ProfileName)
	}
}

func TestFakeFanotifyEventsFromEnvParsesPromptData(t *testing.T) {
	t.Setenv(envFakeFanotifyEvents, filepath.Join(t.TempDir(), "events.jsonl"))
	err := os.WriteFile(
		os.Getenv(envFakeFanotifyEvents),
		[]byte("{\"Profile\":{\"ID\":\"profile-id\",\"Source\":\"local\",\"Name\":\"Code\",\"LinkedPath\":\"/usr/bin/code\"},\"Subject\":{\"PID\":42,\"Exe\":\"/usr/bin/code\",\"Path\":\"/tmp/demo.txt\",\"Op\":\"read\"}}\n"),
		0o600,
	)
	if err != nil {
		t.Fatal(err)
	}

	events, err := fakeFanotifyEventsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	event := events[0].fileEvent()
	if event.PID != 42 || event.Exe != "/usr/bin/code" || event.Path != "/tmp/demo.txt" || event.Op != OpRead {
		t.Fatalf("unexpected subject: %+v", event)
	}
	if event.ProfileID != "profile-id" || event.ProfileSource != "local" || event.ProfileName != "Code" || event.ProfileLinkedPath != "/usr/bin/code" {
		t.Fatalf("unexpected profile: %+v", event)
	}
}

func TestFakeFanotifySourceRunsEvents(t *testing.T) {
	src := &fakeFanotifySource{
		log:    noopLogger{},
		closed: make(chan struct{}),
		events: []fakeFanotifyEvent{
			{PID: 7, Exe: "/usr/bin/bash", Path: "/tmp/demo.txt", Op: "exec"},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var got []FileEvent
	errc := make(chan error, 1)
	go func() {
		errc <- src.Run(ctx, HandlerFunc(func(_ context.Context, event FileEvent) Verdict {
			got = append(got, event)
			cancel()
			return VerdictDeny
		}))
	}()

	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Op != OpExec {
		t.Fatalf("expected exec op, got %s", got[0].Op)
	}
}

func TestFakeFanotifyFromEnvSelectsFake(t *testing.T) {
	t.Setenv(envFileAccessSource, fakeFanotifySourceValue)
	t.Setenv(envWatchPaths, "/tmp/fake-root")

	src, ok, err := fakeFanotifyFromEnv(noopLogger{})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected fake fanotify source to be selected")
	}
	fake, ok := src.(*fakeFanotifySource)
	if !ok {
		t.Fatalf("expected *fakeFanotifySource, got %T", src)
	}
	events := fake.snapshotEvents()
	if len(events) == 0 {
		t.Fatal("expected default events")
	}
	if filepath.Dir(events[0].Path) != "/tmp/fake-root" {
		t.Fatalf("expected first default event under /tmp/fake-root, got %q", events[0].Path)
	}
}

type noopLogger struct{}

func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Warn(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}
