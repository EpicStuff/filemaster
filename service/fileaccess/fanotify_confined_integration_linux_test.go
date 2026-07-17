//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	confinedFanotifyIntegrationEnv      = "FM_FANOTIFY_INTEGRATION"
	confinedFanotifyIntegrationChildEnv = "FM_FANOTIFY_INTEGRATION_CHILD"
)

// TestConfinedFanotifyIntegration exercises a real FAN_CLASS_CONTENT group in
// a child process with a private mount namespace. It never marks the host root:
// the only configured scope is a bind mount created below t.TempDir().
//
// Run explicitly on a capable Linux host:
//
//	FM_FANOTIFY_INTEGRATION=1 go test ./service/fileaccess -run '^TestConfinedFanotifyIntegration$' -count=1 -v -timeout=45s
func TestConfinedFanotifyIntegration(t *testing.T) {
	if os.Getenv(confinedFanotifyIntegrationEnv) != "1" {
		t.Skipf("set %s=1 to run the real fanotify integration harness", confinedFanotifyIntegrationEnv)
	}
	if os.Getenv(confinedFanotifyIntegrationChildEnv) == "1" {
		testConfinedFanotifyIntegrationChild(t)
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestConfinedFanotifyIntegration$", "-test.count=1", "-test.v", "-test.timeout=35s")
	command.Env = append(os.Environ(), confinedFanotifyIntegrationEnv+"=1", confinedFanotifyIntegrationChildEnv+"=1")
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(err, syscall.EPERM) || strings.Contains(string(output), "requires CAP_SYS_ADMIN") || strings.Contains(string(output), "private mount namespace unavailable") {
			t.Skipf("confined fanotify integration unavailable: %s", strings.TrimSpace(string(output)))
		}
		t.Fatalf("confined fanotify integration child failed: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "--- SKIP:") {
		t.Skipf("confined fanotify integration unavailable: %s", strings.TrimSpace(string(output)))
	}
}

func testConfinedFanotifyIntegrationChild(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("confined fanotify integration requires effective UID 0 with CAP_SYS_ADMIN in the initial user namespace")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("private mount namespace unavailable: %v", err)
		}
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := unix.Mount(root, root, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("temporary bind mount unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(root, unix.MNT_DETACH) })
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(nested, nested, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("nested temporary bind mount unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(nested, unix.MNT_DETACH) })

	previousInterceptReads := cfgOptionInterceptReads
	cfgOptionInterceptReads = func() bool { return true }
	t.Cleanup(func() { cfgOptionInterceptReads = previousInterceptReads })

	filePath := filepath.Join(root, "file")
	promptPath := filepath.Join(root, "prompt")
	nestedPath := filepath.Join(nested, "nested-file")
	if err := os.WriteFile(filePath, []byte("contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(promptPath, []byte("prompt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nestedPath, []byte("nested"), 0o600); err != nil {
		t.Fatal(err)
	}

	source := newConfinedFanotifySource(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	defer func() { _ = source.Close() }()

	prompted := make(chan FileEvent, 1)
	handler := &confinedFanotifyHandler{
		snapshot: &DecisionSnapshot{
			ProfileID: "confined-integration",
			Source:    "integration",
		},
	}
	pipeline := newDecisionPipeline(handler, DecisionPipelineConfig{
		Workers:            1,
		QueueCapacity:      2,
		OutstandingLimit:   4,
		PerProfileAskLimit: 2,
	}, source.lifecycle)
	coordinator := newPromptCoordinator(
		confinedPrompter{events: prompted},
		time.Second,
		pipeline.acquireAsk,
		pipeline.finishTransferredPromptEvent,
		source.lifecycle,
	)
	coordinator.complete = pipeline.releaseOutstanding
	handler.coordinator = coordinator
	pipeline.Start(ctx)

	readerDone := make(chan error, 1)
	go func() { readerDone <- source.Run(ctx, pipeline) }()

	if err := openAndRead(filePath); err != nil {
		t.Fatal(err)
	}
	if err := openAndRead(nestedPath); err != nil {
		t.Fatal(err)
	}
	openAndReadDirectory(t, root)

	promptResult := make(chan error, 1)
	go func() {
		promptResult <- openAndRead(promptPath)
	}()
	promptDeadline := time.NewTimer(5 * time.Second)
	defer promptDeadline.Stop()
	sawPromptOpen := false
	for {
		select {
		case event := <-prompted:
			if event.Path != promptPath {
				t.Fatalf("prompt event = %+v, want path %s", event, promptPath)
			}
			sawPromptOpen = sawPromptOpen || event.Op == OpOpen
		case err := <-promptResult:
			if err != nil {
				t.Fatal(err)
			}
			if !sawPromptOpen {
				t.Fatal("prompt coordinator did not receive an open event")
			}
			goto promptCompleted
		case <-promptDeadline.C:
			t.Fatal("prompt coordinator did not resolve the real fanotify event")
		}
	}

promptCompleted:

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer drainCancel()
	if err := pipeline.WaitOutstanding(drainCtx); err != nil {
		t.Fatalf("confined decision pipeline did not drain: %v", err)
	}
	if diagnostics := source.ReaderDiagnostics(); diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("confined descriptor accounting did not drain: %+v", diagnostics)
	}
	if diagnostics := coordinator.Diagnostics(); diagnostics.Events != 0 {
		t.Fatalf("confined prompt coordinator did not drain: %+v", diagnostics)
	}
	if diagnostics := source.MountDiagnostics(); diagnostics.PartialCoverage || len(diagnostics.ActiveMountIDs) < 2 {
		t.Fatalf("confined mount coverage = %+v", diagnostics)
	}
	if result := source.RemoveAllMarks(); !result.Complete {
		t.Fatalf("remove confined fanotify marks: %+v", result)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-readerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fanotify reader did not exit after confined group closure")
	}
	workersCtx, workersCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer workersCancel()
	if err := pipeline.WaitWorkers(workersCtx); err != nil {
		t.Fatalf("confined decision workers did not exit: %v", err)
	}
	if diagnostics := source.ReaderDiagnostics(); diagnostics.OutstandingDescriptors != 0 || !diagnostics.Exited {
		t.Fatalf("reader diagnostics after confined shutdown = %+v", diagnostics)
	}
}

func newConfinedFanotifySource(t *testing.T, root string) *fanotifySource {
	t.Helper()
	source, err := newFanotifySource([]string{root}, nopLogger{})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSYS) || strings.Contains(err.Error(), "CAP_SYS_ADMIN") {
			t.Skipf("fanotify unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if diagnostics := source.MountDiagnostics(); diagnostics.PartialCoverage {
		_ = source.Close()
		t.Skipf("confined fanotify mount mark unavailable: %+v", diagnostics)
	}
	return source
}

func openAndRead(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	if _, err := file.Read(make([]byte, 1)); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func openAndReadDirectory(t *testing.T, path string) {
	t.Helper()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := directory.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := directory.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

type confinedPrompter struct {
	events chan<- FileEvent
}

func (p confinedPrompter) Prompt(_ context.Context, event FileEvent, _ time.Duration) (string, bool) {
	p.events <- event
	return ActionAllow, true
}

type confinedFanotifyHandler struct {
	coordinator *PromptCoordinator
	snapshot    *DecisionSnapshot
}

func (h *confinedFanotifyHandler) Decide(_ context.Context, _ *FileEvent) Verdict {
	return VerdictAllow
}

func (h *confinedFanotifyHandler) DecidePending(ctx context.Context, pending PendingEvent) (bool, bool, Verdict, func()) {
	event := pending.Event()
	if event == nil || filepath.Base(event.Path) != "prompt" {
		return false, false, VerdictDeny, nil
	}
	return h.coordinator.Admit(ctx, pending, confinedRuleStore{}, h.snapshot)
}

type confinedRuleStore struct{}

func (confinedRuleStore) ID() string { return "confined-integration" }

func (confinedRuleStore) AppendRule(string) error { return nil }

var _ RuleStore = confinedRuleStore{}
var _ Handler = (*confinedFanotifyHandler)(nil)
