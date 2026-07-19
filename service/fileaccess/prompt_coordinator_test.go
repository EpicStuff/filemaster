package fileaccess

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/safing/portmaster/service/profile"
)

type coordinatorPrompter struct {
	entered chan FileEvent
	actions chan string
}

type coordinatorPrompterFunc func(context.Context, FileEvent, time.Duration) (string, bool)

func (f coordinatorPrompterFunc) Prompt(ctx context.Context, event FileEvent, timeout time.Duration) (string, bool) {
	return f(ctx, event, timeout)
}

func (p *coordinatorPrompter) Prompt(ctx context.Context, event FileEvent, _ time.Duration) (string, bool) {
	p.entered <- event
	select {
	case action := <-p.actions:
		return action, true
	case <-ctx.Done():
		return "", false
	}
}

type coordinatorHarness struct {
	coordinator *PromptCoordinator

	mu       sync.Mutex
	pending  map[string]int
	limit    int
	finished int
}

func newCoordinatorHarness(prompter Prompter, limit int) *coordinatorHarness {
	h := &coordinatorHarness{pending: make(map[string]int), limit: limit}
	h.coordinator = NewPromptCoordinator(prompter, 20*time.Millisecond, func(profileKey string) (func(), bool) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.limit > 0 && h.pending[profileKey] >= h.limit {
			return nil, false
		}
		h.pending[profileKey]++
		return func() {
			h.mu.Lock()
			h.pending[profileKey]--
			h.finished++
			h.mu.Unlock()
		}, true
	}, func(_ context.Context, pending PendingEvent, verdict Verdict) bool {
		return pending.Respond(verdict) == nil
	})
	return h
}

func coordinatorPending(event FileEvent) (PendingEvent, <-chan Verdict) {
	responses := make(chan Verdict, 1)
	return newPendingEvent(&event, func(verdict Verdict) responseResult {
		responses <- verdict
		return responseResult{accepted: true}
	}), responses
}

func coordinatorSnapshot(id string, revision uint64, defaultAction uint8, rules ...string) *DecisionSnapshot {
	return newDecisionSnapshot(id, "local", defaultAction, rules, revision)
}

func waitCoordinatorPrompt(t *testing.T, prompter *coordinatorPrompter) FileEvent {
	t.Helper()
	select {
	case event := <-prompter.entered:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for prompt")
		return FileEvent{}
	}
}

func waitCoordinatorVerdict(t *testing.T, responses <-chan Verdict) Verdict {
	t.Helper()
	select {
	case verdict := <-responses:
		return verdict
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for prompt verdict")
		return VerdictDeny
	}
}

func TestPromptCoordinatorGroupsOnlyExactDuplicates(t *testing.T) {
	prompter := &coordinatorPrompter{entered: make(chan FileEvent, 4), actions: make(chan string, 4)}
	h := newCoordinatorHarness(prompter, 8)
	snapshot := coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)

	first, firstResponses := coordinatorPending(FileEvent{PID: 1, Path: "/tmp/../tmp/file", Op: OpOpen})
	second, secondResponses := coordinatorPending(FileEvent{PID: 2, Path: "/tmp/file", Op: OpOpen})
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), first, nil, snapshot); !handled || !handedOff {
		t.Fatal("first event was not transferred to the coordinator")
	}
	if got := waitCoordinatorPrompt(t, prompter); got.Path != "/tmp/file" {
		t.Fatalf("prompt event path = %q", got.Path)
	}
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), second, nil, snapshot); !handled || !handedOff {
		t.Fatal("duplicate event was not grouped")
	}
	select {
	case extra := <-prompter.entered:
		t.Fatalf("duplicate created a second visible prompt: %+v", extra)
	default:
	}
	prompter.actions <- ActionAllow
	if got := waitCoordinatorVerdict(t, firstResponses); got != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", got)
	}
	if got := waitCoordinatorVerdict(t, secondResponses); got != VerdictAllow {
		t.Fatalf("second verdict = %s, want allow", got)
	}
}

func TestPromptCoordinatorSeparatesDifferentKeysAndUnidentifiedProcesses(t *testing.T) {
	prompter := &coordinatorPrompter{entered: make(chan FileEvent, 8), actions: make(chan string, 8)}
	h := newCoordinatorHarness(prompter, 8)
	profileA := coordinatorSnapshot("profile-a", 1, profile.DefaultActionAsk)
	profileB := coordinatorSnapshot("profile-b", 1, profile.DefaultActionAsk)
	unidentified := &DecisionSnapshot{DefaultAction: profile.DefaultActionAsk}

	events := []struct {
		event    FileEvent
		snapshot *DecisionSnapshot
	}{
		{FileEvent{Path: "/tmp/one", Op: OpOpen}, profileA},
		{FileEvent{Path: "/tmp/two", Op: OpOpen}, profileA},
		{FileEvent{Path: "/tmp/one", Op: OpRead}, profileA},
		{FileEvent{Path: "/tmp/one", Op: OpOpen}, profileB},
		{FileEvent{PID: 10, ProcessIdentity: "10-1", Path: "/tmp/unknown", Op: OpOpen}, unidentified},
		{FileEvent{PID: 10, ProcessIdentity: "10-1", Path: "/tmp/unknown", Op: OpOpen}, unidentified},
		{FileEvent{PID: 10, ProcessIdentity: "10-2", Path: "/tmp/unknown", Op: OpOpen}, unidentified},
	}
	responses := make([]<-chan Verdict, 0, len(events))
	for _, item := range events {
		pending, result := coordinatorPending(item.event)
		responses = append(responses, result)
		if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), pending, nil, item.snapshot); !handled || !handedOff {
			t.Fatal("event was not admitted")
		}
	}
	for range 6 {
		waitCoordinatorPrompt(t, prompter)
	}
	for range 6 {
		prompter.actions <- ActionDeny
	}
	for _, responses := range responses {
		if got := waitCoordinatorVerdict(t, responses); got != VerdictDeny {
			t.Fatalf("verdict = %s, want deny", got)
		}
	}
}

func TestPromptCoordinatorKeepsEveryGroupedEventInPipelineAccounting(t *testing.T) {
	release := make(chan struct{})
	prompter := &blockingPrompter{entered: make(chan struct{}, 1), release: release}
	handler := NewProfileHandler(askLookup{store: &fakeRuleStore{id: "profile"}}, prompter, nil, time.Second, nopLogger{})
	pipeline := NewDecisionPipeline(handler, DecisionPipelineConfig{Workers: 2, QueueCapacity: 2, OutstandingLimit: 4, PerProfileAskLimit: 4})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)

	first, firstResponses := pipelinePending(FileEvent{PID: 1, Path: "/tmp/file", Op: OpOpen})
	second, secondResponses := pipelinePending(FileEvent{PID: 2, Path: "/tmp/file", Op: OpOpen})
	if err := pipeline.Handle(ctx, first); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	if err := pipeline.Handle(ctx, second); err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	<-prompter.entered
	deadline := time.After(time.Second)
	for pipeline.Diagnostics().Outstanding != 2 {
		select {
		case <-deadline:
			t.Fatalf("outstanding grouped events = %d, want 2", pipeline.Diagnostics().Outstanding)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(release)
	if got := waitPipelineVerdict(t, firstResponses); got != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", got)
	}
	if got := waitPipelineVerdict(t, secondResponses); got != VerdictAllow {
		t.Fatalf("second verdict = %s, want allow", got)
	}
	deadline = time.After(time.Second)
	for pipeline.Diagnostics().Outstanding != 0 {
		select {
		case <-deadline:
			t.Fatalf("outstanding grouped events = %d, want 0", pipeline.Diagnostics().Outstanding)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestPromptCoordinatorBudgetCountsEveryGroupedEvent(t *testing.T) {
	prompter := &coordinatorPrompter{entered: make(chan FileEvent, 1), actions: make(chan string, 1)}
	h := newCoordinatorHarness(prompter, 1)
	snapshot := coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)
	first, firstResponses := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	second, secondResponses := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), first, nil, snapshot); !handled || !handedOff {
		t.Fatal("first event was not admitted")
	}
	waitCoordinatorPrompt(t, prompter)
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), second, nil, snapshot); !handled || handedOff {
		t.Fatal("over-budget duplicate was not denied immediately")
	}
	if got := waitCoordinatorVerdict(t, secondResponses); got != VerdictDeny {
		t.Fatalf("over-budget verdict = %s, want deny", got)
	}
	prompter.actions <- ActionAllow
	if got := waitCoordinatorVerdict(t, firstResponses); got != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", got)
	}
}

func TestPromptCoordinatorReevaluatesSnapshotRevisionAndDefaultAction(t *testing.T) {
	prompter := &coordinatorPrompter{entered: make(chan FileEvent, 2), actions: make(chan string, 2)}
	h := newCoordinatorHarness(prompter, 4)
	firstSnapshot := coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)
	pending, responses := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), pending, nil, firstSnapshot); !handled || !handedOff {
		t.Fatal("event was not admitted")
	}
	waitCoordinatorPrompt(t, prompter)

	askAgain := coordinatorSnapshot("profile", 2, profile.DefaultActionAsk)
	h.coordinator.SnapshotReplaced(askAgain)
	h.coordinator.mu.Lock()
	for _, group := range h.coordinator.groups {
		if group.snapshot != askAgain {
			h.coordinator.mu.Unlock()
			t.Fatal("Ask reevaluation did not replace the group revision")
		}
	}
	h.coordinator.mu.Unlock()

	h.coordinator.SnapshotReplaced(coordinatorSnapshot("profile", 3, profile.DefaultActionPermit))
	if got := waitCoordinatorVerdict(t, responses); got != VerdictAllow {
		t.Fatalf("default-action reevaluation verdict = %s, want allow", got)
	}
}

func TestPromptCoordinatorRuleUpdateResolvesOpenGroup(t *testing.T) {
	prompter := &coordinatorPrompter{entered: make(chan FileEvent, 1), actions: make(chan string, 1)}
	h := newCoordinatorHarness(prompter, 4)
	pending, responses := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), pending, nil, coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)); !handled || !handedOff {
		t.Fatal("event was not admitted")
	}
	waitCoordinatorPrompt(t, prompter)
	h.coordinator.SnapshotReplaced(coordinatorSnapshot("profile", 2, profile.DefaultActionAsk, FormatRule("/tmp/file", VerdictAllow)))
	if got := waitCoordinatorVerdict(t, responses); got != VerdictAllow {
		t.Fatalf("rule-update verdict = %s, want allow", got)
	}
}

func TestPromptCoordinatorTimeoutAndClosingDeny(t *testing.T) {
	prompter := coordinatorPrompterFunc(func(_ context.Context, _ FileEvent, timeout time.Duration) (string, bool) {
		time.Sleep(timeout)
		return "", false
	})
	h := newCoordinatorHarness(prompter, 4)
	snapshot := coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)
	pending, responses := coordinatorPending(FileEvent{Path: "/tmp/timeout", Op: OpOpen})
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), pending, nil, snapshot); !handled || !handedOff {
		t.Fatal("timeout event was not admitted")
	}
	if got := waitCoordinatorVerdict(t, responses); got != VerdictDeny {
		t.Fatalf("timeout verdict = %s, want deny", got)
	}

	h.coordinator.Close()
	newPending, newResponses := coordinatorPending(FileEvent{Path: "/tmp/closing", Op: OpOpen})
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), newPending, nil, snapshot); !handled || handedOff {
		t.Fatal("closing coordinator accepted ownership transfer")
	}
	if got := waitCoordinatorVerdict(t, newResponses); got != VerdictDeny {
		t.Fatalf("closing verdict = %s, want deny", got)
	}
}

// TestPromptCoordinatorCountsTimeouts asserts a prompt abandoned to the default
// deny is counted as a timeout (§15.16), while an explicitly answered block is
// not — the two are otherwise indistinguishable in the verdict alone.
func TestPromptCoordinatorCountsTimeouts(t *testing.T) {
	timeoutPrompter := coordinatorPrompterFunc(func(_ context.Context, _ FileEvent, timeout time.Duration) (string, bool) {
		time.Sleep(timeout)
		return "", false
	})
	h := newCoordinatorHarness(timeoutPrompter, 4)
	snapshot := coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)
	pending, responses := coordinatorPending(FileEvent{Path: "/tmp/timeout", Op: OpOpen})
	h.coordinator.Admit(context.Background(), pending, nil, snapshot)
	if got := waitCoordinatorVerdict(t, responses); got != VerdictDeny {
		t.Fatalf("timeout verdict = %s, want deny", got)
	}
	if got := h.coordinator.Diagnostics().Timeouts; got != 1 {
		t.Fatalf("timeouts after one abandoned prompt = %d, want 1", got)
	}

	// An explicit block must not inflate the timeout counter.
	denyPrompter := coordinatorPrompterFunc(func(_ context.Context, _ FileEvent, _ time.Duration) (string, bool) {
		return ActionDeny, true
	})
	h = newCoordinatorHarness(denyPrompter, 4)
	pending, responses = coordinatorPending(FileEvent{Path: "/tmp/explicit", Op: OpOpen})
	h.coordinator.Admit(context.Background(), pending, nil, snapshot)
	if got := waitCoordinatorVerdict(t, responses); got != VerdictDeny {
		t.Fatalf("explicit verdict = %s, want deny", got)
	}
	if got := h.coordinator.Diagnostics().Timeouts; got != 0 {
		t.Fatalf("timeouts after explicit block = %d, want 0", got)
	}
}
