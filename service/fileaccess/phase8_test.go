//go:build linux

package fileaccess

import (
	"context"
	"testing"

	"github.com/safing/portmaster/service/mgr"
)

type phase8DiagnosticSource struct {
	mount    MountDiagnostics
	reader   ReaderDiagnostics
	response ResponseWriterDiagnostics
}

func (s *phase8DiagnosticSource) Run(context.Context, PendingHandler) error { return nil }
func (s *phase8DiagnosticSource) Close() error                              { return nil }
func (s *phase8DiagnosticSource) SetWatchPaths([]string) error              { return nil }
func (s *phase8DiagnosticSource) MountDiagnostics() MountDiagnostics        { return s.mount }
func (s *phase8DiagnosticSource) ReaderDiagnostics() ReaderDiagnostics      { return s.reader }
func (s *phase8DiagnosticSource) ResponseDiagnostics() ResponseWriterDiagnostics {
	return s.response
}

func TestConfiguredDecisionPipelineConfigUsesDefaultsAndOverrides(t *testing.T) {
	previousWorkers := cfgOptionDecisionWorkers
	previousQueue := cfgOptionDecisionQueue
	previousOutstanding := cfgOptionOutstanding
	previousAsk := cfgOptionProfileAsk
	t.Cleanup(func() {
		cfgOptionDecisionWorkers = previousWorkers
		cfgOptionDecisionQueue = previousQueue
		cfgOptionOutstanding = previousOutstanding
		cfgOptionProfileAsk = previousAsk
	})
	cfgOptionDecisionWorkers = func() int64 { return 7 }
	cfgOptionDecisionQueue = func() int64 { return 99 }
	cfgOptionOutstanding = func() int64 { return 123 }
	cfgOptionProfileAsk = func() int64 { return 8 }

	got := configuredDecisionPipelineConfig()
	if got != (DecisionPipelineConfig{Workers: 7, QueueCapacity: 99, OutstandingLimit: 123, PerProfileAskLimit: 8}) {
		t.Fatalf("unexpected effective config: %+v", got)
	}
}

func TestPipelineSettingsValidationRejectsUnsafeValues(t *testing.T) {
	if err := validateIntRange("workers", minimumDecisionWorkers, maximumDecisionWorkers)(int64(0)); err == nil {
		t.Fatal("expected worker lower bound error")
	}
	if err := validateIntRange("workers", minimumDecisionWorkers, maximumDecisionWorkers)(int64(maximumDecisionWorkers + 1)); err == nil {
		t.Fatal("expected worker upper bound error")
	}
	if err := validateIntRange("workers", minimumDecisionWorkers, maximumDecisionWorkers)(int64(4)); err != nil {
		t.Fatalf("valid worker count rejected: %v", err)
	}
}

func TestDiagnosticsCopiesSensitiveDescriptorIdentitiesAndCreatesWarnings(t *testing.T) {
	source := &phase8DiagnosticSource{
		mount: MountDiagnostics{PartialCoverage: true},
		reader: ReaderDiagnostics{
			AccountedDescriptors:      []int32{10},
			FailedResponseDescriptors: []int32{11},
			QueueOverflowCount:        1,
			DescriptorPressure:        true,
			UnresolvedPathDenyCount:   1,
		},
		response: ResponseWriterDiagnostics{CurrentFD: -1, FatalError: "write failed"},
	}
	fa := &FileAccess{
		source:                  source,
		effectivePipelineConfig: DefaultDecisionPipelineConfig(),
	}
	diagnostics := fa.Diagnostics()
	if diagnostics.LifecycleState != "running" {
		t.Fatalf("lifecycle state = %q, want running", diagnostics.LifecycleState)
	}
	if len(diagnostics.Reader.AccountedDescriptors) != 0 || len(diagnostics.Reader.FailedResponseDescriptors) != 0 {
		t.Fatalf("public diagnostics leaked descriptor identities: %+v", diagnostics.Reader)
	}
	if diagnostics.FailedResponseCount != 1 {
		t.Fatalf("failed response count = %d, want 1", diagnostics.FailedResponseCount)
	}
	if len(diagnostics.Warnings) < 5 {
		t.Fatalf("warnings = %+v, want coverage, response, overflow, pressure and unresolved path warnings", diagnostics.Warnings)
	}
	if source.reader.AccountedDescriptors[0] != 10 || source.reader.FailedResponseDescriptors[0] != 11 {
		t.Fatal("diagnostics mutated source-owned descriptor data")
	}
}

func TestWarningStatesCoalesceUpdateAndClear(t *testing.T) {
	source := &phase8DiagnosticSource{mount: MountDiagnostics{PartialCoverage: true}}
	fa := &FileAccess{
		source:                  source,
		effectivePipelineConfig: DefaultDecisionPipelineConfig(),
		states:                  mgr.New("fileaccess phase8 warning states").NewStateMgr(),
		warningStates:           make(map[string]DegradedWarning),
	}
	fa.refreshWarningStates()
	states := fa.States().Export().States
	if len(states) != 1 || states[0].ID != "fileaccess/partial-mount-coverage" {
		t.Fatalf("unexpected active warning states: %+v", states)
	}
	fa.refreshWarningStates()
	if got := fa.States().Export().States; len(got) != 1 || got[0].ID != states[0].ID {
		t.Fatalf("identical warning did not coalesce: %+v", got)
	}
	source.mount.PartialCoverage = false
	fa.refreshWarningStates()
	if got := fa.States().Export().States; len(got) != 0 {
		t.Fatalf("recovered warning was not cleared: %+v", got)
	}
}

func TestShutdownMarkRemovalFailureWarningSurvivesClosed(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	lifecycle.BeginClosing(context.Background())
	lifecycle.PublishClosed(nil)
	fa := &FileAccess{
		source:                  &phase8DiagnosticSource{},
		lifecycle:               lifecycle,
		effectivePipelineConfig: DefaultDecisionPipelineConfig(),
		states:                  mgr.New("fileaccess phase8 shutdown warning states").NewStateMgr(),
		warningStates:           make(map[string]DegradedWarning),
		shutdownDiagnostics: ShutdownDiagnostics{Marks: MarkRemovalDiagnostics{
			Final:    true,
			Complete: false,
			Failures: []MarkRemovalFailure{{MountID: 7, MountPath: "/scope", Error: "injected removal failure"}},
		}},
	}

	if diagnostics := fa.Diagnostics(); diagnostics.Shutdown.State != LifecycleClosed || len(diagnostics.Shutdown.Marks.Failures) != 1 || !hasWarning(diagnostics.Warnings, "shutdown-mark-removal-failed") {
		t.Fatalf("closed shutdown lost its mark removal warning: %+v", diagnostics)
	}
	fa.refreshWarningStates()
	if states := fa.States().Export().States; len(states) != 1 || states[0].ID != "fileaccess/shutdown-mark-removal-failed" {
		t.Fatalf("mark removal warning was not published through manager state: %+v", states)
	}

	fa.shutdownMu.Lock()
	fa.shutdownDiagnostics.Marks = MarkRemovalDiagnostics{Final: true, Complete: true}
	fa.shutdownMu.Unlock()
	fa.refreshWarningStates()
	if diagnostics := fa.Diagnostics(); hasWarning(diagnostics.Warnings, "shutdown-mark-removal-failed") {
		t.Fatalf("successful final mark removal retained warning: %+v", diagnostics.Warnings)
	}
	if states := fa.States().Export().States; len(states) != 0 {
		t.Fatalf("recovered mark removal warning was not cleared: %+v", states)
	}
}

func hasWarning(warnings []DegradedWarning, id string) bool {
	for _, warning := range warnings {
		if warning.ID == id {
			return true
		}
	}
	return false
}
