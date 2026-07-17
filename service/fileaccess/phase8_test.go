//go:build linux

package fileaccess

import (
	"context"
	"testing"
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

func TestRootAskGateRequiresTrustedCompleteEvidence(t *testing.T) {
	previousPaths := cfgOptionWatchPaths
	previousRequested := cfgOptionRootAskGate
	previousEvidence := rootAskEvidence()
	t.Cleanup(func() {
		cfgOptionWatchPaths = previousPaths
		cfgOptionRootAskGate = previousRequested
		SetRootAskRolloutEvidence(previousEvidence)
	})
	cfgOptionWatchPaths = func() []string { return []string{"/"} }
	cfgOptionRootAskGate = func() bool { return true }
	fa := &FileAccess{effectivePipelineConfig: DefaultDecisionPipelineConfig()}
	if status := fa.RootAskGateStatus(); status.Open || len(status.Reasons) == 0 {
		t.Fatalf("gate opened without evidence: %+v", status)
	}

	SetRootAskRolloutEvidence(RootAskRolloutEvidence{
		ImplementationVersion: rootAskRolloutImplementationVersion,
		SettingsFingerprint:   rootAskSettingsFingerprint(DefaultDecisionPipelineConfig()),
		ConfinedIntegration:   true,
		SystemdPID1Host:       true,
		RootPipelineBenchmark: true,
		ShutdownVerified:      true,
		PersistenceHealthy:    true,
		PromptGroupingHealthy: true,
	})
	if status := fa.RootAskGateStatus(); !status.Open {
		t.Fatalf("gate remained closed with complete trusted evidence: %+v", status)
	}
}

func TestRootAskGateBlocksPromptAdmissionWhenClosed(t *testing.T) {
	previousPaths := cfgOptionWatchPaths
	t.Cleanup(func() { cfgOptionWatchPaths = previousPaths })
	cfgOptionWatchPaths = func() []string { return []string{"/"} }
	handler := &ProfileHandler{}
	handler.setRootAskGate(func() RootAskGateStatus { return RootAskGateStatus{} })
	if handler.rootAskAllowed() {
		t.Fatal("closed root Ask gate allowed prompt admission")
	}
}
