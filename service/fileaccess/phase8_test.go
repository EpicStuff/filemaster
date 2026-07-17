//go:build linux

package fileaccess

import (
	"context"
	"os"
	"path/filepath"
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

type rootAskEvidenceTestInstance struct {
	dataDir string
}

func (i rootAskEvidenceTestInstance) DataDir() string { return i.dataDir }

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

func TestRootAskGateRequiresTrustedCompleteEvidence(t *testing.T) {
	previousPaths := cfgOptionWatchPaths
	previousRequested := cfgOptionRootAskGate
	rootAskRolloutState.RLock()
	previousEvidence := rootAskRolloutState.evidence
	previousStore := rootAskRolloutState.store
	previousPersisted := rootAskRolloutState.persisted
	previousLoadErr := rootAskRolloutState.loadErr
	previousGeneration := rootAskRolloutState.storeGeneration
	rootAskRolloutState.RUnlock()
	t.Cleanup(func() {
		cfgOptionWatchPaths = previousPaths
		cfgOptionRootAskGate = previousRequested
		rootAskRolloutState.Lock()
		rootAskRolloutState.evidence = previousEvidence
		rootAskRolloutState.store = previousStore
		rootAskRolloutState.persisted = previousPersisted
		rootAskRolloutState.loadErr = previousLoadErr
		rootAskRolloutState.storeGeneration = previousGeneration
		rootAskRolloutState.Unlock()
	})

	cfgOptionWatchPaths = func() []string { return []string{"/"} }
	cfgOptionRootAskGate = func() bool { return true }
	fa := &FileAccess{
		instance:                rootAskEvidenceTestInstance{dataDir: t.TempDir()},
		effectivePipelineConfig: DefaultDecisionPipelineConfig(),
	}
	fa.configureRootAskRolloutEvidence()
	if status := fa.RootAskGateStatus(); status.Open || len(status.Reasons) == 0 {
		t.Fatalf("gate opened without evidence: %+v", status)
	}

	// This compatibility test hook resembles a browser attempting to provide
	// evidence. It must not open the gate because it was never persisted.
	SetRootAskRolloutEvidence(RootAskRolloutEvidence{
		ImplementationVersion:  rootAskRolloutImplementationVersion,
		SettingsFingerprint:    rootAskSettingsFingerprint(DefaultDecisionPipelineConfig()),
		EnvironmentFingerprint: rootAskEnvironmentFingerprint(),
		ConfinedIntegration:    true,
		SystemdPID1Host:        true,
		RootPipelineBenchmark:  true,
		ShutdownVerified:       true,
		PersistenceHealthy:     true,
		PromptGroupingHealthy:  true,
	})
	if status := fa.RootAskGateStatus(); status.Open {
		t.Fatalf("in-memory evidence opened the gate: %+v", status)
	}

	if err := fa.RecordRootAskRolloutEvidence(RootAskRolloutEvidence{
		ConfinedIntegration:   true,
		SystemdPID1Host:       true,
		RootPipelineBenchmark: true,
		ShutdownVerified:      true,
		PersistenceHealthy:    true,
		PromptGroupingHealthy: true,
	}); err != nil {
		t.Fatalf("record trusted evidence: %v", err)
	}
	if status := fa.RootAskGateStatus(); !status.Open {
		t.Fatalf("gate remained closed with complete persisted evidence: %+v", status)
	}
	if info, err := os.Stat(filepath.Join(fa.instance.(rootAskEvidenceTestInstance).DataDir(), rootAskRolloutEvidenceFilename)); err != nil {
		t.Fatalf("stat persisted evidence: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("persisted evidence mode = %o, want 0600", info.Mode().Perm())
	}

	reloaded := &FileAccess{
		instance:                fa.instance,
		effectivePipelineConfig: DefaultDecisionPipelineConfig(),
	}
	reloaded.configureRootAskRolloutEvidence()
	if status := reloaded.RootAskGateStatus(); !status.Open {
		t.Fatalf("persisted evidence did not survive reload: %+v", status)
	}

	store := rootAskEvidenceFileStore{path: filepath.Join(fa.instance.(rootAskEvidenceTestInstance).DataDir(), rootAskRolloutEvidenceFilename)}
	staleEnvironment := rootAskEvidence()
	staleEnvironment.EnvironmentFingerprint = "different-kernel-environment"
	if err := store.Save(staleEnvironment); err != nil {
		t.Fatalf("store stale environment evidence: %v", err)
	}
	reloaded.configureRootAskRolloutEvidence()
	if status := reloaded.RootAskGateStatus(); status.Open || !rootAskGateReason(status, "environment_evidence_stale") {
		t.Fatalf("kernel environment change did not invalidate evidence: %+v", status)
	}

	if err := fa.RecordRootAskRolloutEvidence(RootAskRolloutEvidence{
		ConfinedIntegration:   true,
		SystemdPID1Host:       true,
		RootPipelineBenchmark: true,
		ShutdownVerified:      true,
		PersistenceHealthy:    true,
		PromptGroupingHealthy: true,
	}); err != nil {
		t.Fatalf("restore current evidence: %v", err)
	}
	reloaded.configureRootAskRolloutEvidence()
	reloaded.effectivePipelineConfig.Workers++
	if status := reloaded.RootAskGateStatus(); status.Open || !rootAskGateReason(status, "settings_evidence_stale") {
		t.Fatalf("settings change did not invalidate evidence: %+v", status)
	}
}

func rootAskGateReason(status RootAskGateStatus, reason string) bool {
	for _, candidate := range status.Reasons {
		if candidate == reason {
			return true
		}
	}
	return false
}

func TestRootAskGateReportsEvidencePersistenceFailure(t *testing.T) {
	previousPaths := cfgOptionWatchPaths
	previousRequested := cfgOptionRootAskGate
	rootAskRolloutState.RLock()
	previousEvidence := rootAskRolloutState.evidence
	previousStore := rootAskRolloutState.store
	previousPersisted := rootAskRolloutState.persisted
	previousLoadErr := rootAskRolloutState.loadErr
	previousGeneration := rootAskRolloutState.storeGeneration
	rootAskRolloutState.RUnlock()
	t.Cleanup(func() {
		cfgOptionWatchPaths = previousPaths
		cfgOptionRootAskGate = previousRequested
		rootAskRolloutState.Lock()
		rootAskRolloutState.evidence = previousEvidence
		rootAskRolloutState.store = previousStore
		rootAskRolloutState.persisted = previousPersisted
		rootAskRolloutState.loadErr = previousLoadErr
		rootAskRolloutState.storeGeneration = previousGeneration
		rootAskRolloutState.Unlock()
	})

	cfgOptionWatchPaths = func() []string { return []string{"/"} }
	cfgOptionRootAskGate = func() bool { return true }
	dataFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(dataFile, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("create invalid data directory: %v", err)
	}
	fa := &FileAccess{
		instance:                rootAskEvidenceTestInstance{dataDir: dataFile},
		effectivePipelineConfig: DefaultDecisionPipelineConfig(),
	}
	fa.configureRootAskRolloutEvidence()
	status := fa.RootAskGateStatus()
	if status.Open || !rootAskGateReason(status, "rollout_evidence_persistence_error") {
		t.Fatalf("failed evidence store did not close the gate visibly: %+v", status)
	}
	if err := fa.RecordRootAskRolloutEvidence(RootAskRolloutEvidence{}); err == nil {
		t.Fatal("recording through a failed evidence store succeeded")
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
