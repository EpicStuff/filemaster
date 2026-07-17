//go:build linux

package fileaccess

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/safing/portmaster/base/utils/renameio"
)

const rootAskRolloutImplementationVersion = "fanotify-phase8-v1"

const rootAskRolloutEvidenceFilename = "fileaccess-root-ask-rollout-evidence.json"

// RootAskRolloutEvidence is supplied only by a trusted verification harness.
// The frontend can request the gate but cannot manufacture this evidence.
// Evidence is versioned so an implementation change closes the gate again.
type RootAskRolloutEvidence struct {
	ImplementationVersion  string
	SettingsFingerprint    string
	EnvironmentFingerprint string
	RecordedAt             time.Time
	ConfinedIntegration    bool
	SystemdPID1Host        bool
	RootPipelineBenchmark  bool
	ShutdownVerified       bool
	PersistenceHealthy     bool
	PromptGroupingHealthy  bool
}

// RootAskGateStatus is safe to expose to unprivileged callers. Reasons are
// machine-readable and deliberately contain no paths or profile data.
type RootAskGateStatus struct {
	Requested bool
	Open      bool
	Reasons   []string
	Evidence  RootAskRolloutEvidence
}

var rootAskRolloutState struct {
	sync.RWMutex
	evidence        RootAskRolloutEvidence
	store           rootAskEvidenceStore
	persisted       bool
	loadErr         error
	storeGeneration uint64
}

type rootAskEvidenceStore interface {
	Load() (RootAskRolloutEvidence, bool, error)
	Save(RootAskRolloutEvidence) error
}

type rootAskEvidenceFileStore struct {
	path string
}

func (s rootAskEvidenceFileStore) Load() (RootAskRolloutEvidence, bool, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return RootAskRolloutEvidence{}, false, nil
	}
	if err != nil {
		return RootAskRolloutEvidence{}, false, fmt.Errorf("read root Ask rollout evidence: %w", err)
	}

	var evidence RootAskRolloutEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return RootAskRolloutEvidence{}, false, fmt.Errorf("decode root Ask rollout evidence: %w", err)
	}
	return evidence, true, nil
}

func (s rootAskEvidenceFileStore) Save(evidence RootAskRolloutEvidence) error {
	data, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("encode root Ask rollout evidence: %w", err)
	}
	if err := renameio.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("write root Ask rollout evidence: %w", err)
	}
	return nil
}

type rootAskEvidenceDataDir interface {
	DataDir() string
}

func (fa *FileAccess) configureRootAskRolloutEvidence() {
	instance, ok := fa.instance.(rootAskEvidenceDataDir)
	if !ok || instance.DataDir() == "" {
		return
	}

	store := rootAskEvidenceFileStore{path: filepath.Join(instance.DataDir(), rootAskRolloutEvidenceFilename)}
	evidence, persisted, err := store.Load()
	rootAskRolloutState.Lock()
	rootAskRolloutState.evidence = evidence
	rootAskRolloutState.store = store
	rootAskRolloutState.persisted = persisted && err == nil
	rootAskRolloutState.loadErr = err
	rootAskRolloutState.storeGeneration++
	rootAskRolloutState.Unlock()
}

// SetRootAskRolloutEvidence is an in-memory test hook. It deliberately does
// not make the gate eligible to open: only RecordRootAskRolloutEvidence writes
// trusted evidence to Filemaster's private data directory.
func SetRootAskRolloutEvidence(evidence RootAskRolloutEvidence) {
	rootAskRolloutState.Lock()
	rootAskRolloutState.evidence = evidence
	rootAskRolloutState.persisted = false
	rootAskRolloutState.loadErr = nil
	rootAskRolloutState.Unlock()
}

func rootAskEvidence() RootAskRolloutEvidence {
	rootAskRolloutState.RLock()
	evidence := rootAskRolloutState.evidence
	rootAskRolloutState.RUnlock()
	return evidence
}

func rootAskEvidencePersistence() (bool, error) {
	rootAskRolloutState.RLock()
	persisted := rootAskRolloutState.persisted
	err := rootAskRolloutState.loadErr
	rootAskRolloutState.RUnlock()
	return persisted, err
}

// RecordRootAskRolloutEvidence is a backend-only host-verification entry
// point. It is intentionally not registered as an API endpoint or config
// option, so a browser can request root Ask mode but cannot open the gate.
// Version, current effective settings, and current kernel environment are
// derived here rather than trusted from the caller.
func (fa *FileAccess) RecordRootAskRolloutEvidence(evidence RootAskRolloutEvidence) error {
	config := fa.effectivePipelineConfig
	if config == (DecisionPipelineConfig{}) {
		config = configuredDecisionPipelineConfig()
	}
	evidence.ImplementationVersion = rootAskRolloutImplementationVersion
	evidence.SettingsFingerprint = rootAskSettingsFingerprint(config)
	evidence.EnvironmentFingerprint = rootAskEnvironmentFingerprint()
	evidence.RecordedAt = time.Now().UTC()

	rootAskRolloutState.RLock()
	store := rootAskRolloutState.store
	generation := rootAskRolloutState.storeGeneration
	rootAskRolloutState.RUnlock()
	if store == nil {
		return errors.New("root Ask rollout evidence has no persistent store")
	}
	if err := store.Save(evidence); err != nil {
		rootAskRolloutState.Lock()
		if rootAskRolloutState.storeGeneration == generation {
			rootAskRolloutState.loadErr = err
		}
		rootAskRolloutState.Unlock()
		return err
	}

	rootAskRolloutState.Lock()
	defer rootAskRolloutState.Unlock()
	if rootAskRolloutState.storeGeneration != generation {
		return errors.New("root Ask rollout evidence store changed during persistence")
	}
	rootAskRolloutState.evidence = evidence
	rootAskRolloutState.persisted = true
	rootAskRolloutState.loadErr = nil
	return nil
}

func rootScopeConfigured() bool {
	for _, path := range resolveWatchPaths() {
		if path == "/" {
			return true
		}
	}
	return false
}

func (fa *FileAccess) RootAskGateStatus() RootAskGateStatus {
	return fa.rootAskGateStatus(fa.Diagnostics())
}

func (fa *FileAccess) rootAskGateStatus(diagnostics FileAccessDiagnostics) RootAskGateStatus {
	persisted, persistenceErr := rootAskEvidencePersistence()
	status := RootAskGateStatus{
		Requested: diagnostics.Settings.RequestedRootAsk,
		Evidence:  rootAskEvidence(),
	}
	if !rootScopeConfigured() {
		status.Reasons = append(status.Reasons, "root_scope_not_configured")
	}
	if !status.Requested {
		status.Reasons = append(status.Reasons, "not_requested")
	}
	if !persisted {
		status.Reasons = append(status.Reasons, "trusted_evidence_not_persisted")
	}
	if persistenceErr != nil {
		status.Reasons = append(status.Reasons, "rollout_evidence_persistence_error")
	}
	if status.Evidence.ImplementationVersion != rootAskRolloutImplementationVersion {
		status.Reasons = append(status.Reasons, "implementation_evidence_stale")
	}
	if status.Evidence.SettingsFingerprint != rootAskSettingsFingerprint(diagnostics.Settings.EffectivePipelineConfig) {
		status.Reasons = append(status.Reasons, "settings_evidence_stale")
	}
	if status.Evidence.EnvironmentFingerprint != rootAskEnvironmentFingerprint() {
		status.Reasons = append(status.Reasons, "environment_evidence_stale")
	}
	if !status.Evidence.ConfinedIntegration {
		status.Reasons = append(status.Reasons, "confined_integration_missing")
	}
	if !status.Evidence.SystemdPID1Host {
		status.Reasons = append(status.Reasons, "systemd_pid1_verification_missing")
	}
	if !status.Evidence.RootPipelineBenchmark {
		status.Reasons = append(status.Reasons, "root_pipeline_benchmark_missing")
	}
	if !status.Evidence.ShutdownVerified {
		status.Reasons = append(status.Reasons, "shutdown_verification_missing")
	}
	if !status.Evidence.PersistenceHealthy {
		status.Reasons = append(status.Reasons, "persistence_verification_missing")
	}
	if !status.Evidence.PromptGroupingHealthy {
		status.Reasons = append(status.Reasons, "prompt_grouping_verification_missing")
	}
	if diagnostics.Mount.PartialCoverage {
		status.Reasons = append(status.Reasons, "partial_mount_coverage")
	}
	if diagnostics.Reader.Fatal {
		status.Reasons = append(status.Reasons, "reader_fatal")
	}
	if diagnostics.Response.FatalError != "" {
		status.Reasons = append(status.Reasons, "response_writer_fatal")
	}
	if diagnostics.Settings.EffectivePipelineConfig.Workers <= 0 || diagnostics.Settings.EffectivePipelineConfig.QueueCapacity <= 0 || diagnostics.Settings.EffectivePipelineConfig.OutstandingLimit <= 0 || diagnostics.Settings.EffectivePipelineConfig.PerProfileAskLimit <= 0 {
		status.Reasons = append(status.Reasons, "pipeline_limits_invalid")
	}
	if diagnostics.Prompt.ActivePrompts < 0 {
		status.Reasons = append(status.Reasons, "prompt_grouping_unavailable")
	}
	for _, persistence := range diagnostics.PermanentRules {
		if persistence.PersistentFailure {
			status.Reasons = append(status.Reasons, "persistent_rule_failure")
			break
		}
	}
	sort.Strings(status.Reasons)
	status.Open = len(status.Reasons) == 0
	return status
}

func rootAskSettingsFingerprint(config DecisionPipelineConfig) string {
	return rootAskRolloutImplementationVersion + ":" +
		strconv.Itoa(config.Workers) + ":" + strconv.Itoa(config.QueueCapacity) + ":" +
		strconv.FormatInt(config.OutstandingLimit, 10) + ":" + strconv.Itoa(config.PerProfileAskLimit)
}

func rootAskEnvironmentFingerprint() string {
	kernelRelease, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return runtime.GOOS + ":" + runtime.GOARCH + ":kernel-release-unavailable"
	}
	return runtime.GOOS + ":" + runtime.GOARCH + ":" + strings.TrimSpace(string(kernelRelease))
}
