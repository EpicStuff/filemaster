//go:build linux

package fileaccess

import (
	"sort"
	"strconv"
	"sync"
)

const rootAskRolloutImplementationVersion = "fanotify-phase8-v1"

// RootAskRolloutEvidence is supplied only by a trusted verification harness.
// The frontend can request the gate but cannot manufacture this evidence.
// Evidence is versioned so an implementation change closes the gate again.
type RootAskRolloutEvidence struct {
	ImplementationVersion string
	SettingsFingerprint   string
	ConfinedIntegration   bool
	SystemdPID1Host       bool
	RootPipelineBenchmark bool
	ShutdownVerified      bool
	PersistenceHealthy    bool
	PromptGroupingHealthy bool
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
	evidence RootAskRolloutEvidence
}

// SetRootAskRolloutEvidence is a harness-only backend entry point. It is not
// registered as an API endpoint; host verification records evidence through
// a trusted process rather than a browser setting.
func SetRootAskRolloutEvidence(evidence RootAskRolloutEvidence) {
	rootAskRolloutState.Lock()
	rootAskRolloutState.evidence = evidence
	rootAskRolloutState.Unlock()
}

func rootAskEvidence() RootAskRolloutEvidence {
	rootAskRolloutState.RLock()
	evidence := rootAskRolloutState.evidence
	rootAskRolloutState.RUnlock()
	return evidence
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
	if status.Evidence.ImplementationVersion != rootAskRolloutImplementationVersion {
		status.Reasons = append(status.Reasons, "implementation_evidence_stale")
	}
	if status.Evidence.SettingsFingerprint != rootAskSettingsFingerprint(diagnostics.Settings.EffectivePipelineConfig) {
		status.Reasons = append(status.Reasons, "settings_evidence_stale")
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
