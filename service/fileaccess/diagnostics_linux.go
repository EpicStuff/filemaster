//go:build linux

package fileaccess

import (
	"sort"

	"github.com/safing/portmaster/service/mgr"
)

// FileAccessSettingsDiagnostics separates requested settings from the active
// pipeline. Restart-required settings remain visible as requested values while
// Effective records the limits that currently own descriptors and workers.
type FileAccessSettingsDiagnostics struct {
	WatchPaths              []string
	EffectivePipelineConfig DecisionPipelineConfig
}

// DegradedWarning is a compact, stable warning suitable for API and UI
// consumption. Details intentionally avoid paths and descriptor identities.
type DegradedWarning struct {
	ID       string
	Severity string
	Message  string
}

// FileAccessDiagnostics is a race-safe, value-only diagnostic snapshot. It
// deliberately composes producers after each producer has copied its own maps
// and slices, so API serialization never holds fanotify or policy locks.
type FileAccessDiagnostics struct {
	Settings            FileAccessSettingsDiagnostics
	Mount               MountDiagnostics
	Reader              ReaderDiagnostics
	Response            ResponseWriterDiagnostics
	FailedResponseCount int
	Decision            DecisionPipelineDiagnostics
	Prompt              PromptCoordinatorDiagnostics
	Observation         ObservationDiagnostics
	PermanentRules      map[string]RulePersistenceDiagnostics
	Shutdown            ShutdownDiagnostics
	LifecycleState      string
	Warnings            []DegradedWarning
}

type mountDiagnosticSource interface {
	MountDiagnostics() MountDiagnostics
}

type readerDiagnosticSource interface {
	ReaderDiagnostics() ReaderDiagnostics
}

type responseDiagnosticSource interface {
	ResponseDiagnostics() ResponseWriterDiagnostics
}

type observationDiagnosticSource interface {
	ObservationDiagnostics() ObservationDiagnostics
}

// Diagnostics returns compact diagnostics by default. Descriptor identities
// are intentionally excluded from the exported snapshot; the source's local
// detailed diagnostics remain available only to privileged debugging code.
func (fa *FileAccess) Diagnostics() FileAccessDiagnostics {
	diagnostics := FileAccessDiagnostics{
		Settings: FileAccessSettingsDiagnostics{
			WatchPaths:              append([]string(nil), resolveWatchPaths()...),
			EffectivePipelineConfig: fa.effectivePipelineConfig,
		},
		Shutdown: cloneShutdownDiagnostics(fa.ShutdownDiagnostics()),
	}
	if source, ok := fa.source.(mountDiagnosticSource); ok {
		diagnostics.Mount = source.MountDiagnostics()
	}
	if source, ok := fa.source.(readerDiagnosticSource); ok {
		diagnostics.Reader = source.ReaderDiagnostics()
		diagnostics.FailedResponseCount = len(diagnostics.Reader.FailedResponseDescriptors)
		diagnostics.Reader.AccountedDescriptors = nil
		diagnostics.Reader.FailedResponseDescriptors = nil
	}
	if source, ok := fa.source.(responseDiagnosticSource); ok {
		diagnostics.Response = source.ResponseDiagnostics()
	}
	if fa.pipeline != nil {
		diagnostics.Decision = fa.pipeline.Diagnostics()
	}
	if handler, ok := fa.handler.(observationDiagnosticSource); ok {
		diagnostics.Observation = handler.ObservationDiagnostics()
	}
	if fa.profileHandler != nil {
		if coordinator := fa.profileHandler.coordinator(); coordinator != nil {
			diagnostics.Prompt = coordinator.Diagnostics()
		}
		if persistence := fa.profileHandler.rulePersistence(); persistence != nil {
			diagnostics.PermanentRules = persistence.Diagnostics()
		}
	}
	if diagnostics.PermanentRules == nil {
		diagnostics.PermanentRules = make(map[string]RulePersistenceDiagnostics)
	}
	diagnostics.LifecycleState = diagnostics.Shutdown.State.String()
	diagnostics.Warnings = diagnosticsWarnings(diagnostics)
	return diagnostics
}

func diagnosticsWarnings(diagnostics FileAccessDiagnostics) []DegradedWarning {
	warnings := make([]DegradedWarning, 0, 10)
	appendWarning := func(id, severity, message string) {
		warnings = append(warnings, DegradedWarning{ID: id, Severity: severity, Message: message})
	}
	if diagnostics.Mount.PartialCoverage {
		appendWarning("partial-mount-coverage", "error", "File access coverage is partial because one or more required mount marks are missing.")
	}
	if diagnostics.Reader.Fatal {
		appendWarning("reader-fatal", "error", "The fanotify reader is in a fatal state; enforcement cannot be considered complete.")
	}
	if diagnostics.Response.FatalError != "" {
		appendWarning("response-writer-fatal", "error", "A fanotify permission response failed and retained event ownership requires attention.")
	}
	if diagnostics.Reader.QueueOverflowCount > 0 {
		appendWarning("kernel-queue-overflow", "error", "The kernel fanotify queue overflowed; some file access events may not have been observed.")
	}
	if diagnostics.Reader.EMFILECount > 0 || diagnostics.Reader.DescriptorPressure {
		appendWarning("descriptor-pressure", "error", "Descriptor pressure prevented normal fanotify reads; reduce load or increase the available descriptor budget.")
	}
	if diagnostics.Reader.UnresolvedPathDenyCount > 0 {
		appendWarning("unresolved-path-deny", "warning", "File access events with unresolved paths were denied for safety.")
	}
	if diagnostics.Observation.Dropped > 0 {
		appendWarning("observation-drops", "warning", "The observation feed is saturated; some file access records were dropped and are not visible in the activity log. Enforcement is unaffected.")
	}
	if diagnostics.FailedResponseCount > 0 {
		appendWarning("retained-response-ownership", "error", "One or more permission events have a retained failed response owner.")
	}
	for _, persistence := range diagnostics.PermanentRules {
		if persistence.PersistentFailure {
			appendWarning("permanent-rule-persistence", "error", "A permanent file access rule is effective in memory but has not been saved durably.")
			break
		}
	}
	if diagnostics.Shutdown.State == LifecycleClosing && len(diagnostics.Shutdown.Unresolved) > 0 {
		appendWarning("incomplete-shutdown", "error", "Controlled shutdown still has unresolved file access ownership.")
	}
	// Mark-removal failures remain enforcement-relevant after the reader and
	// group have closed. Errors retains history, whereas Failures describes the
	// current unsuccessful final removal state and clears after verified recovery.
	if len(diagnostics.Shutdown.Marks.Failures) > 0 || (diagnostics.Shutdown.State != LifecycleRunning && !diagnostics.Shutdown.Marks.Complete) {
		appendWarning("shutdown-mark-removal-failed", "error", "Controlled shutdown could not remove every fanotify mark; enforcement coverage was not cleanly released.")
	}
	sort.Slice(warnings, func(i, j int) bool { return warnings[i].ID < warnings[j].ID })
	return warnings
}

func (fa *FileAccess) refreshWarningStates() {
	if fa.states == nil {
		return
	}
	warnings := fa.Diagnostics().Warnings
	next := make(map[string]DegradedWarning, len(warnings))
	for _, warning := range warnings {
		next[warning.ID] = warning
	}

	fa.warningMu.Lock()
	previous := fa.warningStates
	if previous == nil {
		previous = make(map[string]DegradedWarning)
	}
	for id, warning := range next {
		if prior, ok := previous[id]; ok && prior == warning {
			continue
		}
		fa.states.Add(mgr.State{
			ID:      "fileaccess/" + id,
			Name:    "File Access Enforcement",
			Message: warning.Message,
			Type:    warningStateType(warning.Severity),
		})
	}
	for id := range previous {
		if _, ok := next[id]; !ok {
			fa.states.Remove("fileaccess/" + id)
		}
	}
	fa.warningStates = next
	fa.warningMu.Unlock()
}

func warningStateType(severity string) mgr.StateType {
	if severity == "error" {
		return mgr.StateTypeError
	}
	return mgr.StateTypeWarning
}
