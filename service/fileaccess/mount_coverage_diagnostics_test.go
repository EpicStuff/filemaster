//go:build linux

package fileaccess

import (
	"strings"
	"testing"
)

func warningByID(t *testing.T, warnings []DegradedWarning, id string) DegradedWarning {
	t.Helper()

	for _, warning := range warnings {
		if warning.ID == id {
			return warning
		}
	}
	t.Fatalf("warning %q not present in %+v", id, warnings)
	return DegradedWarning{}
}

// A partial-coverage report that says only "coverage is partial" cannot be acted
// on. Operators need the scope that was configured, what it canonicalised to,
// which mounts are unmarked, and the mountinfo rows those IDs refer to.
func TestPartialCoverageWarningCarriesScopeAndMountDetail(t *testing.T) {
	source := &phase8DiagnosticSource{mount: MountDiagnostics{
		ConfiguredScopes: []string{"+ /home"},
		CanonicalScopes:  []string{"/home"},
		ActiveMountIDs:   []int{812},
		MissingMountIDs:  []int{1709, 1710},
		MountInfoEntries: []string{
			"1709 1329 0:38 /@derek/home /home rw,relatime shared:1 - btrfs /dev/nvme0n1p2 rw",
			"1710 1329 0:69 / /home/derek/.home rw,relatime shared:2 - tmpfs tmpfs rw",
		},
		PartialCoverage: true,
		CoverageKnown:   true,
	}}
	diagnostics := (&FileAccess{
		source:                  source,
		effectivePipelineConfig: DefaultDecisionPipelineConfig(),
	}).Diagnostics()

	warning := warningByID(t, diagnostics.Warnings, "partial-mount-coverage")
	for _, want := range []string{"+ /home", "/home", "1709", "1710"} {
		if !strings.Contains(warning.Details, want) {
			t.Errorf("partial coverage detail %q missing %q", warning.Details, want)
		}
	}
	if !strings.Contains(warning.Details, "btrfs") || !strings.Contains(warning.Details, "tmpfs") {
		t.Errorf("partial coverage detail %q does not include the mountinfo rows for the missing mounts", warning.Details)
	}
}

// Coverage that could not be determined must not be reported as a specific set
// of missing mounts, otherwise an empty list reads as "nothing missing".
func TestPartialCoverageWarningDistinguishesUnknownCoverage(t *testing.T) {
	source := &phase8DiagnosticSource{mount: MountDiagnostics{
		ConfiguredScopes: []string{"+ /home"},
		PartialCoverage:  true,
		CoverageKnown:    false,
		LastError:        "read /proc/self/mountinfo: permission denied",
	}}
	diagnostics := (&FileAccess{
		source:                  source,
		effectivePipelineConfig: DefaultDecisionPipelineConfig(),
	}).Diagnostics()

	warning := warningByID(t, diagnostics.Warnings, "partial-mount-coverage")
	if !strings.Contains(warning.Details, "coverage unknown") {
		t.Errorf("detail %q does not state that coverage could not be determined", warning.Details)
	}
	if !strings.Contains(warning.Details, "permission denied") {
		t.Errorf("detail %q does not carry the underlying mountinfo error", warning.Details)
	}
}

// fanotify mount marks apply to a vfsmount, not to a superblock. systemd options
// such as ProtectHome, ProtectSystem and PrivateTmp put the service in its own
// mount namespace, where the mounts it marks are clones that no other process on
// the system traverses. Enforcement is then silently absent rather than partial,
// so this has to surface as its own error rather than as ordinary coverage.
func TestMountNamespaceIsolationIsReportedAsEnforcementError(t *testing.T) {
	source := &phase8DiagnosticSource{mount: MountDiagnostics{
		ConfiguredScopes:       []string{"+ /home"},
		CanonicalScopes:        []string{"/home"},
		ActiveMountIDs:         []int{1709},
		MountNamespaceIsolated: true,
		CoverageKnown:          true,
	}}
	diagnostics := (&FileAccess{
		source:                  source,
		effectivePipelineConfig: DefaultDecisionPipelineConfig(),
	}).Diagnostics()

	warning := warningByID(t, diagnostics.Warnings, "mount-namespace-isolated")
	if warning.Severity != "error" {
		t.Errorf("severity = %q, want error: marks taken in a private namespace enforce nothing", warning.Severity)
	}
}

// An isolated namespace must not be reported as healthy just because every mount
// the service can see was marked successfully.
func TestFullCoverageInIsolatedNamespaceStillWarns(t *testing.T) {
	source := &phase8DiagnosticSource{mount: MountDiagnostics{
		ConfiguredScopes:       []string{"+ /home"},
		CanonicalScopes:        []string{"/home"},
		ActiveMountIDs:         []int{1709},
		MissingMountIDs:        nil,
		PartialCoverage:        false,
		MountNamespaceIsolated: true,
		CoverageKnown:          true,
	}}
	diagnostics := (&FileAccess{
		source:                  source,
		effectivePipelineConfig: DefaultDecisionPipelineConfig(),
	}).Diagnostics()

	warningByID(t, diagnostics.Warnings, "mount-namespace-isolated")
}
