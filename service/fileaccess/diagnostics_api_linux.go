//go:build linux

package fileaccess

import (
	"errors"
	"sort"

	"github.com/safing/portmaster/base/api"
)

// ProtectedMountStatus is the stable dashboard-oriented summary of fanotify
// coverage for one required mount.
type ProtectedMountStatus struct {
	MountID   int      `json:"mount_id"`
	MountPath string   `json:"mount_path"`
	Status    string   `json:"status"`
	Reasons   []string `json:"reasons"`
}

const (
	mountStatusProtected = "protected"
	mountStatusPending   = "pending"
	mountStatusDegraded  = "degraded"
)

func registerFileAccessAPI() error {
	if err := api.RegisterEndpoint(api.Endpoint{
		Name:        "File Access Diagnostics",
		Description: "Returns compact fanotify coverage, pipeline, persistence, shutdown, and rollout diagnostics without sensitive descriptor identities.",
		Path:        "fileaccess/diagnostics",
		Read:        api.PermitUser,
		StructFunc: func(*api.Request) (any, error) {
			if module == nil {
				return nil, errors.New("fileaccess module is not initialized")
			}
			return module.Diagnostics(), nil
		},
	}); err != nil {
		return err
	}

	return api.RegisterEndpoint(api.Endpoint{
		Name:        "Protected Mount Status",
		Description: "Returns the current protection status for mounts required by configured file-access scopes.",
		Path:        "fileaccess/mounts",
		Read:        api.PermitUser,
		StructFunc: func(*api.Request) (any, error) {
			if module == nil {
				return nil, errors.New("fileaccess module is not initialized")
			}
			return protectedMountStatuses(module.Diagnostics()), nil
		},
	})
}

func protectedMountStatuses(diagnostics FileAccessDiagnostics) []ProtectedMountStatus {
	missing := make(map[int]struct{}, len(diagnostics.Mount.MissingMountIDs))
	for _, id := range diagnostics.Mount.MissingMountIDs {
		missing[id] = struct{}{}
	}
	dynamicGaps := make(map[int]struct{}, len(diagnostics.Mount.DynamicMountIDs))
	for _, id := range diagnostics.Mount.DynamicMountIDs {
		dynamicGaps[id] = struct{}{}
	}

	statuses := make([]ProtectedMountStatus, 0, len(diagnostics.Mount.RequiredMounts))
	for _, mount := range diagnostics.Mount.RequiredMounts {
		reasons := mountStatusReasons(diagnostics, mount.MountID, missing, dynamicGaps)
		status := mountStatusProtected
		switch {
		case diagnostics.Mount.ScopeActivationPending:
			status = mountStatusPending
		case len(reasons) > 0:
			status = mountStatusDegraded
		}
		statuses = append(statuses, ProtectedMountStatus{
			MountID:   mount.MountID,
			MountPath: mount.MountPath,
			Status:    status,
			Reasons:   reasons,
		})
	}
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].MountID < statuses[j].MountID
	})
	return statuses
}

func mountStatusReasons(diagnostics FileAccessDiagnostics, mountID int, missing, dynamicGaps map[int]struct{}) []string {
	reasons := make([]string, 0, 6)
	if diagnostics.Mount.ScopeActivationPending {
		reasons = append(reasons, "scope_activation_pending")
	}
	if !diagnostics.Mount.CoverageKnown {
		reasons = append(reasons, "coverage_unknown")
	}
	if _, ok := missing[mountID]; ok {
		reasons = append(reasons, "missing_mark")
	}
	if _, ok := dynamicGaps[mountID]; ok {
		reasons = append(reasons, "dynamic_coverage_breach")
	}
	if diagnostics.Mount.MountNamespaceIsolated {
		reasons = append(reasons, "mount_namespace_isolated")
	}
	if diagnostics.Reader.Fatal {
		reasons = append(reasons, "reader_fatal")
	}
	if diagnostics.Mount.LastError != "" && len(reasons) == 0 {
		reasons = append(reasons, "reconciliation_error")
	}
	return reasons
}
