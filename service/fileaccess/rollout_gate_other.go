//go:build !linux

package fileaccess

type RootAskRolloutEvidence struct{}

type RootAskGateStatus struct {
	Requested bool
	Open      bool
	Reasons   []string
	Evidence  RootAskRolloutEvidence
}

func SetRootAskRolloutEvidence(RootAskRolloutEvidence) {}

func rootScopeConfigured() bool { return false }

func (fa *FileAccess) RootAskGateStatus() RootAskGateStatus {
	return RootAskGateStatus{Reasons: []string{"fanotify_not_supported"}}
}
