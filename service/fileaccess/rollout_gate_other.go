//go:build !linux

package fileaccess

import "errors"

type RootAskRolloutEvidence struct{}

type RootAskGateStatus struct {
	Requested bool
	Open      bool
	Reasons   []string
	Evidence  RootAskRolloutEvidence
}

func SetRootAskRolloutEvidence(RootAskRolloutEvidence) {}

func (fa *FileAccess) configureRootAskRolloutEvidence() {}

func (fa *FileAccess) RecordRootAskRolloutEvidence(RootAskRolloutEvidence) error {
	return errors.New("fanotify is not supported on this platform")
}

func rootScopeConfigured() bool { return false }

func (fa *FileAccess) RootAskGateStatus() RootAskGateStatus {
	return RootAskGateStatus{Reasons: []string{"fanotify_not_supported"}}
}
