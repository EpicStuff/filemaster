package status

import (
	"github.com/safing/portmaster/base/notifications"
	"github.com/safing/portmaster/service/mgr"
)

// updateStateNotification brings an existing state notification in line with
// the state's current type and message. Upstream creates it once and never
// changes it, so a warning that became an error stayed shown as a warning.
func updateStateNotification(n *notifications.Notification, state mgr.State) {
	var notifType notifications.Type
	switch state.Type {
	case mgr.StateTypeWarning:
		notifType = notifications.Warning
	case mgr.StateTypeError:
		notifType = notifications.Error
	default:
		notifType = notifications.Info
	}

	n.Lock()
	changed := n.Type != notifType || n.Message != state.Message
	if changed {
		n.Type = notifType
		n.Message = state.Message
	}
	n.Unlock()
	if changed {
		n.Save()
	}
}
