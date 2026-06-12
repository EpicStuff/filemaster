package fileaccess

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/safing/portmaster/base/notifications"
)

// NotificationsPrompter is the production Prompter. It posts the
// prompt via base/notifications and waits on the notification's
// Response channel.
type NotificationsPrompter struct {
	// id is an atomic counter for unique notification GUIDs within a
	// single process lifetime.
	id atomic.Uint64
}

// Prompt implements Prompter.
func (p *NotificationsPrompter) Prompt(ctx context.Context, e FileEvent, timeout time.Duration) (string, bool) {
	nid := fmt.Sprintf("fileaccess:open:%d", p.id.Add(1))
	title := "File access request"
	msg := fmt.Sprintf("%s (pid %d) wants to open %s", displayExe(e.Exe), e.PID, e.Path)

	n := notifications.NotifyPrompt(nid, title, msg,
		notifications.Action{ID: ActionAllow, Text: "Allow once"},
		notifications.Action{ID: ActionDeny, Text: "Deny once"},
		notifications.Action{ID: ActionAllowAlways, Text: "Always allow this path"},
		notifications.Action{ID: ActionDenyAlways, Text: "Always deny this path"},
	)

	select {
	case action := <-n.Response():
		return action, true
	case <-time.After(timeout):
		n.Delete()
		return "", false
	case <-ctx.Done():
		n.Delete()
		return "", false
	}
}

func displayExe(exe string) string {
	if exe == "" {
		return "an unknown program"
	}
	return exe
}
