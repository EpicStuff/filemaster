package fileaccess

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/safing/portmaster/base/notifications"
)

// FilePromptProfile is the profile slice attached to a file-access
// notification's EventData. Matches the field names the Angular UI
// expects so it can group prompts by profile.
type FilePromptProfile struct {
	ID         string `json:"ID"`
	Source     string `json:"Source"`
	Name       string `json:"Name"`
	LinkedPath string `json:"LinkedPath"`
}

// FilePromptSubject describes the file access being requested. Replaces
// the IP/domain "Entity" payload used by the upstream network prompt
// flow.
type FilePromptSubject struct {
	PID  int32  `json:"PID"`
	Exe  string `json:"Exe"`
	Path string `json:"Path"`
	Op   string `json:"Op"`
}

// FilePromptData is the EventData payload for a fileaccess:open:N
// notification. The UI reads Profile + Subject to render the prompt
// card.
type FilePromptData struct {
	Profile FilePromptProfile `json:"Profile"`
	Subject FilePromptSubject `json:"Subject"`
}

// NotificationsPrompter is the production Prompter. It posts the
// prompt via base/notifications and waits on the notification's
// Response channel.
type NotificationsPrompter struct {
	// id is an atomic counter for unique notification GUIDs within a
	// single process lifetime.
	id atomic.Uint64
}

// PromptGroup preserves a stable notification identity for exact duplicate
// requests. Prompt remains the compatibility entry point for existing callers.
func (p *NotificationsPrompter) PromptGroup(ctx context.Context, e FileEvent, timeout time.Duration, groupID string) (string, bool) {
	return p.prompt(ctx, e, timeout, "fileaccess:"+groupID)
}

// Prompt implements Prompter.
func (p *NotificationsPrompter) Prompt(ctx context.Context, e FileEvent, timeout time.Duration) (string, bool) {
	return p.prompt(ctx, e, timeout, fmt.Sprintf("fileaccess:%s:%d", e.Op, p.id.Add(1)))
}

func (p *NotificationsPrompter) prompt(ctx context.Context, e FileEvent, timeout time.Duration, nid string) (string, bool) {
	title := "File access request"
	msg := fmt.Sprintf("%s (pid %d) wants to %s %s", displayExe(e.Exe), e.PID, opVerb(e.Op), e.Path)

	data := &FilePromptData{
		Profile: FilePromptProfile{
			ID:         e.ProfileID,
			Source:     e.ProfileSource,
			Name:       e.ProfileName,
			LinkedPath: e.ProfileLinkedPath,
		},
		Subject: FilePromptSubject{
			PID:  e.PID,
			Exe:  e.Exe,
			Path: e.Path,
			Op:   e.Op.String(),
		},
	}

	n := notifications.Notify(&notifications.Notification{
		EventID:   nid,
		Type:      notifications.Prompt,
		Title:     title,
		Message:   msg,
		EventData: data,
		AvailableActions: []*notifications.Action{
			{ID: ActionAllowAlways, Text: "Allow"},
			{ID: ActionDenyAlways, Text: "Block"},
		},
	})

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

// opVerb returns the user-facing verb for a FileOp ("open" / "read" /
// "execute"). Kept separate from FileOp.String so the wire-format
// strings (op=open, op=read, op=exec) stay stable for logs and the
// EventID prefix.
func opVerb(op FileOp) string {
	switch op {
	case OpRead:
		return "read"
	case OpWrite:
		return "write to"
	case OpExec:
		return "execute"
	default:
		return "open"
	}
}
