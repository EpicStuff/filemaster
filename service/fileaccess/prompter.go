package fileaccess

import (
	"context"
	"time"
)

// Action IDs used by both the notifications-backed prompter and tests. Kept
// stable because the UI also references them.
const (
	ActionAllow       = "allow"
	ActionDeny        = "deny"
	ActionAllowAlways = "allow-always"
	ActionDenyAlways  = "deny-always"
)

// Prompter raises a single file-access prompt and waits for the user's
// response.
type Prompter interface {
	// Prompt sends the prompt and returns the selected action ID.
	// Returns ok=false if the user didn't respond before the timeout or
	// the context was cancelled.
	Prompt(ctx context.Context, event FileEvent, timeout time.Duration) (action string, ok bool)
}
