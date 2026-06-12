package fileaccess

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Action IDs used by both the notifications-backed prompter and the
// fake-prompter test path. Kept stable because the UI also references
// them.
const (
	ActionAllow       = "allow"
	ActionDeny        = "deny"
	ActionAllowAlways = "allow-always"
	ActionDenyAlways  = "deny-always"
)

// Prompter raises a single file-access prompt and waits for the user's
// response. Decoupled from the notifications package so PromptHandler
// stays testable.
type Prompter interface {
	// Prompt sends the prompt and returns the selected action ID.
	// Returns ok=false if the user didn't respond before the timeout or
	// the context was cancelled.
	Prompt(ctx context.Context, event FileEvent, timeout time.Duration) (action string, ok bool)
}

// PromptHandler is a Handler that consults an in-memory PathRules first
// and, on no match, asks the user via a Prompter. "Always" responses
// are persisted as new rules so the same path doesn't keep prompting.
//
// Phase-3 minimum: rules are a single global list, not per-app. Per-app
// profile integration comes later.
type PromptHandler struct {
	prompter Prompter
	timeout  time.Duration

	rulesMu sync.RWMutex
	rules   *PathRules

	// promptID counter so concurrent prompts have distinct notification IDs.
	promptID atomic.Uint64
}

// NewPromptHandler returns a PromptHandler. If initial is nil, an empty
// rule set with VerdictAllow as default is used. Timeout is the
// per-prompt deadline; on expire the handler returns VerdictDeny.
func NewPromptHandler(p Prompter, initial *PathRules, timeout time.Duration) *PromptHandler {
	if initial == nil {
		initial = &PathRules{Default: VerdictAllow}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &PromptHandler{
		prompter: p,
		timeout:  timeout,
		rules:    initial,
	}
}

// Decide implements Handler.
func (h *PromptHandler) Decide(ctx context.Context, e FileEvent) Verdict {
	if v, ok := h.lookup(e.Path); ok {
		return v
	}
	action, ok := h.prompter.Prompt(ctx, e, h.timeout)
	if !ok {
		// No response (timeout or shutdown). Default-deny on the
		// principle that we'd rather break an app than leak data.
		return VerdictDeny
	}
	return h.apply(e, action)
}

// Rules returns a snapshot of the current rule list. Useful for
// inspection in tests.
func (h *PromptHandler) Rules() []PathRule {
	h.rulesMu.RLock()
	defer h.rulesMu.RUnlock()
	out := make([]PathRule, len(h.rules.Rules))
	copy(out, h.rules.Rules)
	return out
}

func (h *PromptHandler) lookup(path string) (Verdict, bool) {
	h.rulesMu.RLock()
	defer h.rulesMu.RUnlock()
	return h.rules.Lookup(path)
}

func (h *PromptHandler) appendRule(pattern string, v Verdict) {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	h.rules.Rules = append(h.rules.Rules, PathRule{Pattern: pattern, Verdict: v})
}

func (h *PromptHandler) apply(e FileEvent, action string) Verdict {
	switch action {
	case ActionAllow:
		return VerdictAllow
	case ActionDeny:
		return VerdictDeny
	case ActionAllowAlways:
		h.appendRule(e.Path, VerdictAllow)
		return VerdictAllow
	case ActionDenyAlways:
		h.appendRule(e.Path, VerdictDeny)
		return VerdictDeny
	default:
		// Unknown action ID -- default-deny.
		return VerdictDeny
	}
}
