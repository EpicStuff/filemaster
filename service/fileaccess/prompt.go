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

// unknownExe is the bucket used when FileEvent.Exe is empty (process
// exited or /proc lookup failed). Keeps the map keying total without
// special-casing every lookup site.
const unknownExe = ""

// Prompter raises a single file-access prompt and waits for the user's
// response. Decoupled from the notifications package so PromptHandler
// stays testable.
type Prompter interface {
	// Prompt sends the prompt and returns the selected action ID.
	// Returns ok=false if the user didn't respond before the timeout or
	// the context was cancelled.
	Prompt(ctx context.Context, event FileEvent, timeout time.Duration) (action string, ok bool)
}

// PromptHandler is a Handler that consults per-app rule lists first
// and, on no match, asks the user via a Prompter. "Always" responses
// are persisted as new rules keyed by the calling process's exe path,
// so allowing /tmp/foo from /usr/bin/cat doesn't auto-allow it from
// some other binary.
//
// Phase 2.5: rules are in-memory and per-exe. Profile-backed storage
// (so rules survive restarts and ride on the existing profile sync
// machinery) lands later.
type PromptHandler struct {
	prompter Prompter
	timeout  time.Duration

	// initial is the default rule set inherited by every newly-seen exe.
	// Lets callers seed bootstrap rules (e.g. always-allow common
	// system paths). Nil = empty rules, VerdictAllow on no match.
	initial *PathRules

	rulesMu sync.RWMutex
	// rules is keyed by FileEvent.Exe. An empty key holds rules for
	// events where the exe couldn't be resolved.
	rules map[string]*PathRules

	// promptID counter so concurrent prompts have distinct notification IDs.
	promptID atomic.Uint64
}

// NewPromptHandler returns a PromptHandler. The initial rule set is
// used as the seed for every per-exe rule list -- typically nil (no
// preseeded rules, VerdictAllow on no match). Timeout is the per-prompt
// deadline; on expire the handler returns VerdictDeny.
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
		initial:  initial,
		rules:    make(map[string]*PathRules),
	}
}

// Decide implements Handler.
func (h *PromptHandler) Decide(ctx context.Context, e FileEvent) Verdict {
	if v, ok := h.lookup(e.Exe, e.Path); ok {
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

// RulesFor returns a snapshot of the rule list for the given exe.
// Useful for inspection in tests.
func (h *PromptHandler) RulesFor(exe string) []PathRule {
	h.rulesMu.RLock()
	defer h.rulesMu.RUnlock()
	rs, ok := h.rules[exe]
	if !ok {
		return nil
	}
	out := make([]PathRule, len(rs.Rules))
	copy(out, rs.Rules)
	return out
}

func (h *PromptHandler) lookup(exe, path string) (Verdict, bool) {
	h.rulesMu.RLock()
	defer h.rulesMu.RUnlock()
	rs, ok := h.rules[exe]
	if !ok {
		return 0, false
	}
	return rs.Lookup(path)
}

func (h *PromptHandler) appendRule(exe, pattern string, v Verdict) {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	rs, ok := h.rules[exe]
	if !ok {
		// Seed from the initial template.
		rs = &PathRules{
			Rules:   append([]PathRule(nil), h.initial.Rules...),
			Default: h.initial.Default,
		}
		h.rules[exe] = rs
	}
	rs.Rules = append(rs.Rules, PathRule{Pattern: pattern, Verdict: v})
}

func (h *PromptHandler) apply(e FileEvent, action string) Verdict {
	switch action {
	case ActionAllow:
		return VerdictAllow
	case ActionDeny:
		return VerdictDeny
	case ActionAllowAlways:
		h.appendRule(e.Exe, e.Path, VerdictAllow)
		return VerdictAllow
	case ActionDenyAlways:
		h.appendRule(e.Exe, e.Path, VerdictDeny)
		return VerdictDeny
	default:
		// Unknown action ID -- default-deny.
		return VerdictDeny
	}
}
