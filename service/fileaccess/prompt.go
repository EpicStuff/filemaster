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

	// persistPath, if non-empty, is the file rules are saved to on
	// every appendRule call. Set via SetPersistPath.
	persistPath string

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
func (h *PromptHandler) Decide(ctx context.Context, e *FileEvent) Verdict {
	verdict, afterResponse := h.DecideForResponse(ctx, e)
	if afterResponse != nil {
		afterResponse()
	}
	return verdict
}

func (h *PromptHandler) DecideForResponse(ctx context.Context, e *FileEvent) (Verdict, func()) {
	if verdict, ok := h.lookup(e.Exe, e.Path, e.Op, e.IsDir); ok {
		return verdict, nil
	}
	action, ok := h.prompter.Prompt(ctx, *e, h.timeout)
	if !ok {
		return VerdictDeny, nil
	}
	switch action {
	case ActionAllow:
		return VerdictAllow, nil
	case ActionDeny:
		return VerdictDeny, nil
	case ActionAllowAlways:
		return VerdictAllow, func() { h.appendRule(e.Exe, e.Path, e.Op, e.IsDir, VerdictAllow) }
	case ActionDenyAlways:
		return VerdictDeny, func() { h.appendRule(e.Exe, e.Path, e.Op, e.IsDir, VerdictDeny) }
	default:
		return VerdictDeny, nil
	}
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

func (h *PromptHandler) lookup(exe, path string, op FileOp, isDir bool) (Verdict, bool) {
	h.rulesMu.RLock()
	defer h.rulesMu.RUnlock()
	rs, ok := h.rules[exe]
	if !ok {
		return 0, false
	}
	return rs.LookupEvent(path, op, isDir)
}

func (h *PromptHandler) appendRule(exe, pattern string, op FileOp, isDir bool, v Verdict) {
	_ = h.appendRuleEntry(exe, PathRule{Pattern: pattern, Verdict: v, Exact: true, Operation: op, OperationScoped: true, DirectoryOnly: isDir})
}

// appendRuleEntry makes a permanent fallback rule effective before saving it.
// A failed save deliberately leaves the exact in-memory rule present; the
// RuleStore adapter returns that error so Phase 6 retry ownership is retained.
func (h *PromptHandler) appendRuleEntry(exe string, rule PathRule) error {
	h.rulesMu.Lock()
	rs, ok := h.rules[exe]
	if !ok {
		// Seed from the initial template.
		rs = &PathRules{
			Rules:   append([]PathRule(nil), h.initial.Rules...),
			Default: h.initial.Default,
		}
		h.rules[exe] = rs
	}
	rules := make([]PathRule, 0, len(rs.Rules)+1)
	rules = append(rules, rule)
	for _, existing := range rs.Rules {
		if existing.Pattern == rule.Pattern && existing.Verdict == rule.Verdict && existing.Exact == rule.Exact && existing.OperationScoped == rule.OperationScoped && (!rule.OperationScoped || (existing.Operation == rule.Operation && existing.DirectoryOnly == rule.DirectoryOnly)) {
			continue
		}
		rules = append(rules, existing)
	}
	rs.Rules = rules
	persistPath := h.persistPath
	h.rulesMu.Unlock()

	if persistPath != "" {
		return h.Save(persistPath)
	}
	return nil
}
