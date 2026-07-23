package fileaccess

import (
	"context"
	"errors"
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
	// events where the exe couldn't be resolved. Each exe carries one rule
	// list per operation, mirroring the profile-backed DecisionSnapshot.
	rules map[string]*exeRuleSet

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
		rules:    make(map[string]*exeRuleSet),
	}
}

// exeRuleSet holds a fallback exe's three per-operation rule lists. The
// operation is carried by which list a rule lives in, exactly like
// DecisionSnapshot.
type exeRuleSet struct {
	read  PathRules
	write PathRules
	exec  PathRules
}

// list returns the list governing op. Opens fold to the read list. It routes
// through the shared fileAccessListOp so an unsupported operation fails closed
// (ok=false) instead of silently landing in the read list, matching the
// authoritative snapshot router.
func (s *exeRuleSet) list(op FileOp) (*PathRules, bool) {
	listOp, ok := fileAccessListOp(op)
	if !ok {
		return nil, false
	}
	switch listOp {
	case OpWrite:
		return &s.write, true
	case OpExec:
		return &s.exec, true
	default:
		return &s.read, true
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

// RulesFor returns a snapshot of every rule stored for the given exe across all
// operation lists. Useful for inspection in tests.
func (h *PromptHandler) RulesFor(exe string) []PathRule {
	h.rulesMu.RLock()
	defer h.rulesMu.RUnlock()
	set, ok := h.rules[exe]
	if !ok {
		return nil
	}
	out := make([]PathRule, 0, len(set.read.Rules)+len(set.write.Rules)+len(set.exec.Rules))
	out = append(out, set.read.Rules...)
	out = append(out, set.write.Rules...)
	out = append(out, set.exec.Rules...)
	return out
}

// ruleListsFor returns copies of the three operation lists for the given exe, so
// the fallback DecisionSnapshot can route decisions the same way the profile
// path does.
func (h *PromptHandler) ruleListsFor(exe string) (read, write, exec PathRules) {
	h.rulesMu.RLock()
	defer h.rulesMu.RUnlock()
	set, ok := h.rules[exe]
	if !ok {
		return PathRules{}, PathRules{}, PathRules{}
	}
	clone := func(list PathRules) PathRules {
		return PathRules{Rules: append([]PathRule(nil), list.Rules...), Default: list.Default}
	}
	return clone(set.read), clone(set.write), clone(set.exec)
}

func (h *PromptHandler) lookup(exe, path string, op FileOp, isDir bool) (Verdict, bool) {
	h.rulesMu.RLock()
	defer h.rulesMu.RUnlock()
	set, ok := h.rules[exe]
	if !ok {
		return 0, false
	}
	list, ok := set.list(op)
	if !ok {
		// Unsupported operation: no match, so the caller prompts/denies rather
		// than consulting an unrelated operation's rules.
		return 0, false
	}
	return list.match(path, isDir)
}

func (h *PromptHandler) appendRule(exe, pattern string, op FileOp, isDir bool, v Verdict) {
	_ = h.appendRuleEntry(exe, op, PathRule{Pattern: pattern, Verdict: v, Exact: true, DirectoryOnly: isDir})
}

// seedRuleSet builds a new per-exe rule set, seeding each operation list from
// the initial template so bootstrap rules apply regardless of operation.
func (h *PromptHandler) seedRuleSet() *exeRuleSet {
	seed := func() PathRules {
		return PathRules{
			Rules:   append([]PathRule(nil), h.initial.Rules...),
			Default: h.initial.Default,
		}
	}
	return &exeRuleSet{read: seed(), write: seed(), exec: seed()}
}

// appendRuleEntry makes a permanent fallback rule effective before saving it.
// The operation selects the destination list. A failed save deliberately leaves
// the exact in-memory rule present; the RuleStore adapter returns that error so
// Phase 6 retry ownership is retained.
func (h *PromptHandler) appendRuleEntry(exe string, op FileOp, rule PathRule) error {
	h.rulesMu.Lock()
	set, ok := h.rules[exe]
	if !ok {
		set = h.seedRuleSet()
		h.rules[exe] = set
	}
	list, ok := set.list(op)
	if !ok {
		h.rulesMu.Unlock()
		return errors.New("unroutable rule operation")
	}
	rules := make([]PathRule, 0, len(list.Rules)+1)
	rules = append(rules, rule)
	for _, existing := range list.Rules {
		if existing.Pattern == rule.Pattern && existing.Verdict == rule.Verdict && existing.Exact == rule.Exact && existing.DirectoryOnly == rule.DirectoryOnly {
			continue
		}
		rules = append(rules, existing)
	}
	list.Rules = rules
	persistPath := h.persistPath
	h.rulesMu.Unlock()

	if persistPath != "" {
		return h.Save(persistPath)
	}
	return nil
}
