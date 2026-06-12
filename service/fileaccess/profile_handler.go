package fileaccess

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"time"
)

// RuleStore is the small slice of *profile.Profile that the
// ProfileHandler needs. Keeping it as an interface lets tests inject a
// fake without pulling in the database/config plumbing.
type RuleStore interface {
	// ID identifies the profile this store backs. Used for diagnostics
	// and to key the prompter's notification IDs so concurrent prompts
	// for the same app collapse where the UI wants them to.
	ID() string

	// Rules returns the persisted rule strings in the order they were
	// added (newest first). Each string is a single "<+|-> <pattern>"
	// entry per the format defined by ParseRule / FormatRule.
	Rules() []string

	// AppendRule prepends a new rule entry and persists it. Errors are
	// surfaced so the caller can log without losing the in-memory
	// verdict; persistence failures are non-fatal to the current event.
	AppendRule(entry string) error
}

// ProfileLookup resolves a PID to the RuleStore for the matched
// profile. Production binding wraps process.GetProcessWithProfile;
// tests pass an in-memory map.
type ProfileLookup interface {
	Lookup(ctx context.Context, pid int32) (RuleStore, error)
}

// ProfileHandler decides verdicts by consulting per-profile rules
// stored in the profile's persisted config map and, on miss, asking
// the user via a Prompter. "Always" responses are written back into
// the profile, which carries the existing portmaster persistence +
// sync machinery.
type ProfileHandler struct {
	lookup   ProfileLookup
	prompter Prompter
	timeout  time.Duration

	// fallback is used when ProfileLookup returns an error (process
	// gone, profile module not ready, etc). Without it the daemon
	// would default-deny every unidentified syscall; with it we keep
	// the in-memory PromptHandler as a safety net.
	fallback Handler

	// log is used for noisy lookup failures so we don't break the
	// kernel-blocking decide path. Nil means silent.
	log logger

	promptID atomic.Uint64
}

// NewProfileHandler returns a profile-backed handler. The fallback
// handler is invoked when ProfileLookup fails -- typically a plain
// PromptHandler so events from processes-without-profiles still get
// to ask the user.
func NewProfileHandler(lookup ProfileLookup, prompter Prompter, fallback Handler, timeout time.Duration, log logger) *ProfileHandler {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if fallback == nil {
		fallback = allowAll
	}
	if log == nil {
		log = nopLogger{}
	}
	return &ProfileHandler{
		lookup:   lookup,
		prompter: prompter,
		timeout:  timeout,
		fallback: fallback,
		log:      log,
	}
}

// Decide implements Handler.
func (h *ProfileHandler) Decide(ctx context.Context, e FileEvent) Verdict {
	store, err := h.lookup.Lookup(ctx, e.PID)
	if err != nil || store == nil {
		if err != nil {
			h.log.Warn("profile lookup failed; using fallback handler",
				"pid", e.PID,
				"path", e.Path,
				"err", err,
			)
		}
		return h.fallback.Decide(ctx, e)
	}

	if v, ok := matchRules(store.Rules(), e.Path); ok {
		return v
	}

	action, ok := h.prompter.Prompt(ctx, e, h.timeout)
	if !ok {
		// Default-deny on timeout/cancel for the same reason the
		// PromptHandler does: better to break an app than leak data.
		return VerdictDeny
	}

	switch action {
	case ActionAllow:
		return VerdictAllow
	case ActionDeny:
		return VerdictDeny
	case ActionAllowAlways:
		if err := store.AppendRule(FormatRule(e.Path, VerdictAllow)); err != nil {
			h.log.Error("persist allow-always failed", "profile", store.ID(), "path", e.Path, "err", err)
		}
		return VerdictAllow
	case ActionDenyAlways:
		if err := store.AppendRule(FormatRule(e.Path, VerdictDeny)); err != nil {
			h.log.Error("persist deny-always failed", "profile", store.ID(), "path", e.Path, "err", err)
		}
		return VerdictDeny
	default:
		return VerdictDeny
	}
}

// FormatRule encodes a (pattern, verdict) pair as a profile rule
// string: "+ <pattern>" for allow, "- <pattern>" for deny. Mirrors the
// existing endpoint rule string layout.
func FormatRule(pattern string, v Verdict) string {
	if v == VerdictAllow {
		return "+ " + pattern
	}
	return "- " + pattern
}

// ParseRule decodes a "<+|-> <pattern>" string into a PathRule. Returns
// false on malformed input.
func ParseRule(entry string) (PathRule, bool) {
	if len(entry) < 3 || entry[1] != ' ' {
		return PathRule{}, false
	}
	var v Verdict
	switch entry[0] {
	case '+':
		v = VerdictAllow
	case '-':
		v = VerdictDeny
	default:
		return PathRule{}, false
	}
	return PathRule{Pattern: strings.TrimSpace(entry[2:]), Verdict: v}, true
}

// matchRules walks the entries in order and returns the first match.
// First-match-wins matches PathRules semantics; AddFileAccessRule
// prepends, so newest rules take priority over older ones.
func matchRules(entries []string, path string) (Verdict, bool) {
	for _, entry := range entries {
		r, ok := ParseRule(entry)
		if !ok {
			continue
		}
		if r.Matches(path) {
			return r.Verdict, true
		}
	}
	return 0, false
}

// ErrNoProfile is returned by a ProfileLookup when no matching profile
// could be found (process gone, detection disabled, etc).
var ErrNoProfile = errors.New("no profile for process")
