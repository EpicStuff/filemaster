package fileaccess

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/safing/portmaster/service/profile"
)

// RuleStore is the small slice of *profile.Profile that the
// ProfileHandler needs for *writing* a new rule. Reads come back as
// pre-parsed rules in LookupResult to keep the hot path free of
// re-parsing.
type RuleStore interface {
	// ID identifies the profile this store backs. Used for diagnostics
	// and the prompter's notification IDs.
	ID() string

	// AppendRule prepends a new rule entry and persists it. Errors are
	// surfaced so the caller can log without losing the in-memory
	// verdict; persistence failures are non-fatal to the current event.
	AppendRule(entry string) error
}

// LookupResult is everything a single ProfileLookup pass yields: the
// resolved exe path (for the fallback handler + audit logging), the
// rule store (nil if no profile resolved), the pre-parsed per-profile
// rules, and the profile's default action.
//
// Bundling all four into one struct means we hit
// process.GetProcessWithProfile exactly once per event -- both
// ProfileHandler and the fallback path get what they need from a
// single call.
type LookupResult struct {
	// Path is the process's resolved exe path, mirrored from
	// Process.Path. Empty when the process couldn't be resolved.
	Path string

	// Store is the rule store backing the matched profile, or nil
	// when no profile resolved.
	Store RuleStore

	// ParsedRules is the cached parsed view of Store.Rules(). Empty
	// PathRules when Store is nil.
	ParsedRules PathRules

	// DefaultAction is the profile's default action constant from
	// service/profile (DefaultActionNotSet / Block / Ask / Permit).
	// DefaultActionAsk when no profile resolved, so default-deny isn't
	// silently applied to processes the lookup couldn't identify.
	DefaultAction uint8

	// Profile metadata, mirrored into the FileEvent before the prompter
	// is called so the UI can group + render the prompt. All empty when
	// Store is nil.
	ProfileSource     string
	ProfileName       string
	ProfileLinkedPath string
}

// ProfileLookup resolves a PID to a LookupResult. Production binding
// wraps process.GetProcessWithProfile; tests pass an in-memory map.
type ProfileLookup interface {
	Lookup(ctx context.Context, pid int32) (LookupResult, error)
}

// ProfileHandler decides verdicts by consulting per-profile rules
// stored in the profile's persisted config map and, on miss, applying
// the profile's default action: permit / block straight through, or
// ask the user via a Prompter. "Always" responses are written back
// into the profile, which carries the existing portmaster persistence
// + sync machinery.
type ProfileHandler struct {
	lookup   ProfileLookup
	prompter Prompter
	timeout  time.Duration

	// fallback is used when ProfileLookup returns an error or no
	// profile resolves. Without it the daemon would default-deny every
	// unidentified syscall; with it we keep the exe-keyed PromptHandler
	// as a safety net.
	fallback Handler

	// log is used for noisy lookup failures so we don't break the
	// kernel-blocking decide path. Nil means silent.
	log logger

	promptID atomic.Uint64
}

// NewProfileHandler returns a profile-backed handler. The fallback
// handler is invoked when ProfileLookup fails OR when no profile
// resolves -- typically a plain PromptHandler so events from
// processes-without-profiles still get to ask the user.
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
func (h *ProfileHandler) Decide(ctx context.Context, e *FileEvent) Verdict {
	res, err := h.lookup.Lookup(ctx, e.PID)
	if err != nil {
		h.log.Warn("profile lookup failed; using fallback handler",
			"pid", e.PID,
			"path", e.Path,
			"err", err,
		)
		// Populate Exe from what we managed to resolve so the fallback
		// can key by it.
		if res.Path != "" {
			e.Exe = res.Path
		}
		return h.fallback.Decide(ctx, e)
	}
	// Always pass the resolved exe to the fallback (and along the
	// audit-log chain), regardless of whether a profile resolved.
	if res.Path != "" {
		e.Exe = res.Path
	}
	if res.Store == nil {
		return h.fallback.Decide(ctx, e)
	}

	// Stamp the profile metadata onto the event so the prompter (and
	// its EventData payload) can show the user which app this is and
	// the UI can group prompts by profile.
	e.ProfileID = res.Store.ID()
	e.ProfileSource = res.ProfileSource
	e.ProfileName = res.ProfileName
	e.ProfileLinkedPath = res.ProfileLinkedPath

	// Profile resolved -- match against its pre-parsed rules.
	if v, ok := res.ParsedRules.Lookup(e.Path); ok {
		return v
	}

	// No rule match. Consult the profile's default action before
	// raising a prompt, mirroring how the network filter chain uses
	// cfgOptionDefaultAction.
	switch res.DefaultAction {
	case profile.DefaultActionPermit:
		return VerdictAllow
	case profile.DefaultActionBlock:
		return VerdictDeny
	case profile.DefaultActionAsk, profile.DefaultActionNotSet:
		// Fall through to the prompter below.
	default:
		// Unknown default-action value: be safe.
		return VerdictDeny
	}

	action, ok := h.prompter.Prompt(ctx, *e, h.timeout)
	if !ok {
		// Default-deny on timeout/cancel for the same reason
		// PromptHandler does: better to break an app than leak data.
		return VerdictDeny
	}

	switch action {
	case ActionAllow:
		return VerdictAllow
	case ActionDeny:
		return VerdictDeny
	case ActionAllowAlways:
		if err := res.Store.AppendRule(FormatRule(e.Path, VerdictAllow)); err != nil {
			h.log.Error("persist allow-always failed", "profile", res.Store.ID(), "path", e.Path, "err", err)
		}
		return VerdictAllow
	case ActionDenyAlways:
		if err := res.Store.AppendRule(FormatRule(e.Path, VerdictDeny)); err != nil {
			h.log.Error("persist deny-always failed", "profile", res.Store.ID(), "path", e.Path, "err", err)
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

// ParseRules parses a []string of rule entries (as stored in a profile)
// into a PathRules with VerdictAllow as the no-match default. Malformed
// entries are skipped.
func ParseRules(entries []string) PathRules {
	rs := PathRules{Default: VerdictAllow}
	for _, entry := range entries {
		if r, ok := ParseRule(entry); ok {
			rs.Rules = append(rs.Rules, r)
		}
	}
	return rs
}

// ErrNoProfile is returned by a ProfileLookup when no matching profile
// could be found (process gone, detection disabled, etc).
var ErrNoProfile = errors.New("no profile for process")
