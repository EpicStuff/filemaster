package fileaccess

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// fallbackRuleStore keeps an accepted Always rule durable when process profile
// lookup is temporarily unavailable. It is deliberately scoped to the
// executable bucket used by PromptHandler, never a mutable profile object.
type fallbackRuleStore struct {
	handler *PromptHandler
	exe     string
}

func (s fallbackRuleStore) ID() string { return "fallback:" + s.exe }

func (s fallbackRuleStore) AppendRule(entry string) error {
	rule, ok := ParseRule(entry)
	if !ok {
		return errors.New("invalid fallback file access rule")
	}
	return s.handler.appendRuleEntry(s.exe, rule)
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

	// ProcessIdentity distinguishes a process lifetime from a reused PID when
	// no profile can be resolved.
	ProcessIdentity string

	// Store is the rule store backing the matched profile, or nil
	// when no profile resolved.
	Store RuleStore

	// Snapshot is the immutable parsed policy used for this lookup. It is
	// nil only for compatibility with non-profile test lookups.
	Snapshot *DecisionSnapshot

	// ParsedRules is retained for compatibility with existing lookups. New
	// production lookups populate it from Snapshot.
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
	lookup                    ProfileLookup
	prompter                  Prompter
	timeout                   time.Duration
	lifecycle                 *PipelineLifecycle
	beforeSnapshotPublication func()
	beforeProfilePublication  func()

	// fallback is used when ProfileLookup returns an error or no
	// profile resolves. Without it the daemon would default-deny every
	// unidentified syscall; with it we keep the exe-keyed PromptHandler
	// as a safety net.
	fallback Handler

	// log is used for noisy lookup failures so we don't break the
	// kernel-blocking decide path. Nil means silent.
	log logger

	promptID     atomic.Uint64
	selfRevision atomic.Uint64

	promptAdmissionMu sync.RWMutex
	promptAdmission   func(string) (func(), bool)
	rootAskGate       func() RootAskGateStatus

	promptCoordinatorMu sync.RWMutex
	promptCoordinator   *PromptCoordinator

	// The daemon's own profile is a complete in-memory decision snapshot.
	// It is refreshed before fanotify marks are installed and on profile
	// changes, so an event from this process never resolves /proc, reads the
	// database, or runs normal process/profile lookup while its open is held.
	selfMu      sync.RWMutex
	selfPID     int32
	selfProfile LookupResult
}

func (h *ProfileHandler) setLifecycle(lifecycle *PipelineLifecycle) {
	h.lifecycle = lifecycle
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
	handler := &ProfileHandler{
		lookup:   lookup,
		prompter: prompter,
		timeout:  timeout,
		fallback: fallback,
		log:      log,
	}
	if publisher, ok := lookup.(interface{ setSnapshotObserver(func(*DecisionSnapshot)) }); ok {
		publisher.setSnapshotObserver(handler.publishSnapshot)
	}
	return handler
}

// SetSelfProfile atomically replaces the daemon's in-memory policy snapshot.
// It is deliberately separate from normal process lookup: deciding an event
// generated by the daemon must not open files or touch the profile database.
func (h *ProfileHandler) setPromptAdmission(admission func(string) (func(), bool)) {
	h.promptAdmissionMu.Lock()
	h.promptAdmission = admission
	h.promptAdmissionMu.Unlock()
}

func (h *ProfileHandler) setRootAskGate(gate func() RootAskGateStatus) {
	h.promptAdmissionMu.Lock()
	h.rootAskGate = gate
	h.promptAdmissionMu.Unlock()
}

func (h *ProfileHandler) rootAskAllowed() bool {
	if !rootScopeConfigured() {
		return true
	}
	h.promptAdmissionMu.RLock()
	gate := h.rootAskGate
	h.promptAdmissionMu.RUnlock()
	return gate != nil && gate().Open
}

func (h *ProfileHandler) setPromptCoordinator(coordinator *PromptCoordinator) {
	h.promptCoordinatorMu.Lock()
	h.promptCoordinator = coordinator
	h.promptCoordinatorMu.Unlock()
	if overlay, ok := h.lookup.(interface{ setRulePersistence(*RulePersistence) }); ok && coordinator != nil {
		overlay.setRulePersistence(coordinator.RulePersistence())
	}
}

func (h *ProfileHandler) coordinator() *PromptCoordinator {
	h.promptCoordinatorMu.RLock()
	defer h.promptCoordinatorMu.RUnlock()
	return h.promptCoordinator
}

func (h *ProfileHandler) acquirePromptSlot(profileKey string) (func(), bool) {
	h.promptAdmissionMu.RLock()
	admission := h.promptAdmission
	h.promptAdmissionMu.RUnlock()
	if admission == nil {
		return func() {}, true
	}
	return admission(profileKey)
}

func (h *ProfileHandler) SetSelfProfile(p *profile.Profile, pid int32) {
	if p == nil || pid <= 0 {
		return
	}
	if h.lifecycle != nil {
		h.lifecycle.whileRunning(func() {
			if h.beforeProfilePublication != nil {
				h.beforeProfilePublication()
			}
			h.setSelfProfileRunning(p, pid)
		})
		return
	}
	if h.beforeProfilePublication != nil {
		h.beforeProfilePublication()
	}
	h.setSelfProfileRunning(p, pid)
}

func (h *ProfileHandler) setSelfProfileRunning(p *profile.Profile, pid int32) {

	p.RLock()
	id := p.ID
	rawRules := append([]string(nil), p.GetFileAccessRules()...)
	defaultAction := p.DefaultAction()
	source := string(p.Source)
	name := p.Name
	linkedPath := p.LinkedPath
	path := p.PresentationPath
	p.RUnlock()

	if defaultAction == profile.DefaultActionNotSet {
		defaultAction = profile.DefaultActionAsk
	}
	store := &profileRuleStore{p: p, source: profile.ProfileSource(source), id: id}
	if coordinator := h.coordinator(); coordinator != nil {
		coordinator.RulePersistence().bindStoreRunning(source, id, store)
	}
	snapshot := newDecisionSnapshot(id, source, defaultAction, rawRules, h.selfRevision.Add(1))
	if coordinator := h.coordinator(); coordinator != nil {
		snapshot = coordinator.RulePersistence().Merge(snapshot)
	}
	if coordinator := h.coordinator(); coordinator != nil {
		coordinator.RulePersistence().bindStoreRunning(snapshot.Source, snapshot.ProfileID, store)
	}
	result := LookupResult{
		Path:              path,
		Store:             store,
		Snapshot:          snapshot,
		ParsedRules:       snapshot.Rules,
		DefaultAction:     snapshot.DefaultAction,
		ProfileSource:     source,
		ProfileName:       name,
		ProfileLinkedPath: linkedPath,
	}

	h.setSelfProfileResultRunning(pid, result)
}

func (h *ProfileHandler) setSelfProfile(pid int32, result LookupResult) {
	if h.lifecycle != nil {
		h.lifecycle.whileRunning(func() { h.setSelfProfileResultRunning(pid, result) })
		return
	}
	h.setSelfProfileResultRunning(pid, result)
}

func (h *ProfileHandler) setSelfProfileResultRunning(pid int32, result LookupResult) {
	h.selfMu.Lock()
	h.selfPID = pid
	h.selfProfile = result
	h.selfMu.Unlock()
	if result.Snapshot != nil {
		h.publishSnapshotRunning(result.Snapshot)
	}
}

func (h *ProfileHandler) publishSnapshot(snapshot *DecisionSnapshot) {
	if snapshot == nil {
		return
	}
	if h.lifecycle != nil {
		h.lifecycle.whileRunning(func() {
			if h.beforeSnapshotPublication != nil {
				h.beforeSnapshotPublication()
			}
			h.publishSnapshotRunning(snapshot)
		})
		return
	}
	h.publishSnapshotRunning(snapshot)
}

func (h *ProfileHandler) publishSnapshotRunning(snapshot *DecisionSnapshot) {
	// The Filemaster self path is intentionally in-memory. Keep its stored
	// snapshot in lockstep with an Always overlay without doing process lookup.
	h.selfMu.Lock()
	if current := h.selfProfile.Snapshot; current != nil && current.ProfileID == snapshot.ProfileID && current.Source == snapshot.Source {
		h.selfProfile.Snapshot = snapshot
		h.selfProfile.ParsedRules = snapshot.Rules
		h.selfProfile.DefaultAction = snapshot.DefaultAction
	}
	h.selfMu.Unlock()
	if coordinator := h.coordinator(); coordinator != nil {
		coordinator.snapshotReplacedRunning(snapshot)
	}
}

// PublishProfileSnapshot is called from the profile change event path. It
// replaces the immutable decision snapshot before pending prompt groups are
// reevaluated, without doing profile storage work in a decision worker.
func (h *ProfileHandler) PublishProfileSnapshot(p *profile.Profile) {
	if p == nil {
		return
	}
	if h.lifecycle != nil {
		h.lifecycle.whileRunning(func() {
			if h.beforeProfilePublication != nil {
				h.beforeProfilePublication()
			}
			h.publishProfileSnapshotRunning(p)
		})
		return
	}
	if h.beforeProfilePublication != nil {
		h.beforeProfilePublication()
	}
	h.publishProfileSnapshotRunning(p)
}

func (h *ProfileHandler) publishProfileSnapshotRunning(p *profile.Profile) {
	p.RLock()
	id := p.ID
	rawRules := append([]string(nil), p.GetFileAccessRules()...)
	defaultAction := p.DefaultAction()
	source := string(p.Source)
	p.RUnlock()
	if defaultAction == profile.DefaultActionNotSet {
		defaultAction = profile.DefaultActionAsk
	}
	store := &profileRuleStore{p: p, source: profile.ProfileSource(source), id: id}
	if coordinator := h.coordinator(); coordinator != nil {
		coordinator.RulePersistence().bindStoreRunning(source, id, store)
	}

	var snapshot *DecisionSnapshot
	if lookup, ok := h.lookup.(*processProfileLookup); ok {
		snapshot, _ = lookup.snapshotForRunning(id, source, defaultAction, rawRules)
	} else {
		snapshot = newDecisionSnapshot(id, source, defaultAction, rawRules, h.selfRevision.Add(1))
		if coordinator := h.coordinator(); coordinator != nil {
			snapshot = coordinator.RulePersistence().Merge(snapshot)
		}
	}
	h.publishSnapshotRunning(snapshot)
	if coordinator := h.coordinator(); coordinator != nil && snapshot != nil {
		coordinator.RulePersistence().bindStoreRunning(snapshot.Source, snapshot.ProfileID, store)
	}
}

func (h *ProfileHandler) lookupSelfProfile(pid int32) (LookupResult, bool) {
	h.selfMu.RLock()
	defer h.selfMu.RUnlock()
	if pid <= 0 || h.selfPID != pid || h.selfProfile.Store == nil {
		return LookupResult{}, false
	}
	return h.selfProfile, true
}

// Decide implements Handler.
func (h *ProfileHandler) Decide(ctx context.Context, e *FileEvent) Verdict {
	verdict, afterResponse := h.DecideForResponse(ctx, e)
	if afterResponse != nil {
		afterResponse()
	}
	return verdict
}

// DecideForResponse separates an immediate kernel verdict from follow-up
// persistence. The decision pipeline invokes the latter only after the
// fanotify response has been accepted.
func (h *ProfileHandler) DecideForResponse(ctx context.Context, e *FileEvent) (Verdict, func()) {
	res, isSelf := h.lookupSelfProfile(e.PID)
	if !isSelf {
		var err error
		res, err = h.lookup.Lookup(ctx, e.PID)
		if err != nil {
			h.log.Warn("profile lookup failed; using fallback handler",
				"pid", e.PID,
				"path", e.Path,
				"err", err,
			)
			if res.Path != "" {
				e.Exe = res.Path
			}
			return h.fallbackDecision(ctx, e)
		}
	}

	if res.Path != "" {
		e.Exe = res.Path
	}
	if res.ProcessIdentity != "" {
		e.ProcessIdentity = res.ProcessIdentity
	}
	if res.Store == nil {
		return h.fallbackDecision(ctx, e)
	}

	e.ProfileID = res.Store.ID()
	e.ProfileSource = res.ProfileSource
	e.ProfileName = res.ProfileName
	e.ProfileLinkedPath = res.ProfileLinkedPath

	rules := res.ParsedRules
	defaultAction := res.DefaultAction
	if res.Snapshot != nil {
		rules = res.Snapshot.Rules
		defaultAction = res.Snapshot.DefaultAction
	}
	if verdict, ok := rules.Lookup(e.Path); ok {
		return verdict, nil
	}

	switch defaultAction {
	case profile.DefaultActionPermit:
		return VerdictAllow, nil
	case profile.DefaultActionBlock:
		return VerdictDeny, nil
	case profile.DefaultActionAsk, profile.DefaultActionNotSet:
	default:
		return VerdictDeny, nil
	}

	release, admitted := h.acquirePromptSlot(e.ProfileSource + "/" + e.ProfileID)
	if !admitted {
		return VerdictDeny, nil
	}
	defer release()

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
		return VerdictAllow, func() {
			if err := res.Store.AppendRule(FormatRule(e.Path, VerdictAllow)); err != nil {
				h.log.Error("persist allow-always failed", "profile", res.Store.ID(), "path", e.Path, "err", err)
			}
		}
	case ActionDenyAlways:
		return VerdictDeny, func() {
			if err := res.Store.AppendRule(FormatRule(e.Path, VerdictDeny)); err != nil {
				h.log.Error("persist deny-always failed", "profile", res.Store.ID(), "path", e.Path, "err", err)
			}
		}
	default:
		return VerdictDeny, nil
	}
}

// DecidePending routes Ask decisions to the prompt coordinator. It is used by
// DecisionPipeline only; the older synchronous DecideForResponse entry point
// remains available to callers outside the owned-event pipeline.
func (h *ProfileHandler) DecidePending(ctx context.Context, pending PendingEvent) (handled, handedOff bool, verdict Verdict, afterResponse func()) {
	e := pending.Event()
	if e == nil {
		return false, false, VerdictDeny, nil
	}

	res, isSelf := h.lookupSelfProfile(e.PID)
	if !isSelf {
		var err error
		res, err = h.lookup.Lookup(ctx, e.PID)
		if err != nil {
			if res.Path != "" {
				e.Exe = res.Path
			}
			if res.ProcessIdentity != "" {
				e.ProcessIdentity = res.ProcessIdentity
			}
			if coordinator := h.coordinator(); coordinator != nil {
				if !h.rootAskAllowed() {
					return false, false, VerdictDeny, nil
				}
				store, snapshot := h.fallbackSnapshot(e)
				return coordinator.Admit(ctx, pending, store, snapshot)
			}
			verdict, afterResponse = h.fallbackDecision(ctx, e)
			return false, false, verdict, afterResponse
		}
	}

	if res.Path != "" {
		e.Exe = res.Path
	}
	if res.ProcessIdentity != "" {
		e.ProcessIdentity = res.ProcessIdentity
	}
	if res.Store == nil {
		if coordinator := h.coordinator(); coordinator != nil {
			if !h.rootAskAllowed() {
				return false, false, VerdictDeny, nil
			}
			store, snapshot := h.fallbackSnapshot(e)
			return coordinator.Admit(ctx, pending, store, snapshot)
		}
		verdict, afterResponse = h.fallbackDecision(ctx, e)
		return false, false, verdict, afterResponse
	}

	e.ProfileID = res.Store.ID()
	e.ProfileSource = res.ProfileSource
	e.ProfileName = res.ProfileName
	e.ProfileLinkedPath = res.ProfileLinkedPath

	snapshot := res.Snapshot
	if snapshot == nil {
		snapshot = &DecisionSnapshot{
			ProfileID:     e.ProfileID,
			Source:        e.ProfileSource,
			DefaultAction: res.DefaultAction,
			Rules:         res.ParsedRules,
		}
	}
	if decision, ask := decisionFromSnapshot(snapshot, e.Path); !ask {
		return false, false, decision, nil
	}
	if !h.rootAskAllowed() {
		return false, false, VerdictDeny, nil
	}

	coordinator := h.coordinator()
	if coordinator == nil {
		verdict, afterResponse = h.DecideForResponse(ctx, e)
		return false, false, verdict, afterResponse
	}
	return coordinator.Admit(ctx, pending, res.Store, snapshot)
}

func (h *ProfileHandler) fallbackSnapshot(event *FileEvent) (RuleStore, *DecisionSnapshot) {
	if fallback, ok := h.fallback.(*PromptHandler); ok {
		exe := event.Exe
		if exe == "" {
			exe = unknownExe
		}
		event.Exe = exe
		store := fallbackRuleStore{handler: fallback, exe: exe}
		event.ProfileID = store.ID()
		event.ProfileSource = "fallback"
		return store, &DecisionSnapshot{
			ProfileID:     event.ProfileID,
			Source:        event.ProfileSource,
			DefaultAction: profile.DefaultActionAsk,
			Rules:         PathRules{Rules: fallback.RulesFor(exe), Default: VerdictDeny},
		}
	}
	return nil, &DecisionSnapshot{DefaultAction: profile.DefaultActionAsk}
}

func (h *ProfileHandler) fallbackDecision(ctx context.Context, e *FileEvent) (Verdict, func()) {
	if handler, ok := h.fallback.(postResponseDecisionHandler); ok {
		return handler.DecideForResponse(ctx, e)
	}
	return h.fallback.Decide(ctx, e), nil
}

func (h *ProfileHandler) RefreshProcessMapping(ctx context.Context, pid int32) error {
	if refresher, ok := h.lookup.(processMappingRefresher); ok {
		return refresher.RefreshProcessMapping(ctx, pid)
	}
	return nil
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

// FormatExactRule stores a normalized literal path using a tagged Go-quoted
// payload. Legacy +/- rules remain patterns; only this tagged form is exact.
func FormatExactRule(path string, v Verdict) string {
	path = filepath.Clean(path)
	if v == VerdictAllow {
		return "+ @" + strconv.Quote(path)
	}
	return "- @" + strconv.Quote(path)
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
	payload := entry[2:]
	if strings.HasPrefix(payload, "@") {
		path, err := strconv.Unquote(payload[1:])
		path = filepath.Clean(path)
		if err != nil || path == "." || !filepath.IsAbs(path) {
			return PathRule{}, false
		}
		return PathRule{Pattern: path, Verdict: v, Exact: true}, true
	}
	return PathRule{Pattern: strings.TrimSpace(payload), Verdict: v}, true
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
