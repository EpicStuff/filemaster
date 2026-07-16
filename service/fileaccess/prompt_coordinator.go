package fileaccess

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/safing/portmaster/service/profile"
)

// groupedPrompter lets a presentation implementation bind one stable
// notification identity to an exact prompt group. Prompter remains supported
// for existing presentations and tests.
type groupedPrompter interface {
	PromptGroup(context.Context, FileEvent, time.Duration, string) (string, bool)
}

type promptKey struct {
	profile string
	op      FileOp
	path    string
	process string
}

func (key promptKey) String() string {
	if key.profile != "" {
		return key.profile + ":" + key.op.String() + ":" + key.path
	}
	return "unidentified:" + key.process + ":" + key.op.String() + ":" + key.path
}

type promptEntry struct {
	pending PendingEvent
	release func()
}

type promptGroup struct {
	key      promptKey
	snapshot *DecisionSnapshot
	store    RuleStore
	event    FileEvent
	entries  []promptEntry
	cancel   context.CancelFunc
}

// PromptCoordinator retains transferred events until the single visible
// exact-match prompt is answered, timed out, overloaded, or superseded by a
// profile snapshot.
type PromptCoordinator struct {
	prompter            Prompter
	timeout             time.Duration
	admit               func(string) (func(), bool)
	finish              func(context.Context, PendingEvent, Verdict) bool
	complete            func()
	afterAdmission      func()
	beforePromptResolve func()

	lifecycle *PipelineLifecycle

	mu                    sync.Mutex
	groups                map[promptKey]*promptGroup
	profiles              map[string]map[*promptGroup]struct{}
	latestProfileSnapshot map[string]*DecisionSnapshot
	unidentifiedSequence  atomic.Uint64
	activePrompts         atomic.Int64
	promptChanged         chan struct{}
	persistence           *RulePersistence
}

func NewPromptCoordinator(prompter Prompter, timeout time.Duration, admit func(string) (func(), bool), finish func(context.Context, PendingEvent, Verdict) bool) *PromptCoordinator {
	return newPromptCoordinator(prompter, timeout, admit, finish, NewPipelineLifecycle())
}

func newPromptCoordinator(prompter Prompter, timeout time.Duration, admit func(string) (func(), bool), finish func(context.Context, PendingEvent, Verdict) bool, lifecycle *PipelineLifecycle) *PromptCoordinator {
	if lifecycle == nil {
		lifecycle = NewPipelineLifecycle()
	}
	coordinator := &PromptCoordinator{
		prompter:              prompter,
		timeout:               timeout,
		admit:                 admit,
		finish:                finish,
		lifecycle:             lifecycle,
		groups:                make(map[promptKey]*promptGroup),
		profiles:              make(map[string]map[*promptGroup]struct{}),
		latestProfileSnapshot: make(map[string]*DecisionSnapshot),
		promptChanged:         make(chan struct{}, 1),
	}
	coordinator.persistence = newRulePersistence(coordinator.SnapshotReplaced, RulePersistenceOptions{}, lifecycle)
	return coordinator
}

// RulePersistence exposes the bounded durable-rule flush interface needed by
// the later shared shutdown phase without activating that shutdown behavior.
func (c *PromptCoordinator) RulePersistence() *RulePersistence {
	return c.persistence
}

// FlushPermanentRules is the bounded persistence-only hook for Phase 7. It
// neither closes prompt admission nor drains fanotify ownership.
func (c *PromptCoordinator) FlushPermanentRules(ctx context.Context) error {
	if c.persistence == nil {
		return nil
	}
	return c.persistence.Flush(ctx)
}

// Admit transfers a pending Ask to an exact group. The result tells the
// pipeline whether it already resolved the event or now owns it asynchronously.
func (c *PromptCoordinator) Admit(ctx context.Context, pending PendingEvent, store RuleStore, snapshot *DecisionSnapshot) (handled, handedOff bool, verdict Verdict, afterResponse func()) {
	if pending == nil || pending.Event() == nil || snapshot == nil {
		return false, false, VerdictDeny, nil
	}
	event := pending.Event()
	path, err := normalizePromptPath(event.Path)
	if err != nil {
		return false, false, VerdictDeny, nil
	}
	if !c.lifecycle.IsRunning() {
		_ = pending.Respond(VerdictDeny)
		return true, false, VerdictDeny, nil
	}

	release, ok := c.admit(snapshot.Source + "/" + snapshot.ProfileID)
	if !ok {
		_ = pending.Respond(VerdictDeny)
		return true, false, VerdictDeny, nil
	}

	var owner PendingEvent
	var transferErr error
	var immediate *Verdict
	admitted := c.lifecycle.whileRunning(func() {
		c.persistence.ensureStoreRunning(snapshot.Source, snapshot.ProfileID, store)
		owner, transferErr = pending.Transfer()
		if transferErr != nil {
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		snapshot = c.latestSnapshotLocked(snapshot)
		if currentVerdict, ask := decisionFromSnapshot(snapshot, path); !ask {
			immediate = &currentVerdict
			return
		}
		key := c.newPromptKey(event, snapshot, path)
		if existing := c.groups[key]; existing != nil {
			existing.entries = append(existing.entries, promptEntry{pending: owner, release: release})
			return
		}
		promptCtx, cancel := context.WithCancel(ctx)
		promptEvent := *event
		promptEvent.Path = path
		group := &promptGroup{
			key:      key,
			snapshot: snapshot,
			store:    store,
			event:    promptEvent,
			entries:  []promptEntry{{pending: owner, release: release}},
			cancel:   cancel,
		}
		c.groups[key] = group
		profileGroups := c.profiles[key.profile]
		if profileGroups == nil {
			profileGroups = make(map[*promptGroup]struct{})
			c.profiles[key.profile] = profileGroups
		}
		profileGroups[group] = struct{}{}
		c.activePrompts.Add(1)
		go func() {
			defer func() {
				c.activePrompts.Add(-1)
				select {
				case c.promptChanged <- struct{}{}:
				default:
				}
			}()
			c.waitForPrompt(promptCtx, group)
		}()
	})
	if !admitted {
		release()
		_ = pending.Respond(VerdictDeny)
		return true, false, VerdictDeny, nil
	}
	if transferErr != nil {
		release()
		return false, false, VerdictDeny, nil
	}
	if c.afterAdmission != nil {
		c.afterAdmission()
	}
	if immediate != nil {
		resolvedVerdict := *immediate
		if !c.lifecycle.IsRunning() {
			resolvedVerdict = VerdictDeny
		}
		if c.finish != nil {
			c.finish(context.Background(), owner, resolvedVerdict)
		} else {
			_ = owner.Respond(resolvedVerdict)
		}
		release()
		if c.complete != nil {
			c.complete()
		}
		return true, true, VerdictDeny, nil
	}
	return true, true, VerdictDeny, nil
}

func (c *PromptCoordinator) waitForPrompt(ctx context.Context, group *promptGroup) {
	if c.prompter == nil {
		c.resolve(group, VerdictDeny)
		return
	}
	var action string
	var ok bool
	if prompter, grouped := c.prompter.(groupedPrompter); grouped {
		action, ok = prompter.PromptGroup(ctx, group.event, c.timeout, group.key.String())
	} else {
		action, ok = c.prompter.Prompt(ctx, group.event, c.timeout)
	}
	if !ok {
		c.resolve(group, VerdictDeny)
		return
	}
	if c.beforePromptResolve != nil {
		c.beforePromptResolve()
	}
	switch action {
	case ActionAllow:
		c.resolve(group, VerdictAllow)
	case ActionDeny:
		c.resolve(group, VerdictDeny)
	case ActionAllowAlways:
		won, accepted := c.resolve(group, VerdictAllow)
		if won && accepted && c.persistence != nil {
			c.persistence.ApplyAccepted(group.snapshot, group.store, group.key.path, VerdictAllow)
		}
	case ActionDenyAlways:
		won, accepted := c.resolve(group, VerdictDeny)
		if won && accepted && c.persistence != nil {
			c.persistence.ApplyAccepted(group.snapshot, group.store, group.key.path, VerdictDeny)
		}
	default:
		c.resolve(group, VerdictDeny)
	}
}

// SnapshotReplaced reevaluates every open group for the changed profile. A
// group is retained only when the replacement still asks for its exact path.
func (c *PromptCoordinator) SnapshotReplaced(snapshot *DecisionSnapshot) {
	if snapshot == nil {
		return
	}
	c.lifecycle.whileRunning(func() { c.snapshotReplacedRunning(snapshot) })
}

func (c *PromptCoordinator) snapshotReplacedRunning(snapshot *DecisionSnapshot) {
	if snapshot == nil {
		return
	}
	profileKey := snapshot.Source + "/" + snapshot.ProfileID
	c.mu.Lock()
	if current := c.latestProfileSnapshot[profileKey]; current != nil && current.Revision >= snapshot.Revision {
		c.mu.Unlock()
		return
	}
	c.latestProfileSnapshot[profileKey] = snapshot
	type detachedGroup struct {
		group   *promptGroup
		entries []promptEntry
		verdict Verdict
	}
	detached := make([]detachedGroup, 0, len(c.profiles[profileKey]))
	for group := range c.profiles[profileKey] {
		latest := c.latestProfileSnapshot[profileKey]
		verdict, ask := decisionFromSnapshot(latest, group.key.path)
		if ask {
			group.snapshot = latest
			continue
		}
		entries, won := c.claimGroupLocked(group)
		if won {
			detached = append(detached, detachedGroup{group: group, entries: entries, verdict: verdict})
		}
	}
	c.mu.Unlock()

	for _, group := range detached {
		c.completeGroup(group.group, group.entries, group.verdict)
	}
}

type PromptCoordinatorDiagnostics struct {
	Groups        int
	Events        int
	ActivePrompts int64
}

func (c *PromptCoordinator) Diagnostics() PromptCoordinatorDiagnostics {
	c.mu.Lock()
	defer c.mu.Unlock()
	diagnostics := PromptCoordinatorDiagnostics{
		Groups:        len(c.groups),
		ActivePrompts: c.activePrompts.Load(),
	}
	for _, group := range c.groups {
		diagnostics.Events += len(group.entries)
	}
	return diagnostics
}

func (c *PromptCoordinator) Drain(ctx context.Context) error {
	type detachedGroup struct {
		group   *promptGroup
		entries []promptEntry
	}
	c.mu.Lock()
	detached := make([]detachedGroup, 0, len(c.groups))
	for _, group := range c.groups {
		entries, won := c.claimGroupLocked(group)
		if won {
			detached = append(detached, detachedGroup{group: group, entries: entries})
		}
	}
	c.mu.Unlock()

	for _, group := range detached {
		c.completeGroup(group.group, group.entries, VerdictDeny)
	}

	for c.activePrompts.Load() > 0 {
		select {
		case <-c.promptChanged:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Close denies pending groups and rejects all future ownership transfers.
func (c *PromptCoordinator) Close() {
	c.lifecycle.BeginClosing(context.Background())
	c.mu.Lock()
	type detachedGroup struct {
		group   *promptGroup
		entries []promptEntry
	}
	detached := make([]detachedGroup, 0, len(c.groups))
	for _, group := range c.groups {
		entries, won := c.claimGroupLocked(group)
		if won {
			detached = append(detached, detachedGroup{group: group, entries: entries})
		}
	}
	c.mu.Unlock()
	for _, group := range detached {
		c.completeGroup(group.group, group.entries, VerdictDeny)
	}
}

func (c *PromptCoordinator) resolve(group *promptGroup, verdict Verdict) (won, accepted bool) {
	c.mu.Lock()
	entries, won := c.claimGroupLocked(group)
	c.mu.Unlock()
	if !won {
		return false, false
	}
	return true, c.completeGroup(group, entries, verdict)
}

// claimGroupLocked is the single resolution winner primitive. Callers must
// hold c.mu; successful claims detach a group before responses run.
func (c *PromptCoordinator) claimGroupLocked(group *promptGroup) ([]promptEntry, bool) {
	if c.groups[group.key] != group {
		return nil, false
	}
	delete(c.groups, group.key)
	delete(c.profiles[group.key.profile], group)
	if len(c.profiles[group.key.profile]) == 0 {
		delete(c.profiles, group.key.profile)
	}
	return group.entries, true
}

func (c *PromptCoordinator) completeGroup(group *promptGroup, entries []promptEntry, verdict Verdict) (accepted bool) {
	group.cancel()
	for _, entry := range entries {
		func() {
			defer func() { _ = recover() }()
			if c.finish != nil && c.finish(context.Background(), entry.pending, verdict) {
				accepted = true
			}
		}()
		func() {
			defer func() { _ = recover() }()
			if entry.release != nil {
				entry.release()
			}
		}()
		func() {
			defer func() { _ = recover() }()
			if c.complete != nil {
				c.complete()
			}
		}()
	}
	return accepted
}

func decisionFromSnapshot(snapshot *DecisionSnapshot, path string) (Verdict, bool) {
	if verdict, ok := snapshot.Rules.Lookup(path); ok {
		return verdict, false
	}
	switch snapshot.DefaultAction {
	case profile.DefaultActionPermit:
		return VerdictAllow, false
	case profile.DefaultActionBlock:
		return VerdictDeny, false
	default:
		return VerdictDeny, true
	}
}

func (c *PromptCoordinator) latestSnapshotLocked(snapshot *DecisionSnapshot) *DecisionSnapshot {
	profileKey := snapshot.Source + "/" + snapshot.ProfileID
	if current := c.latestProfileSnapshot[profileKey]; current != nil {
		return current
	}
	c.latestProfileSnapshot[profileKey] = snapshot
	return snapshot
}

func (c *PromptCoordinator) newPromptKey(event *FileEvent, snapshot *DecisionSnapshot, path string) promptKey {
	key := promptKey{profile: snapshot.Source + "/" + snapshot.ProfileID, op: event.Op, path: path}
	if snapshot.ProfileID == "" {
		key.profile = ""
		key.process = event.ProcessIdentity
		if key.process == "" {
			key.process = "unidentified:" + strconv.FormatUint(c.unidentifiedSequence.Add(1), 10)
		}
	}
	return key
}

func normalizePromptPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("prompt path must be absolute")
	}
	return filepath.Clean(path), nil
}
