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
	prompter Prompter
	timeout  time.Duration
	admit    func(string) (func(), bool)
	finish   func(context.Context, PendingEvent, Verdict) bool

	mu                    sync.Mutex
	groups                map[promptKey]*promptGroup
	profiles              map[string]map[*promptGroup]struct{}
	latestProfileSnapshot map[string]*DecisionSnapshot
	closing               bool
	unidentifiedSequence  atomic.Uint64
}

func NewPromptCoordinator(prompter Prompter, timeout time.Duration, admit func(string) (func(), bool), finish func(context.Context, PendingEvent, Verdict) bool) *PromptCoordinator {
	return &PromptCoordinator{
		prompter:              prompter,
		timeout:               timeout,
		admit:                 admit,
		finish:                finish,
		groups:                make(map[promptKey]*promptGroup),
		profiles:              make(map[string]map[*promptGroup]struct{}),
		latestProfileSnapshot: make(map[string]*DecisionSnapshot),
	}
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
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		_ = pending.Respond(VerdictDeny)
		return true, false, VerdictDeny, nil
	}
	snapshot = c.latestSnapshotLocked(snapshot)
	if verdict, ask := decisionFromSnapshot(snapshot, path); !ask {
		c.mu.Unlock()
		if c.finish != nil {
			c.finish(context.Background(), pending, verdict)
		} else {
			_ = pending.Respond(verdict)
		}
		return true, true, VerdictDeny, nil
	}
	c.mu.Unlock()

	release, ok := c.admit(snapshot.Source + "/" + snapshot.ProfileID)
	if !ok {
		_ = pending.Respond(VerdictDeny)
		return true, false, VerdictDeny, nil
	}
	owner, err := pending.Transfer()
	if err != nil {
		release()
		return false, false, VerdictDeny, nil
	}

	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		release()
		_ = owner.Respond(VerdictDeny)
		return true, false, VerdictDeny, nil
	}
	snapshot = c.latestSnapshotLocked(snapshot)
	if verdict, ask := decisionFromSnapshot(snapshot, path); !ask {
		c.mu.Unlock()
		if c.finish != nil {
			c.finish(context.Background(), owner, verdict)
		} else {
			_ = owner.Respond(verdict)
		}
		release()
		return true, true, VerdictDeny, nil
	}
	key := c.newPromptKey(event, snapshot, path)
	if group := c.groups[key]; group != nil {
		group.entries = append(group.entries, promptEntry{pending: owner, release: release})
		c.mu.Unlock()
		return true, true, VerdictDeny, nil
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
	c.mu.Unlock()

	go c.waitForPrompt(promptCtx, group)
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
	switch action {
	case ActionAllow:
		c.resolve(group, VerdictAllow)
	case ActionDeny:
		c.resolve(group, VerdictDeny)
	case ActionAllowAlways:
		won, accepted := c.resolve(group, VerdictAllow)
		if won && accepted && group.store != nil {
			_ = group.store.AppendRule(FormatRule(group.key.path, VerdictAllow))
		}
	case ActionDenyAlways:
		won, accepted := c.resolve(group, VerdictDeny)
		if won && accepted && group.store != nil {
			_ = group.store.AppendRule(FormatRule(group.key.path, VerdictDeny))
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
	profileKey := snapshot.Source + "/" + snapshot.ProfileID
	c.mu.Lock()
	if current := c.latestProfileSnapshot[profileKey]; current != nil && current.Revision >= snapshot.Revision {
		c.mu.Unlock()
		return
	}
	c.latestProfileSnapshot[profileKey] = snapshot
	groups := make([]*promptGroup, 0, len(c.profiles[profileKey]))
	for group := range c.profiles[profileKey] {
		groups = append(groups, group)
	}
	c.mu.Unlock()

	for _, group := range groups {
		verdict, ask := decisionFromSnapshot(snapshot, group.key.path)
		if ask {
			c.mu.Lock()
			if c.groups[group.key] == group {
				group.snapshot = snapshot
			}
			c.mu.Unlock()
			continue
		}
		c.resolve(group, verdict)
	}
}

// Close denies pending groups and rejects all future ownership transfers.
func (c *PromptCoordinator) Close() {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return
	}
	c.closing = true
	groups := make([]*promptGroup, 0, len(c.groups))
	for _, group := range c.groups {
		groups = append(groups, group)
	}
	c.mu.Unlock()
	for _, group := range groups {
		c.resolve(group, VerdictDeny)
	}
}

func (c *PromptCoordinator) resolve(group *promptGroup, verdict Verdict) (won, accepted bool) {
	c.mu.Lock()
	if c.groups[group.key] != group {
		c.mu.Unlock()
		return false, false
	}
	delete(c.groups, group.key)
	delete(c.profiles[group.key.profile], group)
	if len(c.profiles[group.key.profile]) == 0 {
		delete(c.profiles, group.key.profile)
	}
	entries := group.entries
	c.mu.Unlock()
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
	}
	return true, accepted
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
