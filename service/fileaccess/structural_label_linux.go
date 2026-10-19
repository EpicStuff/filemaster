//go:build linux

package fileaccess

import (
	"context"
	"strings"
	"sync"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/mgr"
	"github.com/safing/portmaster/service/process"
	"github.com/safing/portmaster/service/profile"
)

// structuralLabeller resolves the BPF labelling records into profile labels.
//
// A label is a profile number stable for the daemon's lifetime. Label 0 is the
// unidentified profile; others are assigned the first time a process resolves
// to a profile. The kernel leaves a process it cannot label itself pending and
// emits a record; this resolves the record's process to a profile, publishes
// the label's policy if it is new, and writes the label back.
type structuralLabeller struct {
	fa     *FileAccess
	enf    *bpflsm.Enforcer
	apply  func()
	queue  chan bpflsm.Record
	closed chan struct{}

	mu        sync.Mutex
	byProfile map[string]uint32 // scopedID -> label
	byLabel   map[uint32]string // label -> scopedID
	next      uint32

	captureMu sync.Mutex
	captured  map[int32]capturedIdentity
}

type capturedIdentity struct {
	cmdline string
	env     []string
}

func newStructuralLabeller(fa *FileAccess, apply func()) *structuralLabeller {
	return &structuralLabeller{
		fa:        fa,
		apply:     apply,
		queue:     make(chan bpflsm.Record, 1024),
		closed:    make(chan struct{}),
		byProfile: make(map[string]uint32),
		byLabel:   map[uint32]string{bpflsm.LabelUnidentified: ""},
		next:      bpflsm.LabelUnidentified + 1,
		captured:  make(map[int32]capturedIdentity),
	}
}

// labelPolicies returns one LabelPolicy per assigned label, for the compiler.
// Label 0 is always the unidentified profile; the caller supplies its lists.
func (l *structuralLabeller) labelPolicies(unidentified bpflsm.LabelPolicy) []bpflsm.LabelPolicy {
	l.mu.Lock()
	byLabel := make(map[uint32]string, len(l.byLabel))
	for label, id := range l.byLabel {
		byLabel[label] = id
	}
	l.mu.Unlock()

	unidentified.Label = bpflsm.LabelUnidentified
	policies := []bpflsm.LabelPolicy{unidentified}
	for label, scopedID := range byLabel {
		if label == bpflsm.LabelUnidentified {
			continue
		}
		source, id, ok := strings.Cut(scopedID, "/")
		if !ok {
			continue
		}
		rules, defaultAllow, ok := profileRules(source, id)
		if !ok {
			continue
		}
		policies = append(policies, bpflsm.LabelPolicy{Label: label, Rules: rules, DefaultAllow: defaultAllow})
	}
	return policies
}

// profileRules loads a profile by its scoped parts and flattens its
// file-access rule lists, with the global rules appended, in engine order.
func profileRules(source, id string) ([]bpflsm.RuleInput, bool, bool) {
	p, err := profile.GetLocalProfile(profile.MakeProfileKey(profile.ProfileSource(source), id), nil, nil)
	if err != nil || p == nil {
		return nil, false, false
	}
	lists := scopedRuleLists(p.GetFileAccessReadRules(), p.GetFileAccessWriteRules(), p.GetFileAccessExecRules())
	rules := flattenRules(lists)
	defaultAllow := verdictFromDefaultAction(p.EffectiveDefaultAction()) == VerdictAllow
	return rules, defaultAllow, true
}

func flattenRules(lists ruleLists) []bpflsm.RuleInput {
	var rules []bpflsm.RuleInput
	for _, list := range []struct {
		list    bpflsm.RuleList
		entries []string
	}{
		{bpflsm.ListRead, lists.read},
		{bpflsm.ListWrite, lists.write},
		{bpflsm.ListExecute, lists.exec},
	} {
		for _, entry := range list.entries {
			parsed := ParseRules([]string{entry})
			if len(parsed.Rules) == 0 {
				continue
			}
			rule := parsed.Rules[0]
			rules = append(rules, bpflsm.RuleInput{
				List:    list.list,
				Pattern: rule.Pattern,
				Allow:   rule.Verdict == VerdictAllow,
				Kind:    bpflsm.RuleKind(rule.ObjectKind),
			})
		}
	}
	return rules
}

// enqueue is the enforcer's OnRecord callback.
func (l *structuralLabeller) enqueue(record bpflsm.Record) {
	select {
	case l.queue <- record:
	default:
		// The resolver is behind; the process stays pending (deny) until its
		// next exec, which is the documented overflow behaviour.
	}
}

func (l *structuralLabeller) run(w *mgr.WorkerCtx) {
	for {
		select {
		case <-w.Ctx().Done():
			return
		case <-l.closed:
			return
		case record := <-l.queue:
			l.resolve(w.Ctx(), record)
		}
	}
}

func (l *structuralLabeller) stop() {
	close(l.closed)
}

// resolve resolves one record's process to a label and writes it back.
func (l *structuralLabeller) resolve(ctx context.Context, record bpflsm.Record) {
	if record.Kind == bpflsm.RecordExec {
		l.setCapture(int32(record.TGID), record.Args, record.Env)
		defer l.clearCapture(int32(record.TGID))
	}
	label, tags, fingerprinted, ok := l.labelFor(ctx, int32(record.TGID))
	if !ok {
		return
	}
	if err := l.enf.Resolve(record.TGID, record.Start, record.Seq, label); err != nil {
		l.fa.mgr.Warn("fileaccess: resolve process label", "tgid", record.TGID, "err", err)
		return
	}
	// Learn the fast path for the next exec: a script by its interpreter and
	// inode, a plain binary by itself. An interpreter or a profile keyed on
	// cmdline, env or a tag must stay pending, so distinct invocations do not
	// collapse onto one exe-only label.
	switch {
	case record.Script.Ino != 0:
		_ = l.enf.LearnExec(record.Exe, record.Script, label)
	case record.Kind == bpflsm.RecordExec && !tags && !fingerprinted:
		_ = l.enf.LearnExec(record.Exe, bpflsm.ExecFile{}, label)
	}
}

// labelFor resolves a process to its profile label, allocating and publishing
// a new label if the profile has not been seen. It also reports whether the
// process carries tags or its profile is keyed on cmdline/env/tags.
func (l *structuralLabeller) labelFor(ctx context.Context, pid int32) (label uint32, tags, fingerprinted, ok bool) {
	// Force a fresh read so the captured identity, not a cached /proc one, is used.
	if l.fa.profileHandler != nil {
		if refresher, ok := l.fa.profileHandler.lookup.(interface {
			RefreshProcessMapping(context.Context, int32) error
		}); ok {
			_ = refresher.RefreshProcessMapping(ctx, pid)
		}
	}
	p, err := process.GetProcessWithProfile(ctx, int(pid))
	if err != nil || p == nil {
		return 0, false, false, false
	}
	layered := p.Profile()
	if layered == nil {
		return bpflsm.LabelUnidentified, false, false, true
	}
	local := layered.LocalProfile()
	if local == nil {
		return bpflsm.LabelUnidentified, false, false, true
	}
	tags = len(p.Tags) > 0
	for _, fp := range local.Fingerprints {
		switch fp.Type {
		case profile.FingerprintTypeCmdlineID, profile.FingerprintTypeEnvID, profile.FingerprintTypeTagID:
			fingerprinted = true
		}
	}
	scopedID := local.ScopedID()
	l.mu.Lock()
	label, known := l.byProfile[scopedID]
	if !known {
		label = l.next
		l.next++
		l.byProfile[scopedID] = label
		l.byLabel[label] = scopedID
	}
	l.mu.Unlock()
	if !known {
		if label >= bpflsm.MaxLabels {
			return bpflsm.LabelUnidentified, tags, fingerprinted, true
		}
		// Publish the new label's policy before the label is written, so no
		// operation sees the label mapped to the pending policy.
		l.apply()
	}
	return label, tags, fingerprinted, true
}

// seedRunning enters every pre-existing process as pending, then resolves each
// from /proc so already-running processes are not stuck pending.
func (l *structuralLabeller) seedRunning(ctx context.Context) {
	seeded, err := l.enf.SeedProcesses()
	if err != nil {
		l.fa.mgr.Warn("fileaccess: seed running processes", "err", err)
	}
	for _, s := range seeded {
		label, _, _, ok := l.labelFor(ctx, int32(s.TGID))
		if !ok {
			continue
		}
		_ = l.enf.Resolve(s.TGID, s.Start, 0, label)
	}
}

// beforeOpen resolves a pending opener before its open is answered, so a
// script an interpreter is about to run is labelled before it runs.
func (l *structuralLabeller) beforeOpen(ctx context.Context, event *FileEvent) {
	if event == nil || event.PID <= 0 {
		return
	}
	proc, ok, err := l.enf.Proc(uint32(event.PID))
	if err != nil || !ok || proc.Label != bpflsm.LabelPending {
		return
	}
	label, _, _, ok := l.labelFor(ctx, event.PID)
	if !ok || label == bpflsm.LabelPending {
		return
	}
	_ = l.enf.Resolve(uint32(event.PID), proc.Start, proc.Seq, label)
}

func (l *structuralLabeller) setCapture(pid int32, args, env []string) {
	l.captureMu.Lock()
	l.captured[pid] = capturedIdentity{cmdline: strings.Join(args, " "), env: env}
	l.captureMu.Unlock()
}

func (l *structuralLabeller) clearCapture(pid int32) {
	l.captureMu.Lock()
	delete(l.captured, pid)
	l.captureMu.Unlock()
}

func (l *structuralLabeller) capture(pid int32) (string, []string, bool) {
	l.captureMu.Lock()
	defer l.captureMu.Unlock()
	c, ok := l.captured[pid]
	return c.cmdline, c.env, ok
}
