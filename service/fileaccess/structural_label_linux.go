//go:build linux

package fileaccess

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/safing/portmaster/base/database"
	"github.com/safing/portmaster/base/database/query"
	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/mgr"
	"github.com/safing/portmaster/service/process"
	"github.com/safing/portmaster/service/process/tags"
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
	// generation is the last generation seeded; only apply, which holds
	// structuralApplyMu, reads or writes it.
	generation string

	mu        sync.Mutex
	byProfile map[string]uint32 // scopedID -> label
	byLabel   map[uint32]string // label -> scopedID
	next      uint32
	// compiled is the label set of the table apply is publishing; published
	// holds the labels whose policies the active bank carries.
	compiled  []uint32
	published map[uint32]bool
	// interpreters caches isInterpreter by executable path.
	interpreters map[string]bool
	// fingerprints is the digest the learned exec labels were learned under,
	// over learnedPaths; empty when nothing is learned.
	fingerprints string
	learnedPaths map[string]bool

	captureMu sync.Mutex
	captured  map[int32]capturedIdentity
}

type capturedIdentity struct {
	cmdline string
	env     []string
}

func newStructuralLabeller(fa *FileAccess, apply func()) *structuralLabeller {
	return &structuralLabeller{
		fa:           fa,
		apply:        apply,
		queue:        make(chan bpflsm.Record, 1024),
		closed:       make(chan struct{}),
		byProfile:    make(map[string]uint32),
		byLabel:      map[uint32]string{bpflsm.LabelUnidentified: ""},
		published:    make(map[uint32]bool),
		interpreters: make(map[string]bool),
		learnedPaths: make(map[string]bool),
		next:         bpflsm.LabelUnidentified + 1,
		captured:     make(map[int32]capturedIdentity),
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
	compiled := []uint32{bpflsm.LabelUnidentified}
	defer func() {
		l.mu.Lock()
		l.compiled = compiled
		l.mu.Unlock()
	}()
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
		compiled = append(compiled, label)
	}
	return policies
}

// markPublished records that the table built by the last labelPolicies call
// is now the active bank. apply calls it after a successful publish.
func (l *structuralLabeller) markPublished() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, label := range l.compiled {
		l.published[label] = true
	}
}

// ensurePublished publishes the table once if any label's policy is not in
// the active bank yet, so no label is written while it still maps to the
// pending policy. It reports whether every label is published.
func (l *structuralLabeller) ensurePublished(labels ...uint32) bool {
	missing := func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, label := range labels {
			if !l.published[label] {
				return true
			}
		}
		return false
	}
	if !missing() {
		return true
	}
	l.apply()
	return !missing()
}

// profileRules loads a profile by its scoped parts and flattens its
// file-access rule lists, with the global rules appended, in engine order.
func profileRules(source, id string) ([]bpflsm.RuleInput, bool, bool) {
	if profile.ProfileSource(source) != profile.SourceLocal {
		return nil, false, false
	}
	p, err := profile.GetLocalProfile(id, nil, nil)
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
	p, ok := l.liveProcess(ctx, int32(record.TGID))
	if !ok && record.Kind == bpflsm.RecordExec {
		// A short-lived process (an rm, say) can exit before its record is
		// read. It needs no label any more, but identifying it from the record
		// lets its executable be learned, so its next exec is labelled at once.
		p, ok = l.exitedProcess(ctx, record)
	}
	if !ok {
		return
	}
	label, tags, fingerprinted := l.labelOf(p)
	if !l.ensurePublished(label) {
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
	if record.Kind != bpflsm.RecordExec {
		return
	}
	switch {
	case record.Script.Ino != 0 && p.MatchingPath != "":
		l.learn(record.Exe, record.Script, label, p.MatchingPath)
	case record.Script.Ino == 0 && !tags && !fingerprinted:
		if identity, _ := scanFingerprints(nil); !identity {
			l.learn(record.Exe, bpflsm.ExecFile{}, label, p.Path)
		}
	}
}

// labelFor resolves a process to its profile label, allocating a new label if
// the profile has not been seen; callers publish it with ensurePublished. It also reports whether the
// process carries tags or its profile is keyed on cmdline/env/tags.
func (l *structuralLabeller) labelFor(ctx context.Context, pid int32) (label uint32, tags, fingerprinted, ok bool) {
	p, ok := l.liveProcess(ctx, pid)
	if !ok {
		return 0, false, false, false
	}
	label, tags, fingerprinted = l.labelOf(p)
	return label, tags, fingerprinted, true
}

// liveProcess identifies a running process through the daemon's own process
// lookup, re-read so a registered captured identity replaces a cached one.
func (l *structuralLabeller) liveProcess(ctx context.Context, pid int32) (*process.Process, bool) {
	if l.fa.profileHandler != nil {
		if refresher, ok := l.fa.profileHandler.lookup.(interface {
			RefreshProcessMapping(context.Context, int32) error
		}); ok {
			_ = refresher.RefreshProcessMapping(ctx, pid)
		}
	}
	p, err := process.GetProcessWithProfile(ctx, int(pid))
	if err != nil || p == nil {
		return nil, false
	}
	return p, true
}

// exitedProcess identifies an exited process from its exec record alone: the
// recorded path, confirmed to be the recorded inode, and the captured argv and
// envp. Only a plain executable qualifies; an interpreter's or an app
// bundle's profile depends on tags this cannot reproduce.
func (l *structuralLabeller) exitedProcess(ctx context.Context, record bpflsm.Record) (*process.Process, bool) {
	if !filepath.IsAbs(record.Path) {
		return nil, false
	}
	path, err := filepath.EvalSymlinks(record.Path)
	if err != nil || !bpflsm.SameFile(path, record.Exe) || l.isInterpreter(path) || strings.HasPrefix(path, "/app/") {
		return nil, false
	}
	env := make(map[string]string, len(record.Env))
	for _, entry := range record.Env {
		if key, value, ok := strings.Cut(entry, "="); ok {
			env[key] = value
		}
	}
	for _, key := range []string{"APPIMAGE", "SNAP", "FLATPAK_ID"} {
		if _, ok := env[key]; ok {
			return nil, false
		}
	}
	p := &process.Process{
		Pid:      int(record.TGID),
		Path:     path,
		ExecName: filepath.Base(path),
		Name:     filepath.Base(path),
		CmdLine:  strings.Join(record.Args, " "),
		Env:      env,
	}
	if _, err := p.GetProfile(ctx); err != nil {
		return nil, false
	}
	return p, true
}

// labelOf maps a process's profile to its label, allocating one for a profile
// not seen before. It also reports whether the process is an interpreter or
// carries tags, and whether its profile matches on cmdline, env or tags.
func (l *structuralLabeller) labelOf(p *process.Process) (label uint32, tags, fingerprinted bool) {
	layered := p.Profile()
	if layered == nil {
		return bpflsm.LabelUnidentified, false, false
	}
	local := layered.LocalProfile()
	if local == nil {
		return bpflsm.LabelUnidentified, false, false
	}
	tags = len(p.Tags) > 0 || l.isInterpreter(p.Path)
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
	if !known && label >= bpflsm.MaxLabels {
		return bpflsm.LabelUnidentified, tags, fingerprinted
	}
	return label, tags, fingerprinted
}

// isInterpreter reports whether processes of exe can be told apart by their
// script argument: the interpreter tag handler tags a probe invocation of it.
// `python -c` and similar carry no tag, yet the interpreter must never be
// labelled by its inode alone. Results are cached per path.
func (l *structuralLabeller) isInterpreter(exe string) bool {
	l.mu.Lock()
	known, cached := l.interpreters[exe]
	l.mu.Unlock()
	if cached {
		return known
	}
	probe, err := os.CreateTemp("", "filemaster-interpreter-probe-*.txt")
	if err != nil {
		return true
	}
	defer os.Remove(probe.Name())
	_, _ = probe.WriteString("#\n")
	_ = probe.Close()
	candidate := &process.Process{Path: exe, CmdLine: shellQuote(exe) + " " + shellQuote(probe.Name()), Cwd: "/"}
	new(tags.InterpHandler).AddTags(candidate)
	interpreter := len(candidate.Tags) > 0
	l.mu.Lock()
	l.interpreters[exe] = interpreter
	l.mu.Unlock()
	return interpreter
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// seedRunning enters every pre-existing process as pending, then resolves each
// from /proc so already-running processes are not stuck pending.
func (l *structuralLabeller) seedRunning(ctx context.Context) {
	seeded, err := l.enf.SeedProcesses()
	if err != nil {
		l.fa.mgr.Warn("fileaccess: seed running processes", "err", err)
	}
	// Resolve every process first and publish the new labels once, rather
	// than republishing per newly seen profile.
	labels := make([]uint32, len(seeded))
	resolved := make([]bool, len(seeded))
	for i, s := range seeded {
		labels[i], _, _, resolved[i] = l.labelFor(ctx, int32(s.TGID))
	}
	l.ensurePublished(labels...)
	for i, s := range seeded {
		if resolved[i] {
			_ = l.enf.Resolve(s.TGID, s.Start, 0, labels[i])
		}
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
	if !ok || !l.ensurePublished(label) {
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

var profileQueryDB = database.NewInterface(&database.Options{Local: true, Internal: true})

// scanFingerprints reports whether any profile matches on cmdline or env,
// and a digest of the fingerprints that can decide a learned executable's or
// script's profile: every prefix, regex, cmdline and env fingerprint, plus the
// equals fingerprints naming one of the learned paths. A cmdline or env
// profile can claim any executable's process, so no executable is labelled by
// its inode alone while one exists.
func scanFingerprints(learned map[string]bool) (identity bool, digest string) {
	it, err := profileQueryDB.Query(query.New(profile.ProfilesDBPath))
	if err != nil {
		return true, ""
	}
	var all []string
	for r := range it.Next {
		p, err := profile.EnsureProfile(r)
		if err != nil {
			continue
		}
		for _, fp := range p.Fingerprints {
			if fp.Type == profile.FingerprintTypeCmdlineID || fp.Type == profile.FingerprintTypeEnvID {
				identity = true
			}
			if fp.Operation == profile.FingerprintOperationEqualsID && !learned[fp.Value] {
				continue
			}
			all = append(all, p.ID+"\x00"+fp.Type+"\x00"+fp.Key+"\x00"+fp.Operation+"\x00"+fp.Value)
		}
	}
	if it.Err() != nil {
		return true, ""
	}
	sort.Strings(all)
	return identity, strings.Join(all, "\n")
}

// forgetIfFingerprintsChanged drops every learned exec label when a
// fingerprint that could decide a learned path's profile changed. Metadata
// saves and new profiles for other paths keep them.
func (l *structuralLabeller) forgetIfFingerprintsChanged() {
	l.mu.Lock()
	learnedAt := l.fingerprints
	paths := maps.Clone(l.learnedPaths)
	l.mu.Unlock()
	if learnedAt == "" {
		return
	}
	if _, digest := scanFingerprints(paths); digest != learnedAt {
		l.mu.Lock()
		l.fingerprints = ""
		l.learnedPaths = make(map[string]bool)
		l.mu.Unlock()
		_ = l.enf.ClearExecLabels()
	}
}

// learn records an exec label for the process at path and re-takes the
// fingerprint digest over the learned paths.
func (l *structuralLabeller) learn(exe, script bpflsm.ExecFile, label uint32, path string) {
	l.mu.Lock()
	l.learnedPaths[path] = true
	paths := maps.Clone(l.learnedPaths)
	l.mu.Unlock()
	_, digest := scanFingerprints(paths)
	l.mu.Lock()
	l.fingerprints = digest
	l.mu.Unlock()
	_ = l.enf.LearnExec(exe, script, label)
}
