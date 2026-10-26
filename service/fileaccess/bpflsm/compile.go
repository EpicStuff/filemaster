//go:build linux

package bpflsm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

// Operation is the Filemaster decision-engine operation the BPF side counts.
type Operation uint32

const (
	OperationRead Operation = iota
	OperationWrite
	OperationExecute
	OperationCreate
	OperationDelete
)

var allOperations = [...]Operation{OperationRead, OperationWrite, OperationExecute, OperationCreate, OperationDelete}

// RuleList is the rule list a rule came from.
type RuleList uint8

const (
	ListRead RuleList = iota
	ListWrite
	ListExecute
)

// RuleKind mirrors fileaccess.ObjectKind.
type RuleKind uint8

const (
	KindAny RuleKind = iota
	KindFile
	KindFolder
)

// RuleInput is one rule of one list, in engine order.
type RuleInput struct {
	List    RuleList
	Pattern string
	Allow   bool
	Kind    RuleKind
}

// ScopeInput is one watch-path rule, in configured order.
type ScopeInput struct {
	Path    string
	Exclude bool
}

// LabelPolicy is one label's profile snapshot: its rules in engine order
// and whether its no-match default allows.
type LabelPolicy struct {
	Label        uint32
	Rules        []RuleInput
	DefaultAllow bool
}

// Policy is the plain policy the compiler receives. The package cannot
// import fileaccess, so the caller flattens its snapshots into this. A label
// left out maps to the pending policy, which denies.
type Policy struct {
	Scopes []ScopeInput
	Labels []LabelPolicy
}

// CompiledPattern is one distinct kernel pattern: a cleaned `/**` prefix
// matched by containment, or a tokenized filepath.Match program indexing the
// table's flat Chunks range.
type CompiledPattern struct {
	Text      string
	Recursive bool
	ChunkOff  uint32
	ChunkLen  uint32
}

// CompiledChunk, CompiledToken and CompiledRange are the flat token program a
// non-recursive pattern compiles to, mirroring the kernel's Chunk/Token/Range.
type CompiledChunk struct {
	Star     bool
	TokenOff uint32
	TokenLen uint32
}

type CompiledToken struct {
	Kind     tokKind
	Byte     byte
	Negated  bool
	RangeOff uint32
	RangeLen uint32
}

type CompiledRange struct {
	Lo uint32
	Hi uint32
}

// CompiledRule is one rule reference in a rule list.
type CompiledRule struct {
	Pattern uint16
	List    RuleList
	Allow   bool
	Kind    RuleKind
}

// CompiledContext is one absolute path an object is reachable at. Subvolume
// marks a context on a covered filesystem whose subvolumes the kernel cannot
// tell apart; it denies.
type CompiledContext struct {
	Path      string
	ParentLen uint32
	Overflow  bool
	Subvolume bool
	Scopes    []ScopeInput
}

// CompiledRuleList is one policy's ordered rules for a context. An overflowed
// list denies.
type CompiledRuleList struct {
	Overflow bool
	Rules    []CompiledRule
}

// CompiledPolicy is one distinct rule set. Lists maps a context index to its
// rule list; a context without an entry has no rules for this policy.
type CompiledPolicy struct {
	DefaultAllow bool
	Lists        map[uint32]uint32
}

// CompiledObject is one inode-keyed walk stop and its contexts.
type CompiledObject struct {
	File         fileID
	FirstContext uint32
	ContextCount uint32
}

// Table is the complete bank image Enforcer.Publish writes. Policies[0] is
// the pending policy: every label's rules as denies, and a deny default.
type Table struct {
	Objects   []CompiledObject
	Contexts  []CompiledContext
	Patterns  []CompiledPattern
	Chunks    []CompiledChunk
	Tokens    []CompiledToken
	Ranges    []CompiledRange
	Policies  []CompiledPolicy
	RuleLists []CompiledRuleList
	Labels    map[uint32]uint32

	// btrfs is the layout the kernel needs to key btrfs objects by subvolume
	// as this table does; it is published with the table's bank.
	btrfs btrfsLayout
}

// classifiedRule is a rule after matchPathPattern's split into the `/**`
// containment form and the filepath.Match form.
type classifiedRule struct {
	input     RuleInput
	recursive bool
	prefix    string       // the /** containment prefix, for a recursive rule
	program   tokenProgram // the token program, for a filepath.Match rule
	// literal is the prefix every path the rule can match starts with.
	literal string
}

// Compile turns a policy and the current mount table into a bank image.
func Compile(policy Policy) (Table, []CompileWarning, error) {
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return Table{}, nil, fmt.Errorf("read mountinfo: %w", err)
	}
	warnings := newWarnings()

	// Each distinct rule set becomes one policy. Policy 0 is the pending policy
	// and is never shared with a label's own.
	type labelRules struct {
		rules        []classifiedRule
		defaultAllow bool
	}
	var sets []labelRules
	setIndex := make(map[string]uint32)
	labels := make(map[uint32]uint32, len(policy.Labels))
	var pending []classifiedRule
	seenPending := make(map[string]struct{})
	for _, label := range policy.Labels {
		var rules []classifiedRule
		var key strings.Builder
		fmt.Fprintf(&key, "%t", label.DefaultAllow)
		for _, rule := range label.Rules {
			classified, ok := classifyRule(rule)
			if !ok {
				warnings.add("pattern-never-matches", rule.Pattern)
				continue
			}
			rules = append(rules, classified)
			fmt.Fprintf(&key, "\x00%d|%d|%t|%s", rule.List, rule.Kind, rule.Allow, rule.Pattern)
			denied := classified
			denied.input.Allow = false
			pendingKey := fmt.Sprintf("%d|%d|%s", rule.List, rule.Kind, rule.Pattern)
			if _, ok := seenPending[pendingKey]; !ok {
				seenPending[pendingKey] = struct{}{}
				pending = append(pending, denied)
			}
		}
		index, ok := setIndex[key.String()]
		if !ok {
			index = uint32(len(sets)) + 1
			setIndex[key.String()] = index
			sets = append(sets, labelRules{rules: rules, defaultAllow: label.DefaultAllow})
		}
		labels[label.Label] = index
	}
	sets = append([]labelRules{{rules: pending}}, sets...)
	if len(sets) > maxPolicies {
		return Table{}, warnings.list(), fmt.Errorf("compile structural table: %d distinct policies, more than %d", len(sets), maxPolicies)
	}

	var scopes []ScopeInput
	for _, scope := range policy.Scopes {
		if !filepath.IsAbs(scope.Path) {
			continue
		}
		scopes = append(scopes, ScopeInput{Path: filepath.Clean(scope.Path), Exclude: scope.Exclude})
	}

	// A candidate is true when a scope or rule anchors on it.
	candidates := make(map[string]bool)
	for _, scope := range scopes {
		if !scope.Exclude {
			if anchor, ok := existingDirectory(scope.Path); ok {
				candidates[anchor] = true
			}
		}
	}
	for _, rule := range pending {
		if anchor, ok := existingDirectory(anchorPath(rule)); ok {
			candidates[anchor] = true
		}
	}
	for _, mount := range mounts {
		if _, ok := candidates[mount.Mountpoint]; !ok {
			candidates[mount.Mountpoint] = false
		}
	}

	byID := make(map[int]*mountinfo.Info, len(mounts))
	var btrfs btrfsLayout
	var btrfsErr error
	for _, mount := range mounts {
		byID[mount.ID] = mount
		if mount.FSType == "btrfs" && !btrfs.ok && btrfsErr == nil {
			btrfs, btrfsErr = btrfsLayoutSource()
		}
	}
	unknownSubvolumes := make(map[uint64]bool)
	anchored := make(map[uint64]bool)
	contextsByObject := make(map[fileID]map[string]struct{})
	for candidate, anchor := range candidates {
		id, paths, ok := reachablePaths(candidate, mounts, byID, btrfs, unknownSubvolumes)
		if anchor && id.dev != 0 {
			anchored[id.dev] = true
		}
		if !ok {
			continue
		}
		if contextsByObject[id] == nil {
			contextsByObject[id] = make(map[string]struct{})
		}
		for _, path := range paths {
			contextsByObject[id][path] = struct{}{}
		}
	}
	if len(contextsByObject) > maxObjects {
		return Table{}, warnings.list(), fmt.Errorf("compile structural table: %d inode objects, more than %d", len(contextsByObject), maxObjects)
	}

	ids := make([]fileID, 0, len(contextsByObject))
	for id := range contextsByObject {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].dev != ids[j].dev {
			return ids[i].dev < ids[j].dev
		}
		if ids[i].subvol != ids[j].subvol {
			return ids[i].subvol < ids[j].subvol
		}
		return ids[i].ino < ids[j].ino
	})

	table := Table{Labels: labels, btrfs: btrfs}
	for _, set := range sets {
		table.Policies = append(table.Policies, CompiledPolicy{DefaultAllow: set.defaultAllow, Lists: make(map[uint32]uint32)})
	}
	patternIndex := make(map[string]uint16)
	listIndex := make(map[string]uint32)
	overflowPatterns := make(map[string]struct{})
	policyLists := 0
	for _, id := range ids {
		paths := make([]string, 0, len(contextsByObject[id]))
		for path := range contextsByObject[id] {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		object := CompiledObject{File: id, FirstContext: uint32(len(table.Contexts)), ContextCount: uint32(len(paths))}
		for _, path := range paths {
			if len(path) > maxString {
				return Table{}, warnings.list(), fmt.Errorf("compile structural table: path %q is longer than %d bytes", path, maxString)
			}
			contextIndex := uint32(len(table.Contexts))
			context := CompiledContext{Path: path, ParentLen: uint32(len(filepath.Dir(path)))}
			for _, scope := range scopes {
				if pathContains(scope.Path, path) {
					context.Scopes = append(context.Scopes, scope)
					break
				}
				if pathContains(path, scope.Path) {
					context.Scopes = append(context.Scopes, scope)
				}
			}
			if len(context.Scopes) > contextScopes {
				context.Overflow = true
				context.Scopes = nil
				warnings.add("context-scope-overflow", path)
			}
			for policyIndex, set := range sets {
				var list CompiledRuleList
				var included []string
				for _, rule := range set.rules {
					if !couldMatchAtOrBelow(rule.literal, path) {
						continue
					}
					included = append(included, rule.input.Pattern)
					index, fits, err := internPattern(&table, patternIndex, rule)
					if err != nil {
						return Table{}, warnings.list(), err
					}
					if !fits {
						// The pattern does not fit the token tables: deny this
						// context for this policy, like a rule-count overflow.
						list.Overflow = true
						continue
					}
					list.Rules = append(list.Rules, CompiledRule{
						Pattern: index,
						List:    rule.input.List,
						Allow:   rule.input.Allow,
						Kind:    rule.input.Kind,
					})
				}
				if len(list.Rules) > contextRules {
					list.Overflow = true
				}
				if list.Overflow {
					list.Rules = nil
					for _, pattern := range included {
						overflowPatterns[pattern] = struct{}{}
					}
				} else if len(list.Rules) == 0 {
					continue
				}
				key := fmt.Sprint(list)
				index, ok := listIndex[key]
				if !ok {
					index = uint32(len(table.RuleLists))
					listIndex[key] = index
					table.RuleLists = append(table.RuleLists, list)
				}
				table.Policies[policyIndex].Lists[contextIndex] = index
				policyLists++
			}
			table.Contexts = append(table.Contexts, context)
		}
		table.Objects = append(table.Objects, object)
	}
	if len(table.Contexts) > maxContexts {
		return Table{}, warnings.list(), fmt.Errorf("compile structural table: %d path contexts, more than %d", len(table.Contexts), maxContexts)
	}
	if len(table.RuleLists) > maxRuleLists {
		return Table{}, warnings.list(), fmt.Errorf("compile structural table: %d distinct rule lists, more than %d", len(table.RuleLists), maxRuleLists)
	}
	if policyLists > maxPolicyLists/numBanks {
		return Table{}, warnings.list(), fmt.Errorf("compile structural table: %d policy rule lists, more than %d", policyLists, maxPolicyLists/numBanks)
	}
	for pattern := range overflowPatterns {
		warnings.add("context-rule-overflow", pattern)
	}
	var literals []string
	for _, rule := range pending {
		literals = append(literals, rule.literal)
	}
	markUnknownSubvolumes(&table, unknownSubvolumes, anchored, mounts, scopes, literals, btrfsErr, warnings)
	if _, _, err := layoutArena(table); err != nil {
		return Table{}, warnings.list(), err
	}
	return table, warnings.list(), nil
}

// classifyRule applies matchPathPattern's split. ok is false for a rule the
// engine can never match: a `/**` rule whose prefix is not absolute, or a
// pattern filepath.Match rejects.
func classifyRule(rule RuleInput) (classifiedRule, bool) {
	if strings.HasSuffix(rule.Pattern, "/**") {
		prefix := strings.TrimSuffix(rule.Pattern, "/**")
		if prefix == "" || !filepath.IsAbs(prefix) {
			return classifiedRule{}, false
		}
		prefix = filepath.Clean(prefix)
		return classifiedRule{input: rule, recursive: true, prefix: prefix, literal: prefix}, true
	}
	program, ok := tokenize(rule.Pattern)
	if !ok {
		return classifiedRule{}, false
	}
	literal := rule.Pattern
	if index := strings.IndexAny(literal, `*?[\`); index >= 0 {
		literal = literal[:index]
	}
	return classifiedRule{input: rule, program: program, literal: literal}, true
}

// internPattern returns the table index of rule's pattern, adding it (and, for
// a tokenized pattern, its chunks/tokens/ranges) on first use. fits is false
// when the pattern would overflow a token table; err is a hard publish error
// when a global table limit is reached.
func internPattern(table *Table, index map[string]uint16, rule classifiedRule) (slot uint16, fits bool, err error) {
	if existing, ok := index[rule.input.Pattern]; ok {
		return existing, true, nil
	}
	if rule.recursive {
		if len(rule.prefix) > maxString {
			return 0, false, nil
		}
	}
	if len(table.Patterns) >= maxPatterns {
		return 0, false, fmt.Errorf("compile structural table: more than %d distinct patterns", maxPatterns)
	}
	pattern := CompiledPattern{Text: rule.input.Pattern, Recursive: rule.recursive}
	if rule.recursive {
		pattern.Text = rule.prefix
	} else {
		chunkOff, tokenOff0, rangeOff0 := len(table.Chunks), len(table.Tokens), len(table.Ranges)
		for _, c := range rule.program.Chunks {
			tokenOff := len(table.Tokens)
			for _, tok := range c.Tokens {
				rangeOff := len(table.Ranges)
				for _, rng := range tok.Ranges {
					table.Ranges = append(table.Ranges, CompiledRange{Lo: uint32(rng.Lo), Hi: uint32(rng.Hi)})
				}
				table.Tokens = append(table.Tokens, CompiledToken{
					Kind: tok.Kind, Byte: tok.Byte, Negated: tok.Negated,
					RangeOff: uint32(rangeOff), RangeLen: uint32(len(tok.Ranges)),
				})
			}
			table.Chunks = append(table.Chunks, CompiledChunk{
				Star: c.Star, TokenOff: uint32(tokenOff), TokenLen: uint32(len(c.Tokens)),
			})
		}
		if len(table.Chunks) > maxChunks || len(table.Tokens) > maxTokens || len(table.Ranges) > maxRanges {
			// Roll back this pattern's slots and report it as not representable.
			table.Chunks = table.Chunks[:chunkOff]
			table.Tokens = table.Tokens[:tokenOff0]
			table.Ranges = table.Ranges[:rangeOff0]
			return 0, false, nil
		}
		pattern.ChunkOff = uint32(chunkOff)
		pattern.ChunkLen = uint32(len(rule.program.Chunks))
	}
	slot = uint16(len(table.Patterns))
	index[rule.input.Pattern] = slot
	table.Patterns = append(table.Patterns, pattern)
	return slot, true, nil
}

// anchorPath is the directory whose deepest existing ancestor anchors rule.
func anchorPath(rule classifiedRule) string {
	if rule.recursive || rule.literal == rule.input.Pattern {
		return rule.literal
	}
	return filepath.Dir(rule.literal + "x")
}

// existingDirectory returns the deepest existing directory at or above path.
func existingDirectory(path string) (string, bool) {
	if !filepath.IsAbs(path) {
		return "", false
	}
	path = filepath.Clean(path)
	for {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return path, true
		}
		if path == "/" {
			return "", false
		}
		path = filepath.Dir(path)
	}
}

// reachablePaths returns the inode identity of the directory at candidate and
// every absolute path in this mount namespace at which that same dentry is
// visible: the same filesystem path under every mount of the superblock whose
// root contains it, confirmed by statx. A superblock whose subvolumes the
// kernel cannot tell apart is added to unknown. A btrfs placeholder is not an
// object, but its identity still names its superblock.
func reachablePaths(candidate string, mounts []*mountinfo.Info, byID map[int]*mountinfo.Info, btrfs btrfsLayout, unknown map[uint64]bool) (fileID, []string, bool) {
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return fileID{}, nil, false
	}
	st, err := statPath(real)
	if err != nil || st.mode&unix.S_IFMT != unix.S_IFDIR {
		return fileID{}, nil, false
	}
	mount, ok := byID[int(st.mountID)]
	if !ok || !pathContains(mount.Mountpoint, real) {
		return fileID{}, nil, false
	}
	// Every empty placeholder btrfs shows for a subvolume nested in a
	// snapshot is inode 2 of the snapshot's own subvolume, and nothing can be
	// created below one, so a placeholder is never an object.
	if mount.FSType == "btrfs" && st.ino == btrfsEmptySubvolumeDir {
		return fileID{dev: deviceID(mount)}, nil, false
	}
	inFS := joinBelow(mount.Root, strings.TrimPrefix(real, mount.Mountpoint))
	subvol, known := objectSubvolume(mount.FSType, st, btrfs)
	id := fileID{dev: deviceID(mount), ino: st.ino, subvol: subvol}
	if !known {
		unknown[id.dev] = true
	}
	var paths []string
	for _, other := range mounts {
		if other.Major != mount.Major || other.Minor != mount.Minor || !pathContains(other.Root, inFS) {
			continue
		}
		path := joinBelow(other.Mountpoint, strings.TrimPrefix(inFS, other.Root))
		otherStat, err := statPath(path)
		if err != nil || otherStat.ino != st.ino || int(otherStat.mountID) != other.ID {
			continue
		}
		if otherSubvol, _ := objectSubvolume(other.FSType, otherStat, btrfs); otherSubvol != subvol {
			continue
		}
		paths = append(paths, path)
	}
	return id, paths, len(paths) > 0
}

// joinBelow joins base and a rest that is empty or starts below base.
func joinBelow(base, rest string) string {
	return filepath.Clean(base + "/" + strings.TrimPrefix(rest, "/"))
}

func pathContains(scope, path string) bool {
	return path == scope || (scope == "/" || strings.HasPrefix(path, scope+"/"))
}

// couldMatchAtOrBelow reports whether a rule whose matches all start with
// literal can match path, anything below it, or its parent folder.
func couldMatchAtOrBelow(literal, path string) bool {
	return path == "/" || strings.HasPrefix(path, literal) || strings.HasPrefix(literal, path+"/")
}

// layoutArena lays out every string the bank references.
func layoutArena(table Table) ([]byte, map[string]uint32, error) {
	offsets := make(map[string]uint32)
	arena := make([]byte, 0, 4096)
	add := func(text string) {
		if _, ok := offsets[text]; ok {
			return
		}
		offsets[text] = uint32(len(arena))
		arena = append(arena, text...)
	}
	for _, context := range table.Contexts {
		add(context.Path)
		for _, scope := range context.Scopes {
			add(scope.Path)
		}
	}
	for _, pattern := range table.Patterns {
		// Only a recursive pattern stores a string (its /** prefix); a
		// tokenized pattern lives in the Chunks/Tokens/Ranges tables.
		if pattern.Recursive {
			add(pattern.Text)
		}
	}
	if len(arena) > arenaSize {
		return nil, nil, fmt.Errorf("compile structural table: %d bytes of paths and patterns, more than %d", len(arena), arenaSize)
	}
	value := make([]byte, arenaValueSize)
	copy(value, arena)
	return value, offsets, nil
}

type warningSet map[string]map[string]struct{}

func newWarnings() warningSet {
	return make(warningSet)
}

func (w warningSet) add(id, pattern string) {
	if w[id] == nil {
		w[id] = make(map[string]struct{})
	}
	w[id][pattern] = struct{}{}
}

func (w warningSet) list() []CompileWarning {
	result := make([]CompileWarning, 0, len(w))
	for id, patterns := range w {
		list := make([]string, 0, len(patterns))
		for pattern := range patterns {
			list = append(list, pattern)
		}
		sort.Strings(list)
		result = append(result, CompileWarning{ID: id, Patterns: list})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
