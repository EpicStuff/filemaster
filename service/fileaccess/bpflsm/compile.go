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

// Policy is the plain policy the compiler receives. The package cannot
// import fileaccess, so the caller flattens its snapshot into this.
type Policy struct {
	Scopes       []ScopeInput
	Rules        []RuleInput
	DefaultAllow bool
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

// CompiledRule is one rule reference in a context's ordered list.
type CompiledRule struct {
	Pattern uint16
	List    RuleList
	Allow   bool
	Kind    RuleKind
}

// CompiledContext is one absolute path an object is reachable at.
type CompiledContext struct {
	Path      string
	ParentLen uint32
	Overflow  bool
	Scopes    []ScopeInput
	Rules     []CompiledRule
}

// CompiledObject is one inode-keyed walk stop and its contexts.
type CompiledObject struct {
	File         fileID
	FirstContext uint32
	ContextCount uint32
}

// Table is the complete bank image Enforcer.Publish writes.
type Table struct {
	Objects      []CompiledObject
	Contexts     []CompiledContext
	Patterns     []CompiledPattern
	Chunks       []CompiledChunk
	Tokens       []CompiledToken
	Ranges       []CompiledRange
	DefaultAllow bool
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

	var rules []classifiedRule
	for _, rule := range policy.Rules {
		classified, ok := classifyRule(rule)
		if !ok {
			warnings.add("pattern-never-matches", rule.Pattern)
			continue
		}
		rules = append(rules, classified)
	}

	var scopes []ScopeInput
	for _, scope := range policy.Scopes {
		if !filepath.IsAbs(scope.Path) {
			continue
		}
		scopes = append(scopes, ScopeInput{Path: filepath.Clean(scope.Path), Exclude: scope.Exclude})
	}

	candidates := make(map[string]struct{})
	for _, scope := range scopes {
		if !scope.Exclude {
			if anchor, ok := existingDirectory(scope.Path); ok {
				candidates[anchor] = struct{}{}
			}
		}
	}
	for _, rule := range rules {
		if anchor, ok := existingDirectory(anchorPath(rule)); ok {
			candidates[anchor] = struct{}{}
		}
	}
	for _, mount := range mounts {
		candidates[mount.Mountpoint] = struct{}{}
	}

	byID := make(map[int]*mountinfo.Info, len(mounts))
	for _, mount := range mounts {
		byID[mount.ID] = mount
	}
	contextsByObject := make(map[fileID]map[string]struct{})
	for candidate := range candidates {
		id, paths, ok := reachablePaths(candidate, mounts, byID)
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
		return ids[i].ino < ids[j].ino
	})

	table := Table{DefaultAllow: policy.DefaultAllow}
	patternIndex := make(map[string]uint16)
	overflowPatterns := make(map[string]struct{})
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
			var included []string
			unrepresentable := false
			for _, rule := range rules {
				if !couldMatchAtOrBelow(rule.literal, path) {
					continue
				}
				included = append(included, rule.input.Pattern)
				index, ok, fits, err := internPattern(&table, patternIndex, rule)
				if err != nil {
					return Table{}, warnings.list(), err
				}
				if !fits {
					// The pattern does not fit the token tables: deny this
					// context, like a rule-count overflow.
					unrepresentable = true
					continue
				}
				_ = ok
				context.Rules = append(context.Rules, CompiledRule{
					Pattern: index,
					List:    rule.input.List,
					Allow:   rule.input.Allow,
					Kind:    rule.input.Kind,
				})
			}
			if unrepresentable || len(context.Rules) > contextRules || len(context.Scopes) > contextScopes {
				context.Overflow = true
				context.Rules = nil
				context.Scopes = nil
				for _, pattern := range included {
					overflowPatterns[pattern] = struct{}{}
				}
			}
			table.Contexts = append(table.Contexts, context)
		}
		table.Objects = append(table.Objects, object)
	}
	if len(table.Contexts) > maxContexts {
		return Table{}, warnings.list(), fmt.Errorf("compile structural table: %d path contexts, more than %d", len(table.Contexts), maxContexts)
	}
	for pattern := range overflowPatterns {
		warnings.add("context-rule-overflow", pattern)
	}
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
func internPattern(table *Table, index map[string]uint16, rule classifiedRule) (slot uint16, added, fits bool, err error) {
	if existing, ok := index[rule.input.Pattern]; ok {
		return existing, false, true, nil
	}
	if rule.recursive {
		if len(rule.prefix) > maxString {
			return 0, false, false, nil
		}
	}
	if len(table.Patterns) >= maxPatterns {
		return 0, false, false, fmt.Errorf("compile structural table: more than %d distinct patterns", maxPatterns)
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
			return 0, false, false, nil
		}
		pattern.ChunkOff = uint32(chunkOff)
		pattern.ChunkLen = uint32(len(rule.program.Chunks))
	}
	slot = uint16(len(table.Patterns))
	index[rule.input.Pattern] = slot
	table.Patterns = append(table.Patterns, pattern)
	return slot, true, true, nil
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
// root contains it, confirmed by statx.
func reachablePaths(candidate string, mounts []*mountinfo.Info, byID map[int]*mountinfo.Info) (fileID, []string, bool) {
	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return fileID{}, nil, false
	}
	ino, mountID, mode, err := statPath(real)
	if err != nil || mode&unix.S_IFMT != unix.S_IFDIR {
		return fileID{}, nil, false
	}
	mount, ok := byID[int(mountID)]
	if !ok || !pathContains(mount.Mountpoint, real) {
		return fileID{}, nil, false
	}
	inFS := joinBelow(mount.Root, strings.TrimPrefix(real, mount.Mountpoint))
	id := fileID{dev: deviceID(mount), ino: ino}
	var paths []string
	for _, other := range mounts {
		if other.Major != mount.Major || other.Minor != mount.Minor || !pathContains(other.Root, inFS) {
			continue
		}
		path := joinBelow(other.Mountpoint, strings.TrimPrefix(inFS, other.Root))
		otherIno, otherMount, _, err := statPath(path)
		if err != nil || otherIno != ino || int(otherMount) != other.ID {
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
