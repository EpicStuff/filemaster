package fileaccess

import (
	"context"
	"path/filepath"
	"strings"
)

// PathRule maps a file-path pattern to a Verdict.
//
// Pattern syntax:
//
//   - "/foo/bar" -- exact match.
//   - "/foo/*.txt" -- filepath.Match against the full path (single segment
//     wildcards only, as per stdlib).
//   - "/foo/**" -- recursive match: anything at or below /foo, including
//     /foo itself.
//
// The "**" form is the common case for "this dir and everything inside,"
// so it's worth the custom code on top of filepath.Match.
type PathRule struct {
	Pattern string
	Verdict Verdict
	Exact   bool

	// OperationScoped restricts this rule to one filesystem operation. Legacy
	// rules leave it false and therefore continue to apply to every operation.
	Operation       FileOp
	OperationScoped bool
	DirectoryOnly   bool
}

// Matches reports whether the rule applies to path.
func (r PathRule) Matches(path string) bool {
	if r.Exact {
		return r.Pattern == path
	}
	return matchPathPattern(r.Pattern, path)
}

// MatchesEvent applies the path match plus an optional operation and directory
// discriminator. This keeps legacy path-only rules backward compatible while
// allowing learned Always rules to be safely operation-specific.
func (r PathRule) MatchesEvent(path string, op FileOp, isDir bool) bool {
	if !r.Matches(path) {
		return false
	}
	if r.OperationScoped && r.Operation != op {
		return false
	}
	return !r.DirectoryOnly || isDir
}

// PathRules is an ordered list of PathRules. First match wins; if no
// rule matches, Default is returned.
type PathRules struct {
	Rules   []PathRule
	Default Verdict
}

// Decide implements Handler: look up the event's path in the rule list
// and return the matching verdict (or the default).
func (rs PathRules) Decide(_ context.Context, e *FileEvent) Verdict {
	if v, ok := rs.LookupEvent(e.Path, e.Op, e.IsDir); ok {
		return v
	}
	return rs.Default
}

// Lookup walks the rule list and returns (verdict, true) on the first
// match, or (zero, false) if no rule applies. Unlike Decide, Lookup
// does not fall back to Default -- the caller decides what "no match"
// means (e.g. prompt the user vs. apply a system-wide default).
func (rs PathRules) Lookup(path string) (Verdict, bool) {
	for _, r := range rs.Rules {
		if r.Matches(path) {
			return r.Verdict, true
		}
	}
	return 0, false
}

// LookupEvent evaluates the first matching rule for this exact operation.
func (rs PathRules) LookupEvent(path string, op FileOp, isDir bool) (Verdict, bool) {
	for _, r := range rs.Rules {
		if r.MatchesEvent(path, op, isDir) {
			return r.Verdict, true
		}
	}
	return 0, false
}

func matchPathPattern(pattern, path string) bool {
	// Recursive "this dir and below" pattern. Matches the prefix itself
	// (so "/foo/**" catches "/foo") and any descendant.
	if strings.HasSuffix(pattern, "/**") {
		prefix, err := normalizePath(strings.TrimSuffix(pattern, "/**"))
		path, pathErr := normalizePath(path)
		return err == nil && pathErr == nil && pathContains(prefix, path)
	}
	// Fall through to single-segment glob.
	ok, err := filepath.Match(pattern, path)
	return err == nil && ok
}
