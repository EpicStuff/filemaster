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
}

// Matches reports whether the rule applies to path.
func (r PathRule) Matches(path string) bool {
	return matchPathPattern(r.Pattern, path)
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
	if v, ok := rs.Lookup(e.Path); ok {
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

func matchPathPattern(pattern, path string) bool {
	// Recursive "this dir and below" pattern. Matches the prefix itself
	// (so "/foo/**" catches "/foo") and any descendant.
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	// Fall through to single-segment glob.
	ok, err := filepath.Match(pattern, path)
	return err == nil && ok
}
