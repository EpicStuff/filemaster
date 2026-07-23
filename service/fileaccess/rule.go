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
//
// A PathRule never carries its own operation. The operation is implied by which
// per-operation list (Access/Write/Execute) the rule was parsed into; the
// snapshot selects that list before the rule is ever matched. See
// DecisionSnapshot.rulesFor.
type PathRule struct {
	Pattern string
	Verdict Verdict
	Exact   bool

	// DirectoryOnly restricts the rule to directory events (FAN_ONDIR). A
	// file-only variant is not needed: a plain rule already applies to both.
	DirectoryOnly bool
}

// Matches reports whether the rule's path pattern applies to path, ignoring the
// directory discriminator.
func (r PathRule) Matches(path string) bool {
	if r.Exact {
		return r.Pattern == path
	}
	return matchPathPattern(r.Pattern, path)
}

// applies reports whether the rule governs an event on path. isDir is the event
// object's directory-ness (FAN_ONDIR). The operation is not checked here: the
// rule already lives in the operation's own list.
func (r PathRule) applies(path string, isDir bool) bool {
	if !r.Matches(path) {
		return false
	}
	return !r.DirectoryOnly || isDir
}

// PathRules is an ordered list of PathRules governing a single operation. First
// match wins; if no rule matches, Default is returned.
type PathRules struct {
	Rules   []PathRule
	Default Verdict
}

// match is the single shared matcher every decision path uses once the
// operation's list has been selected. It walks the ordered list and returns
// (verdict, true) on the first rule that applies, or (0, false) if none do.
func (rs PathRules) match(path string, isDir bool) (Verdict, bool) {
	for _, r := range rs.Rules {
		if r.applies(path, isDir) {
			return r.Verdict, true
		}
	}
	return 0, false
}

// Decide implements Handler for a standalone list: match the event's path and
// return the matching verdict, or the list default. A bare PathRules is one
// operation's list, so the event's Op is not consulted -- routing to the right
// list happens at the snapshot level.
func (rs PathRules) Decide(_ context.Context, e *FileEvent) Verdict {
	if v, ok := rs.match(e.Path, e.IsDir); ok {
		return v
	}
	return rs.Default
}

// Lookup returns the first matching verdict for path (directory discriminator
// ignored), or (0, false) if no rule applies. Unlike Decide it does not fall
// back to Default -- the caller decides what "no match" means.
func (rs PathRules) Lookup(path string) (Verdict, bool) {
	return rs.match(path, false)
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
