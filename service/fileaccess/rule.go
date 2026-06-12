package fileaccess

import (
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
func (rs PathRules) Decide(e FileEvent) Verdict {
	for _, r := range rs.Rules {
		if r.Matches(e.Path) {
			return r.Verdict
		}
	}
	return rs.Default
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
