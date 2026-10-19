//go:build linux

package bpflsm

import (
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestClassifyRuleFollowsMatchPathPattern(t *testing.T) {
	for _, test := range []struct {
		pattern   string
		ok        bool
		recursive bool
		prefix    string
		literal   string
	}{
		{"/a//b/**", true, true, "/a/b", "/a/b"},
		{"/**", false, false, "", ""},
		{"rel/**", false, false, "", ""},
		{"/a/*.txt", true, false, "", "/a/"},
		{`/a/\*x`, true, false, "", "/a/"},
		{"/a/exact", true, false, "", "/a/exact"},
		{"/a/[", false, false, "", ""},
		{"/a/*[", false, false, "", ""},
		{`/a/x\`, false, false, "", ""},
	} {
		got, ok := classifyRule(RuleInput{Pattern: test.pattern})
		if ok != test.ok {
			t.Errorf("%q: ok=%v, want %v", test.pattern, ok, test.ok)
			continue
		}
		if ok && (got.recursive != test.recursive || got.prefix != test.prefix || got.literal != test.literal) {
			t.Errorf("%q: recursive=%v prefix=%q literal=%q", test.pattern, got.recursive, got.prefix, got.literal)
		}
	}
}

// TestRuleInclusionIsSound checks that a context's list keeps every rule that
// can match a path at or below it, or the parent folder of the context.
func TestRuleInclusionIsSound(t *testing.T) {
	random := rand.New(rand.NewSource(11))
	segments := []string{"a", "b", "ab", "a*", "?", "[ab]", "[^a]", `\a`, "*"}
	names := []string{"a", "b", "ab", "ba", "aa"}
	for range 20000 {
		var pattern string
		for range 1 + random.Intn(4) {
			pattern += "/" + segments[random.Intn(len(segments))]
		}
		if random.Intn(4) == 0 {
			pattern += "/**"
		}
		rule, ok := classifyRule(RuleInput{Pattern: pattern})
		if !ok {
			continue
		}
		var path string
		for range 1 + random.Intn(5) {
			path += "/" + names[random.Intn(len(names))]
		}
		matches := func(p string) bool {
			if rule.recursive {
				return pathContains(rule.prefix, p)
			}
			ok, err := filepath.Match(pattern, p)
			return err == nil && ok
		}
		for context := path; ; context = filepath.Dir(context) {
			if (matches(path) || matches(filepath.Dir(context))) && !couldMatchAtOrBelow(rule.literal, context) {
				t.Fatalf("rule %q matches under %q but is left out of context %q", pattern, path, context)
			}
			if context == "/" {
				break
			}
		}
	}
}

func TestCompileBuildsContextsForScopeAndRules(t *testing.T) {
	root := t.TempDir()
	scope := filepath.Join(root, "scope")
	other := filepath.Join(root, "other")
	for _, dir := range []string{scope, other} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	policy := Policy{
		Scopes: []ScopeInput{{Path: scope}, {Path: filepath.Join(scope, "skip"), Exclude: true}},
		Rules: []RuleInput{
			{List: ListWrite, Pattern: filepath.Join(scope, "missing", "*.txt"), Kind: KindFile},
			{List: ListRead, Pattern: filepath.Join(other, "**"), Allow: true},
			{List: ListWrite, Pattern: "/a/[", Allow: true},
		},
		DefaultAllow: true,
	}
	table, warnings, err := Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || warnings[0].ID != "pattern-never-matches" || warnings[0].Patterns[0] != "/a/[" {
		t.Fatalf("warnings = %#v", warnings)
	}
	contexts := make(map[string]CompiledContext)
	for _, context := range table.Contexts {
		contexts[context.Path] = context
	}
	scopeContext, ok := contexts[scope]
	if !ok {
		t.Fatalf("no context for scope root %q in %d contexts", scope, len(table.Contexts))
	}
	if len(scopeContext.Rules) != 1 || table.Patterns[scopeContext.Rules[0].Pattern].Text != policy.Rules[0].Pattern {
		t.Fatalf("scope rules = %+v", scopeContext.Rules)
	}
	if len(scopeContext.Scopes) != 1 || scopeContext.Scopes[0].Path != scope {
		t.Fatalf("scope entries = %+v, want only the containing scope", scopeContext.Scopes)
	}
	otherContext, ok := contexts[other]
	if !ok || len(otherContext.Rules) != 1 || !table.Patterns[otherContext.Rules[0].Pattern].Recursive {
		t.Fatalf("other context = %+v", otherContext)
	}
	rootContext, ok := contexts["/"]
	if !ok || len(rootContext.Rules) != 2 {
		t.Fatalf("root context = %+v, want both representable rules", rootContext)
	}
	if !table.DefaultAllow {
		t.Fatal("default lost")
	}
}

func TestCompileOverflowDeniesContextAndWarns(t *testing.T) {
	root := t.TempDir()
	var rules []RuleInput
	for i := range contextRules + 1 {
		rules = append(rules, RuleInput{List: ListWrite, Pattern: filepath.Join(root, "r"+strconv.Itoa(i))})
	}
	table, warnings, err := Compile(Policy{Scopes: []ScopeInput{{Path: root}}, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, context := range table.Contexts {
		if context.Path == root {
			found = context.Overflow
		}
	}
	if !found {
		t.Fatal("over-full context did not overflow")
	}
	if len(warnings) != 1 || warnings[0].ID != "context-rule-overflow" || len(warnings[0].Patterns) != contextRules+1 {
		t.Fatalf("warnings = %#v", warnings)
	}
}
