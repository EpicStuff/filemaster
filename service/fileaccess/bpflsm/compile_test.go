//go:build linux

package bpflsm

import (
	"math/rand"
	"os"
	"path/filepath"
	"slices"
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
	rules := []RuleInput{
		{List: ListWrite, Pattern: filepath.Join(scope, "missing", "*.txt"), Kind: KindFile},
		{List: ListRead, Pattern: filepath.Join(other, "**"), Allow: true},
		{List: ListWrite, Pattern: "/a/[", Allow: true},
	}
	table, warnings, err := Compile(Policy{
		Scopes: []ScopeInput{{Path: scope}, {Path: filepath.Join(scope, "skip"), Exclude: true}},
		Labels: []LabelPolicy{{Label: LabelUnidentified, Rules: rules, DefaultAllow: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || warnings[0].ID != "pattern-never-matches" || warnings[0].Patterns[0] != "/a/[" {
		t.Fatalf("warnings = %#v", warnings)
	}
	policy := table.Labels[LabelUnidentified]
	if policy == policyPending || !table.Policies[policy].DefaultAllow {
		t.Fatalf("label 0 maps to policy %d %+v", policy, table.Policies)
	}
	scopeRules := policyRules(t, table, policy, scope)
	if len(scopeRules) != 1 || table.Patterns[scopeRules[0].Pattern].Text != rules[0].Pattern {
		t.Fatalf("scope rules = %+v", scopeRules)
	}
	if context := findContext(t, table, scope); len(context.Scopes) != 1 || context.Scopes[0].Path != scope {
		t.Fatalf("scope entries = %+v, want only the containing scope", context.Scopes)
	}
	if otherRules := policyRules(t, table, policy, other); len(otherRules) != 1 || !table.Patterns[otherRules[0].Pattern].Recursive {
		t.Fatalf("other rules = %+v", otherRules)
	}
	if rootRules := policyRules(t, table, policy, "/"); len(rootRules) != 2 {
		t.Fatalf("root rules = %+v, want both representable rules", rootRules)
	}
	for _, rule := range policyRules(t, table, policyPending, "/") {
		if rule.Allow {
			t.Fatalf("pending policy allows: %+v", rule)
		}
	}
	if table.Policies[policyPending].DefaultAllow {
		t.Fatal("pending policy default allows")
	}
}

func TestCompileSharesPoliciesBetweenEqualLabels(t *testing.T) {
	root := t.TempDir()
	allow := []RuleInput{{List: ListWrite, Pattern: filepath.Join(root, "**"), Allow: true}}
	deny := []RuleInput{{List: ListWrite, Pattern: filepath.Join(root, "**")}}
	table, _, err := Compile(Policy{
		Scopes: []ScopeInput{{Path: root}},
		Labels: []LabelPolicy{
			{Label: 0, Rules: allow},
			{Label: 7, Rules: deny},
			{Label: 9, Rules: allow},
			{Label: 11, Rules: allow, DefaultAllow: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if table.Labels[0] != table.Labels[9] || table.Labels[0] == table.Labels[7] || table.Labels[0] == table.Labels[11] {
		t.Fatalf("label policies = %v", table.Labels)
	}
	for label, policy := range table.Labels {
		if policy == policyPending {
			t.Fatalf("label %d shares the pending policy", label)
		}
	}
	if len(table.Policies) != 4 {
		t.Fatalf("%d policies, want pending + 3", len(table.Policies))
	}
	if allowRules, denyRules := policyRules(t, table, table.Labels[0], root), policyRules(t, table, table.Labels[7], root); len(allowRules) != 1 || !allowRules[0].Allow || len(denyRules) != 1 || denyRules[0].Allow {
		t.Fatalf("allow %+v deny %+v", allowRules, denyRules)
	}
}

func TestCompileOverflowDeniesContextAndWarns(t *testing.T) {
	root := t.TempDir()
	var rules []RuleInput
	for i := range contextRules + 1 {
		rules = append(rules, RuleInput{List: ListWrite, Pattern: filepath.Join(root, "r"+strconv.Itoa(i))})
	}
	table, warnings, err := Compile(Policy{Scopes: []ScopeInput{{Path: root}}, Labels: []LabelPolicy{{Rules: rules}}})
	if err != nil {
		t.Fatal(err)
	}
	context := uint32(slices.IndexFunc(table.Contexts, func(c CompiledContext) bool { return c.Path == root }))
	list, ok := table.Policies[table.Labels[0]].Lists[context]
	if !ok || !table.RuleLists[list].Overflow {
		t.Fatal("over-full rule list did not overflow")
	}
	if len(warnings) != 1 || warnings[0].ID != "context-rule-overflow" || len(warnings[0].Patterns) != contextRules+1 {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func findContext(t *testing.T, table Table, path string) CompiledContext {
	t.Helper()
	for _, context := range table.Contexts {
		if context.Path == path {
			return context
		}
	}
	t.Fatalf("no context for %q in %d contexts", path, len(table.Contexts))
	return CompiledContext{}
}

// policyRules returns policy's rule list for the context at path.
func policyRules(t *testing.T, table Table, policy uint32, path string) []CompiledRule {
	t.Helper()
	findContext(t, table, path)
	context := uint32(slices.IndexFunc(table.Contexts, func(c CompiledContext) bool { return c.Path == path }))
	list, ok := table.Policies[policy].Lists[context]
	if !ok {
		return nil
	}
	return table.RuleLists[list].Rules
}

func TestObjectSubvolumeMatchesTheKernelKey(t *testing.T) {
	layout := btrfsLayout{ok: true, root: -400, rootID: 384}
	for _, c := range []struct {
		name   string
		fsType string
		stat   pathStat
		btrfs  btrfsLayout
		subvol uint64
		known  bool
	}{
		{"btrfs with layout", "btrfs", pathStat{subvol: 257, hasSubvol: true}, layout, 257, true},
		{"btrfs top level", "btrfs", pathStat{subvol: 5, hasSubvol: true}, layout, 5, true},
		{"btrfs without layout", "btrfs", pathStat{subvol: 257, hasSubvol: true}, btrfsLayout{}, 0, false},
		{"btrfs without STATX_SUBVOL", "btrfs", pathStat{}, layout, 0, false},
		{"bcachefs", "bcachefs", pathStat{subvol: 1, hasSubvol: true}, layout, 0, false},
		{"ext4", "ext4", pathStat{}, layout, 0, true},
		{"tmpfs without layout", "tmpfs", pathStat{}, btrfsLayout{}, 0, true},
	} {
		subvol, known := objectSubvolume(c.fsType, c.stat, c.btrfs)
		if subvol != c.subvol || known != c.known {
			t.Errorf("%s: got (%d, %t), want (%d, %t)", c.name, subvol, known, c.subvol, c.known)
		}
	}
}
