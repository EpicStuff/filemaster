//go:build linux

package bpflsm

import (
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
)

// TestTokenizeRefMatchEqualsFilepathMatch proves the Go reference (tokenize +
// refMatch) equals filepath.Match on a large generated set, including the
// adversarial cases where a class matches '/' after a star and multi-byte or
// invalid UTF-8 follows a star skip.
func TestTokenizeRefMatchEqualsFilepathMatch(t *testing.T) {
	random := rand.New(rand.NewSource(3))
	alphabet := []string{"a", "b", "/", "*", "?", "[", "]", "^", "-", `\`, ".", "z", "0", "9", "é", "\xff", "\xc3\x28", "日"}
	pick := func(n int) string {
		var b strings.Builder
		for i := 0; i < random.Intn(n); i++ {
			b.WriteString(alphabet[random.Intn(len(alphabet))])
		}
		return b.String()
	}
	total, checked := 0, 0
	run := func(pattern, name string) {
		total++
		program, ok := tokenize(pattern)
		matched, err := filepath.Match(pattern, name)
		// What the engine's rule does: matchPathPattern is err == nil && ok.
		engineMatches := err == nil && matched
		if !ok {
			// A rejected pattern must never match, on any name: filepath.Match
			// is lazy, so it only errors on a bad chunk it reaches, but the
			// rule is false whether it errors or matches false.
			if engineMatches {
				t.Fatalf("tokenize rejected %q but the engine matches %q", pattern, name)
			}
			return
		}
		checked++
		if got := refMatch(program, name); got != engineMatches {
			t.Fatalf("refMatch(%q,%q)=%v want %v (err=%v)", pattern, name, got, engineMatches, err)
		}
	}
	for total < 60000 {
		run(pick(12), pick(12))
	}
	for _, c := range [][2]string{
		{"*[^z]*y", "ab/y"}, {"*[/]*", "a/b"}, {"a*[^x]", "a/"}, {"*[a-z]", "日"},
		{"*é", "xx/é"}, {"*é", "é"}, {"?", "é"}, {"?", "/"}, {"[^/]", "/"},
		{"a*b", "a\xffb"}, {"*[\xc3]", "\xc3\x28"}, {`*\*`, "a*"}, {"**/y", "a/y"},
		{"*", "a/b"}, {"[a-c]*", "b日"}, {"a[^b]c", "a/c"}, {"*/*", "a/b/c"},
	} {
		run(c[0], c[1])
	}
	t.Logf("tokenize/refMatch vs filepath.Match: total=%d valid-checked=%d mismatches=0", total, checked)
}
