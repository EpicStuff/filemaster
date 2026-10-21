package fileaccess

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/safing/portmaster/service/profile"
)

// execLearning decides which executables the BPF labeller may label by inode
// alone ("exe-only"), so that their execs are labelled at exec time instead of
// staying pending until the daemon resolves them.
//
// That label is exact only if the daemon would resolve every exec of the
// executable to the same profile, whatever its argv and envp. For a process
// without tags, profile resolution (profile.MatchFingerprints, highest score
// across profiles) depends on the executable path, which is fixed, and on the
// command line and environment, which are not. So:
//
//   - any env fingerprint can match any process, and turns learning off;
//   - a cmdline fingerprint can match only command lines that start with some
//     argv[0], so it claims the executables that argv[0] can name, and turns
//     learning off when its argv[0] cannot be worked out;
//   - prefix and regex path fingerprints are kept out of learning for the
//     paths they match, as the tag-derived paths (interpreters, Flatpak, Snap
//     and AppImage) are.
//
// argv[0] is chosen by the caller. A disguised argv[0] can make a process
// match a cmdline profile its executable would not, which upstream Portmaster
// allows too; for a learned executable the kernel label then follows the
// executable, not the disguise. Likewise a symlink outside aliasDirs naming a
// claimed program is not followed, and a caller-set APPIMAGE/APPDIR or SNAP
// environment that tags an ordinary executable is not anticipated.
type execLearning struct {
	// off, when set, is why no executable is learned.
	off string
	// A cmdline fingerprint can match the bare argv[0]s in names or starting
	// with one of prefixes, and the absolute argv[0]s in paths or starting
	// with one of pathPrefixes.
	names        map[string]bool
	prefixes     []string
	paths        []string
	pathPrefixes []string
	// pathPrints are the prefix and regex path fingerprints.
	pathPrints []pathPrint
	// aliasDirs are searched for symlinks that name a claimed program but
	// resolve to an executable with another base name (vi -> vim).
	aliasDirs []string
}

type pathPrint struct {
	value string
	regex *regexp.Regexp
}

func (p pathPrint) matches(path string) bool {
	if p.regex == nil {
		return strings.HasPrefix(path, p.value)
	}
	for _, match := range p.regex.FindAllString(path, -1) {
		if match != "" {
			return true
		}
	}
	return false
}

// newExecLearning analyses every profile's fingerprints, keyed by profile ID.
func newExecLearning(profiles map[string][]profile.Fingerprint, aliasDirs []string) execLearning {
	learning := execLearning{names: make(map[string]bool), aliasDirs: aliasDirs}
	ids := make([]string, 0, len(profiles))
	for id := range profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, fp := range profiles[id] {
			if reason := learning.add(fp); reason != "" && learning.off == "" {
				learning.off = fmt.Sprintf("%s fingerprint %q of profile %s %s", fp.Type, fp.Value, id, reason)
			}
		}
	}
	return learning
}

// add records what fp can claim, or returns why it can claim any process.
func (l *execLearning) add(fp profile.Fingerprint) string {
	switch fp.Type {
	case profile.FingerprintTypeEnvID:
		return "can match any process's environment"
	case profile.FingerprintTypePathID:
		switch fp.Operation {
		case profile.FingerprintOperationPrefixID:
			l.pathPrints = append(l.pathPrints, pathPrint{value: fp.Value})
		case profile.FingerprintOperationRegexID:
			regex, err := regexp.Compile(fp.Value)
			if err == nil {
				l.pathPrints = append(l.pathPrints, pathPrint{value: fp.Value, regex: regex})
			}
		}
		return ""
	case profile.FingerprintTypeCmdlineID:
	default:
		return ""
	}
	var literals []string
	complete := false
	switch fp.Operation {
	case profile.FingerprintOperationEqualsID:
		literals, complete = []string{fp.Value}, true
	case profile.FingerprintOperationPrefixID:
		literals = []string{fp.Value}
	case profile.FingerprintOperationRegexID:
		parsed, err := syntax.Parse(fp.Value, syntax.Perl)
		if err != nil {
			// ParseFingerprints drops a regex that does not compile.
			return ""
		}
		var ok bool
		if literals, complete, ok = anchoredPrefixes(parsed.Simplify()); !ok {
			return "is not anchored to the start of the command line, so its argv[0] cannot be determined"
		}
	default:
		return ""
	}
	for _, literal := range literals {
		if reason := l.claim(literal, complete); reason != "" {
			return reason
		}
	}
	return ""
}

// claim records the argv[0]s of the command lines that start with literal (or
// equal it, when complete). The command line is argv joined by spaces, so
// argv[0] is the literal up to any of its spaces, or the whole literal and
// whatever follows it.
func (l *execLearning) claim(literal string, complete bool) string {
	if complete && literal == "" {
		// Only an empty match; MatchFingerprints never counts one.
		return ""
	}
	for i := 0; i < len(literal); i++ {
		if literal[i] == ' ' {
			l.claimExact(literal[:i])
		}
	}
	if complete {
		l.claimExact(literal)
		return ""
	}
	switch {
	case literal == "":
		return "can match every program's command line"
	case !strings.Contains(literal, "/"):
		l.prefixes = append(l.prefixes, literal)
	case strings.HasPrefix(literal, "/"):
		l.pathPrefixes = append(l.pathPrefixes, literal)
	default:
		return "starts with a relative path, so the programs it can match cannot be determined"
	}
	return ""
}

// claimExact records one exact argv[0]: a bare name is looked up in PATH, an
// absolute path names its file, and a relative path is taken by its base name.
func (l *execLearning) claimExact(argv0 string) {
	switch {
	case argv0 == "":
	case !strings.Contains(argv0, "/"):
		l.names[argv0] = true
	case strings.HasPrefix(argv0, "/"):
		l.paths = append(l.paths, argv0)
	default:
		l.names[filepath.Base(argv0)] = true
	}
}

// claimsArgv0 reports whether a cmdline fingerprint can match a command line
// whose argv[0] is argv0.
func (l *execLearning) claimsArgv0(argv0 string) bool {
	if !strings.Contains(argv0, "/") {
		return l.names[argv0] || l.hasClaimedPrefix(argv0)
	}
	if !strings.HasPrefix(argv0, "/") {
		base := filepath.Base(argv0)
		return l.names[base] || l.hasClaimedPrefix(base)
	}
	for _, prefix := range l.pathPrefixes {
		if strings.HasPrefix(argv0, prefix) {
			return true
		}
	}
	return slices.Contains(l.paths, argv0)
}

// learnable reports whether exe, an absolute executable path with symlinks
// resolved, may be labelled by its inode alone; otherwise the reason.
func (l *execLearning) learnable(exe string) (bool, string) {
	if l.off != "" {
		return false, l.off
	}
	if reason := tagClaimed(exe); reason != "" {
		return false, reason
	}
	for _, print := range l.pathPrints {
		if print.matches(exe) {
			return false, fmt.Sprintf("path fingerprint %q matches it", print.value)
		}
	}
	if l.claimsArgv0(exe) || l.claimsArgv0(filepath.Base(exe)) {
		return false, "a cmdline fingerprint can match it"
	}
	for _, path := range l.paths {
		if resolvesTo(path, exe) {
			return false, fmt.Sprintf("a cmdline fingerprint can match it as %s", path)
		}
	}
	if len(l.names) == 0 && len(l.prefixes) == 0 && len(l.pathPrefixes) == 0 {
		return true, ""
	}
	for _, dir := range l.aliasDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			alias := filepath.Join(dir, entry.Name())
			if (l.claimsArgv0(entry.Name()) || l.claimsArgv0(alias)) && resolvesTo(alias, exe) {
				return false, fmt.Sprintf("a cmdline fingerprint can match it through %s", alias)
			}
		}
	}
	return true, ""
}

func (l *execLearning) hasClaimedPrefix(name string) bool {
	for _, prefix := range l.prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// summary is the learning state for diagnostics.
func (l *execLearning) summary() string {
	if l.off != "" {
		return "off: " + l.off
	}
	names := make([]string, 0, len(l.names))
	for name := range l.names {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Sprintf("on, except interpreters, app bundles, %d prefix/regex path fingerprint(s), and what cmdline fingerprints claim: names %v, name prefixes %v, paths %v, path prefixes %v",
		len(l.pathPrints), names, l.prefixes, l.paths, l.pathPrefixes)
}

func resolvesTo(path, exe string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && resolved == exe
}

// appImageMountDir and snapBaseDir mirror the process tag handlers
// (process/tags/appimage_unix.go, snap_unix.go), which tag by these paths.
var appImageMountDir = regexp.MustCompile(`^/tmp/.mount_[^/]+`)

const snapBaseDir = "/snap/"

// tagClaimed reports why exe's processes can be tagged by their path, which
// lets a tag fingerprint or the tag's matching path decide their profile.
// Interpreters are checked by the labeller.
func tagClaimed(exe string) string {
	switch {
	case strings.HasPrefix(exe, "/app/"):
		return "a Flatpak path is tagged"
	case strings.HasPrefix(exe, snapBaseDir):
		return "a Snap path is tagged"
	case appImageMountDir.MatchString(exe):
		return "an AppImage mount is tagged"
	}
	return ""
}

// defaultAliasDirs are the standard command directories plus the daemon's
// PATH, where a program's other names live as symlinks.
func defaultAliasDirs() []string {
	dirs := []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	seen := make(map[string]bool)
	var unique []string
	for _, dir := range append(dirs, filepath.SplitList(os.Getenv("PATH"))...) {
		if filepath.IsAbs(dir) && !seen[dir] {
			seen[dir] = true
			unique = append(unique, dir)
		}
	}
	return unique
}

// maxLiterals bounds the literal prefixes one regex expands to.
const maxLiterals = 64

// anchoredPrefixes returns literal prefixes one of which starts every input
// re matches, and whether every such input equals one of them, if re only
// matches at the start of its input.
func anchoredPrefixes(re *syntax.Regexp) (literals []string, complete, ok bool) {
	switch re.Op {
	case syntax.OpBeginText:
		// Only the empty match, which MatchFingerprints never counts.
		return []string{""}, true, true
	case syntax.OpCapture:
		return anchoredPrefixes(re.Sub[0])
	case syntax.OpConcat:
		if len(re.Sub) == 0 || re.Sub[0].Op != syntax.OpBeginText {
			return nil, false, false
		}
		literals, complete = concatPrefixes(re.Sub[1:])
		// A match need not reach the end of the input unless re says so.
		return literals, complete && re.Sub[len(re.Sub)-1].Op == syntax.OpEndText, true
	case syntax.OpAlternate:
		complete = true
		for _, sub := range re.Sub {
			subLiterals, subComplete, subOK := anchoredPrefixes(sub)
			if !subOK {
				return nil, false, false
			}
			literals = append(literals, subLiterals...)
			complete = complete && subComplete
		}
		if len(literals) > maxLiterals {
			return []string{""}, false, true
		}
		return literals, complete, true
	}
	return nil, false, false
}

// literalPrefixes returns literal prefixes one of which starts every match of
// re, and whether every match equals one of them.
func literalPrefixes(re *syntax.Regexp) (literals []string, complete bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginText, syntax.OpEndText, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}, true
	case syntax.OpLiteral:
		pieces := make([]*syntax.Regexp, len(re.Rune))
		for i, r := range re.Rune {
			runes := []rune{r}
			if re.Flags&syntax.FoldCase != 0 {
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					runes = append(runes, f)
				}
			}
			pieces[i] = &syntax.Regexp{Op: syntax.OpCharClass, Rune: pairs(runes)}
		}
		return concatPrefixes(pieces)
	case syntax.OpCharClass:
		var runes []rune
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				if len(runes) == 16 {
					return []string{""}, false
				}
				runes = append(runes, r)
			}
		}
		literals = make([]string, len(runes))
		for i, r := range runes {
			literals[i] = string(r)
		}
		return literals, true
	case syntax.OpCapture:
		return literalPrefixes(re.Sub[0])
	case syntax.OpConcat:
		return concatPrefixes(re.Sub)
	case syntax.OpAlternate:
		complete = true
		for _, sub := range re.Sub {
			subLiterals, subComplete := literalPrefixes(sub)
			literals = append(literals, subLiterals...)
			complete = complete && subComplete
		}
		if len(literals) > maxLiterals {
			return []string{""}, false
		}
		return literals, complete
	case syntax.OpPlus:
		literals, _ = literalPrefixes(re.Sub[0])
		return literals, false
	case syntax.OpRepeat:
		if re.Min >= 1 {
			literals, _ = literalPrefixes(re.Sub[0])
			return literals, false
		}
	}
	return []string{""}, false
}

func concatPrefixes(subs []*syntax.Regexp) (literals []string, complete bool) {
	literals = []string{""}
	for _, sub := range subs {
		next, subComplete := literalPrefixes(sub)
		if len(literals)*len(next) > maxLiterals {
			return literals, false
		}
		var joined []string
		for _, head := range literals {
			for _, tail := range next {
				joined = append(joined, head+tail)
			}
		}
		literals = joined
		if !subComplete {
			return literals, false
		}
	}
	return literals, true
}

func pairs(runes []rune) []rune {
	out := make([]rune, 0, 2*len(runes))
	for _, r := range runes {
		out = append(out, r, r)
	}
	return out
}
