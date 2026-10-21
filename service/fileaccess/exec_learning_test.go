package fileaccess

import (
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/safing/portmaster/service/profile"
)

type testMatchingData struct {
	path    string
	cmdline string
	env     map[string]string
}

func (md testMatchingData) Tags() []profile.Tag    { return nil }
func (md testMatchingData) Env() map[string]string { return md.env }
func (md testMatchingData) Path() string           { return md.path }
func (md testMatchingData) MatchingPath() string   { return "" }
func (md testMatchingData) Cmdline() string        { return md.cmdline }

// resolveTestProfile is findProfile over an in-memory profile list: the
// highest MatchFingerprints score wins and the first of equal scores is kept.
func resolveTestProfile(profiles []*profile.ParsedFingerprints, md profile.MatchingData) int {
	best, bestScore := -1, 0
	for i, prints := range profiles {
		if score := profile.MatchFingerprints(prints, md); score > bestScore {
			best, bestScore = i, score
		}
	}
	return best
}

// TestExecLearningDifferential checks that whenever execLearning allows an
// executable to be labelled by inode alone, profile resolution gives it the
// same profile for every argv and environment it is generated with: argv[0]
// as the executable's path, its base name, a relative path to it, or a
// symlink naming it, followed by arbitrary arguments.
func TestExecLearningDifferential(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	bin := filepath.Join(root, "bin")
	for _, dir := range []string{real, bin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var exes []string
	for _, name := range []string{"rm", "rmdir", "mv", "vim", "tool", "rx", "python3.12", "my prog"} {
		exe := filepath.Join(real, name)
		if err := os.WriteFile(exe, nil, 0o755); err != nil {
			t.Fatal(err)
		}
		exes = append(exes, exe)
	}
	aliases := map[string][]string{}
	for alias, target := range map[string]string{"vi": "vim", "rview": "vim", "python3": "python3.12", "remove": "rm", "mvx": "mv"} {
		link := filepath.Join(bin, alias)
		if err := os.Symlink(filepath.Join(real, target), link); err != nil {
			t.Fatal(err)
		}
		aliases[filepath.Join(real, target)] = append(aliases[filepath.Join(real, target)], link)
	}

	cmdlineValues := []string{
		"rm", "rm -f", "rm ", "mv", "vi", "vim -R", real + "/rm", real + "/rm -f", real + "/r", bin + "/vi", bin + "/",
		"python3 ", "my prog", "my", "./rm", "./r", "", " ",
	}
	cmdlineRegexes := []string{
		`^rm `, `^rm$`, `^(rm|mv) `, `^r[mx]`, `(?i)^RM`, `^vi\b`, `^` + regexp.QuoteMeta(real) + `/r`, `^` + regexp.QuoteMeta(bin) + `/v`,
		`^python3 -c`, `\Amv`, `^`, `^rm|^mv`, `^my prog`, `^m[a-z]`, `^r+m`, `^(?:vi|vim)$`,
		`rm`, `.*rm`, `(?m)^rm`, `^.rm`, `^\./r`,
	}
	pathValues := []string{real + "/", real + "/r", real + "/rm", real + "/vim", bin + "/vi", "/usr/bin/"}
	pathRegexes := []string{`rm$`, `^` + regexp.QuoteMeta(real) + `/r`, `vim`, `^/usr/`}
	envKeys := []string{"HOME", "MODE"}

	random := rand.New(rand.NewSource(1))
	pick := func(values []string) string { return values[random.Intn(len(values))] }
	fingerprint := func() profile.Fingerprint {
		switch random.Intn(10) {
		case 0, 1, 2:
			return profile.Fingerprint{Type: profile.FingerprintTypeCmdlineID, Operation: profile.FingerprintOperationRegexID, Value: pick(cmdlineRegexes)}
		case 3:
			return profile.Fingerprint{Type: profile.FingerprintTypeCmdlineID, Operation: profile.FingerprintOperationEqualsID, Value: pick(cmdlineValues)}
		case 4:
			return profile.Fingerprint{Type: profile.FingerprintTypeCmdlineID, Operation: profile.FingerprintOperationPrefixID, Value: pick(cmdlineValues)}
		case 5:
			if random.Intn(4) == 0 {
				return profile.Fingerprint{Type: profile.FingerprintTypeEnvID, Key: pick(envKeys), Operation: profile.FingerprintOperationEqualsID, Value: "x"}
			}
			return profile.Fingerprint{Type: profile.FingerprintTypeTagID, Key: "python-script", Operation: profile.FingerprintOperationEqualsID, Value: "/a.py"}
		case 6:
			return profile.Fingerprint{Type: profile.FingerprintTypePathID, Operation: profile.FingerprintOperationPrefixID, Value: pick(pathValues)}
		case 7:
			return profile.Fingerprint{Type: profile.FingerprintTypePathID, Operation: profile.FingerprintOperationRegexID, Value: pick(pathRegexes)}
		default:
			return profile.Fingerprint{Type: profile.FingerprintTypePathID, Operation: profile.FingerprintOperationEqualsID, Value: pick(exes)}
		}
	}
	argTails := [][]string{nil, {"-f"}, {"x"}, {"-f", "x y"}, {"-c", "print()"}, {"-R"}, {""}}
	envs := []map[string]string{nil, {"HOME": "/root"}, {"MODE": "x"}, {"HOME": "x", "MODE": "y"}}

	var learnable, checked, refused int
	for set := 0; set < 3000; set++ {
		raw := make(map[string][]profile.Fingerprint)
		var parsed []*profile.ParsedFingerprints
		for p := 0; p < 1+random.Intn(4); p++ {
			var prints []profile.Fingerprint
			for f := 0; f < 1+random.Intn(3); f++ {
				prints = append(prints, fingerprint())
			}
			raw["p"+strconv.Itoa(p)] = prints
			parsedPrints, _ := profile.ParseFingerprints(prints, "")
			parsed = append(parsed, parsedPrints)
		}
		learning := newExecLearning(raw, []string{bin})
		for _, exe := range exes {
			ok, _ := learning.learnable(exe)
			if !ok {
				refused++
				continue
			}
			learnable++
			argv0s := []string{exe, filepath.Base(exe), "./" + filepath.Base(exe)}
			for _, alias := range aliases[exe] {
				argv0s = append(argv0s, alias, filepath.Base(alias))
			}
			want := -2
			for _, argv0 := range argv0s {
				for _, tail := range argTails {
					for _, env := range envs {
						md := testMatchingData{path: exe, cmdline: strings.Join(append([]string{argv0}, tail...), " "), env: env}
						got := resolveTestProfile(parsed, md)
						checked++
						if want == -2 {
							want = got
						} else if got != want {
							t.Fatalf("exe %s learnable under %v, but cmdline %q env %v resolves to profile %d, not %d",
								exe, raw, md.cmdline, env, got, want)
						}
					}
				}
			}
		}
	}
	t.Logf("%d learnable and %d refused (set, exe) pairs; %d resolutions agreed", learnable, refused, checked)
	if learnable < 1000 || refused < 1000 {
		t.Fatalf("the generator is unbalanced: %d learnable, %d refused", learnable, refused)
	}
}

// TestExecLearningAnalysis pins the argv[0] analysis of individual
// fingerprints.
func TestExecLearningAnalysis(t *testing.T) {
	cmdline := func(op, value string) map[string][]profile.Fingerprint {
		return map[string][]profile.Fingerprint{"p": {{Type: profile.FingerprintTypeCmdlineID, Operation: op, Value: value}}}
	}
	for _, c := range []struct {
		prints  map[string][]profile.Fingerprint
		exe     string
		learn   bool
		offWant bool
	}{
		{cmdline(profile.FingerprintOperationRegexID, `^python3 `), "/usr/bin/rm", true, false},
		{cmdline(profile.FingerprintOperationRegexID, `^python3 `), "/opt/python3", false, false},
		{cmdline(profile.FingerprintOperationRegexID, `^rm `), "/usr/bin/rm", false, false},
		{cmdline(profile.FingerprintOperationRegexID, `^rm `), "/usr/bin/rmdir", true, false},
		{cmdline(profile.FingerprintOperationRegexID, `^rm`), "/usr/bin/rmdir", false, false},
		{cmdline(profile.FingerprintOperationRegexID, `^/usr/bin/rm `), "/usr/bin/rm", false, false},
		{cmdline(profile.FingerprintOperationRegexID, `^/usr/bin/rm `), "/tmp/rm", true, false},
		{cmdline(profile.FingerprintOperationRegexID, `/a2\.py `), "/usr/bin/rm", false, true},
		{cmdline(profile.FingerprintOperationRegexID, `^.*foo`), "/usr/bin/rm", false, true},
		{cmdline(profile.FingerprintOperationPrefixID, ""), "/usr/bin/rm", false, true},
		{cmdline(profile.FingerprintOperationEqualsID, "mv a b"), "/usr/bin/mv", false, false},
		{cmdline(profile.FingerprintOperationEqualsID, "mv a b"), "/usr/bin/rm", true, false},
		{map[string][]profile.Fingerprint{"p": {{Type: profile.FingerprintTypeEnvID, Key: "K", Operation: profile.FingerprintOperationEqualsID, Value: "v"}}}, "/usr/bin/rm", false, true},
		{map[string][]profile.Fingerprint{"p": {{Type: profile.FingerprintTypePathID, Operation: profile.FingerprintOperationPrefixID, Value: "/usr/"}}}, "/usr/bin/rm", false, false},
		{map[string][]profile.Fingerprint{"p": {{Type: profile.FingerprintTypePathID, Operation: profile.FingerprintOperationRegexID, Value: "^/opt/"}}}, "/usr/bin/rm", true, false},
		{nil, "/app/bin/tool", false, false},
		{nil, "/tmp/.mount_abc/usr/bin/tool", false, false},
		{nil, "/snap/foo/1/bin/tool", false, false},
	} {
		learning := newExecLearning(c.prints, nil)
		got, reason := learning.learnable(c.exe)
		if got != c.learn || (learning.off != "") != c.offWant {
			t.Errorf("%v on %s: learnable=%v (%s) off=%q, want learnable=%v off=%v", c.prints, c.exe, got, reason, learning.off, c.learn, c.offWant)
		}
	}
}

// TestAnchoredPrefixes pins the regex literal-prefix analysis.
func TestAnchoredPrefixes(t *testing.T) {
	for _, c := range []struct {
		regex    string
		want     []string
		complete bool
		ok       bool
	}{
		{`^rm `, []string{"rm "}, false, true},
		{`^rm$`, []string{"rm"}, true, true},
		{`^(rm|mv) `, []string{"rm ", "mv "}, false, true},
		{`^rm|^mv`, []string{"rm", "mv"}, false, true},
		{`(?i)^rm`, []string{"rm", "rM", "Rm", "RM"}, false, true},
		{`^r[mx] `, []string{"rm ", "rx "}, false, true},
		{`^r+m`, []string{"r"}, false, true},
		{`^`, []string{""}, true, true},
		{`rm`, nil, false, false},
		{`(?m)^rm`, nil, false, false},
	} {
		parsed, err := syntax.Parse(c.regex, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		got, complete, ok := anchoredPrefixes(parsed.Simplify())
		slices.Sort(got)
		want := slices.Clone(c.want)
		slices.Sort(want)
		if ok != c.ok || (ok && (complete != c.complete || !slices.Equal(got, want))) {
			t.Errorf("%s: %q complete=%v ok=%v, want %q %v %v", c.regex, got, complete, ok, want, c.complete, c.ok)
		}
	}
}
