package profile

import (
	"reflect"
	"strings"
	"sync"
	"testing"
)

var (
	profileConfigOnce sync.Once
	profileConfigErr  error
)

func requireProfileConfiguration(t *testing.T) {
	t.Helper()
	profileConfigOnce.Do(func() { profileConfigErr = registerConfiguration() })
	if profileConfigErr != nil {
		t.Fatalf("register profile configuration: %v", profileConfigErr)
	}
}

func TestFilemasterSpecialProfileSeedsEditableRules(t *testing.T) {
	requireProfileConfiguration(t)
	previousHomes := userHomeDirsFunc
	userHomeDirsFunc = func() []string { return []string{"/home/tester"} }
	SetFilemasterSeedPaths("/opt/filemaster", "/var/lib/filemaster")
	t.Cleanup(func() {
		userHomeDirsFunc = previousHomes
		SetFilemasterSeedPaths("", "")
	})

	p := createSpecialProfile(PortmasterProfileID, "/opt/filemaster/filemaster")
	if p == nil {
		t.Fatal("expected Filemaster special profile")
	}
	if p.Internal {
		t.Fatal("Filemaster profile must remain visible in the app-profile editor")
	}
	if got := p.DefaultAction(); got != DefaultActionPermit {
		t.Fatalf("default action = %d, want permit", got)
	}
	want := []string{
		"+ /opt/filemaster/filemaster",
		"+ /opt/filemaster/**",
		"+ /var/lib/filemaster/**",
		"+ /home/tester/.config/filemaster/**",
		"+ /home/tester/.local/share/filemaster/**",
		"+ /home/tester/.cache/filemaster/**",
		"+ /home/tester/.cache/mesa_shader_cache/**",
		"+ /home/tester/.cache/dconf/**",
	}
	if got := p.GetFileAccessReadRules(); !reflect.DeepEqual(got, want) {
		t.Fatalf("read seed rules = %#v, want %#v", got, want)
	}
	wantExec := []string{
		"+ /opt/filemaster/filemaster",
		"+ /opt/filemaster/**",
	}
	if got := p.GetFileAccessExecRules(); !reflect.DeepEqual(got, wantExec) {
		t.Fatalf("exec seed rules = %#v, want %#v", got, wantExec)
	}
	if got := p.GetFileAccessWriteRules(); len(got) != 0 {
		t.Fatalf("inactive write seed rules = %#v, want none", got)
	}
	for _, rule := range append(p.GetFileAccessReadRules(), p.GetFileAccessExecRules()...) {
		if strings.HasPrefix(rule, "+ folder:") {
			t.Fatalf("recursive seed must retain file access, got %q", rule)
		}
	}
}

func TestSystemdSpecialProfileSeedsRulesWithoutDefaultAction(t *testing.T) {
	requireProfileConfiguration(t)
	p := createSpecialProfile(SystemdProfileID, "/usr/lib/systemd/systemd")
	if p == nil {
		t.Fatal("expected systemd special profile")
	}
	if got := p.DefaultAction(); got != DefaultActionNotSet {
		t.Fatalf("default action = %d, want unset", got)
	}
	want := systemdFileAccessRules()
	for name, got := range map[string][]string{
		"read": p.GetFileAccessReadRules(),
		"exec": p.GetFileAccessExecRules(),
	} {
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("systemd %s seed rules = %#v, want %#v", name, got, want)
		}
	}
	if got := p.GetFileAccessWriteRules(); len(got) != 0 {
		t.Fatalf("inactive systemd write seed rules = %#v, want none", got)
	}

}

func TestFilemasterAppSpecialProfilesSeedRulesWithoutDefaultAction(t *testing.T) {
	requireProfileConfiguration(t)
	previousHomes := userHomeDirsFunc
	userHomeDirsFunc = func() []string { return []string{"/home/tester"} }
	SetFilemasterSeedPaths("/opt/filemaster", "/var/lib/filemaster")
	t.Cleanup(func() {
		userHomeDirsFunc = previousHomes
		SetFilemasterSeedPaths("", "")
	})

	// The desktop's own state directories are seeded so it never blocks on its
	// own storage in prompt mode.
	want := []string{
		"+ /opt/filemaster/filemaster",
		"+ /opt/filemaster/**",
		"+ /var/lib/filemaster/**",
		"+ /home/tester/.config/filemaster/**",
		"+ /home/tester/.local/share/filemaster/**",
		"+ /home/tester/.cache/filemaster/**",
		"+ /home/tester/.cache/mesa_shader_cache/**",
		"+ /home/tester/.cache/dconf/**",
	}
	for _, id := range []string{PortmasterAppProfileID, PortmasterNotifierProfileID} {
		p := createSpecialProfile(id, "/opt/filemaster/filemaster")
		if p == nil {
			t.Fatalf("expected %s special profile", id)
		}
		if !p.Internal {
			t.Fatalf("%s must remain internal", id)
		}
		if got := p.DefaultAction(); got != DefaultActionNotSet {
			t.Fatalf("%s default action = %d, want unset", id, got)
		}
		if got := p.GetFileAccessReadRules(); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s read seed rules = %#v, want %#v", id, got, want)
		}
		wantExec := []string{
			"+ /opt/filemaster/filemaster",
			"+ /opt/filemaster/**",
		}
		if got := p.GetFileAccessExecRules(); !reflect.DeepEqual(got, wantExec) {
			t.Fatalf("%s exec seed rules = %#v, want %#v", id, got, wantExec)
		}
		if got := p.GetFileAccessWriteRules(); len(got) != 0 {
			t.Fatalf("%s inactive write seed rules = %#v, want none", id, got)
		}
	}
}

// TestSeededRuleDefaults exercises the registry the UI "reset to default" action
// reads: seeded profiles return their rule-list config keyed by option, while
// profiles with no seed (regular apps) return nil so reset clears the per-app
// override and inherits the global rules.
func TestSeededRuleDefaults(t *testing.T) {
	requireProfileConfiguration(t)
	SetFilemasterSeedPaths("/opt/filemaster", "/var/lib/filemaster")
	t.Cleanup(func() { SetFilemasterSeedPaths("", "") })

	seed := SeededRuleDefaults(PortmasterProfileID, "/opt/filemaster/filemaster")
	if seed == nil {
		t.Fatal("seeded profile returned nil defaults")
	}
	// Only rule-list keys belong in the seed; the default action is set by
	// createSpecialProfile, not here.
	if _, ok := seed[CfgOptionDefaultActionKey]; ok {
		t.Error("seed must not carry the default-action key")
	}
	for _, key := range []string{CfgOptionFileAccessReadRulesKey, CfgOptionFileAccessExecRulesKey} {
		if _, ok := seed[key]; !ok {
			t.Errorf("seed missing %s", key)
		}
	}

	if got := SeededRuleDefaults("_some-regular-app", "/usr/bin/app"); got != nil {
		t.Errorf("unseeded profile defaults = %#v, want nil (inherits global)", got)
	}
}
