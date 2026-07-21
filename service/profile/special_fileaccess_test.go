package profile

import (
	"reflect"
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
	SetFilemasterSeedPaths("/opt/filemaster", "/var/lib/filemaster")
	t.Cleanup(func() { SetFilemasterSeedPaths("", "") })

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
	SetFilemasterSeedPaths("/opt/filemaster", "/var/lib/filemaster")
	t.Cleanup(func() { SetFilemasterSeedPaths("", "") })

	want := []string{
		"+ /opt/filemaster/filemaster",
		"+ /opt/filemaster/**",
		"+ /var/lib/filemaster/**",
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
