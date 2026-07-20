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
	SetFilemasterSeedPaths([]string{"/opt/filemaster", "/var/lib/filemaster"})
	t.Cleanup(func() { SetFilemasterSeedPaths(nil) })

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
	// Trusted paths are seeded into every per-operation list.
	for name, got := range map[string][]string{
		"read":  p.GetFileAccessReadRules(),
		"write": p.GetFileAccessWriteRules(),
		"exec":  p.GetFileAccessExecRules(),
	} {
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s seed rules = %#v, want %#v", name, got, want)
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
	if len(p.GetFileAccessReadRules()) == 0 {
		t.Fatal("expected editable systemd seed rules")
	}
}
