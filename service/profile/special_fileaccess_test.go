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

func TestFilemasterAppSpecialProfilesSeedRulesWithoutDefaultAction(t *testing.T) {
	requireProfileConfiguration(t)
	SetFilemasterSeedPaths([]string{"/opt/filemaster", "/var/lib/filemaster"})
	t.Cleanup(func() { SetFilemasterSeedPaths(nil) })

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
		for name, got := range map[string][]string{
			"read":  p.GetFileAccessReadRules(),
			"exec":  p.GetFileAccessExecRules(),
			"write": p.GetFileAccessWriteRules(),
		} {
			if name == "write" {
				if len(got) != 0 {
					t.Fatalf("%s %s seed rules = %#v, want none", id, name, got)
				}
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s %s seed rules = %#v, want %#v", id, name, got, want)
			}
		}
	}
}

func TestFilemasterAppSpecialProfilesUpgradeUnmodifiedBlockPolicy(t *testing.T) {
	requireProfileConfiguration(t)
	for _, id := range []string{PortmasterAppProfileID, PortmasterNotifierProfileID} {
		legacy := New(&Profile{
			ID:     id,
			Source: SourceLocal,
			Config: map[string]interface{}{CfgOptionDefaultActionKey: DefaultActionBlockValue},
		})
		if !specialProfileNeedsReset(legacy) {
			t.Fatalf("unmodified %s legacy block policy was not selected for upgrade", id)
		}

		legacy.LastEdited = 1
		if specialProfileNeedsReset(legacy) {
			t.Fatalf("edited %s legacy policy was selected for upgrade", id)
		}
	}
}
