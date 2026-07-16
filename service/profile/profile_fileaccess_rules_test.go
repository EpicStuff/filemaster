package profile

import (
	"reflect"
	"testing"

	"github.com/safing/portmaster/base/database"
)

func TestCoalesceFileAccessRuleEntriesUsesEffectivePrecedence(t *testing.T) {
	tests := []struct {
		name  string
		list  []string
		entry string
		want  []string
	}{
		{
			name:  "failed mutation with unrelated prepend saves without duplicate",
			list:  []string{"+ /tmp/unrelated", "+ /tmp/file"},
			entry: "+ /tmp/file",
			want:  []string{"+ /tmp/unrelated", "+ /tmp/file"},
		},
		{
			name:  "opposing exact rule requires new leading decision",
			list:  []string{"- /tmp/file", "+ /tmp/file", "+ /tmp/unrelated"},
			entry: "+ /tmp/file",
			want:  []string{"+ /tmp/file", "+ /tmp/unrelated"},
		},
		{
			name:  "broader first match requires new leading exact decision",
			list:  []string{"+ /tmp/*", "+ /tmp/file", "- /tmp/unrelated"},
			entry: "+ /tmp/file",
			want:  []string{"+ /tmp/file", "+ /tmp/*", "- /tmp/unrelated"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := coalesceFileAccessRuleEntries(test.list, test.entry)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("coalesced entries = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPersistCurrentFileAccessRuleUsesCurrentDurableRecord(t *testing.T) {
	if err := database.Initialize(t.TempDir()); err != nil && err.Error() != "database already initialized" {
		t.Fatalf("database.Initialize: %v", err)
	}
	if _, err := database.Register(&database.Database{Name: "core", StorageType: "sqlite"}); err != nil {
		t.Fatalf("database.Register core: %v", err)
	}
	if err := registerConfiguration(); err != nil {
		t.Fatalf("register profile configuration: %v", err)
	}
	const id = "current-file-access-rule"
	old := New(&Profile{ID: id, Source: SourceLocal, Name: "old", Description: "old description"})
	if err := old.Save(); err != nil {
		t.Fatalf("save old profile: %v", err)
	}
	current := New(&Profile{ID: id, Source: SourceLocal, Name: "replacement", Description: "kept description"})
	if err := current.Save(); err != nil {
		t.Fatalf("save replacement profile: %v", err)
	}
	if err := PersistCurrentFileAccessRule(SourceLocal, id, `+ @"/tmp/stale"`, func() bool { return false }); err == nil {
		t.Fatal("stale authority was allowed to write a permanent rule")
	}
	staleCheck, err := getProfile(MakeScopedID(SourceLocal, id))
	if err != nil {
		t.Fatalf("load profile after stale conflict: %v", err)
	}
	if staleCheck.Name != "replacement" || len(staleCheck.GetFileAccessRules()) != 0 {
		t.Fatalf("stale update changed replacement record: %+v", staleCheck.GetFileAccessRules())
	}
	if err := PersistCurrentFileAccessRule(SourceLocal, id, `+ @"/tmp/literal*path"`, func() bool { return true }); err != nil {
		t.Fatalf("persist current file access rule: %v", err)
	}
	loaded, err := getProfile(MakeScopedID(SourceLocal, id))
	if err != nil {
		t.Fatalf("load current profile: %v", err)
	}
	if loaded.Name != "replacement" || loaded.Description != "kept description" {
		t.Fatalf("current profile fields were overwritten: name=%q description=%q", loaded.Name, loaded.Description)
	}
	if rules := loaded.GetFileAccessRules(); !reflect.DeepEqual(rules, []string{`+ @"/tmp/literal*path"`}) {
		t.Fatalf("stored rules = %v", rules)
	}
}
