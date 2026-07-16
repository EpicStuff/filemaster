package profile

import (
	"errors"
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
	if err := registerValidationDBHook(); err != nil {
		t.Fatalf("register profile revision hook: %v", err)
	}
	const id = "current-file-access-rule"
	old := New(&Profile{ID: id, Source: SourceLocal, Name: "old", Description: "old description"})
	if err := old.Save(); err != nil {
		t.Fatalf("save old profile: %v", err)
	}
	if old.Revision != 1 {
		t.Fatalf("initial durable revision = %d, want 1", old.Revision)
	}
	current, err := getProfile(MakeScopedID(SourceLocal, id))
	if err != nil {
		t.Fatalf("load current profile: %v", err)
	}
	current.Name = "replacement"
	current.Description = "kept description"
	if err := current.Save(); err != nil {
		t.Fatalf("save replacement profile: %v", err)
	}
	if current.Revision != 2 {
		t.Fatalf("replacement durable revision = %d, want 2", current.Revision)
	}
	old.Name = "stale overwrite"
	if err := old.Save(); !errors.Is(err, ErrProfileRevisionConflict) {
		t.Fatalf("stale profile save error = %v, want revision conflict", err)
	}
	if err := profileDB.Put(old); !errors.Is(err, ErrProfileRevisionConflict) {
		t.Fatalf("stale generic profile put error = %v, want revision conflict", err)
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
	if loaded.Revision != 3 {
		t.Fatalf("rule update durable revision = %d, want 3", loaded.Revision)
	}
	if rules := loaded.GetFileAccessRules(); !reflect.DeepEqual(rules, []string{`+ @"/tmp/literal*path"`}) {
		t.Fatalf("stored rules = %v", rules)
	}
	first, err := getProfile(MakeScopedID(SourceLocal, id))
	if err != nil {
		t.Fatalf("load first concurrent editor: %v", err)
	}
	second, err := getProfile(MakeScopedID(SourceLocal, id))
	if err != nil {
		t.Fatalf("load second concurrent editor: %v", err)
	}
	first.Name = "first concurrent update"
	second.Description = "second concurrent update"
	start := make(chan struct{})
	errs := make(chan error, 2)
	go func() { <-start; errs <- first.Save() }()
	go func() { <-start; errs <- profileDB.Put(second) }()
	close(start)
	firstErr, secondErr := <-errs, <-errs
	if (firstErr == nil) == (secondErr == nil) || (!errors.Is(firstErr, ErrProfileRevisionConflict) && !errors.Is(secondErr, ErrProfileRevisionConflict)) {
		t.Fatalf("concurrent writes = %v, %v; want one success and one revision conflict", firstErr, secondErr)
	}
	concurrent, err := getProfile(MakeScopedID(SourceLocal, id))
	if err != nil {
		t.Fatalf("load concurrent result: %v", err)
	}
	if rules := concurrent.GetFileAccessRules(); !reflect.DeepEqual(rules, []string{`+ @"/tmp/literal*path"`}) {
		t.Fatalf("concurrent profile update lost durable rule: %v", rules)
	}
	if err := old.delete(); !errors.Is(err, ErrProfileRevisionConflict) {
		t.Fatalf("stale delete error = %v, want revision conflict", err)
	}
}
