package profile

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/safing/portmaster/base/database"
)

var phase6ProfileDatabaseOnce struct {
	sync.Once
	err error
}

func setupPhase6ProfileDatabase(t *testing.T) {
	t.Helper()
	phase6ProfileDatabaseOnce.Do(func() {
		if err := database.Initialize(t.TempDir()); err != nil && err.Error() != "database already initialized" {
			phase6ProfileDatabaseOnce.err = err
			return
		}
		if _, err := database.Register(&database.Database{Name: "core", StorageType: "sqlite"}); err != nil {
			phase6ProfileDatabaseOnce.err = err
			return
		}
		if err := registerConfiguration(); err != nil {
			phase6ProfileDatabaseOnce.err = err
			return
		}
		phase6ProfileDatabaseOnce.err = registerValidationDBHook()
	})
	if phase6ProfileDatabaseOnce.err != nil {
		t.Fatalf("set up profile database: %v", phase6ProfileDatabaseOnce.err)
	}
}

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
	setupPhase6ProfileDatabase(t)
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

func TestProfileRevisionRemainsRetryableAfterValidationFailure(t *testing.T) {
	setupPhase6ProfileDatabase(t)
	const id = "retry-after-validation-failure"
	profile := New(&Profile{
		ID:     id,
		Source: SourceLocal,
		Fingerprints: []Fingerprint{{
			Type:      FingerprintTypePathID,
			Operation: FingerprintOperationRegexID,
			Value:     "[",
		}},
	})
	if err := profile.Save(); err == nil {
		t.Fatal("invalid fingerprint save unexpectedly succeeded")
	}
	if profile.Revision != 0 {
		t.Fatalf("failed validation changed revision to %d, want 0", profile.Revision)
	}
	profile.Fingerprints = nil
	if err := profile.Save(); err != nil {
		t.Fatalf("retry corrected profile: %v", err)
	}
	if profile.Revision != 1 {
		t.Fatalf("corrected retry revision = %d, want 1", profile.Revision)
	}
	loaded, err := getProfile(MakeScopedID(SourceLocal, id))
	if err != nil {
		t.Fatalf("load corrected profile: %v", err)
	}
	if loaded.Revision != profile.Revision {
		t.Fatalf("durable revision = %d, want %d", loaded.Revision, profile.Revision)
	}

	configProfile := New(&Profile{ID: "retry-after-config-failure", Source: SourceLocal})
	configProfile.Config = map[string]interface{}{
		"filter": map[string]interface{}{"defaultAction": "invalid"},
	}
	if err := configProfile.Save(); err == nil {
		t.Fatal("invalid config save unexpectedly succeeded")
	}
	if configProfile.Revision != 0 {
		t.Fatalf("failed config validation changed revision to %d, want 0", configProfile.Revision)
	}
	configProfile.Config["filter"].(map[string]interface{})["defaultAction"] = DefaultActionPermitValue
	if err := configProfile.Save(); err != nil {
		t.Fatalf("retry corrected config: %v", err)
	}
	if configProfile.Revision != 1 {
		t.Fatalf("corrected config retry revision = %d, want 1", configProfile.Revision)
	}
}
