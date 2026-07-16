package profile

import (
	"bytes"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/safing/portmaster/base/database"
	"github.com/safing/portmaster/base/database/record"
	"github.com/safing/structures/dsd"
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

func TestWrappedProfileTransactionPublishesCommittedPayload(t *testing.T) {
	setupPhase6ProfileDatabase(t)
	profile := New(&Profile{ID: "wrapped-transaction", Source: SourceLocal, Name: "first"})
	if err := profile.Save(); err != nil {
		t.Fatalf("save initial profile: %v", err)
	}
	payload, err := profile.MarshalDataOnly(profile, dsd.JSON)
	if err != nil {
		t.Fatalf("marshal wrapped profile: %v", err)
	}
	wrapper, err := record.NewWrapper(profile.Key(), profile.Meta().Duplicate(), dsd.JSON, payload)
	if err != nil {
		t.Fatalf("create wrapper: %v", err)
	}
	if err := profileDB.Put(wrapper); err != nil {
		t.Fatalf("save wrapped profile: %v", err)
	}
	committed := &Profile{}
	if err := record.Unwrap(wrapper, committed); err != nil {
		t.Fatalf("unwrap committed wrapper: %v", err)
	}
	if committed.Revision != 2 {
		t.Fatalf("wrapped committed revision = %d, want 2", committed.Revision)
	}
	if wrapper.Format != dsd.JSON {
		t.Fatalf("wrapped format = %d, want JSON", wrapper.Format)
	}

	committed.Name = "second"
	payload, err = committed.MarshalDataOnly(committed, wrapper.Format)
	if err != nil {
		t.Fatalf("marshal wrapper reuse edit: %v", err)
	}
	wrapper.Data = payload
	if err := profileDB.Put(wrapper); err != nil {
		t.Fatalf("reuse committed wrapper: %v", err)
	}
	if err := record.Unwrap(wrapper, committed); err != nil {
		t.Fatalf("unwrap reused wrapper: %v", err)
	}
	if committed.Revision != 3 || committed.Name != "second" {
		t.Fatalf("reused wrapper = revision %d name %q, want revision 3 name second", committed.Revision, committed.Name)
	}
}

func TestWrappedProfileValidationFailureDoesNotPublishPayload(t *testing.T) {
	setupPhase6ProfileDatabase(t)
	profile := New(&Profile{
		ID:     "wrapped-validation-failure",
		Source: SourceLocal,
		Fingerprints: []Fingerprint{{
			Type:      FingerprintTypePathID,
			Operation: FingerprintOperationRegexID,
			Value:     "[",
		}},
	})
	profile.CreateMeta()
	payload, err := profile.MarshalDataOnly(profile, dsd.JSON)
	if err != nil {
		t.Fatalf("marshal invalid wrapped profile: %v", err)
	}
	wrapper, err := record.NewWrapper(profile.Key(), profile.Meta().Duplicate(), dsd.JSON, payload)
	if err != nil {
		t.Fatalf("create invalid wrapper: %v", err)
	}
	beforeData := bytes.Clone(wrapper.Data)
	beforeMeta := wrapper.Meta().Duplicate()
	if err := profileDB.Put(wrapper); err == nil {
		t.Fatal("invalid wrapped profile save unexpectedly succeeded")
	}
	if !bytes.Equal(wrapper.Data, beforeData) || !reflect.DeepEqual(wrapper.Meta(), beforeMeta) {
		t.Fatal("failed wrapped profile save published payload or metadata")
	}
}

func TestProfilePayloadMustMatchSubmittedKey(t *testing.T) {
	setupPhase6ProfileDatabase(t)
	profileA := New(&Profile{ID: "key-identity-a", Source: SourceLocal, Name: "A"})
	if err := profileA.Save(); err != nil {
		t.Fatalf("save profile A: %v", err)
	}
	profileB := New(&Profile{ID: "key-identity-b", Source: SourceLocal, Name: "B"})
	if err := profileB.Save(); err != nil {
		t.Fatalf("save profile B: %v", err)
	}
	profileB.Name = "B revision two"
	if err := profileB.Save(); err != nil {
		t.Fatalf("advance profile B: %v", err)
	}

	payload, err := profileB.MarshalDataOnly(profileB, dsd.JSON)
	if err != nil {
		t.Fatalf("marshal profile B: %v", err)
	}
	mismatched, err := record.NewWrapper(profileA.Key(), profileA.Meta().Duplicate(), dsd.JSON, payload)
	if err != nil {
		t.Fatalf("create mismatched wrapper: %v", err)
	}
	if err := profileDB.Put(mismatched); !errors.Is(err, ErrProfileRevisionConflict) {
		t.Fatalf("mismatched wrapper error = %v, want revision conflict", err)
	}
	loadedA, err := getProfile(MakeScopedID(SourceLocal, profileA.ID))
	if err != nil {
		t.Fatalf("load profile A: %v", err)
	}
	loadedB, err := getProfile(MakeScopedID(SourceLocal, profileB.ID))
	if err != nil {
		t.Fatalf("load profile B: %v", err)
	}
	if loadedA.Revision != 1 || loadedA.Name != "A" || loadedB.Revision != 2 || loadedB.Name != "B revision two" {
		t.Fatalf("mismatched write changed profiles: A=%d/%q B=%d/%q", loadedA.Revision, loadedA.Name, loadedB.Revision, loadedB.Name)
	}

	concrete := New(&Profile{ID: profileB.ID, Source: SourceLocal, Name: "mismatched concrete"})
	concrete.ResetKey()
	concrete.SetKey(profileA.Key())
	if err := concrete.Save(); !errors.Is(err, ErrProfileRevisionConflict) {
		t.Fatalf("mismatched concrete error = %v, want revision conflict", err)
	}
}
