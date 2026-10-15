//go:build linux

package bpflsm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type abiManifestLayout struct {
	Size    int            `json:"size"`
	Offsets map[string]int `json:"offsets"`
}

type abiManifest struct {
	FileID     abiManifestLayout `json:"FileId"`
	Settings   abiManifestLayout `json:"Settings"`
	ObjectKey  abiManifestLayout `json:"ObjectKey"`
	VerdictKey abiManifestLayout `json:"VerdictKey"`
	NoMatchKey abiManifestLayout `json:"NoMatchKey"`
	Verdict    abiManifestLayout `json:"Verdict"`
	Audit      struct {
		KeySize   int `json:"key_size"`
		ValueSize int `json:"value_size"`
	} `json:"AUDIT"`
}

func TestABImanifestMatchesGoLayout(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("find ABI test source")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(here), "../../../bpf/filemaster-lsm-common/abi-manifest.json"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Rust ABI manifest: %v", err)
	}
	var manifest abiManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse Rust ABI manifest: %v", err)
	}

	assertLayout(t, "FileId", manifest.FileID, 16, map[string]int{"dev": 0, "ino": 8})
	assertLayout(t, "Settings", manifest.Settings, settingsSize, map[string]int{
		"daemon_pid": 0, "active_bank": 4, "daemon_exe": 8, "audit": 24, "pad": 28,
	})
	assertLayout(t, "ObjectKey", manifest.ObjectKey, objectKeySize, map[string]int{
		"file": 0, "bank": 16, "pad": 20,
	})
	assertLayout(t, "VerdictKey", manifest.VerdictKey, verdictKeySize, map[string]int{
		"bank": 0, "object": 4, "label": 8, "operation": 12, "relation": 16, "target_kind": 20,
	})
	assertLayout(t, "NoMatchKey", manifest.NoMatchKey, noMatchKeySize, map[string]int{
		"bank": 0, "label": 4, "operation": 8, "target_kind": 12,
	})
	assertLayout(t, "Verdict", manifest.Verdict, verdictSize, nil)
	if manifest.Audit.KeySize != auditKeySize || manifest.Audit.ValueSize != auditValueSize {
		t.Fatalf("AUDIT ABI = key=%d value=%d, Go expects key=%d value=%d", manifest.Audit.KeySize, manifest.Audit.ValueSize, auditKeySize, auditValueSize)
	}
}

func assertLayout(t *testing.T, name string, got abiManifestLayout, size int, offsets map[string]int) {
	t.Helper()
	if got.Size != size {
		t.Errorf("%s size=%d, want %d", name, got.Size, size)
	}
	for field, want := range offsets {
		if got.Offsets[field] != want {
			t.Errorf("%s.%s offset=%d, want %d", name, field, got.Offsets[field], want)
		}
	}
}
