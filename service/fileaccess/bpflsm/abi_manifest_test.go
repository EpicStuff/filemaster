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
	Layouts   map[string]abiManifestLayout
	Constants map[string]int
}

func (m *abiManifest) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.Layouts = make(map[string]abiManifestLayout)
	for name, value := range raw {
		if name == "constants" {
			if err := json.Unmarshal(value, &m.Constants); err != nil {
				return err
			}
			continue
		}
		var layout abiManifestLayout
		if err := json.Unmarshal(value, &layout); err != nil {
			return err
		}
		m.Layouts[name] = layout
	}
	return nil
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

	layouts := []struct {
		name    string
		size    int
		offsets map[string]int
	}{
		{"FileId", 16, map[string]int{"dev": 0, "ino": 8}},
		{"Settings", settingsSize, map[string]int{"daemon_pid": 0, "active_bank": 4, "daemon_exe": 8, "audit": 24, "pad": 28}},
		{"ObjectKey", objectKeySize, map[string]int{"file": 0, "bank": 16, "pad": 20}},
		{"ObjectValue", objectValueSize, map[string]int{"first_context": 0, "context_count": 4}},
		{"ScopeRef", scopeRefSize, map[string]int{"off": 0, "len": 4, "exclude": 8}},
		{"RuleRef", ruleRefSize, map[string]int{"pattern": 0, "list": 2, "flags": 3}},
		{"Context", contextSize, map[string]int{
			"path_off": 0, "path_len": 4, "parent_len": 8, "flags": 12, "scope_count": 16, "rule_count": 20,
			"scopes": 24, "rules": 24 + contextScopes*scopeRefSize,
		}},
		{"Pattern", patternSize, map[string]int{"off": 0, "len": 4, "recursive": 8, "chunk_off": 12, "chunk_len": 16}},
		{"Chunk", chunkSize, map[string]int{"star": 0, "token_off": 4, "token_len": 8}},
		{"Token", tokenSize, map[string]int{"kind": 0, "byte": 1, "negated": 2, "range_off": 4, "range_len": 8}},
		{"Range", rangeSize, map[string]int{"lo": 0, "hi": 4}},
		{"Arena", arenaValueSize, nil},
		{"Scratch", scratchSize, nil},
		{"Offsets", offsetsSize, nil},
	}
	for _, layout := range layouts {
		got, ok := manifest.Layouts[layout.name]
		if !ok {
			t.Errorf("manifest has no %s", layout.name)
			continue
		}
		assertLayout(t, layout.name, got, layout.size, layout.offsets)
	}
	for name, want := range map[string]int{
		"NUM_BANKS": numBanks, "MAX_OBJECTS": maxObjects, "MAX_CONTEXTS": maxContexts, "MAX_PATTERNS": maxPatterns,
		"MAX_CHUNKS": maxChunks, "MAX_TOKENS": maxTokens, "MAX_RANGES": maxRanges,
		"CONTEXT_RULES": contextRules, "CONTEXT_SCOPES": contextScopes, "ARENA_SIZE": arenaSize, "MAX_STRING": maxString,
		"AUDIT_COUNTERS": auditSlots, "NOMATCH_ENTRIES": nomatchEntries, "HOOKS": hookCount, "REASONS": reasonCount,
	} {
		if got, ok := manifest.Constants[name]; !ok || got != want {
			t.Errorf("constant %s = %d (present %v), Go expects %d", name, got, ok, want)
		}
	}
	if len(Hooks) != hookCount {
		t.Errorf("Hooks has %d entries, COUNTERS has %d hook slots", len(Hooks), hookCount)
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
