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
		{"Settings", settingsSize, map[string]int{"daemon_start": 0, "daemon_tgid": 8, "daemon_span": 12, "active_bank": 16, "audit": 20, "flags": 24}},
		{"ObjectKey", objectKeySize, map[string]int{"file": 0, "bank": 16, "pad": 20}},
		{"ObjectValue", objectValueSize, map[string]int{"first_context": 0, "context_count": 4}},
		{"ScopeRef", scopeRefSize, map[string]int{"off": 0, "len": 4, "exclude": 8}},
		{"RuleRef", ruleRefSize, map[string]int{"pattern": 0, "list": 2, "flags": 3}},
		{"Context", contextSize, map[string]int{
			"path_off": 0, "path_len": 4, "parent_len": 8, "flags": 12, "scope_count": 16, "scopes": 24,
		}},
		{"ExecFile", execFileSize, map[string]int{"dev": 0, "ino": 8, "generation": 16}},
		{"ExecLabelKey", execLabelKey, map[string]int{"exe": 0, "script": execFileSize}},
		{"ProcValue", procValueSize, map[string]int{"start": 0, "seq": 8, "span": 16, "label": 20}},
		{"Resolved", resolvedSize, map[string]int{"start": 0, "seq": 8, "label": 16}},
		{"PolicyListKey", policyListKey, map[string]int{"bank": 0, "policy": 4, "context": 8}},
		{"RuleList", ruleListSize, map[string]int{"rule_count": 0, "flags": 4, "rules": 8}},
		{"WaitSettings", waitSettingsSize, map[string]int{"heartbeat": 0, "max_waiters": 8, "enabled": 12}},
		{"RecordHeader", recordHeader, map[string]int{
			"kind": 0, "tgid": 4, "start": 8, "seq": 16, "exe": 24, "script": 48, "parent_seq": 72,
			"parent_tgid": 80, "flags": 84, "args_len": 88, "env_len": 92, "path_len": 96,
		}},
		{"DecisionRecord", decisionRecordSize, map[string]int{
			"kind": 0, "operation": 4, "verdict": 8, "reason": 12, "tgid": 16, "label": 20, "bank": 24, "flags": 28,
			"start": 32, "source": 40, "target": 56, "source_context": 72, "target_context": 76,
			"source_len": 80, "target_len": 84, "suppressed": 88, "source_path": 96, "target_path": 8288,
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
		"MAX_LABELS": maxLabels, "MAX_POLICIES": maxPolicies, "MAX_RULELISTS": maxRuleLists, "MAX_POLICY_LISTS": maxPolicyLists,
		"MAX_PROCS": maxProcs, "MAX_EXEC_LABELS": maxExecLabels, "EXEC_SCRATCH_ENTRIES": execScratchSize,
		"STATE_SLOTS": stateSlots, "RECORDS_SIZE": recordsSize, "RECORD_BUF_SIZE": recordBufSize, "DECISION_RECORD_SIZE": decisionRecordSize,
		"DECISION_PATH_MAX": decisionPathMax, "DECISION_SUPPRESS_ENTRIES": decisionSuppressEntries,
		"DECISION_SUPPRESS_LIMIT": decisionSuppressLimit, "ARGS_MAX": argsMax, "ENV_MAX": envMax,
		"LABEL_COUNTERS": labelCounters, "WAIT_CAP_NS": int(waitCap), "WAIT_STALE_NS": int(waitStale),
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
