package fileaccess

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// persistedFile is the on-disk schema for per-exe rules. Version bumps
// trigger a refusal to load (rather than silently losing state) so we
// notice incompatible schema changes during development.
type persistedFile struct {
	Version int                    `json:"version"`
	Rules   map[string][]PathRule  `json:"rules"`
}

const persistedFileVersion = 1

// Save writes the handler's per-exe rule map to disk as JSON. Safe to
// call from any goroutine; takes the handler's read lock.
//
// Writes go through a temp-file + rename so a crashed write doesn't
// truncate the existing rules file.
func (h *PromptHandler) Save(path string) error {
	if path == "" {
		return errors.New("save path empty")
	}

	h.rulesMu.RLock()
	snapshot := make(map[string][]PathRule, len(h.rules))
	for exe, rs := range h.rules {
		rules := make([]PathRule, len(rs.Rules))
		copy(rules, rs.Rules)
		snapshot[exe] = rules
	}
	h.rulesMu.RUnlock()

	payload := persistedFile{Version: persistedFileVersion, Rules: snapshot}
	data, err := json.MarshalIndent(payload, "", "\t")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// Load replaces the handler's rule map with whatever's on disk at path.
// A missing file is not an error: it just leaves the in-memory map
// empty. A file present but malformed or wrong-version returns an
// error rather than silently dropping rules.
func (h *PromptHandler) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read: %w", err)
	}

	var payload persistedFile
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	if payload.Version != persistedFileVersion {
		return fmt.Errorf("unsupported rules-file version %d (want %d)", payload.Version, persistedFileVersion)
	}

	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	h.rules = make(map[string]*PathRules, len(payload.Rules))
	for exe, rules := range payload.Rules {
		h.rules[exe] = &PathRules{
			Rules:   append([]PathRule(nil), rules...),
			Default: h.initial.Default,
		}
	}
	return nil
}

// SetPersistPath enables auto-save on every rule change. Pass "" to
// disable. Must be set before Start (or the first prompt response)
// since it's not goroutine-safe with concurrent appendRule calls.
//
// On set, also triggers a Load() of the existing file (if any) so the
// caller doesn't have to chain Load+SetPersistPath separately.
func (h *PromptHandler) SetPersistPath(path string) error {
	h.persistPath = path
	if path == "" {
		return nil
	}
	return h.Load(path)
}
