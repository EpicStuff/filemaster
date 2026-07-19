package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWritePrivateJSONCreatesCompletePrivateAtomicReplacement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "benchmark.json")
	if err := os.WriteFile(path, []byte("{\"old\":true}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()

	payload := []byte(`{"complete":true,"events":7}`)
	if err := writePrivateJSON(path, payload); err != nil {
		t.Fatalf("writePrivateJSON: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("complete JSON: %v", err)
	}
	if decoded["events"] != float64(7) {
		t.Fatalf("JSON = %s, want new complete payload", data)
	}
	oldData := make([]byte, len("{\"old\":true}\n"))
	if _, err := old.ReadAt(oldData, 0); err != nil {
		t.Fatal(err)
	}
	if string(oldData) != "{\"old\":true}\n" {
		t.Fatalf("replacement mutated pre-rename file handle: %q", oldData)
	}
}

func TestWritePrivateJSONIgnoresPredictableTemporarySymlink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "benchmark.json")
	victim := filepath.Join(directory, "victim")
	if err := os.WriteFile(victim, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateJSON(path, []byte(`{"safe":true}`)); err != nil {
		t.Fatalf("writePrivateJSON: %v", err)
	}
	victimData, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(victimData) != "do not overwrite" {
		t.Fatalf("predictable symlink redirected write: %q", victimData)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\"safe\":true}\n" {
		t.Fatalf("artifact = %q", data)
	}
}

func TestWritePrivateJSONRemovesTemporaryFileAfterFailedCommit(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "benchmark.json")
	ops := defaultPrivateJSONOps
	ops.rename = func(string, string) error { return errors.New("rename failed") }
	if err := writePrivateJSONWithOps(path, []byte(`{"failed":true}`), ops); err == nil {
		t.Fatal("writePrivateJSONWithOps unexpectedly succeeded")
	}
	leftovers, err := filepath.Glob(filepath.Join(directory, ".benchmark.json-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temporary artifacts left behind: %v", leftovers)
	}
}
