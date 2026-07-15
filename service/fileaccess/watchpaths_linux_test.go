//go:build linux

package fileaccess

import (
	"reflect"
	"testing"
)

func TestResolveWatchPathsHonorsEmptyConfig(t *testing.T) {
	previous := cfgOptionWatchPaths
	cfgOptionWatchPaths = func() []string { return []string{} }
	defer func() { cfgOptionWatchPaths = previous }()

	t.Setenv(envWatchPaths, "/tmp/should-not-be-used")
	if got := resolveWatchPaths(); len(got) != 0 {
		t.Fatalf("resolveWatchPaths() = %v, want no paths", got)
	}
}

func TestResolveWatchPathsReturnsEmptyWithoutConfig(t *testing.T) {
	previous := cfgOptionWatchPaths
	cfgOptionWatchPaths = nil
	defer func() { cfgOptionWatchPaths = previous }()

	if got := resolveWatchPaths(); len(got) != 0 {
		t.Fatalf("resolveWatchPaths() = %v, want no paths", got)
	}
}

func TestWatchPathsFromEnv(t *testing.T) {
	t.Setenv(envWatchPaths, " /a :/b:: ")
	got := watchPathsFromEnv()
	want := []string{"/a", "/b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("watchPathsFromEnv() = %v, want %v", got, want)
	}
}

func TestWatchPathsFromEnvReturnsEmptyWhenUnset(t *testing.T) {
	t.Setenv(envWatchPaths, "")
	if got := watchPathsFromEnv(); len(got) != 0 {
		t.Fatalf("watchPathsFromEnv() = %v, want no paths", got)
	}
}

func TestNormalizePath(t *testing.T) {
	got, err := normalizePath("/a/../b/")
	if err != nil || got != "/b" {
		t.Fatalf("normalized path = %q, %v; want /b", got, err)
	}
	if _, err := normalizePath("relative"); err == nil {
		t.Fatal("relative path was accepted")
	}
}
