package base

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestDefaultAPIPortMatchesUIConstants(t *testing.T) {
	host, port, err := net.SplitHostPort(DefaultAPIListenAddress)
	if err != nil {
		t.Fatalf("DefaultAPIListenAddress %q is not host:port: %v", DefaultAPIListenAddress, err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("DefaultAPIListenAddress host = %q, want 127.0.0.1", host)
	}

	root := filepath.Join("..", "..", "..")
	assertRustAPIPorts(t, root, port, []string{
		"desktop/tauri/src-tauri/src/portmaster/websocket.rs",
		"desktop/tauri/src-tauri/src/portmaster/mod.rs",
		"desktop/tauri/src-tauri/src/window.rs",
	})
	assertCapabilityRemotePort(t, root, port)
	assertAngularDefaultPort(t, root, port)
}

func assertRustAPIPorts(t *testing.T, root, wantPort string, files []string) {
	t.Helper()
	re := regexp.MustCompile(`127\.0\.0\.1:(\d+)`)
	for _, file := range files {
		path := filepath.Join(root, filepath.FromSlash(file))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		matches := re.FindAllSubmatch(data, -1)
		if len(matches) == 0 {
			t.Fatalf("%s has no hardcoded localhost port", file)
		}
		for _, match := range matches {
			gotPort := string(match[1])
			if gotPort == "4200" {
				continue
			}
			if gotPort != wantPort {
				t.Fatalf("%s has API port %s, want %s", file, gotPort, wantPort)
			}
		}
	}
}

func assertCapabilityRemotePort(t *testing.T, root, wantPort string) {
	t.Helper()
	path := filepath.Join(root, "desktop", "tauri", "src-tauri", "capabilities", "default.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capabilities/default.json: %v", err)
	}
	var capability struct {
		Remote struct {
			URLs []string `json:"urls"`
		} `json:"remote"`
	}
	if err := json.Unmarshal(data, &capability); err != nil {
		t.Fatalf("parse capabilities/default.json: %v", err)
	}
	if len(capability.Remote.URLs) == 0 {
		t.Fatal("capabilities/default.json has no remote urls")
	}
	for _, url := range capability.Remote.URLs {
		re := regexp.MustCompile(`^http://127\.0\.0\.1:(\d+)$`)
		match := re.FindStringSubmatch(url)
		if match == nil {
			t.Fatalf("capabilities/default.json remote url %q is not a localhost API URL", url)
		}
		if match[1] != wantPort {
			t.Fatalf("capabilities/default.json remote url %q has port %s, want %s", url, match[1], wantPort)
		}
	}
}

func assertAngularDefaultPort(t *testing.T, root, wantPort string) {
	t.Helper()
	path := filepath.Join(root, "desktop", "angular", "src", "environments", "environment.ts")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read environment.ts: %v", err)
	}
	re := regexp.MustCompile(`const DEFAULT_PORT = '(\d+)';`)
	match := re.FindSubmatch(data)
	if match == nil {
		t.Fatal("environment.ts DEFAULT_PORT constant not found")
	}
	if string(match[1]) != wantPort {
		t.Fatalf("environment.ts DEFAULT_PORT = %s, want %s", match[1], wantPort)
	}
}
