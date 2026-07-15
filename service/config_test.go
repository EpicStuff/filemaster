package service

import (
	"runtime"
	"testing"
)

func TestLinuxDefaultDirectories(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux defaults only")
	}

	config := &ServiceConfig{}
	if err := config.Init(); err != nil {
		t.Fatalf("initialize default service configuration: %v", err)
	}

	if config.BinDir != "/opt/filemaster" {
		t.Errorf("BinDir = %q, want /opt/filemaster", config.BinDir)
	}
	if config.DataDir != "/var/lib/filemaster" {
		t.Errorf("DataDir = %q, want /var/lib/filemaster", config.DataDir)
	}
}
