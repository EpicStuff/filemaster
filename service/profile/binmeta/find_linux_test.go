package binmeta

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindIcon(t *testing.T) {
	if testing.Short() {
		t.Skip("test depends on linux desktop environment")
	}
	t.Parallel()

	home := t.TempDir()
	iconDir := filepath.Join(home, ".local/share/icons/hicolor/48x48/apps")
	if err := os.MkdirAll(iconDir, 0o700); err != nil {
		t.Fatalf("create icon dir: %s", err)
	}
	for _, name := range []string{"filemaster-test-evolution", "filemaster-test-nextcloud"} {
		if err := os.WriteFile(filepath.Join(iconDir, name+".png"), []byte("png"), 0o600); err != nil {
			t.Fatalf("write icon: %s", err)
		}
		testFindIcon(t, name, home)
	}
}

func testFindIcon(t *testing.T, binName string, homeDir string) {
	t.Helper()

	iconPath, err := searchForIcon(binName, homeDir)
	if err != nil {
		t.Error(err)
		return
	}
	if iconPath == "" {
		t.Errorf("no icon found for %s", binName)
		return
	}
	t.Logf("icon for %s found: %s", binName, iconPath)
}
