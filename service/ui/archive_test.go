package ui

import (
	"archive/zip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spkg/zipfs"
)

// writeArchive builds a zip on disk with the given entry names and returns its
// path. Entry names are used verbatim so tests can reproduce the exact archive
// layouts the packaging step can produce.
func writeArchive(t *testing.T, entries map[string]string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "module.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	defer file.Close()

	archive := zip.NewWriter(file)
	for name, content := range entries {
		entry, err := archive.Create(name)
		if err != nil {
			t.Fatalf("create entry %q: %v", name, err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatalf("write entry %q: %v", name, err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return path
}

func serveFromArchive(t *testing.T, archivePath, request string) *httptest.ResponseRecorder {
	t.Helper()

	archiveFS, err := zipfs.New(archivePath)
	if err != nil {
		t.Fatalf("open archive with zipfs: %v", err)
	}
	recorder := httptest.NewRecorder()
	ServeFileFromArchive(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "filemaster", archiveFS, request)
	return recorder
}

// The desktop app loads the UI module by opening index.html out of the packaged
// archive through zipfs. Archives are built by the packaging step, so the entry
// name it writes is what decides whether the installed app can start at all.
func TestServeFileFromArchiveServesTopLevelIndex(t *testing.T) {
	archive := writeArchive(t, map[string]string{
		"index.html": `<!doctype html><base href="/ui/modules/filemaster/">`,
	})

	recorder := serveFromArchive(t, archive, "index.html")
	if recorder.Code != http.StatusOK {
		t.Fatalf("serving index.html returned %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); body == "" {
		t.Fatal("served index.html was empty")
	}
}

// An archiver invoked as `tar -cf archive.zip .` stores entries as "./index.html".
// zipfs resolves names literally, so the desktop then reports
// "Open index.html: file does not exist" and never renders. Packaging must
// produce exact top-level names.
func TestServeFileFromArchiveRejectsDotPrefixedIndex(t *testing.T) {
	archive := writeArchive(t, map[string]string{
		"./index.html": `<!doctype html><base href="/ui/modules/filemaster/">`,
	})

	recorder := serveFromArchive(t, archive, "index.html")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("dot-prefixed archive returned %d, want 404 so packaging fails loudly", recorder.Code)
	}
}

// Angular routes are not archive entries; the server falls back to index.html so
// deep links still boot the app shell.
func TestServeFileFromArchiveFallsBackToIndexForRoutes(t *testing.T) {
	archive := writeArchive(t, map[string]string{
		"index.html": `<!doctype html><base href="/ui/modules/filemaster/">`,
	})

	recorder := serveFromArchive(t, archive, "dashboard")
	if recorder.Code != http.StatusOK {
		t.Fatalf("route request returned %d, want 200 via index.html fallback", recorder.Code)
	}
}

// A module archive that has no index.html at all cannot serve the app shell.
func TestServeFileFromArchiveReportsMissingIndex(t *testing.T) {
	archive := writeArchive(t, map[string]string{"app.js": "console.log('not the entry point')"})

	recorder := serveFromArchive(t, archive, "index.html")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("archive without index.html returned %d, want 404", recorder.Code)
	}
}
