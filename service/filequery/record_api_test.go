package filequery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/safing/portmaster/service/filequery/orm"
)

func TestDirectoryFlagPersistsAndIsReturnedByQueryAPI(t *testing.T) {
	schema, err := orm.GenerateTableSchema("file_events", FileAccessRecord{})
	if err != nil {
		t.Fatalf("generate schema: %v", err)
	}
	db, err := NewInMemory(schema)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := db.Save(context.Background(), FileAccessRecord{
		At:      time.Now(),
		PID:     7,
		Path:    "/tmp/directory",
		IsDir:   true,
		Op:      "open",
		Verdict: "allow",
	}); err != nil {
		t.Fatalf("save record: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/query", bytes.NewBufferString(`{}`))
	resp := httptest.NewRecorder()
	(&QueryHandler{Database: db, IsDevMode: func() bool { return false }}).ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("query status = %d, want %d: %s", resp.Code, http.StatusOK, resp.Body.String())
	}

	var body struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(body.Results))
	}
	if isDir, ok := body.Results[0]["is_dir"].(bool); !ok || !isDir {
		t.Errorf("API is_dir = %#v, want true", body.Results[0]["is_dir"])
	}
}
