package filequery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/safing/portmaster/service/filequery/orm"
)

type mountActivityResponse struct {
	Results []mountActivity `json:"results"`
}

type mountActivity struct {
	MountID        int64  `json:"mount_id"`
	MountPath      string `json:"mount_path"`
	LastActivityAt string `json:"last_activity_at"`
	OpenAllowed    int64  `json:"open_allowed"`
	OpenBlocked    int64  `json:"open_blocked"`
	ExecuteAllowed int64  `json:"execute_allowed"`
	ExecuteBlocked int64  `json:"execute_blocked"`
}

func TestMountActivityHandlerReturnsPerMountCountsAndLatestActivity(t *testing.T) {
	schema, err := orm.GenerateTableSchema("file_events", FileAccessRecord{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := NewInMemory(schema)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	for _, record := range []FileAccessRecord{
		{At: now.Add(-2 * time.Minute), MountID: 2, MountPath: "/home", Op: "open", Verdict: "allow"},
		{At: now, MountID: 2, MountPath: "/home", Op: "exec", Verdict: "deny"},
		{At: now.Add(-time.Minute), MountID: 3, MountPath: "/var", Op: "open", Verdict: "deny"},
		{At: now, Op: "open", Verdict: "allow"},
	} {
		if err := db.Save(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/filequery/mounts/activity", nil)
	(&MountActivityHandler{Database: db}).ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var response mountActivityResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != 2 {
		t.Fatalf("results = %#v, want two known mounts", response.Results)
	}
	if got := response.Results[0]; got.MountID != 2 || got.MountPath != "/home" || got.LastActivityAt == "" || got.OpenAllowed != 1 || got.ExecuteBlocked != 1 {
		t.Fatalf("first result = %#v, want latest /home aggregate", got)
	}
	if got := response.Results[1]; got.MountID != 3 || got.MountPath != "/var" || got.OpenBlocked != 1 {
		t.Fatalf("second result = %#v, want /var aggregate", got)
	}
}

func TestMountActivityHandlerRejectsNonGetRequests(t *testing.T) {
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/filequery/mounts/activity", nil)
	(&MountActivityHandler{}).ServeHTTP(rec, request)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
