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

type decisionChartResponse struct {
	Results []decisionChartBucket `json:"results"`
}

type decisionChartBucket struct {
	Timestamp      int64 `json:"timestamp"`
	OpenAllowed    int64 `json:"open_allowed"`
	OpenBlocked    int64 `json:"open_blocked"`
	ExecuteAllowed int64 `json:"execute_allowed"`
	ExecuteBlocked int64 `json:"execute_blocked"`
}

func TestDecisionChartHandlerReturnsCompleteBucketsAndDecisionCounts(t *testing.T) {
	schema, err := orm.GenerateTableSchema("file_events", FileAccessRecord{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := NewInMemory(schema)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC()
	for _, record := range []FileAccessRecord{
		{At: now, Op: "open", Verdict: "allow"},
		{At: now, Op: "open", Verdict: "deny"},
		{At: now, Op: "exec", Verdict: "allow"},
		{At: now, Op: "exec", Verdict: "deny"},
		{At: now, Op: "read", Verdict: "allow"},
		{At: now.Add(-11 * time.Minute), Op: "open", Verdict: "allow"},
	} {
		if err := db.Save(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}

	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/filequery/charts/decisions", nil)
	(&DecisionChartHandler{Database: db}).ServeHTTP(rec, request)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	var response decisionChartResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if got := len(response.Results); got != decisionChartWindowSeconds/decisionChartBucketSeconds {
		t.Fatalf("bucket count = %d, want %d", got, decisionChartWindowSeconds/decisionChartBucketSeconds)
	}

	var openAllowed, openBlocked, executeAllowed, executeBlocked int64
	for i, bucket := range response.Results {
		if i > 0 && bucket.Timestamp-response.Results[i-1].Timestamp != decisionChartBucketSeconds {
			t.Fatalf("bucket interval = %d, want %d", bucket.Timestamp-response.Results[i-1].Timestamp, decisionChartBucketSeconds)
		}
		openAllowed += bucket.OpenAllowed
		openBlocked += bucket.OpenBlocked
		executeAllowed += bucket.ExecuteAllowed
		executeBlocked += bucket.ExecuteBlocked
	}
	if openAllowed != 1 || openBlocked != 1 || executeAllowed != 1 || executeBlocked != 1 {
		t.Fatalf("decision totals = open allow %d, open deny %d, exec allow %d, exec deny %d; want 1 each", openAllowed, openBlocked, executeAllowed, executeBlocked)
	}
}

func TestDecisionChartHandlerRejectsNonGetRequests(t *testing.T) {
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/filequery/charts/decisions", nil)
	(&DecisionChartHandler{}).ServeHTTP(rec, request)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow = %q, want %q", got, http.MethodGet)
	}
}
