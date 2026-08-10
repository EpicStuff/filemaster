package filequery

import (
	"context"
	"testing"
	"time"

	"github.com/safing/portmaster/service/filequery/orm"
)

func TestCleanupBeforeRemovesOnlyExpiredEventsForProfile(t *testing.T) {
	schema, err := orm.GenerateTableSchema("file_events", FileAccessRecord{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := NewInMemory(schema)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	for _, record := range []FileAccessRecord{
		{At: now.Add(-48 * time.Hour), Profile: "local/expired"},
		{At: now.Add(-2 * time.Hour), Profile: "local/recent"},
		{At: now.Add(-48 * time.Hour), Profile: "local/other"},
	} {
		if err := db.Save(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}

	if err := db.cleanupBefore(context.Background(), "local/expired", now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	var result []FileAccessRecord
	if err := db.Execute(context.Background(), "SELECT * FROM main.file_events ORDER BY profile", orm.WithResult(&result)); err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatalf("event count = %d, want 2", len(result))
	}
	if result[0].Profile != "local/other" || result[1].Profile != "local/recent" {
		t.Fatalf("remaining profiles = %q, %q, want local/other and local/recent", result[0].Profile, result[1].Profile)
	}
}
