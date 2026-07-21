// Filemaster-specific: verifies the Phase 2.5 mount_id / mount_path migration
// (docs/backend-todo-plan.md) — the columns are added to EXISTING databases via
// ALTER TABLE (not just fresh CREATEs), existing rows backfill to unknown
// (0 / ""), and new records round-trip their mount attribution.
package filequery

import (
	"context"
	"testing"
	"time"

	"github.com/safing/portmaster/service/filequery/orm"
)

// oldFileAccessRecord mirrors FileAccessRecord as it existed before the Phase
// 2.5 mount columns were added. Used to build a pre-migration table schema.
type oldFileAccessRecord struct {
	ID      int64     `sqlite:"id,primary,autoincrement"`
	At      time.Time `sqlite:"at,text,time"`
	PID     int32     `sqlite:"pid"`
	Exe     string    `sqlite:"exe"`
	Path    string    `sqlite:"path"`
	Op      string    `sqlite:"op"`
	Verdict string    `sqlite:"verdict"`
	Profile string    `sqlite:"profile"`
	AppName string    `sqlite:"app_name"`
}

func fullSchema(t *testing.T) *orm.TableSchema {
	t.Helper()
	schema, err := orm.GenerateTableSchema("file_events", FileAccessRecord{})
	if err != nil {
		t.Fatalf("generate full schema: %v", err)
	}
	return schema
}

func columnSet(t *testing.T, db *Database) map[string]struct{} {
	t.Helper()
	cols := make(map[string]struct{})
	var rows []struct {
		Name string `sqlite:"name"`
	}
	if err := db.Execute(context.Background(), "PRAGMA main.table_info(file_events)", orm.WithResult(&rows)); err != nil {
		t.Fatalf("read table_info: %v", err)
	}
	for _, r := range rows {
		cols[r.Name] = struct{}{}
	}
	return cols
}

// TestMigrationAltersExistingTable is the highest-value test: an "old" database
// that predates the mount columns must gain them via ALTER TABLE when a handle
// with the full schema applies migrations, and its pre-existing row must
// backfill to unknown (0 / "").
func TestMigrationAltersExistingTable(t *testing.T) {
	ctx := context.Background()

	// Build the old table (no mount columns) in the shared-cache in-memory db.
	oldSchema, err := orm.GenerateTableSchema("file_events", oldFileAccessRecord{})
	if err != nil {
		t.Fatalf("generate old schema: %v", err)
	}
	oldDB, err := NewInMemory(oldSchema)
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	defer oldDB.Close()

	// Sanity: the old table has no mount columns.
	if cols := columnSet(t, oldDB); hasMountCols(cols) {
		t.Fatalf("old table unexpectedly already has mount columns: %v", cols)
	}

	// Insert a legacy row through the old schema.
	if err := oldDB.Save(ctx, oldFileAccessRecord{
		At:      time.Now(),
		PID:     99,
		Exe:     "/usr/bin/legacy",
		Path:    "/home/user/enc/old.txt",
		Op:      "open",
		Verdict: "allow",
		Profile: "p/1",
		AppName: "Legacy",
	}); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	// Open a second handle over the SAME shared-cache db with the full schema.
	// NewInMemory runs ApplyMigrations -> ensureColumns, which must ALTER the
	// existing table to add mount_id / mount_path.
	fullDB, err := NewInMemory(fullSchema(t))
	if err != nil {
		t.Fatalf("open full db (migrate): %v", err)
	}
	defer fullDB.Close()

	if cols := columnSet(t, fullDB); !hasMountCols(cols) {
		t.Fatalf("after migration, table still missing mount columns: %v", cols)
	}

	// The legacy row must be readable and backfilled to unknown mount.
	var rows []FileAccessRecord
	if err := fullDB.Execute(ctx,
		"SELECT * FROM main.file_events WHERE exe = :exe",
		orm.WithNamedArgs(map[string]any{":exe": "/usr/bin/legacy"}),
		orm.WithResult(&rows),
		orm.WithSchema(*fullDB.Schema),
	); err != nil {
		t.Fatalf("query legacy row: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 legacy row, got %d", len(rows))
	}
	if rows[0].MountID != 0 || rows[0].MountPath != "" {
		t.Fatalf("legacy row mount should backfill to unknown (0, \"\"), got (%d, %q)",
			rows[0].MountID, rows[0].MountPath)
	}
}

// TestFreshSchemaHasMountColumns verifies a brand-new database has the mount
// columns.
func TestFreshSchemaHasMountColumns(t *testing.T) {
	db, err := NewInMemory(fullSchema(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if cols := columnSet(t, db); !hasMountCols(cols) {
		t.Fatalf("fresh table missing mount columns: %v", cols)
	}
}

// TestApplyMigrationsIdempotent verifies re-running migrations does not error
// (columns already present must be skipped).
func TestApplyMigrationsIdempotent(t *testing.T) {
	db, err := NewInMemory(fullSchema(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	for i := 0; i < 3; i++ {
		if err := db.ApplyMigrations(); err != nil {
			t.Fatalf("ApplyMigrations run %d: %v", i, err)
		}
	}
}

// TestMountRoundTrip verifies a record with mount attribution persists and
// reads back with the same MountID/MountPath.
func TestMountRoundTrip(t *testing.T) {
	ctx := context.Background()
	db, err := NewInMemory(fullSchema(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := db.Save(ctx, FileAccessRecord{
		At:        time.Now(),
		PID:       7,
		Exe:       "/usr/bin/cat",
		Path:      "/home/user/enc/secret.txt",
		Op:        "open",
		Verdict:   "allow",
		Profile:   "p/2",
		AppName:   "Cat",
		MountID:   42,
		MountPath: "/home/user/enc",
	}); err != nil {
		t.Fatalf("save record: %v", err)
	}

	var rows []FileAccessRecord
	if err := db.Execute(ctx,
		"SELECT * FROM main.file_events WHERE pid = 7",
		orm.WithResult(&rows),
		orm.WithSchema(*db.Schema),
	); err != nil {
		t.Fatalf("query record: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].MountID != 42 || rows[0].MountPath != "/home/user/enc" {
		t.Fatalf("round-trip mount: expected (42, /home/user/enc), got (%d, %q)",
			rows[0].MountID, rows[0].MountPath)
	}
}

func hasMountCols(cols map[string]struct{}) bool {
	_, id := cols["mount_id"]
	_, path := cols["mount_path"]
	return id && path
}
