// Ported from service/netquery/database.go.
// Changes: single SQLite file (no history attachment), generic Save(), removed
// bandwidth/history/cleanup methods and the Conn model (moved to record.go).
package filequery

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/jackc/puddle/v2"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/base/utils"
	"github.com/safing/portmaster/service/filequery/orm"
)

const inMemory = "file:filequery_inmem.db?mode=memory&cache=shared"

type (
	// Database is a SQLite3-backed file-access event store.
	Database struct {
		Schema *orm.TableSchema

		readConnPool *puddle.Pool[*sqlite.Conn]

		l         sync.Mutex
		writeConn *sqlite.Conn
	}

	// BatchExecute bundles one SQL query for ExecuteBatch.
	BatchExecute struct {
		ID     string
		SQL    string
		Params map[string]any
		Result *[]map[string]any
	}
)

// newDatabase opens or creates the fileaccess SQLite database under dataDir.
func newDatabase(dataDir string, schema *orm.TableSchema) (*Database, error) {
	dbDir := filepath.Join(dataDir, "databases")
	if err := utils.EnsureDirectory(dbDir, utils.AdminOnlyExecPermission); err != nil {
		return nil, fmt.Errorf("ensure database dir: %w", err)
	}

	dbFile := filepath.Join(dbDir, "fileaccess.db")
	dbURI := "file:///" + strings.TrimPrefix(filepath.ToSlash(dbFile), "/")

	constructor := func(_ context.Context) (*sqlite.Conn, error) {
		c, err := sqlite.OpenConn(dbURI, sqlite.OpenReadOnly, sqlite.OpenSharedCache, sqlite.OpenURI)
		if err != nil {
			return nil, fmt.Errorf("open read-only sqlite at %s: %w", dbURI, err)
		}
		return c, nil
	}
	destructor := func(c *sqlite.Conn) {
		if err := c.Close(); err != nil {
			log.Errorf("filequery: close pooled sqlite conn: %s", err)
		}
	}
	pool, err := puddle.NewPool(&puddle.Config[*sqlite.Conn]{
		Constructor: constructor,
		Destructor:  destructor,
		MaxSize:     10,
	})
	if err != nil {
		return nil, err
	}

	writeConn, err := sqlite.OpenConn(
		dbURI,
		sqlite.OpenCreate, sqlite.OpenReadWrite, sqlite.OpenWAL,
		sqlite.OpenSharedCache, sqlite.OpenURI,
	)
	if err != nil {
		return nil, fmt.Errorf("open sqlite write conn at %s: %w", dbURI, err)
	}

	return &Database{readConnPool: pool, Schema: schema, writeConn: writeConn}, nil
}

// NewInMemory creates an in-memory database (for testing).
func NewInMemory(schema *orm.TableSchema) (*Database, error) {
	constructor := func(_ context.Context) (*sqlite.Conn, error) {
		c, err := sqlite.OpenConn(inMemory, sqlite.OpenReadOnly, sqlite.OpenSharedCache, sqlite.OpenURI)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	destructor := func(c *sqlite.Conn) { _ = c.Close() }
	pool, err := puddle.NewPool(&puddle.Config[*sqlite.Conn]{
		Constructor: constructor,
		Destructor:  destructor,
		MaxSize:     5,
	})
	if err != nil {
		return nil, err
	}

	writeConn, err := sqlite.OpenConn(
		inMemory,
		sqlite.OpenCreate, sqlite.OpenReadWrite, sqlite.OpenWAL,
		sqlite.OpenSharedCache, sqlite.OpenURI,
	)
	if err != nil {
		return nil, err
	}

	db := &Database{readConnPool: pool, Schema: schema, writeConn: writeConn}
	if err := db.ApplyMigrations(); err != nil {
		return nil, fmt.Errorf("prepare in-memory db: %w", err)
	}
	return db, nil
}

// Close closes all connections.
func (db *Database) Close() error {
	db.readConnPool.Close()
	return db.writeConn.Close()
}

// ApplyMigrations creates the file_events table and indexes if they don't exist.
func (db *Database) ApplyMigrations() error {
	db.l.Lock()
	defer db.l.Unlock()

	sql := db.Schema.CreateStatement("main", true)
	log.Debugf("filequery: applying table schema")
	if err := sqlitex.ExecuteTransient(db.writeConn, sql, nil); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	// CREATE TABLE IF NOT EXISTS never alters an existing table, so databases
	// created before a column was introduced (e.g. the Phase 2.5 mount_id /
	// mount_path columns) must gain it via ALTER TABLE ADD COLUMN.
	if err := db.ensureColumns(); err != nil {
		return err
	}

	indexes := []string{
		`CREATE INDEX IF NOT EXISTS main.filequery_profile_index ON %s (profile)`,
		`CREATE INDEX IF NOT EXISTS main.filequery_exe_index ON %s (exe)`,
		`CREATE INDEX IF NOT EXISTS main.filequery_at_index ON %s (strftime('%%s', at)+0)`,
	}
	for _, idx := range indexes {
		stmt := fmt.Sprintf(idx, db.Schema.Name)
		if err := sqlitex.ExecuteTransient(db.writeConn, stmt, nil); err != nil {
			return fmt.Errorf("create index: %w", err)
		}
	}
	return nil
}

// ensureColumns adds any schema columns missing from an existing file_events
// table. It is idempotent: columns already present are skipped. A NOT NULL
// column is added with a zero-value default so existing rows backfill to the
// column's zero value (for mount attribution that means unknown: 0 / "").
func (db *Database) ensureColumns() error {
	existing := make(map[string]struct{})
	pragma := fmt.Sprintf("PRAGMA main.table_info(%s)", db.Schema.Name)
	err := sqlitex.ExecuteTransient(db.writeConn, pragma, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			existing[stmt.GetText("name")] = struct{}{}
			return nil
		},
	})
	if err != nil {
		return fmt.Errorf("read table columns: %w", err)
	}
	for _, col := range db.Schema.Columns {
		if _, ok := existing[col.Name]; ok {
			continue
		}
		definition := col.Name + " " + sqliteTypeName(col.Type)
		if !col.Nullable {
			definition += " NOT NULL DEFAULT " + sqliteZeroDefault(col.Type)
		}
		alter := fmt.Sprintf("ALTER TABLE main.%s ADD COLUMN %s", db.Schema.Name, definition)
		if err := sqlitex.ExecuteTransient(db.writeConn, alter, nil); err != nil {
			return fmt.Errorf("add column %s: %w", col.Name, err)
		}
	}
	return nil
}

func sqliteTypeName(t sqlite.ColumnType) string {
	switch t {
	case sqlite.TypeInteger:
		return "INTEGER"
	case sqlite.TypeFloat:
		return "REAL"
	case sqlite.TypeText:
		return "TEXT"
	default:
		return "BLOB"
	}
}

func sqliteZeroDefault(t sqlite.ColumnType) string {
	switch t {
	case sqlite.TypeInteger, sqlite.TypeFloat:
		return "0"
	case sqlite.TypeText:
		return "''"
	default:
		return "x''"
	}
}

func (db *Database) withConn(ctx context.Context, fn func(*sqlite.Conn) error) error {
	res, err := db.readConnPool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer res.Release()
	return fn(res.Value())
}

// ExecuteWrite runs sql on the write connection.
func (db *Database) ExecuteWrite(ctx context.Context, sql string, args ...orm.QueryOption) error {
	db.l.Lock()
	defer db.l.Unlock()
	return orm.RunQuery(ctx, db.writeConn, sql, args...)
}

// Execute runs sql on a pooled read-only connection.
func (db *Database) Execute(ctx context.Context, sql string, args ...orm.QueryOption) error {
	return db.withConn(ctx, func(conn *sqlite.Conn) error {
		return orm.RunQuery(ctx, conn, sql, args...)
	})
}

// ExecuteBatch runs multiple queries in one pooled read-only connection.
func (db *Database) ExecuteBatch(ctx context.Context, batches []BatchExecute) error {
	return db.withConn(ctx, func(conn *sqlite.Conn) error {
		merr := new(multierror.Error)
		for _, b := range batches {
			if err := orm.RunQuery(ctx, conn, b.SQL, orm.WithNamedArgs(b.Params), orm.WithResult(b.Result)); err != nil {
				merr.Errors = append(merr.Errors, fmt.Errorf("%s: %w", b.ID, err))
			}
		}
		return merr.ErrorOrNil()
	})
}

// Save inserts record (any struct with sqlite tags) into the main database.
func (db *Database) Save(ctx context.Context, record interface{}) error {
	paramMap, err := orm.ToParamMap(ctx, record, "", orm.DefaultEncodeConfig, []string{"id"})
	if err != nil {
		return fmt.Errorf("encode record: %w", err)
	}

	keys := make([]string, 0, len(paramMap))
	for k := range paramMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	columns := make([]string, 0, len(keys))
	placeholders := make([]string, 0, len(keys))
	values := make(map[string]interface{}, len(keys))
	for _, k := range keys {
		columns = append(columns, k)
		placeholders = append(placeholders, ":"+k)
		values[":"+k] = paramMap[k]
	}

	sql := fmt.Sprintf(
		"INSERT INTO main.%s (%s) VALUES (%s)",
		db.Schema.Name,
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
	)

	db.l.Lock()
	defer db.l.Unlock()
	return orm.RunQuery(ctx, db.writeConn, sql, orm.WithNamedArgs(values), orm.WithTransient())
}
