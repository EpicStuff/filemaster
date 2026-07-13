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
