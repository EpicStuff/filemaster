// Filemaster-specific: wires filequery into the module system and exposes the API.
package filequery

import (
	"fmt"

	servertiming "github.com/mitchellh/go-server-timing"

	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/service/filequery/orm"
	"github.com/safing/portmaster/service/mgr"
)

// instance is the minimal slice of the service.Instance that FileQuery needs.
type instance interface {
	DataDir() string
}

// FileQuery is the filequery module.
type FileQuery struct {
	mgr      *mgr.Manager
	instance instance

	db   *Database
	feed chan FileAccessRecord
}

// NewFileQuery creates a new FileQuery module. Call Start() to begin recording.
func NewFileQuery(inst instance) (*FileQuery, error) {
	schema, err := orm.GenerateTableSchema("file_events", FileAccessRecord{})
	if err != nil {
		return nil, fmt.Errorf("generate file_events schema: %w", err)
	}

	db, err := newDatabase(inst.DataDir(), schema)
	if err != nil {
		return nil, fmt.Errorf("open filequery database: %w", err)
	}

	fq := &FileQuery{
		mgr:      mgr.New("filequery"),
		instance: inst,
		db:       db,
		feed:     make(chan FileAccessRecord, 256),
	}

	isDevMode := config.Concurrent.GetAsBool(config.CfgDevModeKey, false)

	queryHandler := servertiming.Middleware(&QueryHandler{
		IsDevMode: isDevMode,
		Database:  db,
	}, nil)
	batchHandler := servertiming.Middleware(&BatchQueryHandler{
		IsDevMode: isDevMode,
		Database:  db,
	}, nil)

	if err := api.RegisterEndpoint(api.Endpoint{
		Name:        "File-Access Query",
		Description: "Query the file-access event history.",
		Path:        "filequery/query",
		Read:        api.PermitSelf,
		HandlerFunc: queryHandler.ServeHTTP,
	}); err != nil {
		return nil, fmt.Errorf("register filequery/query endpoint: %w", err)
	}

	if err := api.RegisterEndpoint(api.Endpoint{
		Name:        "File-Access Batch Query",
		Description: "Run multiple file-access queries in one request.",
		Path:        "filequery/query/batch",
		Read:        api.PermitSelf,
		HandlerFunc: batchHandler.ServeHTTP,
	}); err != nil {
		return nil, fmt.Errorf("register filequery/query/batch endpoint: %w", err)
	}

	return fq, nil
}

// Manager returns the module manager.
func (fq *FileQuery) Manager() *mgr.Manager { return fq.mgr }

// Feed returns a channel to send file-access records for persistence.
func (fq *FileQuery) Feed() chan<- FileAccessRecord { return fq.feed }

// Start applies DB migrations and begins draining the feed channel.
func (fq *FileQuery) Start() error {
	if err := fq.db.ApplyMigrations(); err != nil {
		return fmt.Errorf("filequery migrations: %w", err)
	}

	fq.mgr.Go("feed-consumer", func(w *mgr.WorkerCtx) error {
		m := newManager(fq.db, fq.feed)
		return m.Run(w.Ctx())
	})

	return nil
}

// Stop shuts down the module.
func (fq *FileQuery) Stop() error {
	log.Info("filequery: stopped")
	return nil
}
