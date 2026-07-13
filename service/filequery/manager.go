// Filemaster-specific: consumes the file-access event feed and persists records.
package filequery

import (
	"context"

	"github.com/safing/portmaster/base/log"
)

// Manager drains the feed channel and saves each record to the database.
type Manager struct {
	db   *Database
	feed <-chan FileAccessRecord
}

func newManager(db *Database, feed <-chan FileAccessRecord) *Manager {
	return &Manager{db: db, feed: feed}
}

// Run reads from the feed until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case rec, ok := <-m.feed:
			if !ok {
				return nil
			}
			if err := m.db.Save(ctx, rec); err != nil {
				log.Errorf("filequery: save record: %s", err)
			}
		}
	}
}
