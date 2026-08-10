// Ported from service/netquery/database.go — adapted from connection history
// to completed file-access events in the single fileaccess database.
package filequery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/service/filequery/orm"
	"github.com/safing/portmaster/service/profile"
)

// CleanupHistory deletes file events outside each profile's retention period.
func (db *Database) CleanupHistory(ctx context.Context) error {
	ctx, tracer := log.AddTracer(ctx)
	defer tracer.Submit()

	var result []struct {
		Profile string `sqlite:"profile"`
	}
	if err := db.Execute(ctx, "SELECT DISTINCT profile FROM main.file_events", orm.WithResult(&result)); err != nil {
		return fmt.Errorf("list file-event history profiles: %w", err)
	}

	globalRetentionDays := profile.FileEventHistoryRetentionDays()
	profileCnt := 0
	merr := new(multierror.Error)
	for _, row := range result {
		profileName := row.Profile
		retentionDays := globalRetentionDays
		id := strings.TrimPrefix(row.Profile, string(profile.SourceLocal)+"/")
		if p, err := profile.GetLocalProfile(id, nil, nil); err == nil {
			profileName = p.String()
			retentionDays = p.EffectiveFileEventHistoryRetentionDays()
		} else {
			tracer.Errorf("filequery: failed to load profile %s for history cleanup: %s", id, err)
		}

		if retentionDays <= 0 {
			if retentionDays < 0 {
				tracer.Warningf("filequery: invalid negative retention for %s, skipping cleanup", profileName)
			}
			tracer.Tracef("filequery: retention disabled for %s, skipping", profileName)
			continue
		}
		profileCnt++

		threshold := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
		if err := db.cleanupBefore(ctx, row.Profile, threshold); err != nil {
			tracer.Warningf("filequery: failed to delete old events for %s: %s", profileName, err)
			merr.Errors = append(merr.Errors, fmt.Errorf("profile %s: %w", row.Profile, err))
			continue
		}
		tracer.Debugf("filequery: deleted events older than %d days (before %s) for %s", retentionDays, threshold.Format(time.RFC822), profileName)
	}

	tracer.Infof("filequery: applied history retention to %d profiles", profileCnt)
	return merr.ErrorOrNil()
}

func (db *Database) cleanupBefore(ctx context.Context, profileID string, threshold time.Time) error {
	return db.ExecuteWrite(ctx,
		"DELETE FROM main.file_events WHERE profile = :profile AND datetime(at) < datetime(:threshold)",
		orm.WithNamedArgs(map[string]any{
			":profile":   profileID,
			":threshold": threshold.Format(orm.SqliteTimeFormat),
		}),
	)
}
