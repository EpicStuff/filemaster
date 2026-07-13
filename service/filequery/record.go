// Filemaster-specific: defines the file-access event schema stored in SQLite.
package filequery

import "time"

// FileAccessRecord is one row in the file_events table.
type FileAccessRecord struct {
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
