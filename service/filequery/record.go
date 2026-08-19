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
	IsDir   bool      `sqlite:"is_dir,integer"`
	Op      string    `sqlite:"op"`
	Verdict string    `sqlite:"verdict"`
	Profile string    `sqlite:"profile"`
	AppName string    `sqlite:"app_name"`

	// MountID / MountPath attribute the record to the protected mount that was
	// active when the decision occurred (backend-todo-plan Phase 2.5). A zero
	// MountID with an empty MountPath means the mount was unknown (attribution
	// unavailable); it is stored explicitly rather than inferred later.
	MountID   int    `sqlite:"mount_id"`
	MountPath string `sqlite:"mount_path"`
}
