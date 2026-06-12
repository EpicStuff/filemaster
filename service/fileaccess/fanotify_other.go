//go:build !linux

package fileaccess

type fanotifyHandle struct{}

func (fa *FileAccess) startFanotify() error {
	fa.mgr.Warn("file-access interception not implemented on this platform")
	return nil
}

func (fa *FileAccess) stopFanotify() error {
	return nil
}
