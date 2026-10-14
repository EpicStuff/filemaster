//go:build !linux

package fileaccess

type structuralBackend struct{}

func (fa *FileAccess) startStructuralEnforcement() {}

func (fa *FileAccess) closeStructuralEnforcement() {}
