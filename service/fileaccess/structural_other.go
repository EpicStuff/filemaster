//go:build !linux

package fileaccess

import "context"

type structuralBackend struct{}

type structuralLabeller struct{}

func (l *structuralLabeller) beforeOpen(context.Context, *FileEvent) {}

func (fa *FileAccess) startStructuralEnforcement() {}

func (fa *FileAccess) closeStructuralEnforcement() {}
