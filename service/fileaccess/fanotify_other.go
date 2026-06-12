//go:build !linux

package fileaccess

import "context"

func newPlatformSource(log logger) (Source, error) {
	return &nopSource{log: log}, nil
}

type nopSource struct {
	log logger
}

func (s *nopSource) Run(ctx context.Context, h Handler) error {
	s.log.Warn("file-access interception not implemented on this platform")
	<-ctx.Done()
	return nil
}

func (s *nopSource) Close() error { return nil }
