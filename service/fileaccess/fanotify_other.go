//go:build !linux

package fileaccess

import (
	"context"
	"os"
)

func newPlatformSource(log logger) (Source, error) {
	if path := os.Getenv("FM_FAKE_SOCKET"); path != "" {
		return newSocketSource(path, log)
	}
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

func (s *nopSource) SetWatchPaths([]string) error { return nil }
