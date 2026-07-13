//go:build !linux

package core

import (
	"net/http"

	"github.com/safing/portmaster/base/api"
)

// localhostAuthenticator is a stub on non-Linux platforms. The daemon only
// makes sense on Linux (fanotify), so this is only reached in unit tests.
func localhostAuthenticator(_ *http.Request, _ *http.Server) (*api.AuthToken, error) {
	return nil, nil
}
