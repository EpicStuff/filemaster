//go:build linux

package fileaccess

import (
	"errors"

	"github.com/safing/portmaster/base/api"
)

func registerFileAccessAPI() error {
	return api.RegisterEndpoint(api.Endpoint{
		Name:        "File Access Diagnostics",
		Description: "Returns compact fanotify coverage, pipeline, persistence, shutdown, and rollout diagnostics without sensitive descriptor identities.",
		Path:        "fileaccess/diagnostics",
		Read:        api.PermitUser,
		StructFunc: func(*api.Request) (any, error) {
			if module == nil {
				return nil, errors.New("fileaccess module is not initialized")
			}
			return module.Diagnostics(), nil
		},
	})
}
