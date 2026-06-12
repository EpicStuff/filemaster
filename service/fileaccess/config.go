package fileaccess

import (
	"github.com/safing/portmaster/base/config"
)

// CfgOptionWatchPathsKey is the global option that controls which
// directories the fanotify source marks. Each entry is an absolute
// directory path. Empty list = nothing watched (the source still
// initializes; it just has no marks to issue).
const CfgOptionWatchPathsKey = "fileaccess/watchPaths"

const cfgOptionWatchPathsOrder = 10

var cfgOptionWatchPaths config.StringArrayOption

func registerConfig() error {
	err := config.Register(&config.Option{
		Name:         "File Access Watch Paths",
		Key:          CfgOptionWatchPathsKey,
		Description:  "Absolute directory paths whose immediate children fanotify intercepts. Empty = no marks issued at startup.",
		OptType:      config.OptTypeStringArray,
		DefaultValue: []string{},
		Annotations: config.Annotations{
			config.DisplayOrderAnnotation: cfgOptionWatchPathsOrder,
			config.CategoryAnnotation:     "File Access",
		},
		// Per-line: any non-empty absolute path. Validation is left
		// permissive; the source surfaces a real error on Start if a
		// path is unmarkable.
		ValidationRegex: `^/.+$`,
	})
	if err != nil {
		return err
	}
	cfgOptionWatchPaths = config.Concurrent.GetAsStringArray(CfgOptionWatchPathsKey, []string{})
	return nil
}
