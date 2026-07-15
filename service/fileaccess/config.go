package fileaccess

import (
	"github.com/safing/portmaster/base/config"
)

// CfgOptionWatchPathsKey is the global option that controls which
// directories the fanotify source marks. Each entry is an absolute
// directory path. Empty list = nothing watched (the source still
// initializes; it just has no marks to issue).
const CfgOptionWatchPathsKey = "fileaccess/watchPaths"

// CfgOptionInterceptReadsKey toggles FAN_ACCESS_PERM in the fanotify
// mask. Off by default: read events fire per read() syscall and a
// chatty consumer (cat, grep) can produce thousands of prompts before
// a rule is in place. Turn on when you specifically want read-vs-open
// rule granularity.
const CfgOptionInterceptReadsKey = "fileaccess/interceptReads"

const (
	cfgOptionWatchPathsOrder     = 10
	cfgOptionInterceptReadsOrder = 60
)

var (
	cfgOptionWatchPaths     config.StringArrayOption
	cfgOptionInterceptReads config.BoolOption
)

func registerConfig() error {
	err := config.Register(&config.Option{
		Name:         "File Access Watch Paths",
		Key:          CfgOptionWatchPathsKey,
		Description:  "Absolute directory paths whose immediate children fanotify intercepts. Defaults to /home; / enables whole-system monitoring and can disrupt essential services if policies are made restrictive.",
		OptType:      config.OptTypeStringArray,
		DefaultValue: []string{"/home"},
		Annotations: config.Annotations{
			config.DisplayOrderAnnotation: cfgOptionWatchPathsOrder,
			config.CategoryAnnotation:     "File Access",
		},
		// Per-line: any non-empty absolute path. Validation is left
		// permissive; the source surfaces a real error on Start if a
		// path is unmarkable.
		ValidationRegex: `^/$|^/.+$`,
	})
	if err != nil {
		return err
	}
	cfgOptionWatchPaths = config.Concurrent.GetAsStringArray(CfgOptionWatchPathsKey, []string{"/home"})

	err = config.Register(&config.Option{
		Name:         "Intercept Read Syscalls",
		Key:          CfgOptionInterceptReadsKey,
		Description:  "Also intercept read() syscalls against watched files, not just open() and execve(). Off by default because FAN_ACCESS_PERM fires per read syscall and can be very chatty.",
		OptType:      config.OptTypeBool,
		DefaultValue: false,
		Annotations: config.Annotations{
			config.DisplayOrderAnnotation: cfgOptionInterceptReadsOrder,
			config.CategoryAnnotation:     "Other",
		},
	})
	if err != nil {
		return err
	}
	cfgOptionInterceptReads = config.Concurrent.GetAsBool(CfgOptionInterceptReadsKey, false)

	return nil
}
