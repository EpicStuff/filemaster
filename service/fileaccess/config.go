package fileaccess

import (
	"fmt"

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

// Pipeline limits intentionally require restart. The queue and worker count
// own goroutines and buffered ownership; replacing either live would make the
// configured value disagree with the active enforcement limits.
const (
	CfgOptionDecisionWorkersKey       = "fileaccess/decisionWorkers"
	CfgOptionDecisionQueueCapacityKey = "fileaccess/decisionQueueCapacity"
	CfgOptionOutstandingLimitKey      = "fileaccess/outstandingEventLimit"
	CfgOptionProfileAskLimitKey       = "fileaccess/perProfileAskLimit"
)

const (
	cfgOptionWatchPathsOrder      = 10
	cfgOptionDecisionWorkersOrder = 20
	cfgOptionDecisionQueueOrder   = 30
	cfgOptionOutstandingOrder     = 40
	cfgOptionProfileAskOrder      = 50
	cfgOptionInterceptReadsOrder  = 60
)

var (
	cfgOptionWatchPaths      config.StringArrayOption
	cfgOptionInterceptReads  config.BoolOption
	cfgOptionDecisionWorkers config.IntOption
	cfgOptionDecisionQueue   config.IntOption
	cfgOptionOutstanding     config.IntOption
	cfgOptionProfileAsk      config.IntOption
)

const (
	minimumDecisionWorkers       = 1
	maximumDecisionWorkers       = 64
	minimumDecisionQueueCapacity = 1
	maximumDecisionQueueCapacity = 4096
	minimumOutstandingLimit      = 1
	maximumOutstandingLimit      = 65536
	minimumProfileAskLimit       = 1
	maximumProfileAskLimit       = 1024
)

func validateIntRange(name string, minimum, maximum int64) func(interface{}) error {
	return func(value interface{}) error {
		actual, ok := value.(int64)
		if !ok {
			return fmt.Errorf("%s must be an integer", name)
		}
		if actual < minimum || actual > maximum {
			return fmt.Errorf("%s must be between %d and %d", name, minimum, maximum)
		}
		return nil
	}
}

// configuredDecisionPipelineConfig returns the restart-applied pipeline
// configuration. Options are deliberately read only while constructing a new
// pipeline; live mutation would invalidate queue and ownership accounting.
func configuredDecisionPipelineConfig() DecisionPipelineConfig {
	configured := DefaultDecisionPipelineConfig()
	if cfgOptionDecisionWorkers != nil {
		configured.Workers = int(cfgOptionDecisionWorkers())
	}
	if cfgOptionDecisionQueue != nil {
		configured.QueueCapacity = int(cfgOptionDecisionQueue())
	}
	if cfgOptionOutstanding != nil {
		configured.OutstandingLimit = cfgOptionOutstanding()
	}
	if cfgOptionProfileAsk != nil {
		configured.PerProfileAskLimit = int(cfgOptionProfileAsk())
	}
	return configured.normalized()
}

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

	defaults := DefaultDecisionPipelineConfig()
	for _, option := range []struct {
		name         string
		key          string
		description  string
		order        int
		defaultValue int64
		minimum      int64
		maximum      int64
	}{
		{"Decision Workers", CfgOptionDecisionWorkersKey, "Number of bounded decision workers. This setting requires a service restart so active ownership and worker accounting remain consistent.", cfgOptionDecisionWorkersOrder, int64(defaults.Workers), minimumDecisionWorkers, maximumDecisionWorkers},
		{"Decision Queue Capacity", CfgOptionDecisionQueueCapacityKey, "Maximum permission events waiting for a decision. Full queues deny new events. This setting requires a service restart.", cfgOptionDecisionQueueOrder, int64(defaults.QueueCapacity), minimumDecisionQueueCapacity, maximumDecisionQueueCapacity},
		{"Outstanding Event Limit", CfgOptionOutstandingLimitKey, "Maximum accounted fanotify event descriptors. It is capped by the process descriptor limit after Filemaster reserves headroom. This setting requires a service restart.", cfgOptionOutstandingOrder, defaults.OutstandingLimit, minimumOutstandingLimit, maximumOutstandingLimit},
		{"Per Profile Pending Ask Limit", CfgOptionProfileAskLimitKey, "Maximum permission events one profile may hold in prompts. Additional Ask decisions are denied. This setting requires a service restart.", cfgOptionProfileAskOrder, int64(defaults.PerProfileAskLimit), minimumProfileAskLimit, maximumProfileAskLimit},
	} {
		err = config.Register(&config.Option{
			Name:            option.name,
			Key:             option.key,
			Description:     option.description,
			OptType:         config.OptTypeInt,
			RequiresRestart: true,
			DefaultValue:    option.defaultValue,
			ValidationFunc:  validateIntRange(option.name, option.minimum, option.maximum),
			Annotations: config.Annotations{
				config.DisplayOrderAnnotation: option.order,
				config.CategoryAnnotation:     "File Access",
			},
		})
		if err != nil {
			return err
		}
	}
	cfgOptionDecisionWorkers = config.Concurrent.GetAsInt(CfgOptionDecisionWorkersKey, int64(defaults.Workers))
	cfgOptionDecisionQueue = config.Concurrent.GetAsInt(CfgOptionDecisionQueueCapacityKey, int64(defaults.QueueCapacity))
	cfgOptionOutstanding = config.Concurrent.GetAsInt(CfgOptionOutstandingLimitKey, defaults.OutstandingLimit)
	cfgOptionProfileAsk = config.Concurrent.GetAsInt(CfgOptionProfileAskLimitKey, int64(defaults.PerProfileAskLimit))

	err = config.Register(&config.Option{
		Name:         "Intercept Read Syscalls",
		Key:          CfgOptionInterceptReadsKey,
		Description:  "Also intercept read() syscalls, including directory reads such as readdir(), against watched paths. Off by default because FAN_ACCESS_PERM can fire for every read and generate high event volume.",
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
