package profile

import (
	"github.com/safing/portmaster/base/config"
)

// Configuration Keys.
var (
	cfgStringOptions      = make(map[string]config.StringOption)
	cfgStringArrayOptions = make(map[string]config.StringArrayOption)
	cfgIntOptions         = make(map[string]config.IntOption)
	cfgBoolOptions        = make(map[string]config.BoolOption)
)

// Default action option.
var (
	CfgOptionDefaultActionKey   = "filter/defaultAction"
	cfgOptionDefaultAction      config.StringOption
	cfgOptionDefaultActionOrder = 1

	DefaultActionPermitValue = "permit"
	DefaultActionBlockValue  = "block"
	DefaultActionAskValue    = "ask"
)

// File-access rules option. Each entry is "<verdict> <path-pattern>",
// where verdict is "+" (allow) or "-" (deny) and pattern follows the
// service/fileaccess PathRule syntax.
var (
	CfgOptionFileAccessRulesKey   = "fileaccess/rules"
	cfgOptionFileAccessRules      config.StringArrayOption
	cfgOptionFileAccessRulesOrder = 50
)

func registerConfiguration() error { //nolint:maintidx
	// Default Action -- inherited from the upstream "Default Network
	// Action" option. Filemaster reuses the same key + values so the
	// network-rule UX users coming from Portmaster still applies:
	// permit / block / ask, settable per-app, ask is the default.
	err := config.Register(&config.Option{
		Name:         "Default Action",
		Key:          CfgOptionDefaultActionKey,
		Description:  `Applied when no rule explicitly allows or blocks a file-access request. "ask" prompts the user; "permit" allows; "block" denies.`,
		OptType:      config.OptTypeString,
		DefaultValue: DefaultActionAskValue,
		Annotations: config.Annotations{
			config.SettablePerAppAnnotation: true,
			config.DisplayHintAnnotation:    config.DisplayHintOneOf,
			config.DisplayOrderAnnotation:   cfgOptionDefaultActionOrder,
			config.CategoryAnnotation:       "General",
		},
		PossibleValues: []config.PossibleValue{
			{
				Name:        "Allow",
				Value:       DefaultActionPermitValue,
				Description: "Allow all file access",
			},
			{
				Name:        "Block",
				Value:       DefaultActionBlockValue,
				Description: "Block all file access",
			},
			{
				Name:        "Prompt",
				Value:       DefaultActionAskValue,
				Description: "Prompt for decisions",
			},
		},
	})
	if err != nil {
		return err
	}
	cfgOptionDefaultAction = config.Concurrent.GetAsString(CfgOptionDefaultActionKey, DefaultActionAskValue)
	cfgStringOptions[CfgOptionDefaultActionKey] = cfgOptionDefaultAction

	// File-Access Rules
	err = config.Register(&config.Option{
		Name:         "File Access Rules",
		Key:          CfgOptionFileAccessRulesKey,
		Description:  "Rules governing file-access requests from this application. Each entry is `<+|-> <pattern>`; `+` allows, `-` denies, and `pattern` follows the same syntax as the global file-access rules.",
		Sensitive:    true,
		OptType:      config.OptTypeStringArray,
		DefaultValue: []string{},
		Annotations: config.Annotations{
			config.SettablePerAppAnnotation: true,
			config.StackableAnnotation:      true,
			config.DisplayOrderAnnotation:   cfgOptionFileAccessRulesOrder,
			config.CategoryAnnotation:       "Rules",
			// Render via the +/- rule-list editor in the UI. The
			// hint is a frontend-only string; the value matches
			// ExternalOptionHint.EndpointList in the Angular config
			// types so the same component (app-rule-list) draws our
			// path-rule list with Allow/Block prefix labels.
			config.DisplayHintAnnotation: "endpoint list",
		},
	})
	if err != nil {
		return err
	}
	cfgOptionFileAccessRules = config.Concurrent.GetAsStringArray(CfgOptionFileAccessRulesKey, []string{})
	cfgStringArrayOptions[CfgOptionFileAccessRulesKey] = cfgOptionFileAccessRules

	return nil
}
