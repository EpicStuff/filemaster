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

// File-access rules options. Rules are split by filesystem operation —
// read, write, and execute — mirroring how upstream Portmaster keeps
// separate incoming/outgoing rule lists. Each entry is "<verdict> <pattern>",
// where verdict is "+" (allow) or "-" (deny). The list an entry lives in
// determines the operation it governs; the pattern follows the
// service/fileaccess PathRule syntax.
var (
	CfgOptionFileAccessReadRulesKey  = "fileaccess/readRules"
	CfgOptionFileAccessWriteRulesKey = "fileaccess/writeRules"
	CfgOptionFileAccessExecRulesKey  = "fileaccess/execRules"

	cfgOptionFileAccessReadRules  config.StringArrayOption
	cfgOptionFileAccessWriteRules config.StringArrayOption
	cfgOptionFileAccessExecRules  config.StringArrayOption

	cfgOptionFileAccessReadRulesOrder  = 50
	cfgOptionFileAccessWriteRulesOrder = 51
	cfgOptionFileAccessExecRulesOrder  = 52
)

func registerConfiguration() error { //nolint:maintidx
	// Default Action -- inherited from the upstream "Default Network
	// Action" option. Filemaster reuses the same key + values so the
	// network-rule UX users coming from Portmaster still applies:
	// permit / block / ask, settable per-app, permit is the default.
	err := config.Register(&config.Option{
		Name:         "Default File Access Action",
		Key:          CfgOptionDefaultActionKey,
		Description:  `Applied when no rule explicitly allows or blocks a file-access request. Governs read, write, and execute alike. "ask" prompts the user; "permit" allows; "block" denies.`,
		OptType:      config.OptTypeString,
		DefaultValue: DefaultActionPermitValue,
		Annotations: config.Annotations{
			config.SettablePerAppAnnotation: true,
			config.DisplayHintAnnotation:    config.DisplayHintOneOf,
			config.DisplayOrderAnnotation:   cfgOptionDefaultActionOrder,
			config.CategoryAnnotation:       "File Access",
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
	cfgOptionDefaultAction = config.Concurrent.GetAsString(CfgOptionDefaultActionKey, DefaultActionPermitValue)
	cfgStringOptions[CfgOptionDefaultActionKey] = cfgOptionDefaultAction

	// File-Access Rules, split by operation. One list per operation mirrors
	// upstream Portmaster's separate Incoming/Outgoing rule lists: the list an
	// entry lives in decides which operation it governs, so the pattern stays a
	// plain path/glob with no operation tag. All three render via the same +/-
	// rule-list editor in the UI (the "endpoint list" hint matches
	// ExternalOptionHint.EndpointList in the Angular config types, drawing our
	// path-rule list with Allow/Block prefix labels).
	const ruleSyntax = " Each entry is `<+|-> <pattern>`; `+` allows, `-` denies, and `pattern` is a path or glob."
	fileAccessRuleOptions := []struct {
		name  string
		key   string
		desc  string
		order int
		// hidden marks a list retained internally but not exposed in the normal
		// UI. Write is hidden in the current release: no runtime event populates
		// or consults it (writes need LSM), but its storage and plumbing are kept
		// so the future Write evaluation engine can be built and unit-tested
		// against it before enforcement lands (backend-todo-plan sections 2 and 16).
		hidden bool
		into   *config.StringArrayOption
	}{
		// "Access" (not "Read") because the current backend decides at open time
		// via FAN_OPEN_PERM and cannot tell read from write; the list governs any
		// open of a file or folder (backend-todo-plan sections 2 and 4).
		{"Access Rules", CfgOptionFileAccessReadRulesKey, "Rules governing whether this application may open files and folders — for reading, writing, or both." + ruleSyntax, cfgOptionFileAccessReadRulesOrder, false, &cfgOptionFileAccessReadRules},
		{"Write Rules", CfgOptionFileAccessWriteRulesKey, "Rules governing content changes to files by this application." + ruleSyntax, cfgOptionFileAccessWriteRulesOrder, true, &cfgOptionFileAccessWriteRules},
		// Files and folders share one Execute list, so folder entries are accepted,
		// but folder Execute (traversal) is not enforceable without LSM and has no
		// effect in the current release (backend-todo-plan section 2).
		{"Execute Rules", CfgOptionFileAccessExecRulesKey, "Rules governing whether this application may execute files. Folder entries are accepted but have no effect in the current release." + ruleSyntax, cfgOptionFileAccessExecRulesOrder, false, &cfgOptionFileAccessExecRules},
	}
	for _, opt := range fileAccessRuleOptions {
		// Developer expertise hides the option from the normal and expert UIs
		// while keeping it registered and fully functional -- the idiomatic
		// Portmaster way to retain a setting without surfacing it.
		expertise := config.ExpertiseLevelUser
		if opt.hidden {
			expertise = config.ExpertiseLevelDeveloper
		}
		err = config.Register(&config.Option{
			Name:           opt.name,
			Key:            opt.key,
			Description:    opt.desc,
			Sensitive:      true,
			OptType:        config.OptTypeStringArray,
			ExpertiseLevel: expertise,
			DefaultValue:   []string{},
			Annotations: config.Annotations{
				config.SettablePerAppAnnotation: true,
				config.StackableAnnotation:      true,
				config.DisplayOrderAnnotation:   opt.order,
				config.CategoryAnnotation:       "Rules",
				config.DisplayHintAnnotation:    "endpoint list",
			},
		})
		if err != nil {
			return err
		}
		*opt.into = config.Concurrent.GetAsStringArray(opt.key, []string{})
		cfgStringArrayOptions[opt.key] = *opt.into
	}

	return nil
}
