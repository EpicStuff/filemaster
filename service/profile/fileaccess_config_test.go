package profile

import (
	"testing"

	"github.com/safing/portmaster/base/config"
)

// TestFileAccessWriteRulesHidden verifies the current-release rule-list scope:
// the Write list is retained and registered but hidden from the normal UI via
// developer expertise, while Read and Execute stay user-visible. Hiding, not
// removal, keeps the Write storage/plumbing available for the future Write
// engine.
func TestFileAccessWriteRulesHidden(t *testing.T) {
	if err := registerConfiguration(); err != nil {
		t.Fatalf("registerConfiguration: %v", err)
	}

	cases := []struct {
		key            string
		wantExpertise  config.ExpertiseLevel
		hiddenFromUser bool
	}{
		{CfgOptionFileAccessReadRulesKey, config.ExpertiseLevelUser, false},
		{CfgOptionFileAccessWriteRulesKey, config.ExpertiseLevelDeveloper, true},
		{CfgOptionFileAccessExecRulesKey, config.ExpertiseLevelUser, false},
	}
	for _, tc := range cases {
		option, err := config.GetOption(tc.key)
		if err != nil {
			t.Errorf("%s not registered: %v (Write must be retained, not removed)", tc.key, err)
			continue
		}
		if option.ExpertiseLevel != tc.wantExpertise {
			t.Errorf("%s ExpertiseLevel = %d, want %d", tc.key, option.ExpertiseLevel, tc.wantExpertise)
		}
	}
}

// TestGlobalFileAccessRulesWired verifies the accessors the fileaccess decision
// engine uses to stack the global rule lists beneath each profile's own rules
// are wired to their config options: after registration each resolves without
// panicking and returns its registered default (empty). Setting live values
// requires booting the config module, which unit tests here don't do; the
// stacking semantics are covered in service/fileaccess (see
// TestGlobalRulesStackBeneathProfileRules).
func TestGlobalFileAccessRulesWired(t *testing.T) {
	if err := registerConfiguration(); err != nil {
		t.Fatalf("registerConfiguration: %v", err)
	}

	for name, got := range map[string][]string{
		"read":  GlobalFileAccessReadRules(),
		"write": GlobalFileAccessWriteRules(),
		"exec":  GlobalFileAccessExecRules(),
	} {
		if len(got) != 0 {
			t.Errorf("Global %s rules = %v, want empty default", name, got)
		}
	}
}

func TestGlobalFileAccessRulesReturnsIndependentSnapshot(t *testing.T) {
	cfgLock.Lock()
	originalRead := cfgFileAccessReadRules
	originalWrite := cfgFileAccessWriteRules
	originalExec := cfgFileAccessExecRules
	cfgFileAccessReadRules = []string{"+ /read/**"}
	cfgFileAccessWriteRules = []string{"+ /write/**"}
	cfgFileAccessExecRules = []string{"+ /exec/**"}
	cfgLock.Unlock()
	t.Cleanup(func() {
		cfgLock.Lock()
		cfgFileAccessReadRules = originalRead
		cfgFileAccessWriteRules = originalWrite
		cfgFileAccessExecRules = originalExec
		cfgLock.Unlock()
	})

	read, write, exec := GlobalFileAccessRules()
	if len(read) != 1 || read[0] != "+ /read/**" {
		t.Errorf("read rules = %v, want [+ /read/**]", read)
	}
	if len(write) != 1 || write[0] != "+ /write/**" {
		t.Errorf("write rules = %v, want [+ /write/**]", write)
	}
	if len(exec) != 1 || exec[0] != "+ /exec/**" {
		t.Errorf("exec rules = %v, want [+ /exec/**]", exec)
	}

	read[0] = "- /changed"
	write[0] = "- /changed"
	exec[0] = "- /changed"
	againRead, againWrite, againExec := GlobalFileAccessRules()
	if againRead[0] != "+ /read/**" {
		t.Errorf("read snapshot aliases cached rules: got %q", againRead[0])
	}
	if againWrite[0] != "+ /write/**" {
		t.Errorf("write snapshot aliases cached rules: got %q", againWrite[0])
	}
	if againExec[0] != "+ /exec/**" {
		t.Errorf("exec snapshot aliases cached rules: got %q", againExec[0])
	}
}
