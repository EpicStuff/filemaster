package main

import (
	"github.com/safing/portmaster/cmds/cmdbase"
	"github.com/spf13/cobra"
)

func runPlatformSpecifics(cmd *cobra.Command, args []string) {
	if printVersion {
		runFlagCmd(cmdbase.Version, cmd, args)
	}
}
