package main

import (
	"github.com/safing/portmaster/cmds/cmdbase"
	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "bpf-teardown",
		Short: "Detach and unpin every Filemaster BPF LSM program",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return bpflsm.Teardown()
		},
	})
}

func runPlatformSpecifics(cmd *cobra.Command, args []string) {
	if printVersion {
		runFlagCmd(cmdbase.Version, cmd, args)
	}
}
