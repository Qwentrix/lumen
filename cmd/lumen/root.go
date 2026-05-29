package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "lumen",
		Short: "Lumen — open-source local security scanner",
		Long: `Lumen scans your workstation across five security domains and produces
a self-contained HTML risk report. No data leaves your machine by default.

Learn more: https://lumen.micelium.com
Trust promises: https://lumen.micelium.com/trust`,
		SilenceUsage: true,
	}

	root.AddCommand(
		newScanCmd(),
		newConsentCmd(),
		newUpdateCmd(),
		newVersionCmd(),
	)

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("lumen %s (commit %s, built %s)\n", Version, Commit, BuiltAt)
		},
	}
}
