// Copyright 2026 Qwentrix Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
		// Version wires the --version / -v flag on the root command.
		// The value is overridden at build time via:
		//   -ldflags "-X main.Version=<tag>"
		// so that both "lumen --version" and "lumen version" print the same string.
		Version:      versionString(),
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

// versionString returns the version line printed by "lumen --version".
// Build-time vars Version, Commit, and BuiltAt are injected via -ldflags in main.go.
func versionString() string {
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, BuiltAt)
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("lumen %s\n", versionString())
		},
	}
}
