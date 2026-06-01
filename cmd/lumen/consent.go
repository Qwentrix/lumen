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
	"github.com/spf13/cobra"

	"github.com/Qwentrix/lumen/internal/consent"
)

// newConsentCmd returns the `lumen consent` subcommand.
// The consent command walks the user through each domain's access manifest
// and stores the result in ~/.lumen/consent.json.
func newConsentCmd() *cobra.Command {
	var (
		reset      bool
		acceptAll  bool
	)

	cmd := &cobra.Command{
		Use:   "consent",
		Short: "Review and accept the per-domain access manifest",
		Long: `Walk through the list of OS APIs and file paths that Lumen will access for
each domain. Consent is stored in ~/.lumen/consent.json. If a future release
adds new access paths, consent is re-requested for the affected domains only.

The install identity key (~/.lumen/install.key) is generated during this step.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return consent.Run(reset, acceptAll)
		},
	}

	cmd.Flags().BoolVar(&reset, "reset", false, "Clear existing consent and start fresh (regenerates install key)")
	cmd.Flags().BoolVar(&acceptAll, "yes", false, "Accept all domains non-interactively (for CI/headless environments)")

	return cmd
}
