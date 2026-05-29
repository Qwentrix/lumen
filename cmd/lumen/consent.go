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

// newConsentCmd returns the `lumen consent` subcommand.
// The consent command walks the user through each domain's access manifest
// and stores the result in ~/.lumen/consent.json.
func newConsentCmd() *cobra.Command {
	var reset bool

	cmd := &cobra.Command{
		Use:   "consent",
		Short: "Review and accept the per-domain access manifest",
		Long: `Walk through the list of OS APIs and file paths that Lumen will access for
each domain. Consent is stored in ~/.lumen/consent.json. If a future release
adds new access paths, consent is re-requested for the affected domains only.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConsent(reset)
		},
	}

	cmd.Flags().BoolVar(&reset, "reset", false, "Clear existing consent and start fresh")

	return cmd
}

func runConsent(reset bool) error {
	// TODO (LU-4): implement interactive consent walkthrough.
	// - Load manifest entries from each probe via Probe.Manifest().
	// - Present each domain's API/path list to the user.
	// - Prompt for per-domain acceptance.
	// - Persist accepted domains to ~/.lumen/consent.json.
	// - If reset=true, delete the existing consent.json first.
	fmt.Println("lumen consent: TODO — interactive walkthrough to be implemented in LU-4")
	if reset {
		fmt.Println("--reset: will clear ~/.lumen/consent.json before prompting")
	}
	return nil
}
