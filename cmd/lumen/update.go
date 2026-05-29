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

// newUpdateCmd returns the `lumen update` subcommand.
// The update command downloads a signed rule + NVD bundle from the Lumen
// update server, verifies the ed25519 signature against the key pinned in
// the binary, and atomically swaps ~/.lumen/content/.
func newUpdateCmd() *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download and verify the latest rule and NVD bundle",
		Long: `Fetches the latest signed content bundle from lumen.micelium.com/updates/manifest.json,
verifies the SHA-256 checksum and ed25519 signature against the public key
embedded in the binary, and atomically replaces ~/.lumen/content/.

In v1 this command updates rules and the NVD snapshot only.
Binary self-update is deferred to a future release.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(dryRun)
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Check for updates without applying them")

	return cmd
}

func runUpdate(dryRun bool) error {
	// TODO (LU-4): implement signed bundle pull.
	// - GET https://lumen.micelium.com/updates/manifest.json
	// - Compare bundle_sha256 against current ~/.lumen/content/.sha256
	// - If different: download bundle, verify sha256, verify ed25519 signature
	// - Atomically swap ~/.lumen/content/ via temp dir + rename
	fmt.Println("lumen update: TODO — signed bundle download to be implemented in LU-4")
	if dryRun {
		fmt.Println("--dry-run: would check manifest without writing to disk")
	}
	return nil
}
