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
	"encoding/json"
	"fmt"

	"github.com/Qwentrix/lumen/internal/nvd"
	"github.com/Qwentrix/lumen/internal/rules"
	"github.com/spf13/cobra"
)

// newUpdateCmd returns the `lumen update` subcommand.
//
// In this release `update` reports the status of the content dataset that is
// embedded in the binary (NVD CVE index + finding rules + industry overlays)
// and makes ZERO network calls — every Lumen build ships fully self-contained
// and works offline. Online delta refresh (pulling a signed rule + NVD bundle
// from the Lumen update server and atomically swapping ~/.lumen/content/) is
// deferred to a future release; see ENT-108 / LU-5.
func newUpdateCmd() *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Show the embedded content dataset status (offline; online refresh arrives in a future release)",
		Long: `Reports the NVD CVE index, finding rules, and industry overlays embedded in
this binary, including when they were generated and synced.

This command makes NO network calls — Lumen ships with a complete embedded
dataset and is fully functional offline. Online delta updates (fetching a
signed content bundle from the Lumen update server, verifying its ed25519
signature, and atomically swapping ~/.lumen/content/) are deferred to a
future release.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(dryRun)
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Alias for the default offline status check (no network, no writes)")

	return cmd
}

// runUpdate prints the status of the embedded content dataset. It performs no
// network I/O and writes nothing to disk, so it is safe under the zero-network
// guarantee enforced by internal/netcheck.
func runUpdate(dryRun bool) error {
	fmt.Println("Lumen embedded content dataset")
	fmt.Println("==============================")

	// NVD CVE index.
	if idx, err := nvd.Load(); err == nil {
		fmt.Printf("NVD CVE index : %d CVEs loaded", idx.Count())
		if m := parseMeta(nvd.Meta()); m != nil {
			fmt.Printf(" (generated %s, CVSS >= %s, %s-month window)",
				str(m, "generated_at"), num(m, "min_cvss"), num(m, "window_months"))
		}
		fmt.Println()
	} else {
		fmt.Printf("NVD CVE index : unavailable (%v)\n", err)
	}

	// Rules + overlays snapshot.
	if m := parseMeta(rules.MetaJSON); m != nil {
		fmt.Printf("Rules         : %s rules, %s overlays (synced %s from %s @ %s)\n",
			num(m, "rule_count"), num(m, "overlay_count"), str(m, "synced_at"),
			str(m, "source_repo"), shortSHA(str(m, "source_sha")))
	}

	fmt.Println()
	fmt.Println("This build is self-contained and requires no network access to run.")
	fmt.Println("Online delta updates (signed bundle refresh) arrive in a future release.")
	if dryRun {
		fmt.Println("(dry run — no changes made)")
	}
	return nil
}

// parseMeta decodes an embedded *.meta.json blob into a generic map. Returns nil
// on any error so callers can degrade gracefully.
func parseMeta(b []byte) map[string]interface{} {
	if len(b) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

func str(m map[string]interface{}, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return "?"
}

// num renders a JSON number (decoded as float64) without a trailing ".0".
func num(m map[string]interface{}, k string) string {
	switch v := m[k].(type) {
	case float64:
		return fmt.Sprintf("%g", v)
	case string:
		return v
	default:
		return "?"
	}
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
