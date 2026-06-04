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
	"errors"
	"fmt"

	"github.com/Qwentrix/lumen/internal/nvd"
	"github.com/Qwentrix/lumen/internal/rules"
	"github.com/Qwentrix/lumen/internal/update"
	"github.com/spf13/cobra"
)

// newUpdateCmd returns the `lumen update` subcommand.
//
// ENT-108 adds the real network delta path. Two modes:
//
//  1. Offline status (--check / --dry-run / default with --status):
//     Reports the embedded content snapshot status; makes ZERO network calls.
//     This is the legacy behavior and is always safe to run.
//
//  2. Online delta (default, no flag):
//     Fetches the latest signed content bundle from github.com/Qwentrix/lumen-bundles,
//     verifies SHA-256 then ed25519 against the pinned public key, atomically
//     swaps ~/.lumen/content/, and emits a staleness warning if the bundle is
//     older than 30 days.  This is the ONLY networked code path in `lumen update`.
//
// NOTE: `lumen scan` is ZERO-NETWORK.  `lumen update` is explicitly networked
// and is NOT part of the scan surface guarded by internal/netcheck.
func newUpdateCmd() *cobra.Command {
	var dryRun bool
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Fetch and apply the latest signed content bundle, or show offline status",
		Long: `Fetches the latest content bundle (rules + overlays) from the Lumen update
server (github.com/Qwentrix/lumen-bundles), verifies its SHA-256 checksum and
ed25519 signature against the key pinned in this binary, then atomically replaces
~/.lumen/content/.

SECURITY: Signature verification uses the ed25519 public key embedded in this
binary.  A tampered or invalid-signature bundle is rejected with exit code 1 and
the literal error token 'signature_verification_failed'.  The pinned key cannot
be overridden by any flag or environment variable — key rotation requires a new
binary release.

Use --check / --dry-run to see the current content status without making any
network calls.

This command makes outbound HTTPS calls to github.com.  lumen scan is
ZERO-NETWORK and is NOT affected by this command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRun || checkOnly {
				return runUpdateOfflineStatus()
			}
			return runUpdateOnline(cmd)
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show offline content status; no network, no writes")
	cmd.Flags().BoolVar(&checkOnly, "check", false, "Show offline content status; no network, no writes")

	return cmd
}

// runUpdateOfflineStatus prints the status of the embedded content dataset.
// Makes ZERO network calls.
func runUpdateOfflineStatus() error {
	fmt.Println("Lumen embedded content dataset (offline status)")
	fmt.Println("================================================")

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

		// FR-8: staleness warning.
		syncedAt := str(m, "synced_at")
		status := update.CheckStaleness(syncedAt)
		if status.IsStale {
			fmt.Printf("\nWARNING: Content is %d days old (>%d day threshold). Run 'lumen update' to refresh.\n",
				status.DaysOld, update.StalenessDays)
		}
	}

	fmt.Println()
	fmt.Println("This build is self-contained and requires no network access to run.")
	fmt.Println("Run 'lumen update' (without --check) to fetch the latest signed bundle.")
	return nil
}

// runUpdateOnline fetches, verifies, and applies the latest content bundle.
// This is the networked path added in ENT-108. It is the ONLY function in the
// lumen codebase that makes outbound HTTP calls (besides the hybrid uploader).
func runUpdateOnline(cmd *cobra.Command) error {
	ctx := cmd.Context()

	fmt.Println("Fetching content bundle manifest from lumen-bundles...")

	// Fetch manifest.
	m, err := update.FetchManifest(ctx)
	if err != nil {
		return fmt.Errorf("update: fetch manifest: %w", err)
	}

	fmt.Printf("Bundle manifest: %d rules, %d overlays, generated %s\n",
		m.RuleCount, m.OverlayCount, m.GeneratedAt)

	// Fetch bundle bytes.
	fmt.Println("Downloading bundle...")
	bundleBytes, err := update.FetchBundle(ctx, m)
	if err != nil {
		return fmt.Errorf("update: fetch bundle: %w", err)
	}
	fmt.Printf("Downloaded %d bytes\n", len(bundleBytes))

	// Verify SHA-256 + ed25519 signature.
	fmt.Println("Verifying bundle integrity and signature...")
	if err := update.VerifyBundle(m, bundleBytes); err != nil {
		// Propagate the signature_verification_failed token.
		if errors.Is(err, update.ErrSignatureVerificationFailed) {
			fmt.Fprintln(cmd.ErrOrStderr(), "ERROR: signature_verification_failed — bundle rejected. Do NOT apply.")
		}
		return err
	}
	fmt.Println("Signature verified OK.")

	// Atomically apply.
	fmt.Println("Applying bundle to ~/.lumen/content/...")
	result, err := update.Apply(m, bundleBytes)
	if err != nil {
		return fmt.Errorf("update: apply: %w", err)
	}

	fmt.Printf("Applied: %d rules, %d overlays → %s\n",
		result.RuleCount, result.OverlayCount, result.ContentDir)

	// FR-8: staleness warning for the just-applied bundle.
	status := update.CheckStaleness("")
	if status.IsStale {
		fmt.Printf("\nWARNING: The applied bundle is %d days old (>%d day threshold). "+
			"Check for a newer release.\n", status.DaysOld, update.StalenessDays)
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
