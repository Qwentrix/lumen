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

package consent

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Qwentrix/lumen/internal/keys"
	"github.com/Qwentrix/lumen/internal/probes/ai_governance"
	"github.com/Qwentrix/lumen/internal/probes/common"
	"github.com/Qwentrix/lumen/internal/probes/compliance"
	"github.com/Qwentrix/lumen/internal/probes/privacy"
	"github.com/Qwentrix/lumen/internal/probes/security_posture"
	"github.com/Qwentrix/lumen/internal/probes/vulnerabilities"
)

// scannerVersion is the version tag to embed in consent.json.
// Overridden at build time via ldflags by the same mechanism as main.Version.
var scannerVersion = "v0.1.0"

// domainManifests collects the manifest entry from each probe domain.
// The order is deterministic (same as AllDomains) so the consent walkthrough
// always presents domains in the same order.
func domainManifests() []common.ManifestEntry {
	return []common.ManifestEntry{
		vulnerabilities.Manifest(),
		compliance.Manifest(),
		ai_governance.Manifest(),
		security_posture.Manifest(),
		privacy.Manifest(),
	}
}

// manifestHash produces a stable sha256 hash of a manifest entry's declared
// OS APIs and file paths. The inputs are sorted before hashing so that the
// order they appear in the slice does not affect the hash.
//
// Hash algorithm: sha256(json.Marshal(sorted_combined_strings)).
// JSON encoding is canonical for a sorted []string, ensuring determinism
// across platforms and Go versions.
func manifestHash(entry common.ManifestEntry) string {
	combined := append(append([]string{}, entry.OSAPIs...), entry.FilePaths...)
	sort.Strings(combined)
	h := sha256.New()
	data, _ := json.Marshal(combined) // canonical, deterministic encoding
	h.Write(data)
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// isTTY returns true when os.Stdin is an interactive terminal. We check the
// OS-level stat flags rather than importing golang.org/x/term to keep the
// dependency footprint minimal.
func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Run executes the interactive consent walkthrough.
//
//   - If reset is true, the existing consent.json is removed and the user is
//     re-prompted for all domains.
//   - acceptAll skips per-domain prompts and accepts all domains; intended for
//     CI/headless environments when --yes is passed.
//
// Network: none. All operations are local.
func Run(reset bool, acceptAll bool) error {
	// Non-interactive guard: if stdin is not a TTY and --yes is not set, bail.
	if !isTTY() && !acceptAll {
		return fmt.Errorf(
			"consent: stdin is not a terminal and --yes was not passed\n" +
				"  Run `lumen consent --yes` to accept all domains non-interactively (e.g. in CI).",
		)
	}

	if reset {
		fmt.Println("lumen consent: clearing existing consent record…")
		if err := Reset(); err != nil {
			return fmt.Errorf("consent: reset: %w", err)
		}
	}

	// Keygen happens here — consent is the trust gate.
	fmt.Println("\nlumen consent: generating install identity key…")
	_, _, err := keys.EnsureInstallKey()
	if err != nil {
		return fmt.Errorf("consent: keygen: %w", err)
	}
	fingerprint, err := keys.InstallKeyFingerprint()
	if err != nil {
		return fmt.Errorf("consent: key fingerprint: %w", err)
	}
	fmt.Printf("  Install key fingerprint: %s\n", fingerprint)

	// Print the trust promise.
	fmt.Print(`
  Lumen Trust Promise
  ───────────────────
  • Zero outbound network calls during lumen scan (default mode).
  • Read-only access to your system — no files are written except under ~/.lumen/.
  • All data stays on your machine unless you explicitly run lumen scan --hybrid.
  • Full access manifest: lumen.micelium.com/trust

`)

	// Walk each domain manifest.
	manifests := domainManifests()
	reader := bufio.NewReader(os.Stdin)

	consentRecord := &Consent{
		Version:               1,
		AcceptedAt:            time.Now().UTC(),
		ScannerVersion:        scannerVersion,
		InstallKeyFingerprint: fingerprint,
		Domains:               make(map[string]*DomainConsent, len(manifests)),
	}

	for _, entry := range manifests {
		fmt.Printf("  Domain: %s\n", entry.DomainID)

		if len(entry.OSAPIs) > 0 {
			fmt.Println("    OS APIs / commands:")
			for _, api := range entry.OSAPIs {
				fmt.Printf("      • %s\n", api)
			}
		}
		if len(entry.FilePaths) > 0 {
			fmt.Println("    File paths:")
			for _, p := range entry.FilePaths {
				fmt.Printf("      • %s\n", p)
			}
		}
		fmt.Println("    Network: none (default mode)")

		accepted := acceptAll
		if !acceptAll {
			fmt.Printf("  Accept access for %s? [y/N] ", entry.DomainID)
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(strings.ToLower(line))
			accepted = line == "y" || line == "yes"
		} else {
			fmt.Printf("  Accepting %s (--yes)\n", entry.DomainID)
		}

		hash := manifestHash(entry)
		consentRecord.Domains[entry.DomainID] = &DomainConsent{
			Accepted:     accepted,
			ManifestHash: hash,
		}
		fmt.Println()
	}

	if err := Save(consentRecord); err != nil {
		return fmt.Errorf("consent: saving record: %w", err)
	}

	accepted := 0
	for _, d := range consentRecord.Domains {
		if d.Accepted {
			accepted++
		}
	}
	fmt.Printf("lumen consent: saved (%d/%d domains accepted). Key: %s\n",
		accepted, len(consentRecord.Domains), fingerprint)

	return nil
}
