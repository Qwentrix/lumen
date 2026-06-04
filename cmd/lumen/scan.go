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
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/consent"
	"github.com/Qwentrix/lumen/internal/hybrid"
	"github.com/Qwentrix/lumen/internal/keys"
	"github.com/Qwentrix/lumen/internal/manifest"
	"github.com/Qwentrix/lumen/internal/probes/ai_governance"
	"github.com/Qwentrix/lumen/internal/probes/common"
	"github.com/Qwentrix/lumen/internal/probes/compliance"
	"github.com/Qwentrix/lumen/internal/probes/privacy"
	"github.com/Qwentrix/lumen/internal/probes/security_posture"
	"github.com/Qwentrix/lumen/internal/probes/vulnerabilities"
	"github.com/Qwentrix/lumen/internal/report"
	"github.com/Qwentrix/lumen/internal/scoring"
)

func newScanCmd() *cobra.Command {
	var (
		domain          string
		hybridFlag      bool
		hybridServer    string
		insecureServer  bool
		output          string
		industry        string
		companySize     string
		skipConsent     bool
		includePrivacy  bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a local security scan",
		Long: `Scan the local workstation across the five security domains (or a single
domain with --domain) and write a self-contained HTML report.

Zero network calls are made in the default mode. Use --hybrid to upload
structured findings to lumen.micelium.com after reviewing a preview.

Run 'lumen consent' before scanning to review and accept the access manifest.

The privacy probe (~/Documents PII scan) is opt-in and DISABLED by default.
Enable with --include-privacy after reviewing the access manifest.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), domain, hybridFlag, hybridServer, insecureServer, output, industry, companySize, skipConsent, includePrivacy)
		},
	}

	home, _ := os.UserHomeDir()
	defaultOutput := filepath.Join(home, "lumen-report.html")

	cmd.Flags().StringVar(&domain, "domain", "", "Scan a single domain: vulnerabilities, compliance, ai_governance, security_posture, privacy")
	cmd.Flags().BoolVar(&hybridFlag, "hybrid", false, "Upload structured findings to lumen.micelium.com (preview shown before upload; requires explicit y/N confirmation)")
	cmd.Flags().StringVar(&hybridServer, "server", "", "Override the gateway base URL for --hybrid upload (default: https://lumen.micelium.com) (env: LUMEN_SERVER_URL)")
	cmd.Flags().BoolVar(&insecureServer, "insecure-server", false,
		"Allow a non-https:// --server URL (for local testing only; NEVER use in production)")
	cmd.Flags().StringVar(&output, "output", defaultOutput, "Output path for the HTML report")
	cmd.Flags().StringVar(&industry, "industry", "", "Industry vertical for overlay selection (healthcare, financial, technology, …)")
	cmd.Flags().StringVar(&companySize, "company-size", "smb", "Company size bucket: individual, smb, mid, enterprise")
	cmd.Flags().BoolVar(&skipConsent, "skip-consent", false, "Skip the consent gate (for CI/install-time-consent scenarios); prints a prominent warning")
	cmd.Flags().BoolVar(&includePrivacy, "include-privacy", false,
		"Enable the privacy probe: scan ~/Documents for PII (SSN, credit cards). "+
			"OFF by default. Only enable after reviewing the access manifest with 'lumen consent'.")

	return cmd
}

// validateOutputPath sanitises the --output flag value.
//
// Rules enforced:
//  1. The path is cleaned (filepath.Clean) and converted to an absolute path.
//  2. The path must have a ".html" extension (case-sensitive).
//  3. The resolved path must be rooted inside the user's home directory OR
//     the current working directory — ".." traversal that escapes both is
//     rejected to prevent overwriting arbitrary files (e.g. /etc/passwd).
//  4. Symlinks are resolved (filepath.EvalSymlinks on the parent directory when
//     the final component does not yet exist) and the REAL path is re-checked
//     against home/cwd to prevent a symlink pointing outside (e.g.
//     ~/lumen-report.html -> /etc/cron.daily/x). Dangling symlinks (parent
//     exists but target does not) are allowed to fail naturally at os.Create.
//
// Returns the validated absolute path or an error with a descriptive message.
func validateOutputPath(raw string) (string, error) {
	// Step 1: clean and make absolute.
	abs, err := filepath.Abs(filepath.Clean(raw))
	if err != nil {
		return "", fmt.Errorf("--output: cannot resolve path %q: %w", raw, err)
	}

	// Step 2: enforce .html extension (case-sensitive).
	if filepath.Ext(abs) != ".html" {
		return "", fmt.Errorf("--output: path %q must have a .html extension", abs)
	}

	// Step 3a: resolve symlinks to get the real path.
	// If the full path does not exist yet (new report file), try resolving the
	// parent directory so we catch symlinks in the directory components.
	real := abs
	if resolved, resolveErr := filepath.EvalSymlinks(abs); resolveErr == nil {
		// Path exists and all symlinks resolved.
		real = resolved
	} else {
		// Path does not exist yet — resolve the parent directory only.
		// This catches a symlinked directory (e.g. ~/reports -> /tmp/reports).
		parent := filepath.Dir(abs)
		if resolvedParent, parentErr := filepath.EvalSymlinks(parent); parentErr == nil {
			real = filepath.Join(resolvedParent, filepath.Base(abs))
		}
		// If parent resolution also fails (dangling path), keep abs as-is and let
		// os.Create fail naturally later.
	}

	// Step 3b: path must be inside home dir or cwd — checked on the REAL path.
	// Resolve symlinks in home and cwd themselves so the prefix comparison is
	// consistent when home or cwd is under a symlinked directory (e.g. /tmp →
	// /private/tmp on macOS).
	home, errHome := os.UserHomeDir()
	cwd, errCwd := os.Getwd()

	if errHome == nil {
		if resolved, err := filepath.EvalSymlinks(home); err == nil {
			home = resolved
		}
	}
	if errCwd == nil {
		if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
			cwd = resolved
		}
	}

	insideHome := errHome == nil && (real == home || strings.HasPrefix(real, home+string(filepath.Separator)))
	insideCwd := errCwd == nil && (real == cwd || strings.HasPrefix(real, cwd+string(filepath.Separator)))

	if !insideHome && !insideCwd {
		return "", fmt.Errorf(
			"--output: path %q is outside your home directory and current working directory; "+
				"path traversal to arbitrary locations is not allowed",
			abs,
		)
	}

	return abs, nil
}

func runScan(ctx context.Context, domain string, hybridFlag bool, hybridServer string, insecureServer bool, outputPath, industry, companySize string, skipConsent bool, includePrivacy bool) error {
	fmt.Println("Lumen scan starting...")

	// H-4: Reject non-https:// destination unless --insecure-server is set.
	// This check applies before any scanning so we fail fast on misconfiguration.
	if hybridFlag && hybridServer != "" {
		if !strings.HasPrefix(hybridServer, "https://") && !insecureServer {
			return fmt.Errorf(
				"--server %q does not use https://; refusing to upload over a non-TLS connection.\n"+
					"Use --insecure-server to override (for local testing only; NEVER in production).",
				hybridServer,
			)
		}
		if !strings.HasPrefix(hybridServer, "https://") && insecureServer {
			fmt.Fprintln(os.Stderr, "WARNING: --insecure-server is set. Uploading over a non-TLS connection.")
		}
	}

	// C-1: Enforce consent before running any probes.
	// H-2: Load the full consent record here; per-domain gating happens in runDomain.
	var consentRecord *consent.Consent
	if skipConsent {
		fmt.Fprintln(os.Stderr, "WARNING: --skip-consent bypasses the consent gate.")
		fmt.Fprintln(os.Stderr, "WARNING: Ensure 'lumen consent' was already accepted for this installation.")
	} else {
		c, err := consent.Load()
		if err != nil {
			return fmt.Errorf("consent: could not load consent record: %w", err)
		}
		if c == nil {
			return fmt.Errorf("run 'lumen consent' to review and accept the access manifest before scanning")
		}
		anyAccepted := false
		for _, d := range c.Domains {
			if d.Accepted {
				anyAccepted = true
				break
			}
		}
		if !anyAccepted {
			return fmt.Errorf("run 'lumen consent' to review and accept the access manifest before scanning")
		}
		consentRecord = c
	}

	// Validate --output before doing any work.
	validatedPath, err := validateOutputPath(outputPath)
	if err != nil {
		return err
	}
	outputPath = validatedPath

	// Initialise the runtime manifest recorder.
	manifest.Default = manifest.New(Version)

	// Collect probe results for each requested domain.
	results := map[string]*common.ProbeResult{}

	// H-2: Gate each probe on its OWN domain consent rather than the coarse
	// "any domain accepted" check. A probe is skipped (not an error) when its
	// domain is not in the consent record or was explicitly declined.
	// The per-domain gate is bypassed only by --skip-consent.
	isDomainConsented := func(name string) bool {
		if skipConsent {
			return true
		}
		if consentRecord == nil {
			return false
		}
		d, ok := consentRecord.Domains[name]
		return ok && d != nil && d.Accepted
	}

	runDomain := func(name string, fn func(context.Context) (*common.ProbeResult, error)) error {
		if domain != "" && domain != name {
			return nil
		}
		// Per-domain consent gate (H-2).
		if !isDomainConsented(name) {
			fmt.Fprintf(os.Stderr, "NOTE: domain %q not consented — skipping probe (run 'lumen consent' to accept).\n", name)
			return nil
		}
		r, err := fn(ctx)
		if err != nil {
			return fmt.Errorf("probe %s: %w", name, err)
		}
		results[name] = r
		return nil
	}

	// Privacy probe: use RunWithPrivacy when --include-privacy is set; otherwise
	// use the default no-op Run that emits zero counts and "disabled" metadata.
	//
	// --include-privacy additionally requires the privacy domain to have been
	// explicitly consented (enforced by the per-domain isDomainConsented check
	// inside runDomain). The ~/Documents PII scan is materially more sensitive
	// than the standard probes and must not run on a blanket consent record alone.
	privacyFn := privacy.Run
	if includePrivacy {
		if !skipConsent && !isDomainConsented("privacy") {
			return fmt.Errorf(
				"--include-privacy requires explicit consent to the 'privacy' domain.\n" +
					"Run 'lumen consent' and accept the privacy domain to enable PII scanning.")
		}
		fmt.Fprintln(os.Stderr, "NOTE: --include-privacy enabled. ~/Documents will be scanned for PII patterns.")
		fmt.Fprintln(os.Stderr, "NOTE: Only match counts are recorded. No filenames or matched content are stored.")
		privacyFn = privacy.RunWithPrivacy
	}

	probes := []struct {
		name string
		fn   func(context.Context) (*common.ProbeResult, error)
	}{
		{"vulnerabilities", vulnerabilities.Run},
		{"compliance", compliance.Run},
		{"ai_governance", ai_governance.Run},
		{"security_posture", security_posture.Run},
		{"privacy", privacyFn},
	}

	for _, p := range probes {
		if err := runDomain(p.name, p.fn); err != nil {
			return err
		}
	}

	// Write the runtime manifest.
	manifestPath := manifest.DefaultManifestPath()
	if err := manifest.Default.Write(manifestPath); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write manifest: %v\n", err)
	} else {
		fmt.Printf("Access manifest written to: %s\n", manifestPath)
	}

	// C-2/M-3: Build ScannerFindings ONCE and reuse for both local scoring and
	// the hybrid upload payload. This eliminates the previous double-build (where
	// ScoreScan internally called buildScannerFindings again, producing a second
	// independent map from the same results). Using ScoreScanWithFindings with the
	// pre-built struct guarantees score-parity: the server receives the exact same
	// ScannerFindings that produced the local score.
	scannerFindings := scoring.BuildScannerFindings(results)

	// Score results using the pre-built ScannerFindings (single build, score-parity guaranteed).
	payload, err := scoring.ScoreScanWithFindings(scannerFindings, industry, companySize)
	if err != nil {
		return fmt.Errorf("scoring: %w", err)
	}

	// Cache the scored payload for `lumen report` to consume.
	if err := cachePayload(payload); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not cache scan payload: %v\n", err)
	}

	// Render report.
	if err := report.Render(payload, outputPath); err != nil {
		return fmt.Errorf("render: %w", err)
	}

	fmt.Printf("Report written to: %s\n", outputPath)
	fmt.Printf("Overall score: %d (%s)\n", payload.OverallScore, payload.OverallGrade)

	// L-4: Resolve hybrid server URL with priority: --server flag > LUMEN_SERVER_URL
	// env var > hardcoded default. The comment in hybrid/upload.go claimed this
	// env-var override existed but no code read it; implemented here.
	if hybridServer == "" {
		if envURL := os.Getenv("LUMEN_SERVER_URL"); envURL != "" {
			hybridServer = envURL
		}
		// If still empty, Upload() will fall through to DefaultGatewayBaseURL.
	}

	// --hybrid upload path.
	// This is one of exactly two networked code paths in the lumen binary.
	// It is gated behind the explicit --hybrid flag AND interactive confirmation.
	// Probe Run() functions never reach this code. The netcheck gate stays green.
	if hybridFlag {
		uploadErr := doHybridUpload(ctx, *scannerFindings, industry, companySize, hybridServer)
		if uploadErr == hybrid.ErrAborted {
			fmt.Fprintln(os.Stderr, "Hybrid upload cancelled.")
		} else if uploadErr != nil {
			return fmt.Errorf("hybrid upload: %w", uploadErr)
		}
	}

	return nil
}

// doHybridUpload implements the full --hybrid upload flow:
//
//  1. Load the install keypair from ~/.lumen/install.key.
//  2. Build an UploadPayload from the exact ScannerFindings that were fed into
//     the scoring engine (score-parity guarantee: the server runs the same
//     shared lumen-scoring engine on the same struct → same score).
//  3. Sign the canonical JSON body with the install private key.
//  4. Preview the EXACT signed JSON and prompt for explicit y/N confirmation.
//  5. On confirmation, POST to the gateway and print assessment_id + summary_url.
//
// Trust model (ENT-109 §7.4): the signature proves payload integrity and
// tamper-evidence. It is NOT an identity-authentication mechanism. The public
// key travels in the payload body. No install-key registration server-side v1.
//
// NETWORK NOTE: this function is the ONLY networked code path triggered by
// --hybrid. Probe Run() functions do not reach this code. netcheck stays green.
func doHybridUpload(ctx context.Context, sf lstypes.ScannerFindings, industry, companySize, serverBase string) error {
	// Step 1: Load the install keypair.
	priv, pub, err := keys.EnsureInstallKey()
	if err != nil {
		return fmt.Errorf("could not load install key (~/.lumen/install.key): %w", err)
	}
	pubHex := hex.EncodeToString(pub)

	// Step 2: Build the upload payload from the exact ScannerFindings.
	// No file paths, no PII values, no hostnames — only integer counts and booleans.
	p := hybrid.BuildPayload(Version, industry, companySize, sf, pubHex)

	// Step 3: Sign the canonical body.
	if err := hybrid.Sign(p, priv); err != nil {
		return fmt.Errorf("sign payload: %w", err)
	}

	// H-4: Resolve the effective destination URL so PreviewAndConfirm shows the
	// REAL URL the user's data will be sent to (not a hardcoded fallback).
	effectiveURL := serverBase
	if effectiveURL == "" {
		effectiveURL = hybrid.DefaultGatewayBaseURL
	}

	// Step 4: Preview the EXACT JSON that will be sent and confirm.
	// Pass the resolved URL so the confirmation message shows the real destination.
	if err := hybrid.PreviewAndConfirm(p, os.Stdout, os.Stdin, effectiveURL); err != nil {
		return err // hybrid.ErrAborted or I/O error
	}

	// Step 5: Upload.
	fmt.Printf("Uploading findings to %s...\n", effectiveURL)
	result, err := hybrid.Upload(ctx, p, serverBase)
	if err != nil {
		return err
	}

	fmt.Printf("Upload successful.\n")
	fmt.Printf("  Assessment ID: %s\n", result.AssessmentID)
	fmt.Printf("  Summary URL:   %s\n", result.SummaryURL)

	return nil
}

// lastScanPath returns the path where the cached scan payload is stored.
func lastScanPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".lumen", "last-scan.json")
}

// cachePayload writes the scored payload to ~/.lumen/last-scan.json for
// `lumen report` to re-render without re-scanning.
func cachePayload(payload interface{}) error {
	path := lastScanPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
