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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Qwentrix/lumen/internal/consent"
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
		domain      string
		hybrid      bool
		output      string
		industry    string
		companySize string
		skipConsent bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a local security scan",
		Long: `Scan the local workstation across the five security domains (or a single
domain with --domain) and write a self-contained HTML report.

Zero network calls are made in the default mode. Use --hybrid to upload
structured findings to lumen.micelium.com after reviewing a preview.

Run 'lumen consent' before scanning to review and accept the access manifest.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), domain, hybrid, output, industry, companySize, skipConsent)
		},
	}

	home, _ := os.UserHomeDir()
	defaultOutput := filepath.Join(home, "lumen-report.html")

	cmd.Flags().StringVar(&domain, "domain", "", "Scan a single domain: vulnerabilities, compliance, ai_governance, security_posture, privacy")
	cmd.Flags().BoolVar(&hybrid, "hybrid", false, "Upload structured findings to lumen.micelium.com (preview shown before upload)")
	cmd.Flags().StringVar(&output, "output", defaultOutput, "Output path for the HTML report")
	cmd.Flags().StringVar(&industry, "industry", "", "Industry vertical for overlay selection (healthcare, financial, technology, …)")
	cmd.Flags().StringVar(&companySize, "company-size", "smb", "Company size bucket: individual, smb, mid, enterprise")
	cmd.Flags().BoolVar(&skipConsent, "skip-consent", false, "Skip the consent gate (for CI/install-time-consent scenarios); prints a prominent warning")

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

	// Step 3: path must be inside home dir or cwd.
	home, errHome := os.UserHomeDir()
	cwd, errCwd := os.Getwd()

	insideHome := errHome == nil && (abs == home || strings.HasPrefix(abs, home+string(filepath.Separator)))
	insideCwd := errCwd == nil && (abs == cwd || strings.HasPrefix(abs, cwd+string(filepath.Separator)))

	if !insideHome && !insideCwd {
		return "", fmt.Errorf(
			"--output: path %q is outside your home directory and current working directory; "+
				"path traversal to arbitrary locations is not allowed",
			abs,
		)
	}

	return abs, nil
}

func runScan(ctx context.Context, domain string, hybrid bool, outputPath, industry, companySize string, skipConsent bool) error {
	fmt.Println("Lumen scan starting...")

	// C-1: Enforce consent before running any probes.
	// Load the stored consent record; abort if absent or not accepted.
	if skipConsent {
		// --skip-consent is intended for CI pipelines where consent was
		// accepted at install time. Print a prominent warning so operators
		// are aware the gate is bypassed.
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
		// Verify at least one domain was actually accepted.
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

	runDomain := func(name string, fn func(context.Context) (*common.ProbeResult, error)) error {
		if domain != "" && domain != name {
			return nil
		}
		r, err := fn(ctx)
		if err != nil {
			return fmt.Errorf("probe %s: %w", name, err)
		}
		results[name] = r
		return nil
	}

	probes := []struct {
		name string
		fn   func(context.Context) (*common.ProbeResult, error)
	}{
		{"vulnerabilities", vulnerabilities.Run},
		{"compliance", compliance.Run},
		{"ai_governance", ai_governance.Run},
		{"security_posture", security_posture.Run},
		{"privacy", privacy.Run},
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

	// Score results using the real lumen-scoring engine.
	payload, err := scoring.ScoreScan(results, industry, companySize)
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

	if hybrid {
		fmt.Println("--hybrid: TODO — implement preview + upload in LU-5")
	}

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
