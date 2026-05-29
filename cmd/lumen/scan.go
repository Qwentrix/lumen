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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Qwentrix/lumen/internal/probes/ai_governance"
	"github.com/Qwentrix/lumen/internal/probes/compliance"
	"github.com/Qwentrix/lumen/internal/probes/privacy"
	"github.com/Qwentrix/lumen/internal/probes/security_posture"
	"github.com/Qwentrix/lumen/internal/probes/vulnerabilities"
	"github.com/Qwentrix/lumen/internal/report"
	"github.com/Qwentrix/lumen/internal/scoring"
)

func newScanCmd() *cobra.Command {
	var (
		domain string
		hybrid bool
		output string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a local security scan",
		Long: `Scan the local workstation across the five security domains (or a single
domain with --domain) and write a self-contained HTML report.

Zero network calls are made in the default mode. Use --hybrid to upload
structured findings to lumen.micelium.com after reviewing a preview.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), domain, hybrid, output)
		},
	}

	home, _ := os.UserHomeDir()
	defaultOutput := filepath.Join(home, "lumen-report.html")

	cmd.Flags().StringVar(&domain, "domain", "", "Scan a single domain: vulnerabilities, compliance, ai_governance, security_posture, privacy")
	cmd.Flags().BoolVar(&hybrid, "hybrid", false, "Upload structured findings to lumen.micelium.com (preview shown before upload)")
	cmd.Flags().StringVar(&output, "output", defaultOutput, "Output path for the HTML report")

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

func runScan(ctx context.Context, domain string, hybrid bool, outputPath string) error {
	fmt.Println("Lumen scan starting...")

	// Validate --output before doing any work.
	validatedPath, err := validateOutputPath(outputPath)
	if err != nil {
		return err
	}
	outputPath = validatedPath

	// Collect probe results for each requested domain.
	results := map[string]interface{}{}

	runDomain := func(name string, fn func(context.Context) (interface{}, error)) error {
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
		fn   func(context.Context) (interface{}, error)
	}{
		{"vulnerabilities", func(c context.Context) (interface{}, error) { return vulnerabilities.Run(c) }},
		{"compliance", func(c context.Context) (interface{}, error) { return compliance.Run(c) }},
		{"ai_governance", func(c context.Context) (interface{}, error) { return ai_governance.Run(c) }},
		{"security_posture", func(c context.Context) (interface{}, error) { return security_posture.Run(c) }},
		{"privacy", func(c context.Context) (interface{}, error) { return privacy.Run(c) }},
	}

	for _, p := range probes {
		if err := runDomain(p.name, p.fn); err != nil {
			return err
		}
	}

	// Score results.
	payload, err := scoring.Score(results)
	if err != nil {
		return fmt.Errorf("scoring: %w", err)
	}

	// Render report.
	if err := report.Render(payload, outputPath); err != nil {
		return fmt.Errorf("render: %w", err)
	}

	fmt.Printf("Report written to: %s\n", outputPath)

	if hybrid {
		fmt.Println("--hybrid: TODO — implement preview + upload in LU-4")
	}

	return nil
}
