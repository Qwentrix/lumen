package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

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

func runScan(ctx context.Context, domain string, hybrid bool, outputPath string) error {
	fmt.Println("Lumen scan starting...")

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
