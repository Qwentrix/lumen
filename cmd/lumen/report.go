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
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"
	"github.com/Qwentrix/lumen/internal/report"
)

// newReportCmd returns the `lumen report` subcommand.
// It reads the cached payload from the last scan and (re-)renders the HTML report.
func newReportCmd() *cobra.Command {
	var output string

	home, _ := os.UserHomeDir()
	defaultOutput := filepath.Join(home, "lumen-report.html")

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Re-render the HTML report from the last scan",
		Long: `Reads the cached scoring payload from the last lumen scan
(~/.lumen/last-scan.json) and re-renders the self-contained HTML report.

If no cached scan exists, run 'lumen scan' first.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(output)
		},
	}

	cmd.Flags().StringVar(&output, "output", defaultOutput, "Output path for the HTML report")
	return cmd
}

func runReport(outputPath string) error {
	// Validate output path.
	validatedPath, err := validateOutputPath(outputPath)
	if err != nil {
		return err
	}
	outputPath = validatedPath

	// Read the cached payload.
	scanPath := lastScanPath()
	data, err := os.ReadFile(scanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no cached scan found at %s — run 'lumen scan' first", scanPath)
		}
		return fmt.Errorf("report: reading cached scan: %w", err)
	}

	var payload lstypes.ReportPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("report: parsing cached scan: %w", err)
	}

	if err := report.Render(&payload, outputPath); err != nil {
		return fmt.Errorf("report: render: %w", err)
	}

	fmt.Printf("Report re-rendered to: %s\n", outputPath)
	return nil
}
