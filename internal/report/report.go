// Package report renders the local HTML risk report from a scoring payload.
// The output is a single self-contained HTML file with all CSS and SVG charts
// inlined — no external resources. This is enforced by a CI test that scans
// the rendered output for any http(s):// references.
//
// TODO (LU-4): implement the full HTML template and chart renderer.
package report

import (
	"fmt"
	"os"

	"github.com/Qwentrix/lumen/internal/scoring"
)

// Render writes a self-contained HTML report to outputPath.
// The payload is the result of scoring.Score().
func Render(payload *scoring.ReportPayload, outputPath string) error {
	html := buildHTML(payload)

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(html)
	return err
}

// buildHTML produces the HTML string for the report.
// TODO (LU-4): replace with a proper go:embed template + SVG chart renderer.
func buildHTML(payload *scoring.ReportPayload) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lumen Security Report</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; }
    h1   { color: #1a1a2e; }
    .grade { font-size: 3rem; font-weight: 700; }
  </style>
</head>
<body>
  <h1>Lumen Security Report</h1>
  <p>Overall Score: <span class="grade">%d (%s)</span></p>
  <p><em>Full report rendering coming in LU-4.</em></p>
  <p>Learn more: <a href="https://lumen.micelium.com">lumen.micelium.com</a></p>
</body>
</html>`, payload.OverallScore, payload.OverallGrade)
}
