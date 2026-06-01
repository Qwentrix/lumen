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

// Package report — html_renderer.go builds the full template data model from
// a ReportPayload and executes the embedded Go template to produce the
// self-contained HTML report.
//
// Design constraints (ENT-106):
//   - ALL CSS is inlined from the embedded style.css — no <link> tags, no CDN.
//   - Charts are inline SVG produced by chart_svg.go — no JS libraries.
//   - The self-contained gate in Render() rejects any output containing
//     http:// or https://, ensuring the report is safe for offline use and
//     will never leak an external network reference.
//   - The template and CSS are compiled into the binary via go:embed in
//     template.go — no runtime file reads.
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"
)

// templateData is the data model passed to the Go HTML template.
// All fields exported; template functions are handled by pre-processing here
// so the template itself remains simple.
type templateData struct {
	// Top-level
	AssessmentID   string
	GeneratedAtFmt string
	Industry       string
	CompanySize    string
	OverallScore   int
	OverallGrade   string
	GradeDesc      string
	ScannerUsed    bool
	FooterMeta     string

	// Inlined CSS (from embedded style.css)
	InlineCSS template.CSS

	// Inline SVG bar chart
	BarChartSVG template.HTML

	// Per-domain
	Domains []domainData

	// What to fix first
	WhatToFixFirst []fixItem

	// Framework summary
	FrameworkSummary []lstypes.FrameworkCoverage
}

type domainData struct {
	DomainID     lstypes.DomainID
	DomainLabel  string
	Score        int
	Grade        string
	GradeColor   string
	PlainSummary string
	Findings     []findingData
	Explain      explainData
}

type findingData struct {
	RuleID           string
	Title            string
	Severity         string
	Contribution     float64
	RemediationPlain string
	Frameworks       []lstypes.FrameworkRef
	MiceliumProducts []string
	TriggeredBy      []string
}

type explainData struct {
	HasSteps    bool
	Formula     string
	Steps       []explainStep
	RawLoss     float64
	CappedLoss  float64
	DomainScore int
}

type explainStep struct {
	FindingID             string
	Title                 string
	Severity              string
	DefaultWeight         float64
	IndustryMultiplier    float64
	SeverityFactor        float64
	EffectiveContribution float64
	TriggeredBy           []string
}

type fixItem struct {
	Priority         int
	RuleID           string
	Title            string
	Domain           lstypes.DomainID
	DomainLabel      string
	RemediationPlain string
	Contribution     float64
	HasMicelium      bool
}

// gradeDescription returns a one-line description for a grade letter.
func gradeDescription(grade string) string {
	switch grade {
	case "A":
		return "Excellent posture"
	case "B":
		return "Good, minor gaps"
	case "C":
		return "Moderate risk"
	case "D":
		return "Significant gaps"
	case "F":
		return "Critical issues"
	default:
		return "Unknown"
	}
}

// domainLabel returns a human-friendly label for a domain ID.
func domainLabel(id lstypes.DomainID) string {
	switch id {
	case lstypes.DomainVulnerabilities:
		return "Vulnerabilities"
	case lstypes.DomainCompliance:
		return "Compliance"
	case lstypes.DomainAIGovernance:
		return "AI Governance"
	case lstypes.DomainSecurityPosture:
		return "Security Posture"
	case lstypes.DomainPrivacy:
		return "Privacy"
	default:
		return string(id)
	}
}

// buildTemplateData converts a *lstypes.ReportPayload into the templateData
// model consumed by the embedded HTML template.
func buildTemplateData(payload *lstypes.ReportPayload) templateData {
	domains := make([]domainData, 0, len(payload.Domains))
	for _, d := range payload.Domains {
		findings := make([]findingData, 0, len(d.Findings))
		for _, f := range d.Findings {
			findings = append(findings, findingData{
				RuleID:           f.RuleID,
				Title:            f.Title,
				Severity:         string(f.Severity),
				Contribution:     f.Contribution,
				RemediationPlain: f.RemediationPlain,
				Frameworks:       f.Frameworks,
				MiceliumProducts: f.MiceliumProducts,
				TriggeredBy:      f.TriggeredBy,
			})
		}

		steps := make([]explainStep, 0, len(d.Explain.Steps))
		for _, s := range d.Explain.Steps {
			steps = append(steps, explainStep{
				FindingID:             s.FindingID,
				Title:                 s.Title,
				Severity:              string(s.Severity),
				DefaultWeight:         s.DefaultWeight,
				IndustryMultiplier:    s.IndustryMultiplier,
				SeverityFactor:        s.SeverityFactor,
				EffectiveContribution: s.EffectiveContribution,
				TriggeredBy:           s.TriggeredBy,
			})
		}

		domains = append(domains, domainData{
			DomainID:     d.DomainID,
			DomainLabel:  domainLabel(d.DomainID),
			Score:        d.Score,
			Grade:        d.Grade,
			GradeColor:   gradeColor(d.Grade),
			PlainSummary: d.PlainSummary,
			Findings:     findings,
			Explain: explainData{
				HasSteps:    len(d.Explain.Steps) > 0,
				Formula:     d.Explain.Formula,
				Steps:       steps,
				RawLoss:     d.Explain.RawLoss,
				CappedLoss:  d.Explain.CappedLoss,
				DomainScore: d.Explain.DomainScore,
			},
		})
	}

	fixes := make([]fixItem, 0, len(payload.WhatToFixFirst))
	for _, r := range payload.WhatToFixFirst {
		// Detect Micelium product alignment for the 1.2× ordered items:
		// find the matching FindingResult to get MiceliumProducts.
		hasMicelium := false
		for _, d := range payload.Domains {
			for _, f := range d.Findings {
				if f.RuleID == r.RuleID && len(f.MiceliumProducts) > 0 {
					hasMicelium = true
				}
			}
		}
		fixes = append(fixes, fixItem{
			Priority:         r.Priority,
			RuleID:           r.RuleID,
			Title:            r.Title,
			Domain:           r.Domain,
			DomainLabel:      domainLabel(r.Domain),
			RemediationPlain: r.RemediationPlain,
			Contribution:     r.Contribution,
			HasMicelium:      hasMicelium,
		})
	}

	footerMeta := fmt.Sprintf("Scanner version: %s", versionForReport())
	if !payload.GeneratedAt.IsZero() {
		footerMeta += fmt.Sprintf(" | Assessed: %s", payload.GeneratedAt.UTC().Format("2006-01-02"))
	}

	return templateData{
		AssessmentID:     payload.AssessmentID,
		GeneratedAtFmt:   payload.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		Industry:         payload.Industry,
		CompanySize:      payload.CompanySize,
		OverallScore:     payload.OverallScore,
		OverallGrade:     payload.OverallGrade,
		GradeDesc:        gradeDescription(payload.OverallGrade),
		ScannerUsed:      payload.ScannerUsed,
		FooterMeta:       footerMeta,
		InlineCSS:        template.CSS(reportCSS),
		BarChartSVG:      template.HTML(renderBarChart(payload.Domains)),
		Domains:          domains,
		WhatToFixFirst:   fixes,
		FrameworkSummary: payload.FrameworkSummary,
	}
}

// versionForReport returns the scanner version string for the report footer.
// It reads from the package-level var injected by scan.go from main.Version,
// with a safe default if not set.
var versionForReport = func() string { return "dev" }

// SetVersionForReport wires the build-time version string into the renderer.
// Called by scan.go at startup so the report footer shows the real version.
func SetVersionForReport(v string) {
	if v != "" {
		versionForReport = func() string { return v }
	}
}

// renderHTML executes the embedded template against payload and returns the
// complete HTML string. The caller (Render) applies the self-contained gate
// before writing to disk.
func renderHTML(payload *lstypes.ReportPayload) (string, error) {
	data := buildTemplateData(payload)

	funcMap := template.FuncMap{
		"len": func(v interface{}) int {
			switch x := v.(type) {
			case []findingData:
				return len(x)
			case []lstypes.FrameworkRef:
				return len(x)
			case []string:
				return len(x)
			}
			return 0
		},
		"printf": fmt.Sprintf,
		"gt": func(a, b int) bool { return a > b },
	}

	tmpl, err := template.New("report").
		Funcs(funcMap).
		Parse(reportTemplateHTML)
	if err != nil {
		return "", fmt.Errorf("report: parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("report: execute template: %w", err)
	}

	html := buf.String()

	// Self-contained gate (defense-in-depth): the CI test report_selfcontained_test.go
	// is the primary gate. This runtime check is a secondary safeguard that prevents
	// a faulty template edit from silently leaking an external resource reference.
	if strings.Contains(html, "http://") || strings.Contains(html, "https://") {
		return "", fmt.Errorf(
			"report: self-contained gate failed: rendered HTML contains an " +
				"external http(s):// reference — template must not include any " +
				"remote resource URLs (CDN, fonts, images). " +
				"Use data: URIs or inline SVG only.",
		)
	}

	return html, nil
}

// GeneratedAt shim: expose for use in time-formatting helpers.
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}
