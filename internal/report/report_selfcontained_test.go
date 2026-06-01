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

// Package report — report_selfcontained_test.go is the CI gate for ENT-106.
//
// It renders a fixture ReportPayload and asserts:
//  1. The rendered HTML contains ZERO http:// or https:// references
//     (self-contained gate: no CDN, remote fonts, external images).
//  2. The overall score and grade appear in the rendered output.
//  3. Fired findings (rule IDs) appear in the output.
//  4. The "What to Fix First" section is present.
//  5. Per-domain "Why?" explainability steps are present when supplied.
//  6. Framework citations appear when present in the payload.
//
// This test is the PRIMARY gate for the self-contained requirement.
// The runtime check in renderHTML() is a secondary defense-in-depth layer.
package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"
)

// fixturePayload builds a representative ReportPayload that exercises all
// report sections: multiple domains, findings with frameworks + Micelium
// products, explainability steps, and the "What to Fix First" list.
func fixturePayload() *lstypes.ReportPayload {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)

	complianceFindings := []lstypes.FindingResult{
		{
			RuleID:    "COMP_NO_HOST_FIREWALL",
			Domain:    lstypes.DomainCompliance,
			Title:     "Host firewall disabled on endpoint",
			Severity:  lstypes.SeverityHigh,
			DefaultWeight: 0.6,
			IndustryMultiplier: 1.0,
			SeverityFactor: 0.8,
			Contribution:  0.48,
			TriggeredBy:  []string{"compliance.firewall_enabled"},
			Frameworks: []lstypes.FrameworkRef{
				{ID: "CIS Controls v8 4.5", Text: "Implement and manage a host-based firewall"},
				{ID: "NIST 800-53 SC-7", Text: "Boundary protection"},
			},
			RemediationPlain: "Enable the host-based firewall on all endpoints.",
			MiceliumProducts: []string{"Sovera", "Sense"},
		},
		{
			RuleID:    "COMP_NO_SCREEN_LOCK",
			Domain:    lstypes.DomainCompliance,
			Title:     "Automatic screen lock not configured",
			Severity:  lstypes.SeverityMedium,
			DefaultWeight: 0.4,
			IndustryMultiplier: 1.0,
			SeverityFactor: 0.5,
			Contribution:  0.20,
			TriggeredBy:  []string{"compliance.screen_lock_enabled"},
			Frameworks: []lstypes.FrameworkRef{
				{ID: "HIPAA 164.312(a)(2)(iii)", Text: "Automatic logoff"},
			},
			RemediationPlain: "Configure automatic screen lock after inactivity.",
			MiceliumProducts: []string{"Proof"},
		},
	}

	explainSteps := []lstypes.ExplainStep{
		{
			FindingID:             "COMP_NO_HOST_FIREWALL",
			Title:                 "Host firewall disabled on endpoint",
			Severity:              lstypes.SeverityHigh,
			DefaultWeight:         0.6,
			IndustryMultiplier:    1.0,
			SeverityFactor:        0.8,
			EffectiveContribution: 0.48,
			TriggeredBy:           []string{"compliance.firewall_enabled"},
			Frameworks:            nil,
		},
		{
			FindingID:             "COMP_NO_SCREEN_LOCK",
			Title:                 "Automatic screen lock not configured",
			Severity:              lstypes.SeverityMedium,
			DefaultWeight:         0.4,
			IndustryMultiplier:    1.0,
			SeverityFactor:        0.5,
			EffectiveContribution: 0.20,
			TriggeredBy:           []string{"compliance.screen_lock_enabled"},
			Frameworks:            nil,
		},
	}

	return &lstypes.ReportPayload{
		AssessmentID: "test-assess-001",
		GeneratedAt:  now,
		Industry:     "healthcare",
		CompanySize:  "smb",
		OverallScore: 67,
		OverallGrade: "C",
		ScannerUsed:  true,
		Domains: []lstypes.DomainResult{
			{
				DomainID:     lstypes.DomainVulnerabilities,
				Score:        100,
				Grade:        "A",
				PlainSummary: "No issues detected in vulnerabilities — grade A.",
				Findings:     nil,
				Explain: lstypes.DomainExplain{
					DomainID:    lstypes.DomainVulnerabilities,
					Formula:     "100 * (1 - min(1.0, Σ contributions))",
					Steps:       nil,
					RawLoss:     0,
					CappedLoss:  0,
					DomainScore: 100,
				},
			},
			{
				DomainID:     lstypes.DomainCompliance,
				Score:        32,
				Grade:        "F",
				PlainSummary: "2 issue(s) detected in compliance — grade F.",
				Findings:     complianceFindings,
				Explain: lstypes.DomainExplain{
					DomainID:    lstypes.DomainCompliance,
					Formula:     "100 * (1 - min(1.0, Σ contributions))",
					Steps:       explainSteps,
					RawLoss:     0.68,
					CappedLoss:  0.68,
					DomainScore: 32,
				},
			},
		},
		TopRisks: []lstypes.FindingResult{complianceFindings[0]},
		WhatToFixFirst: []lstypes.Remediation{
			{
				RuleID:           "COMP_NO_HOST_FIREWALL",
				Title:            "Host firewall disabled on endpoint",
				Domain:           lstypes.DomainCompliance,
				Priority:         1,
				RemediationPlain: "Enable the host-based firewall on all endpoints.",
				Contribution:     0.48,
			},
			{
				RuleID:           "COMP_NO_SCREEN_LOCK",
				Title:            "Automatic screen lock not configured",
				Domain:           lstypes.DomainCompliance,
				Priority:         2,
				RemediationPlain: "Configure automatic screen lock after inactivity.",
				Contribution:     0.20,
			},
		},
		FrameworkSummary: []lstypes.FrameworkCoverage{
			{
				FrameworkID: "CIS",
				Controls: []lstypes.FrameworkRef{
					{ID: "CIS Controls v8 4.5", Text: "Implement and manage a host-based firewall"},
				},
			},
			{
				FrameworkID: "HIPAA",
				Controls: []lstypes.FrameworkRef{
					{ID: "HIPAA 164.312(a)(2)(iii)", Text: "Automatic logoff"},
				},
			},
		},
	}
}

// TestSelfContained_NoExternalURLs is the PRIMARY CI gate for ENT-106.
// It asserts the rendered HTML contains ZERO http:// or https:// references.
func TestSelfContained_NoExternalURLs(t *testing.T) {
	payload := fixturePayload()

	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.html")

	if err := Render(payload, outPath); err != nil {
		t.Fatalf("Render() returned unexpected error: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	html := string(raw)

	// PRIMARY GATE: no http(s):// in output
	if strings.Contains(html, "http://") {
		t.Errorf("SELF-CONTAINED GATE FAILED: rendered HTML contains http:// reference.\n" +
			"This means the report will not work offline and may leak an external " +
			"network reference. Every resource (CSS, fonts, images) must be inlined.")
		// Log context around the violation
		idx := strings.Index(html, "http://")
		start := idx - 80
		if start < 0 {
			start = 0
		}
		end := idx + 80
		if end > len(html) {
			end = len(html)
		}
		t.Logf("Context: ...%s...", html[start:end])
	}
	if strings.Contains(html, "https://") {
		t.Errorf("SELF-CONTAINED GATE FAILED: rendered HTML contains https:// reference.\n" +
			"This means the report will not work offline and may leak an external " +
			"network reference. Every resource (CSS, fonts, images) must be inlined.")
		idx := strings.Index(html, "https://")
		start := idx - 80
		if start < 0 {
			start = 0
		}
		end := idx + 80
		if end > len(html) {
			end = len(html)
		}
		t.Logf("Context: ...%s...", html[start:end])
	}
}

// TestReport_ContainsOverallScoreAndGrade asserts the overall score and grade
// are present in the rendered output.
func TestReport_ContainsOverallScoreAndGrade(t *testing.T) {
	payload := fixturePayload()
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.html")

	if err := Render(payload, outPath); err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	raw, _ := os.ReadFile(outPath)
	html := string(raw)

	checks := []struct {
		desc string
		want string
	}{
		{"overall score", "67"},
		{"overall grade C in circle", ">C<"},
		{"grade description", "Moderate risk"},
		{"scanner badge", "SCANNER"},
		{"assessment ID", "test-assess-001"},
	}
	for _, c := range checks {
		if !strings.Contains(html, c.want) {
			t.Errorf("report missing %s: expected to find %q in output", c.desc, c.want)
		}
	}
}

// TestReport_ContainsFindings asserts findings, remediation, and framework
// citations appear in the rendered output.
func TestReport_ContainsFindings(t *testing.T) {
	payload := fixturePayload()
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.html")

	if err := Render(payload, outPath); err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	raw, _ := os.ReadFile(outPath)
	html := string(raw)

	checks := []struct {
		desc string
		want string
	}{
		{"finding COMP_NO_HOST_FIREWALL rule ID", "COMP_NO_HOST_FIREWALL"},
		{"finding COMP_NO_SCREEN_LOCK rule ID", "COMP_NO_SCREEN_LOCK"},
		{"firewall remediation text", "Enable the host-based firewall"},
		{"screen lock remediation text", "Configure automatic screen lock"},
		{"CIS framework citation", "CIS Controls v8 4.5"},
		{"HIPAA framework citation", "HIPAA 164.312(a)(2)(iii)"},
		{"Micelium product Sovera", "Sovera"},
		{"Micelium product Proof", "Proof"},
	}
	for _, c := range checks {
		if !strings.Contains(html, c.want) {
			t.Errorf("report missing %s: expected to find %q in output", c.desc, c.want)
		}
	}
}

// TestReport_ContainsWhatToFixFirst asserts the prioritised remediation section
// is rendered.
func TestReport_ContainsWhatToFixFirst(t *testing.T) {
	payload := fixturePayload()
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.html")

	if err := Render(payload, outPath); err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	raw, _ := os.ReadFile(outPath)
	html := string(raw)

	if !strings.Contains(html, "What to Fix First") {
		t.Error("report missing 'What to Fix First' section")
	}
}

// TestReport_ContainsExplainabilityTrace asserts the "Why?" explain steps
// appear for domains that have them.
func TestReport_ContainsExplainabilityTrace(t *testing.T) {
	payload := fixturePayload()
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.html")

	if err := Render(payload, outPath); err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	raw, _ := os.ReadFile(outPath)
	html := string(raw)

	checks := []struct {
		desc string
		want string
	}{
		{"explain formula", "100 * (1 - min"},
		{"explain step for firewall", "COMP_NO_HOST_FIREWALL"},
		{"explain step contribution value", "0.48"},
		{"why this score label", "Why this score?"},
	}
	for _, c := range checks {
		if !strings.Contains(html, c.want) {
			t.Errorf("report missing explainability %s: expected to find %q in output", c.desc, c.want)
		}
	}
}

// TestReport_BarChartPresent asserts the domain score bar chart SVG is present.
func TestReport_BarChartPresent(t *testing.T) {
	payload := fixturePayload()
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.html")

	if err := Render(payload, outPath); err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	raw, _ := os.ReadFile(outPath)
	html := string(raw)

	if !strings.Contains(html, "<svg") {
		t.Error("report missing SVG bar chart")
	}
	// SVG must NOT use xmlns which would include an http:// namespace URI
	if strings.Contains(html, `xmlns="http://www.w3.org/2000/svg"`) {
		t.Error("SVG uses xmlns http:// attribute — remove it for HTML5 inline SVG")
	}
}

// TestReport_FrameworkSummaryPresent asserts the framework summary section renders.
func TestReport_FrameworkSummaryPresent(t *testing.T) {
	payload := fixturePayload()
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.html")

	if err := Render(payload, outPath); err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	raw, _ := os.ReadFile(outPath)
	html := string(raw)

	if !strings.Contains(html, "Triggered Framework Controls") {
		t.Error("report missing 'Triggered Framework Controls' section")
	}
	if !strings.Contains(html, "HIPAA") {
		t.Error("report missing HIPAA in framework summary")
	}
}

// TestReport_EmptyPayload asserts Render handles a minimal/empty payload without panicking.
func TestReport_EmptyPayload(t *testing.T) {
	payload := &lstypes.ReportPayload{
		AssessmentID: "empty-001",
		GeneratedAt:  time.Now(),
		OverallScore: 100,
		OverallGrade: "A",
		CompanySize:  "individual",
	}
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "report.html")

	if err := Render(payload, outPath); err != nil {
		t.Fatalf("Render() with empty payload error: %v", err)
	}
	raw, _ := os.ReadFile(outPath)
	html := string(raw)

	// Gate still passes on empty payload
	if strings.Contains(html, "http://") || strings.Contains(html, "https://") {
		t.Error("empty payload report still violates self-contained gate")
	}
	if !strings.Contains(html, "100") {
		t.Error("expected score '100' in empty-payload report")
	}
}
