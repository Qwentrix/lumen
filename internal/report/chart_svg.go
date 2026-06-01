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

// Package report — chart_svg.go renders per-domain scores as an inline SVG
// horizontal bar chart. No external libraries, no CDN, no JS — pure SVG strings.
package report

import (
	"fmt"
	"strings"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"
)

// gradeColor returns a fill colour for a score bar based on grade.
func gradeColor(grade string) string {
	switch grade {
	case "A":
		return "#48bb78"
	case "B":
		return "#68d391"
	case "C":
		return "#f6e05e"
	case "D":
		return "#f6ad55"
	case "F":
		return "#fc8181"
	default:
		return "#90cdf4"
	}
}

// domainShortName returns a display-friendly short name for a domain.
func domainShortName(id lstypes.DomainID) string {
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

// renderBarChart produces a self-contained inline SVG horizontal bar chart
// showing each domain's score (0–100). All drawing uses SVG primitives only.
//
// Returns an empty string if domains is empty.
//
// IMPORTANT: this function must NEVER emit any http(s):// URL — the self-contained
// gate in Render() will reject the output if it does.
func renderBarChart(domains []lstypes.DomainResult) string {
	if len(domains) == 0 {
		return ""
	}

	const (
		svgWidth   = 680
		barHeight  = 28
		barGap     = 14
		labelWidth = 160
		barMaxW    = svgWidth - labelWidth - 80 // 80 = score label + margin
		marginTop  = 10
		marginBot  = 10
	)

	rows := len(domains)
	svgHeight := marginTop + rows*(barHeight+barGap) - barGap + marginBot

	var sb strings.Builder
	// NOTE: no xmlns attribute — valid in HTML5 inline SVG, and avoids
	// including an http:// namespace URI that would trip the self-contained gate.
	fmt.Fprintf(&sb,
		`<svg viewBox="0 0 %d %d" `+
			`style="width:100%%;max-width:%dpx;display:block;margin:8px 0" `+
			`role="img" aria-label="Domain score bar chart">`,
		svgWidth, svgHeight, svgWidth)
	sb.WriteString(`<title>Domain score bar chart</title>`)

	for i, d := range domains {
		y := marginTop + i*(barHeight+barGap)
		score := d.Score
		barW := barMaxW * score / 100
		color := gradeColor(d.Grade)
		label := domainShortName(d.DomainID)

		// Background track
		fmt.Fprintf(&sb,
			`<rect x="%d" y="%d" width="%d" height="%d" rx="4" fill="#edf2f7"/>`,
			labelWidth, y, barMaxW, barHeight)
		// Score bar
		if barW > 0 {
			fmt.Fprintf(&sb,
				`<rect x="%d" y="%d" width="%d" height="%d" rx="4" fill="%s"/>`,
				labelWidth, y, barW, barHeight, color)
		}
		// Domain label (left)
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" text-anchor="end" dominant-baseline="middle" `+
				`font-family="system-ui,sans-serif" font-size="12" fill="#4a5568">%s</text>`,
			labelWidth-8, y+barHeight/2, label)
		// Score number (right of bar)
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" dominant-baseline="middle" `+
				`font-family="system-ui,sans-serif" font-size="12" font-weight="600" fill="#2d3748">%d (%s)</text>`,
			labelWidth+barMaxW+8, y+barHeight/2, score, d.Grade)
	}

	sb.WriteString(`</svg>`)
	return sb.String()
}
