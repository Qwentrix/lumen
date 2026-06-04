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

// Package scoring wires the lumen-scoring engine with the embedded rules and
// probe results to produce a scored ReportPayload.
//
// The full scoring pipeline is:
//
//	probe.Run(ctx) → *common.ProbeResult{ScannerFields: ...}
//	  → buildScannerFindings(results) → *types.ScannerFindings
//	  → engine.Score(types.ScoringInput{ScannerFindings: sf, Industry, CompanySize})
//	      → evaluateRules → evalScannerCondition   [lumen-scoring]
//	  → *types.ReportPayload
//
// Scanner-active domains: vulnerabilities and compliance have had detect.scanner
// conditions since LU-4. ai_governance, security_posture, and privacy are now
// wired (LU-5) — their probe fields flow into ScannerFindings and will trigger
// scoring rules as soon as AIGOV_*/SECPOS_*/PRIV_* rules carry detect.scanner
// conditions in the embedded snapshot.
package scoring

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	lsscoring "github.com/Qwentrix/lumen-scoring/pkg/scoring"
	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/probes/common"
	lumenrules "github.com/Qwentrix/lumen/internal/rules"
)

// ScoreScan converts probe results into a *types.ReportPayload using the real
// lumen-scoring engine and the embedded rule/overlay snapshot.
//
// industry and companySize map to lumen-scoring's overlay selection.
// Default (offline scanner): industry="" → all-1.0 overlay; companySize="smb".
//
// Scanner-active domains (vulnerabilities + compliance) produce findings that
// directly affect the score. ai_governance, security_posture, and privacy are
// questionnaire-only in v0.1.x and require --hybrid answers to score below A.
//
// Callers that need the ScannerFindings struct for other purposes (e.g. the
// hybrid upload path) should use BuildScannerFindings once and pass the result
// to ScoreScanWithFindings to avoid building the struct twice.
func ScoreScan(results map[string]*common.ProbeResult, industry, companySize string) (*lstypes.ReportPayload, error) {
	sf := BuildScannerFindings(results)
	return ScoreScanWithFindings(sf, industry, companySize)
}

// ScoreScanWithFindings scores a pre-built *lstypes.ScannerFindings struct.
// It is the preferred entry-point when the caller has already built the
// ScannerFindings (e.g. for the hybrid upload path), so the same struct is
// used for both local scoring and the upload payload — guaranteeing
// score-parity between local report and server assessment.
func ScoreScanWithFindings(sf *lstypes.ScannerFindings, industry, companySize string) (*lstypes.ReportPayload, error) {
	// Load embedded rules and overlays.
	ruleStore, overlayStore, cleanup, err := lumenrules.LoadEmbedded()
	if err != nil {
		return nil, fmt.Errorf("scoring: load embedded rules: %w", err)
	}
	defer cleanup()

	// Construct the engine.
	engine, err := lsscoring.NewEngine(ruleStore, overlayStore)
	if err != nil {
		return nil, fmt.Errorf("scoring: create engine: %w", err)
	}

	// Generate a local UUID (no network).
	assessmentID := localUUID()

	// Score.
	payload, err := engine.Score(lstypes.ScoringInput{
		AssessmentID:    assessmentID,
		Industry:        industry,
		CompanySize:     companySize,
		Answers:         map[string]string{}, // offline scanner: no questionnaire answers
		ScannerFindings: sf,
	})
	if err != nil {
		return nil, fmt.Errorf("scoring: engine.Score: %w", err)
	}

	return payload, nil
}

// BuildScannerFindings is the exported form of buildScannerFindings.
// It maps each probe domain's ScannerFields into the typed types.ScannerFindings
// struct consumed by the lumen-scoring engine.
//
// This is exported for use by the hybrid upload path in cmd/lumen/scan.go so that
// the exact same ScannerFindings passed to Score() can also be sent to lumen-api,
// guaranteeing server-side score == local score (score-parity invariant).
func BuildScannerFindings(results map[string]*common.ProbeResult) *lstypes.ScannerFindings {
	return buildScannerFindings(results)
}

// buildScannerFindings maps each probe domain's ScannerFields into the typed
// types.ScannerFindings struct consumed by the lumen-scoring engine.
//
// All five domains are now populated: vulnerabilities and compliance (since LU-4);
// ai_governance, security_posture, and privacy (wired in LU-5).
func buildScannerFindings(results map[string]*common.ProbeResult) *lstypes.ScannerFindings {
	sf := &lstypes.ScannerFindings{}

	for _, result := range results {
		if result == nil {
			continue
		}
		switch result.DomainID {
		case "vulnerabilities":
			if result.ScannerFields.Vulnerabilities != nil {
				sf.Vulnerabilities = *result.ScannerFields.Vulnerabilities
			}
		case "compliance":
			if result.ScannerFields.Compliance != nil {
				sf.Compliance = *result.ScannerFields.Compliance
			}
		case "ai_governance":
			if result.ScannerFields.AIGovernance != nil {
				sf.AIGovernance = *result.ScannerFields.AIGovernance
			}
		case "security_posture":
			if result.ScannerFields.SecurityPosture != nil {
				sf.SecurityPosture = *result.ScannerFields.SecurityPosture
			}
		case "privacy":
			if result.ScannerFields.Privacy != nil {
				sf.Privacy = *result.ScannerFields.Privacy
			}
		}
	}

	return sf
}

// localUUID generates a UUID v4 from crypto/rand (zero network calls).
func localUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: time-based (should never happen).
		return fmt.Sprintf("local-%x", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:]),
	)
}
