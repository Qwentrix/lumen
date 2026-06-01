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
// Scanner-active domains (v0.1.x): vulnerabilities and compliance.
// The embedded rules snapshot contains active detect.scanner conditions for
// both of these domains, so probe findings directly affect the score and grade.
//
// Questionnaire-only in v0.1.x (no scanner conditions yet): ai_governance,
// security_posture, and privacy. These domains contribute to the score only
// when questionnaire answers are provided (--hybrid mode, LU-5).
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
func ScoreScan(results map[string]*common.ProbeResult, industry, companySize string) (*lstypes.ReportPayload, error) {
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

	// Build scanner findings from probe results.
	sf := buildScannerFindings(results)

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

// buildScannerFindings maps each probe domain's ScannerFields into the typed
// types.ScannerFindings struct consumed by the lumen-scoring engine.
//
// For LU-4, only Vulnerabilities and Compliance are populated from real probes.
// AIGovernance, SecurityPosture, and Privacy remain zero-valued (LU-5 fills them).
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
		// LU-5: ai_governance, security_posture, privacy
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
