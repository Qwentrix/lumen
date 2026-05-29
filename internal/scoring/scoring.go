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

// Package scoring wraps github.com/Qwentrix/lumen-scoring and adapts probe
// results into the report payload expected by the HTML renderer.
//
// The lumen-scoring module is the single source of truth for the deterministic
// scoring algorithm shared between the lumen scanner CLI and the lumen-api
// server service. Both vendor the same module version to guarantee identical
// scores on the web and locally.
//
// ENT-104 (LU-4) MIGRATION NOTE:
//
// This package currently uses a LOCAL stub ReportPayload / DomainResult that
// does NOT match the canonical types in github.com/Qwentrix/lumen-scoring/pkg/types.
// This is intentional for LU-1 — the replace directive in go.mod keeps the
// module resolvable at ../lumen-scoring, but the actual import is deferred.
//
// ENT-104 MUST:
//  1. Add `require github.com/Qwentrix/lumen-scoring v0.1.0` to go.mod
//     (or keep the replace for local dev).
//  2. Replace this file's local type universe with imports from:
//     - github.com/Qwentrix/lumen-scoring/pkg/types (ScoringInput, ReportPayload, etc.)
//     - github.com/Qwentrix/lumen-scoring/pkg/scoring (Engine, NewEngine)
//     - github.com/Qwentrix/lumen-scoring/pkg/rules (RuleStore, OverlayStore,
//       LoadRulesFromDir, LoadOverlaysFromDir)
//  3. Replace Score(map[string]interface{}) with:
//       engine.Score(types.ScoringInput{ScannerFindings: buildScannerFindings(results)})
//     using the TYPED types.ScannerFindings struct (NOT map[string]interface{}).
//  4. Update internal/report/report.go to accept *types.ReportPayload instead of
//     *scoring.ReportPayload.
//
// See LU1-BUILD-BLUEPRINT.md §3.1 for the pinned contract.
package scoring

import (
	"github.com/Qwentrix/lumen/internal/probes/common"
)

// ReportPayload is the intermediate representation passed to the report renderer.
// In v1, this mirrors the ReportPayload struct in lumen-api for consistency.
type ReportPayload struct {
	OverallScore int
	OverallGrade string
	Domains      []DomainResult
}

// DomainResult holds the score and grade for a single security domain.
type DomainResult struct {
	DomainID string
	Score    int
	Grade    string
	Findings []common.FindingHint
}

// Score converts a map of raw ProbeResults into a ReportPayload using the
// lumen-scoring engine.
func Score(results map[string]interface{}) (*ReportPayload, error) {
	// TODO (LU-4): invoke github.com/Qwentrix/lumen-scoring engine with the
	// probe results and the bundled rule YAML. For now return a stub payload.
	domains := make([]DomainResult, 0, len(results))
	for domainID := range results {
		domains = append(domains, DomainResult{
			DomainID: domainID,
			Score:    100,
			Grade:    "A",
			Findings: []common.FindingHint{},
		})
	}
	return &ReportPayload{
		OverallScore: 100,
		OverallGrade: "A",
		Domains:      domains,
	}, nil
}
