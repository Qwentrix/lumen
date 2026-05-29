// Package scoring wraps github.com/Qwentrix/lumen-scoring and adapts probe
// results into the report payload expected by the HTML renderer.
//
// The lumen-scoring module is the single source of truth for the deterministic
// scoring algorithm shared between the lumen scanner CLI and the lumen-api
// server service. Both vendor the same module version to guarantee identical
// scores on the web and locally.
//
// TODO (LU-3 / LU-4): wire the real lumen-scoring engine once
// github.com/Qwentrix/lumen-scoring publishes its first tag and the
// local-dev replace directive in go.mod is resolved.
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
