// Package privacy probes for PII at rest in the user's home directory using
// regex matching. The scanner reads file content in a streaming fashion and
// never stores or logs matched content.
// TODO (LU-4): implement dlp_scanner.go and home_walker.go.
package privacy

import (
	"context"

	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "privacy"

// Run executes the privacy probe.
// Walks ~/Documents (and any additional paths consented to) and applies the
// bundled PII regex set. No file content is stored in the result; only
// finding hints referencing the rule IDs that were triggered.
func Run(ctx context.Context) (*common.ProbeResult, error) {
	// TODO: implement streaming home_walker.go + pii_regex.go.
	// - Walk only directories included in the current consent snapshot.
	// - Apply regex patterns (SSN, CC, DOB, email, phone) to file content.
	// - Record only FindingHints (rule IDs + hit counts), never the matched text.
	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: map[string]interface{}{"status": "stub"},
	}, nil
}

// Manifest returns the static access declaration for the privacy probe.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs:   []string{},
		FilePaths: []string{
			"~/Documents/ (streaming read, content never stored or transmitted)",
		},
		NetworkCalls: []string{},
	}
}
