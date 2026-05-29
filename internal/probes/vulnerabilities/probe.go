// Package vulnerabilities probes installed package inventory and matches it
// against a bundled NVD snapshot to detect known CVEs.
// TODO (LU-4): implement OS-specific inventory collection and CVE matching.
package vulnerabilities

import (
	"context"

	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "vulnerabilities"

// Run executes the vulnerability probe for the current platform.
// Returns a ProbeResult whose FindingHints map to vulnerability rule IDs.
func Run(ctx context.Context) (*common.ProbeResult, error) {
	// TODO: dispatch to inventory_darwin.go / inventory_linux.go / inventory_windows.go
	// via build tags, then run cve_match.go against the embedded NVD snapshot.
	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: map[string]interface{}{"status": "stub"},
	}, nil
}

// Manifest returns the static access declaration for the vulnerability probe.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs: []string{
			"/usr/sbin/system_profiler (macOS)",
			"/usr/sbin/softwareupdate (macOS)",
			"dpkg-query (Linux)",
			"rpm -qa (Linux)",
			"winget list / Get-WmiObject Win32_Product (Windows)",
		},
		FilePaths:    []string{},
		NetworkCalls: []string{},
	}
}
