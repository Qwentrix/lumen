// Package compliance probes OS-level compliance controls: MFA, disk encryption,
// firewall, patch level, and screen lock.
// TODO (LU-4): implement per-platform checks.
package compliance

import (
	"context"

	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "compliance"

// Run executes the compliance probe for the current platform.
func Run(ctx context.Context) (*common.ProbeResult, error) {
	// TODO: dispatch to mfa_darwin.go / disk_encryption_*.go / firewall_*.go /
	// patch_level_*.go / screen_lock_*.go via build tags.
	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: map[string]interface{}{"status": "stub"},
	}, nil
}

// Manifest returns the static access declaration for the compliance probe.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs: []string{
			"profiles command, MDM payloads (macOS)",
			"PAM module enumeration (Linux)",
			"Get-LocalUser, MFA registry (Windows)",
			"fdesetup status / diskutil (macOS)",
			"lsblk / cryptsetup status (Linux)",
			"manage-bde (Windows)",
		},
		FilePaths:    []string{},
		NetworkCalls: []string{},
	}
}
