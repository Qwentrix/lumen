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

// Package compliance probes OS-level compliance controls: disk encryption,
// firewall state, and screen lock configuration.
//
// MFA is intentionally NOT probed by this package. Multi-factor authentication
// is an organisation-wide identity-provider setting that cannot be determined
// by inspecting a single workstation. MFAEnabled is left at its zero value
// (false) in ComplianceFindings; it is populated exclusively via the
// questionnaire path (Q-COMP-MFA-001) and is documented as
// "mfa_local_indeterminate" in probe metadata when the host scan runs.
//
// Per-platform collection is split across build-tagged files:
//   - collect_darwin.go  (//go:build darwin)
//   - collect_linux.go   (//go:build linux)
//   - collect_other.go   (//go:build !darwin && !linux) — stub, returns zero values
//
// All collectors record their exec and file-read calls via manifest.Default
// immediately before performing the OS call, so the runtime ledger reflects
// what was attempted even if the call fails.
package compliance

import (
	"context"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "compliance"

// Run executes the compliance probe for the current platform and returns a
// ProbeResult whose ScannerFields.Compliance is populated with real findings.
//
// The probe degrades gracefully on any individual collector error: a missing
// or inaccessible tool produces a false/zero value and a metadata note, but
// never fails the entire scan.
func Run(ctx context.Context) (*common.ProbeResult, error) {
	meta := map[string]interface{}{
		// Document the intentional non-population of MFAEnabled.
		"mfa_local_indeterminate": "MFA is an org-wide IdP setting; it cannot be " +
			"determined from a single-host scan. Use the questionnaire (Q-COMP-MFA-001) " +
			"to supply this signal.",
	}

	diskEnc := collectDiskEncryption(ctx, meta)
	firewall := collectFirewall(ctx, meta)
	slResult := collectScreenLock(ctx, meta)

	findings := &lstypes.ComplianceFindings{
		// MFAEnabled is intentionally left false (zero value) — see package doc.
		MFAEnabled:               false,
		DiskEncryptionEnabled:    diskEnc,
		FirewallEnabled:          firewall,
		ScreenLockEnabled:        slResult.enabled,
		ScreenLockTimeoutSeconds: slResult.timeoutSeconds,
	}

	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: meta,
		ScannerFields: common.ScannerFields{
			Compliance: findings,
		},
	}, nil
}

// Manifest returns the static access declaration for the compliance probe.
// Entries cover all platforms (macOS, Linux, Windows) and are static documentation —
// no build tags; disclosure is unconditional per the SCANNER_MANIFEST transparency promise.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs: []string{
			// macOS — disk encryption
			"/usr/bin/fdesetup status",
			// macOS — firewall
			"/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
			"/usr/bin/defaults read /Library/Preferences/com.apple.alf globalstate",
			// macOS — screen lock
			"/usr/bin/defaults read com.apple.screensaver askForPassword",
			"/usr/bin/defaults read com.apple.screensaver askForPasswordDelay",
			"/usr/bin/defaults -currentHost read com.apple.screensaver idleTime",
			// Linux — disk encryption
			"lsblk -o NAME,TYPE --noheadings",
			// Linux — firewall
			"firewall-cmd --state",
			// Linux — screen lock
			"gsettings get org.gnome.desktop.screensaver lock-enabled",
			"gsettings get org.gnome.desktop.screensaver lock-delay",
			"gsettings get org.gnome.desktop.session idle-delay",
		},
		FilePaths: []string{
			// macOS — firewall fallback plist
			"/Library/Preferences/com.apple.alf.plist",
			// Linux — disk encryption
			"/etc/crypttab",
			// Linux — firewall
			"/etc/ufw/ufw.conf",
			// Windows — BitLocker encryption state
			`HKLM\SYSTEM\CurrentControlSet\Control\BitLocker\Volume (Windows registry — BitLocker ProtectionStatus)`,
			// Windows — BitLocker Group Policy fallback
			`HKLM\SOFTWARE\Policies\Microsoft\FVE (Windows registry — BitLocker FVE policy fallback)`,
			// Windows — Firewall profile states
			`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy (Windows registry — firewall profiles)`,
			// Windows — Screen lock / screensaver settings
			`HKCU\Control Panel\Desktop (Windows registry — screen lock)`,
		},
		NetworkCalls: []string{}, // ZERO — this probe is fully offline
	}
}
