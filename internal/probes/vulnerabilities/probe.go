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

// Package vulnerabilities probes installed package inventory and matches it
// against the bundled NVD snapshot (internal/nvd) to detect known CVEs.
//
// Per-platform inventory collection is split across build-tagged files:
//   - collect_darwin.go  (//go:build darwin)  — system_profiler + SoftwareUpdate plist
//   - collect_linux.go   (//go:build linux)    — dpkg-query / rpm
//   - collect_other.go   (//go:build !darwin && !linux) — stub (Windows is LU-5)
//
// The scoring wire (probe → scoring engine):
//   Run(ctx) → ProbeResult.ScannerFields.Vulnerabilities → *types.VulnerabilityFindings
//     → scoring.buildScannerFindings → engine.Score → *types.ReportPayload
package vulnerabilities

import (
	"context"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/nvd"
	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "vulnerabilities"

// Run executes the vulnerability probe for the current platform.
//
// Steps:
//  1. Collect the installed package inventory via OS-specific collectors.
//  2. Load the embedded NVD index and match each package.
//  3. Roll up critical/high CVE counts into VulnerabilityFindings.
//  4. Collect days-since-last-update from the OS's update records.
//
// The probe degrades gracefully: a missing inventory tool or an unreadable
// update stamp produces zero/default values with metadata notes, but never
// returns a non-nil error (programmer faults remain errors).
func Run(ctx context.Context) (*common.ProbeResult, error) {
	meta := map[string]interface{}{}

	// 1. Collect installed packages.
	pkgs := collectInventory(ctx, meta)

	// 2. Load NVD index (embedded, zero network).
	idx, err := nvd.Load()
	if err != nil {
		meta["nvd_load_error"] = err.Error()
		// Degrade: return findings with only package count.
		return &common.ProbeResult{
			DomainID: domainID,
			Findings: []common.FindingHint{},
			Metadata: meta,
			ScannerFields: common.ScannerFields{
				Vulnerabilities: &lstypes.VulnerabilityFindings{
					TotalPackages: len(pkgs),
				},
			},
		}, nil
	}

	// 3. Match each package against the CVE index.
	criticalCount, highCount := matchCVEs(idx, pkgs)

	// 4. Days since last update.
	daysSince := collectDaysSinceLastUpdate(ctx, meta)

	findings := &lstypes.VulnerabilityFindings{
		TotalPackages:       len(pkgs),
		CriticalCVECount:    criticalCount,
		HighCVECount:        highCount,
		DaysSinceLastUpdate: daysSince,
	}

	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: meta,
		ScannerFields: common.ScannerFields{
			Vulnerabilities: findings,
		},
	}, nil
}

// matchCVEs iterates the package inventory, matches each against the NVD index,
// and returns (criticalCount, highCount). Duplicate CVEs are counted once per unique
// CVE ID to avoid inflating counts when multiple CPE entries map the same CVE.
func matchCVEs(idx *nvd.Index, pkgs []nvd.InstalledPackage) (critical, high int) {
	seen := map[string]struct{}{}

	for _, pkg := range pkgs {
		for _, rec := range idx.Match(pkg) {
			if _, already := seen[rec.CVE]; already {
				continue
			}
			seen[rec.CVE] = struct{}{}
			switch rec.Severity {
			case "critical":
				critical++
			case "high":
				high++
			}
		}
	}
	return critical, high
}

// Manifest returns the static access declaration for the vulnerability probe.
// Windows entries are marked (LU-5) and are not invoked in LU-4.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs: []string{
			// macOS — package inventory
			"/usr/sbin/system_profiler SPApplicationsDataType -json",
			// macOS — update age (reads plist; no network)
			"/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate LastSuccessfulDate",
			"/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate LastFullSuccessfulDate",
			// Linux — Debian/Ubuntu package inventory
			"dpkg-query -W -f '${Package}\\t${Version}\\n'",
			// Linux — RHEL/CentOS package inventory
			"rpm -qa --qf '%{NAME}\\t%{VERSION}\\n'",
			// Linux — update age (RHEL)
			"rpm -qa --last",
			// Windows (LU-5 scope only — not invoked in LU-4)
			"winget list (Windows — LU-5)",
			"Get-WmiObject Win32_Product (Windows — LU-5)",
		},
		FilePaths: []string{
			// macOS — Software Update plist (read via defaults, not direct file open)
			"/Library/Preferences/com.apple.SoftwareUpdate.plist",
			// Linux — Debian/Ubuntu update stamps
			"/var/lib/apt/periodic/update-success-stamp",
			"/var/log/apt/history.log",
		},
		NetworkCalls: []string{}, // ZERO — fully offline
	}
}
