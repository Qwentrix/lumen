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

//go:build darwin

package vulnerabilities

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/Qwentrix/lumen/internal/manifest"
	"github.com/Qwentrix/lumen/internal/nvd"
)

// collectInventory returns the installed package list on macOS by combining:
//  1. system_profiler SPApplicationsDataType -json  (.app bundles)
//  2. /usr/bin/sw_vers -productVersion              (OS version → apple:macos)
//  3. /usr/sbin/pkgutil --pkgs                      (receipts: CLI tools, SDKs)
//  4. brew list --versions                          (best-effort; tolerate absence)
//
// All sources are ZERO-NETWORK — they read local state only.
// NOTE: `softwareupdate -l` is explicitly NOT called; it dials Apple servers
// and would trip the ZERO-NETWORK netcheck gate.
func collectInventory(ctx context.Context, meta map[string]interface{}) []nvd.InstalledPackage {
	var pkgs []nvd.InstalledPackage

	// 1. .app bundles via system_profiler.
	{
		cmd := "/usr/sbin/system_profiler"
		args := []string{"SPApplicationsDataType", "-json"}
		manifest.Default.RecordExec(cmd, args)
		out, err := exec.CommandContext(ctx, cmd, args...).Output()
		if err != nil {
			meta["inventory_system_profiler_error"] = err.Error()
		} else {
			pkgs = append(pkgs, parseSystemProfilerApps(out, meta)...)
		}
	}

	// 2. OS version → apple:macos so CVEs against macOS itself are matched.
	{
		cmd := "/usr/bin/sw_vers"
		args := []string{"-productVersion"}
		manifest.Default.RecordExec(cmd, args)
		out, err := exec.CommandContext(ctx, cmd, args...).Output()
		if err != nil {
			meta["inventory_sw_vers_error"] = err.Error()
		} else {
			ver := strings.TrimSpace(string(out))
			if ver != "" {
				pkgs = append(pkgs, nvd.InstalledPackage{
					Vendor:  "apple",
					Product: "macos",
					Version: ver,
				})
			}
		}
	}

	// 3. pkgutil receipts — CLI tools (curl, git, openssl, python, node, etc.)
	// that are installed as pkg receipts but not as .app bundles.
	pkgs = append(pkgs, collectPkgutilPackages(ctx, meta)...)

	// 4. Homebrew (best-effort — many developer machines have it; tolerate absence).
	pkgs = append(pkgs, collectBrewPackages(ctx, meta)...)

	return pkgs
}

// collectPkgutilPackages enumerates installed package receipts via
// `/usr/sbin/pkgutil --pkgs` and attempts a version lookup for a small
// curated set of security-relevant receipts via `pkgutil --pkg-info <id>`.
//
// Full `pkgutil --pkg-info` for every receipt is expensive (~seconds on a
// machine with thousands of pkgs), so we only fetch version info for receipts
// whose bundle-id prefix maps to a known CPE product.
func collectPkgutilPackages(ctx context.Context, meta map[string]interface{}) []nvd.InstalledPackage {
	cmd := "/usr/sbin/pkgutil"
	args := []string{"--pkgs"}
	manifest.Default.RecordExec(cmd, args)

	out, err := exec.CommandContext(ctx, cmd, args...).Output()
	if err != nil {
		meta["inventory_pkgutil_error"] = err.Error()
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	seen := map[string]struct{}{}
	var pkgs []nvd.InstalledPackage

	for _, line := range lines {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		vp := matchPkgutilID(id)
		if vp == nil {
			continue
		}
		key := vp[0] + ":" + vp[1]
		if _, already := seen[key]; already {
			continue
		}
		seen[key] = struct{}{}

		// Best-effort version lookup via pkgutil --pkg-info.
		ver := pkgutilLookupVersion(ctx, id)

		pkgs = append(pkgs, nvd.InstalledPackage{
			Vendor:  vp[0],
			Product: vp[1],
			Version: ver,
		})
	}
	return pkgs
}

// pkgutilLookupVersion runs `pkgutil --pkg-info <id>` and extracts the version.
// Returns "" on any error — unknown version is safe, the index still matches
// all-version CVEs where applicable.
func pkgutilLookupVersion(ctx context.Context, id string) string {
	pkgInfoCmd := "/usr/sbin/pkgutil"
	pkgInfoArgs := []string{"--pkg-info", id}
	manifest.Default.RecordExec(pkgInfoCmd, pkgInfoArgs)

	infoOut, infoErr := exec.CommandContext(ctx, pkgInfoCmd, pkgInfoArgs...).Output()
	if infoErr != nil {
		return ""
	}
	return parsePkgutilVersion(infoOut)
}

// collectBrewPackages enumerates packages installed via Homebrew via
// `brew list --versions`. Tolerates absence of brew gracefully.
//
// ZERO network — brew list reads local Cellar metadata only.
func collectBrewPackages(ctx context.Context, meta map[string]interface{}) []nvd.InstalledPackage {
	// Homebrew may be in several locations depending on CPU architecture.
	brewCandidates := []string{
		"/opt/homebrew/bin/brew", // Apple Silicon (default)
		"/usr/local/bin/brew",    // Intel
	}
	var brewPath string
	for _, p := range brewCandidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			brewPath = p
			break
		}
	}
	if brewPath == "" {
		// brew absent — not an error; many machines don't have Homebrew.
		meta["inventory_brew_unavailable"] = "homebrew not found at standard locations"
		return nil
	}

	args := []string{"list", "--versions"}
	manifest.Default.RecordExec(brewPath, args)

	out, err := exec.CommandContext(ctx, brewPath, args...).Output()
	if err != nil {
		meta["inventory_brew_error"] = err.Error()
		return nil
	}
	return parseBrewListVersions(out)
}

// DaysSinceUpdateUnknown is the fail-secure sentinel value returned by
// collectDaysSinceLastUpdate when the last-update date cannot be read or
// parsed. It is intentionally large (365 days) so that the VULN_NO_PATCH
// rule (threshold: 30 days) fires rather than being silently suppressed.
//
// Fail-secure rationale: returning 0 ("just updated") when we don't actually
// know the patch date would hide a potential vulnerability. Returning 365
// causes the rule to fire and prompts the user to verify their patch status.
const DaysSinceUpdateUnknown = 365

// collectDaysSinceLastUpdate reads the macOS Software Update preference plist
// to determine how many days have elapsed since the last successful update.
//
// Reads LastSuccessfulDate (or LastFullSuccessfulDate) from:
//   /Library/Preferences/com.apple.SoftwareUpdate.plist
//
// Uses `defaults read` which reads the local plist file — ZERO network.
// `softwareupdate -l` is explicitly NOT used (it dials Apple servers).
//
// M-4 fail-secure: if neither date field can be read/parsed, returns
// DaysSinceUpdateUnknown (365) and sets patch_status="unknown" in meta,
// rather than returning 0 (which would falsely suppress VULN_NO_PATCH).
func collectDaysSinceLastUpdate(ctx context.Context, meta map[string]interface{}) int {
	plistPath := "/Library/Preferences/com.apple.SoftwareUpdate"

	keys := []string{"LastSuccessfulDate", "LastFullSuccessfulDate"}
	for _, key := range keys {
		days, ok := readSoftwareUpdateDate(ctx, plistPath, key)
		if ok {
			return days
		}
	}
	// M-4: fail-secure — patch date unknown; do not suppress VULN_NO_PATCH.
	meta["days_since_update_unavailable"] = "could not read SoftwareUpdate plist date fields"
	meta["patch_status"] = "unknown"
	return DaysSinceUpdateUnknown
}

// readSoftwareUpdateDate reads a date string from the macOS SoftwareUpdate plist
// via `defaults read`, parses it, and returns days elapsed. Returns (days, true)
// on success, (0, false) on any error.
func readSoftwareUpdateDate(ctx context.Context, plistPath, key string) (int, bool) {
	cmd := "/usr/bin/defaults"
	args := []string{"read", plistPath, key}
	manifest.Default.RecordExec(cmd, args)
	manifest.Default.RecordFileRead(plistPath + ".plist")

	out, err := exec.CommandContext(ctx, cmd, args...).Output()
	if err != nil {
		return 0, false
	}
	return parseMacOSDate(bytes.TrimSpace(out))
}
