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
	"os/exec"

	"github.com/Qwentrix/lumen/internal/manifest"
	"github.com/Qwentrix/lumen/internal/nvd"
)

// collectInventory returns the installed package list on macOS via
// `system_profiler SPApplicationsDataType -json`.
//
// Zero network — system_profiler reads the local application inventory
// and does not contact Apple servers when given -json without -detailLevel.
//
// NOTE: `softwareupdate -l` is explicitly NOT called here because it dials
// Apple servers and would trip the ZERO-NETWORK netcheck gate.
// (See LU4-BUILD-BLUEPRINT §4.4 and §0 Hard Rule 1.)
func collectInventory(ctx context.Context, meta map[string]interface{}) []nvd.InstalledPackage {
	cmd := "/usr/sbin/system_profiler"
	args := []string{"SPApplicationsDataType", "-json"}
	manifest.Default.RecordExec(cmd, args)

	out, err := exec.CommandContext(ctx, cmd, args...).Output()
	if err != nil {
		meta["inventory_unavailable"] = "system_profiler error: " + err.Error()
		return nil
	}
	return parseSystemProfilerApps(out, meta)
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
