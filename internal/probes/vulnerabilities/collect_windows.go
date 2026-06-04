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

//go:build windows

// Windows vulnerability probe collector.
//
// Data sources:
//   - Installed programs: registry HKLM+HKCU SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
//     (both 32-bit and 64-bit views) → InstalledPackage list for NVD lookup.
//   - Patch recency: registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install
//     LastSuccessTime value (REG_SZ "YYYY-MM-DD HH:MM:SS") → days_since_last_update.
//     Falls back to the most-recent Qfe InstallDate from WMI Win32_QuickFixEngineering
//     via PowerShell get-hotfix if the registry key is absent.
//
// All exec calls go through manifest.Default.RecordExec.
// ZERO network calls — all data from the local registry/WMI.
package vulnerabilities

import (
	"context"
	"os/exec"
	"strings"

	"github.com/Qwentrix/lumen/internal/manifest"
	"github.com/Qwentrix/lumen/internal/nvd"
	"golang.org/x/sys/windows/registry"
)

// DaysSinceUpdateUnknown is the fail-secure sentinel (365 days) returned when
// the last-patch date cannot be determined. Matches the darwin/linux constant.
const DaysSinceUpdateUnknown = 365

// uninstallRoots enumerates the Uninstall registry paths to check under
// both HKLM and HKCU, covering 64-bit and 32-bit installed programs.
var uninstallRoots = []struct {
	hive registry.Key
	path string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
}

// collectInventory returns installed packages on Windows by reading registry Uninstall keys.
// Merges HKLM 64-bit, HKLM 32-bit (WOW6432Node), and HKCU entries into one deduplicated list.
//
// ZERO network — reads local registry only.
func collectInventory(ctx context.Context, meta map[string]interface{}) []nvd.InstalledPackage {
	manifest.Default.RecordFileRead(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`)
	manifest.Default.RecordFileRead(`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`)
	manifest.Default.RecordFileRead(`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`)

	seen := map[string]struct{}{}
	var pkgs []nvd.InstalledPackage

	for _, root := range uninstallRoots {
		k, err := registry.OpenKey(root.hive, root.path, registry.ENUMERATE_SUB_KEYS|registry.READ)
		if err != nil {
			continue
		}
		subkeys, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}

		for _, subkey := range subkeys {
			sk, err := registry.OpenKey(root.hive, root.path+`\`+subkey, registry.QUERY_VALUE|registry.READ)
			if err != nil {
				continue
			}
			displayName, _, _ := sk.GetStringValue("DisplayName")
			displayVersion, _, _ := sk.GetStringValue("DisplayVersion")
			sk.Close()

			if displayName == "" {
				continue
			}

			// De-duplicate by normalised name+version to avoid counting the same
			// program multiple times from the 32-bit and 64-bit registry views.
			key := strings.ToLower(displayName) + "|" + strings.ToLower(displayVersion)
			if _, already := seen[key]; already {
				continue
			}
			seen[key] = struct{}{}

			pkgs = append(pkgs, nvd.InstalledPackage{
				Product: normaliseWindowsAppName(displayName),
				Version: displayVersion,
			})
		}
	}

	return pkgs
}

// normaliseWindowsAppName is defined in parsers.go (no build tag) for cross-platform testability.

// collectDaysSinceLastUpdate reads the Windows Update last-success timestamp
// from the registry and returns the number of days elapsed.
//
// Primary: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install
//
//	LastSuccessTime (REG_SZ) — format "YYYY-MM-DD HH:MM:SS"
//
// Fallback: `powershell -NoProfile -NonInteractive -Command "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"`
// M-4 fail-secure: returns DaysSinceUpdateUnknown (365) on any read/parse failure.
func collectDaysSinceLastUpdate(ctx context.Context, meta map[string]interface{}) int {
	const wuaPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install`
	manifest.Default.RecordFileRead(`HKLM\` + wuaPath)

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, wuaPath, registry.QUERY_VALUE|registry.READ)
	if err == nil {
		defer k.Close()
		val, _, err2 := k.GetStringValue("LastSuccessTime")
		if err2 == nil {
			days, ok := parseWindowsUpdateDate([]byte(val))
			if ok {
				return days
			}
		}
	}

	// Fallback: PowerShell Get-HotFix most-recent install date.
	psCmd := "powershell.exe"
	psArgs := []string{
		"-NoProfile", "-NonInteractive", "-Command",
		"(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn",
	}
	manifest.Default.RecordExec(psCmd, psArgs)

	out, psErr := exec.CommandContext(ctx, psCmd, psArgs...).Output()
	if psErr != nil {
		meta["days_since_update_unavailable"] = "WUA registry unavailable; Get-HotFix error: " + psErr.Error()
		meta["patch_status"] = "unknown"
		return DaysSinceUpdateUnknown
	}

	days, ok := parseWindowsUpdateDate(out)
	if !ok {
		meta["days_since_update_unavailable"] = "could not parse Get-HotFix date output"
		meta["patch_status"] = "unknown"
		return DaysSinceUpdateUnknown
	}
	return days
}

// parseWindowsUpdateDate is defined in parsers.go (no build tag) for cross-platform testability.
