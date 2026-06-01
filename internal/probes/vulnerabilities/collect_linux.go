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

//go:build linux

package vulnerabilities

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/Qwentrix/lumen/internal/manifest"
	"github.com/Qwentrix/lumen/internal/nvd"
)

// resolveAbsPath returns the absolute path of an executable, preventing PATH
// hijacking. It tries each candidate in order; if none exist it falls back to
// exec.LookPath and records the resolved path in meta so the access manifest
// captures the actual binary that was executed.
// Returns "" when the binary cannot be found by any method.
func resolveAbsPath(name string, candidates []string, meta map[string]interface{}) string {
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	resolved, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	if meta != nil {
		meta[name+"_resolved_path"] = resolved
	}
	return resolved
}

// collectInventory returns the installed package list on Linux.
//
// Detection order:
//  1. dpkg-query (Debian/Ubuntu)
//  2. rpm (RHEL/CentOS/Fedora)
//
// Returns nil (not an error) when neither tool is found — degrades gracefully.
func collectInventory(ctx context.Context, meta map[string]interface{}) []nvd.InstalledPackage {
	if pkgs, ok := collectDpkg(ctx, meta); ok {
		return pkgs
	}
	if pkgs, ok := collectRPM(ctx, meta); ok {
		return pkgs
	}
	meta["inventory_unavailable"] = "neither dpkg-query nor rpm found on this system"
	return nil
}

// collectDpkg enumerates installed packages via dpkg-query.
// Uses the absolute path /usr/bin/dpkg-query to prevent PATH hijacking;
// falls back to exec.LookPath if not present at the standard location.
// Returns (packages, true) on success; (nil, false) if dpkg is absent.
func collectDpkg(ctx context.Context, meta map[string]interface{}) ([]nvd.InstalledPackage, bool) {
	cmd := resolveAbsPath("dpkg-query", []string{"/usr/bin/dpkg-query"}, meta)
	if cmd == "" {
		return nil, false
	}
	args := []string{"-W", "-f=${Package}\t${Version}\n"}
	manifest.Default.RecordExec(cmd, args)

	out, err := exec.CommandContext(ctx, cmd, args...).Output()
	if err != nil {
		return nil, false
	}
	return parseDpkgQuery(out), true
}

// collectRPM enumerates installed packages via rpm.
// Uses the absolute path /usr/bin/rpm to prevent PATH hijacking;
// falls back to exec.LookPath if not present at the standard location.
// Returns (packages, true) on success; (nil, false) if rpm is absent.
func collectRPM(ctx context.Context, meta map[string]interface{}) ([]nvd.InstalledPackage, bool) {
	cmd := resolveAbsPath("rpm", []string{"/usr/bin/rpm"}, meta)
	if cmd == "" {
		return nil, false
	}
	args := []string{"-qa", "--qf", "%{NAME}\t%{VERSION}\n"}
	manifest.Default.RecordExec(cmd, args)

	out, err := exec.CommandContext(ctx, cmd, args...).Output()
	if err != nil {
		return nil, false
	}
	return parseRPMQuery(out), true
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

// collectDaysSinceLastUpdate determines the age of the last successful package
// update on Linux.
//
// Detection order (prefers file mtime — no exec needed):
//  1. mtime of /var/lib/apt/periodic/update-success-stamp (Debian/Ubuntu)
//  2. mtime of /var/log/apt/history.log (Debian/Ubuntu fallback)
//  3. Most-recent rpm install timestamp via `rpm -qa --last` (RHEL)
//
// M-4 fail-secure: if the date cannot be read or parsed, returns
// DaysSinceUpdateUnknown (365) and sets patch_status="unknown" in meta,
// rather than returning 0 (which would falsely suppress VULN_NO_PATCH).
func collectDaysSinceLastUpdate(ctx context.Context, meta map[string]interface{}) int {
	// 1. apt update-success-stamp
	aptStamp := "/var/lib/apt/periodic/update-success-stamp"
	manifest.Default.RecordFileRead(aptStamp)

	if info, err := os.Stat(aptStamp); err == nil {
		days := int(time.Since(info.ModTime()).Hours() / 24)
		if days < 0 {
			days = 0
		}
		return days
	}

	// 2. apt history.log
	aptHistory := "/var/log/apt/history.log"
	manifest.Default.RecordFileRead(aptHistory)

	if info, err := os.Stat(aptHistory); err == nil {
		days := int(time.Since(info.ModTime()).Hours() / 24)
		if days < 0 {
			days = 0
		}
		return days
	}

	// 3. rpm --last — use absolute path to prevent PATH hijacking.
	rpmCmd := resolveAbsPath("rpm", []string{"/usr/bin/rpm"}, meta)
	if rpmCmd == "" {
		// M-4: fail-secure — no patch date known.
		meta["days_since_update_unavailable"] = "apt stamp/log not found; rpm not found"
		meta["patch_status"] = "unknown"
		return DaysSinceUpdateUnknown
	}
	rpmArgs := []string{"-qa", "--last"}
	manifest.Default.RecordExec(rpmCmd, rpmArgs)

	out, err := exec.CommandContext(ctx, rpmCmd, rpmArgs...).Output()
	if err != nil {
		// M-4: fail-secure — rpm ran but failed; patch date unknown.
		meta["days_since_update_unavailable"] = "apt stamp/log not found; rpm --last error: " + err.Error()
		meta["patch_status"] = "unknown"
		return DaysSinceUpdateUnknown
	}
	days, ok := parseRPMLast(out)
	if !ok {
		// M-4: fail-secure — output unparseable; patch date unknown.
		meta["days_since_update_unavailable"] = "could not parse rpm --last output"
		meta["patch_status"] = "unknown"
		return DaysSinceUpdateUnknown
	}
	return days
}
