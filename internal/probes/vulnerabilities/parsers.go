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

// Package vulnerabilities — OS-agnostic pure parser functions.
//
// All parse* functions in this file accept raw bytes (command stdout or file
// content) and return typed results. No exec, no file I/O, no build tag.
// This allows every parser — including Linux parsers — to be unit-tested on
// the macOS development host via `go test ./...`.
package vulnerabilities

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/Qwentrix/lumen/internal/nvd"
)

// ─── macOS parsers ────────────────────────────────────────────────────────────

// spApplicationsOutput mirrors the JSON structure emitted by
// `system_profiler SPApplicationsDataType -json`.
type spApplicationsOutput struct {
	SPApplicationsDataType []struct {
		Name    string `json:"_name"`
		Version string `json:"version"`
	} `json:"SPApplicationsDataType"`
}

// parseSystemProfilerApps parses the JSON output of
// `system_profiler SPApplicationsDataType -json` into InstalledPackage records.
// Pure function — accepts raw stdout bytes for unit-testability.
func parseSystemProfilerApps(out []byte, meta map[string]interface{}) []nvd.InstalledPackage {
	var data spApplicationsOutput
	if err := json.Unmarshal(out, &data); err != nil {
		if meta != nil {
			meta["inventory_parse_error"] = "system_profiler JSON parse: " + err.Error()
		}
		return nil
	}

	pkgs := make([]nvd.InstalledPackage, 0, len(data.SPApplicationsDataType))
	for _, app := range data.SPApplicationsDataType {
		if app.Name == "" {
			continue
		}
		pkgs = append(pkgs, nvd.InstalledPackage{
			Product: normaliseAppName(app.Name),
			Version: app.Version,
		})
	}
	return pkgs
}

// normaliseAppName strips common macOS suffixes (".app") and lowercases the
// name for CPE table lookup.
func normaliseAppName(name string) string {
	name = strings.TrimSuffix(name, ".app")
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "_")
	return name
}

// parseMacOSDate parses a macOS property-list date string and returns
// the number of whole days since that date. Returns (days, true) on success.
//
// macOS `defaults read` returns dates in the form:
//
//	"2025-03-15 14:22:08 +0000"
//
// Pure function — accepts raw output bytes for unit-testability.
func parseMacOSDate(raw []byte) (int, bool) {
	s := strings.TrimSpace(string(raw))
	formats := []string{
		"2006-01-02 15:04:05 +0000",
		"2006-01-02 15:04:05 +0000 UTC",
		time.RFC3339,
		"2006-01-02",
	}
	for _, f := range formats {
		t, err := time.Parse(f, s)
		if err == nil {
			days := int(time.Since(t).Hours() / 24)
			if days < 0 {
				days = 0
			}
			return days, true
		}
	}
	return 0, false
}

// ─── macOS pkgutil / brew pure parsers ────────────────────────────────────────

// pkgutilCPEPrefixes maps a pkgutil bundle-id prefix (or exact id) to the
// (vendor, product) pair used for NVD lookup. Only security-relevant receipts
// are listed; this avoids the cost of `pkgutil --pkg-info` for thousands of
// Apple SDK sub-packages that have no corresponding NVD CPE.
var pkgutilCPEPrefixes = []struct {
	prefix  string
	vendor  string
	product string
}{
	{"com.apple.pkg.curl", "haxx", "curl"},
	{"com.apple.pkg.git", "git-scm", "git"},
	{"com.apple.pkg.Python", "python", "python"},
	{"com.apple.pkg.python", "python", "python"},
	{"org.node.pkg.node", "nodejs", "node.js"},
	{"com.openssh.openssh", "openbsd", "openssh"},
	{"org.openssl.openssl", "openssl", "openssl"},
	{"com.apple.pkg.update.os.", "apple", "macos"}, // OS update receipts
}

// matchPkgutilID returns [vendor, product] when id matches a known CPE prefix,
// otherwise nil. Pure function — no exec.
func matchPkgutilID(id string) []string {
	for _, entry := range pkgutilCPEPrefixes {
		if strings.HasPrefix(id, entry.prefix) {
			return []string{entry.vendor, entry.product}
		}
	}
	return nil
}

// parsePkgutilVersion extracts the "version: X.Y.Z" line from `pkgutil --pkg-info` output.
// Pure function — accepts raw stdout bytes for unit-testability.
func parsePkgutilVersion(out []byte) string {
	for _, line := range bytes.Split(out, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("version:")) {
			ver := strings.TrimSpace(strings.TrimPrefix(string(trimmed), "version:"))
			return ver
		}
	}
	return ""
}

// parseBrewListVersions parses `brew list --versions` output.
// Each line is: "<package-name> <version> [<version2> ...]"
// Pure function — accepts raw stdout bytes for unit-testability.
func parseBrewListVersions(out []byte) []nvd.InstalledPackage {
	var pkgs []nvd.InstalledPackage
	for _, line := range bytes.Split(out, []byte("\n")) {
		fields := bytes.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSpace(string(fields[0]))
		ver := strings.TrimSpace(string(fields[1])) // first (current) version
		if name == "" {
			continue
		}
		pkgs = append(pkgs, nvd.InstalledPackage{
			Product: name,
			Version: ver,
		})
	}
	return pkgs
}

// ─── Linux parsers ────────────────────────────────────────────────────────────

// parseDpkgQuery parses `dpkg-query -W -f='${Package}\t${Version}\n'` output.
// Pure function — accepts raw stdout bytes for unit-testability.
func parseDpkgQuery(out []byte) []nvd.InstalledPackage {
	var pkgs []nvd.InstalledPackage
	for _, line := range bytes.Split(out, []byte("\n")) {
		fields := bytes.SplitN(line, []byte("\t"), 2)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimSpace(string(fields[0]))
		version := strings.TrimSpace(string(fields[1]))
		if name == "" {
			continue
		}
		pkgs = append(pkgs, nvd.InstalledPackage{
			Product: name,
			Version: version,
		})
	}
	return pkgs
}

// parseRPMQuery parses `rpm -qa --qf '%{NAME}\t%{VERSION}\n'` output.
// Pure function — accepts raw stdout bytes for unit-testability.
func parseRPMQuery(out []byte) []nvd.InstalledPackage {
	var pkgs []nvd.InstalledPackage
	for _, line := range bytes.Split(out, []byte("\n")) {
		fields := bytes.SplitN(line, []byte("\t"), 2)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimSpace(string(fields[0]))
		version := strings.TrimSpace(string(fields[1]))
		if name == "" {
			continue
		}
		pkgs = append(pkgs, nvd.InstalledPackage{
			Product: name,
			Version: version,
		})
	}
	return pkgs
}

// ─── Windows pure parsers (no build tag — testable on any host) ──────────────

// parseWindowsUpdateDate parses a Windows Update last-success date string.
// Accepts "YYYY-MM-DD HH:MM:SS", "MM/DD/YYYY HH:MM:SS", and RFC3339 variants.
// Returns (days, true) on success; (0, false) on parse failure.
// Used by collect_windows.go collectDaysSinceLastUpdate.
func parseWindowsUpdateDate(raw []byte) (int, bool) {
	s := strings.TrimSpace(string(raw))
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02",
		"1/2/2006 3:04:05 PM",
		"1/2/2006 3:04:05 AM",
		"1/2/2006 15:04:05",
		"01/02/2006 3:04:05 PM",
		"01/02/2006 3:04:05 AM",
		"01/02/2006 15:04:05",
		time.RFC3339,
		"Monday, January 2, 2006 3:04:05 PM",
		"Monday, January 2, 2006 3:04:05 AM",
	}
	for _, f := range formats {
		t, err := time.Parse(f, s)
		if err == nil {
			days := int(time.Since(t).Hours() / 24)
			if days < 0 {
				days = 0
			}
			return days, true
		}
	}
	return 0, false
}

// normaliseWindowsAppName strips common Windows suffixes and lowercases the name
// for consistent CPE table lookup. Used by collect_windows.go collectInventory.
func normaliseWindowsAppName(name string) string {
	name = strings.TrimSpace(name)
	for _, suffix := range []string{" (64-bit)", " (32-bit)", " (x64)", " (x86)", " (64 bit)", " (32 bit)"} {
		name = strings.TrimSuffix(name, suffix)
	}
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), " ", "_"))
}

// parseRPMLast extracts the most-recent install date from `rpm -qa --last`
// output and returns days elapsed since that date.
//
// Expected line format (first = most recent):
//
//	"bash-5.1.8-6.el9.x86_64    Fri 03 Mar 2023 10:45:01 AM UTC"
//
// Split by whitespace yields 8 tokens; the date is tokens 1–7.
// We try joining the last 7, 6, and 5 tokens against known formats.
//
// M-3 fix: Go's time package uses the reference time Mon Jan 2 15:04:05 2006.
// For 12-hour AM/PM parsing the hour reference MUST be "3" (not "15").
// Using "15" with "AM"/"PM" suffixes produces incorrect parses because Go
// treats "15" as a 24-hour literal; "3" enables 12-hour mode correctly.
//
// Pure function — accepts raw stdout bytes for unit-testability.
func parseRPMLast(out []byte) (int, bool) {
	// rpm --last date formats encountered in practice.
	// IMPORTANT: use "3:04:05 PM" (12-hour ref) for AM/PM variants; use
	// "15:04:05" (24-hour ref) only for the no-AM/PM variant.
	formats := []string{
		// "Fri 03 Mar 2023 10:45:01 AM UTC"  (7 tokens joined, 12-hour clock)
		"Mon 02 Jan 2006 3:04:05 PM MST",
		"Mon 02 Jan 2006 3:04:05 AM MST",
		// "03 Mar 2023 10:45:01 AM UTC"  (6 tokens joined, 12-hour clock)
		"02 Jan 2006 3:04:05 PM MST",
		"02 Jan 2006 3:04:05 AM MST",
		// "03 Mar 2023 10:45:01 UTC"  (5 tokens joined, 24-hour clock, no AM/PM)
		"02 Jan 2006 15:04:05 MST",
		// Plain date fallback
		"02 Jan 2006",
		"2 Jan 2006",
	}

	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		parts := bytes.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}

		// Try the last N tokens (N = 7 down to 2) to find a parseable date substring.
		maxTokens := 7
		if maxTokens > len(parts)-1 {
			maxTokens = len(parts) - 1
		}
		for n := maxTokens; n >= 2; n-- {
			dateParts := parts[len(parts)-n:]
			dateStr := string(bytes.Join(dateParts, []byte(" ")))
			for _, f := range formats {
				t, err := time.Parse(f, dateStr)
				if err == nil {
					days := int(time.Since(t).Hours() / 24)
					if days < 0 {
						days = 0
					}
					return days, true
				}
			}
		}
		// First non-empty line tried — don't scan all packages, just need the newest.
		break
	}
	return 0, false
}
