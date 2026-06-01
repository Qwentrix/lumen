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

// Package compliance — OS-agnostic pure parser functions.
//
// All parse* functions in this file are pure: they accept raw bytes (command
// stdout or file content) and return typed results. No exec, no file I/O, no
// build tag. This allows every parser — including Linux parsers — to be
// unit-tested on the macOS development host via `go test ./...`.
package compliance

import (
	"bytes"
	"strings"
)

// screenLockResult carries the screen-lock probe output.
// Defined here (no build tag) so both macOS and Linux collectors can use it,
// and so the parser functions — which are also tag-free — can return it.
type screenLockResult struct {
	enabled        bool
	timeoutSeconds int
}

// ─── macOS parsers ────────────────────────────────────────────────────────────

// parseFdesetupStatus parses the output of `fdesetup status`.
// Returns true if the output contains "FileVault is On".
func parseFdesetupStatus(out []byte) bool {
	line := strings.TrimSpace(string(out))
	return strings.HasPrefix(line, "FileVault is On")
}

// parseSocketfilterfw parses `socketfilterfw --getglobalstate` output.
// Returns (enabled, ok). ok is false when the output cannot be parsed.
func parseSocketfilterfw(out []byte) (bool, bool) {
	line := strings.ToLower(strings.TrimSpace(string(out)))
	if strings.Contains(line, "enabled") {
		return true, true
	}
	if strings.Contains(line, "disabled") {
		return false, true
	}
	return false, false
}

// parseALFGlobalState parses the integer output of
// `defaults read /Library/Preferences/com.apple.alf globalstate`.
// Returns true for "1" (on) or "2" (block all incoming), false for "0".
func parseALFGlobalState(out []byte) bool {
	val := strings.TrimSpace(string(out))
	return val == "1" || val == "2"
}

// parseScreenLockDarwin parses the three `defaults` outputs for macOS screen lock.
//
// askForPasswordOut: "1\n" or "0\n"
// askForPasswordDelayOut: "<seconds>\n" (may be empty/missing = 0)
// idleTimeOut: "<seconds>\n" (may be empty/missing = 0)
func parseScreenLockDarwin(askForPasswordOut, askForPasswordDelayOut, idleTimeOut []byte) screenLockResult {
	askVal := strings.TrimSpace(string(askForPasswordOut))
	enabled := askVal == "1"

	delay := parseIntDefault(strings.TrimSpace(string(askForPasswordDelayOut)), 0)
	idle := parseIntDefault(strings.TrimSpace(string(idleTimeOut)), 0)

	timeout := idle + delay
	return screenLockResult{enabled: enabled, timeoutSeconds: timeout}
}

// parseIntDefaultMax is the maximum value returned by parseIntDefault.
// This caps inputs at one week in seconds (604800) to prevent integer overflow
// from tampered or malformed large numeric strings that could wrap to negative.
const parseIntDefaultMax = 604800

// parseIntDefault parses s as a non-negative decimal integer.
// Returns def on any error or empty string.
// Caps the result at parseIntDefaultMax (604800) to guard against overflow
// from tampered/huge numeric strings (L-4).
func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
		if n > parseIntDefaultMax {
			return parseIntDefaultMax
		}
	}
	return n
}

// ─── Linux parsers ────────────────────────────────────────────────────────────

// parseCrypttab returns true if /etc/crypttab has at least one active mapping
// entry (non-comment, non-blank line with at least two whitespace-separated fields).
func parseCrypttab(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		fields := bytes.Fields(trimmed)
		if len(fields) >= 2 {
			return true
		}
	}
	return false
}

// parseLsblkForCrypt returns true if any row in `lsblk -o NAME,TYPE` output
// has TYPE == "crypt" (dm-crypt/LUKS device).
func parseLsblkForCrypt(out []byte) bool {
	for _, line := range bytes.Split(out, []byte("\n")) {
		fields := bytes.Fields(line)
		if len(fields) >= 2 && bytes.Equal(bytes.ToLower(fields[1]), []byte("crypt")) {
			return true
		}
	}
	return false
}

// parseUFWConf returns true if /etc/ufw/ufw.conf contains ENABLED=yes.
func parseUFWConf(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("#")) {
			continue
		}
		// Accept "ENABLED=yes" and "ENABLED = yes" (some distros use spaces).
		normalized := bytes.ReplaceAll(trimmed, []byte(" "), []byte(""))
		if bytes.EqualFold(normalized, []byte("ENABLED=yes")) {
			return true
		}
	}
	return false
}

// parseFirewalldState returns true if `firewall-cmd --state` output is "running".
func parseFirewalldState(out []byte) bool {
	return strings.TrimSpace(string(out)) == "running"
}

// parseScreenLockLinux parses the three `gsettings get` outputs.
//
// lockEnabledOut: "true\n" or "false\n"
// lockDelayOut:   "uint32 0\n" or "0\n"
// idleDelayOut:   "uint32 300\n" or "300\n"
func parseScreenLockLinux(lockEnabledOut, lockDelayOut, idleDelayOut []byte) screenLockResult {
	lockEnabledStr := strings.TrimSpace(string(lockEnabledOut))
	enabled := lockEnabledStr == "true"

	lockDelay := parseGSettingsUint32(strings.TrimSpace(string(lockDelayOut)))
	idleDelay := parseGSettingsUint32(strings.TrimSpace(string(idleDelayOut)))

	timeout := idleDelay + lockDelay
	return screenLockResult{enabled: enabled, timeoutSeconds: timeout}
}

// parseGSettingsUint32 parses a gsettings uint32 value.
// Accepts both "uint32 300" and plain "300".
// Returns 0 on any parse error.
func parseGSettingsUint32(s string) int {
	s = strings.TrimPrefix(s, "uint32 ")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
