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

// Package ai_governance — OS-agnostic pure parser functions.
//
// All parse* and match* functions in this file are pure: they accept raw bytes
// (command stdout, file content, or directory listings) and return typed results.
// No exec, no file I/O, no build tag. This allows every parser — including
// Linux-only parsers — to be unit-tested on the macOS development host.
package ai_governance

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// ─── Shadow AI app detection ──────────────────────────────────────────────────

// parseShadowAppsFromProcessList parses `ps -axo comm` (darwin) or the contents
// of /proc/*/comm (linux) output — one process name per line — and counts how
// many distinct processes match the shadow-AI app name list.
//
// Matching is case-insensitive substring. A single app is counted at most once
// even if multiple processes carry the same name.
func parseShadowAppsFromProcessList(psOut []byte) int {
	seen := map[string]struct{}{}
	count := 0
	for _, line := range bytes.Split(psOut, []byte("\n")) {
		name := strings.ToLower(strings.TrimSpace(string(line)))
		if name == "" {
			continue
		}
		for _, app := range shadowAIAppNames {
			if strings.Contains(name, strings.ToLower(app)) {
				key := app
				if _, already := seen[key]; !already {
					seen[key] = struct{}{}
					count++
				}
				break
			}
		}
	}
	return count
}

// parseShadowAppsFromAppDir parses a list of application bundle names or
// directory names (one per line, e.g. output of ls /Applications on darwin,
// or ls ~/.local/bin on linux) and counts shadow AI apps.
//
// Uses the same case-insensitive substring matching as parseShadowAppsFromProcessList.
// Results are de-duplicated against a provided seen-set so callers can combine
// process-list and app-directory results without double-counting.
func parseShadowAppsFromAppDir(lsOut []byte, seen map[string]struct{}) int {
	count := 0
	for _, line := range bytes.Split(lsOut, []byte("\n")) {
		name := strings.ToLower(strings.TrimSpace(string(line)))
		if name == "" {
			continue
		}
		for _, app := range shadowAIAppNames {
			if strings.Contains(name, strings.ToLower(app)) {
				key := app
				if _, already := seen[key]; !already {
					seen[key] = struct{}{}
					count++
				}
				break
			}
		}
	}
	return count
}

// ─── Browser extension AI detection ──────────────────────────────────────────

// extensionManifest is the subset of a Chrome/Edge/Brave extension manifest.json
// that we parse. We only extract the name field.
type extensionManifest struct {
	Name string `json:"name"`
}

// parseExtensionManifestJSON parses the contents of an extension's manifest.json
// and returns the extension name. Returns "" on parse error or missing name.
func parseExtensionManifestJSON(data []byte) string {
	var m extensionManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	return m.Name
}

// isAIExtensionByID returns true if the extension ID (directory name) matches
// one of the known AI extension IDs in the allowlist.
func isAIExtensionByID(extID string) bool {
	id := strings.ToLower(strings.TrimSpace(extID))
	for _, known := range aiExtensionIDs {
		if id == strings.ToLower(known) {
			return true
		}
	}
	return false
}

// isAIExtensionByName returns true if the extension display name contains one of
// the known AI-assistant name substrings (case-insensitive).
func isAIExtensionByName(name string) bool {
	lower := strings.ToLower(name)
	for _, substr := range aiExtensionNameSubstrings {
		if strings.Contains(lower, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// firefoxExtension is the subset of a Firefox extensions.json entry that we parse.
type firefoxExtension struct {
	ID              string `json:"id"`
	DefaultLocale   struct {
		Name string `json:"name"`
	} `json:"defaultLocale"`
	Name string `json:"name"`
}

// firefoxExtensionsFile is the top-level structure of Firefox extensions.json.
type firefoxExtensionsFile struct {
	Addons []firefoxExtension `json:"addons"`
}

// parseFirefoxExtensionsJSON parses a Firefox extensions.json file content and
// returns the count of AI-assistant extensions found.
func parseFirefoxExtensionsJSON(data []byte) int {
	var f firefoxExtensionsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return 0
	}
	count := 0
	seen := map[string]struct{}{}
	for _, addon := range f.Addons {
		// Try matching by ID first.
		if isAIExtensionByID(addon.ID) {
			if _, already := seen[addon.ID]; !already {
				seen[addon.ID] = struct{}{}
				count++
			}
			continue
		}
		// Fall back to name matching.
		name := addon.Name
		if name == "" {
			name = addon.DefaultLocale.Name
		}
		if name != "" && isAIExtensionByName(name) {
			key := addon.ID
			if key == "" {
				key = name
			}
			if _, already := seen[key]; !already {
				seen[key] = struct{}{}
				count++
			}
		}
	}
	return count
}

// ─── LLM egress socket table parsing ─────────────────────────────────────────

// parseLSOFEgressCount parses the output of lsof with HOSTNAME resolution
// (i.e. WITHOUT -n flag) and counts distinct PIDs with ESTABLISHED connections
// to known LLM API endpoints by hostname matching.
//
// Sample lsof line (with hostname resolution):
//
//	node      12345 user  27u  IPv4  ...  TCP 10.0.0.1:54321->api.openai.com:443 (ESTABLISHED)
//
// This function is kept for backwards-compatibility and reference. On macOS the
// caller uses parseLSOFEgressCountNumeric (lsof -n returns numeric IPs).
func parseLSOFEgressCount(lsofOut []byte) int {
	pids := map[string]struct{}{}
	for _, line := range bytes.Split(lsofOut, []byte("\n")) {
		s := string(line)
		if !strings.Contains(s, "ESTABLISHED") {
			continue
		}
		// Extract the remote address token (after "->").
		arrowIdx := strings.Index(s, "->")
		if arrowIdx < 0 {
			continue
		}
		remote := s[arrowIdx+2:]
		// Strip the state suffix "(ESTABLISHED)".
		if spaceIdx := strings.Index(remote, " "); spaceIdx >= 0 {
			remote = remote[:spaceIdx]
		}
		// remote is now "hostname:port" or "ip:port".
		// Strip port.
		if colonIdx := strings.LastIndex(remote, ":"); colonIdx >= 0 {
			remote = remote[:colonIdx]
		}
		remote = strings.TrimSpace(remote)
		if remote == "" {
			continue
		}

		if matchesLLMHost(remote) {
			// Extract PID from field 2 (0-indexed column 1).
			fields := strings.Fields(s)
			if len(fields) >= 2 {
				pid := fields[1]
				pids[pid] = struct{}{}
			}
		}
	}
	return len(pids)
}

// parseLSOFEgressCountNumeric parses the output of:
//
//	lsof -nP -iTCP -sTCP:ESTABLISHED
//
// where -n suppresses reverse-DNS (required to stay zero-network). Since remote
// addresses are numeric IPs, hostname matching cannot be used. Instead we:
//  1. Try CIDR matching against bundled LLM-provider IP ranges.
//  2. As a secondary check, try hostname matching in case the OS has already
//     resolved the name in the connection tuple (some lsof builds ignore -n).
//
// BEST-EFFORT: CDN routing and IP rotation mean undercounting is expected.
// This is intentional — false negatives are acceptable; false positives are not.
//
// Sample lsof line (numeric):
//
//	node      12345 user  27u  IPv4  ...  TCP 10.0.0.1:54321->104.18.12.34:443 (ESTABLISHED)
func parseLSOFEgressCountNumeric(lsofOut []byte) int {
	pids := map[string]struct{}{}
	for _, line := range bytes.Split(lsofOut, []byte("\n")) {
		s := string(line)
		if !strings.Contains(s, "ESTABLISHED") {
			continue
		}
		arrowIdx := strings.Index(s, "->")
		if arrowIdx < 0 {
			continue
		}
		remote := s[arrowIdx+2:]
		if spaceIdx := strings.Index(remote, " "); spaceIdx >= 0 {
			remote = remote[:spaceIdx]
		}
		// remote is "ip:port" (numeric) — strip port.
		if colonIdx := strings.LastIndex(remote, ":"); colonIdx >= 0 {
			remote = remote[:colonIdx]
		}
		remote = strings.TrimSpace(remote)
		if remote == "" {
			continue
		}

		// Match by CIDR (for numeric IPs) or by hostname (in case lsof resolved it).
		if matchesLLMCIDR(remote) || matchesLLMHost(remote) {
			fields := strings.Fields(s)
			if len(fields) >= 2 {
				pid := fields[1]
				pids[pid] = struct{}{}
			}
		}
	}
	return len(pids)
}

// parseSSEgressCount parses the output of:
//
//	ss -tnp state established
//
// and counts distinct PIDs that have at least one ESTABLISHED connection whose
// remote address matches a known LLM provider by hostname OR CIDR range.
//
// ss output columns (space-separated, no header when piped):
//
//	State    Recv-Q  Send-Q  LocalAddr:Port   PeerAddr:Port   [process]
//	ESTAB    0       0       10.0.0.1:54321   104.18.12.34:443  users:(("node",pid=1234,fd=10))
//
// The peer/remote address is the 5th field (index 4). The process info (if
// available with -p flag) is in the 6th+ fields. PID is extracted from the
// users:((...,pid=N,...)) token. If no PID is available (non-root ss run),
// we fall back to counting distinct remote addresses.
//
// BEST-EFFORT: IP-based CIDR matching undercounts when providers use CDNs or
// rotate IPs. Hostname matching applies only when ss resolves names (no -n flag).
func parseSSEgressCount(ssOut []byte) int {
	pids := map[string]struct{}{}
	remotes := map[string]struct{}{} // fallback when pid is unavailable

	for _, line := range bytes.Split(ssOut, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if s == "" {
			continue
		}
		// Skip the header line if present ("State Recv-Q Send-Q ...")
		if strings.HasPrefix(s, "State") || strings.HasPrefix(s, "Netid") {
			continue
		}
		// Only process ESTABLISHED (ESTAB) lines.
		fields := strings.Fields(s)
		if len(fields) < 5 {
			continue
		}
		if !strings.EqualFold(fields[0], "ESTAB") {
			continue
		}

		// Peer address is in field index 4 (0-based): "IP:port"
		peerAddrPort := fields[4]
		// Strip port: last colon-separated segment.
		colonIdx := strings.LastIndex(peerAddrPort, ":")
		if colonIdx < 0 {
			continue
		}
		peerAddr := peerAddrPort[:colonIdx]
		// IPv6 addresses may be wrapped in brackets: [::1]
		peerAddr = strings.TrimPrefix(peerAddr, "[")
		peerAddr = strings.TrimSuffix(peerAddr, "]")
		peerAddr = strings.TrimSpace(peerAddr)
		if peerAddr == "" {
			continue
		}

		// Match by hostname (when ss resolves names) OR by CIDR (numeric IPs).
		if !matchesLLMHost(peerAddr) && !matchesLLMCIDR(peerAddr) {
			continue
		}

		// Extract PID from users:(("proc",pid=N,fd=M)) if present.
		pid := extractSSPID(s)
		if pid != "" {
			pids[pid] = struct{}{}
		} else {
			// No process info available — count unique remote addresses instead.
			remotes[peerAddr] = struct{}{}
		}
	}

	// If we got any real PID data, prefer that count; otherwise use remote count.
	if len(pids) > 0 {
		return len(pids)
	}
	return len(remotes)
}

// extractSSPID extracts the PID number from a ss -p output line.
// The process token has the form: users:(("name",pid=1234,fd=10))
// Returns "" if no PID token is present (e.g. run without root/sudo).
func extractSSPID(line string) string {
	pidIdx := strings.Index(line, "pid=")
	if pidIdx < 0 {
		return ""
	}
	rest := line[pidIdx+4:]
	end := strings.IndexAny(rest, ",)")
	if end < 0 {
		end = len(rest)
	}
	pid := strings.TrimSpace(rest[:end])
	if pid == "" {
		return ""
	}
	return pid
}

// matchesLLMCIDR returns true if the given numeric IP address falls within any
// of the known LLM provider CIDR ranges in llmProviderCIDRs.
//
// BEST-EFFORT: providers use CDNs and rotate IPs; undercounting is expected.
// This function makes ZERO network calls — all CIDRs are bundled statically.
func matchesLLMCIDR(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range llmProviderCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// parseProcNetTCPEgressCount parses /proc/net/tcp (or tcp6) content and counts
// distinct socket inodes that have an ESTABLISHED (state=01) connection whose
// remote hex IP matches a known LLM API host.
//
// On Linux we only have raw IPs in /proc/net/tcp — we cannot match hostnames
// without a DNS lookup, which is prohibited. We therefore skip IP-based matching
// and return 0 for this path to stay ZERO-NETWORK. The egress count for Linux
// instead comes from `ss -tnp state established` output which includes hostnames
// when available, or from parsing /proc/net/tcp and comparing against a small set
// of hardcoded IP ranges (not implemented in v1 — conservative choice).
//
// NOTE: On Linux the primary path is ss output parsed by parseLSOFEgressCount
// (ss output format is similar enough to lsof for our purposes when called with
// the right flags). This function is a no-op stub returning 0, kept for interface
// symmetry and to document the conservative decision.
func parseProcNetTCPEgressCount(_ []byte) int {
	// Conservative: without DNS, we cannot reliably match raw IP addresses to
	// LLM API endpoints without a network call. Return 0 rather than false-positive.
	return 0
}

// matchesLLMHost returns true if the given remote host token contains any of the
// known LLM API hostnames (case-insensitive suffix match).
func matchesLLMHost(remote string) bool {
	lower := strings.ToLower(remote)
	for _, host := range llmAPIHosts {
		h := strings.ToLower(host)
		if lower == h || strings.HasSuffix(lower, "."+h) || strings.HasSuffix(lower, h) {
			return true
		}
	}
	return false
}

// ─── Chromium multi-profile enumeration ──────────────────────────────────────

// enumerateChromiumProfileExtDirs returns the Extensions subdirectory path for
// every Chromium profile found under a "User Data" base directory.
//
// Chromium (Chrome/Edge/Brave) creates profiles as subdirectories of the
// "User Data" directory named either "Default" or "Profile N" (e.g. "Profile 1",
// "Profile 2"). Each profile contains an "Extensions" subdirectory.
//
// Only scanning the "Default" profile causes an undercount when the user has
// signed in with multiple Google accounts — each additional account gets its own
// "Profile N" directory.
//
// This function is pure (no exec, no build tag) so it can be tested on any host.
func enumerateChromiumProfileExtDirs(userDataDir string) []string {
	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return nil
	}
	var result []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		// Accept "Default" and "Profile <anything>" directory names.
		if name != "Default" && !strings.HasPrefix(name, "Profile ") {
			continue
		}
		extDir := filepath.Join(userDataDir, name, "Extensions")
		result = append(result, extDir)
	}
	return result
}

// ─── Shared helpers used by both darwin and linux collectors ─────────────────

// parseShadowAppsIntoSeen is like parseShadowAppsFromProcessList but writes
// matched app keys directly into the caller-supplied seen map without returning
// a count. Used by collect_*.go to share the seen set across process-list and
// app-directory scans, preventing double-counting.
func parseShadowAppsIntoSeen(psOut []byte, seen map[string]struct{}) {
	for _, line := range splitLines(psOut) {
		name := lowerTrim(line)
		if name == "" {
			continue
		}
		for _, app := range shadowAIAppNames {
			if containsLower(name, app) {
				seen[app] = struct{}{}
				break
			}
		}
	}
}

// parseFirefoxExtensionsJSONWithSeen is like parseFirefoxExtensionsJSON but
// de-duplicates against a caller-provided seen map so results across multiple
// Firefox profiles are counted only once.
func parseFirefoxExtensionsJSONWithSeen(data []byte, seen map[string]struct{}) int {
	var f firefoxExtensionsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return 0
	}
	count := 0
	for _, addon := range f.Addons {
		if isAIExtensionByID(addon.ID) {
			if _, already := seen[addon.ID]; !already {
				seen[addon.ID] = struct{}{}
				count++
			}
			continue
		}
		name := addon.Name
		if name == "" {
			name = addon.DefaultLocale.Name
		}
		if name != "" && isAIExtensionByName(name) {
			key := addon.ID
			if key == "" {
				key = name
			}
			if _, already := seen[key]; !already {
				seen[key] = struct{}{}
				count++
			}
		}
	}
	return count
}

// splitLines splits b on newlines.
func splitLines(b []byte) [][]byte {
	return splitOnNewline(b)
}

// splitOnNewline splits a byte slice on '\n'.
func splitOnNewline(b []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			lines = append(lines, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, b[start:])
	}
	return lines
}

// lowerTrim trims whitespace and lowercases a byte slice to string.
func lowerTrim(b []byte) string {
	return strings.ToLower(strings.TrimSpace(string(b)))
}

// containsLower returns true if s contains substr (case-insensitive).
func containsLower(s, substr string) bool {
	return strings.Contains(s, strings.ToLower(substr))
}

// ─── MCP server process detection ────────────────────────────────────────────

// parseMCPCountFromProcessArgs parses the output of `ps -axo args` (darwin) or
// the concatenated cmdline strings from /proc/*/cmdline (linux) and counts
// distinct MCP server processes detected.
//
// Each line (or cmdline entry) is checked for the bundled MCP name patterns.
// A single match per unique command line is counted.
func parseMCPCountFromProcessArgs(psOut []byte) int {
	seen := map[string]struct{}{}
	count := 0
	for _, line := range bytes.Split(psOut, []byte("\n")) {
		cmdline := strings.TrimSpace(string(line))
		if cmdline == "" {
			continue
		}
		lowerCmd := strings.ToLower(cmdline)
		for _, pattern := range mcpServerNames {
			lower := strings.ToLower(pattern)
			if strings.Contains(lowerCmd, lower) {
				if _, already := seen[cmdline]; !already {
					seen[cmdline] = struct{}{}
					count++
				}
				break
			}
		}
	}
	return count
}
