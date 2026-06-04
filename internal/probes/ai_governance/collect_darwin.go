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

package ai_governance

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Qwentrix/lumen/internal/manifest"
)

// collectShadowAIApps enumerates running processes and the /Applications directory
// to detect local LLM / AI-assistant apps on macOS.
// Returns a count of distinct shadow-AI apps detected and a shared seen-set for
// de-duplication across process list and app directory results.
//
// The implementation mirrors the Linux pattern: parseShadowAppsIntoSeen writes
// matches directly into the seen map so the /Applications scan can de-duplicate
// against it in a single pass. count is derived from len(seen) after each step.
func collectShadowAIApps(ctx context.Context, meta map[string]interface{}) int {
	seen := map[string]struct{}{}

	// 1. Running process list: `ps -axo comm`
	psCmd := "/bin/ps"
	psArgs := []string{"-axo", "comm"}
	manifest.Default.RecordExec(psCmd, psArgs)

	out, err := exec.CommandContext(ctx, psCmd, psArgs...).Output()
	if err != nil {
		meta["shadow_ai_ps_unavailable"] = err.Error()
	} else {
		// parseShadowAppsIntoSeen writes all matches into seen; count is derived
		// from len(seen) below to avoid a redundant second parse of out.
		parseShadowAppsIntoSeen(out, seen)
	}

	// 2. /Applications directory listing (no exec — just a directory walk).
	appsDir := "/Applications"
	manifest.Default.RecordFileRead(appsDir)

	entries, err := os.ReadDir(appsDir)
	if err != nil {
		meta["shadow_ai_appdir_unavailable"] = err.Error()
	} else {
		// Build a newline-separated listing to reuse parseShadowAppsFromAppDir.
		var lsBytes []byte
		for _, e := range entries {
			lsBytes = append(lsBytes, []byte(e.Name()+"\n")...)
		}
		parseShadowAppsFromAppDir(lsBytes, seen)
	}

	// Derive count from the unified seen map (matches Linux pattern).
	return len(seen)
}

// collectBrowserExtensionsAI counts AI-assistant browser extensions across
// Chrome, Edge, Brave, and Firefox on macOS.
func collectBrowserExtensionsAI(ctx context.Context, meta map[string]interface{}) int {
	_ = ctx
	home, err := os.UserHomeDir()
	if err != nil {
		meta["browser_ext_home_unavailable"] = err.Error()
		return 0
	}

	count := 0

	// Chromium-family (Chrome, Edge, Brave) share the same extension directory layout:
	// ~/Library/Application Support/<browser>/User Data/<profile>/Extensions/<extID>/<version>/
	// Profiles include "Default" and "Profile N" (one per additional Google account).
	// We enumerate all profile directories to avoid undercounting multi-profile users.
	chromiumUserDataDirs := []string{
		filepath.Join(home, "Library", "Application Support", "Google", "Chrome"),
		filepath.Join(home, "Library", "Application Support", "Microsoft Edge"),
		filepath.Join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser"),
	}

	seen := map[string]struct{}{}
	for _, userDataDir := range chromiumUserDataDirs {
		manifest.Default.RecordFileRead(userDataDir)
		for _, extDir := range enumerateChromiumProfileExtDirs(userDataDir) {
			count += countChromiumAIExtensions(extDir, seen)
		}
	}

	// Firefox: ~/Library/Application Support/Firefox/Profiles/*/extensions.json
	ffProfilesDir := filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	manifest.Default.RecordFileRead(ffProfilesDir)
	count += countFirefoxAIExtensions(ffProfilesDir, meta)

	return count
}

// collectLLMEgressProcesses reads the local socket table via `lsof -nP -iTCP
// -sTCP:ESTABLISHED` to count distinct processes with active connections to
// known LLM API endpoints. ZERO DNS / ZERO network — lsof reads the kernel
// socket table only.
//
// NOTE: -n is intentionally kept to suppress reverse-DNS lookups (which would
// be outbound network calls, violating the netcheck zero-network gate). Because
// -n produces numeric IPs rather than hostnames, hostname matching is replaced
// with CIDR-range matching against bundled LLM-provider prefixes. This is
// BEST-EFFORT — CDN routing and IP rotation mean undercounting is expected.
func collectLLMEgressProcesses(ctx context.Context, meta map[string]interface{}) int {
	lsofCmd := "/usr/sbin/lsof"
	lsofArgs := []string{"-nP", "-iTCP", "-sTCP:ESTABLISHED"}
	manifest.Default.RecordExec(lsofCmd, lsofArgs)

	out, err := exec.CommandContext(ctx, lsofCmd, lsofArgs...).Output()
	if err != nil {
		meta["llm_egress_lsof_unavailable"] = err.Error()
		return 0
	}
	return parseLSOFEgressCountNumeric(out)
}

// collectMCPServers counts running MCP server processes by examining the full
// command-line arguments from `ps -axo args`.
func collectMCPServers(ctx context.Context, meta map[string]interface{}) int {
	psCmd := "/bin/ps"
	psArgs := []string{"-axo", "args"}
	manifest.Default.RecordExec(psCmd, psArgs)

	out, err := exec.CommandContext(ctx, psCmd, psArgs...).Output()
	if err != nil {
		meta["mcp_ps_unavailable"] = err.Error()
		return 0
	}
	return parseMCPCountFromProcessArgs(out)
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// countChromiumAIExtensions walks a Chromium-family extensions directory and
// counts AI assistant extensions by matching extension IDs and manifest names.
func countChromiumAIExtensions(extDir string, seen map[string]struct{}) int {
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return 0
	}
	count := 0
	for _, extEntry := range entries {
		if !extEntry.IsDir() {
			continue
		}
		extID := extEntry.Name()

		// Match by known extension ID (no file content needed).
		if isAIExtensionByID(extID) {
			if _, already := seen[extID]; !already {
				seen[extID] = struct{}{}
				count++
			}
			continue
		}

		// Fallback: read the manifest.json from the most recent version subdirectory.
		extPath := filepath.Join(extDir, extID)
		versionEntries, err := os.ReadDir(extPath)
		if err != nil {
			continue
		}
		for _, vEntry := range versionEntries {
			if !vEntry.IsDir() {
				continue
			}
			manifestPath := filepath.Join(extPath, vEntry.Name(), "manifest.json")
			data, err := os.ReadFile(manifestPath)
			if err != nil {
				continue
			}
			name := parseExtensionManifestJSON(data)
			if name != "" && isAIExtensionByName(name) {
				key := extID + "|" + name
				if _, already := seen[key]; !already {
					seen[key] = struct{}{}
					count++
				}
			}
			break // only check the first (typically only) version directory
		}
	}
	return count
}

// countFirefoxAIExtensions walks Firefox profile directories and parses
// extensions.json to count AI-assistant add-ons.
func countFirefoxAIExtensions(profilesDir string, meta map[string]interface{}) int {
	profiles, err := os.ReadDir(profilesDir)
	if err != nil {
		meta["browser_ext_firefox_unavailable"] = err.Error()
		return 0
	}
	count := 0
	seen := map[string]struct{}{}
	for _, p := range profiles {
		if !p.IsDir() {
			continue
		}
		extFile := filepath.Join(profilesDir, p.Name(), "extensions.json")
		manifest.Default.RecordFileRead(extFile)
		data, err := os.ReadFile(extFile)
		if err != nil {
			continue
		}
		// parseFirefoxExtensionsJSON uses its own internal seen map;
		// we use a global seen here to avoid double-counting across profiles.
		n := parseFirefoxExtensionsJSONWithSeen(data, seen)
		count += n
	}
	return count
}
