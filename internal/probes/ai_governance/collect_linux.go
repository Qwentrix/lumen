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

package ai_governance

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Qwentrix/lumen/internal/manifest"
)

// collectShadowAIApps enumerates running processes and ~/.local/share/applications
// to detect local LLM / AI-assistant apps on Linux.
func collectShadowAIApps(ctx context.Context, meta map[string]interface{}) int {
	seen := map[string]struct{}{}
	count := 0

	// 1. Running process list via /proc/*/comm (no exec, no sudo).
	manifest.Default.RecordFileRead("/proc")
	procComm, err := readAllProcComm()
	if err != nil {
		meta["shadow_ai_proc_unavailable"] = err.Error()
	} else {
		parseShadowAppsIntoSeen(procComm, seen)
		count += len(seen)
	}

	// 2. ~/.local/bin directory (AppImages, symlinks, local installs).
	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		localBin := filepath.Join(home, ".local", "bin")
		manifest.Default.RecordFileRead(localBin)
		if entries, err := os.ReadDir(localBin); err == nil {
			var lsBytes []byte
			for _, e := range entries {
				lsBytes = append(lsBytes, []byte(e.Name()+"\n")...)
			}
			count += parseShadowAppsFromAppDir(lsBytes, seen)
		}
	}

	// 3. Ollama-specific: check if the `ollama` binary exists in standard paths.
	for _, p := range []string{"/usr/local/bin/ollama", "/usr/bin/ollama"} {
		if _, err := os.Stat(p); err == nil {
			if _, already := seen["ollama"]; !already {
				seen["ollama"] = struct{}{}
				count++
			}
			break
		}
	}

	_ = ctx
	return count
}

// readAllProcComm reads /proc/*/comm into a single newline-separated byte slice.
func readAllProcComm() ([]byte, error) {
	entries, err := filepath.Glob("/proc/[0-9]*/comm")
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, path := range entries {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		out = append(out, data...)
		// Ensure newline separation.
		if len(data) > 0 && data[len(data)-1] != '\n' {
			out = append(out, '\n')
		}
	}
	return out, nil
}

// collectBrowserExtensionsAI counts AI-assistant browser extensions across
// Chrome, Edge (Linux), and Firefox on Linux.
func collectBrowserExtensionsAI(ctx context.Context, meta map[string]interface{}) int {
	_ = ctx
	home, err := os.UserHomeDir()
	if err != nil {
		meta["browser_ext_home_unavailable"] = err.Error()
		return 0
	}

	count := 0
	seen := map[string]struct{}{}

	// Chromium-family on Linux. Each browser's "User Data" root may contain
	// multiple profile directories ("Default", "Profile 1", "Profile 2", …).
	// We enumerate all profiles to avoid undercounting multi-profile users.
	chromiumUserDataDirs := []string{
		filepath.Join(home, ".config", "google-chrome"),
		filepath.Join(home, ".config", "chromium"),
		filepath.Join(home, ".config", "microsoft-edge"),
		filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser"),
	}
	for _, userDataDir := range chromiumUserDataDirs {
		manifest.Default.RecordFileRead(userDataDir)
		for _, extDir := range enumerateChromiumProfileExtDirs(userDataDir) {
			count += countChromiumAIExtensions(extDir, seen)
		}
	}

	// Firefox: ~/.mozilla/firefox/*/extensions.json
	ffProfilesDir := filepath.Join(home, ".mozilla", "firefox")
	manifest.Default.RecordFileRead(ffProfilesDir)
	count += countFirefoxAIExtensions(ffProfilesDir, meta)

	return count
}

// collectLLMEgressProcesses reads the local socket table via `ss -tnp state
// established` to count distinct processes with active connections to known
// LLM API endpoints. ZERO DNS / ZERO network — ss reads the kernel socket
// table only.
func collectLLMEgressProcesses(ctx context.Context, meta map[string]interface{}) int {
	// Prefer `ss` (iproute2); fall back to `netstat`.
	ssCmd := resolveLinuxAbsPath("ss", []string{"/usr/sbin/ss", "/sbin/ss", "/bin/ss"}, meta)
	if ssCmd != "" {
		ssArgs := []string{"-tnp", "state", "established"}
		manifest.Default.RecordExec(ssCmd, ssArgs)
		out, err := exec.CommandContext(ctx, ssCmd, ssArgs...).Output()
		if err == nil {
			return parseSSEgressCount(out)
		}
		meta["llm_egress_ss_error"] = err.Error()
	}

	// Fallback: netstat -tnp (shows established connections with process info).
	nsCmd := resolveLinuxAbsPath("netstat", []string{"/usr/sbin/netstat", "/sbin/netstat"}, meta)
	if nsCmd == "" {
		meta["llm_egress_unavailable"] = "ss and netstat not found"
		return 0
	}
	nsArgs := []string{"-tnp"}
	manifest.Default.RecordExec(nsCmd, nsArgs)
	out, err := exec.CommandContext(ctx, nsCmd, nsArgs...).Output()
	if err != nil {
		meta["llm_egress_netstat_error"] = err.Error()
		return 0
	}
	return parseSSEgressCount(out)
}

// collectMCPServers counts running MCP server processes via /proc/*/cmdline.
func collectMCPServers(_ context.Context, meta map[string]interface{}) int {
	manifest.Default.RecordFileRead("/proc")
	entries, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		meta["mcp_proc_unavailable"] = err.Error()
		return 0
	}
	var combined []byte
	for _, path := range entries {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// /proc/*/cmdline separates args with NUL bytes; replace with spaces.
		for i, b := range data {
			if b == 0 {
				data[i] = ' '
			}
		}
		combined = append(combined, data...)
		combined = append(combined, '\n')
	}
	return parseMCPCountFromProcessArgs(combined)
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

		if isAIExtensionByID(extID) {
			if _, already := seen[extID]; !already {
				seen[extID] = struct{}{}
				count++
			}
			continue
		}

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
			break
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
		n := parseFirefoxExtensionsJSONWithSeen(data, seen)
		count += n
	}
	return count
}

// resolveLinuxAbsPath returns the absolute path of a binary on Linux.
// Mirrors the resolveAbsPath helper in the compliance probe.
func resolveLinuxAbsPath(name string, candidates []string, meta map[string]interface{}) string {
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
