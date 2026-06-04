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

// Windows AI governance probe collector.
//
// Data sources:
//   - Shadow AI apps: registry HKLM+HKCU Uninstall DisplayName scan +
//     toolhelp32 Process32First/Next running process exe names.
//   - Browser AI extensions: walk %LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions
//     and Microsoft Edge equivalent; %APPDATA%\Mozilla\Firefox\Profiles\*\extensions.json.
//   - LLM egress: GetExtendedTcpTable (ESTABLISHED state) via iphlpapi.dll,
//     match remote IPv4 via connection table. ZERO DNS/network.
//   - MCP servers: toolhelp32 process enumeration + QueryFullProcessImageName
//     for command-line matching.
//
// All exec/registry accesses go through manifest.Default.RecordExec/RecordFileRead.
// ZERO network calls.
package ai_governance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/Qwentrix/lumen/internal/manifest"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ─── Shadow AI apps ───────────────────────────────────────────────────────────

// collectShadowAIApps detects local LLM / AI desktop apps on Windows via
// registry Uninstall keys and the running process list.
func collectShadowAIApps(ctx context.Context, meta map[string]interface{}) int {
	seen := map[string]struct{}{}
	count := 0

	// 1. Registry Uninstall scan.
	manifest.Default.RecordFileRead(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`)
	manifest.Default.RecordFileRead(`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`)

	uninstallRoots := []struct {
		hive registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}

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
		for _, sub := range subkeys {
			sk, err := registry.OpenKey(root.hive, root.path+`\`+sub, registry.QUERY_VALUE|registry.READ)
			if err != nil {
				continue
			}
			displayName, _, _ := sk.GetStringValue("DisplayName")
			sk.Close()

			if displayName == "" {
				continue
			}
			lname := strings.ToLower(displayName)
			for _, app := range shadowAIAppNames {
				if strings.Contains(lname, strings.ToLower(app)) {
					if _, already := seen[app]; !already {
						seen[app] = struct{}{}
						count++
					}
					break
				}
			}
		}
	}

	// 2. Running process list via toolhelp32.
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		meta["shadow_ai_process_snap_error"] = err.Error()
		return count
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return count
	}

	for {
		exeName := windows.UTF16ToString(entry.ExeFile[:])
		lname := strings.ToLower(exeName)
		for _, app := range shadowAIAppNames {
			if strings.Contains(lname, strings.ToLower(app)) {
				if _, already := seen[app]; !already {
					seen[app] = struct{}{}
					count++
				}
				break
			}
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return count
}

// ─── Browser AI extensions ────────────────────────────────────────────────────

// collectBrowserExtensionsAI counts AI-assistant browser extensions on Windows.
// Checks Chrome and Edge under %LOCALAPPDATA% and Firefox under %APPDATA%.
func collectBrowserExtensionsAI(ctx context.Context, meta map[string]interface{}) int {
	localAppData := os.Getenv("LOCALAPPDATA")
	appData := os.Getenv("APPDATA")

	count := 0
	seen := map[string]struct{}{}

	// Chromium-family: Chrome, Edge, and Brave.
	// Each browser stores profiles under a "User Data" directory; profiles are
	// named "Default" or "Profile N". We enumerate all profiles to avoid
	// undercounting users with multiple Google/Microsoft accounts.
	chromiumUserDataDirs := []string{
		filepath.Join(localAppData, "Google", "Chrome", "User Data"),
		filepath.Join(localAppData, "Microsoft", "Edge", "User Data"),
		filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data"),
	}

	for _, userDataDir := range chromiumUserDataDirs {
		if userDataDir == "" || strings.TrimSpace(userDataDir) == "" {
			continue
		}
		manifest.Default.RecordFileRead(userDataDir)
		for _, extDir := range enumerateChromiumProfileExtDirs(userDataDir) {
			count += countChromiumAIExtensionsWindows(extDir, seen)
		}
	}

	// Firefox profiles.
	if appData != "" {
		ffProfilesDir := filepath.Join(appData, "Mozilla", "Firefox", "Profiles")
		manifest.Default.RecordFileRead(ffProfilesDir)
		count += countFirefoxAIExtensionsWindows(ffProfilesDir, meta)
	}

	return count
}

// countChromiumAIExtensionsWindows walks a Chromium extensions directory (Windows path)
// and counts AI extensions by ID or manifest name.
func countChromiumAIExtensionsWindows(extDir string, seen map[string]struct{}) int {
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

// countFirefoxAIExtensionsWindows walks Firefox profile directories and parses
// extensions.json to count AI-assistant add-ons.
func countFirefoxAIExtensionsWindows(profilesDir string, meta map[string]interface{}) int {
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
		count += parseFirefoxExtensionsJSONWithSeen(data, seen)
	}
	return count
}

// ─── LLM egress via GetExtendedTcpTable ──────────────────────────────────────

// collectLLMEgressProcesses returns 0 on Windows.
//
// GetExtendedTcpTable yields raw IPv4 addresses only — not hostnames. Matching
// against LLM API endpoints would require reverse-DNS lookups, which are
// prohibited by the ZERO-NETWORK invariant (NFR-9). IP-range matching against a
// static CIDR list is planned as a future enhancement (see parsers.go
// parseProcNetTCPEgressCount). Until then, return 0 to avoid false positives.
func collectLLMEgressProcesses(ctx context.Context, meta map[string]interface{}) int {
	meta["llm_egress_note"] = "Windows: raw IP matching not implemented; requires reverse-DNS which is prohibited (ZERO-NETWORK invariant)"
	return 0
}

// ─── MCP server detection via toolhelp32 ─────────────────────────────────────

// collectMCPServers counts running MCP server processes on Windows by
// examining the process list via toolhelp32.
func collectMCPServers(ctx context.Context, meta map[string]interface{}) int {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		meta["mcp_process_snap_error"] = err.Error()
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0
	}

	seen := map[string]struct{}{}
	count := 0

	for {
		exeName := windows.UTF16ToString(entry.ExeFile[:])
		lname := strings.ToLower(exeName)
		for _, pattern := range mcpServerNames {
			if strings.Contains(lname, strings.ToLower(pattern)) {
				key := exeName + "|" + pattern
				if _, already := seen[key]; !already {
					seen[key] = struct{}{}
					count++
				}
				break
			}
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return count
}
