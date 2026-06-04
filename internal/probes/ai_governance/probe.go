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

// Package ai_governance probes for shadow AI tooling: installed LLM desktop apps,
// browser AI extensions, running MCP server processes, and passive LLM egress
// socket detection.
package ai_governance

import (
	"context"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "ai_governance"

// Run executes the AI governance probe for the current platform.
//
// Data collected (all ZERO-NETWORK):
//   - shadow_ai_apps_count: local LLM / AI-assistant apps from process list + app dir
//   - browser_extensions_ai_count: AI-assistant extensions in Chrome/Edge/Firefox
//   - llm_egress_processes_count: processes with ESTABLISHED connections to LLM APIs
//     (reads local socket table via lsof/ss — no DNS, no dials)
//   - mcp_servers_running: MCP server processes from process args
func Run(ctx context.Context) (*common.ProbeResult, error) {
	meta := map[string]interface{}{}

	shadowApps := collectShadowAIApps(ctx, meta)
	browserExt := collectBrowserExtensionsAI(ctx, meta)
	llmEgress := collectLLMEgressProcesses(ctx, meta)
	mcpServers := collectMCPServers(ctx, meta)

	findings := &lstypes.AIGovernanceFindings{
		ShadowAIAppsCount:        shadowApps,
		BrowserExtensionsAICount: browserExt,
		LLMEgressProcessesCount:  llmEgress,
		MCPServersRunning:        mcpServers,
	}

	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: meta,
		ScannerFields: common.ScannerFields{
			AIGovernance: findings,
		},
	}, nil
}

// Manifest returns the static access declaration for the AI governance probe.
// Entries cover all platforms (macOS, Linux, Windows) and are static documentation —
// no build tags; disclosure is unconditional per the SCANNER_MANIFEST transparency promise.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs: []string{
			// macOS — process list
			"/bin/ps -axo comm",
			"/bin/ps -axo args",
			// macOS — socket table (passive, ZERO network)
			"/usr/sbin/lsof -nP -iTCP -sTCP:ESTABLISHED",
			// Linux — process names from /proc/*/comm (file read, no exec)
			"/proc/[0-9]*/comm",
			// Linux — process cmdlines from /proc/*/cmdline
			"/proc/[0-9]*/cmdline",
			// Linux — socket table (passive, ZERO network)
			"ss -tnp state established",
			"netstat -tnp (fallback if ss absent)",
			// Windows — process enumeration (shadow AI apps + MCP servers)
			"CreateToolhelp32Snapshot TH32CS_SNAPPROCESS (Windows kernel32.dll)",
			"Process32First / Process32Next (Windows kernel32.dll — exe name enumeration)",
			// Windows — TCP connection table (LLM egress detection, ESTABLISHED state, ZERO network)
			"iphlpapi.dll GetExtendedTcpTable (Windows — TCP_TABLE_OWNER_PID_ALL, passive ZERO-network)",
		},
		FilePaths: []string{
			// macOS — application directories
			"/Applications/ (directory listing only)",
			"~/Library/Application Support/Google/Chrome/Default/Extensions/ (macOS)",
			"~/Library/Application Support/Microsoft Edge/Default/Extensions/ (macOS)",
			"~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions/ (macOS)",
			"~/Library/Application Support/Firefox/Profiles/*/extensions.json (macOS)",
			// Linux — application directories
			"~/.config/google-chrome/Default/Extensions/ (Linux)",
			"~/.config/chromium/Default/Extensions/ (Linux)",
			"~/.config/microsoft-edge/Default/Extensions/ (Linux)",
			"~/.config/BraveSoftware/Brave-Browser/Default/Extensions/ (Linux)",
			"~/.mozilla/firefox/*/extensions.json (Linux)",
			"~/.local/bin/ (Linux — local app installs)",
			// Windows — registry: installed programs (shadow AI app detection)
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — DisplayName scan)`,
			`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — DisplayName scan)`,
			// Windows — browser extension directories
			`%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\ (Windows — Chrome AI extensions)`,
			`%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions\ (Windows — Edge AI extensions)`,
			`%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Extensions\ (Windows — Brave AI extensions)`,
			`%APPDATA%\Mozilla\Firefox\Profiles\*\extensions.json (Windows — Firefox AI extensions)`,
		},
		NetworkCalls: []string{}, // ZERO — fully offline
	}
}
