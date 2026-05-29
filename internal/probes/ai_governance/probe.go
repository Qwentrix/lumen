// Package ai_governance probes for shadow AI tooling: installed LLM desktop apps,
// browser AI extensions, running MCP server processes, and passive LLM egress
// socket detection.
// TODO (LU-4): implement per-platform checks.
package ai_governance

import (
	"context"

	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "ai_governance"

// Run executes the AI governance probe for the current platform.
func Run(ctx context.Context) (*common.ProbeResult, error) {
	// TODO: implement installed_apps_*.go (LM Studio, Ollama, Claude Desktop,
	// ChatGPT Desktop, Cursor, etc.), browser_extensions_*.go, mcp_processes.go,
	// llm_egress.go via build tags.
	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: map[string]interface{}{"status": "stub"},
	}, nil
}

// Manifest returns the static access declaration for the AI governance probe.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs: []string{
			"Running process list (passive — no traffic capture)",
			"Chrome / Firefox / Edge extension manifests in user profile",
			"Installed application list",
		},
		FilePaths: []string{
			"~/.config/google-chrome/Default/Extensions/ (Linux)",
			"~/Library/Application Support/Google/Chrome/Default/Extensions/ (macOS)",
		},
		NetworkCalls: []string{},
	}
}
