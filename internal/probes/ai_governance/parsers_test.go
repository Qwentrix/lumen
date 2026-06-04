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

// Parser unit tests for the ai_governance probe.
// No build tag — runs on ALL platforms.
package ai_governance

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// ─── parseShadowAppsFromProcessList ──────────────────────────────────────────

func TestParseShadowAppsFromProcessList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty output",
			input: "",
			want:  0,
		},
		{
			name:  "no AI apps",
			input: "bash\nsafari\nfinder\nchrome\n",
			want:  0,
		},
		{
			name:  "ollama running",
			input: "bash\nollama\nfinder\n",
			want:  1,
		},
		{
			name:  "multiple AI apps",
			input: "ollama\ncursor\ngpt4all\n",
			want:  3,
		},
		{
			name:  "duplicate process — counted once",
			input: "ollama\nollama\nollama serve\n",
			want:  1,
		},
		{
			name:  "case-insensitive match",
			input: "OLLAMA\nLMStudio\n",
			want:  2,
		},
		{
			name:  "ChatGPT desktop",
			input: "ChatGPT\nSafari\n",
			want:  1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseShadowAppsFromProcessList([]byte(tc.input))
			if got != tc.want {
				t.Errorf("parseShadowAppsFromProcessList(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// ─── parseShadowAppsFromAppDir ────────────────────────────────────────────────

func TestParseShadowAppsFromAppDir(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "no AI apps",
			input: "Safari.app\nFinder.app\nTextEdit.app\n",
			want:  0,
		},
		{
			name:  "ollama found in app dir",
			input: "Ollama.app\nChrome.app\n",
			want:  1,
		},
		{
			name:  "LM Studio installed",
			input: "LM Studio.app\nFinder.app\n",
			want:  1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seen := map[string]struct{}{}
			got := parseShadowAppsFromAppDir([]byte(tc.input), seen)
			if got != tc.want {
				t.Errorf("parseShadowAppsFromAppDir(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// ─── isAIExtensionByID ────────────────────────────────────────────────────────

func TestIsAIExtensionByID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		// ChatGPT for Google (in allowlist)
		{"jgjaeacdkonaoafenlfkkkmbaopkbilf", true},
		// Grammarly (in allowlist)
		{"kbfnbcaeplbcioakkpcpgfkobkghlhen", true},
		// Random unknown extension
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		// Empty
		{"", false},
		// Upper case — still matches (case-insensitive)
		{"JGJAEACDKONAOAFENLFKKKMBAOPKBILF", true},
	}
	for _, tc := range tests {
		got := isAIExtensionByID(tc.id)
		if got != tc.want {
			t.Errorf("isAIExtensionByID(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

// ─── isAIExtensionByName ──────────────────────────────────────────────────────

func TestIsAIExtensionByName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"ChatGPT Writer", true},
		{"Claude AI Assistant", true},
		{"Perplexity for Chrome", true},
		{"AdBlock Pro", false},
		{"GitHub Copilot", true},
		{"Grammarly for Chrome", true},
		{"Dark Reader", false},
	}
	for _, tc := range tests {
		got := isAIExtensionByName(tc.name)
		if got != tc.want {
			t.Errorf("isAIExtensionByName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ─── parseFirefoxExtensionsJSON ───────────────────────────────────────────────

func TestParseFirefoxExtensionsJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty addons",
			input: `{"addons":[]}`,
			want:  0,
		},
		{
			name: "non-AI addon",
			input: `{"addons":[{"id":"uBlock0@raymondhill.net","name":"uBlock Origin","defaultLocale":{"name":"uBlock Origin"}}]}`,
			want: 0,
		},
		{
			name: "AI addon by name",
			input: `{"addons":[{"id":"chatgpt@ext.example","name":"ChatGPT Writer","defaultLocale":{"name":"ChatGPT Writer"}}]}`,
			want: 1,
		},
		{
			name:  "invalid JSON",
			input: `not json`,
			want:  0,
		},
		{
			name: "two AI addons",
			input: `{"addons":[
				{"id":"foo@bar","name":"Grammarly for Firefox","defaultLocale":{"name":"Grammarly"}},
				{"id":"baz@qux","name":"Claude AI","defaultLocale":{"name":"Claude AI"}}
			]}`,
			want: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseFirefoxExtensionsJSON([]byte(tc.input))
			if got != tc.want {
				t.Errorf("parseFirefoxExtensionsJSON = %d, want %d", got, tc.want)
			}
		})
	}
}

// ─── parseLSOFEgressCount ─────────────────────────────────────────────────────

func TestParseLSOFEgressCount(t *testing.T) {
	// Fixture: lsof -nP -iTCP -sTCP:ESTABLISHED output (abbreviated)
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty output",
			input: "",
			want:  0,
		},
		{
			name:  "no LLM connections",
			input: "node      100  user  10u  IPv4  ...  TCP 10.0.0.1:50000->github.com:443 (ESTABLISHED)\n",
			want:  0,
		},
		{
			name: "one process to openai",
			input: "node      1234  user  10u  IPv4  ...  TCP 10.0.0.1:50001->api.openai.com:443 (ESTABLISHED)\n",
			want:  1,
		},
		{
			name: "two processes to different LLM APIs — distinct PIDs",
			input: "node      1234  user  10u  IPv4  ...  TCP 10.0.0.1:50001->api.openai.com:443 (ESTABLISHED)\n" +
				"python3   5678  user  8u   IPv4  ...  TCP 10.0.0.1:50002->api.anthropic.com:443 (ESTABLISHED)\n",
			want: 2,
		},
		{
			name: "same PID, two LLM connections — counted once",
			input: "node      1234  user  10u  IPv4  ...  TCP 10.0.0.1:50001->api.openai.com:443 (ESTABLISHED)\n" +
				"node      1234  user  11u  IPv4  ...  TCP 10.0.0.1:50002->api.openai.com:443 (ESTABLISHED)\n",
			want: 1,
		},
		{
			name: "anthropic connection",
			input: "curl      9999  user  3u   IPv4  ...  TCP 192.168.1.2:60000->api.anthropic.com:443 (ESTABLISHED)\n",
			want: 1,
		},
		{
			name: "connection to google gemini",
			input: "python3   2222  user  5u   IPv4  ...  TCP 10.0.0.1:55555->generativelanguage.googleapis.com:443 (ESTABLISHED)\n",
			want: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLSOFEgressCount([]byte(tc.input))
			if got != tc.want {
				t.Errorf("parseLSOFEgressCount = %d, want %d", got, tc.want)
			}
		})
	}
}

// ─── parseSSEgressCount ───────────────────────────────────────────────────────

// TestParseSSEgressCount tests the Linux ss-output parser with real ss -tnp
// state established fixture lines.
func TestParseSSEgressCount(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty output",
			input: "",
			want:  0,
		},
		{
			name:  "header only",
			input: "State    Recv-Q  Send-Q  Local Address:Port   Peer Address:Port\n",
			want:  0,
		},
		{
			name:  "no LLM connections",
			input: "ESTAB    0       0       10.0.0.1:54321       140.82.121.3:443    users:((\"git\",pid=99,fd=5))\n",
			want:  0,
		},
		{
			// ss output: ESTAB state, peer is a known LLM hostname (when ss resolves names)
			name: "one process — hostname match",
			input: "ESTAB    0       0       10.0.0.1:56789       api.openai.com:443  users:((\"node\",pid=1234,fd=10))\n",
			want:  1,
		},
		{
			// ss -tnp output: ESTAB state, numeric IP in the OpenAI CIDR range
			name: "one process — numeric IP CIDR match (OpenAI 104.18.x.x range)",
			input: "ESTAB    0       0       192.168.1.2:56789    104.18.12.34:443    users:((\"node\",pid=1234,fd=10))\n",
			want:  1,
		},
		{
			// Two distinct PIDs, both to LLM endpoints
			name: "two processes — distinct PIDs",
			input: "ESTAB    0       0       10.0.0.1:56789    api.openai.com:443     users:((\"node\",pid=1234,fd=10))\n" +
				"ESTAB    0       0       10.0.0.1:56790    api.anthropic.com:443  users:((\"python3\",pid=5678,fd=8))\n",
			want: 2,
		},
		{
			// Same PID, two connections — counted once
			name: "same PID — two LLM connections",
			input: "ESTAB    0       0       10.0.0.1:56789    api.openai.com:443   users:((\"node\",pid=1234,fd=10))\n" +
				"ESTAB    0       0       10.0.0.1:56790    api.openai.com:443   users:((\"node\",pid=1234,fd=11))\n",
			want: 1,
		},
		{
			// No PID available (non-root run) — fallback to remote address counting
			name: "no PID token — fallback to remote count",
			input: "ESTAB    0       0       10.0.0.1:56789    api.openai.com:443\n" +
				"ESTAB    0       0       10.0.0.1:56790    api.anthropic.com:443\n",
			want: 2,
		},
		{
			// No PID — same remote, counted once
			name: "no PID — same remote twice — counted once",
			input: "ESTAB    0       0       10.0.0.1:56789    api.openai.com:443\n" +
				"ESTAB    0       0       10.0.0.1:56790    api.openai.com:443\n",
			want: 1,
		},
		{
			// Real ss -tnp output format with state filter (no header):
			// ss -tnp state established produces no header row
			name: "real ss fixture — openai numeric CIDR",
			input: "ESTAB      0      0      192.168.1.100:45678      104.18.7.192:443   users:((\"node\",pid=9999,fd=27))\n",
			want:  1,
		},
		{
			// Non-ESTAB lines (LISTEN, etc.) must be ignored
			name: "non-ESTAB lines ignored",
			input: "LISTEN     0      128    0.0.0.0:22           0.0.0.0:*\n" +
				"ESTAB      0      0      10.0.0.1:56789    api.openai.com:443   users:((\"node\",pid=1234,fd=10))\n",
			want: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSSEgressCount([]byte(tc.input))
			if got != tc.want {
				t.Errorf("parseSSEgressCount = %d, want %d", got, tc.want)
			}
		})
	}
}

// ─── matchesLLMCIDR ───────────────────────────────────────────────────────────

func TestMatchesLLMCIDR(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// OpenAI / Fastly ranges
		{"104.18.12.34", true},
		{"104.19.200.1", true},
		// Anthropic / Cloudflare
		{"104.21.5.100", true},
		{"172.67.180.1", true},
		// Google AI Platform
		{"34.127.0.1", true},
		// Azure OpenAI
		{"40.74.100.50", true},
		{"52.230.10.1", true},
		// Not LLM
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"140.82.121.3", false}, // GitHub
		// Invalid IP
		{"not-an-ip", false},
		{"", false},
	}
	for _, tc := range tests {
		got := matchesLLMCIDR(tc.ip)
		if got != tc.want {
			t.Errorf("matchesLLMCIDR(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// ─── parseLSOFEgressCountNumeric ──────────────────────────────────────────────

func TestParseLSOFEgressCountNumeric(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty",
			input: "",
			want:  0,
		},
		{
			name: "numeric IP in OpenAI CIDR",
			// lsof -nP output: numeric IP, ESTABLISHED
			input: "node    1234 user  10u  IPv4  12345  0t0  TCP 192.168.1.1:55000->104.18.12.34:443 (ESTABLISHED)\n",
			want:  1,
		},
		{
			name: "numeric IP not in any LLM CIDR",
			input: "node    1234 user  10u  IPv4  12345  0t0  TCP 192.168.1.1:55000->8.8.8.8:443 (ESTABLISHED)\n",
			want:  0,
		},
		{
			name: "hostname in lsof output (some lsof ignore -n)",
			input: "node    1234 user  10u  IPv4  12345  0t0  TCP 192.168.1.1:55000->api.openai.com:443 (ESTABLISHED)\n",
			want:  1,
		},
		{
			name: "two distinct PIDs in CIDR range",
			input: "node    1234 user  10u  IPv4  12345  0t0  TCP 192.168.1.1:55000->104.18.12.34:443 (ESTABLISHED)\n" +
				"python3 5678 user  8u   IPv4  12346  0t0  TCP 192.168.1.1:55001->172.67.1.5:443 (ESTABLISHED)\n",
			want: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLSOFEgressCountNumeric([]byte(tc.input))
			if got != tc.want {
				t.Errorf("parseLSOFEgressCountNumeric = %d, want %d", got, tc.want)
			}
		})
	}
}

// ─── matchesLLMHost ───────────────────────────────────────────────────────────

func TestMatchesLLMHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"api.openai.com", true},
		{"api.anthropic.com", true},
		{"generativelanguage.googleapis.com", true},
		{"api.mistral.ai", true},
		{"github.com", false},
		{"google.com", false},
		{"", false},
		// Subdomain matching
		{"sub.api.openai.com", true},
	}
	for _, tc := range tests {
		got := matchesLLMHost(tc.host)
		if got != tc.want {
			t.Errorf("matchesLLMHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// ─── parseMCPCountFromProcessArgs ─────────────────────────────────────────────

func TestParseMCPCountFromProcessArgs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "no MCP servers",
			input: "bash\nnginx\npython3 server.py\n",
			want:  0,
		},
		{
			name:  "one MCP server by name",
			input: "node mcp-server --port 8080\nbash\n",
			want:  1,
		},
		{
			name:  "npx MCP server",
			input: "npx @modelcontextprotocol/server-filesystem /tmp\nbash\n",
			want:  1,
		},
		{
			name:  "duplicate cmdline — counted once",
			input: "node mcp-server\nnode mcp-server\n",
			want:  1,
		},
		{
			name:  "multiple distinct MCP servers",
			input: "node mcp-server\nnpx @modelcontextprotocol/server-github\n",
			want:  2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMCPCountFromProcessArgs([]byte(tc.input))
			if got != tc.want {
				t.Errorf("parseMCPCountFromProcessArgs = %d, want %d", got, tc.want)
			}
		})
	}
}

// ─── enumerateChromiumProfileExtDirs (M-5) ───────────────────────────────────

// TestEnumerateChromiumProfileExtDirs verifies that multi-profile Chromium
// user data directories are fully enumerated (M-5 fix regression guard).
//
// The fixture creates a User Data tree with:
//   - Default/  (must be included)
//   - Profile 1/ (must be included)
//   - Profile 2/ (must be included)
//   - Snapshots/ (not a profile dir — must be excluded)
//   - System Profile/ (not a "Profile N" dir — must be excluded)
func TestEnumerateChromiumProfileExtDirs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create profile and non-profile directories.
	profileDirs := []string{"Default", "Profile 1", "Profile 2"}
	nonProfileDirs := []string{"Snapshots", "System Profile", "GrShaderCache"}

	for _, d := range append(profileDirs, nonProfileDirs...) {
		extPath := filepath.Join(tmpDir, d, "Extensions")
		if err := os.MkdirAll(extPath, 0755); err != nil {
			t.Fatalf("MkdirAll %q: %v", extPath, err)
		}
	}

	got := enumerateChromiumProfileExtDirs(tmpDir)

	// Build expected set.
	expected := map[string]struct{}{}
	for _, d := range profileDirs {
		expected[filepath.Join(tmpDir, d, "Extensions")] = struct{}{}
	}

	// Verify: all expected dirs are present.
	sort.Strings(got)
	for _, dir := range got {
		if _, ok := expected[dir]; !ok {
			t.Errorf("enumerateChromiumProfileExtDirs: unexpected dir %q in result", dir)
		}
		delete(expected, dir)
	}
	for missing := range expected {
		t.Errorf("enumerateChromiumProfileExtDirs: expected dir %q missing from result", missing)
	}

	// Verify count matches.
	if len(got) != len(profileDirs) {
		t.Errorf("enumerateChromiumProfileExtDirs: got %d dirs, want %d", len(got), len(profileDirs))
	}

	// Non-profile dirs must NOT appear.
	gotSet := map[string]struct{}{}
	for _, d := range got {
		gotSet[d] = struct{}{}
	}
	for _, d := range nonProfileDirs {
		excluded := filepath.Join(tmpDir, d, "Extensions")
		if _, present := gotSet[excluded]; present {
			t.Errorf("enumerateChromiumProfileExtDirs: non-profile dir %q should be excluded", excluded)
		}
	}
}

// TestEnumerateChromiumProfileExtDirs_Empty verifies that a nonexistent
// User Data directory returns nil gracefully (no panic).
func TestEnumerateChromiumProfileExtDirs_Empty(t *testing.T) {
	got := enumerateChromiumProfileExtDirs("/nonexistent/path/that/does/not/exist")
	if got != nil {
		t.Errorf("expected nil for nonexistent dir, got %v", got)
	}
}
