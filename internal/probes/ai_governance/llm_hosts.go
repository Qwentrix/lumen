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

package ai_governance

// llmAPIHosts is the bundled static allowlist of well-known commercial LLM API
// hostnames. Matching is done against remote addresses that the OS already
// reports as ESTABLISHED in the local socket table — this is passive observation
// of existing connections, not a network dial.
//
// The list is intentionally conservative (commercial API providers only) to
// minimise false positives. Trailing dots are omitted; matching is substring-
// based on the remote host token extracted from the socket table.
//
// When lsof is invoked with -n (numeric IPs), hostname matching is impossible.
// In that case, matchesLLMCIDR is used to check against the CIDR ranges below.
// IMPORTANT: LLM providers use CDNs and rotate IPs aggressively. CIDR matching
// is BEST-EFFORT — undercounting is expected and normal (false negatives only,
// never false positives). See comment on llmProviderCIDRs for details.
//
// Documented in SCANNER_MANIFEST.md §AI-Governance.
var llmAPIHosts = []string{
	// OpenAI
	"api.openai.com",
	"openai.com",
	// Anthropic (Claude)
	"api.anthropic.com",
	"anthropic.com",
	// Google Gemini / PaLM
	"generativelanguage.googleapis.com",
	"aiplatform.googleapis.com",
	// Mistral AI
	"api.mistral.ai",
	"mistral.ai",
	// Cohere
	"api.cohere.ai",
	"cohere.ai",
	// Hugging Face Inference API
	"api-inference.huggingface.co",
	"huggingface.co",
	// Perplexity
	"api.perplexity.ai",
	"perplexity.ai",
	// Together AI
	"api.together.xyz",
	"together.xyz",
	// Groq
	"api.groq.com",
	"groq.com",
	// Replicate
	"api.replicate.com",
	"replicate.com",
	// AWS Bedrock (regional endpoints share this pattern)
	"bedrock-runtime.amazonaws.com",
	"bedrock.amazonaws.com",
	// Azure OpenAI
	"openai.azure.com",
	// Fireworks AI
	"api.fireworks.ai",
	// Deepseek
	"api.deepseek.com",
	"deepseek.com",
	// xAI (Grok)
	"api.x.ai",
}

// mcpServerNames is the bundled list of known MCP (Model Context Protocol) server
// process names and command-line substrings. Matching is done via
// strings.Contains (literal), so every entry must be a literal substring of
// the process command line — regexp metacharacters are NOT interpreted.
var mcpServerNames = []string{
	"mcp-server",
	"@modelcontextprotocol",
	"modelcontextprotocol",
	"mcp_server",
	// Specific known MCP servers
	"filesystem-mcp",
	"github-mcp",
	"sqlite-mcp",
	"postgres-mcp",
	"brave-search-mcp",
	"fetch-mcp",
	"memory-mcp",
	"sequentialthinking",
	"puppeteer-mcp",
	"everything-mcp",
	// npx-launched MCP servers: match the literal substrings that appear in
	// real npx invocations. The old "npx.*mcp" entry looked like a regex but
	// was matched via strings.Contains and never fired. Replaced with literals.
	"npx @modelcontextprotocol",
	"-mcp",
}

// llmProviderCIDRs is a curated list of known IP CIDR ranges for major LLM
// API providers. Used when only numeric IPs are available (e.g. lsof -n on
// macOS) and hostname matching is not possible.
//
// BEST-EFFORT ONLY: These providers use Anycast, CDNs, and frequently rotate
// IP allocations. Undercounting (false negatives) is expected and normal.
// This list is conservative — only statically-announced prefixes from published
// BGP/ARIN records as of 2026-06. It is NOT a complete inventory.
//
// Sources (public, no network calls required):
//   - OpenAI:     AS54113 (Fastly) + dedicated /24s under 104.18.x.x
//   - Anthropic:  Cloudflare AS13335 shared ranges
//   - Azure OpenAI: Azure public IP space (40.74.0.0/15, 52.224.0.0/13)
//   - Google AI:  Google Cloud 34.64.0.0/10
var llmProviderCIDRs = []string{
	// OpenAI — primary API ranges (Fastly + own)
	"104.18.0.0/16",
	"104.19.0.0/16",
	// Anthropic — Cloudflare-fronted
	"104.21.0.0/16",
	"172.64.0.0/13",
	// Azure OpenAI — Azure public ranges
	"40.74.0.0/15",
	"52.224.0.0/13",
	// Google AI Platform / Gemini — Google Cloud
	"34.64.0.0/10",
	"35.186.0.0/18",
}

// shadowAIAppNames is the bundled list of known local LLM / AI desktop application
// names and process names. Matching is case-insensitive substring-based.
var shadowAIAppNames = []string{
	// Local LLM runtimes
	"ollama",
	"lm studio",
	"lmstudio",
	"lm_studio",
	"gpt4all",
	"jan",
	"localai",
	"local.ai",
	"koboldcpp",
	"kobold",
	"llamafile",
	"llama.cpp",
	"llamacpp",
	// AI-native editors / coding assistants
	"cursor",
	// Cloud-backed but locally-installed AI apps
	"claude",       // Claude Desktop
	"chatgpt",      // ChatGPT Desktop
	// Image / multimodal AI tools
	"comfyui",
	"invokeai",
	"automatic1111",
	"stable diffusion",
	"stablediffusion",
}

// aiExtensionIDs is the allowlist of Chrome/Edge/Brave extension IDs known to be
// AI-assistant extensions. Used for exact-ID matching against the installed
// extension directory names.
var aiExtensionIDs = []string{
	// ChatGPT for Google
	"jgjaeacdkonaoafenlfkkkmbaopkbilf",
	// Merlin AI
	"camppjleccjaphfdbohjdohecfnoikec",
	// Perplexity AI
	"hlgbcneanomplepojfcnclggenpcoldo",
	// Monica AI
	"ofpnmcalabcbjgholdjcjblkibolbppb",
	// Compose AI (autocomplete)
	"ddlbpiadoechcolndfekhkhlionaphdj",
	// Jasper AI
	"lpdmpomlknokmibfammcehgkjfhagfoo",
	// Glasp (AI note-taking)
	"blillmbchncajnhkjfdnincfndboieik",
	// Wordtune
	"nllcnknpjnininklegdoijpljgdjkijc",
	// Grammarly (AI writing)
	"kbfnbcaeplbcioakkpcpgfkobkghlhen",
	// Copilot (GitHub / Microsoft)
	"fhcgcagknlognfgeaidagmfomfodijod",
	// Claude AI extension (unofficial)
	"aejalnccbocfanfdacmpkjohkjakgbfn",
}

// aiExtensionNameSubstrings is the list of name substrings used to match AI
// extensions by display name in Firefox's extensions.json, or when an extension's
// manifest.json name contains one of these strings.
var aiExtensionNameSubstrings = []string{
	"chatgpt",
	"claude",
	"gemini",
	"copilot",
	"ai assistant",
	"ai chat",
	"ai writer",
	"perplexity",
	"grammarly",
	"writesonic",
	"jasper",
	"compose ai",
	"wordtune",
	"gpt",
	"llm",
	"openai",
	"anthropic",
	"bard",
	"merlin",
	"monica",
	"otter.ai",
	"glasp",
}
