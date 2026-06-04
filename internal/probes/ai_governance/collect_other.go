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

//go:build !darwin && !linux && !windows

// Package ai_governance stubs for non-darwin/linux/windows platforms.
// Windows AI governance probes are implemented in collect_windows.go (ENT-108).
package ai_governance

import "context"

func collectShadowAIApps(_ context.Context, meta map[string]interface{}) int {
	meta["shadow_ai_unavailable"] = "platform not supported in LU-4; Windows probes are LU-5"
	return 0
}

func collectBrowserExtensionsAI(_ context.Context, meta map[string]interface{}) int {
	meta["browser_ext_unavailable"] = "platform not supported in LU-4; Windows probes are LU-5"
	return 0
}

func collectLLMEgressProcesses(_ context.Context, meta map[string]interface{}) int {
	meta["llm_egress_unavailable"] = "platform not supported in LU-4; Windows probes are LU-5"
	return 0
}

func collectMCPServers(_ context.Context, meta map[string]interface{}) int {
	meta["mcp_unavailable"] = "platform not supported in LU-4; Windows probes are LU-5"
	return 0
}
