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

// Package security_posture probes overall security hygiene: SSH key strength,
// password manager presence, browser security settings, startup items, and
// open listening ports.
// TODO (LU-4): implement per-platform checks.
package security_posture

import (
	"context"

	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "security_posture"

// Run executes the security posture probe for the current platform.
func Run(ctx context.Context) (*common.ProbeResult, error) {
	// TODO: implement ssh_keys.go, password_manager_*.go, browser_config_*.go,
	// startup_items_*.go, listening_ports_*.go via build tags.
	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: map[string]interface{}{"status": "stub"},
	}, nil
}

// Manifest returns the static access declaration for the security posture probe.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs: []string{
			"ssh-keygen -l (enumerate ~/.ssh key bit-lengths)",
			"launchctl list (macOS startup items)",
			"systemctl --user list-units (Linux)",
			"netstat -tlnp / lsof -i / Get-NetTCPConnection (listening ports)",
		},
		FilePaths: []string{
			"~/.ssh/ (key enumeration — no private key content read)",
			"~/Library/Application Support/*/browser security prefs (macOS)",
		},
		NetworkCalls: []string{},
	}
}
