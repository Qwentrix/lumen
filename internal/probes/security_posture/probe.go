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
// password manager presence, and open listening ports.
//
// Per-platform collection is split across build-tagged files:
//   - collect_darwin.go  (//go:build darwin)
//   - collect_linux.go   (//go:build linux)
//   - collect_other.go   (//go:build !darwin && !linux) — stub, returns zero values
//
// All collectors record their exec and file-read calls via manifest.Default
// immediately before performing the OS call, so the runtime ledger reflects
// what was attempted even if the call fails.
package security_posture

import (
	"context"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "security_posture"

// Run executes the security posture probe for the current platform.
//
// Data collected (all ZERO-NETWORK):
//   - ssh_keys_count: private keys in ~/.ssh (by header sniff + ssh-keygen -l)
//   - weak_ssh_key_count: keys below RSA-2048 / ECDSA-256 thresholds, or any DSA
//   - password_manager_detected: known PM agent/app in running process list
//   - listening_ports_count: non-loopback TCP/UDP listening ports (lsof/ss)
func Run(ctx context.Context) (*common.ProbeResult, error) {
	meta := map[string]interface{}{}

	sshTotal, sshWeak := collectSSHKeys(ctx, meta)
	pmDetected := collectPasswordManager(ctx, meta)
	listeningPorts := collectListeningPorts(ctx, meta)

	findings := &lstypes.SecurityPostureFindings{
		SSHKeysCount:            sshTotal,
		WeakSSHKeyCount:         sshWeak,
		PasswordManagerDetected: pmDetected,
		ListeningPortsCount:     listeningPorts,
	}

	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: meta,
		ScannerFields: common.ScannerFields{
			SecurityPosture: findings,
		},
	}, nil
}

// Manifest returns the static access declaration for the security posture probe.
// Entries cover all platforms (macOS, Linux, Windows) and are static documentation —
// no build tags; disclosure is unconditional per the SCANNER_MANIFEST transparency promise.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs: []string{
			// macOS — SSH key enumeration
			"/usr/bin/ssh-keygen -l -f <key>",
			// macOS — password manager detection
			"/bin/ps -axo comm",
			// macOS — listening ports
			"/usr/sbin/lsof -nP -iTCP -iUDP -sTCP:LISTEN",
			// Linux — SSH key enumeration
			"/usr/bin/ssh-keygen -l -f <key>",
			// Linux — password manager detection (file read, no exec)
			"/proc/[0-9]*/comm",
			// Linux — listening ports
			"ss -tlnpu (preferred) / netstat -tlnpu (fallback)",
			// Windows — SSH key enumeration
			`C:\Windows\System32\OpenSSH\ssh-keygen.exe -l -f <key> (Windows built-in OpenSSH)`,
			// Windows — password manager detection: process list
			"CreateToolhelp32Snapshot TH32CS_SNAPPROCESS (Windows kernel32.dll — password manager process detection)",
			"Process32First / Process32Next (Windows kernel32.dll — exe name enumeration)",
			// Windows — listening ports via iphlpapi
			"iphlpapi.dll GetExtendedTcpTable (Windows — TCP_TABLE_OWNER_PID_ALL, listening ports)",
			"iphlpapi.dll GetExtendedUdpTable (Windows — UDP_TABLE_OWNER_PID, listening ports)",
		},
		FilePaths: []string{
			"~/.ssh/ (directory listing + first-64-bytes header sniff per file; no private key content read)",
			// Windows — SSH keys location
			`%USERPROFILE%\.ssh\ (Windows — directory listing + header sniff; no private key content read)`,
			// Windows — registry: installed programs (password manager detection)
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — password manager DisplayName scan)`,
			`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — password manager DisplayName scan)`,
		},
		NetworkCalls: []string{}, // ZERO — fully offline
	}
}
