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

package security_posture

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Qwentrix/lumen/internal/manifest"
)

// collectSSHKeys enumerates private SSH keys in ~/.ssh and checks each one's
// bit-length via `ssh-keygen -l -f`. Returns (total, weak) counts.
//
// Only files that are identifiable as SSH private keys (PEM headers or
// OpenSSH format) are inspected; public keys (.pub) are skipped.
// No private key material is read — ssh-keygen reads the file itself.
func collectSSHKeys(ctx context.Context, meta map[string]interface{}) (total, weak int) {
	home, err := os.UserHomeDir()
	if err != nil {
		meta["ssh_keys_home_unavailable"] = err.Error()
		return 0, 0
	}
	sshDir := filepath.Join(home, ".ssh")
	manifest.Default.RecordFileRead(sshDir)

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		meta["ssh_keys_dir_unavailable"] = err.Error()
		return 0, 0
	}

	// errorCount tracks ssh-keygen invocation errors. A counter is used instead
	// of recording the filename to avoid leaking private key filenames into
	// probe metadata (privacy probe path-omission discipline).
	errorCount := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip known non-key files.
		if strings.HasSuffix(name, ".pub") ||
			name == "known_hosts" ||
			name == "authorized_keys" ||
			name == "config" ||
			strings.HasPrefix(name, ".") {
			continue
		}

		keyPath := filepath.Join(sshDir, name)
		// Quick sniff: read first 50 bytes to check for PEM/OpenSSH header.
		if !looksLikePrivateKey(keyPath) {
			continue
		}

		info := probeSSHKeyLen(ctx, keyPath, &errorCount)
		if info.bits == 0 && info.keyType == "" {
			// ssh-keygen couldn't parse it — not a key file.
			continue
		}
		total++
		if info.isWeak {
			weak++
		}
	}
	if errorCount > 0 {
		meta["ssh_keygen_error_count"] = errorCount
	}
	return total, weak
}

// probeSSHKeyLen runs `ssh-keygen -l -f <path>` to get the key bit-length.
// ssh-keygen reads the file itself; we pass only the path.
// errorCount is incremented (not the filename) to avoid leaking filenames into metadata.
func probeSSHKeyLen(ctx context.Context, keyPath string, errorCount *int) sshKeyInfo {
	cmd := "/usr/bin/ssh-keygen"
	args := []string{"-l", "-f", keyPath}
	manifest.Default.RecordExec(cmd, args)

	out, err := exec.CommandContext(ctx, cmd, args...).Output()
	if err != nil {
		// Not fatal — file may not be parseable by ssh-keygen.
		// Increment counter instead of recording filename (privacy discipline).
		*errorCount++
		return sshKeyInfo{}
	}
	return parseSSHKeygenOutput(out)
}

// collectPasswordManager checks whether a known password manager agent or
// desktop application is running on macOS.
func collectPasswordManager(ctx context.Context, meta map[string]interface{}) bool {
	psCmd := "/bin/ps"
	psArgs := []string{"-axo", "comm"}
	manifest.Default.RecordExec(psCmd, psArgs)

	out, err := exec.CommandContext(ctx, psCmd, psArgs...).Output()
	if err != nil {
		meta["pm_ps_unavailable"] = err.Error()
		return false
	}
	return parsePasswordManagerFromProcessList(out)
}

// collectListeningPorts counts non-loopback TCP/UDP listening ports via lsof.
func collectListeningPorts(ctx context.Context, meta map[string]interface{}) int {
	// lsof -nP -iTCP -iUDP -sTCP:LISTEN enumerates listening sockets.
	// -nP: numeric hosts and ports (no DNS, no port-name lookup — ZERO network).
	lsofCmd := "/usr/sbin/lsof"
	lsofArgs := []string{"-nP", "-iTCP", "-iUDP", "-sTCP:LISTEN"}
	manifest.Default.RecordExec(lsofCmd, lsofArgs)

	out, err := exec.CommandContext(ctx, lsofCmd, lsofArgs...).Output()
	if err != nil {
		meta["listening_ports_lsof_unavailable"] = err.Error()
		return 0
	}
	return parseListeningPortsLSOF(out)
}
