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

	// Resolve ssh-keygen path (no PATH hijacking).
	skCmd := resolveSecAbsPath("ssh-keygen", []string{"/usr/bin/ssh-keygen", "/usr/local/bin/ssh-keygen"}, meta)

	// errorCount tracks ssh-keygen invocation errors. A counter is used instead
	// of recording the filename to avoid leaking private key filenames into
	// probe metadata (privacy probe path-omission discipline).
	errorCount := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".pub") ||
			name == "known_hosts" ||
			name == "authorized_keys" ||
			name == "config" ||
			strings.HasPrefix(name, ".") {
			continue
		}

		keyPath := filepath.Join(sshDir, name)
		if !looksLikePrivateKey(keyPath) {
			continue
		}

		var info sshKeyInfo
		if skCmd != "" {
			info = probeSSHKeyLen(ctx, skCmd, keyPath, &errorCount)
		}
		if info.bits == 0 && info.keyType == "" {
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

// looksLikePrivateKey is defined in parsers.go (no build tag) and shared by all OS collectors.

// probeSSHKeyLen runs `ssh-keygen -l -f <path>` to get the key bit-length.
// errorCount is incremented on failure (not the filename) to avoid leaking
// private key filenames into metadata (privacy probe path-omission discipline).
func probeSSHKeyLen(ctx context.Context, sshKeygenCmd, keyPath string, errorCount *int) sshKeyInfo {
	args := []string{"-l", "-f", keyPath}
	manifest.Default.RecordExec(sshKeygenCmd, args)

	out, err := exec.CommandContext(ctx, sshKeygenCmd, args...).Output()
	if err != nil {
		*errorCount++
		return sshKeyInfo{}
	}
	return parseSSHKeygenOutput(out)
}

// collectPasswordManager checks whether a known password manager process is
// running on Linux via /proc/*/comm.
func collectPasswordManager(_ context.Context, meta map[string]interface{}) bool {
	manifest.Default.RecordFileRead("/proc")
	entries, err := filepath.Glob("/proc/[0-9]*/comm")
	if err != nil {
		meta["pm_proc_unavailable"] = err.Error()
		return false
	}
	var combined []byte
	for _, path := range entries {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		combined = append(combined, data...)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			combined = append(combined, '\n')
		}
	}
	return parsePasswordManagerFromProcessList(combined)
}

// collectListeningPorts counts non-loopback listening TCP/UDP ports on Linux.
// Prefers `ss -tlnpu`; falls back to `netstat -tlnpu`.
func collectListeningPorts(ctx context.Context, meta map[string]interface{}) int {
	ssCmd := resolveSecAbsPath("ss", []string{"/usr/sbin/ss", "/sbin/ss", "/bin/ss"}, meta)
	if ssCmd != "" {
		ssArgs := []string{"-tlnpu"}
		manifest.Default.RecordExec(ssCmd, ssArgs)
		out, err := exec.CommandContext(ctx, ssCmd, ssArgs...).Output()
		if err == nil {
			return parseListeningPortsSS(out)
		}
		meta["listening_ports_ss_error"] = err.Error()
	}

	nsCmd := resolveSecAbsPath("netstat", []string{"/usr/sbin/netstat", "/sbin/netstat"}, meta)
	if nsCmd == "" {
		meta["listening_ports_unavailable"] = "ss and netstat not found"
		return 0
	}
	nsArgs := []string{"-tlnpu"}
	manifest.Default.RecordExec(nsCmd, nsArgs)
	out, err := exec.CommandContext(ctx, nsCmd, nsArgs...).Output()
	if err != nil {
		meta["listening_ports_netstat_error"] = err.Error()
		return 0
	}
	return parseListeningPortsSS(out)
}

// resolveSecAbsPath returns the absolute path of a binary, preventing PATH
// hijacking. Mirrors the pattern in the compliance Linux collector.
func resolveSecAbsPath(name string, candidates []string, meta map[string]interface{}) string {
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
