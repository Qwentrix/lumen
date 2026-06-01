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

package compliance

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/Qwentrix/lumen/internal/manifest"
)

// collectDiskEncryption probes Linux disk encryption status.
//
// Strategy (in order, first success wins):
//  1. Read /etc/crypttab — if it has non-comment, non-empty lines, encryption is configured.
//  2. Run lsblk -o NAME,TYPE --noheadings — look for a device of type "crypt".
//     Tries /usr/bin/lsblk then /bin/lsblk; falls back to exec.LookPath and records
//     the resolved absolute path in the manifest to prevent PATH hijacking.
//
// Degrades gracefully: any error returns false + metadata note.
func collectDiskEncryption(ctx context.Context, meta map[string]interface{}) bool {
	// 1. /etc/crypttab (file read — no exec, no sudo)
	crypttabPath := "/etc/crypttab"
	manifest.Default.RecordFileRead(crypttabPath)

	data, err := os.ReadFile(crypttabPath)
	if err == nil {
		if parseCrypttab(data) {
			return true
		}
	} else {
		meta["disk_encryption_crypttab_unavailable"] = err.Error()
	}

	// 2. lsblk — use absolute path to prevent PATH hijacking.
	lsblkCmd := resolveAbsPath("lsblk", []string{"/usr/bin/lsblk", "/bin/lsblk"}, meta)
	if lsblkCmd == "" {
		meta["disk_encryption_lsblk_unavailable"] = "lsblk not found at standard paths"
		return false
	}
	lsblkArgs := []string{"-o", "NAME,TYPE", "--noheadings"}
	manifest.Default.RecordExec(lsblkCmd, lsblkArgs)

	out, err := exec.CommandContext(ctx, lsblkCmd, lsblkArgs...).Output()
	if err != nil {
		meta["disk_encryption_lsblk_unavailable"] = err.Error()
		return false
	}
	return parseLsblkForCrypt(out)
}

// collectFirewall probes Linux firewall status.
//
// Strategy (file-read preferred; exec only for firewall-cmd):
//  1. Read /etc/ufw/ufw.conf → look for ENABLED=yes (ufw).
//  2. Run `/usr/bin/firewall-cmd --state` (firewalld) — no sudo required for query.
//
// A disabled or absent UFW is not definitive — the system may still run
// firewalld. Both states are checked; the function returns true when either
// firewall is active, and false only when both are absent or disabled.
//
// Degrades gracefully.
func collectFirewall(ctx context.Context, meta map[string]interface{}) bool {
	// 1. UFW config (no exec, no sudo needed)
	ufwConf := "/etc/ufw/ufw.conf"
	manifest.Default.RecordFileRead(ufwConf)

	ufwEnabled := false
	data, err := os.ReadFile(ufwConf)
	if err == nil {
		ufwEnabled = parseUFWConf(data)
		if ufwEnabled {
			meta["firewall_ufw_state"] = "enabled"
			return true
		}
		// UFW present but disabled — record and fall through to firewalld check.
		meta["firewall_ufw_state"] = "disabled"
	} else {
		meta["firewall_ufw_state"] = "absent"
	}

	// 2. firewalld check — try standard absolute path first; fall back to LookPath.
	fcCmd := "/usr/bin/firewall-cmd"
	if _, statErr := os.Stat(fcCmd); statErr != nil {
		// Not at standard path; try resolving via PATH.
		if resolved, lookErr := exec.LookPath("firewall-cmd"); lookErr == nil {
			fcCmd = resolved
			meta["firewall_cmd_resolved_path"] = resolved
		} else {
			meta["firewall_unavailable"] = "ufw disabled/absent; firewall-cmd not found"
			return false
		}
	}
	fcArgs := []string{"--state"}
	manifest.Default.RecordExec(fcCmd, fcArgs)

	out, err := exec.CommandContext(ctx, fcCmd, fcArgs...).Output()
	if err != nil {
		meta["firewall_unavailable"] = "ufw disabled/absent; firewall-cmd error: " + err.Error()
		return false
	}
	if parseFirewalldState(out) {
		meta["firewall_firewalld_state"] = "running"
		return true
	}
	meta["firewall_firewalld_state"] = "not running"
	return false
}

// collectScreenLock probes the GNOME screensaver lock settings via gsettings.
//
// Fields queried:
//   - org.gnome.desktop.screensaver lock-enabled → bool
//   - org.gnome.desktop.screensaver lock-delay   → uint32 (seconds after idle triggers lock)
//   - org.gnome.desktop.session    idle-delay    → uint32 (seconds until idle)
//
// ScreenLockTimeoutSeconds = idle-delay + lock-delay (total until locked).
//
// M-5 (false-positive guard): gsettings is GNOME-specific. On KDE, XFCE,
// headless, or other non-GNOME desktops it errors and reports lock-disabled,
// which would falsely fire COMP_NO_SCREEN_LOCK. This function only reports
// screen_lock_enabled=false when gsettings POSITIVELY returns "false". If
// gsettings is absent, errors, or the desktop environment is not GNOME-family,
// the result is INDETERMINATE (enabled=true so the rule does NOT fire) with
// metadata screen_lock="indeterminate_non_gnome". This mirrors the MFA
// "don't fire on unprobeable" principle.
func collectScreenLock(ctx context.Context, meta map[string]interface{}) screenLockResult {
	// M-5: Only probe via gsettings when the current desktop is GNOME-family.
	// GNOME-family desktops use XDG_CURRENT_DESKTOP or XDG_SESSION_DESKTOP
	// containing "GNOME", "Unity", or "ubuntu".
	if !isGNOMEDesktop() {
		meta["screen_lock"] = "indeterminate_non_gnome"
		// Return enabled=true so COMP_NO_SCREEN_LOCK does NOT fire.
		return screenLockResult{enabled: true, timeoutSeconds: 0}
	}

	// M-1: Use absolute path for gsettings to prevent PATH hijacking.
	gsCmd := resolveAbsPath("gsettings", []string{"/usr/bin/gsettings"}, meta)
	if gsCmd == "" {
		// gsettings absent on a GNOME system is unusual; treat as indeterminate.
		meta["screen_lock"] = "indeterminate_non_gnome"
		return screenLockResult{enabled: true, timeoutSeconds: 0}
	}

	lockEnabledArgs := []string{"get", "org.gnome.desktop.screensaver", "lock-enabled"}
	manifest.Default.RecordExec(gsCmd, lockEnabledArgs)
	lockEnabledOut, lockEnabledErr := exec.CommandContext(ctx, gsCmd, lockEnabledArgs...).Output()

	if lockEnabledErr != nil {
		// gsettings errored — treat as indeterminate, do not fire the rule.
		meta["screen_lock"] = "indeterminate_non_gnome"
		meta["screen_lock_unavailable"] = "gsettings error: " + lockEnabledErr.Error()
		return screenLockResult{enabled: true, timeoutSeconds: 0}
	}

	lockDelayArgs := []string{"get", "org.gnome.desktop.screensaver", "lock-delay"}
	manifest.Default.RecordExec(gsCmd, lockDelayArgs)
	lockDelayOut, _ := exec.CommandContext(ctx, gsCmd, lockDelayArgs...).Output()

	idleDelayArgs := []string{"get", "org.gnome.desktop.session", "idle-delay"}
	manifest.Default.RecordExec(gsCmd, idleDelayArgs)
	idleDelayOut, idleDelayErr := exec.CommandContext(ctx, gsCmd, idleDelayArgs...).Output()

	if idleDelayErr != nil {
		meta["screen_lock_idle_unavailable"] = "gsettings idle-delay error: " + idleDelayErr.Error()
	}

	return parseScreenLockLinux(lockEnabledOut, lockDelayOut, idleDelayOut)
}

// isGNOMEDesktop returns true when the current desktop environment is
// GNOME-family (GNOME, Unity, ubuntu). It checks XDG_CURRENT_DESKTOP and
// XDG_SESSION_DESKTOP environment variables.
func isGNOMEDesktop() bool {
	gnomeFamilies := []string{"gnome", "unity", "ubuntu"}
	for _, envKey := range []string{"XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP"} {
		val := strings.ToLower(os.Getenv(envKey))
		if val == "" {
			continue
		}
		for _, family := range gnomeFamilies {
			if strings.Contains(val, family) {
				return true
			}
		}
	}
	return false
}

// resolveAbsPath returns the absolute path of an executable, preventing PATH
// hijacking. It tries each candidate path in order; if none exist it falls
// back to exec.LookPath and records the resolved path in meta so the access
// manifest captures the actual binary that was executed.
// Returns "" when the binary cannot be found by any method.
func resolveAbsPath(name string, candidates []string, meta map[string]interface{}) string {
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Fall back to PATH resolution and record the resolved path.
	resolved, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	if meta != nil {
		meta[name+"_resolved_path"] = resolved
	}
	return resolved
}
