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

package compliance

import (
	"context"
	"os/exec"

	"github.com/Qwentrix/lumen/internal/manifest"
)

// collectDiskEncryption probes FileVault status via `fdesetup status`.
// Returns true if FileVault is On.
// On error (tool absent, permission denied), degrades gracefully to false.
func collectDiskEncryption(ctx context.Context, meta map[string]interface{}) bool {
	cmd := "/usr/bin/fdesetup"
	args := []string{"status"}
	manifest.Default.RecordExec(cmd, args)

	out, err := exec.CommandContext(ctx, cmd, args...).Output()
	if err != nil {
		meta["disk_encryption_unavailable"] = "fdesetup error: " + err.Error()
		return false
	}
	return parseFdesetupStatus(out)
}

// collectFirewall probes the macOS Application Layer Firewall state.
// Tries `socketfilterfw --getglobalstate` first; falls back to reading the ALF plist.
// Returns true if the firewall is enabled.
func collectFirewall(ctx context.Context, meta map[string]interface{}) bool {
	// Preferred: socketfilterfw (authoritative, synchronous, no network)
	sfwCmd := "/usr/libexec/ApplicationFirewall/socketfilterfw"
	sfwArgs := []string{"--getglobalstate"}
	manifest.Default.RecordExec(sfwCmd, sfwArgs)

	out, err := exec.CommandContext(ctx, sfwCmd, sfwArgs...).Output()
	if err == nil {
		enabled, ok := parseSocketfilterfw(out)
		if ok {
			return enabled
		}
	}

	// Fallback: read the ALF plist via `defaults read`.
	dCmd := "/usr/bin/defaults"
	dArgs := []string{"read", "/Library/Preferences/com.apple.alf", "globalstate"}
	manifest.Default.RecordExec(dCmd, dArgs)
	manifest.Default.RecordFileRead("/Library/Preferences/com.apple.alf.plist")

	out2, err2 := exec.CommandContext(ctx, dCmd, dArgs...).Output()
	if err2 != nil {
		meta["firewall_unavailable"] = "socketfilterfw error: " + err.Error() + "; defaults error: " + err2.Error()
		return false
	}
	return parseALFGlobalState(out2)
}

// collectScreenLock probes the macOS screensaver lock settings.
//
// Reads two values:
//   - `defaults read com.apple.screensaver askForPassword` → "1" means lock is required
//   - `defaults read com.apple.screensaver askForPasswordDelay` → seconds delay (usually 0 = immediate)
//   - `defaults -currentHost read com.apple.screensaver idleTime` → screensaver idle timeout (seconds)
//
// ScreenLockTimeoutSeconds = idleTime + askForPasswordDelay (total seconds until lock).
// Returns zero-value on any error.
func collectScreenLock(ctx context.Context, meta map[string]interface{}) screenLockResult {
	// 1. askForPassword
	dCmd := "/usr/bin/defaults"
	askArgs := []string{"read", "com.apple.screensaver", "askForPassword"}
	manifest.Default.RecordExec(dCmd, askArgs)

	askOut, askErr := exec.CommandContext(ctx, dCmd, askArgs...).Output()

	// 2. askForPasswordDelay
	delayArgs := []string{"read", "com.apple.screensaver", "askForPasswordDelay"}
	manifest.Default.RecordExec(dCmd, delayArgs)

	delayOut, _ := exec.CommandContext(ctx, dCmd, delayArgs...).Output()

	// 3. idleTime (per-host, stored differently from user defaults)
	idleArgs := []string{"-currentHost", "read", "com.apple.screensaver", "idleTime"}
	manifest.Default.RecordExec(dCmd, idleArgs)

	idleOut, idleErr := exec.CommandContext(ctx, dCmd, idleArgs...).Output()

	if askErr != nil {
		meta["screen_lock_unavailable"] = "defaults read askForPassword error: " + askErr.Error()
	}
	if idleErr != nil {
		meta["screen_lock_idle_unavailable"] = "defaults read idleTime error: " + idleErr.Error()
	}

	return parseScreenLockDarwin(askOut, delayOut, idleOut)
}

