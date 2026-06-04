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

//go:build windows

// Windows compliance probe collector.
//
// Data sources:
//   - Disk encryption (BitLocker): registry
//     HKLM\SYSTEM\CurrentControlSet\Control\BitLocker\Volume\<GUID>\ProtectionStatus
//     or PowerShell Get-BitLockerVolume. Returns true when ANY volume has
//     ProtectionStatus == 1 (protection on).
//   - Firewall: registry
//     HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{Domain,Standard,Public}Profile
//     EnableFirewall DWORD. Returns true when ALL profiles (or at minimum the
//     Standard/Public profiles) have EnableFirewall == 1.
//   - Screen lock: registry HKCU\Control Panel\Desktop
//     ScreenSaveActive ("1"=enabled), ScreenSaverIsSecure ("1"=password required),
//     ScreenSaveTimeOut (seconds as REG_SZ). mfa_enabled stays unprobed.
//
// All registry reads go through manifest.Default.RecordFileRead.
// ZERO network calls.
package compliance

import (
	"context"

	"github.com/Qwentrix/lumen/internal/manifest"
	"golang.org/x/sys/windows/registry"
)

// collectDiskEncryption probes BitLocker status on Windows.
//
// Reads registry HKLM\SYSTEM\CurrentControlSet\Control\BitLocker\Volume\*\ProtectionStatus.
// Returns true if at least one volume has protection enabled (value == 1).
// Degrades gracefully to false on any registry access error.
func collectDiskEncryption(ctx context.Context, meta map[string]interface{}) bool {
	const bitlockerPath = `SYSTEM\CurrentControlSet\Control\BitLocker\Volume`
	manifest.Default.RecordFileRead(`HKLM\` + bitlockerPath)

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, bitlockerPath, registry.ENUMERATE_SUB_KEYS|registry.READ)
	if err != nil {
		// BitLocker registry key not present — try the FVE key used on older Windows.
		return collectBitLockerFVE(ctx, meta)
	}
	defer k.Close()

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		meta["disk_encryption_unavailable"] = "BitLocker volume enum error: " + err.Error()
		return false
	}

	for _, sub := range subkeys {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, bitlockerPath+`\`+sub, registry.QUERY_VALUE|registry.READ)
		if err != nil {
			continue
		}
		val, _, err2 := sk.GetIntegerValue("ProtectionStatus")
		sk.Close()
		if err2 == nil && val == 1 {
			return true
		}
	}

	meta["disk_encryption_note"] = "BitLocker registry found but no protected volumes detected"
	return false
}

// collectBitLockerFVE checks the older HKLM\SOFTWARE\Policies\Microsoft\FVE registry key
// which indicates BitLocker Group Policy configuration.
func collectBitLockerFVE(_ context.Context, meta map[string]interface{}) bool {
	const fvePath = `SOFTWARE\Policies\Microsoft\FVE`
	manifest.Default.RecordFileRead(`HKLM\` + fvePath)

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, fvePath, registry.QUERY_VALUE|registry.READ)
	if err != nil {
		meta["disk_encryption_unavailable"] = "BitLocker registry key absent (HKLM\\SYSTEM\\...\\BitLocker and HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE both missing)"
		return false
	}
	defer k.Close()

	// UseTPM or any FVE policy key present suggests BitLocker is configured.
	val, _, err2 := k.GetIntegerValue("UseTPM")
	if err2 == nil && val >= 1 {
		return true
	}

	meta["disk_encryption_note"] = "FVE policy key present but UseTPM not set — BitLocker status indeterminate"
	return false
}

// collectFirewall probes Windows Firewall state by reading all three profiles
// (Domain, Standard, Public) from the registry.
// Returns true when all three standard profiles have EnableFirewall == 1.
// Degrades gracefully on any registry error.
func collectFirewall(ctx context.Context, meta map[string]interface{}) bool {
	const fwBase = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`
	manifest.Default.RecordFileRead(`HKLM\` + fwBase)

	profiles := []struct {
		name string
		path string
	}{
		{"DomainProfile", fwBase + `\DomainProfile`},
		{"StandardProfile", fwBase + `\StandardProfile`},
		{"PublicProfile", fwBase + `\PublicProfile`},
	}

	allEnabled := true
	anyFound := false

	for _, p := range profiles {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p.path, registry.QUERY_VALUE|registry.READ)
		if err != nil {
			// Missing profile key — skip without failing the whole check.
			meta["firewall_profile_missing_"+p.name] = err.Error()
			continue
		}
		anyFound = true
		val, _, err2 := k.GetIntegerValue("EnableFirewall")
		k.Close()
		if err2 != nil || val != 1 {
			allEnabled = false
			meta["firewall_disabled_"+p.name] = "EnableFirewall != 1"
		}
	}

	if !anyFound {
		meta["firewall_unavailable"] = "Windows Firewall registry keys not found"
		return false
	}

	return allEnabled
}

// collectScreenLock probes Windows screen-lock (screensaver + password) settings.
//
// Registry keys read (all under HKCU\Control Panel\Desktop):
//   - ScreenSaveActive      REG_SZ "1" = screensaver enabled
//   - ScreenSaverIsSecure   REG_SZ "1" = password required on resume
//   - ScreenSaveTimeOut     REG_SZ seconds until screensaver activates
//
// Returns a screenLockResult. Screen lock is considered enabled when BOTH
// ScreenSaveActive == "1" AND ScreenSaverIsSecure == "1".
func collectScreenLock(ctx context.Context, meta map[string]interface{}) screenLockResult {
	const desktopPath = `Control Panel\Desktop`
	manifest.Default.RecordFileRead(`HKCU\` + desktopPath)

	k, err := registry.OpenKey(registry.CURRENT_USER, desktopPath, registry.QUERY_VALUE|registry.READ)
	if err != nil {
		meta["screen_lock_unavailable"] = "HKCU\\Control Panel\\Desktop error: " + err.Error()
		return screenLockResult{}
	}
	defer k.Close()

	active, _, _ := k.GetStringValue("ScreenSaveActive")
	secure, _, _ := k.GetStringValue("ScreenSaverIsSecure")
	timeoutStr, _, _ := k.GetStringValue("ScreenSaveTimeOut")

	return parseScreenLockWindows([]byte(active), []byte(secure), []byte(timeoutStr))
}

// parseScreenLockWindows is defined in parsers.go (no build tag) for cross-platform testability.
