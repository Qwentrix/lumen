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

// Windows security posture probe collector.
//
// Data sources:
//   - SSH keys: %USERPROFILE%\.ssh\ — header sniff + ssh-keygen -l -f
//   - Password manager: registry Uninstall scan (HKLM+HKCU) + running processes
//     via toolhelp32 Process32First/Next. Windows Hello is NOT counted.
//   - Listening ports: GetExtendedTcpTable + GetExtendedUdpTable (iphlpapi.dll)
//     via golang.org/x/sys/windows syscall; loopback excluded.
//
// All exec/registry accesses go through manifest.Default.RecordExec/RecordFileRead.
// ZERO network calls.
package security_posture

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/Qwentrix/lumen/internal/manifest"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// collectSSHKeys enumerates private SSH keys in %USERPROFILE%\.ssh on Windows.
// Mirrors the darwin/linux implementation — header sniff + ssh-keygen -l -f.
func collectSSHKeys(ctx context.Context, meta map[string]interface{}) (total, weak int) {
	profile, err := os.UserHomeDir()
	if err != nil {
		meta["ssh_keys_home_unavailable"] = err.Error()
		return 0, 0
	}

	sshDir := filepath.Join(profile, ".ssh")
	manifest.Default.RecordFileRead(sshDir)

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		// ~/.ssh absent is normal on Windows — not an error condition.
		meta["ssh_keys_dir_note"] = "no .ssh directory found in USERPROFILE"
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
		if strings.HasSuffix(name, ".pub") ||
			strings.EqualFold(name, "known_hosts") ||
			strings.EqualFold(name, "authorized_keys") ||
			strings.EqualFold(name, "config") ||
			strings.HasPrefix(name, ".") {
			continue
		}

		keyPath := filepath.Join(sshDir, name)
		if !looksLikePrivateKey(keyPath) {
			continue
		}

		info := probeSSHKeyLenWindows(ctx, keyPath, &errorCount)
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

// probeSSHKeyLenWindows runs ssh-keygen -l -f <path> to get the key bit-length.
// Windows OpenSSH ships ssh-keygen in %SystemRoot%\System32\OpenSSH\ssh-keygen.exe.
// Falls back to PATH lookup if not at the standard location.
// errorCount is incremented on failure (not the filename) to avoid leaking
// private key filenames into metadata (privacy probe path-omission discipline).
func probeSSHKeyLenWindows(ctx context.Context, keyPath string, errorCount *int) sshKeyInfo {
	// Standard Windows OpenSSH location (Windows 10/11 built-in).
	sshKeygenCandidates := []string{
		`C:\Windows\System32\OpenSSH\ssh-keygen.exe`,
		`C:\Program Files\Git\usr\bin\ssh-keygen.exe`,
	}

	cmdPath := ""
	for _, c := range sshKeygenCandidates {
		if _, err := os.Stat(c); err == nil {
			cmdPath = c
			break
		}
	}
	if cmdPath == "" {
		// Fallback to PATH.
		if p, err := exec.LookPath("ssh-keygen"); err == nil {
			cmdPath = p
		}
	}
	if cmdPath == "" {
		*errorCount++
		return sshKeyInfo{}
	}

	args := []string{"-l", "-f", keyPath}
	manifest.Default.RecordExec(cmdPath, args)

	out, err := exec.CommandContext(ctx, cmdPath, args...).Output()
	if err != nil {
		*errorCount++
		return sshKeyInfo{}
	}
	return parseSSHKeygenOutput(out)
}

// collectPasswordManager checks whether a known password manager is installed
// or running on Windows.
//
// Detection order:
//  1. Registry Uninstall scan (HKLM+HKCU) for known PM display names.
//  2. Running process list via toolhelp32.
//
// Windows Hello is explicitly NOT counted as a password manager.
func collectPasswordManager(ctx context.Context, meta map[string]interface{}) bool {
	// 1. Registry Uninstall scan.
	if registryHasPasswordManager(meta) {
		return true
	}

	// 2. Running process check via toolhelp32 snapshot.
	return runningProcessHasPasswordManager(meta)
}

// registryHasPasswordManager checks Uninstall keys for known PM DisplayNames.
func registryHasPasswordManager(meta map[string]interface{}) bool {
	manifest.Default.RecordFileRead(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`)
	manifest.Default.RecordFileRead(`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`)

	roots := []struct {
		hive registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}

	for _, root := range roots {
		k, err := registry.OpenKey(root.hive, root.path, registry.ENUMERATE_SUB_KEYS|registry.READ)
		if err != nil {
			continue
		}
		subkeys, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		for _, sub := range subkeys {
			sk, err := registry.OpenKey(root.hive, root.path+`\`+sub, registry.QUERY_VALUE|registry.READ)
			if err != nil {
				continue
			}
			displayName, _, _ := sk.GetStringValue("DisplayName")
			sk.Close()
			if parsePasswordManagerFromProcessList([]byte(displayName + "\n")) {
				return true
			}
		}
	}
	return false
}

// runningProcessHasPasswordManager uses CreateToolhelp32Snapshot to enumerate
// running processes and checks exe names against known password managers.
func runningProcessHasPasswordManager(meta map[string]interface{}) bool {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		meta["pm_process_snap_error"] = err.Error()
		return false
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return false
	}

	for {
		exeName := windows.UTF16ToString(entry.ExeFile[:])
		if parsePasswordManagerFromProcessList([]byte(exeName + "\n")) {
			return true
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return false
}

// ─── Listening ports via iphlpapi ────────────────────────────────────────────

// MIB_TCPROW_OWNER_PID is the struct returned by GetExtendedTcpTable for each
// TCP connection row (AF_INET, TCP_TABLE_OWNER_PID_ALL).
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// MIB_UDPROW_OWNER_PID is the struct returned by GetExtendedUdpTable.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// TCP listener state = 2 (MIB_TCP_STATE_LISTEN per MSDN).
const tcpStateListen = 2

// collectListeningPorts counts non-loopback TCP/UDP listening ports on Windows
// using GetExtendedTcpTable and GetExtendedUdpTable from iphlpapi.dll.
// ZERO network — reads kernel connection tables only.
func collectListeningPorts(ctx context.Context, meta map[string]interface{}) int {
	manifest.Default.RecordFileRead("iphlpapi.dll (GetExtendedTcpTable/GetExtendedUdpTable)")

	ports := map[uint32]struct{}{}

	// TCP listeners.
	tcpRows := getExtendedTCPTable(meta)
	for _, row := range tcpRows {
		if row.State != tcpStateListen {
			continue
		}
		// Skip loopback (127.0.0.1 = 0x0100007F in little-endian).
		if isLoopbackIPv4(row.LocalAddr) {
			continue
		}
		// Port is in network byte order (big-endian); decode.
		port := networkOrderPort(row.LocalPort)
		ports[port] = struct{}{}
	}

	// UDP "listeners" (all UDP sockets are considered open).
	udpRows := getExtendedUDPTable(meta)
	for _, row := range udpRows {
		if isLoopbackIPv4(row.LocalAddr) {
			continue
		}
		port := networkOrderPort(row.LocalPort)
		ports[port] = struct{}{}
	}

	return len(ports)
}

// getExtendedTCPTable calls iphlpapi GetExtendedTcpTable and returns all rows.
// Returns nil on any error; degrades gracefully.
// FindProc (not MustFindProc) is used so that absent procs on Wine / sandbox /
// future Windows versions produce a graceful degrade rather than a panic.
func getExtendedTCPTable(meta map[string]interface{}) []mibTCPRowOwnerPID {
	iphlpapi := windows.MustLoadDLL("iphlpapi.dll")
	proc, err := iphlpapi.FindProc("GetExtendedTcpTable")
	if err != nil {
		meta["tcp_table_proc_unavailable"] = "GetExtendedTcpTable not found in iphlpapi.dll (graceful degrade)"
		return nil
	}

	// First call: get required buffer size.
	var size uint32
	ret, _, _ := proc.Call(
		0, uintptr(unsafe.Pointer(&size)),
		1,          // bOrder=TRUE (sort by local address)
		2,          // AF_INET
		uintptr(5), // TCP_TABLE_OWNER_PID_ALL
		0,
	)
	// 122 = ERROR_INSUFFICIENT_BUFFER — expected on the sizing call.
	if ret != 0 && ret != 122 {
		meta["tcp_table_size_error"] = windows.Errno(ret).Error()
		return nil
	}
	if size == 0 {
		size = 65536
	}

	buf := make([]byte, size)
	ret, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, 2, uintptr(5), 0,
	)
	if ret != 0 {
		meta["tcp_table_get_error"] = windows.Errno(ret).Error()
		return nil
	}

	return parseTCPTableBuf(buf, meta)
}

// parseTCPTableBuf parses a raw GetExtendedTcpTable buffer into TCP rows.
// The buffer starts with a DWORD count followed by count mibTCPRowOwnerPID structs.
func parseTCPTableBuf(buf []byte, meta map[string]interface{}) []mibTCPRowOwnerPID {
	if len(buf) < 4 {
		return nil
	}
	// First DWORD is the number of rows.
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := uint32(unsafe.Sizeof(mibTCPRowOwnerPID{}))
	needed := 4 + count*rowSize
	if uint32(len(buf)) < needed {
		meta["tcp_table_buf_short"] = "buffer too small for reported row count"
		return nil
	}
	rows := make([]mibTCPRowOwnerPID, count)
	for i := uint32(0); i < count; i++ {
		offset := 4 + i*rowSize
		rows[i] = *(*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[offset]))
	}
	return rows
}

// getExtendedUDPTable calls iphlpapi GetExtendedUdpTable and returns all rows.
// FindProc (not MustFindProc) is used to degrade gracefully on Wine / sandbox /
// future Windows versions where the proc may be absent.
func getExtendedUDPTable(meta map[string]interface{}) []mibUDPRowOwnerPID {
	iphlpapi := windows.MustLoadDLL("iphlpapi.dll")
	proc, err := iphlpapi.FindProc("GetExtendedUdpTable")
	if err != nil {
		meta["udp_table_proc_unavailable"] = "GetExtendedUdpTable not found in iphlpapi.dll (graceful degrade)"
		return nil
	}

	var size uint32
	ret, _, _ := proc.Call(
		0, uintptr(unsafe.Pointer(&size)),
		1, 2, uintptr(1), 0, // UDP_TABLE_OWNER_PID = 1
	)
	if ret != 0 && ret != 122 {
		meta["udp_table_size_error"] = windows.Errno(ret).Error()
		return nil
	}
	if size == 0 {
		size = 65536
	}

	buf := make([]byte, size)
	ret, _, _ = proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, 2, uintptr(1), 0,
	)
	if ret != 0 {
		meta["udp_table_get_error"] = windows.Errno(ret).Error()
		return nil
	}

	return parseUDPTableBuf(buf, meta)
}

// parseUDPTableBuf parses a raw GetExtendedUdpTable buffer into UDP rows.
func parseUDPTableBuf(buf []byte, meta map[string]interface{}) []mibUDPRowOwnerPID {
	if len(buf) < 4 {
		return nil
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := uint32(unsafe.Sizeof(mibUDPRowOwnerPID{}))
	needed := 4 + count*rowSize
	if uint32(len(buf)) < needed {
		meta["udp_table_buf_short"] = "buffer too small"
		return nil
	}
	rows := make([]mibUDPRowOwnerPID, count)
	for i := uint32(0); i < count; i++ {
		offset := 4 + i*rowSize
		rows[i] = *(*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[offset]))
	}
	return rows
}

// isLoopbackIPv4 and networkOrderPort are pure helpers defined in parsers.go
// (no build tag) so they can be unit-tested on macOS.
