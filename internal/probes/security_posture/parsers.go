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

// Package security_posture — OS-agnostic pure parser functions.
//
// All parse* functions in this file are pure: they accept raw bytes (command
// stdout or file content) and return typed results. No exec, no file I/O, no
// build tag. This allows every parser — including Linux-only parsers — to be
// unit-tested on the macOS development host via `go test ./...`.
package security_posture

import (
	"bytes"
	"os"
	"strings"
)

// openFile is a thin wrapper around os.Open used by looksLikePrivateKey.
// Defined here so parsers.go can do file I/O in looksLikePrivateKey while
// remaining importable on all platforms.
func openFile(path string) (*os.File, error) {
	return os.Open(path)
}

// ─── SSH key parsing ──────────────────────────────────────────────────────────

// sshKeyInfo holds the parsed result from one `ssh-keygen -l -f` invocation.
type sshKeyInfo struct {
	bits    int    // key bit-length (0 if unparseable)
	keyType string // e.g. "RSA", "EC", "ED25519"
	isWeak  bool   // true if the key does not meet the minimum bit-length threshold
}

// parseSSHKeygenOutput parses the output of `ssh-keygen -l -f <keyfile>`.
//
// Typical output formats:
//
//	2048 SHA256:... comment (RSA)
//	256 SHA256:... comment (ECDSA)
//	256 SHA256:... comment (ED25519)
//
// Returns sshKeyInfo with bits and keyType set. isWeak is computed by
// determineWeakSSHKey.
func parseSSHKeygenOutput(out []byte) sshKeyInfo {
	line := strings.TrimSpace(string(out))
	if line == "" {
		return sshKeyInfo{}
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return sshKeyInfo{}
	}

	bits := 0
	for _, c := range fields[0] {
		if c < '0' || c > '9' {
			bits = 0
			break
		}
		bits = bits*10 + int(c-'0')
	}

	// Key type is typically the last field, wrapped in parentheses: "(RSA)"
	rawType := fields[len(fields)-1]
	rawType = strings.TrimPrefix(rawType, "(")
	rawType = strings.TrimSuffix(rawType, ")")
	keyType := strings.ToUpper(rawType)

	info := sshKeyInfo{bits: bits, keyType: keyType}
	info.isWeak = determineWeakSSHKey(keyType, bits)
	return info
}

// determineWeakSSHKey returns true when the key type and bit-length do not
// meet the minimum recommendations per NIST SP 800-57 / IETF RFC 8332:
//
//   - RSA / DSA: ≥ 2048 bits (DSA is always weak, NIST deprecated)
//   - ECDSA (NISTP): ≥ 256 bits (NISTP-256 acceptable; 192 is weak)
//   - ED25519 / ED448: always strong (fixed 255/448 bit strength)
//
// A bits value of 0 (unparseable) is treated as weak (fail-secure).
func determineWeakSSHKey(keyType string, bits int) bool {
	upper := strings.ToUpper(keyType)
	switch {
	case upper == "RSA" || upper == "DSA":
		// DSA keys are always considered weak (deprecated by NIST).
		if upper == "DSA" {
			return true
		}
		return bits < 2048 || bits == 0
	case upper == "ECDSA" || strings.HasPrefix(upper, "NISTP"):
		return bits < 256 || bits == 0
	case upper == "ED25519" || upper == "ED448":
		// Modern Edwards-curve keys are unconditionally strong.
		return false
	default:
		// Unknown key type — fail-secure: treat as weak if bits < 2048.
		return bits < 2048 || bits == 0
	}
}

// ─── Password manager detection ───────────────────────────────────────────────

// passwordManagerProcess represents a known password manager and its process name
// substrings for detection via the process list.
type passwordManagerProcess struct {
	name       string // human-readable name
	substrings []string
}

// knownPasswordManagers is the list of password managers detected by process name.
var knownPasswordManagers = []passwordManagerProcess{
	{name: "1Password", substrings: []string{"1password", "1password 7", "1password 8", "1passwordagent", "op-agent"}},
	{name: "Bitwarden", substrings: []string{"bitwarden", "bitwarden-desktop"}},
	{name: "KeePassXC", substrings: []string{"keepassxc", "keepass"}},
	{name: "Dashlane", substrings: []string{"dashlane"}},
	{name: "LastPass", substrings: []string{"lastpass"}},
	{name: "Enpass", substrings: []string{"enpass"}},
	{name: "NordPass", substrings: []string{"nordpass"}},
	{name: "RoboForm", substrings: []string{"roboform"}},
	{name: "Keeper", substrings: []string{"keepersecurity", "keeperapp"}},
}

// parsePasswordManagerFromProcessList checks whether any process in the list
// (one name per line, e.g. `ps -axo comm` or /proc/*/comm) matches a known
// password manager. Returns true if at least one password manager is detected.
func parsePasswordManagerFromProcessList(psOut []byte) bool {
	for _, line := range bytes.Split(psOut, []byte("\n")) {
		name := strings.ToLower(strings.TrimSpace(string(line)))
		if name == "" {
			continue
		}
		for _, pm := range knownPasswordManagers {
			for _, substr := range pm.substrings {
				if strings.Contains(name, strings.ToLower(substr)) {
					return true
				}
			}
		}
	}
	return false
}

// ─── Listening port parsing ───────────────────────────────────────────────────

// parseListeningPortsLSOF parses `lsof -nP -iTCP -iUDP -sTCP:LISTEN` output
// and counts distinct non-loopback listening ports.
//
// TCP lines contain "LISTEN"; UDP lines do not (UDP is connectionless and has
// no LISTEN state in lsof output). Both are counted:
//   - TCP: lines containing "LISTEN" with address:port in column 8.
//   - UDP: lines containing " UDP " (protocol token) with address:port in
//     column 8. Only non-loopback addresses are counted; the existing loopback
//     exclusion applies to UDP as well.
//
// Sample lsof lines:
//
//	node  1234 user  22u  IPv4  ...  TCP *:3000 (LISTEN)
//	sshd   500 root  3u   IPv6  ...  TCP *:22 (LISTEN)
//	avahi  800 root  10u  IPv4  ...  UDP *:5353
func parseListeningPortsLSOF(lsofOut []byte) int {
	ports := map[string]struct{}{}
	for _, line := range bytes.Split(lsofOut, []byte("\n")) {
		s := string(line)
		fields := strings.Fields(s)

		isTCPListen := strings.Contains(s, "LISTEN")
		// UDP lines: protocol token is "UDP" (no LISTEN state token).
		// Guard: must have at least 9 fields and the type field (index 7) or
		// the name field (index 8) contains "UDP".
		isUDP := !isTCPListen && len(fields) >= 9 && strings.Contains(fields[7], "UDP")

		if !isTCPListen && !isUDP {
			continue
		}
		if len(fields) < 9 {
			continue
		}
		// The address:port field is typically column 8 (0-indexed) for lsof.
		addrPort := fields[8]

		// Extract host and port. Format: "host:port" or "[ipv6]:port"
		host := extractHost(addrPort)

		// Skip pure loopback addresses.
		if isLoopback(host) {
			continue
		}

		ports[addrPort] = struct{}{}
	}
	return len(ports)
}

// parseListeningPortsSS parses `ss -tlnpu` or `ss -tlnp` output and counts
// distinct non-loopback listening ports.
//
// ss output columns (0-indexed):
//
//	0:State  1:Recv-Q  2:Send-Q  3:LocalAddress:Port  4:PeerAddress:Port  5+:optional
//
// Sample lines:
//
//	LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=500,fd=3))
//	LISTEN  0  128  *:3000      *:*
func parseListeningPortsSS(ssOut []byte) int {
	ports := map[string]struct{}{}
	for _, line := range bytes.Split(ssOut, []byte("\n")) {
		s := string(line)
		if !strings.HasPrefix(strings.TrimSpace(s), "LISTEN") {
			continue
		}
		fields := strings.Fields(s)
		// Local address is column 3 (0-indexed) in ss output:
		// State(0) Recv-Q(1) Send-Q(2) Local(3) Peer(4) ...
		if len(fields) < 4 {
			continue
		}
		addrPort := fields[3]
		host := extractHost(addrPort)
		if isLoopback(host) {
			continue
		}
		ports[addrPort] = struct{}{}
	}
	return len(ports)
}

// extractHost extracts the host portion from "host:port", "[ipv6addr]:port", or "*:port".
func extractHost(addrPort string) string {
	// IPv6: "[::1]:22"
	if strings.HasPrefix(addrPort, "[") {
		end := strings.LastIndex(addrPort, "]")
		if end > 0 {
			return addrPort[1:end]
		}
	}
	// IPv4 or hostname: "host:port"
	last := strings.LastIndex(addrPort, ":")
	if last > 0 {
		return addrPort[:last]
	}
	return addrPort
}

// isLoopback returns true if host is a loopback address.
func isLoopback(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "127.0.0.1" ||
		h == "::1" ||
		strings.HasPrefix(h, "127.") ||
		h == "localhost"
}

// ─── Windows pure parsers (no build tag — testable on any host) ──────────────

// isLoopbackIPv4 returns true for 127.x.x.x addresses stored in little-endian
// network order as returned by iphlpapi GetExtendedTcpTable/GetExtendedUdpTable.
// The first byte in little-endian representation carries the lowest octet,
// which is 127 for all loopback addresses.
func isLoopbackIPv4(addr uint32) bool {
	return addr&0xFF == 127
}

// networkOrderPort converts a port stored in big-endian (network byte order)
// in the low 16 bits of a uint32 DWORD (as returned by iphlpapi) to host order.
// Example: port 80 is stored as 0x00005000 → returns 80.
func networkOrderPort(p uint32) uint32 {
	lo := (p >> 8) & 0xFF
	hi := (p & 0xFF) << 8
	return lo | hi
}

// looksLikePrivateKey reads the first 64 bytes of the file and returns true
// if the content starts with a known SSH private key header. This pure function
// is shared by the darwin, linux, and windows collectors.
//
// Only PRIVATE key headers are matched. Public key PEM headers
// (-----BEGIN PUBLIC KEY-----) are explicitly excluded.
func looksLikePrivateKey(path string) bool {
	f, err := openFile(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}
	header := string(buf[:n])
	return isPrivateKeyHeader(header)
}

// isPrivateKeyHeader returns true when the PEM header is a known PRIVATE key type.
// Pure function — testable without file I/O.
//
// NOTE: "openssh-key-v1\0" is the magic that appears INSIDE the base64 body of
// an OpenSSH private key — it is never the file header. The correct file header
// for OpenSSH keys is "-----BEGIN OPENSSH PRIVATE KEY-----", which is already
// in the list below. We do NOT check for the inner magic here.
func isPrivateKeyHeader(header string) bool {
	// PEM PRIVATE KEY markers — accept any "... PRIVATE KEY ..." but reject plain "PUBLIC KEY".
	privateMarkers := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN DSA PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",           // PKCS#8 unencrypted
		"-----BEGIN ENCRYPTED PRIVATE KEY-----", // PKCS#8 encrypted
		"-----BEGIN OPENSSH PRIVATE KEY-----",   // OpenSSH native format (covers all key types)
	}
	for _, marker := range privateMarkers {
		if strings.HasPrefix(header, marker) {
			return true
		}
	}
	return false
}
