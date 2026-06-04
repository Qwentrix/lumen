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

// Windows security posture parser tests — no build tag; runs on any host (macOS dev box).
// Tests the pure parser functions isLoopbackIPv4 and networkOrderPort which are
// used by the Windows listening-ports collector. Also tests looksLikePrivateKey
// which is shared across platforms via the security_posture package.
package security_posture

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsLoopbackIPv4 tests the loopback detection for Windows iphlpapi addresses.
func TestIsLoopbackIPv4(t *testing.T) {
	tests := []struct {
		name     string
		addr     uint32 // raw little-endian IPv4 from iphlpapi
		wantLoop bool
	}{
		// Loopback: first byte (little-endian) = 127
		{"127.0.0.1 loopback", 0x0100007F, true},  // 127.0.0.1 little-endian
		{"127.0.0.2 loopback", 0x0200007F, true},   // 127.0.0.2 little-endian
		{"0.0.0.0", 0x00000000, false},
		{"10.0.0.1", 0x0100000A, false},
		{"192.168.1.1", 0x0101A8C0, false},
		{"0.0.0.127 not loopback", 0x7F000000, false}, // 127 in the wrong byte position
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isLoopbackIPv4(tc.addr)
			if got != tc.wantLoop {
				t.Errorf("isLoopbackIPv4(0x%08X) = %v, want %v", tc.addr, got, tc.wantLoop)
			}
		})
	}
}

// TestNetworkOrderPort tests big-endian port conversion from iphlpapi DWORD.
func TestNetworkOrderPort(t *testing.T) {
	tests := []struct {
		name    string
		raw     uint32 // network-order port from iphlpapi (stored in DWORD low 16 bits)
		wantPort uint32
	}{
		// Port 80: big-endian 0x5000 in low 16 bits → host 80 = 0x0050
		{"port 80", 0x00005000, 80},
		// Port 443: 0xBB01 big-endian → 443 = 0x01BB
		{"port 443", 0x0000BB01, 443},
		// Port 22: 0x1600 big-endian → 22 = 0x0016
		{"port 22", 0x00001600, 22},
		// Port 8080: 0x901F big-endian → 8080 = 0x1F90
		{"port 8080", 0x0000901F, 8080},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := networkOrderPort(tc.raw)
			if got != tc.wantPort {
				t.Errorf("networkOrderPort(0x%08X) = %d, want %d", tc.raw, got, tc.wantPort)
			}
		})
	}
}

// TestLooksLikePrivateKey_Windows tests the private key header detector with
// standard PEM and OpenSSH key headers, using temp files.
func TestLooksLikePrivateKey_Windows(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"RSA PEM header", "-----BEGIN RSA PRIVATE KEY-----\nMIIEo...", true},
		{"OpenSSH header", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...", true},
		{"EC PEM header", "-----BEGIN EC PRIVATE KEY-----\nMHQCA...", true},
		{"Public key", "-----BEGIN PUBLIC KEY-----\nMIIBI...", false},
		{"Random text", "This is not a key file", false},
		{"Empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			f := filepath.Join(tmpDir, "testkey")
			if err := os.WriteFile(f, []byte(tc.content), 0600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			got := looksLikePrivateKey(f)
			if got != tc.want {
				t.Errorf("looksLikePrivateKey(%q content) = %v, want %v", tc.content[:min(20, len(tc.content))], got, tc.want)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
