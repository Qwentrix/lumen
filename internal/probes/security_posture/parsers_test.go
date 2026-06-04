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

// Parser unit tests for the security_posture probe.
// No build tag — runs on ALL platforms.
package security_posture

import "testing"

// ─── parseSSHKeygenOutput ─────────────────────────────────────────────────────

func TestParseSSHKeygenOutput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantBits  int
		wantType  string
		wantWeak  bool
	}{
		{
			name:     "empty output",
			input:    "",
			wantBits: 0, wantType: "", wantWeak: false,
		},
		{
			name:     "2048-bit RSA — strong",
			input:    "2048 SHA256:abc123 user@host (RSA)\n",
			wantBits: 2048, wantType: "RSA", wantWeak: false,
		},
		{
			name:     "1024-bit RSA — weak",
			input:    "1024 SHA256:abc123 user@host (RSA)\n",
			wantBits: 1024, wantType: "RSA", wantWeak: true,
		},
		{
			name:     "256-bit ED25519 — always strong",
			input:    "256 SHA256:abc123 user@host (ED25519)\n",
			wantBits: 256, wantType: "ED25519", wantWeak: false,
		},
		{
			name:     "DSA key — always weak",
			input:    "1024 SHA256:abc123 user@host (DSA)\n",
			wantBits: 1024, wantType: "DSA", wantWeak: true,
		},
		{
			name:     "256-bit ECDSA — strong",
			input:    "256 SHA256:abc123 user@host (ECDSA)\n",
			wantBits: 256, wantType: "ECDSA", wantWeak: false,
		},
		{
			name:     "192-bit ECDSA — weak",
			input:    "192 SHA256:abc123 user@host (ECDSA)\n",
			wantBits: 192, wantType: "ECDSA", wantWeak: true,
		},
		{
			name:     "4096-bit RSA — strong",
			input:    "4096 SHA256:abc123 user@host (RSA)\n",
			wantBits: 4096, wantType: "RSA", wantWeak: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSSHKeygenOutput([]byte(tc.input))
			if got.bits != tc.wantBits {
				t.Errorf("bits: got %d, want %d", got.bits, tc.wantBits)
			}
			if got.keyType != tc.wantType {
				t.Errorf("keyType: got %q, want %q", got.keyType, tc.wantType)
			}
			if got.isWeak != tc.wantWeak {
				t.Errorf("isWeak: got %v, want %v", got.isWeak, tc.wantWeak)
			}
		})
	}
}

// ─── determineWeakSSHKey ──────────────────────────────────────────────────────

func TestDetermineWeakSSHKey(t *testing.T) {
	tests := []struct {
		keyType string
		bits    int
		want    bool
	}{
		{"RSA", 2048, false},
		{"RSA", 4096, false},
		{"RSA", 1024, true},
		{"RSA", 0, true},
		{"DSA", 1024, true},  // DSA always weak
		{"DSA", 2048, true},  // DSA always weak
		{"ECDSA", 256, false},
		{"ECDSA", 192, true},
		{"ED25519", 256, false},
		{"ED25519", 0, false}, // ED25519 always strong
		{"ED448", 448, false},
	}
	for _, tc := range tests {
		got := determineWeakSSHKey(tc.keyType, tc.bits)
		if got != tc.want {
			t.Errorf("determineWeakSSHKey(%q, %d) = %v, want %v", tc.keyType, tc.bits, got, tc.want)
		}
	}
}

// ─── parsePasswordManagerFromProcessList ─────────────────────────────────────

func TestParsePasswordManagerFromProcessList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "no password manager", input: "bash\nsafari\nfinder\n", want: false},
		{name: "empty", input: "", want: false},
		{name: "1Password running", input: "bash\n1password\nfinder\n", want: true},
		{name: "Bitwarden running", input: "bitwarden\nbash\n", want: true},
		{name: "KeePassXC running", input: "keepassxc\nbash\n", want: true},
		{name: "Dashlane running", input: "dashlane\n", want: true},
		{name: "1Password agent", input: "1passwordagent\n", want: true},
		{name: "case-insensitive match", input: "BITWARDEN\n", want: true},
		{name: "partial match in longer name", input: "com.agilebits.1password\n", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePasswordManagerFromProcessList([]byte(tc.input))
			if got != tc.want {
				t.Errorf("parsePasswordManagerFromProcessList(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ─── parseListeningPortsLSOF ──────────────────────────────────────────────────

func TestParseListeningPortsLSOF(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty",
			input: "",
			want:  0,
		},
		{
			name:  "loopback only — excluded",
			input: "node  1234  user  22u  IPv4  1234  0t0  TCP 127.0.0.1:3000 (LISTEN)\n",
			want:  0,
		},
		{
			name:  "wildcard bind — counted",
			input: "node  1234  user  22u  IPv4  1234  0t0  TCP *:3000 (LISTEN)\n",
			want:  1,
		},
		{
			name:  "two distinct non-loopback ports",
			input: "node  1234  user  22u  IPv4  1234  0t0  TCP *:3000 (LISTEN)\n" +
				"sshd   500  root  3u   IPv6  500   0t0  TCP *:22 (LISTEN)\n",
			want: 2,
		},
		{
			name:  "duplicate address — counted once",
			input: "node  1234  user  22u  IPv4  1234  0t0  TCP *:3000 (LISTEN)\n" +
				"node  1234  user  23u  IPv6  1234  0t0  TCP *:3000 (LISTEN)\n",
			want: 1,
		},
		{
			name:  "IPv6 loopback — excluded",
			input: "node  1234  user  22u  IPv6  1234  0t0  TCP [::1]:3000 (LISTEN)\n",
			want:  0,
		},
		{
			name:  "0.0.0.0 bind — counted",
			input: "sshd   500  root  3u   IPv4  500   0t0  TCP 0.0.0.0:22 (LISTEN)\n",
			want:  1,
		},
		// M-4: UDP lines have no LISTEN token — must be counted separately.
		{
			name: "UDP wildcard — counted",
			// lsof -nP -iTCP -iUDP output: UDP line (no LISTEN token)
			// Field layout: cmd pid user fd type device size/off node name
			// Index:         0   1   2    3  4    5      6        7    8
			input: "avahi  800  avahi  10u  IPv4  8000  0t0  UDP *:5353\n",
			want:  1,
		},
		{
			name: "UDP loopback — excluded",
			input: "proc  100  root  5u  IPv4  1000  0t0  UDP 127.0.0.1:1234\n",
			want:  0,
		},
		{
			name: "TCP LISTEN and UDP on same run",
			input: "sshd   500  root  3u  IPv4   500  0t0  TCP *:22 (LISTEN)\n" +
				"avahi  800  avahi 10u  IPv4  8000  0t0  UDP *:5353\n",
			want: 2,
		},
		{
			name: "UDP 0.0.0.0 — counted",
			input: "process 1000 root 5u  IPv4  1000  0t0  UDP 0.0.0.0:514\n",
			want:  1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseListeningPortsLSOF([]byte(tc.input))
			if got != tc.want {
				t.Errorf("parseListeningPortsLSOF: got %d, want %d", got, tc.want)
			}
		})
	}
}

// ─── parseListeningPortsSS ────────────────────────────────────────────────────

func TestParseListeningPortsSS(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty",
			input: "",
			want:  0,
		},
		{
			name:  "loopback only — excluded",
			input: "LISTEN  0  128  127.0.0.1:3000  0.0.0.0:*\n",
			want:  0,
		},
		{
			name:  "wildcard bind — counted",
			input: "LISTEN  0  128  *:22  *:*  users:((\"sshd\",pid=500,fd=3))\n",
			want:  1,
		},
		{
			name:  "two distinct non-loopback ports",
			input: "LISTEN  0  128  *:22  *:*\n" +
				"LISTEN  0  128  0.0.0.0:8080  0.0.0.0:*\n",
			want: 2,
		},
		{
			name:  "IPv6 loopback — excluded",
			input: "LISTEN  0  128  [::1]:3000  [::]:*\n",
			want:  0,
		},
		{
			name:  "0.0.0.0 — counted",
			input: "LISTEN  0  128  0.0.0.0:22  0.0.0.0:*\n",
			want:  1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseListeningPortsSS([]byte(tc.input))
			if got != tc.want {
				t.Errorf("parseListeningPortsSS: got %d, want %d", got, tc.want)
			}
		})
	}
}

// ─── isPrivateKeyHeader (L-2 regression) ─────────────────────────────────────

// TestIsPrivateKeyHeader verifies that:
//  1. All known PRIVATE KEY PEM markers are recognised.
//  2. The "-----BEGIN OPENSSH PRIVATE KEY-----" header (the correct file-level
//     header for OpenSSH native keys) is accepted.
//  3. The inner base64 magic "openssh-key-v1" is NOT treated as a file header —
//     it never appears as the first bytes of a key file (L-2 fix regression guard).
//  4. Public key PEM markers are rejected.
func TestIsPrivateKeyHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		// All recognised PRIVATE KEY markers.
		{"RSA PEM", "-----BEGIN RSA PRIVATE KEY-----\nMII...", true},
		{"EC PEM", "-----BEGIN EC PRIVATE KEY-----\nMHQ...", true},
		{"DSA PEM", "-----BEGIN DSA PRIVATE KEY-----\nMII...", true},
		{"PKCS8 unencrypted", "-----BEGIN PRIVATE KEY-----\nMII...", true},
		{"PKCS8 encrypted", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMII...", true},
		// OpenSSH native format — correct file-level header (must be accepted).
		{"OpenSSH native", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...", true},
		// L-2 regression guard: the base64 inner magic must NOT be matched as a
		// file header. Real files start with "-----BEGIN OPENSSH PRIVATE KEY-----",
		// never with the "openssh-key-v1" magic.
		{"openssh-key-v1 inner magic (not a file header)", "openssh-key-v1\x00rest", false},
		// Public key — must be rejected.
		{"public key PEM", "-----BEGIN PUBLIC KEY-----\nMIIB...", false},
		{"empty", "", false},
		{"random text", "This is not a key", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isPrivateKeyHeader(tc.header)
			if got != tc.want {
				t.Errorf("isPrivateKeyHeader(%q) = %v, want %v", tc.header[:min(30, len(tc.header))], got, tc.want)
			}
		})
	}
}

// ─── isLoopback ───────────────────────────────────────────────────────────────

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.1.1", true},
		{"::1", true},
		{"localhost", true},
		{"0.0.0.0", false},
		{"*", false},
		{"192.168.1.1", false},
		{"", false},
	}
	for _, tc := range tests {
		got := isLoopback(tc.host)
		if got != tc.want {
			t.Errorf("isLoopback(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
