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

// Parser unit tests for the compliance probe.
//
// All parser functions are pure (raw bytes in → typed result out) and are
// therefore testable on any OS regardless of build tags. The tests live in the
// package itself (not _test) so they can access the unexported parse* functions
// directly without needing a separate package import.
//
// Build tag: none — runs on ALL platforms including the macOS dev box, allowing
// Linux parser tests to be validated without a Linux host.
package compliance

import "testing"

// ─── macOS parsers ───────────────────────────────────────────────────────────

func TestParseFdesetupStatus(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "FileVault is On",
			input: []byte("FileVault is On.\n"),
			want:  true,
		},
		{
			name:  "FileVault is Off",
			input: []byte("FileVault is Off (Core Storage).\n"),
			want:  false,
		},
		{
			name:  "FileVault is On (2)",
			input: []byte("FileVault is On (2).\n"),
			want:  true,
		},
		{
			name:  "empty output",
			input: []byte(""),
			want:  false,
		},
		{
			name:  "in progress",
			input: []byte("Encryption in progress: Percent completed = 42.3%\n"),
			want:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseFdesetupStatus(tc.input)
			if got != tc.want {
				t.Errorf("parseFdesetupStatus(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseSocketfilterfw(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		enabled bool
		ok      bool
	}{
		{
			name:    "enabled state 1",
			input:   []byte("Firewall is enabled. (State = 1)\n"),
			enabled: true,
			ok:      true,
		},
		{
			name:    "disabled state 0",
			input:   []byte("Firewall is disabled. (State = 0)\n"),
			enabled: false,
			ok:      true,
		},
		{
			name:    "empty output — not parseable",
			input:   []byte(""),
			enabled: false,
			ok:      false,
		},
		{
			name:    "unknown format",
			input:   []byte("something else entirely\n"),
			enabled: false,
			ok:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotEnabled, gotOK := parseSocketfilterfw(tc.input)
			if gotOK != tc.ok || gotEnabled != tc.enabled {
				t.Errorf("parseSocketfilterfw(%q) = (%v, %v), want (%v, %v)",
					tc.input, gotEnabled, gotOK, tc.enabled, tc.ok)
			}
		})
	}
}

func TestParseALFGlobalState(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"0\n", false},
		{"1\n", true},
		{"2\n", true},   // block all incoming — still "enabled"
		{"0", false},
		{"1", true},
		{"", false},
		{"abc", false},
	}
	for _, tc := range tests {
		got := parseALFGlobalState([]byte(tc.input))
		if got != tc.want {
			t.Errorf("parseALFGlobalState(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseScreenLockDarwin(t *testing.T) {
	tests := []struct {
		name            string
		askForPassword  []byte
		delay           []byte
		idleTime        []byte
		wantEnabled     bool
		wantTimeoutSecs int
	}{
		{
			name:            "lock enabled, 5 min idle, 0 delay",
			askForPassword:  []byte("1\n"),
			delay:           []byte("0\n"),
			idleTime:        []byte("300\n"),
			wantEnabled:     true,
			wantTimeoutSecs: 300,
		},
		{
			name:            "lock disabled",
			askForPassword:  []byte("0\n"),
			delay:           []byte("0\n"),
			idleTime:        []byte("300\n"),
			wantEnabled:     false,
			wantTimeoutSecs: 300,
		},
		{
			name:            "lock enabled with delay",
			askForPassword:  []byte("1\n"),
			delay:           []byte("5\n"),
			idleTime:        []byte("300\n"),
			wantEnabled:     true,
			wantTimeoutSecs: 305,
		},
		{
			name:            "empty outputs — all zero",
			askForPassword:  []byte(""),
			delay:           []byte(""),
			idleTime:        []byte(""),
			wantEnabled:     false,
			wantTimeoutSecs: 0,
		},
		{
			name:            "non-numeric idleTime — zero timeout",
			askForPassword:  []byte("1\n"),
			delay:           []byte("0\n"),
			idleTime:        []byte("not-a-number\n"),
			wantEnabled:     true,
			wantTimeoutSecs: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseScreenLockDarwin(tc.askForPassword, tc.delay, tc.idleTime)
			if got.enabled != tc.wantEnabled {
				t.Errorf("enabled: got %v, want %v", got.enabled, tc.wantEnabled)
			}
			if got.timeoutSeconds != tc.wantTimeoutSecs {
				t.Errorf("timeoutSeconds: got %d, want %d", got.timeoutSeconds, tc.wantTimeoutSecs)
			}
		})
	}
}

// ─── Linux parsers ───────────────────────────────────────────────────────────

func TestParseCrypttab(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name: "active mapping present",
			input: []byte(`# <target name>	<source device>		<key file>	<options>
luks-abc123  UUID=abc123  /dev/urandom  swap
`),
			want: true,
		},
		{
			name:  "only comments and blanks",
			input: []byte("# This is a comment\n\n  \n"),
			want:  false,
		},
		{
			name:  "empty file",
			input: []byte(""),
			want:  false,
		},
		{
			name: "single field line — not enough fields",
			input: []byte("onlyname\n"),
			want:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCrypttab(tc.input)
			if got != tc.want {
				t.Errorf("parseCrypttab = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseLsblkForCrypt(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name: "has crypt device",
			input: []byte(`sda      disk
sda1     part
sda2     part
dm-0     crypt
`),
			want: true,
		},
		{
			name: "no crypt device",
			input: []byte(`sda      disk
sda1     part
sda2     part
`),
			want: false,
		},
		{
			name:  "empty output",
			input: []byte(""),
			want:  false,
		},
		{
			name:  "CRYPT uppercase — case insensitive",
			input: []byte("dm-1     CRYPT\n"),
			want:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLsblkForCrypt(tc.input)
			if got != tc.want {
				t.Errorf("parseLsblkForCrypt = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseUFWConf(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name: "enabled",
			input: []byte(`# /etc/ufw/ufw.conf
ENABLED=yes
LOGLEVEL=low
`),
			want: true,
		},
		{
			name: "disabled",
			input: []byte(`ENABLED=no
LOGLEVEL=low
`),
			want: false,
		},
		{
			name:  "commented out",
			input: []byte("# ENABLED=yes\n"),
			want:  false,
		},
		{
			name:  "empty file",
			input: []byte(""),
			want:  false,
		},
		{
			name:  "spaces around equals",
			input: []byte("ENABLED = yes\n"),
			want:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseUFWConf(tc.input)
			if got != tc.want {
				t.Errorf("parseUFWConf = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseFirewalldState(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"running\n", true},
		{"running", true},
		{"not running\n", false},
		{"", false},
		{"stopped\n", false},
	}
	for _, tc := range tests {
		got := parseFirewalldState([]byte(tc.input))
		if got != tc.want {
			t.Errorf("parseFirewalldState(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseScreenLockLinux(t *testing.T) {
	tests := []struct {
		name            string
		lockEnabled     []byte
		lockDelay       []byte
		idleDelay       []byte
		wantEnabled     bool
		wantTimeoutSecs int
	}{
		{
			name:            "enabled with 5-min idle no extra delay",
			lockEnabled:     []byte("true\n"),
			lockDelay:       []byte("uint32 0\n"),
			idleDelay:       []byte("uint32 300\n"),
			wantEnabled:     true,
			wantTimeoutSecs: 300,
		},
		{
			name:            "disabled",
			lockEnabled:     []byte("false\n"),
			lockDelay:       []byte("uint32 0\n"),
			idleDelay:       []byte("uint32 600\n"),
			wantEnabled:     false,
			wantTimeoutSecs: 600,
		},
		{
			name:            "plain integer values (no uint32 prefix)",
			lockEnabled:     []byte("true\n"),
			lockDelay:       []byte("30\n"),
			idleDelay:       []byte("600\n"),
			wantEnabled:     true,
			wantTimeoutSecs: 630,
		},
		{
			name:            "empty outputs",
			lockEnabled:     []byte(""),
			lockDelay:       []byte(""),
			idleDelay:       []byte(""),
			wantEnabled:     false,
			wantTimeoutSecs: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseScreenLockLinux(tc.lockEnabled, tc.lockDelay, tc.idleDelay)
			if got.enabled != tc.wantEnabled {
				t.Errorf("enabled: got %v, want %v", got.enabled, tc.wantEnabled)
			}
			if got.timeoutSeconds != tc.wantTimeoutSecs {
				t.Errorf("timeoutSeconds: got %d, want %d", got.timeoutSeconds, tc.wantTimeoutSecs)
			}
		})
	}
}

func TestParseGSettingsUint32(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"uint32 300", 300},
		{"300", 300},
		{"0", 0},
		{"uint32 0", 0},
		{"", 0},
		{"abc", 0},
		{"uint32 abc", 0},
	}
	for _, tc := range tests {
		got := parseGSettingsUint32(tc.input)
		if got != tc.want {
			t.Errorf("parseGSettingsUint32(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// TestParseIntDefaultOverflow verifies L-4: a huge numeric string is capped at
// parseIntDefaultMax (604800) rather than overflowing into a negative int.
func TestParseIntDefaultOverflow(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "normal small value",
			input: "300",
			want:  300,
		},
		{
			name:  "exactly at cap",
			input: "604800",
			want:  604800,
		},
		{
			name:  "one over cap — capped",
			input: "604801",
			want:  604800,
		},
		{
			name: "huge value — capped, no overflow",
			// 99999999999999999 would overflow int32/int64 wrap-around to negative.
			input: "99999999999999999",
			want:  604800,
		},
		{
			name:  "empty — returns default",
			input: "",
			want:  0,
		},
		{
			name:  "non-numeric — returns default",
			input: "abc",
			want:  0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseIntDefault(tc.input, 0)
			if got != tc.want {
				t.Errorf("parseIntDefault(%q, 0) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}
