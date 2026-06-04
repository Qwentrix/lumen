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

// Windows vulnerability parser tests — no build tag; runs on any host (macOS dev box).
// Tests the pure parser functions parseWindowsUpdateDate and normaliseWindowsAppName.
package vulnerabilities

import (
	"testing"
	"time"
)

// TestParseWindowsUpdateDate verifies that all date formats emitted by Windows
// Update registry / PowerShell Get-HotFix are parsed correctly.
func TestParseWindowsUpdateDate(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name     string
		input    string
		wantDays int // approximate (±1 acceptable)
		wantOK   bool
	}{
		{
			name:     "registry format YYYY-MM-DD HH:MM:SS",
			input:    now.AddDate(0, 0, -10).Format("2006-01-02 15:04:05"),
			wantDays: 10,
			wantOK:   true,
		},
		{
			name:     "registry format YYYY-MM-DD only",
			input:    now.AddDate(0, 0, -5).Format("2006-01-02"),
			wantDays: 5,
			wantOK:   true,
		},
		{
			name:     "PowerShell MM/DD/YYYY HH:MM:SS AM (12-hour)",
			input:    now.AddDate(0, 0, -20).Format("1/2/2006") + " 10:30:00 AM",
			wantDays: 20,
			wantOK:   true,
		},
		{
			name:     "RFC3339",
			input:    now.AddDate(0, 0, -15).Format(time.RFC3339),
			wantDays: 15,
			wantOK:   true,
		},
		{
			name:   "empty string",
			input:  "",
			wantOK: false,
		},
		{
			name:   "garbage",
			input:  "not a date at all",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			days, ok := parseWindowsUpdateDate([]byte(tc.input))
			if ok != tc.wantOK {
				t.Errorf("parseWindowsUpdateDate(%q): ok=%v, want %v", tc.input, ok, tc.wantOK)
			}
			if tc.wantOK && abs(days-tc.wantDays) > 1 {
				t.Errorf("parseWindowsUpdateDate(%q): days=%d, want ~%d (±1)", tc.input, days, tc.wantDays)
			}
		})
	}
}

// TestNormaliseWindowsAppName verifies suffix stripping and lowercasing.
func TestNormaliseWindowsAppName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Microsoft Edge (64-bit)", "microsoft_edge"},
		{"7-Zip 24.09 (x64)", "7-zip_24.09"},
		{"Zoom (64 bit)", "zoom"},
		{"Visual Studio Code", "visual_studio_code"},
		{"Python 3.11.9 (32-bit)", "python_3.11.9"},
		{"OpenVPN 2.6.9 (x86)", "openvpn_2.6.9"},
		{"Git", "git"},
		{"", ""},
	}

	for _, tc := range tests {
		got := normaliseWindowsAppName(tc.input)
		if got != tc.want {
			t.Errorf("normaliseWindowsAppName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
