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

// Windows compliance parser tests — no build tag; runs on any host (macOS dev box).
// Tests the pure parser function parseScreenLockWindows.
package compliance

import (
	"testing"
)

// TestParseScreenLockWindows tests all combinations of Windows screensaver registry values.
func TestParseScreenLockWindows(t *testing.T) {
	tests := []struct {
		name            string
		active          string // ScreenSaveActive
		secure          string // ScreenSaverIsSecure
		timeout         string // ScreenSaveTimeOut (seconds)
		wantEnabled     bool
		wantTimeoutSecs int
	}{
		{
			name:            "both enabled, 300s",
			active:          "1",
			secure:          "1",
			timeout:         "300",
			wantEnabled:     true,
			wantTimeoutSecs: 300,
		},
		{
			name:            "screensaver active but no password",
			active:          "1",
			secure:          "0",
			timeout:         "600",
			wantEnabled:     false,
			wantTimeoutSecs: 600,
		},
		{
			name:            "both disabled",
			active:          "0",
			secure:          "0",
			timeout:         "0",
			wantEnabled:     false,
			wantTimeoutSecs: 0,
		},
		{
			name:            "password required but screensaver off",
			active:          "0",
			secure:          "1",
			timeout:         "180",
			wantEnabled:     false,
			wantTimeoutSecs: 180,
		},
		{
			name:            "empty values (defaults)",
			active:          "",
			secure:          "",
			timeout:         "",
			wantEnabled:     false,
			wantTimeoutSecs: 0,
		},
		{
			name:            "whitespace trimmed",
			active:          "  1  ",
			secure:          " 1 ",
			timeout:         " 60 ",
			wantEnabled:     true,
			wantTimeoutSecs: 60,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseScreenLockWindows([]byte(tc.active), []byte(tc.secure), []byte(tc.timeout))
			if result.enabled != tc.wantEnabled {
				t.Errorf("enabled = %v, want %v", result.enabled, tc.wantEnabled)
			}
			if result.timeoutSeconds != tc.wantTimeoutSecs {
				t.Errorf("timeoutSeconds = %d, want %d", result.timeoutSeconds, tc.wantTimeoutSecs)
			}
		})
	}
}
