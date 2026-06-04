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

package consent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Qwentrix/lumen/internal/keys"
)

// TestRunResetRegeneratesKey verifies H-3: when Run is called with reset=true
// the install key is regenerated (rotated), not merely reloaded.
//
// This test exercises the code path:
//   consent.Run(reset=true, acceptAll=true) → keys.RegenerateInstallKey()
// and asserts that the key fingerprint CHANGES across the reset, proving that
// RegenerateInstallKey() was called rather than EnsureInstallKey() (which is
// idempotent and returns the same key).
func TestRunResetRegeneratesKey(t *testing.T) {
	// Isolate to a temp HOME so we don't touch the developer's ~/.lumen.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Redirect stdin away from TTY so the isTTY() guard doesn't block us.
	// We pass acceptAll=true so the walkthrough doesn't try to read from stdin.

	// First call: non-reset, acceptAll — establishes the initial key + consent.
	if err := Run(false, true); err != nil {
		t.Fatalf("initial Run: %v", err)
	}

	// Record fingerprint of the initial key.
	fp1, err := keys.InstallKeyFingerprint()
	if err != nil {
		t.Fatalf("fingerprint after initial Run: %v", err)
	}

	// Second call: reset=true — must rotate the key.
	if err := Run(true, true); err != nil {
		t.Fatalf("Run(reset=true): %v", err)
	}

	// Record fingerprint after reset.
	fp2, err := keys.InstallKeyFingerprint()
	if err != nil {
		t.Fatalf("fingerprint after reset Run: %v", err)
	}

	// The fingerprints must differ — reset must have generated a new key.
	if fp1 == fp2 {
		t.Errorf("H-3: key fingerprint did not change after consent --reset (got %s both times); "+
			"RegenerateInstallKey() was not called", fp1)
	}

	// Also verify the consent file was re-created with all domains accepted.
	c, loadErr := Load()
	if loadErr != nil {
		t.Fatalf("Load after reset: %v", loadErr)
	}
	if c == nil {
		t.Fatal("consent record is nil after reset")
	}
	for name, d := range c.Domains {
		if !d.Accepted {
			t.Errorf("domain %q should be accepted after Run(acceptAll=true), got accepted=false", name)
		}
	}

	// Verify the key file has the correct mode (0600) after reset.
	keyPath := filepath.Join(tmp, ".lumen", "install.key")
	info, statErr := os.Stat(keyPath)
	if statErr != nil {
		t.Fatalf("stat key after reset: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key permissions after reset: got %04o, want 0600", perm)
	}
}

// TestRunNoResetKeepsKey verifies that Run(reset=false) does NOT change the
// install key — EnsureInstallKey() is idempotent.
func TestRunNoResetKeepsKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// First call.
	if err := Run(false, true); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	fp1, err := keys.InstallKeyFingerprint()
	if err != nil {
		t.Fatalf("fingerprint after first Run: %v", err)
	}

	// Second call without reset.
	if err := Run(false, true); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	fp2, err := keys.InstallKeyFingerprint()
	if err != nil {
		t.Fatalf("fingerprint after second Run: %v", err)
	}

	if fp1 != fp2 {
		t.Errorf("key should NOT change on non-reset Run: got %s then %s", fp1, fp2)
	}
}
