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

package keys

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestEnsureInstallKey verifies key generation, idempotency, and file permissions.
func TestEnsureInstallKey(t *testing.T) {
	// Override HOME to an isolated temp dir for this test.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// First call: key should be generated.
	priv1, pub1, err := EnsureInstallKey()
	if err != nil {
		t.Fatalf("first EnsureInstallKey: %v", err)
	}
	if priv1 == nil || pub1 == nil {
		t.Fatal("expected non-nil keypair on first call")
	}

	// Verify mode 0600 on the private key file.
	keyPath := filepath.Join(tmp, ".lumen", keyFileName)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("private key permissions: got %04o, want 0600", perm)
	}

	// Second call: must return the same key (idempotent, no overwrite).
	priv2, pub2, err := EnsureInstallKey()
	if err != nil {
		t.Fatalf("second EnsureInstallKey: %v", err)
	}
	if hex.EncodeToString(priv1) != hex.EncodeToString(priv2) {
		t.Error("second call returned different private key (overwrite detected)")
	}
	if hex.EncodeToString(pub1) != hex.EncodeToString(pub2) {
		t.Error("second call returned different public key (overwrite detected)")
	}

	// Verify fingerprint is 16 hex characters.
	fp, err := InstallKeyFingerprint()
	if err != nil {
		t.Fatalf("InstallKeyFingerprint: %v", err)
	}
	if len(fp) != 16 {
		t.Errorf("fingerprint length: got %d, want 16", len(fp))
	}
}

// TestRegenerateInstallKey verifies that --reset creates a new keypair.
func TestRegenerateInstallKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	priv1, _, err := EnsureInstallKey()
	if err != nil {
		t.Fatalf("initial keygen: %v", err)
	}

	priv2, _, err := RegenerateInstallKey()
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	if hex.EncodeToString(priv1) == hex.EncodeToString(priv2) {
		t.Error("regenerated key is identical to original — expected a different key")
	}

	// Verify the new key file also has 0600.
	keyPath := filepath.Join(tmp, ".lumen", keyFileName)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat regenerated key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("regenerated key permissions: got %04o, want 0600", perm)
	}
}

// TestFingerprintNoKey verifies a friendly error when no key exists.
func TestFingerprintNoKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, err := InstallKeyFingerprint()
	if err == nil {
		t.Fatal("expected error when no key exists, got nil")
	}
}
