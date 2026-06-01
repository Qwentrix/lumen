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

// Package keys manages the per-install ed25519 identity keypair.
//
// The private key is stored at ~/.lumen/install.key (mode 0600, O_EXCL create
// to prevent accidental overwrite). The public key is stored alongside at
// ~/.lumen/install.pub. Neither file is transmitted anywhere by default — the
// public key fingerprint is only used locally in consent.json and is available
// for the optional --hybrid upload path (LU-5).
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	keyFileName = "install.key"
	pubFileName = "install.pub"
	dirMode     = 0700
	fileMode    = 0600
)

// lumenDir returns the path to the ~/.lumen directory, creating it if needed.
func lumenDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("keys: cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".lumen")
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return "", fmt.Errorf("keys: cannot create %s: %w", dir, err)
	}
	return dir, nil
}

// EnsureInstallKey returns the install keypair, generating it if it does not exist.
//
// The private key is stored raw (64-byte ed25519 seed+public concatenation) as
// a hex-encoded string in ~/.lumen/install.key with mode 0600, created via
// O_EXCL to prevent accidental overwrites. The public key is stored as hex in
// ~/.lumen/install.pub.
//
// Calling EnsureInstallKey twice returns the same keypair (idempotent).
func EnsureInstallKey() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	dir, err := lumenDir()
	if err != nil {
		return nil, nil, err
	}

	keyPath := filepath.Join(dir, keyFileName)
	pubPath := filepath.Join(dir, pubFileName)

	// Attempt exclusive create first. If the file already exists, load it.
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		if os.IsExist(err) {
			return loadExistingKey(keyPath, pubPath)
		}
		return nil, nil, fmt.Errorf("keys: cannot create %s: %w", keyPath, err)
	}
	defer f.Close()

	// Generate a new ed25519 keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		// Remove the empty file we just created so a retry can succeed.
		_ = os.Remove(keyPath)
		return nil, nil, fmt.Errorf("keys: key generation failed: %w", err)
	}

	// Persist private key as hex.
	privHex := hex.EncodeToString(priv)
	if _, err := f.WriteString(privHex); err != nil {
		_ = os.Remove(keyPath)
		return nil, nil, fmt.Errorf("keys: writing private key: %w", err)
	}

	// Persist public key alongside (0600 — not secret but keep consistent).
	pubHex := hex.EncodeToString(pub)
	if err := os.WriteFile(pubPath, []byte(pubHex), fileMode); err != nil {
		_ = os.Remove(keyPath)
		return nil, nil, fmt.Errorf("keys: writing public key: %w", err)
	}

	return priv, pub, nil
}

// RegenerateInstallKey deletes the existing keypair and generates a new one.
// Used by `lumen consent --reset`.
func RegenerateInstallKey() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	dir, err := lumenDir()
	if err != nil {
		return nil, nil, err
	}
	_ = os.Remove(filepath.Join(dir, keyFileName))
	_ = os.Remove(filepath.Join(dir, pubFileName))
	return EnsureInstallKey()
}

// InstallKeyFingerprint returns a 16-character hex fingerprint of the public key.
// The fingerprint is sha256(pub)[:8 bytes] encoded as 16 hex characters.
func InstallKeyFingerprint() (string, error) {
	dir, err := lumenDir()
	if err != nil {
		return "", err
	}
	pubPath := filepath.Join(dir, pubFileName)
	data, err := os.ReadFile(pubPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("keys: public key not found; run `lumen consent` first")
		}
		return "", fmt.Errorf("keys: reading public key: %w", err)
	}
	pubBytes, err := hex.DecodeString(string(data))
	if err != nil {
		return "", fmt.Errorf("keys: malformed public key file: %w", err)
	}
	h := sha256.Sum256(pubBytes)
	return hex.EncodeToString(h[:8]), nil
}

// loadExistingKey reads and validates an existing keypair from disk.
func loadExistingKey(keyPath, pubPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	// Verify file permissions are exactly 0600.
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: cannot stat %s: %w", keyPath, err)
	}
	if perm := info.Mode().Perm(); perm != fileMode {
		return nil, nil, fmt.Errorf(
			"keys: %s has insecure permissions %04o (want 0600); "+
				"run `lumen consent --reset` to regenerate",
			keyPath, perm,
		)
	}

	privData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: reading private key: %w", err)
	}
	privBytes, err := hex.DecodeString(string(privData))
	if err != nil {
		return nil, nil, fmt.Errorf("keys: malformed private key file: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf(
			"keys: private key wrong length: got %d bytes, want %d",
			len(privBytes), ed25519.PrivateKeySize,
		)
	}
	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}
