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

package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ErrSignatureVerificationFailed is returned when the bundle's ed25519
// signature does not match the pinned public key. The literal token
// "signature_verification_failed" is included in the error message as required
// by ENT-108 acceptance criteria.
var ErrSignatureVerificationFailed = fmt.Errorf("signature_verification_failed")

// VerifyBundle verifies that:
//  1. SHA-256 of bundleBytes matches the manifest's bundle_sha256.
//  2. ed25519.Verify(pinnedPubKey, sha256Bytes, sig) is true.
//
// On any mismatch it returns a typed error wrapping ErrSignatureVerificationFailed.
// A tampered or invalid-signature bundle MUST NOT be applied — callers must check
// for this error before calling Apply.
func VerifyBundle(m *bundleManifest, bundleBytes []byte) error {
	if m == nil {
		return fmt.Errorf("update: nil manifest")
	}

	// 1. SHA-256 integrity check.
	digest := sha256.Sum256(bundleBytes)
	digestHex := hex.EncodeToString(digest[:])

	expectedSHA := m.BundleSHA256
	if len(expectedSHA) > 2 && (expectedSHA[:2] == "0x" || expectedSHA[:2] == "0X") {
		expectedSHA = expectedSHA[2:]
	}

	if digestHex != expectedSHA {
		return fmt.Errorf("update: SHA-256 mismatch (got %s, expected %s): %w",
			digestHex, m.BundleSHA256, ErrSignatureVerificationFailed)
	}

	// 2. ed25519 signature verification over the raw sha256 bytes.
	sigBytes, err := hex.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("update: signature hex decode error (%w): %w", err, ErrSignatureVerificationFailed)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("update: unexpected signature size %d (want %d): %w",
			len(sigBytes), ed25519.SignatureSize, ErrSignatureVerificationFailed)
	}

	pubKey := effectivePubKey()
	ok := ed25519.Verify(ed25519.PublicKey(pubKey[:]), digest[:], sigBytes)
	if !ok {
		return fmt.Errorf("update: ed25519 signature invalid: %w", ErrSignatureVerificationFailed)
	}

	return nil
}
