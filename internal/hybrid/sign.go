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

package hybrid

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// BuildCanonicalBody returns the deterministic JSON bytes that are signed and
// verified. The Signature field is set to "" before marshalling so it is always
// excluded from the signed message (avoids a chicken-and-egg problem).
//
// The canonical form uses encoding/json's default field ordering, which is
// stable for a fixed struct type. This is sufficient for a single Go
// implementation on both client and server; no external canonicalisation
// library is required.
func BuildCanonicalBody(p *UploadPayload) ([]byte, error) {
	// Shallow copy so we do not mutate the caller's payload.
	canonical := *p
	canonical.Signature = ""
	body, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("hybrid: marshal canonical body: %w", err)
	}
	return body, nil
}

// Sign computes the ed25519 signature over the canonical body and writes the
// hex-encoded signature back into p.Signature.
//
// The private key must be a 64-byte ed25519.PrivateKey (as returned by
// internal/keys.EnsureInstallKey). After Sign, the payload is ready for upload.
func Sign(p *UploadPayload, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("hybrid: private key wrong length: got %d, want %d",
			len(priv), ed25519.PrivateKeySize)
	}
	body, err := BuildCanonicalBody(p)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, body)
	p.Signature = hex.EncodeToString(sig)
	return nil
}

// Verify verifies the ed25519 signature on a received payload.
// It re-derives the canonical body (zeroing the Signature field), decodes
// the public key from the payload's PublicKey field, and calls ed25519.Verify.
//
// Returns nil on success, a descriptive error on failure.
// This is the same verification logic used by the server-side handler.
func Verify(p *UploadPayload) error {
	pubBytes, err := hex.DecodeString(p.PublicKey)
	if err != nil {
		return fmt.Errorf("hybrid: decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("hybrid: public key wrong length: got %d, want %d",
			len(pubBytes), ed25519.PublicKeySize)
	}
	sigBytes, err := hex.DecodeString(p.Signature)
	if err != nil {
		return fmt.Errorf("hybrid: decode signature: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("hybrid: signature wrong length: got %d, want %d",
			len(sigBytes), ed25519.SignatureSize)
	}
	body, err := BuildCanonicalBody(p)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), body, sigBytes) {
		return fmt.Errorf("hybrid: signature verification failed")
	}
	return nil
}
