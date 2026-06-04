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

// Package update implements the `lumen update` network delta client.
//
// Bundle format (lumen-bundles GitHub release):
//   - lumen-content-<sha>.tar.gz  — contains content/lumen/rules/*.yaml + overlays/*.yaml
//   - manifest.json               — { bundle_url, bundle_sha256, ed25519_signature,
//                                     generated_at, rule_count, overlay_count }
//
// Signing scheme:
//   - The signature in manifest.json is ed25519(privateKey, bundle_sha256_bytes)
//     where bundle_sha256_bytes = sha256(bundle.tar.gz) as a raw 32-byte digest.
//   - The public key is pinned in this file; it is NOT overridable by any
//     flag, env var, or config file.  Rotating the key requires a new binary release.
//
// PROVISIONING NOTE: The lumen-bundles repo and real keypair do not exist yet.
// The key below is a placeholder test key ONLY. See §9 of LU5-BUILD-BLUEPRINT.md.
//
// RELEASE GATE (C-2): TestPinnedKeyIsNotPlaceholder in update_test.go will FAIL
// when LUMEN_RELEASE=1 is set in the environment and PinnedPublicKey still equals
// the known placeholder bytes below.  The release pipeline MUST set LUMEN_RELEASE=1
// to enforce this gate.  Normal dev/CI runs (no LUMEN_RELEASE) skip the test so
// they stay green while the keypair is being provisioned.
package update

import "sync"

// PinnedPublicKey is the ed25519 public key used to verify signed content bundles
// downloaded from github.com/Qwentrix/lumen-bundles releases.
//
// PROVISIONING: replace this placeholder with the real lumen-bundles signing
// public key once the keypair is generated and the lumen-bundles repo is set up.
// Steps:
//  1. Generate keypair: `openssl genpkey -algorithm ed25519 -out signing.key`
//     Extract public: `openssl pkey -in signing.key -pubout -out signing.pub`
//     Convert to raw 32-byte: `openssl pkey -in signing.key -pubout -outform DER | tail -c 32`
//  2. Store PRIVATE key as GitHub Actions secret LUMEN_BUNDLE_SIGNING_KEY in the
//     lumen-bundles repo (HSM-backed in v2 per design §13.6).
//  3. Replace PinnedPublicKey below with the 32-byte raw ed25519 public key.
//  4. This change requires a new tagged binary release (key rotation requires new binary).
//
// This placeholder key was generated locally for testing only. It corresponds to
// no real signing operation and will reject all real bundle downloads.
var PinnedPublicKey = [32]byte{
	// PLACEHOLDER — generated for test infrastructure only.
	// Replace before production deployment.
	0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
	0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
	0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
	0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
}

// testKeyMu guards testPublicKeyOverride against data races when tests call
// injectTestKey concurrently (L-1).  Both setTestPublicKey and effectivePubKey
// must hold this mutex; the zero value is unlocked and ready to use.
var testKeyMu sync.RWMutex

// testPublicKeyOverride allows tests to inject a different public key without
// modifying the global PinnedPublicKey.  It is unexported, never read by any
// production code path (no flag, env var, or HTTP handler references it), and
// is only mutated via setTestPublicKey which is called exclusively from test
// helpers.  Production builds have no way to trigger this seam.
var testPublicKeyOverride *[32]byte

// setTestPublicKey sets (or clears when key==nil) the test-only key override.
// It must only be called from test helpers.
func setTestPublicKey(key *[32]byte) {
	testKeyMu.Lock()
	defer testKeyMu.Unlock()
	testPublicKeyOverride = key
}

// effectivePubKey returns the public key to use for signature verification.
// In production this is always PinnedPublicKey.  Test code may call
// setTestPublicKey to exercise the full verify/apply path with a
// locally-generated keypair.
func effectivePubKey() [32]byte {
	testKeyMu.RLock()
	defer testKeyMu.RUnlock()
	if testPublicKeyOverride != nil {
		return *testPublicKeyOverride
	}
	return PinnedPublicKey
}
