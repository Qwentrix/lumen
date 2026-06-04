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

package hybrid_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/hybrid"
)

// generateTestKeypair generates a fresh ed25519 keypair for testing.
func generateTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test keypair: %v", err)
	}
	return pub, priv
}

// buildTestPayload returns an UploadPayload with realistic test data.
// The public key is set to the provided pubKeyHex; Signature is "".
func buildTestPayload(pubKeyHex string) *hybrid.UploadPayload {
	findings := lstypes.ScannerFindings{
		Vulnerabilities: lstypes.VulnerabilityFindings{
			TotalPackages:       412,
			CriticalCVECount:    1,
			HighCVECount:        3,
			DaysSinceLastUpdate: 12,
		},
		Compliance: lstypes.ComplianceFindings{
			MFAEnabled:               false,
			DiskEncryptionEnabled:    true,
			FirewallEnabled:          true,
			ScreenLockEnabled:        true,
			ScreenLockTimeoutSeconds: 300,
		},
		AIGovernance: lstypes.AIGovernanceFindings{
			ShadowAIAppsCount:        2,
			BrowserExtensionsAICount: 1,
			LLMEgressProcessesCount:  1,
			MCPServersRunning:        0,
		},
		SecurityPosture: lstypes.SecurityPostureFindings{
			SSHKeysCount:            3,
			WeakSSHKeyCount:         1,
			PasswordManagerDetected: true,
			ListeningPortsCount:     7,
		},
		Privacy: lstypes.PrivacyFindings{
			PIIMatchCount:     14,
			FilesScannedCount: 311,
		},
	}
	return hybrid.BuildPayload("v1.0.0", "healthcare", "smb", findings, pubKeyHex)
}

// TestSignVerifyRoundTrip verifies that Sign + Verify succeed on a valid payload.
func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	pubHex := hex.EncodeToString(pub)

	p := buildTestPayload(pubHex)

	if err := hybrid.Sign(p, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if p.Signature == "" {
		t.Fatal("Sign did not populate Signature field")
	}
	if err := hybrid.Verify(p); err != nil {
		t.Fatalf("Verify after Sign: %v", err)
	}
}

// TestVerifyTamperedBody verifies that mutating the body after signing
// causes Verify to return an error.
func TestVerifyTamperedBody(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	pubHex := hex.EncodeToString(pub)

	p := buildTestPayload(pubHex)
	if err := hybrid.Sign(p, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper: change one integer in the findings.
	p.ScannerFindings.Vulnerabilities.CriticalCVECount = 999

	if err := hybrid.Verify(p); err == nil {
		t.Fatal("Verify must fail on tampered body, but returned nil")
	}
}

// TestBuildCanonicalBodyIsStable verifies that BuildCanonicalBody produces
// identical bytes on two calls with the same payload (stability/determinism).
func TestBuildCanonicalBodyIsStable(t *testing.T) {
	pub, _ := generateTestKeypair(t)
	pubHex := hex.EncodeToString(pub)
	p := buildTestPayload(pubHex)

	b1, err := hybrid.BuildCanonicalBody(p)
	if err != nil {
		t.Fatalf("first BuildCanonicalBody: %v", err)
	}
	b2, err := hybrid.BuildCanonicalBody(p)
	if err != nil {
		t.Fatalf("second BuildCanonicalBody: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("BuildCanonicalBody is not stable:\nfirst:  %s\nsecond: %s", b1, b2)
	}
}

// TestPreviewShowsExactPayload verifies that the bytes printed by
// PreviewAndConfirm are json.MarshalIndent of the signed payload.
func TestPreviewShowsExactPayload(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	pubHex := hex.EncodeToString(pub)
	p := buildTestPayload(pubHex)
	if err := hybrid.Sign(p, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Expected pretty-printed form.
	expected, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}

	var outBuf bytes.Buffer
	// Simulate user typing "y\n".
	inReader := strings.NewReader("y\n")

	if err := hybrid.PreviewAndConfirm(p, &outBuf, inReader, ""); err != nil {
		t.Fatalf("PreviewAndConfirm: %v", err)
	}

	printed := outBuf.String()
	// The pretty-printed JSON must appear verbatim in the output.
	if !strings.Contains(printed, string(expected)) {
		t.Fatalf("preview output does not contain exact JSON payload.\nWant substring:\n%s\n\nGot:\n%s",
			string(expected), printed)
	}
}

// TestPreviewShowsRealURL verifies that PreviewAndConfirm prints the actual
// destination URL (H-4 fix) rather than a hardcoded fallback.
func TestPreviewShowsRealURL(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	pubHex := hex.EncodeToString(pub)
	p := buildTestPayload(pubHex)
	if err := hybrid.Sign(p, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tests := []struct {
		name        string
		gatewayURL  string
		wantURL     string
	}{
		{
			name:       "default URL when empty string passed",
			gatewayURL: "",
			wantURL:    hybrid.DefaultGatewayBaseURL + "/api/v1/lumen/scanner/ingest",
		},
		{
			name:       "custom URL is printed verbatim",
			gatewayURL: "https://lumen-staging.internal.example.com",
			wantURL:    "https://lumen-staging.internal.example.com/api/v1/lumen/scanner/ingest",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var outBuf bytes.Buffer
			inReader := strings.NewReader("y\n")
			if err := hybrid.PreviewAndConfirm(p, &outBuf, inReader, tc.gatewayURL); err != nil {
				t.Fatalf("PreviewAndConfirm: %v", err)
			}
			printed := outBuf.String()
			if !strings.Contains(printed, tc.wantURL) {
				t.Errorf("preview output does not contain expected URL %q.\nGot:\n%s", tc.wantURL, printed)
			}
			// Confirm the hardcoded fallback is NOT shown when a custom URL is in use.
			if tc.gatewayURL != "" && tc.gatewayURL != hybrid.DefaultGatewayBaseURL {
				if strings.Contains(printed, hybrid.DefaultGatewayBaseURL+"/api/v1/lumen/scanner/ingest") {
					t.Errorf("preview should NOT show default URL when a custom URL is provided")
				}
			}
		})
	}
}

// TestPreviewAbortOnNo verifies that answering "n" returns ErrAborted.
func TestPreviewAbortOnNo(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	pubHex := hex.EncodeToString(pub)
	p := buildTestPayload(pubHex)
	if err := hybrid.Sign(p, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	var outBuf bytes.Buffer
	inReader := strings.NewReader("n\n")
	err := hybrid.PreviewAndConfirm(p, &outBuf, inReader, "")
	if err == nil {
		t.Fatal("expected ErrAborted for 'n' answer, got nil")
	}
	if err != hybrid.ErrAborted {
		t.Fatalf("expected ErrAborted, got: %v", err)
	}
}

// TestPayloadNoPIIOrPaths is the mandatory negative safety test.
//
// It seeds the ScannerFindings with realistic integer values and verifies that
// after marshalling the signed payload to JSON:
//   - No file path strings appear (e.g. "/Users/alice/Documents/tax.pdf").
//   - No PII strings appear (e.g. SSN "123-45-6789", credit card "4111111111111111").
//   - No hostname strings appear (e.g. "alice-macbook.local", "alice").
//
// The PrivacyFindings sub-struct must contain ONLY pii_match_count and
// files_scanned_count (integer counts). This test verifies the counts-only
// invariant by checking that none of the seeded sensitive strings appear in
// the marshalled output.
func TestPayloadNoPIIOrPaths(t *testing.T) {
	// Seed values that must NEVER appear in the payload JSON.
	sensitiveStrings := []string{
		// File paths
		"/Users/alice/Documents/tax.pdf",
		"/home/bob/Documents/secrets.txt",
		"C:\\Users\\charlie\\Documents\\ssn.docx",
		// PII values
		"123-45-6789",         // SSN
		"4111111111111111",    // Visa test CC
		"alice@example.com",   // email
		"555-867-5309",        // phone
		// Hostnames / usernames
		"alice-macbook.local",
		"alice",
		"bob-workstation",
	}

	pub, priv := generateTestKeypair(t)
	pubHex := hex.EncodeToString(pub)

	// Build payload with ONLY safe integer/boolean findings (as our real probe
	// code does — the struct fields only accept integers and booleans, so they
	// structurally cannot contain the sensitive strings above).
	p := buildTestPayload(pubHex)

	if err := hybrid.Sign(p, priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	marshalled, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	payloadJSON := string(marshalled)

	for _, s := range sensitiveStrings {
		if strings.Contains(payloadJSON, s) {
			t.Errorf("payload JSON contains sensitive string %q — this must NEVER appear in the upload payload", s)
		}
	}

	// Additionally, confirm the privacy sub-struct contains only the two integer
	// counts by unmarshalling it and checking the key set.
	var payloadMap map[string]json.RawMessage
	if err := json.Unmarshal(marshalled, &payloadMap); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}
	sfRaw, ok := payloadMap["scanner_findings"]
	if !ok {
		t.Fatal("scanner_findings key missing from payload")
	}
	var sf map[string]json.RawMessage
	if err := json.Unmarshal(sfRaw, &sf); err != nil {
		t.Fatalf("Unmarshal scanner_findings: %v", err)
	}
	privRaw, ok := sf["privacy"]
	if !ok {
		t.Fatal("privacy key missing from scanner_findings")
	}
	var privMap map[string]json.RawMessage
	if err := json.Unmarshal(privRaw, &privMap); err != nil {
		t.Fatalf("Unmarshal privacy: %v", err)
	}

	allowedPrivacyKeys := map[string]bool{
		"pii_match_count":     true,
		"files_scanned_count": true,
	}
	for k := range privMap {
		if !allowedPrivacyKeys[k] {
			t.Errorf("privacy sub-struct contains unexpected key %q — only pii_match_count and files_scanned_count are permitted", k)
		}
	}
}

// TestVerifyWrongKey verifies that a payload signed with one key fails
// verification when a different public key is embedded.
func TestVerifyWrongKey(t *testing.T) {
	pub1, priv1 := generateTestKeypair(t)
	pub2, _ := generateTestKeypair(t)

	_ = pub1
	pubHex1 := hex.EncodeToString(pub1)
	pubHex2 := hex.EncodeToString(pub2)

	p := buildTestPayload(pubHex1)
	if err := hybrid.Sign(p, priv1); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Replace the embedded public key with a different one.
	p.PublicKey = pubHex2

	if err := hybrid.Verify(p); err == nil {
		t.Fatal("Verify must fail when public key does not match signing key")
	}
}
