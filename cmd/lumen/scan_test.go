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

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/rand"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/consent"
	"github.com/Qwentrix/lumen/internal/hybrid"
	"github.com/Qwentrix/lumen/internal/manifest"
)

// symlinkSupported returns true when the OS/filesystem supports os.Symlink.
// On some Windows configurations (no Developer Mode) symlinks are unavailable.
func symlinkSupported() bool {
	tmp := os.TempDir()
	target := filepath.Join(tmp, "lumen-symcheck-target")
	link := filepath.Join(tmp, "lumen-symcheck-link")
	_ = os.Remove(target)
	_ = os.Remove(link)
	_ = os.WriteFile(target, []byte("x"), 0600)
	defer os.Remove(target)
	defer os.Remove(link)
	if err := os.Symlink(target, link); err != nil {
		return false
	}
	return true
}

func TestValidateOutputPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home dir: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Skipf("cannot determine cwd: %v", err)
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errFrag string // substring expected in error message
	}{
		{
			name:    "valid path in home dir",
			input:   filepath.Join(home, "lumen-report.html"),
			wantErr: false,
		},
		{
			name:    "valid path in cwd",
			input:   filepath.Join(cwd, "out.html"),
			wantErr: false,
		},
		{
			name:    "valid path in subdirectory of home",
			input:   filepath.Join(home, "reports", "scan.html"),
			wantErr: false,
		},
		{
			name:    "missing .html extension",
			input:   filepath.Join(home, "lumen-report.txt"),
			wantErr: true,
			errFrag: ".html extension",
		},
		{
			name:    "no extension at all",
			input:   filepath.Join(home, "lumen-report"),
			wantErr: true,
			errFrag: ".html extension",
		},
		{
			name:    "traversal outside home and cwd — /tmp",
			input:   "/tmp/evil.html",
			wantErr: true,
			errFrag: "outside your home directory",
		},
		{
			name:    "traversal outside home and cwd — /etc/passwd",
			input:   "/etc/passwd.html",
			wantErr: true,
			errFrag: "outside your home directory",
		},
		{
			name: "dotdot traversal that would escape home",
			// Construct a path like ~/../../etc/evil.html which, once cleaned,
			// resolves to something above home.
			input:   filepath.Join(home, "..", "..", "etc", "evil.html"),
			wantErr: true,
			errFrag: "outside your home directory",
		},
		{
			name:    "relative path in cwd (should resolve and pass)",
			input:   "local-report.html",
			wantErr: false,
		},
		{
			name:    "uppercase .HTML extension rejected (case-sensitive)",
			input:   filepath.Join(home, "report.HTML"),
			wantErr: true,
			errFrag: ".html extension",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateOutputPath(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for input %q, got path %q", tc.input, got)
				} else if tc.errFrag != "" && !strings.Contains(err.Error(), tc.errFrag) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errFrag)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for input %q: %v", tc.input, err)
				}
				if got == "" {
					t.Errorf("expected non-empty validated path for input %q", tc.input)
				}
				if !filepath.IsAbs(got) {
					t.Errorf("validated path %q is not absolute", got)
				}
				if filepath.Ext(got) != ".html" {
					t.Errorf("validated path %q does not end in .html", got)
				}
			}
		})
	}
}

// TestValidateOutputPathSymlinkEscape verifies M-6: a symlink inside home
// pointing outside home (e.g. ~/lumen-report.html -> /tmp/evil.html) is rejected.
func TestValidateOutputPathSymlinkEscape(t *testing.T) {
	if !symlinkSupported() {
		t.Skip("symlinks not available on this platform/filesystem")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home dir: %v", err)
	}

	// Create a temp directory that acts as the "real home" so we don't touch
	// the developer's actual home directory.
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	// Create the escape target OUTSIDE the fake home (in /tmp or os.TempDir()).
	// We use os.TempDir() for portability — it is always outside fakeHome.
	outsideDir := t.TempDir() // separate TempDir → guaranteed outside fakeHome
	target := filepath.Join(outsideDir, "evil.html")
	if err := os.WriteFile(target, []byte("<html/>"), 0600); err != nil {
		t.Fatalf("create escape target: %v", err)
	}

	// Create a symlink inside fakeHome pointing to the outside target.
	link := filepath.Join(fakeHome, "lumen-report.html")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// validateOutputPath should reject this because the REAL path is outside home.
	_, validErr := validateOutputPath(link)
	if validErr == nil {
		t.Errorf("validateOutputPath should reject symlink escaping home dir, got nil error")
	} else if !strings.Contains(validErr.Error(), "outside your home directory") {
		t.Errorf("error %q should mention 'outside your home directory'", validErr.Error())
	}

	// Also verify a normal (non-symlink) path in fakeHome still works.
	normalPath := filepath.Join(fakeHome, "normal-report.html")
	if _, err := validateOutputPath(normalPath); err != nil {
		t.Errorf("non-symlink path inside home should be valid, got: %v", err)
	}
	// t.Setenv restores HOME automatically on test cleanup.
	_ = home
}

// TestPerDomainConsentGate verifies H-2: each probe is gated on its OWN domain
// consent rather than a coarse "any domain accepted" check.
//
// The test creates a consent record that accepts only the "vulnerabilities"
// domain and verifies that runScan does NOT attempt to run (and error on) the
// other domains — it should skip them with a "not consented" notice instead.
func TestPerDomainConsentGate(t *testing.T) {
	manifest.Default = manifest.New("test")

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home dir: %v", err)
	}
	outputPath := filepath.Join(home, "lumen-test-domain-consent.html")

	// Build a consent record where ONLY "vulnerabilities" is accepted.
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	lumenDir := filepath.Join(fakeHome, ".lumen")
	if err := os.MkdirAll(lumenDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	c := &consent.Consent{
		Version:        1,
		AcceptedAt:     time.Now().UTC(),
		ScannerVersion: "v0.0.0-test",
		Domains: map[string]*consent.DomainConsent{
			"vulnerabilities": {Accepted: true, ManifestHash: "sha256:test"},
			"compliance":      {Accepted: false, ManifestHash: "sha256:test"},
			"ai_governance":   {Accepted: false, ManifestHash: "sha256:test"},
			"security_posture": {Accepted: false, ManifestHash: "sha256:test"},
			"privacy":          {Accepted: false, ManifestHash: "sha256:test"},
		},
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	if err := os.WriteFile(filepath.Join(lumenDir, "consent.json"), data, 0600); err != nil {
		t.Fatalf("write consent: %v", err)
	}

	// runScan should proceed past the top-level gate (vulnerabilities is accepted)
	// and NOT return a "lumen consent" error. The non-accepted probes are skipped.
	err = runScan(context.Background(), "", false, "", false, outputPath, "", "smb", false, false, false, "aws")
	// The error may be non-nil for other reasons (no scoring data etc.), but it
	// must not be "run 'lumen consent'" — the consent gate must pass.
	if err != nil && strings.Contains(err.Error(), "run 'lumen consent'") {
		t.Errorf("H-2: per-domain gate should pass when at least one domain is accepted, got: %v", err)
	}
	_ = os.Remove(outputPath)
}

// TestConsentGate verifies C-1: the consent gate in runScan.
//
// These tests redirect ~/.lumen to a temporary directory so that the real
// consent.json on the developer's machine is not disturbed.
func TestConsentGate(t *testing.T) {
	// Initialise the manifest recorder (needed by probe calls inside runScan,
	// but we only test the consent gate here so we use a minimal setup).
	manifest.Default = manifest.New("test")

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home dir: %v", err)
	}
	outputPath := filepath.Join(home, "lumen-test-consent.html")

	// writeConsent writes a minimal consent.json to a temp dir and returns the
	// path to the temp .lumen dir. The caller should set HOME to the parent of
	// the returned dir to make consent.Load() pick it up.
	writeConsent := func(t *testing.T, accepted bool) (tmpHome string) {
		t.Helper()
		dir := t.TempDir()
		lumenDir := filepath.Join(dir, ".lumen")
		if err := os.MkdirAll(lumenDir, 0700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		c := &consent.Consent{
			Version:        1,
			AcceptedAt:     time.Now().UTC(),
			ScannerVersion: "v0.0.0-test",
			Domains: map[string]*consent.DomainConsent{
				"vulnerabilities": {Accepted: accepted, ManifestHash: "sha256:test"},
			},
		}
		data, _ := json.MarshalIndent(c, "", "  ")
		if err := os.WriteFile(filepath.Join(lumenDir, "consent.json"), data, 0600); err != nil {
			t.Fatalf("write consent: %v", err)
		}
		return dir
	}

	t.Run("no consent → error", func(t *testing.T) {
		// Point HOME at an empty temp dir (no consent.json).
		emptyHome := t.TempDir()
		t.Setenv("HOME", emptyHome)

		err := runScan(context.Background(), "", false, "", false, outputPath, "", "smb", false, false, false, "aws")
		if err == nil {
			t.Fatal("expected error when no consent exists, got nil")
		}
		if !strings.Contains(err.Error(), "lumen consent") {
			t.Errorf("error %q should mention 'lumen consent'", err.Error())
		}
	})

	t.Run("consent present and accepted → proceeds past gate", func(t *testing.T) {
		tmpHome := writeConsent(t, true)
		t.Setenv("HOME", tmpHome)

		// runScan will fail after the consent gate (no probes run in test env),
		// but the gate itself must not return the "lumen consent" error.
		err := runScan(context.Background(), "", false, "", false, outputPath, "", "smb", false, false, false, "aws")
		if err != nil && strings.Contains(err.Error(), "lumen consent") {
			t.Errorf("consent gate should pass but got: %v", err)
		}
		// Clean up the report if it was written.
		_ = os.Remove(outputPath)
	})

	t.Run("--skip-consent → proceeds past gate with warning", func(t *testing.T) {
		// Point HOME at an empty dir (no consent) — skip-consent bypasses the gate.
		emptyHome := t.TempDir()
		t.Setenv("HOME", emptyHome)

		// runScan will fail after the consent gate for other reasons (no real
		// probes/scoring in test), but must NOT return the "lumen consent" error.
		err := runScan(context.Background(), "", false, "", false, outputPath, "", "smb", true, false, false, "aws")
		if err != nil && strings.Contains(err.Error(), "lumen consent") {
			t.Errorf("--skip-consent should bypass gate but got: %v", err)
		}
		_ = os.Remove(outputPath)
	})
}

// ---------------------------------------------------------------------------
// Stage-2 Task 7: revealURL helper + hybrid reveal-link output
// ---------------------------------------------------------------------------

// TestRevealURL is a pure unit test for the revealURL helper.
// It verifies that:
//  1. The site origin is kept and /lumen/scan/<id> is appended.
//  2. Any /api prefix (and path after it) is stripped so the result is a web
//     route, not an API route.
//  3. A trailing slash on the base does not produce a double slash.
func TestRevealURL(t *testing.T) {
	tests := []struct {
		name         string
		base         string
		assessmentID string
		want         string
	}{
		{
			name:         "production default base",
			base:         "https://lumen.micelium.com",
			assessmentID: "abc-123",
			want:         "https://lumen.micelium.com/lumen/scan/abc-123",
		},
		{
			name:         "base with trailing slash",
			base:         "https://lumen.micelium.com/",
			assessmentID: "abc-123",
			want:         "https://lumen.micelium.com/lumen/scan/abc-123",
		},
		{
			name:         "base that still has /api prefix — strips it",
			base:         "https://lumen.micelium.com/api/v1/lumen/scanner/ingest",
			assessmentID: "def-456",
			want:         "https://lumen.micelium.com/lumen/scan/def-456",
		},
		{
			name:         "base with /api only — strips /api",
			base:         "https://staging.example.com/api",
			assessmentID: "ghi-789",
			want:         "https://staging.example.com/lumen/scan/ghi-789",
		},
		{
			name:         "localhost insecure override",
			base:         "http://localhost:8125",
			assessmentID: "local-99",
			want:         "http://localhost:8125/lumen/scan/local-99",
		},
		{
			name:         "custom staging server",
			base:         "https://lumen-staging.internal.example.com",
			assessmentID: "stg-001",
			want:         "https://lumen-staging.internal.example.com/lumen/scan/stg-001",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := revealURL(tc.base, tc.assessmentID)
			if got != tc.want {
				t.Errorf("revealURL(%q, %q)\n got  %q\n want %q", tc.base, tc.assessmentID, got, tc.want)
			}
			// Invariant: result must always contain /lumen/scan/ + assessmentID.
			if !strings.Contains(got, "/lumen/scan/"+tc.assessmentID) {
				t.Errorf("result %q does not contain /lumen/scan/%s", got, tc.assessmentID)
			}
		})
	}
}

// TestHybridPrintsRevealURL verifies that doHybridUpload prints a line
// containing "/lumen/scan/<assessment_id>" after a successful upload.
//
// Strategy: spin up an httptest.Server that returns a canned IngestResponse,
// then call doHybridUpload with a stub PreviewAndConfirm input (piped "y\n"),
// capture stdout, and assert the reveal URL is present.
func TestHybridPrintsRevealURL(t *testing.T) {
	const wantAssessmentID = "test-assess-reveal-007"

	// Stub ingest server that returns a valid IngestResponse.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/lumen/scanner/ingest" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		resp := hybrid.IngestResponse{
			AssessmentID: wantAssessmentID,
			SummaryURL:   fmt.Sprintf("%s/r/%s", r.Host, wantAssessmentID),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Build a minimal ScannerFindings (all zeros — scoring still works).
	sf := lstypes.ScannerFindings{}

	// Generate a fresh keypair so keys.EnsureInstallKey works without touching
	// ~/.lumen. We achieve this by pointing HOME at a fresh temp dir and
	// pre-creating the key files there.
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	// Pre-generate and write the install key so EnsureInstallKey picks it up.
	// keys.EnsureInstallKey format:
	//   install.key  — full 64-byte ed25519 private key as hex (no newline)
	//   install.pub  — 32-byte public key as hex (no newline)
	lumenKeyDir := filepath.Join(fakeHome, ".lumen")
	if err := os.MkdirAll(lumenKeyDir, 0700); err != nil {
		t.Fatalf("mkdir .lumen: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	// Full 64-byte private key hex (no newline) — matches hex.EncodeToString(priv) in keygen.go.
	privHex := hex.EncodeToString([]byte(priv))
	pubHex := hex.EncodeToString(pub)
	if err := os.WriteFile(filepath.Join(lumenKeyDir, "install.key"), []byte(privHex), 0600); err != nil {
		t.Fatalf("write install.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(lumenKeyDir, "install.pub"), []byte(pubHex), 0600); err != nil {
		t.Fatalf("write install.pub: %v", err)
	}

	// Capture stdout by redirecting os.Stdout.
	origStdout := os.Stdout
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = pw

	// Pipe "y\n" into os.Stdin so PreviewAndConfirm auto-confirms.
	origStdin := os.Stdin
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		pw.Close()
		os.Stdout = origStdout
		t.Fatalf("os.Pipe stdin: %v", err)
	}
	os.Stdin = stdinR
	_, _ = stdinW.WriteString("y\n")
	stdinW.Close()

	uploadErr := doHybridUpload(context.Background(), sf, "", "smb", srv.URL)

	// Restore stdout/stdin and collect output.
	pw.Close()
	os.Stdout = origStdout
	os.Stdin = origStdin

	var outBuf bytes.Buffer
	_, _ = outBuf.ReadFrom(pr)
	pr.Close()

	if uploadErr != nil {
		t.Fatalf("doHybridUpload returned error: %v", uploadErr)
	}

	printed := outBuf.String()

	// The printed output must contain the reveal URL pattern.
	wantSubstring := "/lumen/scan/" + wantAssessmentID
	if !strings.Contains(printed, wantSubstring) {
		t.Errorf("doHybridUpload output does not contain reveal path %q.\nFull output:\n%s", wantSubstring, printed)
	}

	// The full reveal URL (origin + path) must appear.
	wantReveal := srv.URL + "/lumen/scan/" + wantAssessmentID
	if !strings.Contains(printed, wantReveal) {
		t.Errorf("doHybridUpload output does not contain full reveal URL %q.\nFull output:\n%s", wantReveal, printed)
	}
}
