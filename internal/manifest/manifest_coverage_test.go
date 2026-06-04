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

// Package manifest_test — H-6: manifest coverage gate (external test package
// to avoid import cycles, since probe packages import internal/manifest).
//
// TestManifestCoverage verifies that every OSAPIs and FilePaths entry declared
// in each probe's Manifest() appears (as a substring) in SCANNER_MANIFEST.md.
// This keeps the human-readable consent document in sync with the code
// declarations so that auditors can rely on SCANNER_MANIFEST.md as the
// authoritative access declaration.
//
// How it works:
//  1. Collect Manifest() from all 5 probe domains.
//  2. Read SCANNER_MANIFEST.md from the repo root.
//  3. For each declared OSAPIs and FilePaths entry, assert it appears as a
//     substring in the markdown. Test fails listing every missing entry.
//
// To fix a failure: add the missing entry to SCANNER_MANIFEST.md under the
// appropriate domain section, then re-run the test.
package manifest_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Qwentrix/lumen/internal/probes/ai_governance"
	"github.com/Qwentrix/lumen/internal/probes/compliance"
	"github.com/Qwentrix/lumen/internal/probes/common"
	"github.com/Qwentrix/lumen/internal/probes/privacy"
	"github.com/Qwentrix/lumen/internal/probes/security_posture"
	"github.com/Qwentrix/lumen/internal/probes/vulnerabilities"
)

// repoRoot returns the absolute path to the repository root by walking up from
// the test file's directory until a go.mod is found.
func repoRoot(t *testing.T) string {
	t.Helper()
	// runtime.Caller(0) gives the path of THIS source file.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod) walking up from " + file)
		}
		dir = parent
	}
}

// TestManifestCoverage asserts that every OSAPIs and FilePaths entry in each
// probe's Manifest() is documented (as a substring) in SCANNER_MANIFEST.md.
func TestManifestCoverage(t *testing.T) {
	root := repoRoot(t)
	mdPath := filepath.Join(root, "SCANNER_MANIFEST.md")

	mdBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("cannot read SCANNER_MANIFEST.md at %s: %v", mdPath, err)
	}
	md := string(mdBytes)

	// Collect Manifest() from all 5 probe domains.
	// NOTE: we READ these probes' Manifest() only — no Run() called.
	manifests := []common.ManifestEntry{
		vulnerabilities.Manifest(),
		compliance.Manifest(),
		ai_governance.Manifest(),
		security_posture.Manifest(),
		privacy.Manifest(),
	}

	var failures []string

	for _, m := range manifests {
		// Check every OSAPIs entry.
		for _, api := range m.OSAPIs {
			// Normalise: trim surrounding whitespace, but keep the full string
			// for matching — the markdown may include it as a table cell value.
			needle := strings.TrimSpace(api)
			if needle == "" {
				continue
			}
			// Use the first significant token (the executable path or command
			// name) for a more lenient substring check, since the markdown
			// tables may split args into a separate column.
			//
			// Full-string match is preferred; fall back to first-token match.
			if !strings.Contains(md, needle) {
				// Try matching just the executable/command portion (first space-delimited token).
				firstToken := strings.Fields(needle)[0]
				if !strings.Contains(md, firstToken) {
					failures = append(failures,
						"["+m.DomainID+"] OSAPIs entry not found in SCANNER_MANIFEST.md: "+needle)
				}
			}
		}

		// Check every FilePaths entry.
		for _, fp := range m.FilePaths {
			needle := strings.TrimSpace(fp)
			if needle == "" {
				continue
			}
			// For file paths, use the first path segment as the search token
			// (strips trailing annotation text like " (directory listing only)").
			firstToken := strings.Fields(needle)[0]
			if !strings.Contains(md, firstToken) {
				failures = append(failures,
					"["+m.DomainID+"] FilePaths entry not found in SCANNER_MANIFEST.md: "+needle)
			}
		}
	}

	if len(failures) > 0 {
		t.Errorf("H-6 manifest coverage: %d probe Manifest() entries not documented in SCANNER_MANIFEST.md:\n  %s\n\nFix: add the missing entries to SCANNER_MANIFEST.md under the appropriate domain section.",
			len(failures), strings.Join(failures, "\n  "))
	}
}
