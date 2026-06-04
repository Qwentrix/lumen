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

// Package privacy implements an opt-in DLP scanner that detects PII patterns
// in ~/Documents.
//
// # Safety guarantees (SAFETY-CRITICAL)
//
//  1. The probe ONLY runs when --include-privacy is set on the CLI and the
//     privacy domain has been consented to. It is never invoked by default.
//  2. No filename, file path, matched string, or file content is ever recorded
//     in ProbeResult, Metadata, the manifest, or anywhere else.
//     Only scalar counters (pii_match_count, files_scanned_count) are emitted.
//  3. Symlinks are never followed. The scan root is checked with os.Lstat
//     before WalkDir is called — if the root itself is a symlink the scan is
//     skipped entirely. Within the tree, os.ReadDir / filepath.WalkDir skip
//     symlinked entries; os.Open is called only on regular files identified
//     via DirEntry.Type().
//  4. Files larger than maxFileSizeBytes (5 MiB) are skipped.
//  5. Likely-binary files are skipped via a heuristic NUL-byte scan on the
//     first 512 bytes.
//  6. The total number of files inspected is capped at maxFilesPerScan (5000).
//  7. The scan is bounded to ~/Documents only — no other paths.
//
// These guarantees are verified by TestPrivacyNoLeakInProbeResult in the
// accompanying probe_test.go file.
package privacy

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "privacy"

// maxFileSizeBytes is the maximum file size (in bytes) that the scanner will
// read. Files larger than this are skipped (cap: 5 MiB).
const maxFileSizeBytes = 5 * 1024 * 1024

// maxFilesPerScan is the maximum number of files the scanner will inspect in
// a single run to prevent runaway scans on large home directories.
const maxFilesPerScan = 5000

// binarySniffBytes is the number of bytes read from the start of a file to
// detect likely-binary content via NUL byte presence.
const binarySniffBytes = 512

// ssnPattern matches U.S. Social Security Numbers in the format DDD-DD-DDDD.
// The pattern requires word boundaries to reduce false positives.
var ssnPattern = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

// creditCardPattern matches candidate credit card numbers (13-19 consecutive
// digits). All matches are validated by the Luhn algorithm before counting.
var creditCardPattern = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)

// Run executes the privacy probe.
//
// The probe is a no-op when includePrivacy is false (the default). When enabled,
// it walks ~/Documents and applies the bundled PII regex set. Only scalar
// counters are returned — no file paths, filenames, or matched content.
func Run(ctx context.Context) (*common.ProbeResult, error) {
	return runPrivacy(ctx, false)
}

// RunWithPrivacy executes the privacy probe with PII scanning enabled.
// Called by scan.go when --include-privacy is set.
func RunWithPrivacy(ctx context.Context) (*common.ProbeResult, error) {
	return runPrivacy(ctx, true)
}

// runPrivacy is the internal implementation. includePrivacy gates the scan.
func runPrivacy(ctx context.Context, includePrivacy bool) (*common.ProbeResult, error) {
	// Gate: privacy probe runs ONLY when explicitly opted in.
	if !includePrivacy {
		return &common.ProbeResult{
			DomainID: domainID,
			Findings: []common.FindingHint{},
			Metadata: map[string]interface{}{"status": "disabled — use --include-privacy to enable"},
			ScannerFields: common.ScannerFields{
				Privacy: &lstypes.PrivacyFindings{
					PIIMatchCount:    0,
					FilesScannedCount: 0,
				},
			},
		}, nil
	}

	meta := map[string]interface{}{}

	home, err := os.UserHomeDir()
	if err != nil {
		meta["privacy_home_unavailable"] = "cannot determine home directory"
		return &common.ProbeResult{
			DomainID: domainID,
			Findings: []common.FindingHint{},
			Metadata: meta,
			ScannerFields: common.ScannerFields{
				Privacy: &lstypes.PrivacyFindings{},
			},
		}, nil
	}

	scanRoot := filepath.Join(home, "Documents")
	piiCount, filesScanned := walkAndScan(ctx, scanRoot, meta)

	// SAFETY: only scalar counters are returned. No paths, no content.
	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: meta,
		ScannerFields: common.ScannerFields{
			Privacy: &lstypes.PrivacyFindings{
				PIIMatchCount:    piiCount,
				FilesScannedCount: filesScanned,
			},
		},
	}, nil
}

// walkAndScan walks scanRoot (non-recursively capped at maxFilesPerScan) and
// returns (piiMatchCount, filesScanned).
//
// SAFETY: this function NEVER records filenames, file paths, matched strings,
// or file content anywhere. Only counters are returned.
//
// SAFETY: symlinks are never followed. filepath.WalkDir does not descend into
// symlinked subdirectories, but it DOES call os.Stat on the root itself, which
// resolves a root symlink. We therefore explicitly Lstat the root before calling
// WalkDir and refuse to scan if it is a symlink. This closes the gap between the
// documented guarantee ("symlinks are never followed") and WalkDir's behaviour.
func walkAndScan(ctx context.Context, scanRoot string, meta map[string]interface{}) (piiCount, filesScanned int) {
	// Lstat the scan root to detect a symlink root before WalkDir can resolve it.
	rootInfo, lstatErr := os.Lstat(scanRoot)
	if lstatErr != nil {
		// Root absent (e.g. no ~/Documents on this system) — not an error.
		return 0, 0
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		// The scan root itself is a symlink. Following it would violate the
		// "symlinks are never followed" safety guarantee. Skip the scan.
		meta["privacy_walk_skipped"] = "scan root is a symlink (not followed per safety policy)"
		return 0, 0
	}

	// Walk the directory tree. filepath.WalkDir does not follow symlinks by
	// default (symlinks appear as DirEntry but are not descended into).
	err := filepath.WalkDir(scanRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Skip unreadable directories/files without recording the path.
			return nil
		}

		// Respect context cancellation.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Cap total files scanned.
		if filesScanned >= maxFilesPerScan {
			return filepath.SkipAll
		}

		// Only inspect regular files — skip dirs, symlinks, devices.
		if !d.Type().IsRegular() {
			return nil
		}

		// Skip large files.
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > maxFileSizeBytes {
			return nil
		}

		// Scan the file for PII patterns.
		// A return of -1 signals scanner truncation (line > 256 KiB buffer).
		// We count it as a truncated file and do not add its matches to piiCount
		// to avoid a false count, but we do record it in metadata.
		matches := scanFileForPII(path)
		filesScanned++
		if matches < 0 {
			// Truncated line detected — increment a counter (not the path).
			if n, ok := meta["scan_truncated_count"].(int); ok {
				meta["scan_truncated_count"] = n + 1
			} else {
				meta["scan_truncated_count"] = 1
			}
		} else {
			piiCount += matches
		}
		return nil
	})

	if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		// Record only that an error occurred, not the path.
		meta["privacy_walk_error"] = "scan encountered an error (details omitted for privacy)"
	}
	return piiCount, filesScanned
}

// scanFileForPII opens the file at path, skips binary content, and counts
// PII pattern matches (SSN + Luhn-validated credit cards).
//
// SAFETY: matched strings and file content are never stored. Only the count
// of matches is returned.
func scanFileForPII(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	// Binary sniff: read first binarySniffBytes and check for NUL bytes.
	sniffBuf := make([]byte, binarySniffBytes)
	n, _ := f.Read(sniffBuf)
	if looksLikeBinary(sniffBuf[:n]) {
		return 0
	}

	// Seek back to start for line scanning.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0
	}

	matches := 0
	scanner := bufio.NewScanner(f)
	// Use a 256 KiB line buffer to handle long lines in structured files.
	buf := make([]byte, 256*1024)
	scanner.Buffer(buf, len(buf))

	for scanner.Scan() {
		line := scanner.Bytes()

		// SSN: \d{3}-\d{2}-\d{4}
		found := ssnPattern.FindAll(line, -1)
		matches += len(found)

		// Credit cards: Luhn-validate each candidate match.
		ccFound := creditCardPattern.FindAll(line, -1)
		for _, cc := range ccFound {
			// Strip spaces and dashes before Luhn check.
			digits := extractDigits(cc)
			if luhnValid(digits) {
				matches++
			}
		}
	}

	// Check for scanner errors after the loop. A non-nil error means a line
	// exceeded the 256 KiB buffer (bufio.ErrTooLong) or an I/O error occurred.
	// PII on oversized lines is silently missed without this check.
	// We record a counter only — no file path or content is stored.
	if scanner.Err() != nil {
		// Return a sentinel value (-1) so the caller in scanFileForPII can
		// signal truncation via metadata without embedding path information.
		return -1
	}

	return matches
}

// looksLikeBinary returns true when the buf contains a NUL byte, indicating
// the file is likely binary and should be skipped.
func looksLikeBinary(buf []byte) bool {
	for _, b := range buf {
		if b == 0 {
			return true
		}
	}
	return false
}

// extractDigits returns only the ASCII digit bytes from b.
func extractDigits(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	return out
}

// luhnValid returns true if the digit string passes the Luhn algorithm.
// A valid Luhn number must have between 13 and 19 digits.
func luhnValid(digits []byte) bool {
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}

	sum := 0
	double := false
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// Manifest returns the static access declaration for the privacy probe.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs:   []string{},
		FilePaths: []string{
			"~/Documents/ (streaming read, ≤5000 files, ≤5 MiB/file; no symlinks followed; " +
				"matched content never stored or transmitted)",
		},
		NetworkCalls: []string{}, // ZERO — fully offline
	}
}
