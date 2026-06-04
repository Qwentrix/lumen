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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ApplyResult contains the outcome of a successful Apply call.
type ApplyResult struct {
	ContentDir   string    // path to the new content directory (~/.lumen/content)
	GeneratedAt  time.Time // bundle GeneratedAt timestamp parsed from manifest
	RuleCount    int
	OverlayCount int
}

// Apply atomically extracts and installs a verified content bundle into
// ~/.lumen/content/.
//
// Algorithm:
//  1. Extract bundleBytes (tar.gz) into a temp dir ~/.lumen/.content-tmp-<rand>.
//  2. If a previous ~/.lumen/content/ exists, rename it to ~/.lumen/.content-backup-<rand>
//     (retained for one session as a manual rollback option).
//  3. os.Rename(tempDir, contentDir) — atomic on the same filesystem.
//  4. Remove the backup on success.
//
// Callers MUST call VerifyBundle before Apply. Apply trusts the input.
func Apply(m *bundleManifest, bundleBytes []byte) (*ApplyResult, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("update/apply: home dir: %w", err)
	}

	lumenDir := filepath.Join(home, ".lumen")
	if err := os.MkdirAll(lumenDir, 0700); err != nil {
		return nil, fmt.Errorf("update/apply: mkdir %s: %w", lumenDir, err)
	}

	// 1. Extract into a temp dir.
	tmpDir, err := os.MkdirTemp(lumenDir, ".content-tmp-")
	if err != nil {
		return nil, fmt.Errorf("update/apply: mkdtemp: %w", err)
	}

	// Ensure cleanup on error.
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	if err := extractTarGz(bundleBytes, tmpDir); err != nil {
		return nil, fmt.Errorf("update/apply: extract: %w", err)
	}

	contentDir := filepath.Join(lumenDir, "content")

	// 2. Rename existing content dir to backup (if present).
	var backupDir string
	if _, statErr := os.Stat(contentDir); statErr == nil {
		backupDir, err = os.MkdirTemp(lumenDir, ".content-backup-")
		if err != nil {
			return nil, fmt.Errorf("update/apply: mkdtemp for backup: %w", err)
		}
		// Remove the empty temp dir we just created before renaming into it.
		_ = os.Remove(backupDir)
		if err := os.Rename(contentDir, backupDir); err != nil {
			return nil, fmt.Errorf("update/apply: backup old content: %w", err)
		}
	}

	// 3. Atomic rename: temp → content.
	if err := os.Rename(tmpDir, contentDir); err != nil {
		// Rollback: restore backup if it existed.
		if backupDir != "" {
			_ = os.Rename(backupDir, contentDir)
		}
		return nil, fmt.Errorf("update/apply: rename into place: %w", err)
	}

	// 4. Remove backup on success.
	if backupDir != "" {
		_ = os.RemoveAll(backupDir)
	}

	success = true

	// Parse GeneratedAt from manifest.
	generatedAt := time.Time{}
	if m.GeneratedAt != "" {
		t, err := time.Parse(time.RFC3339, m.GeneratedAt)
		if err == nil {
			generatedAt = t
		}
	}

	// Record apply timestamp for staleness tracking.
	writeApplyTimestamp(contentDir)

	return &ApplyResult{
		ContentDir:   contentDir,
		GeneratedAt:  generatedAt,
		RuleCount:    m.RuleCount,
		OverlayCount: m.OverlayCount,
	}, nil
}

// extractTarGz extracts the contents of a gzip-compressed tar archive (the
// bundle) into destDir.  Only regular files and directories are extracted.
// Path traversal (../ components) is detected and rejected.
//
// Security properties enforced:
//   - Per-file read limit: each file is read via a LimitReader of maxBundleBytes.
//   - Aggregate write limit (H-2): totalWritten across ALL files must not exceed
//     maxBundleBytes.  A bundle with many files that would collectively write more
//     than maxBundleBytes is rejected before the disk is exhausted.
//   - Negative header size (M-5): tar entries with hdr.Size < 0 are rejected
//     immediately to avoid arithmetic underflow in LimitReader.
func extractTarGz(data []byte, destDir string) error {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer gr.Close()

	// H-2: running total of bytes written across all files in the archive.
	var totalWritten int64

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		// M-5: reject entries with a negative declared size.
		if hdr.Size < 0 {
			return fmt.Errorf("tar: entry %q has negative size %d, rejected", hdr.Name, hdr.Size)
		}

		// Security: reject path traversal.
		cleanName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
			return fmt.Errorf("tar: suspicious path %q rejected", hdr.Name)
		}

		destPath := filepath.Join(destDir, cleanName)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destPath, 0750); err != nil {
				return fmt.Errorf("tar: mkdir %s: %w", destPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
				return fmt.Errorf("tar: mkdir parent %s: %w", filepath.Dir(destPath), err)
			}
			f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
			if err != nil {
				return fmt.Errorf("tar: create %s: %w", destPath, err)
			}
			// Per-file limit prevents one huge file; aggregate limit (H-2) prevents
			// many-file bombs that each stay just under the per-file cap.
			lr := io.LimitReader(tr, maxBundleBytes)
			n, err := io.Copy(f, lr)
			f.Close()
			if err != nil {
				return fmt.Errorf("tar: write %s: %w", destPath, err)
			}
			// H-2: accumulate and check the aggregate written bytes.
			totalWritten += n
			if totalWritten > maxBundleBytes {
				return fmt.Errorf("tar: aggregate extraction size exceeded %d bytes (decompression bomb guard)", maxBundleBytes)
			}
		default:
			// Skip symlinks, hardlinks, etc. — not needed in content bundles.
		}
	}
	return nil
}

// applyTimestampFile is the path within the content directory where we record
// the apply timestamp for staleness checking.
const applyTimestampFile = ".lumen-bundle-applied-at"

// writeApplyTimestamp writes the current UTC time to contentDir/.lumen-bundle-applied-at.
// Errors are silently ignored — this is a best-effort staleness hint.
func writeApplyTimestamp(contentDir string) {
	path := filepath.Join(contentDir, applyTimestampFile)
	_ = os.WriteFile(path, []byte(time.Now().UTC().Format(time.RFC3339)), 0600)
}

// ReadApplyTimestamp reads the apply timestamp from contentDir if present.
// Returns (time, true) on success; (zero, false) if the file is absent or unparseable.
func ReadApplyTimestamp(contentDir string) (time.Time, bool) {
	path := filepath.Join(contentDir, applyTimestampFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
