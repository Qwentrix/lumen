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
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StalenessDays is the number of days after which a content bundle is
// considered stale (FR-8: >30-day staleness warning).
const StalenessDays = 30

// StalenessStatus carries the result of a staleness check.
type StalenessStatus struct {
	// IsStale is true when the content is more than StalenessDays old.
	IsStale bool
	// DaysOld is the approximate age of the content in whole days.
	// -1 means "age unknown".
	DaysOld int
	// Source describes what timestamp source was used ("apply_timestamp",
	// "embedded_snapshot", or "unknown").
	Source string
}

// CheckStaleness determines whether the local content (~/.lumen/content) is stale.
//
// Resolution order:
//  1. ~/.lumen/content/.lumen-bundle-applied-at (written by Apply on success)
//  2. ~/.lumen/content/content-snapshot.meta.json "synced_at" field
//     (embedded snapshot copied to content dir by sync-content)
//  3. Fallback to the embedded snapshot via the provided embeddedSyncedAt string.
//
// embeddedSyncedAt should be the "synced_at" field from the binary-embedded
// content-snapshot.meta.json.  Pass "" if unavailable.
func CheckStaleness(embeddedSyncedAt string) StalenessStatus {
	home, err := os.UserHomeDir()
	if err != nil {
		return staleFromEmbedded(embeddedSyncedAt)
	}

	contentDir := filepath.Join(home, ".lumen", "content")

	// 1. Apply timestamp file.
	if t, ok := ReadApplyTimestamp(contentDir); ok {
		return makeStalenessStatus(t, "apply_timestamp")
	}

	// 2. Meta JSON "synced_at" in content dir.
	metaPath := filepath.Join(contentDir, "content-snapshot.meta.json")
	if data, err := os.ReadFile(metaPath); err == nil {
		if t, ok := parseSyncedAt(data); ok {
			return makeStalenessStatus(t, "content_dir_meta")
		}
	}

	// 3. Embedded snapshot.
	return staleFromEmbedded(embeddedSyncedAt)
}

// staleFromEmbedded uses the embeddedSyncedAt string to compute staleness.
func staleFromEmbedded(syncedAt string) StalenessStatus {
	if syncedAt == "" {
		return StalenessStatus{IsStale: false, DaysOld: -1, Source: "unknown"}
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(syncedAt))
	if err != nil {
		return StalenessStatus{IsStale: false, DaysOld: -1, Source: "unknown"}
	}
	return makeStalenessStatus(t, "embedded_snapshot")
}

// makeStalenessStatus computes the StalenessStatus for a given reference time.
func makeStalenessStatus(t time.Time, source string) StalenessStatus {
	age := time.Since(t)
	days := int(age.Hours() / 24)
	if days < 0 {
		days = 0
	}
	return StalenessStatus{
		IsStale: days > StalenessDays,
		DaysOld: days,
		Source:  source,
	}
}

// parseSyncedAt extracts the "synced_at" field from a content-snapshot.meta.json byte slice.
// Returns (time, true) on success.
func parseSyncedAt(data []byte) (time.Time, bool) {
	// Simple string search to avoid importing encoding/json in the hot path.
	// The meta.json is small and has a predictable format.
	s := string(data)
	key := `"synced_at"`
	idx := strings.Index(s, key)
	if idx < 0 {
		return time.Time{}, false
	}
	rest := s[idx+len(key):]
	// rest looks like: : "2026-05-01T12:00:00Z", ...
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return time.Time{}, false
	}
	rest = strings.TrimSpace(rest[colonIdx+1:])
	if len(rest) == 0 || rest[0] != '"' {
		return time.Time{}, false
	}
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return time.Time{}, false
	}
	ts := rest[:end]
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
