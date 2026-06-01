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

// Package nvd provides a curated, embedded CVE→CPE index for offline
// vulnerability matching during `lumen scan`.
//
// The embedded index (internal/nvd/data/cve-index.json.gz) is a curated subset
// of the NVD 2.0 data feed, filtered to CVSS ≥ 7.0 CVEs for common desktop
// and server software packages. It is generated offline by gen/main.go
// (//go:build ignore) and committed as a binary blob.
//
// HARD RULE: this package makes ZERO outbound network calls. All data is read
// from the embedded blob. The full NVD delta feed is deferred to `lumen update`
// (LU-5) which writes an updated blob to ~/.lumen/content/.
package nvd

import (
	_ "embed"
	"compress/gzip"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

//go:generate echo "Run 'NVD_API_KEY=<key> go run ./internal/nvd/gen/main.go' to regenerate the curated index."

//go:embed data/cve-index.json.gz
var embeddedIndex []byte

//go:embed data/cve-index.meta.json
var embeddedMeta []byte

// CVERecord is a single CVE entry in the curated index.
type CVERecord struct {
	CVE       string     `json:"cve"`
	CVSS      float64    `json:"cvss"`
	Severity  string     `json:"severity"`
	CPE       []CPERange `json:"cpe"`
	Published string     `json:"published"`
}

// CPERange defines the affected version range for one CPE entry.
type CPERange struct {
	Vendor                string `json:"vendor"`
	Product               string `json:"product"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
}

// InstalledPackage describes a package from an OS inventory.
type InstalledPackage struct {
	Vendor  string
	Product string
	Version string
}

// Index is the in-memory CVE lookup structure.
type Index struct {
	// byVendorProduct maps "vendor:product" → []CVERecord
	byVendorProduct map[string][]CVERecord
	count           int
}

// Load decompresses and parses the embedded CVE index.
// Zero network calls — reads only from the embedded blob.
func Load() (*Index, error) {
	gr, err := gzip.NewReader(bytes.NewReader(embeddedIndex))
	if err != nil {
		return nil, fmt.Errorf("nvd: decompress embedded index: %w", err)
	}
	defer gr.Close()

	var records []CVERecord
	if err := json.NewDecoder(gr).Decode(&records); err != nil {
		return nil, fmt.Errorf("nvd: parse embedded index: %w", err)
	}

	idx := &Index{
		byVendorProduct: make(map[string][]CVERecord, len(records)*2),
		count:           len(records),
	}

	for _, rec := range records {
		for _, cpe := range rec.CPE {
			key := vendorProductKey(cpe.Vendor, cpe.Product)
			idx.byVendorProduct[key] = append(idx.byVendorProduct[key], rec)
		}
	}

	return idx, nil
}

// Count returns the number of CVE records in the index.
func (idx *Index) Count() int {
	return idx.count
}

// Meta returns the raw content of the embedded cve-index.meta.json as a
// JSON string, for display in the report footer.
func Meta() []byte {
	return embeddedMeta
}

// Match returns the list of CVEs that affect the given installed package.
// Matching is done by vendor:product lookup and then semver-range filtering.
// Returns nil (not an error) if the package is not in the index.
//
// Zero network calls.
func (idx *Index) Match(pkg InstalledPackage) []CVERecord {
	// Normalise via the CPE map.
	vendor, product := normaliseCPE(pkg.Vendor, pkg.Product)
	key := vendorProductKey(vendor, product)

	candidates, ok := idx.byVendorProduct[key]
	if !ok {
		return nil
	}

	var matched []CVERecord
	for _, rec := range candidates {
		for _, cpe := range rec.CPE {
			if vendorProductKey(cpe.Vendor, cpe.Product) != key {
				continue
			}
			if versionInRange(pkg.Version, cpe.VersionStartIncluding, cpe.VersionEndExcluding, cpe.VersionEndIncluding) {
				matched = append(matched, rec)
				break // only append the CVE once per record
			}
		}
	}
	return matched
}

// vendorProductKey returns a normalised lookup key.
func vendorProductKey(vendor, product string) string {
	return strings.ToLower(vendor) + ":" + strings.ToLower(product)
}

// versionInRange returns true when version falls within the CPE range.
// Supports versionStartIncluding, versionEndExcluding, and versionEndIncluding.
// Uses a permissive dotted-integer comparator (not strict semver) because OS
// package versions frequently use non-semver schemes (e.g. "1:3.0.13-0ubuntu3").
func versionInRange(version, startIncl, endExcl, endIncl string) bool {
	v := parseVersion(stripEpochAndDistro(version))

	if startIncl != "" {
		start := parseVersion(startIncl)
		if compareVersion(v, start) < 0 {
			return false
		}
	}
	if endExcl != "" {
		end := parseVersion(endExcl)
		if compareVersion(v, end) >= 0 {
			return false
		}
	}
	if endIncl != "" {
		end := parseVersion(endIncl)
		if compareVersion(v, end) > 0 {
			return false
		}
	}

	// If all range bounds are empty, any version matches (the CPE covers all versions).
	return true
}

// stripEpochAndDistro removes Debian-style epoch prefix "1:" and distro suffix
// like "-0ubuntu3.22.04.1" so "1:3.0.13-0ubuntu3" becomes "3.0.13".
func stripEpochAndDistro(v string) string {
	// Remove epoch prefix "N:".
	if idx := strings.Index(v, ":"); idx > 0 {
		v = v[idx+1:]
	}
	// Remove distro suffix at first "-" or "~" or "+".
	for _, sep := range []string{"-", "~", "+"} {
		if idx := strings.Index(v, sep); idx > 0 {
			v = v[:idx]
		}
	}
	return strings.TrimSpace(v)
}

// versionPart is a parsed version as a slice of int segments.
type versionPart []int

// parseVersion parses a dotted-integer version string. Non-numeric segments
// are treated as 0. E.g. "3.0.14" → [3, 0, 14]; "9p2" → [9, 0, 2].
func parseVersion(s string) versionPart {
	s = strings.TrimPrefix(s, "v")
	// Split on dots first.
	dotParts := strings.Split(s, ".")
	var result []int
	for _, p := range dotParts {
		// Also split on 'p' (as in openssh "9p2").
		subParts := strings.FieldsFunc(p, func(r rune) bool {
			return r < '0' || r > '9'
		})
		for _, sp := range subParts {
			n := 0
			for _, c := range sp {
				if c >= '0' && c <= '9' {
					n = n*10 + int(c-'0')
				}
			}
			result = append(result, n)
		}
	}
	if len(result) == 0 {
		return []int{0}
	}
	return result
}

// compareVersion compares two version parts. Returns -1, 0, or 1.
func compareVersion(a, b versionPart) int {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		ai, bi := 0, 0
		if i < len(a) {
			ai = a[i]
		}
		if i < len(b) {
			bi = b[i]
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}
