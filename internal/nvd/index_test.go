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

package nvd

import (
	"testing"
)

func TestLoad_Embedded(t *testing.T) {
	idx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if idx.Count() == 0 {
		t.Error("embedded index has zero CVE records")
	}
	t.Logf("embedded CVE index: %d records", idx.Count())
}

// newTestIndex builds an in-memory Index from the given records, mirroring the
// keying logic in Load. The Match-logic tests use this instead of the embedded
// index: cve-index.json.gz is real NVD data that rolls with the 24-month window
// on every `make gen-nvd`, so asserting on specific CVE IDs from it would be
// perpetually fragile. These fixtures keep the matching logic deterministic.
func newTestIndex(records []CVERecord) *Index {
	idx := &Index{
		byVendorProduct: make(map[string][]CVERecord, len(records)),
		count:           len(records),
	}
	for _, rec := range records {
		for _, cpe := range rec.CPE {
			key := vendorProductKey(cpe.Vendor, cpe.Product)
			idx.byVendorProduct[key] = append(idx.byVendorProduct[key], rec)
		}
	}
	return idx
}

func TestMatch_KnownVulnerableVersion(t *testing.T) {
	idx := newTestIndex([]CVERecord{
		{
			CVE: "CVE-TEST-CURL", CVSS: 9.8, Severity: "CRITICAL",
			CPE: []CPERange{{Vendor: "haxx", Product: "curl", VersionStartIncluding: "7.69.0", VersionEndExcluding: "8.4.0"}},
		},
		{
			CVE: "CVE-TEST-OPENSSH", CVSS: 9.8, Severity: "CRITICAL",
			CPE: []CPERange{{Vendor: "openbsd", Product: "openssh", VersionStartIncluding: "5.5", VersionEndExcluding: "9.3p2"}},
		},
		{
			CVE: "CVE-TEST-OPENSSL-A", CVSS: 7.5, Severity: "HIGH",
			CPE: []CPERange{{Vendor: "openssl", Product: "openssl", VersionStartIncluding: "3.0.0", VersionEndExcluding: "3.0.13"}},
		},
		{
			CVE: "CVE-TEST-OPENSSL-B", CVSS: 9.1, Severity: "CRITICAL",
			CPE: []CPERange{{Vendor: "openssl", Product: "openssl", VersionStartIncluding: "3.0.0", VersionEndExcluding: "3.0.8"}},
		},
		{
			CVE: "CVE-TEST-SUDO", CVSS: 7.8, Severity: "HIGH",
			CPE: []CPERange{{Vendor: "sudo_project", Product: "sudo", VersionStartIncluding: "1.9.0", VersionEndExcluding: "1.9.5p2"}},
		},
	})

	tests := []struct {
		name    string
		pkg     InstalledPackage
		wantMin int    // minimum expected matches (≥)
		wantCVE string // a specific CVE that must be in results
	}{
		{
			name:    "curl 7.80.0 matches via vendor:product",
			pkg:     InstalledPackage{Vendor: "haxx", Product: "curl", Version: "7.80.0"},
			wantMin: 1,
			wantCVE: "CVE-TEST-CURL",
		},
		{
			name:    "openssh 9.0p1 matches via product-only normalisation",
			pkg:     InstalledPackage{Product: "openssh", Version: "9.0p1"},
			wantMin: 1,
			wantCVE: "CVE-TEST-OPENSSH",
		},
		{
			name:    "openssl 3.0.5 matches multiple overlapping ranges",
			pkg:     InstalledPackage{Vendor: "openssl", Product: "openssl", Version: "3.0.5"},
			wantMin: 2,
			wantCVE: "CVE-TEST-OPENSSL-A",
		},
		{
			name:    "sudo 1.9.5p1 matches via product-only normalisation",
			pkg:     InstalledPackage{Product: "sudo", Version: "1.9.5p1"},
			wantMin: 1,
			wantCVE: "CVE-TEST-SUDO",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := idx.Match(tc.pkg)
			if len(results) < tc.wantMin {
				t.Errorf("got %d matches, want >= %d", len(results), tc.wantMin)
			}
			if tc.wantCVE != "" {
				found := false
				for _, r := range results {
					if r.CVE == tc.wantCVE {
						found = true
						break
					}
				}
				if !found {
					cves := make([]string, len(results))
					for i, r := range results {
						cves[i] = r.CVE
					}
					t.Errorf("CVE %s not found in results %v", tc.wantCVE, cves)
				}
			}
		})
	}
}

func TestMatch_UnaffectedVersion(t *testing.T) {
	idx := newTestIndex([]CVERecord{
		{
			CVE: "CVE-TEST-CURL", CVSS: 9.8, Severity: "CRITICAL",
			CPE: []CPERange{{Vendor: "haxx", Product: "curl", VersionStartIncluding: "7.69.0", VersionEndExcluding: "8.4.0"}},
		},
	})

	// curl 9.0.0 is beyond the affected range [7.69.0, 8.4.0) — must not match.
	results := idx.Match(InstalledPackage{Product: "curl", Version: "9.0.0"})
	for _, r := range results {
		t.Errorf("expected no match for curl 9.0.0, got %s", r.CVE)
	}
}

func TestMatch_UnknownPackage(t *testing.T) {
	idx, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	results := idx.Match(InstalledPackage{Product: "unknown-pkg-xyz", Version: "1.0"})
	if len(results) != 0 {
		t.Errorf("expected 0 matches for unknown package, got %d", len(results))
	}
}

func TestVersionInRange(t *testing.T) {
	tests := []struct {
		version string
		start   string
		endExcl string
		endIncl string
		want    bool
	}{
		// Within range
		{"7.80.0", "7.69.0", "8.4.0", "", true},
		{"3.0.5", "3.0.0", "3.0.13", "", true},
		// At start (inclusive)
		{"7.69.0", "7.69.0", "8.4.0", "", true},
		// At end (exclusive) — must NOT match
		{"8.4.0", "7.69.0", "8.4.0", "", false},
		// Beyond end
		{"8.5.0", "7.69.0", "8.4.0", "", false},
		// Debian epoch
		{"1:3.0.5-0ubuntu1", "3.0.0", "3.0.13", "", true},
		// openssh-style "9p2"
		{"9.0p1", "5.5", "9.3p2", "", true},
		// No bounds — any version matches
		{"99.0.0", "", "", "", true},
		// endIncluding
		{"8.4.0", "7.69.0", "", "8.4.0", true},
		{"8.4.1", "7.69.0", "", "8.4.0", false},
	}

	for _, tc := range tests {
		got := versionInRange(tc.version, tc.start, tc.endExcl, tc.endIncl)
		if got != tc.want {
			t.Errorf("versionInRange(%q, %q, %q, %q) = %v, want %v",
				tc.version, tc.start, tc.endExcl, tc.endIncl, got, tc.want)
		}
	}
}
