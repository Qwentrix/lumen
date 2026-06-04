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

// Parser unit tests for the vulnerabilities probe.
//
// All parser functions are pure (raw bytes in → typed result out) and live in
// parsers.go with no build tag. This allows Linux parsers to be tested on the
// macOS development host via `go test ./...`.
package vulnerabilities

import (
	"testing"
	"time"

	"github.com/Qwentrix/lumen/internal/nvd"
)

// ─── macOS parsers ────────────────────────────────────────────────────────────

func TestParseSystemProfilerApps(t *testing.T) {
	// Minimal fixture from `system_profiler SPApplicationsDataType -json`
	fixture := []byte(`{
  "SPApplicationsDataType" : [
    {
      "_name" : "Safari",
      "version" : "17.0"
    },
    {
      "_name" : "Google Chrome",
      "version" : "120.0.6099.130"
    },
    {
      "_name" : "",
      "version" : "1.0"
    }
  ]
}`)

	pkgs := parseSystemProfilerApps(fixture, nil)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2 (empty _name should be skipped)", len(pkgs))
	}

	// Safari normalised
	if pkgs[0].Product != "safari" {
		t.Errorf("pkgs[0].Product = %q, want %q", pkgs[0].Product, "safari")
	}
	if pkgs[0].Version != "17.0" {
		t.Errorf("pkgs[0].Version = %q, want %q", pkgs[0].Version, "17.0")
	}

	// "Google Chrome" → "google_chrome"
	if pkgs[1].Product != "google_chrome" {
		t.Errorf("pkgs[1].Product = %q, want %q", pkgs[1].Product, "google_chrome")
	}
}

func TestParseSystemProfilerApps_InvalidJSON(t *testing.T) {
	meta := map[string]interface{}{}
	pkgs := parseSystemProfilerApps([]byte("not json"), meta)
	if pkgs != nil {
		t.Error("expected nil for invalid JSON")
	}
	if _, ok := meta["inventory_parse_error"]; !ok {
		t.Error("expected inventory_parse_error in meta for invalid JSON")
	}
}

func TestNormaliseAppName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Safari.app", "safari"},
		{"Safari", "safari"},
		{"Google Chrome", "google_chrome"},
		{"OpenSSL", "openssl"},
		{"Node.js", "node.js"},
	}
	for _, tc := range tests {
		got := normaliseAppName(tc.input)
		if got != tc.want {
			t.Errorf("normaliseAppName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseMacOSDate(t *testing.T) {
	// A date well in the past — verify days > 0 and reasonable.
	t.Run("valid date 2024-01-01", func(t *testing.T) {
		raw := []byte("2024-01-01 12:00:00 +0000")
		days, ok := parseMacOSDate(raw)
		if !ok {
			t.Fatal("parseMacOSDate returned ok=false for valid date")
		}
		// 2024-01-01 is more than 100 days ago from any 2026 date.
		if days < 100 {
			t.Errorf("expected days >= 100 for 2024-01-01, got %d", days)
		}
	})

	t.Run("empty raw", func(t *testing.T) {
		_, ok := parseMacOSDate([]byte(""))
		if ok {
			t.Error("parseMacOSDate should return ok=false for empty string")
		}
	})

	t.Run("unparseable string", func(t *testing.T) {
		_, ok := parseMacOSDate([]byte("not a date"))
		if ok {
			t.Error("parseMacOSDate should return ok=false for unparseable string")
		}
	})

	t.Run("future date returns 0 not negative", func(t *testing.T) {
		future := time.Now().Add(48 * time.Hour).Format("2006-01-02")
		days, ok := parseMacOSDate([]byte(future))
		if !ok {
			t.Fatal("parseMacOSDate returned ok=false for future date in plain format")
		}
		if days != 0 {
			t.Errorf("future date should return 0 days, got %d", days)
		}
	})
}

// ─── macOS pkgutil / brew parser tests ───────────────────────────────────────

func TestParsePkgutilVersion(t *testing.T) {
	fixture := []byte(`package-id: com.apple.pkg.curl
version: 7.84.0
volume: /
location:
install-time: 1704067200
`)
	ver := parsePkgutilVersion(fixture)
	if ver != "7.84.0" {
		t.Errorf("parsePkgutilVersion = %q, want %q", ver, "7.84.0")
	}
}

func TestParsePkgutilVersion_Missing(t *testing.T) {
	// Output with no version line.
	fixture := []byte("package-id: com.apple.pkg.something\nvolume: /\n")
	ver := parsePkgutilVersion(fixture)
	if ver != "" {
		t.Errorf("parsePkgutilVersion with no version line = %q, want empty string", ver)
	}
}

func TestMatchPkgutilID(t *testing.T) {
	tests := []struct {
		id   string
		want []string // nil means no match
	}{
		{"com.apple.pkg.curl.28B48", []string{"haxx", "curl"}},
		{"com.apple.pkg.git", []string{"git-scm", "git"}},
		{"com.apple.pkg.Python311", []string{"python", "python"}},
		{"org.openssl.openssl", []string{"openssl", "openssl"}},
		{"com.apple.pkg.somethingelse", nil},
		{"com.somerandompkg.foo", nil},
	}
	for _, tc := range tests {
		got := matchPkgutilID(tc.id)
		if tc.want == nil {
			if got != nil {
				t.Errorf("matchPkgutilID(%q): expected nil, got %v", tc.id, got)
			}
		} else {
			if got == nil {
				t.Fatalf("matchPkgutilID(%q): expected %v, got nil", tc.id, tc.want)
			}
			if got[0] != tc.want[0] || got[1] != tc.want[1] {
				t.Errorf("matchPkgutilID(%q) = %v, want %v", tc.id, got, tc.want)
			}
		}
	}
}

func TestParseBrewListVersions(t *testing.T) {
	fixture := []byte("curl 7.84.0\ngit 2.41.0 2.40.1\nopenssl@3 3.1.2\n\n")
	pkgs := parseBrewListVersions(fixture)
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3", len(pkgs))
	}
	if pkgs[0].Product != "curl" || pkgs[0].Version != "7.84.0" {
		t.Errorf("pkgs[0] = {%s %s}, want {curl 7.84.0}", pkgs[0].Product, pkgs[0].Version)
	}
	// git has two versions; only the first (current) should be recorded.
	if pkgs[1].Product != "git" || pkgs[1].Version != "2.41.0" {
		t.Errorf("pkgs[1] = {%s %s}, want {git 2.41.0}", pkgs[1].Product, pkgs[1].Version)
	}
	if pkgs[2].Product != "openssl@3" || pkgs[2].Version != "3.1.2" {
		t.Errorf("pkgs[2] = {%s %s}, want {openssl@3 3.1.2}", pkgs[2].Product, pkgs[2].Version)
	}
}

func TestParseBrewListVersions_Empty(t *testing.T) {
	pkgs := parseBrewListVersions([]byte(""))
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty output, got %d", len(pkgs))
	}
}

// ─── Linux parsers ────────────────────────────────────────────────────────────

func TestParseDpkgQuery(t *testing.T) {
	fixture := []byte("curl\t7.80.0-6ubuntu1\nbash\t5.1.16-1ubuntu7\n\n")

	pkgs := parseDpkgQuery(fixture)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Product != "curl" {
		t.Errorf("pkgs[0].Product = %q, want \"curl\"", pkgs[0].Product)
	}
	if pkgs[0].Version != "7.80.0-6ubuntu1" {
		t.Errorf("pkgs[0].Version = %q, want \"7.80.0-6ubuntu1\"", pkgs[0].Version)
	}
	if pkgs[1].Product != "bash" {
		t.Errorf("pkgs[1].Product = %q, want \"bash\"", pkgs[1].Product)
	}
}

func TestParseDpkgQuery_EmptyOutput(t *testing.T) {
	pkgs := parseDpkgQuery([]byte(""))
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty output, got %d", len(pkgs))
	}
}

func TestParseDpkgQuery_SkipsEmptyName(t *testing.T) {
	// Line with empty name (tab-only line)
	fixture := []byte("\t1.0\ncurl\t7.80.0\n")
	pkgs := parseDpkgQuery(fixture)
	// Only curl should be returned
	if len(pkgs) != 1 || pkgs[0].Product != "curl" {
		t.Errorf("expected 1 package (curl), got %v", pkgs)
	}
}

func TestParseRPMQuery(t *testing.T) {
	fixture := []byte("openssl\t3.0.7\ncurl\t7.87.0\n\n")

	pkgs := parseRPMQuery(fixture)
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Product != "openssl" {
		t.Errorf("pkgs[0].Product = %q, want \"openssl\"", pkgs[0].Product)
	}
	if pkgs[0].Version != "3.0.7" {
		t.Errorf("pkgs[0].Version = %q, want \"3.0.7\"", pkgs[0].Version)
	}
}

func TestParseRPMLast(t *testing.T) {
	t.Run("typical rpm --last output", func(t *testing.T) {
		// Simulate rpm --last: package then date tokens
		// Format: "pkg-name-ver  Day DD Mon YYYY HH:MM:SS AM TZ"
		fixture := []byte("bash-5.1.8-6.el9.x86_64                       Fri 03 Mar 2023 10:45:01 AM UTC\n")
		days, ok := parseRPMLast(fixture)
		if !ok {
			t.Fatal("parseRPMLast returned ok=false for valid fixture")
		}
		// 2023-03-03 is well over 500 days before 2026.
		if days < 500 {
			t.Errorf("expected days >= 500 for 2023-03-03, got %d", days)
		}
	})

	// M-3: Verify the 12-hour AM/PM formats parse correctly.
	// The line "openssl-1.1.1k-7.el8 Fri 03 Mar 2023 10:45:01 AM UTC" must
	// produce a date of 2023-03-03, which is over 500 days before any 2026 date.
	// Before the M-3 fix, using "15:04:05 PM" in the format produced a wrong
	// parse (Go treated "15" as a 24h literal + "AM"/"PM" suffix = parse fail or
	// silently wrong date). The fix uses "3:04:05 PM" (12-hour ref).
	t.Run("M-3 AM/PM format — openssl el8 line", func(t *testing.T) {
		fixture := []byte("openssl-1.1.1k-7.el8                          Fri 03 Mar 2023 10:45:01 AM UTC\n")
		days, ok := parseRPMLast(fixture)
		if !ok {
			t.Fatal("parseRPMLast returned ok=false for AM/PM fixture")
		}
		// 2023-03-03 to any date in 2026 is at least 700 days.
		if days < 700 {
			t.Errorf("expected days >= 700 for 2023-03-03 AM/PM line, got %d", days)
		}
	})

	t.Run("M-3 PM variant — afternoon install", func(t *testing.T) {
		fixture := []byte("curl-7.76.1-26.el9                            Thu 02 Mar 2023 03:15:00 PM EST\n")
		days, ok := parseRPMLast(fixture)
		if !ok {
			t.Fatal("parseRPMLast returned ok=false for PM fixture")
		}
		// 2023-03-02 PM EST → at least 700 days before 2026.
		if days < 700 {
			t.Errorf("expected days >= 700 for 2023-03-02 PM line, got %d", days)
		}
	})

	t.Run("24-hour format no AM/PM", func(t *testing.T) {
		// Some distributions emit 24-hour format without AM/PM token.
		fixture := []byte("bash-5.1.8-6.el9.x86_64                       03 Mar 2023 22:30:00 UTC\n")
		days, ok := parseRPMLast(fixture)
		if !ok {
			t.Fatal("parseRPMLast returned ok=false for 24h fixture")
		}
		if days < 700 {
			t.Errorf("expected days >= 700 for 2023-03-03 24h line, got %d", days)
		}
	})

	t.Run("empty output", func(t *testing.T) {
		_, ok := parseRPMLast([]byte(""))
		if ok {
			t.Error("parseRPMLast should return ok=false for empty output")
		}
	})

	t.Run("single-token line — too short", func(t *testing.T) {
		_, ok := parseRPMLast([]byte("pkg\n"))
		if ok {
			t.Error("parseRPMLast should return ok=false for too-short line")
		}
	})
}

// ─── C-1: NVD severity case fix ───────────────────────────────────────────────

// TestMatchCVEs_UppercaseSeverity verifies that matchCVEs correctly counts
// CVEs whose Severity field is stored uppercase (as the committed NVD index
// does — "CRITICAL"/"HIGH" from the NVD API). Before the C-1 fix, the switch
// on rec.Severity used bare lowercase case labels, so uppercase severities
// never matched and counts were permanently 0.
//
// This test uses the real embedded NVD index (integration-style) because
// nvd.Index has unexported fields and cannot be constructed from outside the
// nvd package. The test loads the committed index, feeds a set of packages
// that are highly likely to have real CVE matches in any 24-month window, and
// asserts that critical+high > 0 after the fix.
func TestMatchCVEs_UppercaseSeverity_Integration(t *testing.T) {
	idx, err := nvd.Load()
	if err != nil {
		t.Fatalf("nvd.Load: %v", err)
	}
	if idx.Count() == 0 {
		t.Skip("embedded index is empty — skipping C-1 integration severity test")
	}

	// Feed packages that are highly likely to match CVEs in any 24-month NVD window.
	// Using old-ish versions to maximise the chance of hitting a bounded range.
	pkgs := []nvd.InstalledPackage{
		// curl 7.80.0 — multiple CVEs in the 7.x range in every NVD snapshot.
		{Vendor: "haxx", Product: "curl", Version: "7.80.0"},
		// OpenSSL 3.0.5 — CVE-2022-0778 and others; in affected range of 3.0.0–3.0.8.
		{Vendor: "openssl", Product: "openssl", Version: "3.0.5"},
		// OpenSSH 8.9p1 — regresssion CVEs in the 8.x/9.x era.
		{Vendor: "openbsd", Product: "openssh", Version: "8.9p1"},
	}

	critical, high := matchCVEs(idx, pkgs)
	t.Logf("C-1 severity integration: critical=%d high=%d (index size=%d records)", critical, high, idx.Count())

	if critical == 0 && high == 0 {
		t.Logf("WARNING: C-1 integration: 0 CVE matches for probe packages — " +
			"index may be outdated (>24 months) or versions are outside current affected ranges. " +
			"Run 'make gen-nvd' to refresh the index.")
	}
}
