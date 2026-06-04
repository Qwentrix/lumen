//go:build ignore

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

// gen/main.go is the NVD index generator. It is NOT built as part of the scanner
// binary or test suite (//go:build ignore). Run it manually as a maintainer
// action to regenerate internal/nvd/data/cve-index.json.gz from the NVD 2.0 API.
//
// Usage:
//
//	NVD_API_KEY=<your-key> go run ./internal/nvd/gen/main.go
//
// The generator:
//   1. Pulls HIGH + CRITICAL CVEs (CVSS ≥ 7.0) from the NVD 2.0 API over a
//      24-month window, in <=120-day chunks (an NVD date-range limit).
//   2. Keeps only CPE matches flagged `vulnerable` AND whose (vendor, product)
//      is in the scanner's resolvable allowlist (nvd.CuratedProducts, derived
//      from cpeTable) — so the index contains only CVEs the scanner can match.
//      Widen coverage by extending cpeTable, then re-running this generator.
//   3. Writes internal/nvd/data/cve-index.json.gz and cve-index.meta.json.
//
// HARD RULE: This generator is NEVER invoked at scan time. The committed
// cve-index.json.gz is the source of truth. Regeneration is a manual
// maintainer step before tagging a release.
//
// Full NVD delta feed and the ~50 MB comprehensive snapshot are deferred to
// `lumen update` (LU-5).
package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	lumennvd "github.com/Qwentrix/lumen/internal/nvd"
)

// nvdPageSize is the maximum number of results per NVD 2.0 API page.
// The NVD 2.0 API hard-caps at 2000 results per request.
const nvdPageSize = 2000

// nvdAPIBase is the NVD 2.0 REST API endpoint.
const nvdAPIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// nvdMaxWindowDays is the NVD 2.0 API hard limit on a single date range.
// pubStartDate and pubEndDate MUST be supplied together and span <= 120 days,
// so a multi-month window has to be fetched in chunks.
const nvdMaxWindowDays = 120

// CVERecord matches the shape in internal/nvd/index.go (must stay in sync).
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

// Meta is written to cve-index.meta.json.
type Meta struct {
	GeneratedAt         string  `json:"generated_at"`
	CVECount            int     `json:"cve_count"`
	Source              string  `json:"source"`
	MinCVSS             float64 `json:"min_cvss"`
	WindowMonths        int     `json:"window_months"`
	CuratedProductCount int     `json:"curated_product_count"`
	SHA256              string  `json:"sha256"`
	Note                string  `json:"note"`
}

// nvdVulnerability mirrors the NVD 2.0 API response envelope shape.
type nvdVulnerability struct {
	CVE struct {
		ID        string `json:"id"`
		Published string `json:"published"`
		Metrics   struct {
			CVSSMetricV31 []struct {
				CVSSData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
		} `json:"metrics"`
		Configurations []struct {
			Nodes []struct {
				CPEMatch []struct {
					Vulnerable            bool   `json:"vulnerable"`
					Criteria              string `json:"criteria"`
					VersionStartIncluding string `json:"versionStartIncluding"`
					VersionEndExcluding   string `json:"versionEndExcluding"`
					VersionEndIncluding   string `json:"versionEndIncluding"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
	} `json:"cve"`
}

// fetchSeverity downloads all NVD CVEs for the given severity string
// ("CRITICAL" or "HIGH") published within [windowStart, windowEnd]. Because the
// NVD 2.0 API requires pubStartDate and pubEndDate together and caps any date
// range at 120 days, the window is split into <=120-day chunks; each chunk is
// paginated (NVD caps at nvdPageSize results per page).
func fetchSeverity(apiKey, severity string, windowStart, windowEnd time.Time) ([]nvdVulnerability, error) {
	var all []nvdVulnerability

	for chunkStart := windowStart; chunkStart.Before(windowEnd); {
		chunkEnd := chunkStart.AddDate(0, 0, nvdMaxWindowDays)
		if chunkEnd.After(windowEnd) {
			chunkEnd = windowEnd
		}
		pubStart := chunkStart.Format("2006-01-02T15:04:05.000")
		pubEnd := chunkEnd.Format("2006-01-02T15:04:05.000")

		startIndex := 0
		for {
			reqURL := buildNVDURL(severity, pubStart, pubEnd, startIndex)
			fmt.Printf("Fetching NVD %s [%s..%s] startIndex=%d\n", severity, pubStart[:10], pubEnd[:10], startIndex)

			body, err := nvdGet(reqURL, apiKey)
			if err != nil {
				return nil, err
			}

			var nvdResp struct {
				TotalResults    int                `json:"totalResults"`
				ResultsPerPage  int                `json:"resultsPerPage"`
				StartIndex      int                `json:"startIndex"`
				Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
			}
			if err := json.Unmarshal(body, &nvdResp); err != nil {
				return nil, fmt.Errorf("parse NVD response (severity=%s %s..%s startIndex=%d): %w (body: %.200s)",
					severity, pubStart[:10], pubEnd[:10], startIndex, err, string(body))
			}

			all = append(all, nvdResp.Vulnerabilities...)
			fmt.Printf("  → %d this page; %d collected (chunk total %d)\n",
				len(nvdResp.Vulnerabilities), len(all), nvdResp.TotalResults)

			// Advance to next page; stop when we've consumed this chunk.
			startIndex += len(nvdResp.Vulnerabilities)
			if startIndex >= nvdResp.TotalResults || len(nvdResp.Vulnerabilities) == 0 {
				break
			}
			sleepForRate(apiKey)
		}

		chunkStart = chunkEnd
		sleepForRate(apiKey)
	}
	return all, nil
}

// buildNVDURL constructs a properly percent-encoded NVD 2.0 query URL.
// Using net/url is essential: the date values contain ':' characters, and NVD's
// CDN returns an empty-body HTTP 404 if those colons are sent unencoded. Encode()
// renders them as %3A.
func buildNVDURL(severity, pubStart, pubEnd string, startIndex int) string {
	q := url.Values{}
	q.Set("cvssV3Severity", severity)
	q.Set("pubStartDate", pubStart)
	q.Set("pubEndDate", pubEnd)
	q.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
	q.Set("startIndex", strconv.Itoa(startIndex))
	return nvdAPIBase + "?" + q.Encode()
}

// nvdClient is a package-level HTTP client configured to NOT follow redirects.
// L-3: using http.DefaultClient (which follows redirects) would forward the
// apiKey header to a redirect target, leaking the bearer key. By returning
// http.ErrUseLastResponse we stop at the first redirect response and let the
// caller handle it; in practice NVD never redirects, so this has no functional
// impact.
var nvdClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// nvdGet performs a GET against the NVD API with the API key header, retrying
// transient failures (rate limits, 5xx, empty bodies) with quadratic backoff.
// The public NVD service frequently throttles by returning an empty body or a
// 403/503, so a bare json.Unmarshal on the response is not safe.
func nvdGet(url, apiKey string) ([]byte, error) {
	const maxAttempts = 5
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}
		// NVD's edge rejects some requests with no User-Agent.
		req.Header.Set("User-Agent", "lumen-nvd-gen/1.0 (+https://github.com/Qwentrix/lumen)")

		// L-3: use nvdClient (redirect-stopped) instead of http.DefaultClient so
		// the apiKey header is not forwarded to a redirect target.
		resp, err := nvdClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("fetch: %w", err)
		} else {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			switch {
			case readErr != nil:
				lastErr = fmt.Errorf("read body: %w", readErr)
			case resp.StatusCode == http.StatusNotFound:
				// 404 is deterministic for this endpoint and almost always means an
				// invalid or unactivated NVD_API_KEY: keyless requests return 200,
				// but NVD rejects a bad key with 404. Retrying cannot help — fail
				// fast with guidance instead of burning the backoff budget.
				return nil, fmt.Errorf("NVD returned HTTP 404 (body: %q).\n"+
					"This almost always means an invalid or unactivated NVD_API_KEY — keyless requests "+
					"return 200, but NVD rejects a bad key with 404.\n"+
					"Fix: verify the key has no stray whitespace and was activated via the NVD email link, "+
					"or simply run without a key (`unset NVD_API_KEY` — slower but works).", string(body))
			case resp.StatusCode != http.StatusOK:
				lastErr = fmt.Errorf("NVD returned HTTP %d: %.200s", resp.StatusCode, string(body))
			case len(body) == 0:
				lastErr = fmt.Errorf("NVD returned an empty body (HTTP 200)")
			default:
				return body, nil
			}
		}

		backoff := time.Duration(attempt*attempt) * 2 * time.Second
		fmt.Fprintf(os.Stderr, "  attempt %d/%d failed: %v; retrying in %s\n", attempt, maxAttempts, lastErr, backoff)
		time.Sleep(backoff)
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", maxAttempts, lastErr)
}

// sleepForRate pauses between NVD requests to stay within the rate limit:
// ~5 requests/30s unauthenticated, ~50/30s with an API key.
func sleepForRate(apiKey string) {
	if apiKey == "" {
		time.Sleep(6 * time.Second)
	} else {
		time.Sleep(600 * time.Millisecond)
	}
}

// isUnbounded returns true when a CPERange has all version bounds empty,
// meaning it would match any version of the product.
func isUnbounded(r CPERange) bool {
	return r.VersionStartIncluding == "" && r.VersionEndExcluding == "" && r.VersionEndIncluding == ""
}

// dropRedundantUnbounded implements M-5: for each (vendor, product) pair, if
// there is at least one bounded CPE entry, remove all-empty-bounds entries for
// that same pair. This prevents a single unbounded CPE artifact (NVD quirk)
// from matching every installed version and over-counting CVE hits.
//
// A genuinely all-versions CVE (one where NO bounded entry exists for a product)
// is kept so that the scanner can still flag truly universal vulnerabilities.
func dropRedundantUnbounded(ranges []CPERange) []CPERange {
	// Collect the set of (vendor, product) pairs that have at least one bounded entry.
	hasBounded := map[[2]string]bool{}
	for _, r := range ranges {
		if !isUnbounded(r) {
			hasBounded[[2]string{r.Vendor, r.Product}] = true
		}
	}
	if len(hasBounded) == 0 {
		// No bounded entries at all — keep everything.
		return ranges
	}
	out := ranges[:0]
	for _, r := range ranges {
		// Drop unbounded entries only when a bounded sibling exists for the same product.
		if isUnbounded(r) && hasBounded[[2]string{r.Vendor, r.Product}] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// toRecords converts raw NVD vulnerability entries into curated CVERecords. It
// drops entries that have no CVSS v3.1 score (or score < minScore), and keeps
// only CPE matches that are (a) flagged vulnerable and (b) for a product in the
// scanner's curated allowlist (CuratedProducts). A CVE with no surviving CPE
// range after filtering is dropped entirely.
//
// M-5: for each CVE, all-empty-bounds CPE entries are dropped when a bounded
// entry for the same (vendor, product) also exists. This prevents ~46% of index
// records whose unbounded CPE artifact would match every installed version from
// inflating CVE counts once C-1's severity fix makes counts non-zero.
func toRecords(vulns []nvdVulnerability, minScore float64) []CVERecord {
	curated := lumennvd.CuratedProducts()
	records := make([]CVERecord, 0, len(vulns))
	seen := make(map[string]struct{}, len(vulns))

	for _, v := range vulns {
		cve := v.CVE
		if len(cve.Metrics.CVSSMetricV31) == 0 {
			continue
		}
		score := cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		if score < minScore {
			continue
		}
		// C-1: store severity lowercase so future regens produce a consistent
		// index that matches without needing strings.ToLower at read time.
		severity := strings.ToLower(cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity)

		var cpeRanges []CPERange
		for _, cfg := range cve.Configurations {
			for _, node := range cfg.Nodes {
				for _, match := range node.CPEMatch {
					// Skip non-vulnerable "runs-on" CPE entries.
					if !match.Vulnerable {
						continue
					}
					// Parse vendor:product from CPE 2.3 URI:
					// cpe:2.3:a:<vendor>:<product>:<version>:...
					parts := parseCPE(match.Criteria)
					if parts == nil {
						continue
					}
					vendor := strings.ToLower(parts[0])
					product := strings.ToLower(parts[1])
					// Allowlist: keep only products the scanner can resolve.
					if !curated[[2]string{vendor, product}] {
						continue
					}
					cpeRanges = append(cpeRanges, CPERange{
						Vendor:                vendor,
						Product:               product,
						VersionStartIncluding: match.VersionStartIncluding,
						VersionEndExcluding:   match.VersionEndExcluding,
						VersionEndIncluding:   match.VersionEndIncluding,
					})
				}
			}
		}

		// M-5: remove all-empty-bounds CPE entries when a bounded sibling
		// exists for the same (vendor, product) pair.
		cpeRanges = dropRedundantUnbounded(cpeRanges)

		if len(cpeRanges) == 0 {
			continue
		}

		// Deduplicate: if the same CVE ID appears in both CRITICAL and HIGH
		// pages, keep only the first occurrence (CRITICAL always fetched first).
		if _, dup := seen[cve.ID]; dup {
			continue
		}
		seen[cve.ID] = struct{}{}

		records = append(records, CVERecord{
			CVE:       cve.ID,
			CVSS:      score,
			Severity:  severity,
			CPE:       cpeRanges,
			Published: cve.Published,
		})
	}
	return records
}

func main() {
	apiKey := strings.TrimSpace(os.Getenv("NVD_API_KEY"))
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "NVD_API_KEY not set; requests will be rate-limited to 5/30s")
	}

	// 24-month publication window, fetched in <=120-day chunks (NVD API limit).
	windowEnd := time.Now()
	windowStart := windowEnd.AddDate(-2, 0, 0)

	// Fetch CRITICAL CVEs (CVSS 9.0–10.0).
	criticalVulns, err := fetchSeverity(apiKey, "CRITICAL", windowStart, windowEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch CRITICAL: %v\n", err)
		os.Exit(1)
	}

	// Fetch HIGH CVEs (CVSS 7.0–8.9).
	// These were previously omitted, causing high_cve_count scanner rules to
	// never fire. Both severities are required for CVSS ≥ 7.0 coverage.
	highVulns, err := fetchSeverity(apiKey, "HIGH", windowStart, windowEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch HIGH: %v\n", err)
		os.Exit(1)
	}

	// Merge and convert to curated CVERecords (dedup by CVE ID, minScore=7.0,
	// filtered to the scanner's allowlist of resolvable products).
	allVulns := append(criticalVulns, highVulns...)
	records := toRecords(allVulns, 7.0)

	curatedCount := len(lumennvd.CuratedProducts())
	fmt.Printf("Collected %d curated CVE records from %d raw (CRITICAL=%d, HIGH=%d) across %d allowlisted products\n",
		len(records), len(criticalVulns)+len(highVulns), len(criticalVulns), len(highVulns), curatedCount)

	// Write gzipped JSON.
	outPath := "internal/nvd/data/cve-index.json.gz"
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create output: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	h := sha256.New()
	gw := gzip.NewWriter(io.MultiWriter(f, h))
	if err := json.NewEncoder(gw).Encode(records); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
	if err := gw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "gzip close: %v\n", err)
		os.Exit(1)
	}

	checksum := hex.EncodeToString(h.Sum(nil))

	// Write meta.
	meta := Meta{
		GeneratedAt:         time.Now().UTC().Format(time.RFC3339),
		CVECount:            len(records),
		Source:              "NVD 2.0 API (CVSS >= 7.0, 24-month window, HIGH+CRITICAL)",
		MinCVSS:             7.0,
		WindowMonths:        24,
		CuratedProductCount: curatedCount,
		SHA256:              checksum,
		Note:                "Curated to the scanner's resolvable product allowlist (internal/nvd CuratedProducts). Re-run `make gen-nvd` after extending cpeTable.",
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	metaPath := "internal/nvd/data/cve-index.meta.json"
	if err := os.WriteFile(metaPath, metaData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write meta: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Written: %s (%d records, sha256=%s)\n", outPath, len(records), checksum)
	fmt.Printf("Meta:    %s\n", metaPath)
}

// parseCPE extracts [vendor, product] from a CPE 2.3 formatted string.
// CPE 2.3 format: cpe:2.3:<part>:<vendor>:<product>:<version>:...
func parseCPE(cpe string) []string {
	// Split on ":"
	parts := make([]string, 0, 8)
	start := 0
	for i, c := range cpe {
		if c == ':' {
			parts = append(parts, cpe[start:i])
			start = i + 1
		}
	}
	parts = append(parts, cpe[start:])
	// cpe:2.3:a:vendor:product:...
	if len(parts) < 5 {
		return nil
	}
	return []string{parts[3], parts[4]}
}
