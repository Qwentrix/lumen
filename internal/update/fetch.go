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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// bundleManifest represents the manifest.json in a lumen-bundles GitHub release.
// Fields mirror the design §16.3 signing scheme documented in LU5-BUILD-BLUEPRINT.
type bundleManifest struct {
	BundleURL    string `json:"bundle_url"`
	BundleSHA256 string `json:"bundle_sha256"` // hex-encoded sha256 of the bundle tar.gz
	Signature    string `json:"ed25519_signature"` // hex-encoded ed25519(priv, sha256_bytes)
	GeneratedAt  string `json:"generated_at"` // RFC3339 timestamp
	RuleCount    int    `json:"rule_count"`
	OverlayCount int    `json:"overlay_count"`
}

const (
	// bundlesManifestURL is the URL to the manifest.json in the lumen-bundles repo's
	// latest GitHub release.
	//
	// PROVISIONING: once github.com/Qwentrix/lumen-bundles is created and the
	// first signed bundle is published, this URL will resolve correctly.
	bundlesManifestURL = "https://github.com/Qwentrix/lumen-bundles/releases/latest/download/manifest.json"

	// httpTimeout is the maximum time to wait for a fetch request.
	httpTimeout = 30 * time.Second

	// maxManifestBytes is the maximum number of bytes read from the manifest response.
	maxManifestBytes = 64 * 1024 // 64 KiB — manifest.json is small

	// maxBundleBytes is the maximum bundle size we will download (100 MiB).
	maxBundleBytes = 100 * 1024 * 1024
)

// FetchManifest downloads and parses the bundle manifest from the lumen-bundles
// GitHub release endpoint.
//
// Only dials github.com — no redirects to non-GitHub hosts are followed.
// Times out after httpTimeout.
func FetchManifest(ctx context.Context) (*bundleManifest, error) {
	client := &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow redirects within github.com / objects.githubusercontent.com only.
			host := req.URL.Host
			if !strings.HasSuffix(host, "github.com") &&
				!strings.HasSuffix(host, "githubusercontent.com") {
				return fmt.Errorf("update: redirect to non-GitHub host %q blocked", host)
			}
			if len(via) >= 3 {
				return fmt.Errorf("update: too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bundlesManifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("update: build manifest request: %w", err)
	}
	req.Header.Set("User-Agent", "lumen-scanner/update")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: manifest HTTP %d", resp.StatusCode)
	}

	lr := io.LimitReader(resp.Body, maxManifestBytes)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("update: read manifest body: %w", err)
	}

	var m bundleManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("update: parse manifest JSON: %w", err)
	}
	if m.BundleURL == "" || m.BundleSHA256 == "" || m.Signature == "" {
		return nil, fmt.Errorf("update: manifest missing required fields (bundle_url, bundle_sha256, ed25519_signature)")
	}

	return &m, nil
}

// isAllowedBundleURL reports whether rawURL is on the GitHub/githubusercontent
// allowlist used for both the initial dial and redirect checks.
// This mirrors the CheckRedirect logic so both checks stay consistent.
func isAllowedBundleURL(rawURL string) bool {
	return strings.HasPrefix(rawURL, "https://github.com/") ||
		strings.HasPrefix(rawURL, "https://objects.githubusercontent.com/")
}

// FetchBundle downloads the content bundle tar.gz from the URL in the manifest.
// Returns the raw bytes; the caller must verify SHA256 and signature before use.
//
// L-6 (SSRF pre-flight): m.BundleURL is validated against the GitHub/
// githubusercontent allowlist BEFORE the first dial, regardless of whether the
// manifest has already been signature-verified.  This is defense-in-depth
// against a future refactor that reorders verify/fetch.
//
// Only dials GitHub/githubusercontent hosts — redirects to other hosts are blocked.
func FetchBundle(ctx context.Context, m *bundleManifest) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("update: nil manifest")
	}

	// L-6: pre-flight check before opening any connection.
	if !isAllowedBundleURL(m.BundleURL) {
		return nil, fmt.Errorf("update: bundle_url %q is not on the allowed GitHub host list (must begin with https://github.com/ or https://objects.githubusercontent.com/)", m.BundleURL)
	}

	client := &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			host := req.URL.Host
			if !strings.HasSuffix(host, "github.com") &&
				!strings.HasSuffix(host, "githubusercontent.com") {
				return fmt.Errorf("update: redirect to non-GitHub host %q blocked", host)
			}
			if len(via) >= 3 {
				return fmt.Errorf("update: too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.BundleURL, nil)
	if err != nil {
		return nil, fmt.Errorf("update: build bundle request: %w", err)
	}
	req.Header.Set("User-Agent", "lumen-scanner/update")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: fetch bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: bundle HTTP %d", resp.StatusCode)
	}

	lr := io.LimitReader(resp.Body, maxBundleBytes)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("update: read bundle body: %w", err)
	}

	return data, nil
}
