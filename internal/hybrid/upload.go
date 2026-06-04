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

// Package hybrid: upload.go handles the HTTPS POST to lumen-api.
//
// This is one of exactly two networked code paths in the lumen binary:
//  1. lumen update (content delta fetch)
//  2. lumen scan --hybrid (this file)
//
// Neither path is reachable from probe Run() functions. The netcheck gate
// therefore stays green for all five probes under default scan mode.
package hybrid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// DefaultGatewayBaseURL is the production lumen-api base URL.
	// Overridable via --server flag (highest priority) or the LUMEN_SERVER_URL
	// environment variable (second priority). Resolution happens in
	// cmd/lumen/scan.go before Upload() is called; Upload() uses whatever
	// gatewayBaseURL is passed in, falling back to this constant when empty.
	DefaultGatewayBaseURL = "https://lumen.micelium.com"

	// ingestPath is the route registered in the api-gateway lumen proxy.
	ingestPath = "/api/v1/lumen/scanner/ingest"

	// uploadTimeout is the HTTP client timeout for the ingest request.
	// Generous to allow for slow connections while preventing hung processes.
	uploadTimeout = 30 * time.Second
)

// IngestResponse is the 200 response from POST /api/v1/lumen/scanner/ingest.
type IngestResponse struct {
	AssessmentID       string `json:"assessment_id"`
	SummaryURL         string `json:"summary_url"`
	HybridEnabledInV11 bool   `json:"hybrid_enabled_in_v1_1"`
}

// Upload POSTs the signed payload to the lumen-api ingest endpoint and returns
// the server's IngestResponse on success.
//
// gatewayBaseURL is the base URL of the gateway (no trailing slash), e.g.
// "https://lumen.micelium.com". Pass "" to use DefaultGatewayBaseURL.
//
// The caller must have already signed the payload (Sign must have been called).
// PreviewAndConfirm must have been called and confirmed before Upload is called
// — the --hybrid flow enforces this ordering in cmd/lumen/scan.go.
func Upload(ctx context.Context, p *UploadPayload, gatewayBaseURL string) (*IngestResponse, error) {
	if gatewayBaseURL == "" {
		gatewayBaseURL = DefaultGatewayBaseURL
	}

	if p.Signature == "" {
		return nil, fmt.Errorf("hybrid: payload is not signed — call Sign() before Upload()")
	}

	body, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("hybrid: marshal upload body: %w", err)
	}

	url := gatewayBaseURL + ingestPath

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("hybrid: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "lumen-scanner/"+p.ScannerVersion)

	client := &http.Client{Timeout: uploadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hybrid: upload request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64 KiB max
	if err != nil {
		return nil, fmt.Errorf("hybrid: reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hybrid: server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result IngestResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("hybrid: decode response: %w", err)
	}
	return &result, nil
}
