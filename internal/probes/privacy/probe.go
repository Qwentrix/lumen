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

// Package privacy probes for PII at rest in the user's home directory using
// regex matching. The scanner reads file content in a streaming fashion and
// never stores or logs matched content.
// TODO (LU-4): implement dlp_scanner.go and home_walker.go.
package privacy

import (
	"context"

	"github.com/Qwentrix/lumen/internal/probes/common"
)

const domainID = "privacy"

// Run executes the privacy probe.
// Walks ~/Documents (and any additional paths consented to) and applies the
// bundled PII regex set. No file content is stored in the result; only
// finding hints referencing the rule IDs that were triggered.
func Run(ctx context.Context) (*common.ProbeResult, error) {
	// TODO: implement streaming home_walker.go + pii_regex.go.
	// - Walk only directories included in the current consent snapshot.
	// - Apply regex patterns (SSN, CC, DOB, email, phone) to file content.
	// - Record only FindingHints (rule IDs + hit counts), never the matched text.
	return &common.ProbeResult{
		DomainID: domainID,
		Findings: []common.FindingHint{},
		Metadata: map[string]interface{}{"status": "stub"},
	}, nil
}

// Manifest returns the static access declaration for the privacy probe.
func Manifest() common.ManifestEntry {
	return common.ManifestEntry{
		DomainID: domainID,
		OSAPIs:   []string{},
		FilePaths: []string{
			"~/Documents/ (streaming read, content never stored or transmitted)",
		},
		NetworkCalls: []string{},
	}
}
