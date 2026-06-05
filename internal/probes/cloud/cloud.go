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

// Package cloud implements ENT-118: opt-in, read-only cloud-config probes.
//
// ZERO-NETWORK INVARIANT: this package MUST NOT be added to the default probe
// registry in cmd/lumen/scan.go or the netcheck runs slice. It is invoked ONLY
// inside the guarded "if includeCloud { ... }" block in runScan, behind the
// explicit --include-cloud flag AND the "cloud" consent domain gate. This
// mirrors the --hybrid networked path exemption pattern exactly.
//
// All cloud API operations are READ-ONLY (List/Describe/Get). No resource
// mutations. No credentials are stored — the scanner uses the user's existing
// local cloud credentials (AWS default credential chain, Azure CLI / MSI,
// GCP Application Default Credentials).
//
// AWS is the v1 deliverable. Azure and GCP are framework-ready stubs returning
// "not_implemented" metadata with zero findings; their SDKs are NOT added in v1.
package cloud

import (
	"context"
	"fmt"
	"strings"

	"github.com/Qwentrix/lumen/internal/probes/common"
	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"
)

// Manifest returns the static ManifestEntry for the cloud probe. It declares
// all network endpoints the cloud probe MAY contact when --include-cloud is set.
// This entry must NOT appear in the default probe registry or netcheck runs.
func Manifest() common.ManifestEntry {
	// Collect declared network calls from all providers.
	providers := defaultProviders()
	var networkCalls []string
	for _, p := range providers {
		networkCalls = append(networkCalls, p.DeclaredNetworkCalls()...)
	}
	return common.ManifestEntry{
		DomainID:     "cloud",
		OSAPIs:       nil, // no OS commands — cloud probes are pure HTTP
		FilePaths:    nil, // credentials are read by the AWS SDK from ~/.aws/; not directly by this probe
		NetworkCalls: networkCalls,
	}
}

// Run executes the cloud-config probe for the requested providers.
//
// providers is the list of provider names to scan (e.g. []string{"aws"}).
// An empty or nil list defaults to []string{"aws"}.
//
// This function is NETWORKED. It must only be called from the guarded
// "if includeCloud { ... }" block in runScan — never from a probe Run() or
// the default probe loop. See package doc for the zero-network invariant.
//
// If a provider has no credentials, it skips gracefully with a printed note
// and zero findings (not an error). The scan continues with remaining providers.
func Run(ctx context.Context, providers []string) (*lstypes.CloudFindings, error) {
	if len(providers) == 0 {
		providers = []string{"aws"}
	}

	// Dispatch to the appropriate collector for each requested provider.
	allProviders := providerMap()
	findings := &lstypes.CloudFindings{}
	scanned := []string{}

	for _, name := range providers {
		name = strings.ToLower(strings.TrimSpace(name))
		collector, ok := allProviders[name]
		if !ok {
			fmt.Printf("NOTE: cloud probe: unknown provider %q — supported: aws, azure, gcp\n", name)
			continue
		}

		fmt.Printf("cloud probe (%s): collecting...\n", name)
		checks, err := collector.Collect(ctx)
		if err != nil {
			// Non-fatal: log and continue with other providers.
			fmt.Printf("WARNING: cloud probe (%s): collection error: %v\n", name, err)
			continue
		}

		// Check whether this provider was actually scanned or skipped.
		// H-3: Do NOT print the raw Metadata value — it may contain credential file paths
		// (e.g. ~/.aws/credentials) that must not appear on stdout or in reports.
		// The sanitized message was already printed by the provider's Collect() method.
		if _, ok := checks.Metadata[name+".skipped"]; ok {
			continue
		}
		if v, ok := checks.Metadata[name+".status"]; ok && v == "not_implemented" {
			continue // stub provider — do not add to scanned list
		}

		// Merge findings: counts are summed, booleans require ALL scanned providers to be true.
		mergeChecks(findings, checks, len(scanned) == 0)
		scanned = append(scanned, name)
	}

	findings.ProvidersScanned = scanned
	if len(scanned) == 0 {
		fmt.Println("NOTE: cloud probe: no providers were successfully scanned. Zero cloud findings.")
	}
	return findings, nil
}

// mergeChecks merges CloudChecks from a single provider into the aggregate CloudFindings.
// For the first provider (isFirst=true), values are copied directly.
// For subsequent providers: counts are summed; booleans are ANDed (posture-conservative).
func mergeChecks(dst *lstypes.CloudFindings, src CloudChecks, isFirst bool) {
	// Counts are always summed across providers.
	dst.PublicStorageCount += src.PublicStorageCount
	dst.PublicIngressCount += src.PublicIngressCount
	dst.UnencryptedVolumesCount += src.UnencryptedVolumesCount

	if isFirst {
		// First provider: copy booleans directly.
		dst.RootMFAEnabled = src.RootMFAEnabled
		dst.IAMPasswordPolicyWeak = src.IAMPasswordPolicyWeak
		dst.AuditLoggingEnabled = src.AuditLoggingEnabled
	} else {
		// Subsequent providers: AND booleans (any failure → overall false).
		dst.RootMFAEnabled = dst.RootMFAEnabled && src.RootMFAEnabled
		dst.IAMPasswordPolicyWeak = dst.IAMPasswordPolicyWeak || src.IAMPasswordPolicyWeak
		dst.AuditLoggingEnabled = dst.AuditLoggingEnabled && src.AuditLoggingEnabled
	}
}

// defaultProviders returns the ordered list of provider collectors for the
// manifest declaration (all possible providers, for disclosure purposes).
func defaultProviders() []CloudProvider {
	return []CloudProvider{
		NewAWSCollector(),
		&AzureCollector{},
		&GCPCollector{},
	}
}

// providerMap returns a name-keyed map of CloudProvider implementations.
func providerMap() map[string]CloudProvider {
	return map[string]CloudProvider{
		"aws":   NewAWSCollector(),
		"azure": &AzureCollector{},
		"gcp":   &GCPCollector{},
	}
}
