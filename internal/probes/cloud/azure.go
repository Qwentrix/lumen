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

package cloud

import (
	"context"
	"fmt"
)

// AzureCollector is a framework-ready stub for Azure cloud-config probes.
// Full coverage (Azure Security Center, Storage account public access,
// Defender for Cloud, Activity Log audit logging) is deferred to V2 /
// the paid CSPM-tier cloud pack.
//
// No Azure SDK dependency is added in v1 — the stub is SDK-free to keep
// go.sum lean per the "<20 direct deps" supply-chain promise.
type AzureCollector struct{}

// Name returns the canonical provider identifier.
func (a *AzureCollector) Name() string { return "azure" }

// DeclaredNetworkCalls returns the manifest NetworkCalls strings for Azure.
// Returns non-empty even for the stub so callers know Azure is a networked path.
func (a *AzureCollector) DeclaredNetworkCalls() []string {
	return []string{
		"https://management.azure.com — Azure Management API (read-only, NOT IMPLEMENTED in v1)",
		"https://login.microsoftonline.com — Azure AD auth (DefaultAzureCredential, NOT IMPLEMENTED in v1)",
	}
}

// Collect returns a zero-value CloudChecks with a metadata note indicating
// that Azure probes are not yet implemented. No API calls are made.
func (a *AzureCollector) Collect(_ context.Context) (CloudChecks, error) {
	checks := CloudChecks{
		Metadata: map[string]string{
			"azure.status": "not_implemented",
			"azure.note":   "Azure cloud-config probes are deferred to the paid CSPM-tier cloud pack (V2). No API calls were made.",
		},
	}
	fmt.Println("NOTE: cloud probe (Azure): not implemented in v1 — skipping. Full coverage in V2 CSPM pack.")
	return checks, nil
}

// Compile-time check: *AzureCollector must satisfy CloudProvider.
var _ CloudProvider = (*AzureCollector)(nil)
