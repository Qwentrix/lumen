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

// GCPCollector is a framework-ready stub for Google Cloud Platform cloud-config probes.
// Full coverage (Cloud Storage public access, VPC firewall rules, Cloud KMS encryption,
// Cloud Audit Logs, IAM policy analysis) is deferred to V2 /
// the paid CSPM-tier cloud pack.
//
// No GCP SDK dependency is added in v1 — the stub is SDK-free to keep
// go.sum lean per the "<20 direct deps" supply-chain promise.
// Application Default Credentials (ADC) path scaffolded but not exercised.
type GCPCollector struct{}

// Name returns the canonical provider identifier.
func (g *GCPCollector) Name() string { return "gcp" }

// DeclaredNetworkCalls returns the manifest NetworkCalls strings for GCP.
// Returns non-empty even for the stub so callers know GCP is a networked path.
func (g *GCPCollector) DeclaredNetworkCalls() []string {
	return []string{
		"https://cloudresourcemanager.googleapis.com — GCP Resource Manager API (read-only, NOT IMPLEMENTED in v1)",
		"https://oauth2.googleapis.com — GCP ADC token endpoint (GOOGLE_APPLICATION_CREDENTIALS, NOT IMPLEMENTED in v1)",
	}
}

// Collect returns a zero-value CloudChecks with a metadata note indicating
// that GCP probes are not yet implemented. No API calls are made.
func (g *GCPCollector) Collect(_ context.Context) (CloudChecks, error) {
	checks := CloudChecks{
		Metadata: map[string]string{
			"gcp.status": "not_implemented",
			"gcp.note":   "GCP cloud-config probes are deferred to the paid CSPM-tier cloud pack (V2). No API calls were made.",
		},
	}
	fmt.Println("NOTE: cloud probe (GCP): not implemented in v1 — skipping. Full coverage in V2 CSPM pack.")
	return checks, nil
}

// Compile-time check: *GCPCollector must satisfy CloudProvider.
var _ CloudProvider = (*GCPCollector)(nil)
