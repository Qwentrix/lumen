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
)

// CloudChecks holds the normalised check results from a single cloud provider.
// All values are read-only counts/booleans — no resource ARNs, no account IDs,
// no PII, no credentials.
type CloudChecks struct {
	// PublicStorageCount is the number of public-readable object-storage buckets.
	PublicStorageCount int
	// PublicIngressCount is the number of security-group rules open to 0.0.0.0/0.
	PublicIngressCount int
	// UnencryptedVolumesCount is the number of unencrypted block/DB volumes.
	UnencryptedVolumesCount int
	// RootMFAEnabled is true when the root/admin account has MFA enabled.
	RootMFAEnabled bool
	// IAMPasswordPolicyWeak is true when the IAM password policy is absent or weak.
	IAMPasswordPolicyWeak bool
	// AuditLoggingEnabled is true when CloudTrail or equivalent is active.
	AuditLoggingEnabled bool
	// Metadata is an arbitrary map of provider-specific diagnostic notes
	// (e.g. "aws.cloudtrail.trails_count": "2"). No PII, no credentials.
	Metadata map[string]string
}

// CloudProvider is the interface each cloud-provider collector implements.
// Collectors are injected at Run() time so tests can supply fakes without live
// cloud credentials.
type CloudProvider interface {
	// Name returns the canonical provider identifier, e.g. "aws".
	Name() string
	// Collect runs read-only API calls and returns the findings.
	// It must return (zero-value CloudChecks, nil) when credentials are absent
	// and populate Metadata["<provider>.skipped"] = "no_credentials".
	Collect(ctx context.Context) (CloudChecks, error)
	// DeclaredNetworkCalls returns the manifest NetworkCalls strings for this
	// provider's API endpoints. Included in Manifest().NetworkCalls.
	DeclaredNetworkCalls() []string
}
