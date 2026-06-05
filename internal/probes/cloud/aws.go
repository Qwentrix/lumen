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

// Package cloud implements the opt-in cloud-config probe for ENT-118.
// All API calls are READ-ONLY (Describe/List/Get). No resource mutation.
// No credentials are ever stored — the AWS default credential chain is used.
package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// --- Mockable API interfaces (injected in tests) ---

// S3API is the subset of the AWS S3 client used by the probe.
//
// H-4: GetBucketAcl is part of the S3 read-only surface so that buckets made
// public via a legacy ACL grant (AllUsers / AuthenticatedUsers) — with no public
// bucket *policy* — are still detected. A client that does not implement
// GetBucketAcl (older/partial mocks) still satisfies the policy-only path; the
// ACL path is gated behind a runtime type-assertion to S3ACLAPI so that
// pre-existing mocks remain compatible. The real *s3.Client satisfies both.
type S3API interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketPolicyStatus(ctx context.Context, params *s3.GetBucketPolicyStatusInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error)
}

// S3ACLAPI is the optional ACL-reading extension of S3API. The real *s3.Client
// satisfies it; checkPublicBuckets type-asserts the injected S3API to this
// interface and, when present, also counts buckets public via a legacy ACL grant.
type S3ACLAPI interface {
	GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
}

// IAMAPI is the subset of the AWS IAM client used by the probe.
type IAMAPI interface {
	GetAccountSummary(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GetAccountPasswordPolicy(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
}

// EC2API is the subset of the AWS EC2 client used by the probe.
type EC2API interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
}

// RDSAPI is the subset of the AWS RDS client used by the probe.
type RDSAPI interface {
	DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// CloudTrailAPIIface is the subset of the AWS CloudTrail client used by the probe.
type CloudTrailAPIIface interface {
	DescribeTrails(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

// cloudTrailStatusFunc allows tests to inject a simple boolean-returning function
// instead of a full CloudTrailAPIIface mock, for simpler test scenarios.
type cloudTrailStatusFunc func(ctx context.Context) (bool, error)

// --- AWS Collector ---

// AWSCollector implements CloudProvider for Amazon Web Services.
// All API calls are read-only: ListBuckets, GetBucketPolicyStatus, GetBucketAcl,
// GetAccountSummary, GetAccountPasswordPolicy, DescribeSecurityGroups,
// DescribeVolumes, DescribeDBInstances, DescribeTrails, GetTrailStatus.
//
// The collector uses the AWS default credential chain (env vars → ~/.aws/credentials
// profile → IAM role / EC2 IMDS). It never prompts for credentials or stores them.
type AWSCollector struct {
	// Injected API clients (nil = load from default AWS config at collection time).
	s3Client         S3API
	iamClient        IAMAPI
	ec2Client        EC2API
	rdsClient        RDSAPI
	cloudtrailClient CloudTrailAPIIface

	// trailStatusFn is an optional override for the CloudTrail logging check;
	// used by simple unit tests that don't need a full CloudTrailAPIIface mock.
	trailStatusFn cloudTrailStatusFunc
}

// NewAWSCollector creates an AWSCollector that will load credentials from the
// AWS default credential chain at collection time. All injected clients are nil.
func NewAWSCollector() *AWSCollector {
	return &AWSCollector{}
}

// newAWSCollectorWithClients creates an AWSCollector with pre-injected API
// clients — for unit tests only.
func newAWSCollectorWithClients(s3c S3API, iamc IAMAPI, ec2c EC2API, rdsc RDSAPI, ctc CloudTrailAPIIface) *AWSCollector {
	return &AWSCollector{
		s3Client:         s3c,
		iamClient:        iamc,
		ec2Client:        ec2c,
		rdsClient:        rdsc,
		cloudtrailClient: ctc,
	}
}

// Name returns the canonical provider identifier.
func (a *AWSCollector) Name() string { return "aws" }

// DeclaredNetworkCalls returns the manifest NetworkCalls strings for AWS.
// M-3: IMDS endpoint is included because the AWS default credential chain contacts
// http://169.254.169.254 when running on EC2 to retrieve IAM role credentials.
func (a *AWSCollector) DeclaredNetworkCalls() []string {
	return []string{
		"https://*.amazonaws.com — AWS API (read-only): s3:ListBuckets, s3:GetBucketPolicyStatus, s3:GetBucketAcl",
		"https://*.amazonaws.com — AWS API (read-only): iam:GetAccountSummary, iam:GetAccountPasswordPolicy",
		"https://*.amazonaws.com — AWS API (read-only): ec2:DescribeSecurityGroups, ec2:DescribeVolumes",
		"https://*.amazonaws.com — AWS API (read-only): rds:DescribeDBInstances",
		"https://*.amazonaws.com — AWS API (read-only): cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus",
		"http://169.254.169.254 — EC2 Instance Metadata Service (IAM role credential retrieval; credential-chain fallback, only when run on EC2)",
	}
}

// Collect runs all read-only AWS checks and returns aggregated findings.
// If no AWS credentials are found in the default credential chain, it returns
// zero-value checks with Metadata["aws.skipped"] = "no_credentials" and nil error.
func (a *AWSCollector) Collect(ctx context.Context) (CloudChecks, error) {
	checks := CloudChecks{
		Metadata: make(map[string]string),
	}

	var (
		s3c  S3API
		iamc IAMAPI
		ec2c EC2API
		rdsc RDSAPI
		ctc  CloudTrailAPIIface
	)

	if a.s3Client != nil || a.iamClient != nil || a.ec2Client != nil ||
		a.rdsClient != nil || a.cloudtrailClient != nil || a.trailStatusFn != nil {
		// Test path: use injected clients / function.
		s3c = a.s3Client
		iamc = a.iamClient
		ec2c = a.ec2Client
		rdsc = a.rdsClient
		ctc = a.cloudtrailClient
	} else {
		// Production path: load from default credential chain.
		//
		// H-1: Pass config.WithHTTPClient so the AWS SDK uses a client whose
		// Transport is http.DefaultTransport. This makes SDK HTTP calls
		// interceptable by the netcheck blocking transport in tests, adding a
		// defence-in-depth layer on top of the definitive unshare --net CI gate.
		// Note: the netcheck blocking transport catches HTTP-library calls through
		// http.DefaultTransport. The AWS SDK may use its own internal transport for
		// some credential-chain probes (e.g. IMDS on EC2); the unshare --net CI
		// namespace gate is the definitive zero-network guard for those paths.
		sdkHTTPClient := &http.Client{Transport: http.DefaultTransport}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithHTTPClient(sdkHTTPClient))
		if err != nil {
			// H-3: Raw error may contain file paths (e.g. ~/.aws/credentials).
			// Store it only in Metadata (never printed); show a sanitized message on console.
			checks.Metadata["aws.skipped"] = fmt.Sprintf("credential_load_error: %v", err)
			fmt.Println("NOTE: cloud probe (aws): skipped — credentials unavailable (run 'aws configure' or set AWS_PROFILE)")
			return checks, nil
		}
		if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
			// H-3: Credential retrieval error may contain file paths. Store raw error in
			// Metadata only; print only the sanitized message.
			checks.Metadata["aws.skipped"] = fmt.Sprintf("no_credentials: %v", err)
			fmt.Println("NOTE: cloud probe (aws): skipped — credentials unavailable (run 'aws configure' or set AWS_PROFILE)")
			return checks, nil
		}
		s3c = s3.NewFromConfig(cfg)
		iamc = iam.NewFromConfig(cfg)
		ec2c = ec2.NewFromConfig(cfg)
		rdsc = rds.NewFromConfig(cfg)
		ctc = cloudtrail.NewFromConfig(cfg)
	}

	// --- S3: public bucket check ---
	if s3c != nil {
		publicBuckets, err := checkPublicBuckets(ctx, s3c)
		if err != nil {
			checks.Metadata["aws.s3.error"] = err.Error()
		} else {
			checks.PublicStorageCount = publicBuckets
		}
	}

	// --- IAM: root MFA + password policy ---
	if iamc != nil {
		rootMFA, pwWeak, err := checkIAM(ctx, iamc)
		if err != nil {
			checks.Metadata["aws.iam.error"] = err.Error()
		} else {
			checks.RootMFAEnabled = rootMFA
			checks.IAMPasswordPolicyWeak = pwWeak
		}
	}

	// --- EC2: security groups + unencrypted EBS volumes ---
	if ec2c != nil {
		publicSGs, unencryptedEBS, err := checkEC2(ctx, ec2c)
		if err != nil {
			checks.Metadata["aws.ec2.error"] = err.Error()
		} else {
			checks.PublicIngressCount += publicSGs
			checks.UnencryptedVolumesCount += unencryptedEBS
		}
	}

	// --- RDS: unencrypted DB instances ---
	if rdsc != nil {
		unencryptedRDS, err := checkRDS(ctx, rdsc)
		if err != nil {
			checks.Metadata["aws.rds.error"] = err.Error()
		} else {
			checks.UnencryptedVolumesCount += unencryptedRDS
		}
	}

	// --- CloudTrail: audit logging ---
	if a.trailStatusFn != nil {
		// Simplified test path.
		enabled, err := a.trailStatusFn(ctx)
		if err != nil {
			checks.Metadata["aws.cloudtrail.error"] = err.Error()
		} else {
			checks.AuditLoggingEnabled = enabled
		}
	} else if ctc != nil {
		auditEnabled, err := checkCloudTrail(ctx, ctc)
		if err != nil {
			checks.Metadata["aws.cloudtrail.error"] = err.Error()
		} else {
			checks.AuditLoggingEnabled = auditEnabled
		}
	}

	return checks, nil
}

// maxBuckets caps the number of S3 buckets inspected by checkPublicBuckets.
// Lumen is a workstation assessment tool, not a full CSPM sweep — accounts with
// hundreds of buckets would otherwise cause an unbounded loop and a hung scan.
const maxBuckets = 200

// s3AllUsersURI and s3AuthenticatedUsersURI are the canonical AWS ACL group
// grantee URIs that make a bucket effectively public when granted any permission.
const (
	s3AllUsersURI           = "http://acs.amazonaws.com/groups/global/AllUsers"
	s3AuthenticatedUsersURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// checkPublicBuckets enumerates S3 buckets and counts those that are public via
// EITHER a public bucket policy OR a legacy public ACL grant. Uses
// s3:ListBuckets + s3:GetBucketPolicyStatus + s3:GetBucketAcl (all read-only).
//
// H-4: A bucket public only via a legacy ACL (AllUsers / AuthenticatedUsers grant)
// with no public *policy* would otherwise be reported private. Each bucket is
// counted at most once even if it is public via both policy and ACL.
// H-2: Capped at maxBuckets to prevent an unbounded loop on large accounts.
func checkPublicBuckets(ctx context.Context, client S3API) (int, error) {
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return 0, fmt.Errorf("s3.ListBuckets: %w", err)
	}

	buckets := out.Buckets
	truncated := false
	if len(buckets) > maxBuckets {
		buckets = buckets[:maxBuckets]
		truncated = true
	}
	if truncated {
		fmt.Printf("NOTE: cloud probe (aws): account has >%d S3 buckets — inspecting first %d only (workstation assessment, not a full CSPM sweep)\n", maxBuckets, maxBuckets)
	}

	// H-4: ACL reads are only available when the injected client supports them
	// (the real *s3.Client always does; some narrow mocks may not).
	aclClient, hasACL := client.(S3ACLAPI)

	count := 0
	for _, b := range buckets {
		if b.Name == nil {
			continue
		}

		isPublic := false

		ps, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
			Bucket: b.Name,
		})
		if err != nil {
			// NoSuchBucket or access denied — bucket policy is private/inaccessible.
			var noSuchBucket *s3Types.NoSuchBucket
			if errors.As(err, &noSuchBucket) {
				// bucket gone — nothing to count; skip ACL too.
				continue
			}
			// For "NoSuchBucketPolicy" the SDK returns a smithy API error (not a typed
			// error struct in v2); treat any other error as "not public via policy".
			// Fall through to the ACL check (conservative for policy, but ACL may
			// still reveal public access).
		} else if ps.PolicyStatus != nil && aws.ToBool(ps.PolicyStatus.IsPublic) {
			isPublic = true
		}

		// H-4: ACL fallback — count the bucket public if any grant targets the
		// AllUsers or AuthenticatedUsers group. Skipped if already counted via
		// policy (dedup: at most once per bucket).
		if !isPublic && hasACL {
			acl, aclErr := aclClient.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: b.Name})
			if aclErr != nil {
				// Access-denied / NoSuchBucket / other — tolerate and skip (conservative).
				continue
			}
			if acl != nil && grantsPublicAccess(acl.Grants) {
				isPublic = true
			}
		}

		if isPublic {
			count++
		}
	}
	return count, nil
}

// grantsPublicAccess reports whether any ACL grant targets the AllUsers or
// AuthenticatedUsers group URI (i.e. makes the bucket effectively public).
func grantsPublicAccess(grants []s3Types.Grant) bool {
	for _, g := range grants {
		if g.Grantee == nil {
			continue
		}
		uri := aws.ToString(g.Grantee.URI)
		if uri == s3AllUsersURI || uri == s3AuthenticatedUsersURI {
			return true
		}
	}
	return false
}

// checkIAM checks root-account MFA status and password policy strength.
// Uses iam:GetAccountSummary (AccountMFAEnabled) and iam:GetAccountPasswordPolicy.
func checkIAM(ctx context.Context, client IAMAPI) (rootMFAEnabled bool, pwWeak bool, err error) {
	// Root MFA via GetAccountSummary. SummaryMap is map[string]int32.
	summary, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return false, false, fmt.Errorf("iam.GetAccountSummary: %w", err)
	}
	if v, ok := summary.SummaryMap["AccountMFAEnabled"]; ok {
		rootMFAEnabled = v >= 1
	}

	// Password policy check.
	pp, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		// NoSuchEntity = no password policy configured — that is weak.
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchEntity" {
			return rootMFAEnabled, true, nil
		}
		return rootMFAEnabled, false, fmt.Errorf("iam.GetAccountPasswordPolicy: %w", err)
	}
	policy := pp.PasswordPolicy
	if policy == nil {
		pwWeak = true
	} else {
		weak := false
		if policy.MinimumPasswordLength == nil || *policy.MinimumPasswordLength < 14 {
			weak = true
		}
		if !policy.RequireUppercaseCharacters {
			weak = true
		}
		// L-2: CIS AWS 1.9–1.12 also requires lowercase characters.
		if !policy.RequireLowercaseCharacters {
			weak = true
		}
		if !policy.RequireNumbers {
			weak = true
		}
		if !policy.RequireSymbols {
			weak = true
		}
		pwWeak = weak
	}
	return rootMFAEnabled, pwWeak, nil
}

// maxEC2Pages caps the number of paginated EC2 result pages inspected, as a
// belt-and-suspenders guard against a misbehaving NextToken that never clears.
// Each page returns up to ~1000 items, so this bounds the scan at a sane size
// for a workstation assessment tool.
const maxEC2Pages = 50

// checkEC2 enumerates security groups for 0.0.0.0/0 or ::/0 ingress rules and
// counts unencrypted EBS volumes. Uses ec2:DescribeSecurityGroups + ec2:DescribeVolumes.
//
// H-3 (single-region, v1 limitation): EC2 is a regional service, so these checks
// cover ONLY the default configured region (resolved from the AWS credential/region
// chain). Multi-region enumeration is a deliberate v2 item — see SCANNER_MANIFEST.md.
//
// H-2 (pagination): both Describe calls are paged via NextToken; a single
// non-paginated call silently caps at one page and under-reports large accounts.
func checkEC2(ctx context.Context, client EC2API) (publicSGs int, unencryptedEBS int, err error) {
	// --- Security groups (paginated via NextToken) ---
	var sgToken *string
	for page := 0; page < maxEC2Pages; page++ {
		sgOut, sgErr := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
			NextToken: sgToken,
		})
		if sgErr != nil {
			return 0, 0, fmt.Errorf("ec2.DescribeSecurityGroups: %w", sgErr)
		}
		for _, sg := range sgOut.SecurityGroups {
			hasBroadIngress := false
		permLoop:
			for _, perm := range sg.IpPermissions {
				for _, r := range perm.IpRanges {
					if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
						hasBroadIngress = true
						break permLoop
					}
				}
				for _, r := range perm.Ipv6Ranges {
					if aws.ToString(r.CidrIpv6) == "::/0" {
						hasBroadIngress = true
						break permLoop
					}
				}
			}
			if hasBroadIngress {
				publicSGs++
			}
		}
		if sgOut.NextToken == nil || aws.ToString(sgOut.NextToken) == "" {
			break
		}
		sgToken = sgOut.NextToken
	}

	// --- EBS volumes (paginated via NextToken) ---
	// Filter for unencrypted (encrypted=false).
	var volToken *string
	for page := 0; page < maxEC2Pages; page++ {
		volOut, volErr := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
			Filters: []ec2Types.Filter{
				{Name: aws.String("encrypted"), Values: []string{"false"}},
			},
			NextToken: volToken,
		})
		if volErr != nil {
			return publicSGs, 0, fmt.Errorf("ec2.DescribeVolumes: %w", volErr)
		}
		unencryptedEBS += len(volOut.Volumes)
		if volOut.NextToken == nil || aws.ToString(volOut.NextToken) == "" {
			break
		}
		volToken = volOut.NextToken
	}

	return publicSGs, unencryptedEBS, nil
}

// maxRDSPages caps the number of paginated RDS result pages inspected, as a
// belt-and-suspenders guard against a Marker that never clears.
const maxRDSPages = 50

// checkRDS counts unencrypted RDS DB instances. Uses rds:DescribeDBInstances.
//
// H-1 (overcount fix): the previous implementation passed a DescribeDBInstances
// filter named "storage-encrypted", which is NOT a supported RDS filter
// (supported: db-cluster-id, db-instance-id, dbi-resource-id, domain, engine,
// engine-version). The API ignored/rejected it and returned ALL instances, so
// every instance was counted as unencrypted — false-firing CLOUD_UNENCRYPTED_STORAGE
// even on fully-encrypted accounts. We now fetch all instances and count only
// those where StorageEncrypted is false.
//
// H-3 (single-region, v1 limitation): RDS is a regional service, so this check
// covers ONLY the default configured region. Multi-region enumeration is a
// deliberate v2 item — see SCANNER_MANIFEST.md.
//
// H-2 (pagination): paged via Marker; a single non-paginated call silently caps
// at one page and under-reports large accounts.
func checkRDS(ctx context.Context, client RDSAPI) (int, error) {
	unencrypted := 0
	var marker *string
	for page := 0; page < maxRDSPages; page++ {
		out, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
			Marker: marker,
		})
		if err != nil {
			return 0, fmt.Errorf("rds.DescribeDBInstances: %w", err)
		}
		for _, db := range out.DBInstances {
			if !aws.ToBool(db.StorageEncrypted) {
				unencrypted++
			}
		}
		if out.Marker == nil || aws.ToString(out.Marker) == "" {
			break
		}
		marker = out.Marker
	}
	return unencrypted, nil
}

// checkCloudTrail checks whether at least one CloudTrail trail is logging.
// Uses cloudtrail:DescribeTrails + cloudtrail:GetTrailStatus.
//
// M-2: IncludeShadowTrails must be true (the API default) so that member-account
// shadow copies of an AWS Organizations org-level trail are returned. With it set
// to false, accounts covered ONLY by an org trail would have an empty TrailList
// and be reported as "no audit logging" (false positive).
func checkCloudTrail(ctx context.Context, client CloudTrailAPIIface) (bool, error) {
	out, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(true),
	})
	if err != nil {
		return false, fmt.Errorf("cloudtrail.DescribeTrails: %w", err)
	}
	if len(out.TrailList) == 0 {
		return false, nil
	}
	for _, trail := range out.TrailList {
		if trail.TrailARN == nil {
			continue
		}
		status, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		if err != nil {
			continue // tolerate per-trail errors
		}
		if aws.ToBool(status.IsLogging) {
			return true, nil
		}
	}
	return false, nil
}

// Compile-time check: *AWSCollector must satisfy CloudProvider.
var _ CloudProvider = (*AWSCollector)(nil)
