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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailTypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdsTypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
)

// ---------------------------------------------------------------------------
// Paginating / ACL-aware mocks for the correctness-bug fixes.
//
// These mock types are intentionally named distinctly from those in
// cloud_test.go to avoid redeclaration in the same package. They model
// multi-page responses (via NextToken / Marker) and the widened S3 ACL surface.
// ---------------------------------------------------------------------------

// --- S3 mock with policy + ACL (satisfies S3API and S3ACLAPI) ---

type pagS3Mock struct {
	buckets []s3Types.Bucket
	// policyPublic[name] => bucket is public via policy
	policyPublic map[string]bool
	// policyErr[name] => GetBucketPolicyStatus returns this error (e.g. NoSuchBucketPolicy)
	policyErr map[string]error
	// aclPublic[name] => bucket has an AllUsers / AuthenticatedUsers ACL grant
	aclPublic map[string]bool
	// aclErr[name] => GetBucketAcl returns this error (e.g. access denied)
	aclErr map[string]error

	// call counters for assertions
	policyCalls int
	aclCalls    int
}

func (m *pagS3Mock) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: m.buckets}, nil
}

func (m *pagS3Mock) GetBucketPolicyStatus(_ context.Context, in *s3.GetBucketPolicyStatusInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	m.policyCalls++
	name := aws.ToString(in.Bucket)
	if m.policyErr != nil {
		if err, ok := m.policyErr[name]; ok {
			return nil, err
		}
	}
	pub := false
	if m.policyPublic != nil {
		pub = m.policyPublic[name]
	}
	return &s3.GetBucketPolicyStatusOutput{
		PolicyStatus: &s3Types.PolicyStatus{IsPublic: aws.Bool(pub)},
	}, nil
}

func (m *pagS3Mock) GetBucketAcl(_ context.Context, in *s3.GetBucketAclInput, _ ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	m.aclCalls++
	name := aws.ToString(in.Bucket)
	if m.aclErr != nil {
		if err, ok := m.aclErr[name]; ok {
			return nil, err
		}
	}
	out := &s3.GetBucketAclOutput{}
	if m.aclPublic != nil && m.aclPublic[name] {
		out.Grants = []s3Types.Grant{
			{
				Grantee: &s3Types.Grantee{
					Type: s3Types.TypeGroup,
					URI:  aws.String(s3AllUsersURI),
				},
				Permission: s3Types.PermissionRead,
			},
		}
	} else {
		// Non-public grant (canonical user) — must NOT be counted public.
		out.Grants = []s3Types.Grant{
			{
				Grantee: &s3Types.Grantee{
					Type: s3Types.TypeCanonicalUser,
					ID:   aws.String("owner-canonical-id"),
				},
				Permission: s3Types.PermissionFullControl,
			},
		}
	}
	return out, nil
}

// --- paginating EC2 mock (NextToken-driven, multi-page) ---

type pagEC2Mock struct {
	sgPages  [][]ec2Types.SecurityGroup
	volPages [][]ec2Types.Volume

	sgCalls  int
	volCalls int
}

func (m *pagEC2Mock) DescribeSecurityGroups(_ context.Context, in *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	idx := pageIndex(aws.ToString(in.NextToken))
	m.sgCalls++
	out := &ec2.DescribeSecurityGroupsOutput{}
	if idx < len(m.sgPages) {
		out.SecurityGroups = m.sgPages[idx]
	}
	if idx+1 < len(m.sgPages) {
		out.NextToken = aws.String(tokenForPage(idx + 1))
	}
	return out, nil
}

func (m *pagEC2Mock) DescribeVolumes(_ context.Context, in *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	idx := pageIndex(aws.ToString(in.NextToken))
	m.volCalls++
	out := &ec2.DescribeVolumesOutput{}
	if idx < len(m.volPages) {
		out.Volumes = m.volPages[idx]
	}
	if idx+1 < len(m.volPages) {
		out.NextToken = aws.String(tokenForPage(idx + 1))
	}
	return out, nil
}

// --- paginating RDS mock (Marker-driven, multi-page) ---

type pagRDSMock struct {
	pages [][]rdsTypes.DBInstance

	calls int
}

func (m *pagRDSMock) DescribeDBInstances(_ context.Context, in *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	idx := pageIndex(aws.ToString(in.Marker))
	m.calls++
	out := &rds.DescribeDBInstancesOutput{}
	if idx < len(m.pages) {
		out.DBInstances = m.pages[idx]
	}
	if idx+1 < len(m.pages) {
		out.Marker = aws.String(tokenForPage(idx + 1))
	}
	return out, nil
}

// page-token helpers: empty token => page 0, "page-N" => page N.
func tokenForPage(n int) string {
	return "page-" + string(rune('0'+n))
}

func pageIndex(token string) int {
	if token == "" {
		return 0
	}
	// token format "page-N"
	if len(token) == 6 && token[:5] == "page-" {
		return int(token[5] - '0')
	}
	return 0
}

// --- shadow-trail aware CloudTrail mock ---

// shadowTrailMock returns trails and reports per-trail logging status keyed by ARN.
type shadowTrailMock struct {
	trails    []cloudtrailTypes.Trail
	loggingBy map[string]bool // trail ARN => IsLogging
}

func (m *shadowTrailMock) DescribeTrails(_ context.Context, _ *cloudtrail.DescribeTrailsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{TrailList: m.trails}, nil
}

func (m *shadowTrailMock) GetTrailStatus(_ context.Context, in *cloudtrail.GetTrailStatusInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	logging := false
	if m.loggingBy != nil {
		logging = m.loggingBy[aws.ToString(in.Name)]
	}
	return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(logging)}, nil
}

// noSuchBucketPolicyErr is a smithy.APIError simulating S3 NoSuchBucketPolicy.
type noSuchBucketPolicyErr struct{}

func (e *noSuchBucketPolicyErr) Error() string                 { return "NoSuchBucketPolicy" }
func (e *noSuchBucketPolicyErr) ErrorCode() string             { return "NoSuchBucketPolicy" }
func (e *noSuchBucketPolicyErr) ErrorMessage() string          { return "no bucket policy" }
func (e *noSuchBucketPolicyErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// accessDeniedErr is a smithy.APIError simulating an access-denied response.
type accessDeniedErr struct{}

func (e *accessDeniedErr) Error() string                 { return "AccessDenied" }
func (e *accessDeniedErr) ErrorCode() string             { return "AccessDenied" }
func (e *accessDeniedErr) ErrorMessage() string          { return "access denied" }
func (e *accessDeniedErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// ---------------------------------------------------------------------------
// H-1: checkRDS counts ONLY unencrypted instances, across multiple pages.
// ---------------------------------------------------------------------------

func TestCheckRDSCountsOnlyUnencryptedAcrossPages(t *testing.T) {
	rdsc := &pagRDSMock{
		pages: [][]rdsTypes.DBInstance{
			{
				{DBInstanceIdentifier: aws.String("db-enc-1"), StorageEncrypted: aws.Bool(true)},
				{DBInstanceIdentifier: aws.String("db-unenc-1"), StorageEncrypted: aws.Bool(false)},
			},
			{
				{DBInstanceIdentifier: aws.String("db-enc-2"), StorageEncrypted: aws.Bool(true)},
				{DBInstanceIdentifier: aws.String("db-unenc-2"), StorageEncrypted: aws.Bool(false)},
				// StorageEncrypted nil => treated as unencrypted (aws.ToBool(nil)==false).
				{DBInstanceIdentifier: aws.String("db-nil")},
			},
		},
	}
	got, err := checkRDS(context.Background(), rdsc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 3 {
		t.Errorf("expected 3 unencrypted RDS instances (2 false + 1 nil), got %d", got)
	}
	if rdsc.calls != 2 {
		t.Errorf("expected 2 paginated DescribeDBInstances calls, got %d", rdsc.calls)
	}
}

// Guard against the H-1 regression: an account that encrypted EVERYTHING must
// report ZERO unencrypted instances (the old invalid filter returned them all).
func TestCheckRDSAllEncryptedReportsZero(t *testing.T) {
	rdsc := &pagRDSMock{
		pages: [][]rdsTypes.DBInstance{
			{
				{DBInstanceIdentifier: aws.String("db-1"), StorageEncrypted: aws.Bool(true)},
				{DBInstanceIdentifier: aws.String("db-2"), StorageEncrypted: aws.Bool(true)},
			},
		},
	}
	got, err := checkRDS(context.Background(), rdsc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0 {
		t.Errorf("expected 0 unencrypted RDS instances on fully-encrypted account, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// H-2: checkEC2 paginates security groups and volumes via NextToken.
// ---------------------------------------------------------------------------

func TestCheckEC2PaginatesSecurityGroupsAndVolumes(t *testing.T) {
	openSG := ec2Types.SecurityGroup{
		GroupId: aws.String("sg-open"),
		IpPermissions: []ec2Types.IpPermission{
			{IpRanges: []ec2Types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},
		},
	}
	openSGv6 := ec2Types.SecurityGroup{
		GroupId: aws.String("sg-open-v6"),
		IpPermissions: []ec2Types.IpPermission{
			{Ipv6Ranges: []ec2Types.Ipv6Range{{CidrIpv6: aws.String("::/0")}}},
		},
	}
	closedSG := ec2Types.SecurityGroup{
		GroupId: aws.String("sg-closed"),
		IpPermissions: []ec2Types.IpPermission{
			{IpRanges: []ec2Types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}}},
		},
	}

	ec2c := &pagEC2Mock{
		sgPages: [][]ec2Types.SecurityGroup{
			{openSG, closedSG}, // page 0: 1 open
			{openSGv6},         // page 1: 1 open
		},
		volPages: [][]ec2Types.Volume{
			{{VolumeId: aws.String("vol-1")}}, // page 0
			{{VolumeId: aws.String("vol-2")}, {VolumeId: aws.String("vol-3")}}, // page 1
		},
	}

	sgs, ebs, err := checkEC2(context.Background(), ec2c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sgs != 2 {
		t.Errorf("expected 2 public SGs across 2 pages, got %d", sgs)
	}
	if ebs != 3 {
		t.Errorf("expected 3 unencrypted volumes across 2 pages, got %d", ebs)
	}
	if ec2c.sgCalls != 2 {
		t.Errorf("expected 2 paginated DescribeSecurityGroups calls, got %d", ec2c.sgCalls)
	}
	if ec2c.volCalls != 2 {
		t.Errorf("expected 2 paginated DescribeVolumes calls, got %d", ec2c.volCalls)
	}
}

// ---------------------------------------------------------------------------
// H-4: public-via-ACL detection + dedup with policy.
// ---------------------------------------------------------------------------

func TestCheckPublicBucketsACL(t *testing.T) {
	for _, tc := range []struct {
		name string
		mock *pagS3Mock
		want int
	}{
		{
			name: "acl_only_public_is_counted",
			mock: &pagS3Mock{
				buckets: []s3Types.Bucket{
					{Name: aws.String("acl-public")},
					{Name: aws.String("private")},
				},
				// no public policy at all; NoSuchBucketPolicy on both
				policyErr: map[string]error{
					"acl-public": &noSuchBucketPolicyErr{},
					"private":    &noSuchBucketPolicyErr{},
				},
				aclPublic: map[string]bool{"acl-public": true},
			},
			want: 1,
		},
		{
			name: "public_via_both_policy_and_acl_counted_once",
			mock: &pagS3Mock{
				buckets:      []s3Types.Bucket{{Name: aws.String("dual-public")}},
				policyPublic: map[string]bool{"dual-public": true},
				aclPublic:    map[string]bool{"dual-public": true},
			},
			want: 1,
		},
		{
			name: "acl_access_denied_is_skipped",
			mock: &pagS3Mock{
				buckets: []s3Types.Bucket{{Name: aws.String("denied")}},
				policyErr: map[string]error{
					"denied": &noSuchBucketPolicyErr{},
				},
				aclErr: map[string]error{"denied": &accessDeniedErr{}},
			},
			want: 0,
		},
		{
			name: "policy_public_short_circuits_acl",
			mock: &pagS3Mock{
				buckets:      []s3Types.Bucket{{Name: aws.String("pol-public")}},
				policyPublic: map[string]bool{"pol-public": true},
			},
			want: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checkPublicBuckets(context.Background(), tc.mock)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("expected PublicStorageCount=%d, got %d", tc.want, got)
			}
		})
	}
}

// Verify the dual-public case does NOT invoke GetBucketAcl (policy already public).
func TestCheckPublicBucketsPolicyPublicSkipsACLCall(t *testing.T) {
	m := &pagS3Mock{
		buckets:      []s3Types.Bucket{{Name: aws.String("pol-public")}},
		policyPublic: map[string]bool{"pol-public": true},
	}
	if _, err := checkPublicBuckets(context.Background(), m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.aclCalls != 0 {
		t.Errorf("expected 0 GetBucketAcl calls when policy already public, got %d", m.aclCalls)
	}
}

// AuthenticatedUsers grant must also count as public.
func TestGrantsPublicAccessAuthenticatedUsers(t *testing.T) {
	grants := []s3Types.Grant{
		{Grantee: &s3Types.Grantee{Type: s3Types.TypeGroup, URI: aws.String(s3AuthenticatedUsersURI)}},
	}
	if !grantsPublicAccess(grants) {
		t.Error("AuthenticatedUsers grant should be treated as public")
	}
	// Canonical-user-only grants are NOT public.
	private := []s3Types.Grant{
		{Grantee: &s3Types.Grantee{Type: s3Types.TypeCanonicalUser, ID: aws.String("abc")}},
	}
	if grantsPublicAccess(private) {
		t.Error("canonical-user grant should NOT be treated as public")
	}
}

// Full-collector integration: ACL-only public bucket surfaces in PublicStorageCount.
func TestAWSCollectorACLPublicBucketEndToEnd(t *testing.T) {
	s3c := &pagS3Mock{
		buckets: []s3Types.Bucket{{Name: aws.String("acl-public")}},
		policyErr: map[string]error{
			"acl-public": &noSuchBucketPolicyErr{},
		},
		aclPublic: map[string]bool{"acl-public": true},
	}
	collector := newAWSCollectorWithClients(s3c, nil, nil, nil, nil)
	checks, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checks.PublicStorageCount != 1 {
		t.Errorf("expected PublicStorageCount=1 (ACL-only public), got %d", checks.PublicStorageCount)
	}
}

// ---------------------------------------------------------------------------
// M-2: org/shadow trail logging => audit logging enabled.
// ---------------------------------------------------------------------------

func TestCheckCloudTrailShadowTrailLogging(t *testing.T) {
	shadowARN := "arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail"
	ctc := &shadowTrailMock{
		trails: []cloudtrailTypes.Trail{
			// Only a shadow copy of the org trail is present in this member account.
			{TrailARN: aws.String(shadowARN), IsOrganizationTrail: aws.Bool(true)},
		},
		loggingBy: map[string]bool{shadowARN: true},
	}
	got, err := checkCloudTrail(context.Background(), ctc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("expected AuditLoggingEnabled=true when only a shadow org trail is logging")
	}
}

// ---------------------------------------------------------------------------
// L-2: password policy missing lowercase => weak.
// ---------------------------------------------------------------------------

func TestCheckIAMPasswordPolicyMissingLowercase(t *testing.T) {
	iamc := &lowercaseIAMMock{
		minPwLen:       aws.Int32(16),
		requireUpper:   true,
		requireLower:   false, // missing lowercase
		requireNumbers: true,
		requireSymbols: true,
	}
	_, weak, err := checkIAM(context.Background(), iamc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !weak {
		t.Error("expected password policy missing lowercase to be weak")
	}

	// Sanity: a policy with all requirements (incl. lowercase) is NOT weak.
	strong := &lowercaseIAMMock{
		minPwLen:       aws.Int32(16),
		requireUpper:   true,
		requireLower:   true,
		requireNumbers: true,
		requireSymbols: true,
	}
	_, weak2, err := checkIAM(context.Background(), strong)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if weak2 {
		t.Error("expected fully-compliant password policy (incl. lowercase) to NOT be weak")
	}
}

// lowercaseIAMMock is an IAMAPI mock that exposes RequireLowercaseCharacters.
type lowercaseIAMMock struct {
	minPwLen       *int32
	requireUpper   bool
	requireLower   bool
	requireNumbers bool
	requireSymbols bool
}

func (m *lowercaseIAMMock) GetAccountSummary(_ context.Context, _ *iam.GetAccountSummaryInput, _ ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{
		SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
	}, nil
}

func (m *lowercaseIAMMock) GetAccountPasswordPolicy(_ context.Context, _ *iam.GetAccountPasswordPolicyInput, _ ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	return &iam.GetAccountPasswordPolicyOutput{
		PasswordPolicy: &iamTypes.PasswordPolicy{
			MinimumPasswordLength:      m.minPwLen,
			RequireUppercaseCharacters: m.requireUpper,
			RequireLowercaseCharacters: m.requireLower,
			RequireNumbers:             m.requireNumbers,
			RequireSymbols:             m.requireSymbols,
		},
	}, nil
}
