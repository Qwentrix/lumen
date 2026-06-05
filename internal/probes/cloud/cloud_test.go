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

// --- Mock implementations ---

type mockS3 struct {
	buckets   []s3Types.Bucket
	publicMap map[string]bool // bucket name → isPublic
}

func (m *mockS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: m.buckets}, nil
}

func (m *mockS3) GetBucketPolicyStatus(_ context.Context, in *s3.GetBucketPolicyStatusInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	if in.Bucket == nil {
		return &s3.GetBucketPolicyStatusOutput{}, nil
	}
	isPublic := m.publicMap[*in.Bucket]
	return &s3.GetBucketPolicyStatusOutput{
		PolicyStatus: &s3Types.PolicyStatus{IsPublic: aws.Bool(isPublic)},
	}, nil
}

type mockIAM struct {
	mfaEnabled     bool
	noPolicy       bool   // simulate NoSuchEntity
	minPwLen       *int32 // nil = absent
	requireUpper   bool
	requireLower   bool
	requireNumbers bool
	requireSymbols bool
}

func (m *mockIAM) GetAccountSummary(_ context.Context, _ *iam.GetAccountSummaryInput, _ ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	mfaVal := int32(0)
	if m.mfaEnabled {
		mfaVal = 1
	}
	return &iam.GetAccountSummaryOutput{
		SummaryMap: map[string]int32{"AccountMFAEnabled": mfaVal},
	}, nil
}

func (m *mockIAM) GetAccountPasswordPolicy(_ context.Context, _ *iam.GetAccountPasswordPolicyInput, _ ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	if m.noPolicy {
		return nil, &mockNoSuchEntityError{}
	}
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

// mockNoSuchEntityError is a minimal smithy.APIError simulating IAM NoSuchEntity.
type mockNoSuchEntityError struct{}

func (e *mockNoSuchEntityError) Error() string               { return "NoSuchEntity" }
func (e *mockNoSuchEntityError) ErrorCode() string           { return "NoSuchEntity" }
func (e *mockNoSuchEntityError) ErrorMessage() string        { return "entity does not exist" }
func (e *mockNoSuchEntityError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

type mockEC2 struct {
	sgs     []ec2Types.SecurityGroup
	volumes []ec2Types.Volume
}

func (m *mockEC2) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: m.sgs}, nil
}

func (m *mockEC2) DescribeVolumes(_ context.Context, _ *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{Volumes: m.volumes}, nil
}

type mockRDS struct {
	instances []rdsTypes.DBInstance
}

func (m *mockRDS) DescribeDBInstances(_ context.Context, _ *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: m.instances}, nil
}

type mockCloudTrail struct {
	trails    []cloudtrailTypes.Trail
	isLogging bool
}

func (m *mockCloudTrail) DescribeTrails(_ context.Context, _ *cloudtrail.DescribeTrailsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{TrailList: m.trails}, nil
}

func (m *mockCloudTrail) GetTrailStatus(_ context.Context, _ *cloudtrail.GetTrailStatusInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(m.isLogging)}, nil
}

// --- AWS collector tests ---

// TestAWSCollectorPublicBuckets verifies the S3 public bucket check with mocked clients.
func TestAWSCollectorPublicBuckets(t *testing.T) {
	s3c := &mockS3{
		buckets: []s3Types.Bucket{
			{Name: aws.String("private-bucket")},
			{Name: aws.String("public-bucket")},
		},
		publicMap: map[string]bool{
			"private-bucket": false,
			"public-bucket":  true,
		},
	}
	collector := newAWSCollectorWithClients(s3c, nil, nil, nil, nil)
	checks, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checks.PublicStorageCount != 1 {
		t.Errorf("expected PublicStorageCount=1, got %d", checks.PublicStorageCount)
	}
}

// TestAWSCollectorRootMFA verifies root MFA detection.
func TestAWSCollectorRootMFA(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
	}{
		{"mfa_on", true},
		{"mfa_off", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iamc := &mockIAM{mfaEnabled: tc.enabled, noPolicy: true}
			collector := newAWSCollectorWithClients(nil, iamc, nil, nil, nil)
			checks, err := collector.Collect(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if checks.RootMFAEnabled != tc.enabled {
				t.Errorf("expected RootMFAEnabled=%v, got %v", tc.enabled, checks.RootMFAEnabled)
			}
		})
	}
}

// TestAWSCollectorPasswordPolicy verifies weak/strong password policy detection.
func TestAWSCollectorPasswordPolicy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		iamc       *mockIAM
		expectWeak bool
	}{
		{
			name:       "no_policy",
			iamc:       &mockIAM{noPolicy: true},
			expectWeak: true,
		},
		{
			name: "strong_policy",
			iamc: &mockIAM{
				minPwLen:       aws.Int32(16),
				requireUpper:   true,
				requireLower:   true,
				requireNumbers: true,
				requireSymbols: true,
			},
			expectWeak: false,
		},
		{
			name: "short_password",
			iamc: &mockIAM{
				minPwLen:       aws.Int32(8),
				requireUpper:   true,
				requireNumbers: true,
				requireSymbols: true,
			},
			expectWeak: true,
		},
		{
			name: "missing_symbols",
			iamc: &mockIAM{
				minPwLen:       aws.Int32(14),
				requireUpper:   true,
				requireNumbers: true,
				requireSymbols: false,
			},
			expectWeak: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			collector := newAWSCollectorWithClients(nil, tc.iamc, nil, nil, nil)
			checks, err := collector.Collect(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if checks.IAMPasswordPolicyWeak != tc.expectWeak {
				t.Errorf("expected IAMPasswordPolicyWeak=%v, got %v", tc.expectWeak, checks.IAMPasswordPolicyWeak)
			}
		})
	}
}

// TestAWSCollectorOpenSecurityGroups verifies 0.0.0.0/0 ingress detection.
func TestAWSCollectorOpenSecurityGroups(t *testing.T) {
	ec2c := &mockEC2{
		sgs: []ec2Types.SecurityGroup{
			{
				GroupId: aws.String("sg-open"),
				IpPermissions: []ec2Types.IpPermission{
					{IpRanges: []ec2Types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},
				},
			},
			{
				GroupId: aws.String("sg-restricted"),
				IpPermissions: []ec2Types.IpPermission{
					{IpRanges: []ec2Types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}}},
				},
			},
		},
		volumes: []ec2Types.Volume{},
	}
	collector := newAWSCollectorWithClients(nil, nil, ec2c, nil, nil)
	checks, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checks.PublicIngressCount != 1 {
		t.Errorf("expected PublicIngressCount=1, got %d", checks.PublicIngressCount)
	}
}

// TestAWSCollectorUnencryptedVolumes verifies unencrypted EBS + RDS counting.
func TestAWSCollectorUnencryptedVolumes(t *testing.T) {
	ec2c := &mockEC2{
		sgs: []ec2Types.SecurityGroup{},
		volumes: []ec2Types.Volume{
			{VolumeId: aws.String("vol-1"), Encrypted: aws.Bool(false)},
			{VolumeId: aws.String("vol-2"), Encrypted: aws.Bool(false)},
		},
	}
	rdsc := &mockRDS{
		instances: []rdsTypes.DBInstance{
			{DBInstanceIdentifier: aws.String("db-1"), StorageEncrypted: aws.Bool(false)},
		},
	}
	collector := newAWSCollectorWithClients(nil, nil, ec2c, rdsc, nil)
	checks, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 EBS + 1 RDS = 3
	if checks.UnencryptedVolumesCount != 3 {
		t.Errorf("expected UnencryptedVolumesCount=3, got %d", checks.UnencryptedVolumesCount)
	}
}

// TestAWSCollectorCloudTrail verifies CloudTrail enabled/disabled/no-trails detection.
func TestAWSCollectorCloudTrail(t *testing.T) {
	for _, tc := range []struct {
		name      string
		trails    []cloudtrailTypes.Trail
		isLogging bool
		want      bool
	}{
		{
			name:      "logging_on",
			trails:    []cloudtrailTypes.Trail{{TrailARN: aws.String("arn:aws:cloudtrail:us-east-1:123:trail/t")}},
			isLogging: true,
			want:      true,
		},
		{
			name:      "logging_off",
			trails:    []cloudtrailTypes.Trail{{TrailARN: aws.String("arn:aws:cloudtrail:us-east-1:123:trail/t")}},
			isLogging: false,
			want:      false,
		},
		{
			name:   "no_trails",
			trails: []cloudtrailTypes.Trail{},
			want:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctc := &mockCloudTrail{trails: tc.trails, isLogging: tc.isLogging}
			collector := newAWSCollectorWithClients(nil, nil, nil, nil, ctc)
			checks, err := collector.Collect(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if checks.AuditLoggingEnabled != tc.want {
				t.Errorf("expected AuditLoggingEnabled=%v, got %v", tc.want, checks.AuditLoggingEnabled)
			}
		})
	}
}

// TestTrailStatusFnInjection verifies the cloudTrailStatusFunc injection path.
func TestTrailStatusFnInjection(t *testing.T) {
	collector := &AWSCollector{
		trailStatusFn: func(_ context.Context) (bool, error) {
			return true, nil
		},
	}
	checks, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !checks.AuditLoggingEnabled {
		t.Error("expected AuditLoggingEnabled=true from injected trailStatusFn")
	}
}

// TestTrailStatusFnError verifies that CloudTrail errors are recorded in metadata.
func TestTrailStatusFnError(t *testing.T) {
	collector := &AWSCollector{
		trailStatusFn: func(_ context.Context) (bool, error) {
			return false, fmt.Errorf("rate limit")
		},
	}
	checks, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("expected nil top-level error, got %v", err)
	}
	if checks.AuditLoggingEnabled {
		t.Error("expected AuditLoggingEnabled=false on error")
	}
	if checks.Metadata["aws.cloudtrail.error"] == "" {
		t.Error("expected aws.cloudtrail.error in Metadata on error")
	}
}

// --- Manifest tests ---

// TestManifestNetworkCallsNonEmpty verifies the cloud Manifest declares network calls
// (cloud is an explicitly networked probe — unlike the 5 default probes).
func TestManifestNetworkCallsNonEmpty(t *testing.T) {
	m := Manifest()
	if len(m.NetworkCalls) == 0 {
		t.Error("cloud Manifest().NetworkCalls must be non-empty: cloud is a declared networked probe")
	}
}

// TestManifestDomainID verifies the manifest DomainID is "cloud".
func TestManifestDomainID(t *testing.T) {
	m := Manifest()
	if m.DomainID != "cloud" {
		t.Errorf("expected DomainID=%q, got %q", "cloud", m.DomainID)
	}
}

// TestManifestNoOSAPIs verifies the cloud probe declares no OS commands
// (cloud probes are pure HTTP, not OS-level).
func TestManifestNoOSAPIs(t *testing.T) {
	m := Manifest()
	if len(m.OSAPIs) != 0 {
		t.Errorf("cloud Manifest().OSAPIs should be empty (no OS commands), got %v", m.OSAPIs)
	}
}

// --- Run function test (no live AWS creds required) ---

// TestRunNoCredentialsNonNil verifies that Run() returns non-nil findings even
// when no cloud credentials are present (graceful skip, not a crash).
func TestRunNoCredentialsNonNil(t *testing.T) {
	findings, err := Run(context.Background(), []string{})
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	if findings == nil {
		t.Fatal("Run must return non-nil CloudFindings even without cloud credentials")
	}
}

// TestRunUnknownProvider verifies that an unknown provider name is handled gracefully.
func TestRunUnknownProvider(t *testing.T) {
	findings, err := Run(context.Background(), []string{"unknown-cloud-provider"})
	if err != nil {
		t.Fatalf("Run returned unexpected error for unknown provider: %v", err)
	}
	if findings == nil {
		t.Fatal("Run must return non-nil findings even for unknown providers")
	}
}

// TestAzureCollectorNotImplemented verifies the Azure stub returns not_implemented metadata.
func TestAzureCollectorNotImplemented(t *testing.T) {
	a := &AzureCollector{}
	checks, err := a.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checks.Metadata["azure.status"] != "not_implemented" {
		t.Errorf("expected azure.status=not_implemented, got %q", checks.Metadata["azure.status"])
	}
}

// TestGCPCollectorNotImplemented verifies the GCP stub returns not_implemented metadata.
func TestGCPCollectorNotImplemented(t *testing.T) {
	g := &GCPCollector{}
	checks, err := g.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checks.Metadata["gcp.status"] != "not_implemented" {
		t.Errorf("expected gcp.status=not_implemented, got %q", checks.Metadata["gcp.status"])
	}
}
