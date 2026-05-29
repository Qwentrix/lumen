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

// Package common defines the shared types and interfaces for all Lumen probes.
package common

import "context"

// ManifestEntry declares what OS APIs and file paths a probe will access.
// It is shown to the user during `lumen consent` before any scan runs.
type ManifestEntry struct {
	DomainID    string   // e.g. "vulnerabilities"
	OSAPIs      []string // e.g. ["/usr/sbin/system_profiler"]
	FilePaths   []string // e.g. ["~/.ssh/"]
	NetworkCalls []string // empty for most probes; may list update URLs
}

// ProbeResult is the structured output of a single probe run.
type ProbeResult struct {
	DomainID string
	Findings []FindingHint
	Metadata map[string]interface{}
}

// FindingHint is a lightweight signal returned by a probe.
// The scoring engine maps hints to full finding rules via rule YAML.
type FindingHint struct {
	// RuleID is the rule YAML identifier that this hint triggers (e.g. "NO_MFA_ORG_WIDE").
	RuleID string
	// Value is an optional numeric or string value associated with the hint.
	Value interface{}
}

// Probe is the interface every domain probe must implement.
type Probe interface {
	// Manifest returns the static access declaration for this probe.
	// Called by `lumen consent` without running the actual probe.
	Manifest() ManifestEntry

	// Run executes the probe and returns structured findings.
	// It must not make outbound network calls (except probes that explicitly
	// declare them in Manifest().NetworkCalls, e.g. the update probe).
	Run(ctx context.Context) (*ProbeResult, error)

	// DomainID returns the canonical domain identifier for this probe.
	DomainID() string
}
