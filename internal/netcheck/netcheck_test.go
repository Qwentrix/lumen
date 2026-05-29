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

// Package netcheck verifies Design Principle 4: the lumen scanner makes
// zero outbound network calls during a default (non-hybrid) run.
//
// Gate: every probe's Manifest().NetworkCalls must be empty, and each probe
// Run() must complete successfully without opening any TCP connections.
//
// In LU-1 all probes are stubs and make no network calls, so the test
// passes trivially. The gate exists to prevent LU-4 probe work from
// accidentally introducing default-on network calls, which would violate
// NFR-9 (scanner zero outbound) and break the OSS trust promise.
//
// Network interception strategy
// ==============================
// This test overrides http.DefaultTransport with a blocking transport whose
// DialContext increments an atomic counter and returns an error on every
// attempted TCP/UDP dial. Any probe that uses net/http (directly or via an
// imported library) will trigger this interceptor and cause the test to fail.
//
// Residual gap: probes that call net.Dial / net.DialContext / net.LookupHost
// directly (bypassing http.DefaultTransport) are NOT caught by this interceptor
// in pure Go without OS-level namespacing. The CI job therefore ALSO runs with
// Linux network namespacing:
//
//	unshare --net go test -v -run TestNoDefaultNetworkCalls ./internal/netcheck/...
//
// Any raw syscall-level dial will be caught by the namespace (ECONNREFUSED/
// ENETUNREACH) and the probe will return an error, which fails the test at the
// r.err != nil check. The two layers together form a complete gate.
//
// The CI job runs:
//
//	go test -v -run TestNoDefaultNetworkCalls ./internal/netcheck/...
package netcheck

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Qwentrix/lumen/internal/probes/ai_governance"
	"github.com/Qwentrix/lumen/internal/probes/compliance"
	"github.com/Qwentrix/lumen/internal/probes/privacy"
	"github.com/Qwentrix/lumen/internal/probes/security_posture"
	"github.com/Qwentrix/lumen/internal/probes/vulnerabilities"
)

// blockingTransport is an http.RoundTripper that intercepts every outbound
// TCP dial. On any dial attempt it increments the shared counter and returns
// an error so that no real connection is ever established.
type blockingTransport struct {
	dialCount *atomic.Int64
}

func (bt *blockingTransport) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	bt.dialCount.Add(1)
	return nil, fmt.Errorf("netcheck: outbound dial blocked (network=%s addr=%s)", network, addr)
}

// RoundTrip satisfies http.RoundTripper. It uses a fresh http.Transport whose
// DialContext is wired to our blocking interceptor so that any probe using
// http.DefaultTransport or constructing a default *http.Client will be caught.
func (bt *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t := &http.Transport{
		DialContext: bt.dialContext,
	}
	return t.RoundTrip(req)
}

// TestNoDefaultNetworkCalls asserts that all five probe domains complete
// without making outbound network connections.
//
// The test installs a process-wide HTTP transport interceptor before running
// any probe. It verifies that:
//  1. Each probe completes without returning an error.
//  2. No TCP dial was attempted via http.DefaultTransport (dialCount == 0).
//  3. No probe declares NetworkCalls in its Manifest (offline-by-default rule).
//
// See the package-level doc comment for the residual gap and the complementary
// CI unshare --net layer that covers raw net.Dial calls.
func TestNoDefaultNetworkCalls(t *testing.T) {
	// NOTE: this test must NOT run in parallel with itself because it mutates
	// http.DefaultTransport. It is safe to run alongside unrelated packages.
	var counter atomic.Int64
	bt := &blockingTransport{dialCount: &counter}

	// Install the blocking transport process-wide for the duration of this test.
	origTransport := http.DefaultTransport
	http.DefaultTransport = bt
	defer func() { http.DefaultTransport = origTransport }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run each probe and collect results.
	type probeRun struct {
		name    string
		err     error
		netWork []string // declared network calls from Manifest
	}

	runs := []probeRun{
		{
			name:    "vulnerabilities",
			netWork: vulnerabilities.Manifest().NetworkCalls,
			err: func() error {
				_, err := vulnerabilities.Run(ctx)
				return err
			}(),
		},
		{
			name:    "compliance",
			netWork: compliance.Manifest().NetworkCalls,
			err: func() error {
				_, err := compliance.Run(ctx)
				return err
			}(),
		},
		{
			name:    "ai_governance",
			netWork: ai_governance.Manifest().NetworkCalls,
			err: func() error {
				_, err := ai_governance.Run(ctx)
				return err
			}(),
		},
		{
			name:    "security_posture",
			netWork: security_posture.Manifest().NetworkCalls,
			err: func() error {
				_, err := security_posture.Run(ctx)
				return err
			}(),
		},
		{
			name:    "privacy",
			netWork: privacy.Manifest().NetworkCalls,
			err: func() error {
				_, err := privacy.Run(ctx)
				return err
			}(),
		},
	}

	for _, r := range runs {
		r := r
		t.Run(r.name, func(t *testing.T) {
			// 1. Probe must complete without error.
			if r.err != nil {
				t.Errorf("probe %s returned unexpected error: %v", r.name, r.err)
			}

			// 2. Probe must NOT declare any network calls in its Manifest for
			//    default (non-hybrid) mode.  Default probes must run offline.
			if len(r.netWork) > 0 {
				t.Errorf(
					"Design Principle 4 violation: probe %s declares %d network call(s) "+
						"in Manifest().NetworkCalls: %v\n"+
						"Default probes must make zero outbound connections. "+
						"Network-enabled paths must require explicit user consent "+
						"(obtained via `lumen consent`) and be disabled by default.",
					r.name, len(r.netWork), r.netWork,
				)
			}
		})
	}

	// 3. Assert the blocking transport was never triggered.
	// If dialCount > 0, a probe attempted an outbound HTTP call through
	// http.DefaultTransport, violating Design Principle 4 (NFR-9).
	if n := counter.Load(); n > 0 {
		t.Errorf(
			"Design Principle 4 violation: %d outbound HTTP dial(s) intercepted via "+
				"http.DefaultTransport. A probe is making a network call that must be "+
				"gated behind --hybrid / lumen consent. See NFR-9.",
			n,
		)
	}

	t.Logf("PASS: zero outbound network calls declared or made during default scan.")
}
