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

// Package manifest provides a runtime access ledger that records every OS
// command, file read, and network call made during a scan. The ledger is
// written to ~/.lumen/manifest-{scanID}.json after the scan completes.
//
// A non-empty network_calls slice is a red flag for auditors — default scans
// must produce zero network entries (Design Principle 4, NFR-9).
package manifest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ExecEntry records a single exec.CommandContext call made by a probe.
type ExecEntry struct {
	Cmd  string   `json:"cmd"`
	Args []string `json:"args"`
}

// Manifest is the runtime access ledger written after each scan.
type Manifest struct {
	ScanID         string      `json:"scan_id"`
	ScannerVersion string      `json:"scanner_version"`
	StartedAt      time.Time   `json:"started_at"`
	FinishedAt     time.Time   `json:"finished_at"`
	ExecCalls      []ExecEntry `json:"exec_calls"`
	FileReads      []string    `json:"file_reads"`
	NetworkCalls   []string    `json:"network_calls"`
}

// Recorder is a thread-safe runtime manifest recorder. Probes call its methods
// immediately before each exec.CommandContext or file read so the ledger
// reflects what was actually attempted, including calls that fail.
//
// Use the package-level Default recorder for the active scan. A new Recorder
// (or a reset of Default) should be created at the start of each scan.
type Recorder struct {
	mu           sync.Mutex
	scanID       string
	version      string
	startedAt    time.Time
	execCalls    []ExecEntry
	fileReads    []string
	networkCalls []string
}

// Default is the package-level recorder used by probes.
// Initialised to an empty recorder on package load; replaced by scan.go at
// the start of each scan via New().
var Default = &Recorder{}

// New creates a fresh Recorder with a new scan ID and the current time.
// Call this at the start of each scan and assign to manifest.Default.
func New(scannerVersion string) *Recorder {
	return &Recorder{
		scanID:    newScanID(),
		version:   scannerVersion,
		startedAt: time.Now().UTC(),
	}
}

// ScanID returns the unique identifier for this scan.
func (r *Recorder) ScanID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.scanID
}

// RecordExec logs an exec.CommandContext call. Call this immediately before
// invoking the command so the ledger reflects attempted calls even on error.
func (r *Recorder) RecordExec(cmd string, args []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	argsCopy := make([]string, len(args))
	copy(argsCopy, args)
	r.execCalls = append(r.execCalls, ExecEntry{Cmd: cmd, Args: argsCopy})
}

// RecordFileRead logs an os.ReadFile / os.Open call on a system path.
func (r *Recorder) RecordFileRead(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fileReads = append(r.fileReads, path)
}

// RecordNetwork logs an outbound network call. This MUST NOT be called during
// a default (non-hybrid) scan — its presence in the output JSON is a red flag.
func (r *Recorder) RecordNetwork(url string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.networkCalls = append(r.networkCalls, url)
}

// Write finalises the manifest and writes it to path.
func (r *Recorder) Write(path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := Manifest{
		ScanID:         r.scanID,
		ScannerVersion: r.version,
		StartedAt:      r.startedAt,
		FinishedAt:     time.Now().UTC(),
		ExecCalls:      r.execCalls,
		FileReads:      r.fileReads,
		NetworkCalls:   r.networkCalls,
	}
	if m.ExecCalls == nil {
		m.ExecCalls = []ExecEntry{}
	}
	if m.FileReads == nil {
		m.FileReads = []string{}
	}
	if m.NetworkCalls == nil {
		m.NetworkCalls = []string{}
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("manifest: marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("manifest: mkdir: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("manifest: write %s: %w", path, err)
	}
	return nil
}

// DefaultManifestPath returns the standard path for this recorder's manifest file.
func DefaultManifestPath() string {
	home, _ := os.UserHomeDir()
	scanID := Default.ScanID()
	if scanID == "" {
		scanID = "unknown"
	}
	return filepath.Join(home, ".lumen", fmt.Sprintf("manifest-%s.json", scanID))
}


// newScanID generates a UUID-v4-like identifier using crypto/rand.
// We avoid importing google/uuid to keep the dependency footprint minimal and
// to eliminate any transitive import that might inadvertently call the network.
func newScanID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use current time hex (should never happen).
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	// Set version 4 and variant bits per RFC 4122 §4.4.
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:]),
	)
}
