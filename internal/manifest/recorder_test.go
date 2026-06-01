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

package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecorder_Basic(t *testing.T) {
	r := New("v0.1.0-test")

	if r.ScanID() == "" {
		t.Error("scan ID should be non-empty")
	}

	r.RecordExec("/usr/bin/sw_vers", []string{})
	r.RecordExec("/usr/sbin/fdesetup", []string{"status"})
	r.RecordFileRead("/etc/ssh/sshd_config")

	// Verify no network calls.
	r.mu.Lock()
	netCount := len(r.networkCalls)
	execCount := len(r.execCalls)
	fileCount := len(r.fileReads)
	r.mu.Unlock()

	if netCount != 0 {
		t.Errorf("expected 0 network calls, got %d", netCount)
	}
	if execCount != 2 {
		t.Errorf("expected 2 exec calls, got %d", execCount)
	}
	if fileCount != 1 {
		t.Errorf("expected 1 file read, got %d", fileCount)
	}
}

func TestRecorder_Write(t *testing.T) {
	tmp := t.TempDir()
	r := New("v0.1.0-test")

	r.RecordExec("/bin/ls", []string{"-la"})
	r.RecordFileRead("/proc/version")

	path := filepath.Join(tmp, "manifest-test.json")
	if err := r.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if m.ScanID == "" {
		t.Error("manifest scan_id empty")
	}
	if len(m.ExecCalls) != 1 {
		t.Errorf("exec_calls: got %d, want 1", len(m.ExecCalls))
	}
	if m.ExecCalls[0].Cmd != "/bin/ls" {
		t.Errorf("exec cmd: got %q, want /bin/ls", m.ExecCalls[0].Cmd)
	}
	if len(m.FileReads) != 1 {
		t.Errorf("file_reads: got %d, want 1", len(m.FileReads))
	}
	if len(m.NetworkCalls) != 0 {
		t.Errorf("network_calls: got %d, want 0 — default scan must be zero-network", len(m.NetworkCalls))
	}
}

func TestNewScanID_Format(t *testing.T) {
	id := newScanID()
	// UUID v4: 8-4-4-4-12 hex chars
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Fatalf("scan ID %q has %d parts, want 5", id, len(parts))
	}
	want := []int{8, 4, 4, 4, 12}
	for i, p := range parts {
		if len(p) != want[i] {
			t.Errorf("part[%d] len = %d, want %d", i, len(p), want[i])
		}
	}
}
