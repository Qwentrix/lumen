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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateOutputPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home dir: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Skipf("cannot determine cwd: %v", err)
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errFrag string // substring expected in error message
	}{
		{
			name:    "valid path in home dir",
			input:   filepath.Join(home, "lumen-report.html"),
			wantErr: false,
		},
		{
			name:    "valid path in cwd",
			input:   filepath.Join(cwd, "out.html"),
			wantErr: false,
		},
		{
			name:    "valid path in subdirectory of home",
			input:   filepath.Join(home, "reports", "scan.html"),
			wantErr: false,
		},
		{
			name:    "missing .html extension",
			input:   filepath.Join(home, "lumen-report.txt"),
			wantErr: true,
			errFrag: ".html extension",
		},
		{
			name:    "no extension at all",
			input:   filepath.Join(home, "lumen-report"),
			wantErr: true,
			errFrag: ".html extension",
		},
		{
			name:    "traversal outside home and cwd — /tmp",
			input:   "/tmp/evil.html",
			wantErr: true,
			errFrag: "outside your home directory",
		},
		{
			name:    "traversal outside home and cwd — /etc/passwd",
			input:   "/etc/passwd.html",
			wantErr: true,
			errFrag: "outside your home directory",
		},
		{
			name: "dotdot traversal that would escape home",
			// Construct a path like ~/../../etc/evil.html which, once cleaned,
			// resolves to something above home.
			input:   filepath.Join(home, "..", "..", "etc", "evil.html"),
			wantErr: true,
			errFrag: "outside your home directory",
		},
		{
			name:    "relative path in cwd (should resolve and pass)",
			input:   "local-report.html",
			wantErr: false,
		},
		{
			name:    "uppercase .HTML extension rejected (case-sensitive)",
			input:   filepath.Join(home, "report.HTML"),
			wantErr: true,
			errFrag: ".html extension",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateOutputPath(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for input %q, got path %q", tc.input, got)
				} else if tc.errFrag != "" && !strings.Contains(err.Error(), tc.errFrag) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errFrag)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for input %q: %v", tc.input, err)
				}
				if got == "" {
					t.Errorf("expected non-empty validated path for input %q", tc.input)
				}
				if !filepath.IsAbs(got) {
					t.Errorf("validated path %q is not absolute", got)
				}
				if filepath.Ext(got) != ".html" {
					t.Errorf("validated path %q does not end in .html", got)
				}
			}
		})
	}
}
