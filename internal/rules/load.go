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

package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	lsrules "github.com/Qwentrix/lumen-scoring/pkg/rules"
)

// LoadEmbedded extracts the embedded rule and overlay YAML files to a
// temporary directory and loads them via the lumen-scoring public loaders.
//
// This is Option A from the LU4 blueprint: we extract the embed.FS to a temp
// dir and call rules.LoadRulesFromDir / LoadOverlaysFromDir unchanged.
// The temp dir is cleaned up by the caller via the returned cleanup function.
//
// Option B (adding LoadRulesFromFS to lumen-scoring) is deferred to a future
// lumen-scoring minor release to avoid a two-repo coordinated change in LU-4.
//
// Returns (ruleStore, overlayStore, cleanupFunc, error).
// The cleanup function MUST be called (typically via defer) after scoring.
func LoadEmbedded() (*lsrules.RuleStore, *lsrules.OverlayStore, func(), error) {
	tmp, err := os.MkdirTemp("", "lumen-rules-*")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("rules: create temp dir: %w", err)
	}
	cleanup := func() { os.RemoveAll(tmp) }

	rulesDir := filepath.Join(tmp, "rules")
	overlaysDir := filepath.Join(tmp, "overlays")
	if err := os.MkdirAll(rulesDir, 0700); err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("rules: mkdir rules: %w", err)
	}
	if err := os.MkdirAll(overlaysDir, 0700); err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("rules: mkdir overlays: %w", err)
	}

	// Extract rules.
	if err := extractFS(RulesFS, "data/rules", rulesDir); err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("rules: extract rules: %w", err)
	}
	// Extract overlays.
	if err := extractFS(OverlaysFS, "data/overlays", overlaysDir); err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("rules: extract overlays: %w", err)
	}

	ruleStore, err := lsrules.LoadRulesFromDir(rulesDir)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("rules: load rules: %w", err)
	}

	overlayStore, err := lsrules.LoadOverlaysFromDir(overlaysDir)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("rules: load overlays: %w", err)
	}

	return ruleStore, overlayStore, cleanup, nil
}

// extractFS copies all files from the given embed.FS sub-path into destDir.
func extractFS(embFS fs.FS, fsDir, destDir string) error {
	return fs.WalkDir(embFS, fsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(embFS, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		dest := filepath.Join(destDir, d.Name())
		return os.WriteFile(dest, data, 0600)
	})
}
