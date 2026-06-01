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

// Package consent manages the per-domain consent record stored in
// ~/.lumen/consent.json. It records which probe domains the user has accepted,
// along with a hash of the manifest at the time of consent so future probe
// additions can trigger a re-prompt.
package consent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	consentFile = "consent.json"
	fileMode    = 0600
)

// DomainConsent records the user's acceptance for a single probe domain.
type DomainConsent struct {
	Accepted     bool   `json:"accepted"`
	ManifestHash string `json:"manifest_hash"` // sha256 of sorted OSAPIs+FilePaths
}

// Consent is the full consent record persisted to ~/.lumen/consent.json.
type Consent struct {
	Version               int                       `json:"version"`
	AcceptedAt            time.Time                 `json:"accepted_at"`
	ScannerVersion        string                    `json:"scanner_version"`
	InstallKeyFingerprint string                    `json:"install_key_fingerprint"`
	Domains               map[string]*DomainConsent `json:"domains"`
}

// consentPath returns the path to the consent.json file.
func consentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("consent: cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".lumen", consentFile), nil
}

// Load reads and parses the consent file. Returns (nil, nil) if the file does
// not exist — callers should treat that as "no consent recorded yet".
func Load() (*Consent, error) {
	path, err := consentPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("consent: reading %s: %w", path, err)
	}
	var c Consent
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("consent: parsing %s: %w", path, err)
	}
	return &c, nil
}

// Save writes the consent record to ~/.lumen/consent.json with mode 0600.
func Save(c *Consent) error {
	path, err := consentPath()
	if err != nil {
		return err
	}
	// Ensure the directory exists.
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("consent: creating directory: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("consent: marshaling: %w", err)
	}
	if err := os.WriteFile(path, data, fileMode); err != nil {
		return fmt.Errorf("consent: writing %s: %w", path, err)
	}
	return nil
}

// Reset deletes the consent.json file. A subsequent `lumen consent` will
// re-prompt the user for all domains.
func Reset() error {
	path, err := consentPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("consent: removing %s: %w", path, err)
	}
	return nil
}
