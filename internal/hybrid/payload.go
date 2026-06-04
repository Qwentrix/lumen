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

// Package hybrid implements the --hybrid upload path for lumen scan.
//
// Trust model (ENT-109 §7.4): the ed25519 signature proves payload integrity
// and tamper-evidence. It is NOT an identity-authentication mechanism. The
// public key travels in the payload body; the server accepts any
// schema-conforming, validly-signed payload from any install. No install-key
// registration is performed server-side in v1.
//
// Privacy guarantee: the upload payload contains ONLY counts and structured
// booleans from each probe. No file content, no PII values, no file paths, no
// hostnames, no usernames are included. The PrivacyFindings sub-struct is the
// two integer counts only. This is enforced by the payload struct definition and
// verified by TestPayloadNoPIIOrPaths.
//
// M-7 fix: EmbeddedSnapshotSHA carries the source_sha from the scanner's
// embedded content-snapshot.meta.json so the server can detect divergence.
// The SHA is a git commit hash — not sensitive — and is populated entirely
// within BuildPayload from rules.MetaJSON (no cmd changes required).
package hybrid

import (
	"encoding/json"

	lstypes "github.com/Qwentrix/lumen-scoring/pkg/types"

	"github.com/Qwentrix/lumen/internal/rules"
)

// UploadPayload is the JSON body sent to POST /api/v1/lumen/scanner/ingest.
//
// Fields:
//   - ScannerVersion: semver of the lumen binary.
//   - Industry: overlay selection identifier (may be empty).
//   - CompanySize: one of individual | smb | mid | enterprise.
//   - ScannerFindings: structured counts/booleans from all probes.
//     Contains NO file paths, NO PII values, NO hostnames — only integers and booleans.
//   - EmbeddedSnapshotSHA: the source_sha from the scanner's embedded
//     content-snapshot.meta.json (see internal/rules). Populated by BuildPayload.
//     Allows the server to detect content-bundle divergence (M-7). Empty string
//     when the meta file is absent or unparseable — the server treats absence as
//     "unknown" and suppresses the warning.
//   - PublicKey: hex-encoded ed25519 public key from ~/.lumen/install.pub.
//   - Signature: hex-encoded ed25519 signature over the canonical JSON of the body
//     with the "signature" field set to "" (excluded from the signed message).
//
// The canonical-JSON body that is signed is produced by BuildCanonicalBody.
// The server re-serialises the received payload (with Signature zeroed) using
// the same deterministic serialisation and verifies the signature with the
// public key carried in the payload.
type UploadPayload struct {
	ScannerVersion      string                  `json:"scanner_version"`
	Industry            string                  `json:"industry"`
	CompanySize         string                  `json:"company_size"`
	ScannerFindings     lstypes.ScannerFindings `json:"scanner_findings"`
	EmbeddedSnapshotSHA string                  `json:"embedded_snapshot_sha"`
	PublicKey           string                  `json:"public_key"`
	Signature           string                  `json:"signature"`
}

// snapshotMeta is the minimal struct for parsing content-snapshot.meta.json.
// Only source_sha is required; other fields are ignored.
type snapshotMeta struct {
	SourceSHA string `json:"source_sha"`
}

// embeddedSnapshotSHA reads the source_sha from the embedded content-snapshot.meta.json
// (rules.MetaJSON). Returns an empty string if the file is absent or unparseable — this
// is intentional: absence means "unknown" and the server will skip the divergence check.
// The SHA is a git commit hash and is not sensitive (no PII).
func embeddedSnapshotSHA() string {
	var meta snapshotMeta
	if err := json.Unmarshal(rules.MetaJSON, &meta); err != nil {
		return ""
	}
	return meta.SourceSHA
}

// BuildPayload constructs an UploadPayload from scored scan inputs.
// It does NOT sign the payload; call Sign separately.
//
// scannerVersion is the CLI version string (e.g. "v1.0.0").
// industry and companySize are pass-through from the --industry / --company-size flags.
// findings is the ScannerFindings struct populated by the probe results (counts only).
// pubKeyHex is the hex-encoded ed25519 public key from ~/.lumen/install.pub.
//
// EmbeddedSnapshotSHA is populated automatically from the embedded rules.MetaJSON
// source_sha field (M-7 fix). No cmd changes are required.
//
// No file paths, no PII values, no hostnames are included. The privacy sub-struct
// carries only pii_match_count and files_scanned_count — integer counts.
func BuildPayload(
	scannerVersion string,
	industry string,
	companySize string,
	findings lstypes.ScannerFindings,
	pubKeyHex string,
) *UploadPayload {
	return &UploadPayload{
		ScannerVersion:      scannerVersion,
		Industry:            industry,
		CompanySize:         companySize,
		ScannerFindings:     findings,
		EmbeddedSnapshotSHA: embeddedSnapshotSHA(),
		PublicKey:           pubKeyHex,
		Signature:           "", // populated by Sign()
	}
}
