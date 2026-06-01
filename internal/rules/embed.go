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

// Package rules provides the embedded YAML content snapshot (rules + overlays)
// used for offline scoring. The snapshot is extracted to a temporary directory
// at runtime and loaded via the lumen-scoring public loaders.
//
// Content sync: run 'make sync-content' (or the equivalent go generate target)
// to re-copy from the micelium repo before tagging a release.
//
// Note: The current snapshot uses detect.questionnaire conditions only. The
// detect.scanner conditions that map scanner probe outputs to rule triggers
// are a pending micelium-repo PR (see content-snapshot.meta.json).
package rules

import "embed"

// RulesFS holds the embedded VULN_* and COMP_* rule YAML files.
//
//go:embed data/rules/*.yaml
var RulesFS embed.FS

// OverlaysFS holds the embedded industry overlay YAML files.
//
//go:embed data/overlays/*.yaml
var OverlaysFS embed.FS

// MetaJSON is the content-snapshot.meta.json describing when and from which
// git SHA the rule/overlay YAML was synced.
//
//go:embed data/content-snapshot.meta.json
var MetaJSON []byte
