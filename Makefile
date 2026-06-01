# Copyright 2026 Qwentrix Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: build test clean sync-content gen-nvd

MICELIUM_CONTENT ?= ../micelium/content/lumen

# build compiles the lumen scanner CLI binary.
build:
	go build -o bin/lumen ./cmd/lumen/...

# test runs all unit tests.
test:
	go test ./...

# clean removes build artifacts.
clean:
	rm -rf bin/

# sync-content re-copies the VULN_* and COMP_* rule YAML and all 10 industry
# overlays from the micelium server repo into the scanner's embedded snapshot.
# Run this before tagging a release to pick up content changes.
#
# The MICELIUM_CONTENT variable must point to the micelium repo's content/lumen
# directory (default: ../micelium/content/lumen).
sync-content:
	@echo "Syncing rules and overlays from $(MICELIUM_CONTENT)…"
	@mkdir -p internal/rules/data/rules internal/rules/data/overlays
	@cp "$(MICELIUM_CONTENT)/rules"/VULN_*.yaml internal/rules/data/rules/
	@cp "$(MICELIUM_CONTENT)/rules"/COMP_*.yaml internal/rules/data/rules/
	@cp "$(MICELIUM_CONTENT)/overlays"/*.yaml internal/rules/data/overlays/
	@RULE_COUNT=$$(ls internal/rules/data/rules/*.yaml | wc -l | tr -d ' '); \
	 OVERLAY_COUNT=$$(ls internal/rules/data/overlays/*.yaml | wc -l | tr -d ' '); \
	 SOURCE_SHA=$$(cd ../micelium && git log -1 --format="%H" -- content/lumen/ 2>/dev/null || echo "unknown"); \
	 SYNCED_AT=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	 printf '{\n  "source_repo": "github.com/Qwentrix/micelium",\n  "source_path": "content/lumen",\n  "source_sha": "%s",\n  "synced_at": "%s",\n  "rule_count": %s,\n  "overlay_count": %s,\n  "note": "VULN_* and COMP_* rules + all 10 industry overlays. Re-sync with '"'"'make sync-content'"'"' before tagging a release.",\n  "detect_scanner_status": "ACTIVE — VULN_*/COMP_* rules carry detect.scanner conditions for host-observable fields (critical/high CVE counts, days_since_last_update, disk_encryption_enabled, firewall_enabled, screen_lock_enabled). See LU4-BUILD-BLUEPRINT.md §9."\n}\n' \
	   "$$SOURCE_SHA" "$$SYNCED_AT" "$$RULE_COUNT" "$$OVERLAY_COUNT" \
	   > internal/rules/data/content-snapshot.meta.json
	@echo "Synced $$RULE_COUNT rules + $$OVERLAY_COUNT overlays."

# gen-nvd regenerates the curated NVD CVE index by fetching from the NVD 2.0 API.
# Requires NVD_API_KEY env var for higher rate limits (5 requests/30s without key).
# This is a MAINTAINER action — the committed cve-index.json.gz is the source of truth.
# NEVER called at scan time (//go:build ignore on gen/main.go).
gen-nvd:
	@echo "Regenerating NVD index (requires network access — maintainer action only)…"
	@echo "WARNING: This modifies internal/nvd/data/cve-index.json.gz"
	NVD_API_KEY="$(NVD_API_KEY)" go run ./internal/nvd/gen/main.go
