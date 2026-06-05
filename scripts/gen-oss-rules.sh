#!/usr/bin/env bash
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
#
# gen-oss-rules.sh — Generate the public CC-BY-4.0 OSS rules subset.
#
# PURPOSE
#   Copies a curated, vendor-neutral subset of finding rules from the private
#   micelium monorepo (content/lumen/rules/) into this repo's public rules/
#   directory, stripping the proprietary `micelium_product:` block that
#   encodes Micelium-specific go-to-market positioning.
#
# INCLUSION POLICY (ENT-117 / LU9-BUILD-BLUEPRINT.md §5A)
#   INCLUDE: VULN_*, COMP_*, SECPOS_*, PRIV_*, CLOUD_* rules (all non-AIGOV).
#             These are host-observable, framework-cited findings grounded in
#             public standards (CIS, NIST, HIPAA, PCI, OWASP, GDPR, EU AI Act).
#   EXCLUDE: AIGOV_* rules — the AI governance domain rules encode
#             Sigil-specific and Micelium-specific agent-governance positioning
#             and are kept proprietary until Legal/PM sign off on a public subset.
#
# STRIP: The `micelium_product:` YAML block (and all indented lines beneath it)
#         is removed from every published rule. This block maps findings to
#         Micelium products — proprietary competitive IP, not part of the
#         open methodology.
#
# USAGE
#   ./scripts/gen-oss-rules.sh [SOURCE_DIR]
#
#   SOURCE_DIR defaults to ../micelium/content/lumen/rules
#   (i.e., the adjacent micelium monorepo checkout).
#
# The script is idempotent: running it twice produces the same output.
# Run it from the lumen repo root:
#   make publish-oss-rules
#
# OUTPUT
#   rules/*.yaml  — stripped copies of every included source rule
#
# NOTE: This script does NOT modify rules/LICENSE-CC-BY-4.0, rules/NOTICE,
#       or rules/README.md. Those are static and are committed alongside the
#       generated rules.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SOURCE_DIR="${1:-${REPO_ROOT}/../micelium/content/lumen/rules}"
DEST_DIR="${REPO_ROOT}/rules"

if [[ ! -d "${SOURCE_DIR}" ]]; then
  echo "ERROR: Source rules directory not found: ${SOURCE_DIR}" >&2
  echo "       Set SOURCE_DIR as the first argument or ensure the micelium" >&2
  echo "       monorepo is checked out at ../micelium relative to this repo." >&2
  exit 1
fi

echo "Source: ${SOURCE_DIR}"
echo "Destination: ${DEST_DIR}"
echo ""

# Create the destination directory, preserving license/notice/readme files.
mkdir -p "${DEST_DIR}"

# -------------------------------------------------------------------------
# Strip the micelium_product block from a rule YAML file.
#
# The micelium_product block looks like:
#   micelium_product:
#     - product: Sense
#       role: ...
#     - product: Sypher
#       role: ...
#
# We use Python (available on all CI runners) so the YAML structure is
# preserved correctly without a regex that could corrupt multi-line values.
# -------------------------------------------------------------------------
strip_micelium_product() {
  local src="$1"
  local dst="$2"

  python3 - "${src}" "${dst}" <<'PYEOF'
import sys
import re

src, dst = sys.argv[1], sys.argv[2]

with open(src, 'r', encoding='utf-8') as f:
    lines = f.readlines()

out = []
skip = False
for line in lines:
    # Detect start of micelium_product block (top-level key, zero indent)
    if re.match(r'^micelium_product\s*:', line):
        skip = True
        continue
    # End of block: next top-level key (zero indent, not a list item, not blank)
    if skip:
        if re.match(r'^[a-zA-Z_]', line):
            skip = False
        else:
            # Still inside the block (indented lines / list items)
            continue
    out.append(line)

# Remove trailing blank lines, keep one final newline
content = ''.join(out).rstrip('\n') + '\n'
with open(dst, 'w', encoding='utf-8') as f:
    f.write(content)
PYEOF
}

# -------------------------------------------------------------------------
# Process each included rule.
# -------------------------------------------------------------------------
INCLUDED=0
EXCLUDED_AIGOV=0
TOTAL=0

for src in "${SOURCE_DIR}"/*.yaml; do
  [[ -f "${src}" ]] || continue
  TOTAL=$((TOTAL + 1))
  basename_file="$(basename "${src}")"

  # EXCLUDE: AIGOV_* rules (AI governance domain — positioning-sensitive)
  if [[ "${basename_file}" == AIGOV_* ]]; then
    EXCLUDED_AIGOV=$((EXCLUDED_AIGOV + 1))
    continue
  fi

  # INCLUDE: VULN_*, COMP_*, SECPOS_*, PRIV_*, CLOUD_* rules (all non-AIGOV)
  dst="${DEST_DIR}/${basename_file}"
  strip_micelium_product "${src}" "${dst}"
  INCLUDED=$((INCLUDED + 1))
done

echo "Results:"
echo "  Total source rules:    ${TOTAL}"
echo "  Included (published):  ${INCLUDED}"
echo "  Excluded (AIGOV_*):    ${EXCLUDED_AIGOV}"
echo ""

# -------------------------------------------------------------------------
# Post-generation guard: fail if any micelium_product leaked through.
# -------------------------------------------------------------------------
echo "Verifying no micelium_product in published rules..."
LEAKED=()
for f in "${DEST_DIR}"/*.yaml; do
  [[ -f "${f}" ]] || continue
  if grep -qE '^micelium_product[[:space:]]*:' "${f}"; then
    LEAKED+=("$(basename "${f}")")
  fi
done

if [[ "${#LEAKED[@]}" -gt 0 ]]; then
  echo "ERROR: micelium_product field leaked into the following published rules:" >&2
  printf '  %s\n' "${LEAKED[@]}" >&2
  echo "" >&2
  echo "This is a strip failure. Review the gen-oss-rules.sh stripping logic." >&2
  exit 1
fi

echo "Clean: no micelium_product in ${INCLUDED} published rules."
echo ""
echo "OSS rules subset generated successfully: ${DEST_DIR}/"
