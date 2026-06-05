# Lumen Finding Rules (Open Source — CC BY 4.0)

This directory contains a curated, vendor-neutral subset of the finding rules
used by [Micelium Lumen](https://lumen.micelium.com) to turn raw security
observations into graded, explainable findings.

## Two licenses in this repository

| What | License |
|---|---|
| The Lumen scanner **source code** (everything outside this directory) | Apache License 2.0 |
| The finding-rule **content** in this `rules/` directory | **CC BY 4.0** |

See [`LICENSE-CC-BY-4.0`](./LICENSE-CC-BY-4.0) and [`NOTICE`](./NOTICE).

## What's here

273 rule files across five domains:

| Prefix | Domain | Count |
|---|---|---|
| `VULN_*` | Vulnerabilities | 70 |
| `COMP_*` | Compliance | 100 |
| `SECPOS_*` | Security posture | 52 |
| `PRIV_*` | Privacy | 45 |
| `CLOUD_*` | Cloud configuration (opt-in probe) | 6 |

The AI-governance (`AIGOV_*`) domain is **not** included in this public release.
The Micelium product-mapping metadata (`micelium_product`) has been stripped from
every published rule — it encodes go-to-market positioning, not methodology.

## Rule shape

Each rule is a YAML file:

```yaml
id: COMP_NO_ENCRYPTION_AT_REST
domain: compliance
severity: critical
default_weight: 0.95
detect:
  questionnaire:
    - Q-COMP-021 == no
  scanner:
    - compliance.disk_encryption_enabled == false
title: "..."
description_short: "..."
frameworks:
  - id: "HIPAA 164.312(a)(2)(iv)"
    text: "..."
industry_overlays: { ... }
remediation_plain: "..."
remediation_technical: "..."
```

A rule fires when **either** a questionnaire answer **or** a scanner finding
matches; it then contributes `default_weight × severity_factor × industry_overlay`
to its domain's loss. See [`../docs/METHODOLOGY.md`](../docs/METHODOLOGY.md) for the
full scoring formula, grade buckets, and citation catalog.

## Regenerating this subset (maintainers)

These files are generated from the private Micelium content by
[`../scripts/gen-oss-rules.sh`](../scripts/gen-oss-rules.sh), which copies all
non-`AIGOV` rules and strips the `micelium_product` block. A CI guard fails the
build if `micelium_product` ever appears in this directory.

## Using these rules

You may share and adapt these rules for any purpose, including commercially,
with attribution (see `NOTICE`). They are designed to be scored by the
open-source [`lumen-scoring`](https://github.com/Qwentrix/lumen-scoring) engine,
but the YAML is self-describing and usable by any tooling.
