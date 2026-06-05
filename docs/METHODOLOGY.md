<!--
Copyright 2026 Qwentrix Inc. — Apache License 2.0 (document)
The finding rules referenced herein are CC BY 4.0 (see ../rules/LICENSE-CC-BY-4.0).
-->

# Lumen Scoring Methodology (v2)

This is the canonical, public description of how Lumen turns observations into an
honest, explainable five-domain risk grade. Nothing here is a black box: the
scoring engine is open source ([`lumen-scoring`](https://github.com/Qwentrix/lumen-scoring)),
the finding rules are open ([`../rules/`](../rules/), CC BY 4.0), and the scanner is
open ([this repository](https://github.com/Qwentrix/lumen), Apache 2.0).

> **Trust promise:** explainable scores. Every point a domain loses is traceable to
> a specific rule, its weight, its severity, and the industry overlay applied.

---

## 1. The five domains

Lumen scores five risk domains:

| Domain | What it covers |
|---|---|
| `vulnerabilities` | Unpatched software, CVE exposure, patch latency |
| `compliance` | Encryption, MFA, firewall, audit logging, framework gaps |
| `ai_governance` | Shadow AI, LLM data egress, agent/MCP governance |
| `security_posture` | SSH key hygiene, exposed services, endpoint hardening |
| `privacy` | PII handling, data mapping, retention, erasure |

Cloud-configuration findings (from the opt-in `--include-cloud` probe — see §6)
are scored **within** `security_posture` and `compliance`; there is no separate
"cloud" scoring domain in this version.

---

## 2. From observation to a finding

Findings come from two interchangeable sources that feed the **same** engine:

1. **Questionnaire** — the 10-minute web assessment (`lumen.micelium.com`), no email
   required for the grade.
2. **Scanner** — the open-source CLI run locally on a representative host
   (zero outbound network by default; see §6).

Each finding **rule** (`../rules/*.yaml`) declares `detect` conditions for both
paths. A rule fires when **either**:

- a `questionnaire` answer matches (e.g. `Q-COMP-021 == no`), **or**
- a `scanner` finding matches (e.g. `compliance.disk_encryption_enabled == false`).

Conditions are evaluated against structured findings; scanner conditions resolve
`<domain>.<field>` by reflection over the scanner's findings (so e.g.
`cloud.public_storage_count > 0` is read directly from the cloud probe output).

---

## 3. Scoring formula

For each domain, the score is computed from the rules that fired:

1. **Each fired rule contributes** a loss:

   ```
   contribution = default_weight × severity_factor × industry_overlay_multiplier
   ```

   - `default_weight` ∈ [0, 1] — the rule's base importance.
   - `severity_factor` — derived from the rule's severity
     (critical / high / medium / low map to descending factors).
   - `industry_overlay_multiplier` — the per-RULE multiplier from the rule's
     `industry_overlays` map (its `weight_multiplier`) for the selected industry;
     1.0 if absent. (The separate per-DOMAIN multiplier weights the overall-score
     mean — see §4.)

2. **Domain loss** = the sum of all fired contributions, **capped at 1.0**:

   ```
   domain_loss = min(1.0, Σ contribution)
   ```

   The cap means once a domain is "maxed out" with serious findings, additional
   findings don't push it negative — the grade floor is honest.

3. **Domain score** (0–100):

   ```
   domain_score = round(100 × (1 − domain_loss))
   ```

4. **Overall score** — a weighted mean of the five domain scores, where each
   domain's weight is its industry overlay multiplier:

   ```
   overall_score = round( Σ(domain_score_i × multiplier_i) / Σ(multiplier_i) )
   ```

   When all multipliers are 1.0 (no industry selected), each domain contributes
   exactly 20%.

### Grade buckets

| Score | Grade |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 45–59 | D |
| 0–44 | F |

---

## 4. Industry overlays

Ten industry overlays adjust scoring to a sector's real regulatory and threat
profile. An overlay supplies a per-domain `domain_weight_multiplier` (and, at the
rule level, per-rule `industry_overlays`). For example, healthcare weights
`compliance` and `privacy` higher; financial weights `compliance` and
`security_posture`; technology weights `ai_governance` and `vulnerabilities`.

The same set of bad answers therefore produces a **different** overall grade for
healthcare vs technology — the overlay multipliers (and per-rule overlays) carry
that differentiation.

---

## 5. Framework citations

Every rule cites the public standards it maps to, for explainability and
interoperability — never as a certification claim. Frameworks referenced across
the rule set include:

- **CIS** Controls v8 and CIS AWS Foundations Benchmark
- **NIST** SP 800-53, SP 800-40, NIST CSF 2.0, NIST AI RMF, NIST Privacy Framework
- **ISO/IEC** 27001:2022, ISO/IEC 42001
- **HIPAA** / HITECH, **PCI DSS** v4, **GDPR**, **CCPA/CPRA**
- **OWASP** (incl. LLM Top 10), **SOC 2**, **FedRAMP**, **EU AI Act**

Citing a control means "this finding relates to this control," not "you are
(non-)compliant with it." Compliance is determined by an audit, not a free
assessment.

---

## 6. Trust guarantees (the load-bearing invariants)

- **Anonymous Tier 1.** The questionnaire grade requires no email. Individual
  answers are ephemeral (Redis, 2h TTL); the only durable assessment artifacts are
  anonymous **aggregate** counters/histograms.
- **Scanner zero-network by default.** A plain `lumen scan` makes **zero** outbound
  network calls and produces a self-contained local HTML report. This is enforced
  by a CI gate (`internal/netcheck`).
- **Opt-in networked paths, always explicit.** Three flags — and only these — make
  network calls, each gated behind explicit consent + a manifest disclosure of
  exactly what is accessed:
  - `--hybrid` — uploads **structured findings only** (no file content, no PII),
    after showing a preview.
  - `--include-privacy` — scans local documents for PII **patterns**, reporting
    only counts (never content/paths).
  - `--include-cloud` — read-only cloud-config checks (AWS first; Azure/GCP
    framework-ready) using your **existing local cloud credentials**. Read-only,
    counts/booleans only, no credential storage. Every cloud API call is disclosed
    in `SCANNER_MANIFEST.md` and the per-scan manifest.
- **Open source.** Scanner code (Apache 2.0), scoring engine (Apache 2.0), and the
  finding rules (CC BY 4.0) are all public and auditable.

See [`../SCANNER_MANIFEST.md`](../SCANNER_MANIFEST.md) for the exact OS commands,
file paths, and (opt-in) network endpoints each probe touches.

---

## 7. NVD / CVE data

The vulnerability domain matches installed software against a curated, embedded
NVD CVE index (CVSS ≥ 7.0, scoped to the products the scanner can resolve). The
index is regenerated on a weekly cadence and distributed via signed deltas; the
scanner warns when its embedded data is more than 30 days old. See
[`../NVD_CADENCE.md`](../NVD_CADENCE.md).

---

## 8. Reproduce it yourself

- Rules: [`../rules/`](../rules/) (CC BY 4.0)
- Scoring engine: [`lumen-scoring`](https://github.com/Qwentrix/lumen-scoring) (Apache 2.0)
- Scanner: [this repo](https://github.com/Qwentrix/lumen) (Apache 2.0)
- Manifest of everything the scanner touches: [`../SCANNER_MANIFEST.md`](../SCANNER_MANIFEST.md)

Given the rules + the engine, any score Lumen produces is reproducible.
