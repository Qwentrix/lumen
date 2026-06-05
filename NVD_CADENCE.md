# NVD Snapshot Freshness Policy (OQ-10)

How Lumen keeps its embedded CVE data current.

## Policy

- **Cadence:** the curated NVD CVE index is regenerated **weekly** (Mondays,
  06:00 UTC) by the [`nvd-weekly.yml`](.github/workflows/nvd-weekly.yml) CI
  workflow, which runs `make gen-nvd` against the NVD 2.0 API.
- **Scope:** CVSS ≥ 7.0 (HIGH + CRITICAL), curated to the products the scanner can
  resolve (`internal/nvd/cpe_map.go` → `CuratedProducts`).
- **Distribution:** the regenerated index is packaged into a signed delta bundle
  and published to `github.com/Qwentrix/lumen-bundles` releases. The scanner's
  `lumen update` command downloads the delta, verifies its SHA-256 + ed25519
  signature against the key pinned in the binary, and atomically swaps
  `~/.lumen/content/`.
- **Staleness warning:** the scanner warns the user when its embedded content is
  **more than 30 days old** (`internal/update` `StalenessDays = 30`), so a stalled
  pipeline is visible to users even without `lumen update`.

## Layers

| Layer | Mechanism | Status |
|---|---|---|
| Generate | `make gen-nvd` (NVD 2.0 API, 120-day chunked, retry) | ✅ built |
| Schedule | `nvd-weekly.yml` cron | ✅ written |
| Sign | ed25519 over the bundle SHA-256 | ⚠️ needs `LUMEN_BUNDLE_SIGNING_KEY` |
| Publish | `lumen-bundles` GitHub Releases | ⚠️ needs the `lumen-bundles` repo |
| Consume | `lumen update` verify → atomic swap | ✅ built (ENT-108) |
| Staleness | >30-day embedded-content warning | ✅ built (ENT-108) |

## Provisioning required to go live

The weekly workflow's **publish** job is gated off (`vars.LUMEN_BUNDLES_ENABLED`)
until:

1. **`github.com/Qwentrix/lumen-bundles`** repo is created (the delta release host).
2. **`LUMEN_BUNDLE_SIGNING_KEY`** secret (ed25519 private key) is added, and its
   public half replaces the placeholder pinned in `internal/update/pubkey.go`
   (which requires a new scanner binary release).
3. **`NVD_API_KEY`** secret is added (the regen also works keyless but is slower /
   rate-limited).

Until then the workflow regenerates + smoke-signs as a weekly health check but
does not publish; users stay on the embedded index baked into their binary, with
the 30-day staleness warning as the safety net.
