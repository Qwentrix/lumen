# Lumen Scanner Access Manifest

**Version:** v0.1.x (LU-4)
**License:** Apache 2.0
**Source:** github.com/Qwentrix/lumen

This document is the **public transparency artifact** for the Lumen scanner CLI. It declares every OS command, file path, and network endpoint that any probe *may* access during a `lumen scan` run.

The declarations here are the single source of truth that drives:
- The interactive `lumen consent` walkthrough (which shows this information and prompts acceptance per domain)
- The runtime manifest written to `~/.lumen/manifest-{scanID}.json` (which records what was *actually* accessed)
- The `manifest_coverage_test.go` CI gate (which verifies every OS API in probe `Manifest()` returns appears here)

---

## Trust Promises

| Promise | Status |
|---|---|
| **Zero outbound network by default** | GUARANTEED — the scanner makes no network calls during `lumen scan`. No DNS, no HTTP, no telemetry. |
| **Read-only on the host** | GUARANTEED — no probe writes, modifies, or deletes any host file or configuration. |
| **All assets compiled-in** | GUARANTEED — NVD snapshot, rules, CSS, and report assets are `go:embed`-ed. A scan on an air-gapped machine produces a full report. |
| **Consent before access** | REQUIRED — run `lumen consent` before `lumen scan`. The consent walkthrough shows this manifest and writes `~/.lumen/consent.json` recording acceptance per domain. |
| **Runtime access ledger** | AUTOMATIC — every exec and file-read is recorded in `~/.lumen/manifest-{scanID}.json` so you can audit exactly what was touched. |

**Network exceptions (require explicit user action):**
- `lumen scan --hybrid` — uploads a signed findings summary to `lumen-api`. Requires prior consent. Shows a preview before any upload.
- `lumen update` — fetches a signed rule + NVD bundle update from `lumen.micelium.com`. Requires prior consent. (LU-5 feature — not available in v0.1.x.)

---

## Files Written by the Scanner

| Path | Purpose | Created by |
|---|---|---|
| `~/.lumen/install.key` | ed25519 private key (mode 0600). Used to sign `--hybrid` uploads. Generated once on first `lumen consent`. | `lumen consent` |
| `~/.lumen/consent.json` | Per-domain consent record + manifest hashes (mode 0600). | `lumen consent` |
| `~/.lumen/manifest-{scanID}.json` | Runtime access ledger for the scan. Lists every exec and file-read actually performed. | `lumen scan` |
| `~/.lumen/last-scan.json` | Cached scored `ReportPayload` (mode 0600). Consumed by `lumen report` to re-render without re-scanning. | `lumen scan` |
| `~/lumen-report.html` (default) | Self-contained HTML report (mode 0644). Fully offline — no external resources. Override with `--output`. | `lumen scan` / `lumen report` |

---

## Domain: `vulnerabilities`

**Purpose:** Enumerate installed software and match against the embedded CVE index to identify known vulnerabilities.

**Zero network.** The NVD index is embedded in the binary (`internal/nvd/data/cve-index.json.gz`). No network calls are made during matching.

### macOS (`//go:build darwin`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `/usr/sbin/system_profiler` | `SPApplicationsDataType -json` | Enumerate installed applications | Yes (`exec_calls`) |
| `/usr/bin/defaults read` | `/Library/Preferences/com.apple.SoftwareUpdate LastSuccessfulDate` | Days since last OS/software update | Yes (`exec_calls`) |
| `/usr/bin/defaults read` | `/Library/Preferences/com.apple.SoftwareUpdate LastFullSuccessfulDate` | Days since last full update | Yes (`exec_calls`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `/Library/Preferences/com.apple.SoftwareUpdate.plist` | Software update timestamp (read via `defaults`, indirect) | Yes (`file_reads`) |

**Data collected:** installed application names + version strings (no file content, no user data), days since last OS update, count of CVE matches (critical/high).

### Linux (`//go:build linux`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `dpkg-query` | `-W -f '${Package}\t${Version}\n'` | Enumerate Debian/Ubuntu packages | Yes (`exec_calls`) |
| `rpm` | `-qa --qf '%{NAME}\t%{VERSION}\n'` | Enumerate RHEL/CentOS packages | Yes (`exec_calls`) |
| `rpm` | `-qa --last` | Most recent package install timestamp | Yes (`exec_calls`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `/var/lib/apt/periodic/update-success-stamp` | Last apt update timestamp (mtime) | Yes (`file_reads`) |
| `/var/log/apt/history.log` | Last apt install timestamp | Yes (`file_reads`) |

**Fallback:** if neither `dpkg-query` nor `rpm` is present, the probe returns an empty inventory with a metadata note (`inventory_unavailable`). The scan continues.

**Data collected:** package names + version strings, days since last package update, CVE match counts.

### NVD Index (embedded)

| Asset | Description |
|---|---|
| `internal/nvd/data/cve-index.json.gz` | Curated CVE index (critical + high, CVSS ≥ 7.0, last ~24 months). ≤ 5 MB compressed. Common desktop/server software only. |
| `internal/nvd/data/cve-index.meta.json` | Index metadata: `generated_at`, `cve_count`, `source`, `min_cvss`, `window_months`, `sha256`. Surfaced in the report footer. |

**Coverage note:** the embedded index is a demonstrative curated subset, not the full NVD. Run `lumen update` (LU-5) for the complete feed.

---

## Domain: `compliance`

**Purpose:** Check OS-level security controls: full-disk encryption, host firewall, and automatic screen lock.

**Zero network.** All checks use local OS commands and configuration files only.

**MFA not probed:** Multi-factor authentication is an org-wide IdP setting that cannot be determined by inspecting a single workstation. `MFAEnabled` is always `false` from the scanner; it is populated by the questionnaire path (`Q-COMP-MFA-001`) instead. This is recorded in the metadata as `mfa_local_indeterminate`.

### macOS (`//go:build darwin`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `/usr/bin/fdesetup` | `status` | FileVault encryption state | Yes (`exec_calls`) |
| `/usr/libexec/ApplicationFirewall/socketfilterfw` | `--getglobalstate` | Application Firewall state | Yes (`exec_calls`) |
| `/usr/bin/defaults read` | `/Library/Preferences/com.apple.alf globalstate` | Firewall state (alternative method) | Yes (`exec_calls`) |
| `/usr/bin/defaults read` | `com.apple.screensaver askForPassword` | Screen lock password requirement | Yes (`exec_calls`) |
| `/usr/bin/defaults read` | `com.apple.screensaver askForPasswordDelay` | Screen lock password delay | Yes (`exec_calls`) |
| `/usr/bin/defaults -currentHost read` | `com.apple.screensaver idleTime` | Screensaver idle timeout | Yes (`exec_calls`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `/Library/Preferences/com.apple.alf.plist` | Firewall state fallback (read via defaults) | Yes (`file_reads`) |

**Data collected:** boolean encryption/firewall/screen-lock states, screen lock timeout in seconds.

### Linux (`//go:build linux`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `lsblk` | `-o NAME,TYPE --noheadings` | Detect LUKS/dm-crypt encrypted volumes (fallback if `/etc/crypttab` absent) | Yes (`exec_calls`) |
| `firewall-cmd` | `--state` | firewalld state (exec fallback — only run when `/etc/ufw/ufw.conf` is absent) | Yes (`exec_calls`) |
| `gsettings get` | `org.gnome.desktop.screensaver lock-enabled` | GNOME screen lock state | Yes (`exec_calls`) |
| `gsettings get` | `org.gnome.desktop.screensaver lock-delay` | GNOME screen lock delay | Yes (`exec_calls`) |
| `gsettings get` | `org.gnome.desktop.session idle-delay` | GNOME idle timeout | Yes (`exec_calls`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `/etc/crypttab` | LUKS volume table (primary disk-encryption check — file read, no exec) | Yes (`file_reads`) |
| `/etc/ufw/ufw.conf` | UFW configuration (primary firewall check — file read, no exec; `ENABLED=yes` line determines state) | Yes (`file_reads`) |

**Firewall probe strategy (Linux):** reads `/etc/ufw/ufw.conf` first (no exec, no sudo). If the file is absent, falls back to running `firewall-cmd --state` (firewalld). `ufw status` (exec) and `iptables -S` are NOT called by the scanner.

**Fallback:** if a tool is absent (e.g. `gsettings` on a non-GNOME system), the field returns `false`/`0` with a metadata note. The scan continues.

### Windows (LU-5 — NOT invoked in v0.1.x)

The following will be added in LU-5:

- `Get-BitLockerVolume` — BitLocker encryption state
- `Get-NetFirewallProfile` — Windows Defender Firewall state

---

## Domain: `ai_governance` (LU-5 stub)

v0.1.x: this probe runs but returns zero-valued `AIGovernanceFindings`. Real probe logic ships in LU-5.

**Planned access (LU-5):**
- `ps` / `lsof` — detect running LLM/AI assistant processes
- `~/.config/` / application support directories — detect AI app installations

**Network:** ZERO (same constraint applies in LU-5).

---

## Domain: `security_posture` (LU-5 stub)

v0.1.x: this probe runs but returns zero-valued `SecurityPostureFindings`. Real probe logic ships in LU-5.

**Planned access (LU-5):**
- `~/.ssh/` — enumerate SSH private key files (no content read, only metadata)
- `lsof -i` / `ss -tlnp` — enumerate listening ports

**Network:** ZERO.

---

## Domain: `privacy` (LU-5 stub)

v0.1.x: this probe runs but returns zero-valued `PrivacyFindings`. Real probe logic ships in LU-5.

**Planned access (LU-5):**
- `~/Documents/` — regex scan for PII patterns (no content retained)

**Network:** ZERO.

---

## ed25519 Consent Model

| Concept | Detail |
|---|---|
| **Key generation** | `lumen consent` generates a 32-byte ed25519 seed via `crypto/rand`, stores the 64-byte private key at `~/.lumen/install.key` (mode 0600, `O_EXCL` atomic create — never overwrites). |
| **Key fingerprint** | `hex(sha256(publicKey))[:16]` — surfaced in `consent.json` and `--hybrid` upload headers. Not the private key. |
| **What is signed** | The canonical JSON of the `findings` field in a `--hybrid` upload payload. The signature proves the upload came from the consented install. |
| **Re-consent trigger** | The SHA-256 hash of each domain's `Manifest()` (OSAPIs + FilePaths, JSON-canonical) is stored in `consent.json`. If a future scanner version adds a new probe access path, that domain's hash changes and re-consent is required for that domain. |
| **Revocation** | Run `lumen consent --reset` to delete `~/.lumen/consent.json` and re-run the walkthrough. The install key is NOT rotated by reset (existing signed uploads remain verifiable). |

---

## Runtime Per-Scan Manifest

After every `lumen scan`, the runtime access ledger is written to:

```
~/.lumen/manifest-{scanID}.json
```

where `scanID` is a UUID v4 generated from `crypto/rand` (no network). Example:

```json
{
  "scan_id":        "109d8bb4-8f49-4aab-b029-8c0eb962f75d",
  "scanner_version": "v0.1.0",
  "started_at":     "2026-05-31T12:00:00Z",
  "finished_at":    "2026-05-31T12:00:02Z",
  "exec_calls": [
    { "cmd": "/usr/bin/fdesetup",        "args": ["status"] },
    { "cmd": "/usr/sbin/system_profiler", "args": ["SPApplicationsDataType", "-json"] }
  ],
  "file_reads": [
    "/var/lib/apt/periodic/update-success-stamp"
  ],
  "network_calls": []
}
```

The `network_calls` array is always empty in default mode. Its presence in the schema is intentional — a non-empty value is an auditor red flag indicating a probe violated the zero-network constraint.

---

## Zero-Network CI Gates

Two CI mechanisms enforce the zero-network promise:

1. **`TestNoDefaultNetworkCalls`** (`internal/netcheck/netcheck_test.go`): installs a blocking `http.DefaultTransport` interceptor and runs all five probes. Any probe using `net/http` triggers an atomic counter; the test fails if the counter is non-zero.

2. **Linux namespace gate** (`ci.yml`): runs the netcheck test under `unshare --net`, which creates a network namespace with no interfaces. Any raw `net.Dial` / `net.LookupHost` syscall fails with `ENETUNREACH`, causing a probe to error and the test to fail at the `r.err != nil` check.

Together these two layers form a complete zero-network gate covering both HTTP-library and raw-syscall network access.

---

## What the Scanner Does NOT Collect

- File contents of any kind
- Environment variables
- Passwords or credentials
- Browser history or cookies
- Personal documents
- Hostnames or IP addresses
- Any PII (name, email, etc.)

The scanner collects only the boolean/integer/string *control states* listed in the tables above — nothing about user activity, user identity, or document content.

---

## Feedback / Audit

To audit a scan, inspect `~/.lumen/manifest-{scanID}.json`. If you believe the scanner accessed something not listed in this document, please open an issue at github.com/Qwentrix/lumen with the manifest file attached (review it first to ensure no sensitive paths are included).

Security disclosures: see `SECURITY.md`.
