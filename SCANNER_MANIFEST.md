# Lumen Scanner Access Manifest

**Version:** v0.1.x (LU-5)
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
- `lumen update` — fetches a signed rule + NVD bundle update (content delta) from `lumen.micelium.com`. Requires prior consent. Available from LU-5 / v0.1.x.
- `lumen scan --include-cloud` — makes read-only API calls to cloud provider endpoints (AWS by default). Requires `--include-cloud` flag AND prior consent to the `cloud` domain via `lumen consent`. See [Cloud Probes section](#domain-cloud-opt-in) below.

**Proxy transparency:** both `lumen scan --hybrid` and `lumen update` use the Go default HTTP transport, which honours the standard `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` environment variables if set. The scanner itself never reads or sets these variables; they are resolved by the OS/runtime at HTTP client creation time. In fully air-gapped environments where proxy env vars are absent, no proxy is used.

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

**CVE count methodology:** CVE counts (critical/high) reflect **version-bounded matches** — CVEs with all-empty version bounds are suppressed when a bounded sibling for the same product also exists in the index. This prevents a known NVD artifact (~46% of raw records have at least one unbounded CPE entry) from over-counting matches once the index is regenerated via `make gen-nvd`. The committed index uses UPPERCASE severity strings (`"CRITICAL"`/`"HIGH"` from the NVD API); the probe normalises to lowercase at read time so no regen is needed for the severity fix.

### macOS (`//go:build darwin`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `/usr/sbin/system_profiler` | `SPApplicationsDataType -json` | Enumerate installed .app bundles | Yes (`exec_calls`) |
| `/usr/bin/sw_vers` | `-productVersion` | Retrieve macOS version → `apple:macos` CPE for OS-level CVEs | Yes (`exec_calls`) |
| `/usr/sbin/pkgutil` | `--pkgs` | List installed package receipts (CLI tools, SDKs, frameworks) | Yes (`exec_calls`) |
| `/usr/sbin/pkgutil` | `--pkg-info <receipt-id>` | Get version of a matched security-relevant receipt | Yes (`exec_calls`) |
| `/opt/homebrew/bin/brew` | `list --versions` | Enumerate Homebrew packages (Apple Silicon — best-effort, tolerate absence) | Yes (`exec_calls`) |
| `/usr/local/bin/brew` | `list --versions` | Enumerate Homebrew packages (Intel — best-effort, tolerate absence) | Yes (`exec_calls`) |
| `/usr/bin/defaults read` | `/Library/Preferences/com.apple.SoftwareUpdate LastSuccessfulDate` | Days since last OS/software update | Yes (`exec_calls`) |
| `/usr/bin/defaults read` | `/Library/Preferences/com.apple.SoftwareUpdate LastFullSuccessfulDate` | Days since last full update | Yes (`exec_calls`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `/Library/Preferences/com.apple.SoftwareUpdate.plist` | Software update timestamp (read via `defaults`, indirect) | Yes (`file_reads`) |

**Data collected:** installed application names + version strings (no file content, no user data), OS version, CLI tool versions (curl/git/openssl/python/node), days since last OS update, count of CVE matches (critical/high).

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

### Windows (`//go:build windows`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `powershell.exe Get-HotFix` | `-NoProfile -NonInteractive -Command (Get-HotFix \| Sort-Object InstalledOn -Descending \| Select-Object -First 1).InstalledOn` | Patch recency fallback when WUA registry key is absent | Yes (`exec_calls`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — DisplayName scan)` | Enumerate installed programs (64-bit view) for CVE matching | Yes (`file_reads`) |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — 32-bit view)` | Enumerate 32-bit installed programs for CVE matching | Yes (`file_reads`) |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — DisplayName scan)` | Enumerate user-scope installed programs for CVE matching | Yes (`file_reads`) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install (Windows registry — LastSuccessTime)` | Days since last Windows Update (patch recency) | Yes (`file_reads`) |

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

### Windows (`//go:build windows`)

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Control\BitLocker\Volume (Windows registry — BitLocker ProtectionStatus)` | BitLocker volume encryption state (ProtectionStatus DWORD per volume GUID) | Yes (`file_reads`) |
| `HKLM\SOFTWARE\Policies\Microsoft\FVE (Windows registry — BitLocker FVE policy fallback)` | BitLocker Group Policy key (fallback when BitLocker\Volume key is absent) | Yes (`file_reads`) |
| `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy (Windows registry — firewall profiles)` | Windows Defender Firewall EnableFirewall DWORD for Domain/Standard/Public profiles | Yes (`file_reads`) |
| `HKCU\Control Panel\Desktop (Windows registry — screen lock)` | ScreenSaveActive, ScreenSaverIsSecure, ScreenSaveTimeOut values | Yes (`file_reads`) |

---

## Domain: `ai_governance`

**Purpose:** Detect shadow AI tooling — installed LLM desktop apps, browser AI extensions, running MCP server processes, and passive LLM egress socket detection.

**Zero network.** All checks use the local process list, socket table, and file system only.

### macOS (`//go:build darwin`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `/bin/ps` | `-axo comm` | Enumerate running process names | Yes (`exec_calls`) |
| `/bin/ps` | `-axo args` | Enumerate running process command lines | Yes (`exec_calls`) |
| `/usr/sbin/lsof` | `-nP -iTCP -sTCP:ESTABLISHED` | Detect established TCP connections to LLM API endpoints (passive — no dial) | Yes (`exec_calls`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `/Applications/ (directory listing only)` | Detect installed AI app bundles | Yes (`file_reads`) |
| `~/Library/Application Support/Google/Chrome/Default/Extensions/ (macOS)` | Chrome AI extensions | Yes (`file_reads`) |
| `~/Library/Application Support/Microsoft Edge/Default/Extensions/ (macOS)` | Edge AI extensions | Yes (`file_reads`) |
| `~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions/ (macOS)` | Brave AI extensions | Yes (`file_reads`) |
| `~/Library/Application Support/Firefox/Profiles/*/extensions.json (macOS)` | Firefox AI extensions | Yes (`file_reads`) |

### Linux (`//go:build linux`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `ss` | `-tnp state established` | Detect established connections to LLM APIs (passive — no dial) | Yes (`exec_calls`) |
| `netstat` | `-tnp (fallback if ss absent)` | Fallback socket enumeration | Yes (`exec_calls`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `/proc/[0-9]*/comm` | Process name enumeration (file read, no exec) | Yes (`file_reads`) |
| `/proc/[0-9]*/cmdline` | Process command line enumeration | Yes (`file_reads`) |
| `~/.config/google-chrome/Default/Extensions/ (Linux)` | Chrome AI extensions (Linux) | Yes (`file_reads`) |
| `~/.config/chromium/Default/Extensions/ (Linux)` | Chromium AI extensions | Yes (`file_reads`) |
| `~/.config/microsoft-edge/Default/Extensions/ (Linux)` | Edge AI extensions (Linux) | Yes (`file_reads`) |
| `~/.config/BraveSoftware/Brave-Browser/Default/Extensions/ (Linux)` | Brave AI extensions (Linux) | Yes (`file_reads`) |
| `~/.mozilla/firefox/*/extensions.json (Linux)` | Firefox AI extensions (Linux) | Yes (`file_reads`) |
| `~/.local/bin/ (Linux — local app installs)` | Detect locally installed AI CLI tools | Yes (`file_reads`) |

### Windows (`//go:build windows`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `CreateToolhelp32Snapshot TH32CS_SNAPPROCESS (Windows kernel32.dll)` | — | Enumerate running processes for shadow AI app and MCP server detection | Yes (`exec_calls`) |
| `Process32First / Process32Next (Windows kernel32.dll — exe name enumeration)` | — | Walk process snapshot entries to extract exe names | Yes (`exec_calls`) |
| `iphlpapi.dll GetExtendedTcpTable (Windows — TCP_TABLE_OWNER_PID_ALL, passive ZERO-network)` | — | Read kernel TCP connection table (ESTABLISHED state) for LLM egress detection; no DNS, no dial | Yes (`file_reads`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — DisplayName scan)` | Detect installed AI desktop apps by display name (shadow AI detection) | Yes (`file_reads`) |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — DisplayName scan)` | Detect user-scope installed AI apps | Yes (`file_reads`) |
| `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\ (Windows — Chrome AI extensions)` | Chrome AI extensions (directory walk + manifest.json name read) | Yes (`file_reads`) |
| `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions\ (Windows — Edge AI extensions)` | Edge AI extensions (directory walk + manifest.json name read) | Yes (`file_reads`) |
| `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Extensions\ (Windows — Brave AI extensions)` | Brave AI extensions (directory walk + manifest.json name read) | Yes (`file_reads`) |
| `%APPDATA%\Mozilla\Firefox\Profiles\*\extensions.json (Windows — Firefox AI extensions)` | Firefox AI extensions (JSON parse) | Yes (`file_reads`) |

**Note — LLM egress on Windows:** `GetExtendedTcpTable` returns raw IPv4 addresses; no reverse-DNS lookup is performed (prohibited by the ZERO-network invariant). IP-range matching against LLM API CIDRs is a future enhancement; the current implementation returns 0 conservatively.

**Data collected:** count of shadow AI apps, browser AI extensions, LLM egress processes, and running MCP servers. No process arguments, file contents, or user data are recorded.

---

## Domain: `security_posture`

**Purpose:** Probe overall security hygiene: SSH key strength, password manager presence, and open listening ports.

**Zero network.** All checks use the local filesystem and process/socket tables only.

### macOS (`//go:build darwin`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `/usr/bin/ssh-keygen` | `-l -f <key>` | Determine SSH key type and bit-length (no key content read) | Yes (`exec_calls`) |
| `/bin/ps` | `-axo comm` | Detect running password manager agent processes | Yes (`exec_calls`) |
| `/usr/sbin/lsof` | `-nP -iTCP -iUDP -sTCP:LISTEN` | Enumerate non-loopback listening TCP/UDP ports | Yes (`exec_calls`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `~/.ssh/ (directory listing + first-64-bytes header sniff per file; no private key content read)` | Enumerate SSH private key files by header type | Yes (`file_reads`) |

### Linux (`//go:build linux`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `/usr/bin/ssh-keygen` | `-l -f <key>` | Determine SSH key type and bit-length | Yes (`exec_calls`) |
| `ss` | `-tlnpu (preferred) / netstat -tlnpu (fallback)` | Enumerate non-loopback listening ports | Yes (`exec_calls`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `~/.ssh/ (directory listing + first-64-bytes header sniff per file; no private key content read)` | Enumerate SSH private key files | Yes (`file_reads`) |
| `/proc/[0-9]*/comm` | Detect running password manager processes (file read, no exec) | Yes (`file_reads`) |

### Windows (`//go:build windows`)

| OS API / Command | Arguments | Purpose | Manifest recorded |
|---|---|---|---|
| `C:\Windows\System32\OpenSSH\ssh-keygen.exe -l -f <key> (Windows built-in OpenSSH)` | `-l -f <key>` | Determine SSH key type and bit-length (no key content read); falls back to Git-bundled ssh-keygen or PATH | Yes (`exec_calls`) |
| `CreateToolhelp32Snapshot TH32CS_SNAPPROCESS (Windows kernel32.dll — password manager process detection)` | — | Enumerate running processes to detect password manager executables | Yes (`exec_calls`) |
| `Process32First / Process32Next (Windows kernel32.dll — exe name enumeration)` | — | Walk process snapshot entries to extract exe names | Yes (`exec_calls`) |
| `iphlpapi.dll GetExtendedTcpTable (Windows — TCP_TABLE_OWNER_PID_ALL, listening ports)` | — | Read kernel TCP table; listening-state rows counted (loopback excluded) | Yes (`file_reads`) |
| `iphlpapi.dll GetExtendedUdpTable (Windows — UDP_TABLE_OWNER_PID, listening ports)` | — | Read kernel UDP table; all non-loopback sockets counted | Yes (`file_reads`) |

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `%USERPROFILE%\.ssh\ (Windows — directory listing + header sniff; no private key content read)` | Enumerate SSH private key files by PEM header; no key content is read or stored | Yes (`file_reads`) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — password manager DisplayName scan)` | Detect installed password managers by display name | Yes (`file_reads`) |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (Windows registry — password manager DisplayName scan)` | Detect user-scope installed password managers | Yes (`file_reads`) |

**Data collected:** SSH key count, weak key count (RSA < 2048 bits, any DSA), password manager detected (boolean), listening port count. No key content, file content, or private data is collected.

---

## Domain: `privacy`

**Purpose:** Opt-in DLP scanner — detect PII patterns (SSN, credit card) in `~/Documents`. **Disabled by default.** Requires `--include-privacy` flag and prior consent for the privacy domain.

**Zero network.** The scanner never transmits file contents.

**Safety guarantees:**
- Only invoked when `--include-privacy` is set and privacy domain is consented to.
- No filename, file path, matched string, or file content is ever recorded — only scalar counters.
- Symlinks are never followed.
- Files larger than 5 MiB are skipped.
- Total files capped at 5,000 per scan.
- Scan bounded to `~/Documents` only.

| File Path | Purpose | Manifest recorded |
|---|---|---|
| `~/Documents/ (streaming read, ≤5000 files, ≤5 MiB/file; no symlinks followed; matched content never stored or transmitted)` | PII pattern scan (SSN, Luhn-validated credit cards) | Yes (`file_reads`) |

**Data collected:** `pii_match_count` (integer), `files_scanned_count` (integer). No matched strings, no file paths, no content.

---

## ed25519 Consent Model

| Concept | Detail |
|---|---|
| **Key generation** | `lumen consent` generates a 32-byte ed25519 seed via `crypto/rand`, stores the 64-byte private key at `~/.lumen/install.key` (mode 0600, `O_EXCL` atomic create — never overwrites). |
| **Key fingerprint** | `hex(sha256(publicKey))[:16]` — surfaced in `consent.json` and `--hybrid` upload headers. Not the private key. |
| **What is signed** | The canonical JSON of the `findings` field in a `--hybrid` upload payload. The signature proves the upload came from the consented install. |
| **Re-consent trigger** | The SHA-256 hash of each domain's `Manifest()` (OSAPIs + FilePaths, JSON-canonical) is stored in `consent.json`. If a future scanner version adds a new probe access path, that domain's hash changes and re-consent is required for that domain. |
| **Revocation** | Run `lumen consent --reset` to delete `~/.lumen/consent.json`, rotate the install key (a new `~/.lumen/install.key` is generated), and re-run the walkthrough. Existing `--hybrid` uploads signed with the old key remain verifiable on the server side (old keys are retained server-side); new uploads use the rotated key. |

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

---

## Domain: `cloud` (opt-in — ENT-118)

**Status:** Opt-in only. Disabled by default. Enable with `lumen scan --include-cloud`.

**NETWORKED.** This domain makes outbound HTTPS calls to cloud provider API endpoints. It is the ONLY domain that does so during a scan (in addition to `--hybrid` and `lumen update`).

**Credential model:** the scanner uses your EXISTING LOCAL cloud credentials — it NEVER asks for credentials, prompts for them, or stores them. Credentials are loaded by the cloud provider's own SDK from their standard locations:
- AWS: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars → `~/.aws/credentials` profile (selected by `AWS_PROFILE`) → IAM instance role / EC2 IMDS
- Azure: Azure CLI token (`az login`) / MSI / DefaultAzureCredential *(v2, not implemented in v1)*
- GCP: `GOOGLE_APPLICATION_CREDENTIALS` / `gcloud auth application-default` ADC *(v2, not implemented in v1)*

**If no credentials are found** for a requested provider, the probe skips that provider gracefully with a printed note (`"skipping — no credentials found in default credential chain"`) and zero findings. No error is returned. The scan continues.

**All cloud API calls are READ-ONLY.** Only Describe/List/Get operations are used. Zero resource mutations.

**Data collected:** counts and booleans ONLY. No account IDs, no resource ARNs, no IP addresses, no PII.

**Consent required:** run `lumen consent` and accept the `cloud` domain before using `--include-cloud`.

### AWS (v1 deliverable)

| API Operation | Purpose | Manifest recorded |
|---|---|---|
| `s3:ListBuckets` | Enumerate S3 buckets | Yes (`network_calls`) |
| `s3:GetBucketPolicyStatus` | Check if bucket policy is public-readable | Yes (`network_calls`) |
| `s3:GetBucketAcl` | Detect buckets made public via a legacy ACL grant (`AllUsers` / `AuthenticatedUsers`) when no public *policy* exists | Yes (`network_calls`) |
| `iam:GetAccountSummary` | Read `AccountMFAEnabled` flag (root account MFA) | Yes (`network_calls`) |
| `iam:GetAccountPasswordPolicy` | Check IAM password policy strength (length + upper/lower/number/symbol per CIS AWS 1.9–1.12) | Yes (`network_calls`) |
| `ec2:DescribeSecurityGroups` | Enumerate security groups for 0.0.0.0/0 or ::/0 ingress rules (paginated) | Yes (`network_calls`) |
| `ec2:DescribeVolumes` | Count unencrypted EBS volumes (filter: `encrypted=false`, paginated) | Yes (`network_calls`) |
| `rds:DescribeDBInstances` | Count unencrypted RDS instances (all instances fetched + paginated; counted client-side where `StorageEncrypted=false`) | Yes (`network_calls`) |
| `cloudtrail:DescribeTrails` | Check if CloudTrail trails exist (includes Organizations shadow trails) | Yes (`network_calls`) |
| `cloudtrail:GetTrailStatus` | Check if a trail is actively logging | Yes (`network_calls`) |

**Region scope (v1 limitation):** S3, IAM, and the CloudTrail `DescribeTrails`/`GetTrailStatus` checks are global or org-aware, but the **EC2 (security groups, EBS volumes) and RDS (DB instances) checks cover ONLY the default configured region** — the region resolved from the AWS credential/region chain (`AWS_REGION` / `AWS_DEFAULT_REGION` / profile `region` / IMDS). Resources in other regions are **not** enumerated in v1. Multi-region enumeration (iterating `ec2:DescribeRegions`) is a deliberate **v2** item, deferred because it multiplies API latency and cost by the number of active regions. Treat `unencrypted_volumes_count` and `public_ingress_count` as a default-region floor, not an account-wide total.

**Network endpoints:**
- `https://*.amazonaws.com` — regional AWS API endpoints (all operations listed above)
- `http://169.254.169.254` — EC2 Instance Metadata Service (IAM role credential retrieval; credential-chain fallback, only contacted when the scanner runs on an EC2 instance with an attached IAM role)

### Azure (v2 — not implemented in v1)

Azure cloud-config probes are deferred to the paid CSPM-tier cloud pack. No Azure SDK is included in v1. No Azure API calls are made in v1 — the collector returns a `not_implemented` metadata note and zero findings.

**Planned v2 coverage:** Azure Security Center, Storage account public access, Defender for Cloud, Activity Log audit logging.

### GCP (v2 — not implemented in v1)

GCP cloud-config probes are deferred to the paid CSPM-tier cloud pack. No GCP SDK is included in v1. No GCP API calls are made in v1 — the collector returns a `not_implemented` metadata note and zero findings.

**Planned v2 coverage:** Cloud Storage public access, VPC firewall rules, Cloud KMS encryption, Cloud Audit Logs, IAM policy analysis.

### Cloud Findings (scoring contract — Option B, ENT-118)

Cloud findings map into the **existing** `security_posture` and `compliance` scoring domains — no new sixth domain is added. The `CloudFindings` sub-struct in `ScannerFindings` carries these fields:

| Field | Type | Scoring domain | Maps to |
|---|---|---|---|
| `public_storage_count` | int | `security_posture` | Public-readable S3 buckets |
| `public_ingress_count` | int | `security_posture` | Security groups open to 0.0.0.0/0 |
| `unencrypted_volumes_count` | int | `compliance` | Unencrypted EBS + RDS volumes |
| `root_mfa_enabled` | bool | `compliance` | Root account MFA |
| `iam_password_policy_weak` | bool | `compliance` | Weak / absent IAM password policy |
| `audit_logging_enabled` | bool | `compliance` | CloudTrail active |
| `providers_scanned` | []string | — | Metadata only (e.g. `["aws"]`) |

Rules reference these fields via the `cloud.<field>` condition prefix (e.g. `cloud.public_storage_count > 0`). The reflection-based condition resolver in lumen-scoring automatically handles the `cloud` sub-struct prefix.

### Zero-network guarantee

The cloud probe is **not** in the default probe registry (`probes` slice in `scan.go`) and is **not** in the netcheck test's `runs` slice. It is reached only inside a guarded `if includeCloud { ... }` block, exactly mirroring the `--hybrid` networked path. `TestNoDefaultNetworkCalls`, `TestCloudProbeNotInDefaultRegistry`, and `TestDefaultScanZeroNetworkWithCloudImported` all verify this invariant.

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
