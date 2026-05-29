# Lumen — Open-Source Security Scanner CLI

**Lumen** is the open-source local scanner CLI for [Micelium Lumen](https://lumen.micelium.com), a free security risk-assessment tool. Run it on any workstation to get an honest five-domain risk grade with zero data leaving your machine by default.

[![CI](https://github.com/Qwentrix/lumen/actions/workflows/ci.yml/badge.svg)](https://github.com/Qwentrix/lumen/actions/workflows/ci.yml)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go 1.22+](https://img.shields.io/badge/go-1.22+-00ADD8.svg)](https://go.dev/)

---

## What the scanner does

Lumen probes five security domains locally on the workstation where it runs:

| Domain | What it checks |
|--------|----------------|
| **Vulnerabilities** | Installed package inventory matched against a bundled NVD snapshot |
| **Compliance** | MFA, disk encryption, firewall, patch level, screen lock |
| **AI Governance** | Installed AI apps, browser extensions, MCP server processes, LLM egress sockets |
| **Security Posture** | SSH key strength, password manager presence, browser config, startup items, open ports |
| **Privacy** | PII regex match across `~/Documents` (streaming — content never stored) |

Every probe is **read-only** by contract. Lumen reads OS state; it never writes to your configuration or sends data anywhere by default.

Output: a self-contained HTML report written to `~/lumen-report.html`, with zero external resources.

---

## Seven Trust Promises

Full technical detail: [lumen.micelium.com/trust](https://lumen.micelium.com/trust)

1. **Anonymous Tier 1** — No account or email required to get your risk grade.
2. **Minimum data Tier 2** — If you opt in for the PDF report, only work email + company name are collected.
3. **Scanner zero network** — The CLI makes no outbound network calls in the default scan mode.
4. **Structured-only hybrid** — The `--hybrid` flag uploads structured findings only (never file content, never PII); you see a preview before anything is sent.
5. **Open source** — This repo is Apache 2.0. Read the code, build it yourself, audit it independently.
6. **Compliance by design** — Every finding maps to a named framework control (HIPAA, NIST AI RMF, EU AI Act, OWASP, FedRAMP, ISO 42001).
7. **Explainable scores** — Every grade comes with a per-finding contribution trace so you know exactly why you scored the way you did.

---

## Installation

### macOS and Linux (one-liner)

```sh
curl -fsSL https://lumen.micelium.com/install.sh | sh
```

Or download a specific version:

```sh
curl -fsSL https://lumen.micelium.com/install.sh | sh -s -- --version v0.1.0
```

After install, `lumen` is placed in `/usr/local/bin/lumen`.

### Windows (PowerShell)

```powershell
iwr -useb https://lumen.micelium.com/install.ps1 | iex
```

### Manual download

Download the latest release from [GitHub Releases](https://github.com/Qwentrix/lumen/releases), verify the checksum, and place the binary on your `PATH`:

```sh
# macOS arm64 example
curl -Lo lumen.tar.gz https://github.com/Qwentrix/lumen/releases/latest/download/lumen_darwin_arm64.tar.gz
curl -Lo lumen_checksums.txt https://github.com/Qwentrix/lumen/releases/latest/download/checksums.txt
sha256sum --check --ignore-missing lumen_checksums.txt
tar -xzf lumen.tar.gz
sudo install -m 0755 lumen /usr/local/bin/lumen
```

### Build from source

Requires Go 1.22+.

```sh
git clone https://github.com/Qwentrix/lumen.git
cd lumen
go build -o lumen ./cmd/lumen
```

---

## Quickstart

### 1. Review the consent walkthrough

Before running a scan, review exactly what the scanner will access:

```sh
lumen consent
```

Lumen shows you each domain's manifest — the OS APIs and file paths it will read — and asks for your confirmation per domain. Consent is stored in `~/.lumen/consent.json`. You can revoke any domain at any time.

Example session:

```
Lumen consent walkthrough
=========================

Domain: Vulnerabilities
  Reads: /usr/sbin/system_profiler, /usr/sbin/softwareupdate (macOS)
         dpkg-query / rpm -qa (Linux)
  Network: none
  Accept? [y/N]: y

Domain: AI Governance
  Reads: running process list (passive, no traffic capture)
         Chrome/Firefox/Edge extension manifests in your profile directory
  Network: none
  Accept? [y/N]: y

...

Consent saved to ~/.lumen/consent.json
Run `lumen scan` to start your assessment.
```

### 2. Run a scan

```sh
lumen scan
```

Lumen runs only the domains you consented to, writes `~/lumen-report.html`, and prints a summary to the terminal. No network calls are made.

Scan a single domain:

```sh
lumen scan --domain ai_governance
```

### 3. Hybrid mode (optional)

If you want your scanner findings merged with the web questionnaire result on lumen.micelium.com, use `--hybrid`. Lumen shows you exactly what structured JSON would be sent and requires you to type `yes` before uploading:

```sh
lumen scan --hybrid
```

Only structured findings (finding IDs, probe outputs, scanner version) are sent. No file content, no PII, no hostnames. See the [findings schema](docs/findings-schema.json) for the exact payload shape.

### 4. Keep rules current

```sh
lumen update
```

Downloads a signed rule + NVD bundle from `lumen.micelium.com`. Lumen verifies the ed25519 signature against the public key pinned in the binary before swapping the bundle. If the update server is unreachable, the embedded snapshot is used with a warning if it is older than 30 days.

---

## Supported platforms

| OS | Architecture | Installer |
|----|-------------|-----------|
| macOS | arm64 (Apple Silicon) | `.pkg` (signed, Team ID `T6K5H4JKXF`), `.tar.gz` |
| macOS | amd64 (Intel) | `.pkg` (signed), `.tar.gz` |
| Linux | amd64 | `.deb`, `.rpm`, `.tar.gz` |
| Linux | arm64 | `.deb`, `.rpm`, `.tar.gz` |
| Windows | amd64 | `.msi`, `.exe` |

---

## Commands

| Command | Description |
|---------|-------------|
| `lumen consent` | Interactive per-domain consent walkthrough |
| `lumen scan` | Run a full local scan against consented domains |
| `lumen scan --domain <id>` | Scan one domain only (`vulnerabilities`, `compliance`, `ai_governance`, `security_posture`, `privacy`) |
| `lumen scan --hybrid` | Scan and upload structured findings to lumen.micelium.com after preview |
| `lumen scan --output <path>` | Write the HTML report to a custom path |
| `lumen update` | Download and verify the latest rule + NVD bundle |
| `lumen version` | Print version, build commit, and content bundle SHA |

---

## What data leaves your machine

By default: **nothing**. The only network call the binary ever makes is to `lumen.micelium.com/updates/manifest.json` during `lumen update`.

In `--hybrid` mode, a single signed POST is sent to `lumen-api` containing structured probe outputs. See [docs/findings-schema.json](docs/findings-schema.json) for the exact schema. You must type `yes` to confirm the upload after reviewing the preview.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors must sign the Qwentrix CLA (handled automatically by the CLA bot on your first pull request).

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

---

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
