# Security Policy

## Supported Versions

We actively apply security fixes to the latest released version of Lumen.
Older versions do not receive backported security patches unless the severity
warrants an exception (CVSS >= 9.0 critical).

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | No — please upgrade |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities by email to:

**security@qwentrix.com**

Include in your report:

- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept code where applicable)
- The version(s) of Lumen affected
- The potential impact and attack scenario

### Response Commitment

| Step | Target time |
|------|-------------|
| Initial acknowledgement | Within 2 business days |
| Severity triage and owner assignment | Within 5 business days |
| Patch / mitigation plan communicated to reporter | Within 14 business days |
| Public disclosure (coordinated with reporter) | 90 days from initial report, or sooner if a patch is available |

We follow responsible disclosure. We will coordinate with you before publishing
any advisory or CVE assignment.

## Scope

### In scope

- The `lumen` binary (all probe modules, scoring engine, report renderer, update mechanism)
- The `install.sh` and `install.ps1` installer scripts
- The `internal/hybrid/` upload path (`--hybrid` flag behaviour)
- The `lumen update` bundle verification mechanism (ed25519 chain of trust)

### Out of scope

- `lumen-api` server-side components (report separately to security@qwentrix.com
  and mark as "lumen-api" in the subject)
- Third-party dependencies — please report those to the relevant upstream project
  first; notify us so we can update our vendored copy

## Disclosure History

No public advisories at this time. Past advisories will be listed here
once the product reaches v1.0.0 GA.
