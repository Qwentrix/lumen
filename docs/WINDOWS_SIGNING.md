# Windows EV Code-Signing — Checklist (BLOCKED on OQ-3)

**Status:** BLOCKED. OQ-3 (Windows EV code-signing cert procurement) is UNRESOLVED
as of the ENT-108 / LU-5 sprint. Unsigned Windows binaries are shipped; SmartScreen
will warn on clean Windows 11 VMs.

## What needs to happen (OQ-3 resolution steps)

1. **Procure an EV (Extended Validation) Authenticode certificate.**
   Recommended vendors: DigiCert, Sectigo. EV cert is required for SmartScreen
   reputation pass; OV certs alone are insufficient for new publishers.

2. **Export the certificate as a password-protected .pfx file.**

3. **Add CI secrets to the `lumen` GitHub repo:**
   - `WINDOWS_EV_CERT_PFX_BASE64` — base64-encoded .pfx
   - `WINDOWS_SIGN_PASS` — passphrase for the .pfx

4. **Update `.github/workflows/release.yml`** — replace the blocked stub step
   `[Windows] Authenticode sign binary (BLOCKED on OQ-3 — unsigned)` with:

   ```yaml
   - name: "[Windows] Import EV certificate"
     if: matrix.goos == 'windows'
     shell: pwsh
     env:
       PFX_BASE64: ${{ secrets.WINDOWS_EV_CERT_PFX_BASE64 }}
       PFX_PASS:   ${{ secrets.WINDOWS_SIGN_PASS }}
     run: |
       $pfxPath = "$env:RUNNER_TEMP\cert.pfx"
       [System.Convert]::FromBase64String($env:PFX_BASE64) | Set-Content $pfxPath -AsByteStream
       $securePw = ConvertTo-SecureString $env:PFX_PASS -AsPlainText -Force
       Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\CurrentUser\My `
         -Password $securePw | Out-Null
       Remove-Item $pfxPath

   - name: "[Windows] Authenticode sign binary"
     if: matrix.goos == 'windows'
     shell: pwsh
     run: |
       signtool sign /fd sha256 `
         /tr http://timestamp.digicert.com /td sha256 `
         /a `
         lumen\lumen.exe
       signtool verify /pa lumen\lumen.exe
       Write-Host "Authenticode: OK"
   ```

5. **Remove the `//go:build windows` signing TODO** comments from `.goreleaser.yaml`.

6. **Run SmartScreen acceptance test on a clean Windows 11 VM** (the ENT-108
   acceptance criterion "Win11 SmartScreen passes on clean VM"). This test is
   only meaningful after the EV cert is provisioned and the binary is signed.

7. **Update the release notes** to indicate the Windows binary is now signed.

## Why unsigned binaries are safe for early adopters

Until OQ-3 resolves, users can bypass SmartScreen by right-clicking the binary →
Properties → Unblock, or by running `Unblock-File lumen.exe` in PowerShell.
This is documented in the README under "Windows Installation".

## References

- ENT-108 / LU-5 Build Blueprint §6.4
- OQ-3 tracking issue (internal)
- [Microsoft SmartScreen FAQ](https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/)
- [DigiCert EV Code Signing](https://www.digicert.com/signing/code-signing-certificates)
