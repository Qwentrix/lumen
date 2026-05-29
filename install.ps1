# Lumen installer for Windows (PowerShell)
# Usage: iwr -useb https://lumen.micelium.com/install.ps1 | iex
#        iwr -useb https://lumen.micelium.com/install.ps1 -OutFile install.ps1; .\install.ps1 -Version v0.1.0
#
# The installer:
#   1. Detects Windows/amd64 (only architecture supported on Windows in v1).
#   2. Downloads the matching release archive from GitHub Releases.
#   3. Verifies the SHA-256 checksum against the published checksums.txt.
#   4. Installs the binary to %LOCALAPPDATA%\Programs\Lumen\lumen.exe and
#      adds the directory to the current user's PATH.

[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"

$Repo     = "Qwentrix/lumen"
$Binary   = "lumen.exe"
$Goos     = "windows"
$Goarch   = "amd64"

if ([string]::IsNullOrEmpty($InstallDir)) {
    $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Lumen"
}

# ---------------------------------------------------------------------------
# Resolve version
# ---------------------------------------------------------------------------
if ([string]::IsNullOrEmpty($Version)) {
    Write-Host "Fetching latest release version..."
    $LatestJson = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Version    = $LatestJson.tag_name
    if ([string]::IsNullOrEmpty($Version)) {
        Write-Error "Failed to determine latest release version."
        exit 1
    }
}

Write-Host "Installing Lumen $Version ($Goos/$Goarch)..."

# ---------------------------------------------------------------------------
# Build download URLs
# ---------------------------------------------------------------------------
$Archive      = "lumen_${Version}_${Goos}_${Goarch}.zip"
$BaseUrl      = "https://github.com/$Repo/releases/download/$Version"
$ArchiveUrl   = "$BaseUrl/$Archive"
$ChecksumsUrl = "$BaseUrl/checksums.txt"

# ---------------------------------------------------------------------------
# Download to a temp directory
# ---------------------------------------------------------------------------
$TmpDir = Join-Path $env:TEMP ("lumen_install_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TmpDir | Out-Null

try {
    $ArchivePath   = Join-Path $TmpDir $Archive
    $ChecksumsPath = Join-Path $TmpDir "checksums.txt"

    Write-Host "Downloading $Archive..."
    Invoke-WebRequest -Uri $ArchiveUrl -OutFile $ArchivePath -UseBasicParsing

    Write-Host "Downloading checksums.txt..."
    Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $ChecksumsPath -UseBasicParsing

    # -----------------------------------------------------------------------
    # Verify checksum
    # -----------------------------------------------------------------------
    Write-Host "Verifying checksum..."
    $ExpectedLine = Get-Content $ChecksumsPath | Where-Object { $_ -match [regex]::Escape($Archive) }
    if ($null -eq $ExpectedLine) {
        Write-Error "Checksum entry for $Archive not found in checksums.txt"
        exit 1
    }
    $ExpectedHash = ($ExpectedLine -split '\s+')[0].ToUpper()
    $ActualHash   = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToUpper()
    if ($ExpectedHash -ne $ActualHash) {
        Write-Error "Checksum mismatch for $Archive.`n  Expected: $ExpectedHash`n  Got:      $ActualHash"
        exit 1
    }
    Write-Host "Checksum OK."

    # -----------------------------------------------------------------------
    # Extract
    # -----------------------------------------------------------------------
    Expand-Archive -Path $ArchivePath -DestinationPath $TmpDir -Force

    # -----------------------------------------------------------------------
    # Install
    # -----------------------------------------------------------------------
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir | Out-Null
    }

    $BinarySource = Join-Path $TmpDir $Binary
    $BinaryDest   = Join-Path $InstallDir $Binary
    Copy-Item -Path $BinarySource -Destination $BinaryDest -Force

    # -----------------------------------------------------------------------
    # Add to user PATH if not already present
    # -----------------------------------------------------------------------
    $UserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        $NewPath = "$InstallDir;$UserPath"
        [System.Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
        Write-Host "Added $InstallDir to user PATH."
        Write-Host "Restart your terminal for the PATH change to take effect."
    }

    Write-Host ""
    Write-Host "Lumen $Version installed to $BinaryDest"
    Write-Host ""
    Write-Host "Get started:"
    Write-Host "  lumen consent   # Review and accept the per-domain access manifest"
    Write-Host "  lumen scan      # Run a local security assessment"
    Write-Host "  lumen --help    # Show all commands"
    Write-Host ""
    Write-Host "Learn more: https://lumen.micelium.com"

} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
