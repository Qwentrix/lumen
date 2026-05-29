#!/usr/bin/env sh
# Lumen installer for macOS and Linux
# Usage: curl -fsSL https://lumen.micelium.com/install.sh | sh
#        curl -fsSL https://lumen.micelium.com/install.sh | sh -s -- --version v0.1.0
#
# The installer:
#   1. Detects OS and CPU architecture.
#   2. Downloads the matching release archive from GitHub Releases.
#   3. Verifies the SHA-256 checksum against the published checksums.txt.
#   4. Installs the binary to /usr/local/bin/lumen (or ~/.local/bin/lumen if
#      /usr/local/bin is not writable and sudo is unavailable).

set -eu

REPO="Qwentrix/lumen"
INSTALL_DIR="/usr/local/bin"
BINARY="lumen"
VERSION=""

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------------------
OS="$(uname -s)"
case "$OS" in
  Darwin) GOOS="darwin" ;;
  Linux)  GOOS="linux"  ;;
  *)
    echo "Unsupported OS: $OS" >&2
    echo "For Windows, use install.ps1 instead." >&2
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# Detect architecture
# ---------------------------------------------------------------------------
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)          GOARCH="amd64" ;;
  amd64)           GOARCH="amd64" ;;
  arm64 | aarch64) GOARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# Resolve version
# ---------------------------------------------------------------------------
if [ -z "$VERSION" ]; then
  echo "Fetching latest release version..."
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
  if [ -z "$VERSION" ]; then
    echo "Failed to determine latest release version." >&2
    exit 1
  fi
fi

echo "Installing Lumen ${VERSION} (${GOOS}/${GOARCH})..."

# ---------------------------------------------------------------------------
# Build download URLs
# ---------------------------------------------------------------------------
ARCHIVE="lumen_${VERSION}_${GOOS}_${GOARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ARCHIVE_URL="${BASE_URL}/${ARCHIVE}"
CHECKSUMS_URL="${BASE_URL}/checksums.txt"

# ---------------------------------------------------------------------------
# Download to a temp directory
# ---------------------------------------------------------------------------
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading ${ARCHIVE}..."
curl -fsSL -o "${TMP_DIR}/${ARCHIVE}" "${ARCHIVE_URL}"

echo "Downloading checksums.txt..."
curl -fsSL -o "${TMP_DIR}/checksums.txt" "${CHECKSUMS_URL}"

# ---------------------------------------------------------------------------
# Verify checksum
# ---------------------------------------------------------------------------
echo "Verifying checksum..."
cd "$TMP_DIR"
if command -v sha256sum > /dev/null 2>&1; then
  grep "${ARCHIVE}" checksums.txt | sha256sum --check --status
elif command -v shasum > /dev/null 2>&1; then
  grep "${ARCHIVE}" checksums.txt | shasum -a 256 --check --status
else
  echo "Warning: no sha256sum or shasum found; skipping checksum verification." >&2
fi

# ---------------------------------------------------------------------------
# Extract
# ---------------------------------------------------------------------------
tar -xzf "${ARCHIVE}"

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "${BINARY}" "${INSTALL_DIR}/${BINARY}"
elif command -v sudo > /dev/null 2>&1; then
  echo "Installing to ${INSTALL_DIR} (sudo required)..."
  sudo install -m 0755 "${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  FALLBACK="${HOME}/.local/bin"
  mkdir -p "$FALLBACK"
  install -m 0755 "${BINARY}" "${FALLBACK}/${BINARY}"
  INSTALL_DIR="$FALLBACK"
  echo "Installed to ${FALLBACK}. Add it to your PATH if not already:"
  echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo "Lumen ${VERSION} installed to ${INSTALL_DIR}/${BINARY}"
echo ""
echo "Get started:"
echo "  lumen consent   # Review and accept the per-domain access manifest"
echo "  lumen scan      # Run a local security assessment"
echo "  lumen --help    # Show all commands"
echo ""
echo "Learn more: https://lumen.micelium.com"
