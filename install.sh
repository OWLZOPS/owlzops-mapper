#!/bin/sh
set -e
# Enable pipefail where available
(set -o pipefail 2>/dev/null) && set -o pipefail || true

REPO="OWLZOPS/owlzops-mapper"
BIN="owlzops-mapper"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  SUFFIX="x86_64" ;;
    aarch64) SUFFIX="arm64" ;;
    *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

TARBALL="${BIN}-linux-${SUFFIX}.tar.gz"
CHECKSUM="${TARBALL}.sha256"
SIGNATURE="${TARBALL}.asc"
BASE_URL="https://github.com/${REPO}/releases/latest/download"
GPG_KEY_URL="https://raw.githubusercontent.com/${REPO}/main/gpg-public-key.asc"

echo "→ Downloading ${BIN} for ${SUFFIX}..."
curl -sSLO "${BASE_URL}/${TARBALL}"
curl -sSLO "${BASE_URL}/${CHECKSUM}"

# ---- SHA256 verification ----
echo "→ Verifying SHA256..."
EXPECTED=$(cut -d' ' -f1 "${CHECKSUM}")
ACTUAL=$(sha256sum "${TARBALL}" | cut -d' ' -f1)
if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "✗ Checksum mismatch!"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $ACTUAL"
    exit 1
fi
echo "✓ SHA256 checksum OK"

# ---- Optional GPG verification ----
if command -v gpg >/dev/null 2>&1; then
    echo "→ GPG available – verifying signature..."
    curl -sSLO "${BASE_URL}/${SIGNATURE}"
    curl -sSL "$GPG_KEY_URL" | gpg --import >/dev/null 2>&1
    if gpg --verify "${SIGNATURE}" "${TARBALL}" >/dev/null 2>&1; then
        echo "✓ GPG signature verified"
        rm "${SIGNATURE}"
    else
        echo "✗ GPG verification FAILED – the binary may have been tampered with!"
        exit 1
    fi
else
    echo "ℹ GPG not found – skipping signature verification"
    echo "  Install gnupg to enable cryptographic verification"
fi

# Extract
tar xzf "${TARBALL}"
chmod +x "${BIN}"

# Cleanup
rm "${TARBALL}" "${CHECKSUM}"

echo "✓ Installed to ./${BIN}"
echo "  Run: ./${BIN} --help"