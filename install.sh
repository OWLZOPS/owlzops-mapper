#!/bin/sh
set -e

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
BASE_URL="https://github.com/${REPO}/releases/latest/download"

echo "→ Downloading ${BIN} for ${SUFFIX}..."
curl -sSLO "${BASE_URL}/${TARBALL}"
curl -sSLO "${BASE_URL}/${CHECKSUM}"

# Verify checksum
echo "→ Verifying SHA256..."
EXPECTED=$(cut -d' ' -f1 "${CHECKSUM}")
ACTUAL=$(sha256sum "${TARBALL}" | cut -d' ' -f1)
if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "✗ Checksum mismatch!"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $ACTUAL"
    exit 1
fi

# Extract
tar xzf "${TARBALL}"
chmod +x "${BIN}"

# Cleanup
rm "${TARBALL}" "${CHECKSUM}"

echo "✓ Installed to ./${BIN}"
echo "  Run: ./${BIN} --help"