#!/bin/sh
set -e
# Enable pipefail where available
(set -o pipefail 2>/dev/null) && set -o pipefail || true

REPO="OWLZOPS/owlzops-mapper"
BIN="owlzops-mapper"

# Detect operating system and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64)  SUFFIX="linux-x86_64" ;;
            aarch64) SUFFIX="linux-arm64" ;;
            *)       echo "Unsupported Linux architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    Darwin)
        SUFFIX="macos-arm64"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

TARBALL="${BIN}-${SUFFIX}.tar.gz"
CHECKSUM="${TARBALL}.sha256"
SIGNATURE="${TARBALL}.asc"
BASE_URL="https://github.com/${REPO}/releases/latest/download"
GPG_KEY_URL="https://raw.githubusercontent.com/${REPO}/main/gpg-public-key.asc"

echo "→ Downloading ${BIN} for ${OS} (${SUFFIX})..."
curl -sSLO "${BASE_URL}/${TARBALL}"
curl -sSLO "${BASE_URL}/${CHECKSUM}"

# ---- SHA256 verification ----
echo "→ Verifying SHA256..."
EXPECTED=$(cut -d' ' -f1 "${CHECKSUM}")

# macOS uses 'shasum -a 256' instead of 'sha256sum'
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "${TARBALL}" | cut -d' ' -f1)
else
    ACTUAL=$(shasum -a 256 "${TARBALL}" | cut -d' ' -f1)
fi

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

    # Download signature and public key
    curl -sSLO "${BASE_URL}/${SIGNATURE}"
    curl -sSL "$GPG_KEY_URL" | gpg --import >/dev/null 2>&1

    # Verify fingerprint of the imported key
    EXPECTED_FPR="63C349F81ACBB9929EF8E73EB47BCE304E7C265E"
    ACTUAL_FPR=$(gpg --list-keys --with-colons "$EXPECTED_FPR" 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
    if [ "$ACTUAL_FPR" != "$EXPECTED_FPR" ]; then
        echo "✗ Downloaded key fingerprint mismatch — aborting"
        exit 1
    fi

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

# macOS post-install hint
if [ "$OS" = "Darwin" ]; then
    cat <<EOF

========================================
  macOS orchestrator installed.

  This binary is remote-only – it can scan
  other Linux servers, but local audit is
  NOT supported on macOS.

  To scan remote hosts, download the Linux
  agent binary and pass it with --local-binary:

  curl -sSL https://github.com/OWLZOPS/owlzops-mapper/releases/latest/download/owlzops-mapper-linux-x86_64.tar.gz | tar xz
  ./owlzops-mapper audit --host <host> --copy-binary --local-binary ./owlzops-mapper-linux-x86_64

========================================
EOF
fi

echo "✓ Installed to ./${BIN}"
echo "  Run: ./${BIN} --help"