#!/usr/bin/env bash
# Starling launcher installer — Linux / macOS
# Usage:
#   curl -sSfL https://forgejo.hearthhome.lol/Saltfault/Starling/raw/branch/main/install.sh | bash

set -euo pipefail

BINARY="starling"
REPO="Starling"
VERSION="latest"
UNINSTALL=false
UPGRADE=false
FORGEJO="https://forgejo.hearthhome.lol/Saltfault"
INSTALL_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--version) VERSION="$2"; shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
        --upgrade) UPGRADE=true; shift ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
done

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS" in
    Linux)  OS="unknown-linux-gnu" ;;
    Darwin) OS="apple-darwin" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac
case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac
TARGET="${ARCH}-${OS}"

if $UNINSTALL; then
    rm -f "$INSTALL_DIR/$BINARY"
    echo "Uninstalled $BINARY"
    exit 0
fi

if $UPGRADE; then echo "Upgrading $BINARY to $VERSION..."; fi

if [[ "$VERSION" == "latest" ]]; then
    TAG=$(curl -sSf "$FORGEJO/api/v1/repos/Saltfault/$REPO/releases/latest" | grep -o '"tag_name":"[^"]*"' | cut -d'"' -f4)
else
    TAG="$VERSION"
fi

ASSET="${BINARY}-${TARGET}"
URL="$FORGEJO/$REPO/releases/download/$TAG/$ASSET"
echo "Downloading $ASSET ($TAG)..."
mkdir -p "$INSTALL_DIR"
curl -sSfL "$URL" -o "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

SHA_URL="$FORGEJO/$REPO/releases/download/$TAG/$BINARY-${TARGET}.sha256"
if EXPECTED=$(curl -sSf "$SHA_URL" 2>/dev/null | cut -d' ' -f1); then
    ACTUAL=$(sha256sum "$INSTALL_DIR/$BINARY" | cut -d' ' -f1)
    if [[ "$EXPECTED" != "$ACTUAL" ]]; then
        rm -f "$INSTALL_DIR/$BINARY"
        echo "Checksum mismatch!"
        exit 1
    fi
    echo "Checksum verified"
else
    echo "Skipping checksum verification"
fi

if ! command -v "$BINARY" &>/dev/null; then
    echo "NOTE: $INSTALL_DIR is not on your PATH."
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
fi

echo "Installed $BINARY $TAG to $INSTALL_DIR/$BINARY"
