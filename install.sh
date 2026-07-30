#!/usr/bin/env bash
set -euo pipefail
BINARY="starling"; REPO="Starling"; VERSION="latest"; UNINSTALL=false; UPGRADE=false
FORGEJO="https://forgejo.hearthhome.lol/Saltfault"
API="https://forgejo.hearthhome.lol/api/v1/repos/Saltfault"
INSTALL_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
while [[ $# -gt 0 ]]; do case "$1" in
  -v|--version) VERSION="$2"; shift 2 ;; --uninstall) UNINSTALL=true; shift ;;
  --upgrade) UPGRADE=true; shift ;; *) echo "Unknown flag: $1"; exit 1 ;;
esac; done
OS=$(uname -s); ARCH=$(uname -m)
case "$OS" in
  Linux) OS="unknown-linux-gnu" ;;
  Darwin) OS="apple-darwin" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac
case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  armv7l) ARCH="armv7"; TARGET="armv7-${OS}";;
  i686|i386) ARCH="i686";;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac
TARGET="${ARCH}-${OS}"
if [[ "$ARCH" == "armv7" ]]; then TARGET="armv7-unknown-linux-gnueabihf"; fi
if [[ "$ARCH" == "i686" ]]; then TARGET="i686-unknown-linux-gnu"; fi
if $UNINSTALL; then rm -f "$INSTALL_DIR/$BINARY"; echo "Uninstalled $BINARY"; exit 0; fi
if $UPGRADE; then echo "Upgrading $BINARY to $VERSION..."; fi
if [[ "$VERSION" == "latest" ]]; then TAG=$(curl -sSf "$API/$REPO/releases/latest" | grep -o '"tag_name":"[^"]*"' | cut -d'"' -f4); else TAG="$VERSION"; fi
ASSET="${BINARY}-${TARGET}"; URL="$FORGEJO/$REPO/releases/download/$TAG/$ASSET"
echo "Downloading $ASSET ($TAG)..."; mkdir -p "$INSTALL_DIR"
curl -sSfL "$URL" -o "$INSTALL_DIR/$BINARY"; chmod +x "$INSTALL_DIR/$BINARY"
if ! command -v "$BINARY" &>/dev/null; then echo "NOTE: $INSTALL_DIR is not on PATH. export PATH=\"$INSTALL_DIR:\$PATH\""; fi
echo "Installed $BINARY $TAG to $INSTALL_DIR/$BINARY"
