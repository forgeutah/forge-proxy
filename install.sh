#!/bin/sh
# install.sh — fetch the latest forge-proxy release tarball, verify its
# SHA-256 against checksums.txt, and install the binary to PATH.
#
# Quick install:
#   curl -fsSL https://raw.githubusercontent.com/forgeutah/forge-proxy/main/install.sh | sh
#
# Pin a version:
#   curl -fsSL https://raw.githubusercontent.com/forgeutah/forge-proxy/main/install.sh | FORGE_PROXY_VERSION=v0.1.0 sh
#
# Install to a different directory (e.g. user-local):
#   curl -fsSL https://raw.githubusercontent.com/forgeutah/forge-proxy/main/install.sh | FORGE_PROXY_INSTALL_DIR="$HOME/.local/bin" sh
#
# Env vars:
#   FORGE_PROXY_VERSION       Release tag (e.g. v0.1.0). Default: latest.
#   FORGE_PROXY_INSTALL_DIR   Install target. Default: /usr/local/bin.
#   FORGE_PROXY_SKIP_VERIFY   Set to "1" to skip checksum verification.
#                             Not recommended outside of debugging.

set -eu

REPO="forgeutah/forge-proxy"
INSTALL_DIR="${FORGE_PROXY_INSTALL_DIR:-/usr/local/bin}"
VERSION="${FORGE_PROXY_VERSION:-latest}"
SKIP_VERIFY="${FORGE_PROXY_SKIP_VERIFY:-0}"

# --- OS / arch detection ----------------------------------------------------

case "$(uname -s)" in
    Linux)  OS="linux"  ;;
    Darwin) OS="darwin" ;;
    *) echo "forge-proxy: unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64)         ARCH="amd64" ;;
    aarch64|arm64)        ARCH="arm64" ;;
    *) echo "forge-proxy: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

# --- tooling availability ---------------------------------------------------

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "forge-proxy: $1 is required but not installed" >&2
        exit 1
    fi
}

require curl
require tar

# sha256sum (GNU/coreutils) or shasum (macOS/BSD) — try both.
SHASUM_CMD=""
if [ "$SKIP_VERIFY" != "1" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        SHASUM_CMD="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        SHASUM_CMD="shasum -a 256"
    else
        echo "forge-proxy: neither sha256sum nor shasum found; set FORGE_PROXY_SKIP_VERIFY=1 to bypass" >&2
        exit 1
    fi
fi

# --- resolve version --------------------------------------------------------

if [ "$VERSION" = "latest" ]; then
    echo "forge-proxy: looking up latest release..."
    # The /releases/latest endpoint returns JSON with a tag_name field.
    # sed pulls the value without requiring jq, which isn't universally
    # installed.
    LATEST_JSON="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" || true)"
    if [ -z "$LATEST_JSON" ]; then
        echo "forge-proxy: failed to fetch latest release info from GitHub API" >&2
        exit 1
    fi
    VERSION="$(printf '%s\n' "$LATEST_JSON" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    if [ -z "$VERSION" ]; then
        echo "forge-proxy: could not parse tag_name from API response" >&2
        exit 1
    fi
fi

# Asset name format follows the goreleaser archive template in
# .goreleaser.yaml: forge-proxy_<version-without-v>_<os>_<arch>.tar.gz
VERSION_NUMERIC="${VERSION#v}"
ASSET="forge-proxy_${VERSION_NUMERIC}_${OS}_${ARCH}.tar.gz"
ASSET_URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"
CHECKSUMS_URL="https://github.com/$REPO/releases/download/$VERSION/checksums.txt"

# --- download + verify + install --------------------------------------------

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "forge-proxy: downloading $ASSET ($VERSION)..."
curl -fsSL -o "$TMP/$ASSET" "$ASSET_URL"

if [ "$SKIP_VERIFY" != "1" ]; then
    echo "forge-proxy: downloading checksums.txt..."
    curl -fsSL -o "$TMP/checksums.txt" "$CHECKSUMS_URL"

    echo "forge-proxy: verifying SHA-256..."
    # Extract just the line for our asset so unrelated rows don't cause
    # spurious failures on platforms whose checksum tool is strict.
    EXPECTED="$(grep "  $ASSET\$" "$TMP/checksums.txt" || true)"
    if [ -z "$EXPECTED" ]; then
        echo "forge-proxy: $ASSET not listed in checksums.txt — refusing to install" >&2
        exit 1
    fi
    ( cd "$TMP" && printf '%s\n' "$EXPECTED" | $SHASUM_CMD -c - ) >/dev/null
fi

echo "forge-proxy: extracting..."
( cd "$TMP" && tar -xzf "$ASSET" )

if [ ! -f "$TMP/forge-proxy" ]; then
    echo "forge-proxy: archive did not contain a forge-proxy binary" >&2
    exit 1
fi

# Install. Use sudo only if the target isn't writable by the current user.
echo "forge-proxy: installing to $INSTALL_DIR..."
if [ ! -d "$INSTALL_DIR" ]; then
    echo "forge-proxy: $INSTALL_DIR does not exist; create it or set FORGE_PROXY_INSTALL_DIR" >&2
    exit 1
fi

if [ -w "$INSTALL_DIR" ]; then
    install -m 755 "$TMP/forge-proxy" "$INSTALL_DIR/forge-proxy"
elif command -v sudo >/dev/null 2>&1; then
    sudo install -m 755 "$TMP/forge-proxy" "$INSTALL_DIR/forge-proxy"
else
    echo "forge-proxy: $INSTALL_DIR is not writable and sudo is not available" >&2
    exit 1
fi

# --- post-install ------------------------------------------------------------

INSTALLED_PATH="$INSTALL_DIR/forge-proxy"
echo
echo "✓ installed forge-proxy $VERSION to $INSTALLED_PATH"
echo

# Friendly PATH check — print a hint if the install dir isn't on PATH.
case ":$PATH:" in
    *":$INSTALL_DIR:"*) : ;;  # on PATH; nothing to say
    *)
        echo "note: $INSTALL_DIR is not on your \$PATH. Either add it:"
        echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
        echo "or invoke the binary by full path: $INSTALLED_PATH"
        echo
        ;;
esac

echo "Next steps:"
echo "  1. Copy .env.example to /etc/forge-proxy.env (or \$HOME/.config/forge-proxy.env)"
echo "  2. Fill in SLACK_*, UPSTREAMS, PROXY_SECRET (openssl rand -hex 32), etc."
echo "  3. Run the server:   forge-proxy            # auto-discovers the env file"
echo "  4. Or admin commands: forge-proxy admin list-users"
