#!/bin/bash
set -euo pipefail

# bundle-binaries.sh — Copies mitmdump, squid, and their dependencies into the app bundle.
# Run this before archiving or when binaries need updating.
#
# Usage: ./scripts/bundle-binaries.sh [--dest <path>]
#   --dest  Override output directory (default: proxymate/Resources/bin)
#
# The script resolves symlinks, copies real binaries, bundles OpenSSL dylibs
# for squid, and rewrites rpaths so everything is self-contained.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEST="${PROJECT_DIR}/build/bundle-bin"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dest) DEST="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$DEST/lib"

# --- mitmdump ---
echo "==> Bundling mitmdump..."
MITMDUMP_SRC=""
for candidate in \
    "/opt/homebrew/Caskroom/mitmproxy/*/mitmproxy.app/Contents/MacOS/mitmdump" \
    "/opt/homebrew/bin/mitmdump" \
    "/usr/local/bin/mitmdump"; do
    # Expand glob
    for f in $candidate; do
        if [[ -x "$f" || -L "$f" ]]; then
            MITMDUMP_SRC="$(readlink -f "$f" 2>/dev/null || realpath "$f")"
            break 2
        fi
    done
done

if [[ -z "$MITMDUMP_SRC" ]]; then
    echo "ERROR: mitmdump not found. Install: brew install mitmproxy"
    exit 1
fi
cp "$MITMDUMP_SRC" "$DEST/mitmdump"
chmod 755 "$DEST/mitmdump"
echo "   Copied: $MITMDUMP_SRC ($(du -h "$DEST/mitmdump" | cut -f1))"

# --- squid ---
echo "==> Bundling squid..."
SQUID_SRC=""
for candidate in \
    "/opt/homebrew/Cellar/squid/*/sbin/squid" \
    "/opt/homebrew/sbin/squid" \
    "/usr/local/sbin/squid"; do
    for f in $candidate; do
        if [[ -x "$f" || -L "$f" ]]; then
            SQUID_SRC="$(readlink -f "$f" 2>/dev/null || realpath "$f")"
            break 2
        fi
    done
done

if [[ -z "$SQUID_SRC" ]]; then
    echo "ERROR: squid not found. Install: brew install squid"
    exit 1
fi
cp "$SQUID_SRC" "$DEST/squid"
chmod 755 "$DEST/squid"
echo "   Copied: $SQUID_SRC ($(du -h "$DEST/squid" | cut -f1))"

# --- OpenSSL dylibs (required by squid) ---
echo "==> Bundling OpenSSL for squid..."
OPENSSL_LIB="/opt/homebrew/opt/openssl@3/lib"
if [[ ! -d "$OPENSSL_LIB" ]]; then
    OPENSSL_LIB="/usr/local/opt/openssl@3/lib"
fi

for lib in libssl.3.dylib libcrypto.3.dylib; do
    SRC="$OPENSSL_LIB/$lib"
    if [[ -f "$SRC" ]]; then
        cp "$SRC" "$DEST/lib/$lib"
        chmod 644 "$DEST/lib/$lib"
        echo "   Copied: $lib ($(du -h "$DEST/lib/$lib" | cut -f1))"
    else
        echo "WARNING: $lib not found at $OPENSSL_LIB"
    fi
done

# Rewrite squid's dylib rpaths to use @executable_path/lib/
echo "==> Rewriting squid rpaths..."
install_name_tool -change \
    "$OPENSSL_LIB/libssl.3.dylib" \
    "@executable_path/lib/libssl.3.dylib" \
    "$DEST/squid" 2>/dev/null || true
install_name_tool -change \
    "$OPENSSL_LIB/libcrypto.3.dylib" \
    "@executable_path/lib/libcrypto.3.dylib" \
    "$DEST/squid" 2>/dev/null || true
# Also fix the cross-reference inside libssl -> libcrypto
install_name_tool -change \
    "$OPENSSL_LIB/libcrypto.3.dylib" \
    "@loader_path/libcrypto.3.dylib" \
    "$DEST/lib/libssl.3.dylib" 2>/dev/null || true

# --- Verify ---
echo ""
echo "==> Verifying..."
echo "mitmdump deps:"
otool -L "$DEST/mitmdump" | grep -v "^$DEST" | head -5
echo ""
echo "squid deps:"
otool -L "$DEST/squid" | grep -v "^$DEST" | head -8
echo ""

TOTAL=$(du -sh "$DEST" | cut -f1)
echo "==> Done! Total bundle size: $TOTAL"
echo "    Location: $DEST"
echo ""
echo "Next: Add a Run Script build phase in Xcode that calls: \${SRCROOT}/scripts/xcode-copy-binaries.sh"
