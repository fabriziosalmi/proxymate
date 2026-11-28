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

# --- mitmproxy.app (nested bundle) ---
# mitmdump is PyInstaller-packaged: the binary relies on sibling
# Python.framework in Frameworks/ and Python stdlib in Resources/.
# Copying just the binary produces a broken dlopen at first run.
# We embed the whole mitmproxy.app tree; findMitmdump() uses the
# binary inside it.
echo "==> Bundling mitmproxy.app..."
# Search both Apple Silicon (/opt/homebrew) and Intel (/usr/local) brew
# prefixes. Without the /usr/local pattern, this script aborted on Intel
# Macs even though `brew install --cask mitmproxy` installs the cask in
# the same layout there.
MITMPROXY_APP_SRC=""
for prefix in /opt/homebrew /usr/local; do
    for candidate in "$prefix"/Caskroom/mitmproxy/*/mitmproxy.app; do
        if [[ -d "$candidate" && -x "$candidate/Contents/MacOS/mitmdump" ]]; then
            MITMPROXY_APP_SRC="$candidate"
            break 2
        fi
    done
done

if [[ -z "$MITMPROXY_APP_SRC" ]]; then
    echo "ERROR: mitmproxy.app not found in /opt/homebrew or /usr/local. Install: brew install --cask mitmproxy"
    exit 1
fi
rm -rf "$DEST/mitmproxy.app"
cp -R "$MITMPROXY_APP_SRC" "$DEST/mitmproxy.app"
echo "   Copied: $MITMPROXY_APP_SRC ($(du -sh "$DEST/mitmproxy.app" | cut -f1))"

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

# Point every non-system dependency of the bundled squid and OpenSSL at the
# bundle. Homebrew records both opt/ and versioned Cellar/ paths (libssl
# links libcrypto through Cellar/<version>/), and either path is wrong on a
# user's Mac: it may not exist, and if it does, library validation rejects
# it (different Team ID). Any other non-system dependency is a hard error.
echo "==> Rewriting squid and OpenSSL load paths to the bundle..."
relink() {  # <mach-o file> <new prefix for bundled libs>
    local file="$1" prefix="$2" dep leaf
    while read -r dep; do
        leaf="$(basename "$dep")"
        case "$leaf" in
            libssl.3.dylib|libcrypto.3.dylib)
                install_name_tool -change "$dep" "$prefix/$leaf" "$file" ;;
            *)
                echo "ERROR: $file depends on unbundled $dep"; exit 1 ;;
        esac
    done < <(otool -L "$file" | tail -n +2 | awk '{print $1}' | grep -E '^/(opt/homebrew|usr/local)/' || true)
}
for lib in libssl.3.dylib libcrypto.3.dylib; do
    [[ -f "$DEST/lib/$lib" ]] || { echo "ERROR: $lib was not bundled"; exit 1; }
    install_name_tool -id "@loader_path/$lib" "$DEST/lib/$lib"
done
relink "$DEST/squid" "@executable_path/lib"
relink "$DEST/lib/libssl.3.dylib" "@loader_path"
relink "$DEST/lib/libcrypto.3.dylib" "@loader_path"
if otool -L "$DEST/squid" "$DEST"/lib/*.dylib | grep -E '^[[:space:]]+/(opt/homebrew|usr/local)/'; then
    echo "ERROR: Homebrew load paths remain in the bundled sidecars (above)"
    exit 1
fi
# install_name_tool invalidates the signatures: ad-hoc sign so the binaries
# run for the check below. build-dmg.sh re-signs them with Developer ID.
codesign --force --sign - "$DEST"/lib/*.dylib "$DEST/squid" 2>/dev/null

# --- Verify ---
echo ""
echo "==> Verifying..."
echo "mitmdump runs:"
"$DEST/mitmproxy.app/Contents/MacOS/mitmdump" --version 2>&1 | head -2
echo ""
echo "squid deps:"
otool -L "$DEST/squid" | grep -v "^$DEST" | head -8
echo "squid runs:"
if ! "$DEST/squid" -v 2>&1 | head -1 | grep -q '^Squid Cache'; then
    echo "ERROR: bundled squid does not start:"; "$DEST/squid" -v 2>&1 | head -3
    exit 1
fi
"$DEST/squid" -v 2>&1 | head -1
echo ""

TOTAL=$(du -sh "$DEST" | cut -f1)
echo "==> Done! Total bundle size: $TOTAL"
echo "    Location: $DEST"
echo ""
echo "Next: Add a Run Script build phase in Xcode that calls: \${SRCROOT}/scripts/xcode-copy-binaries.sh"
