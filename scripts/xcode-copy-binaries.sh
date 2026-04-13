#!/bin/bash
# Xcode Run Script Build Phase — copies bundled sidecars (mitmdump, squid,
# and their OpenSSL dylibs) into the app.
#
# Populates ${SRCROOT}/build/bundle-bin on first run by invoking
# scripts/bundle-binaries.sh, then copies everything under the target's
# Resources/bin/. If homebrew doesn't have the prerequisites (mitmproxy,
# squid, openssl@3), the build still succeeds — sidecars are optional at
# runtime (MITM and local caching proxy are opt-in features).

set -uo pipefail

SRC="${SRCROOT}/build/bundle-bin"
DST="${BUILT_PRODUCTS_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/bin"
BUNDLE_SCRIPT="${SRCROOT}/scripts/bundle-binaries.sh"

if [[ ! -d "$SRC" || -z "$(ls -A "$SRC" 2>/dev/null)" ]]; then
    if [[ -x "$BUNDLE_SCRIPT" ]]; then
        echo "note: Populating bundle-bin via bundle-binaries.sh (one-time per clean)"
        if ! "$BUNDLE_SCRIPT" --dest "$SRC"; then
            echo "warning: bundle-binaries.sh failed — build continues without sidecars"
            echo "warning: install prerequisites with: brew install mitmproxy squid openssl@3"
            exit 0
        fi
    else
        echo "warning: bundle-binaries.sh not found at $BUNDLE_SCRIPT — skipping sidecar bundling"
        exit 0
    fi
fi

mkdir -p "$DST/lib"

for bin in mitmdump squid; do
    if [[ -f "$SRC/$bin" ]]; then
        cp -f "$SRC/$bin" "$DST/$bin"
        chmod 755 "$DST/$bin"
        echo "Copied $bin to bundle"
    fi
done

for lib in "$SRC"/lib/*.dylib; do
    if [[ -f "$lib" ]]; then
        cp -f "$lib" "$DST/lib/"
        echo "Copied $(basename "$lib") to bundle"
    fi
done

ADDON="${SRCROOT}/scripts/mitmproxy/proxymate_addon.py"
ADDON_DST="${BUILT_PRODUCTS_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/scripts/mitmproxy"
if [[ -f "$ADDON" ]]; then
    mkdir -p "$ADDON_DST"
    cp -f "$ADDON" "$ADDON_DST/"
    echo "Copied proxymate_addon.py to bundle"
fi
