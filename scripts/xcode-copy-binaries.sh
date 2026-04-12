#!/bin/bash
# Xcode Run Script Build Phase — copies bundled binaries into the app.
# Add this to: Build Phases → New Run Script Phase (after "Copy Bundle Resources")
#
# Input:  ${SRCROOT}/proxymate/Resources/bin/
# Output: ${BUILT_PRODUCTS_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/bin/

set -euo pipefail

SRC="${SRCROOT}/build/bundle-bin"
DST="${BUILT_PRODUCTS_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/bin"

if [[ ! -d "$SRC" ]]; then
    echo "warning: Bundled binaries not found at $SRC — run scripts/bundle-binaries.sh first"
    exit 0
fi

mkdir -p "$DST/lib"

# Copy binaries
for bin in mitmdump squid; do
    if [[ -f "$SRC/$bin" ]]; then
        cp -f "$SRC/$bin" "$DST/$bin"
        chmod 755 "$DST/$bin"
        echo "Copied $bin to bundle"
    fi
done

# Copy dylibs
for lib in "$SRC"/lib/*.dylib; do
    if [[ -f "$lib" ]]; then
        cp -f "$lib" "$DST/lib/"
        echo "Copied $(basename "$lib") to bundle"
    fi
done

# Copy addon script
ADDON="${SRCROOT}/scripts/mitmproxy/proxymate_addon.py"
ADDON_DST="${BUILT_PRODUCTS_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}/scripts/mitmproxy"
if [[ -f "$ADDON" ]]; then
    mkdir -p "$ADDON_DST"
    cp -f "$ADDON" "$ADDON_DST/"
    echo "Copied proxymate_addon.py to bundle"
fi
