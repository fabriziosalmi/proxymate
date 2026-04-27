#!/bin/bash
set -euo pipefail

#
# build-dmg.sh — Build, archive, notarize, and package Proxymate as a DMG.
#
# Prerequisites:
#   - Xcode with a valid Developer ID Application certificate
#   - App-specific password stored in keychain for notarytool:
#     xcrun notarytool store-credentials "proxymate-notarize" \
#       --apple-id "your@email.com" \
#       --team-id "7FC7ZTYMYU" \
#       --password "app-specific-password"
#
# Usage:
#   ./scripts/build-dmg.sh
#   ./scripts/build-dmg.sh --skip-notarize   # local dev build only
#

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCHEME="proxymate"
BUILD_DIR="${PROJECT_DIR}/build"
ARCHIVE_PATH="${BUILD_DIR}/proxymate.xcarchive"
APP_PATH="${BUILD_DIR}/proxymate.app"
DMG_PATH="${BUILD_DIR}/Proxymate.dmg"
NOTARIZE_PROFILE="proxymate-notarize"

SKIP_NOTARIZE=false
if [[ "${1:-}" == "--skip-notarize" ]]; then
    SKIP_NOTARIZE=true
fi

echo "==> Cleaning build directory..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

echo "==> Archiving ${SCHEME}..."
# Force manual signing across every target (main + SPM package targets
# like swift-nio-ssl_NIOSSL). With CODE_SIGN_STYLE=Automatic in the
# project, passing CODE_SIGN_IDENTITY on the CLI conflicts; switching
# both the style and the identity explicitly resolves it for release.
# swift-nio / swift-nio-ssl bundle targets produce resource bundles
# that need no distribution signature — CODE_SIGN_IDENTITY="-" ad-hoc
# signs them, which satisfies Xcode's archive validation without
# requiring Developer ID on every dependency.
xcodebuild archive \
    -project "${PROJECT_DIR}/proxymate.xcodeproj" \
    -scheme "${SCHEME}" \
    -configuration Release \
    -archivePath "${ARCHIVE_PATH}" \
    -destination 'generic/platform=macOS' \
    CODE_SIGN_STYLE=Manual \
    CODE_SIGN_IDENTITY="Developer ID Application: Fabrizio Salmi (7FC7ZTYMYU)" \
    DEVELOPMENT_TEAM=7FC7ZTYMYU \
    PROVISIONING_PROFILE_SPECIFIER="" \
    OTHER_CODE_SIGN_FLAGS="--timestamp" \
    ENABLE_HARDENED_RUNTIME=YES \
    -allowProvisioningUpdates \
    2>&1 | tail -15

echo "==> Exporting archive..."
# Create export options plist
cat > "${BUILD_DIR}/export-options.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>developer-id</string>
    <key>destination</key>
    <string>export</string>
</dict>
</plist>
PLIST

xcodebuild -exportArchive \
    -archivePath "${ARCHIVE_PATH}" \
    -exportPath "${BUILD_DIR}" \
    -exportOptionsPlist "${BUILD_DIR}/export-options.plist" \
    2>&1 | tail -3

# The exported app
EXPORTED_APP="${BUILD_DIR}/${SCHEME}.app"
if [[ ! -d "${EXPORTED_APP}" ]]; then
    echo "ERROR: Export failed, app not found at ${EXPORTED_APP}"
    exit 1
fi

echo "==> Re-signing nested sidecars with Developer ID..."
# The app ships mitmproxy.app + squid + OpenSSL dylibs from homebrew.
# Homebrew signed them with its own certificate chain, which breaks the
# outer signature (mixed anchors) and fails notarization. Re-sign
# bottom-up with our Developer ID + hardened runtime + the app's
# entitlements so library validation sees a consistent Team ID.
SIGN_ID="Developer ID Application"
SIGN_ENT="${PROJECT_DIR}/proxymate/proxymate.entitlements"
BIN_DIR="${EXPORTED_APP}/Contents/Resources/bin"

if [[ -d "${BIN_DIR}" ]]; then
    # 1. Every bundled dylib
    find "${BIN_DIR}" -type f -name "*.dylib" -print0 | \
        xargs -0 -I{} codesign --force --timestamp --options runtime \
            --sign "${SIGN_ID}" {}

    # 2. Every non-app executable in bin/ (squid)
    for bin in "${BIN_DIR}"/*; do
        [[ -f "$bin" && -x "$bin" && ! "$bin" == *.dylib ]] || continue
        codesign --force --timestamp --options runtime \
            --sign "${SIGN_ID}" "$bin"
    done

    # 3. Nested mitmproxy.app — sign contents bottom-up, then the bundle
    NESTED_APP="${BIN_DIR}/mitmproxy.app"
    if [[ -d "${NESTED_APP}" ]]; then
        find "${NESTED_APP}/Contents" -type f \( -name "*.dylib" -o -name "*.so" \) -print0 | \
            xargs -0 -I{} codesign --force --timestamp --options runtime \
                --sign "${SIGN_ID}" {}
        for exe in "${NESTED_APP}/Contents/MacOS"/*; do
            [[ -f "$exe" && -x "$exe" ]] || continue
            codesign --force --timestamp --options runtime \
                --sign "${SIGN_ID}" --entitlements "${SIGN_ENT}" "$exe"
        done
        # Sign Python framework if present
        PY_FW="${NESTED_APP}/Contents/Frameworks/Python.framework"
        if [[ -d "${PY_FW}" ]]; then
            codesign --force --timestamp --options runtime \
                --sign "${SIGN_ID}" "${PY_FW}/Versions/Current/Python" 2>/dev/null || true
            codesign --force --timestamp --options runtime \
                --sign "${SIGN_ID}" "${PY_FW}"
        fi
        # Sign the nested app bundle itself
        codesign --force --timestamp --options runtime \
            --sign "${SIGN_ID}" --entitlements "${SIGN_ENT}" "${NESTED_APP}"
    fi
fi

# 4. Re-sign the outer app last, so the outer signature covers the new
#    nested signatures.
codesign --force --timestamp --options runtime \
    --sign "${SIGN_ID}" --entitlements "${SIGN_ENT}" "${EXPORTED_APP}"

echo "==> Verifying code signature..."
codesign --verify --verbose=2 --strict "${EXPORTED_APP}"
echo "    Signature OK"

if [[ "${SKIP_NOTARIZE}" == false ]]; then
    echo "==> Creating DMG for notarization..."
    hdiutil create -volname "Proxymate" \
        -srcfolder "${EXPORTED_APP}" \
        -ov -format UDBZ \
        "${DMG_PATH}"

    echo "==> Submitting for notarization..."
    xcrun notarytool submit "${DMG_PATH}" \
        --keychain-profile "${NOTARIZE_PROFILE}" \
        --wait

    echo "==> Stapling notarization ticket..."
    xcrun stapler staple "${DMG_PATH}"

    echo "==> Verifying notarization..."
    spctl --assess --type open --context context:primary-signature "${DMG_PATH}" && echo "    Notarization OK"
else
    echo "==> Creating DMG (skipping notarization)..."
    hdiutil create -volname "Proxymate" \
        -srcfolder "${EXPORTED_APP}" \
        -ov -format UDBZ \
        "${DMG_PATH}"
fi

echo ""
echo "==> Done!"
echo "    DMG: ${DMG_PATH}"
echo "    Size: $(du -h "${DMG_PATH}" | cut -f1)"

# Emit + persist SHA-256 alongside the DMG. Without this, every release
# required a manual `shasum -a 256` then a manual paste into
# docs/release-notes.md — every fill-SHA commit in `git log` is a
# round-trip drift opportunity. The .sha256 sidecar is also what GitHub
# Releases consumers expect.
SHA256="$(shasum -a 256 "${DMG_PATH}" | awk '{print $1}')"
SHA_PATH="${DMG_PATH}.sha256"
printf '%s  %s\n' "${SHA256}" "$(basename "${DMG_PATH}")" > "${SHA_PATH}"
echo "    SHA-256: ${SHA256}"
echo "    Sidecar: ${SHA_PATH}"
echo ""
echo "    Paste into docs/release-notes.md:"
echo "    SHA-256: ${SHA256}"
