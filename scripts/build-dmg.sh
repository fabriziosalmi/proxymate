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
xcodebuild archive \
    -project "${PROJECT_DIR}/proxymate.xcodeproj" \
    -scheme "${SCHEME}" \
    -configuration Release \
    -archivePath "${ARCHIVE_PATH}" \
    -destination 'generic/platform=macOS' \
    CODE_SIGN_IDENTITY="Developer ID Application" \
    OTHER_CODE_SIGN_FLAGS="--timestamp" \
    ENABLE_HARDENED_RUNTIME=YES \
    2>&1 | tail -5

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

echo "==> Verifying code signature..."
codesign --verify --deep --strict "${EXPORTED_APP}"
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
