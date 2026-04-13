# Installation

## Requirements

- macOS 15 (Sequoia) or newer — tested on 26 (Tahoe)
- Apple Silicon (M1 / M2 / M3 / M4). Intel is not a supported target.
- ~150 MB free disk (bundled mitmproxy sidecar is 88 MB on its own)

## Download

Grab the signed, notarized DMG from the [latest release](https://github.com/fabriziosalmi/proxymate/releases/latest).

::: tip Integrity check
Verify the SHA-256 before mounting, especially if you downloaded from a mirror:

```bash
shasum -a 256 ~/Downloads/Proxymate-0.9.48.dmg
# expected: b56ecfbc53d0a2132d60f563232ab597c931616db0b1089318620d5c9834cae9
```

The DMG is notarized and the ticket is stapled — `spctl` will accept it offline.
:::

## Install

1. Mount the DMG (double-click).
2. Drag `Proxymate.app` into `Applications`.
3. Eject the DMG, launch the app.

On first launch macOS will silently load it — there is no "app from an unidentified developer" prompt because the notarization ticket is validated against Apple's chain of trust.

## Grant admin rights

Proxymate needs to modify your system proxy settings (`networksetup`) and install the CA. The first time you enable the proxy or install the CA:

- A native macOS authorization prompt appears ("Proxymate wants to make changes")
- Enter your user password (or authorize with Touch ID)
- Subsequent system-proxy changes within the same wake window reuse the cached authorization

You can revoke at any time from **System Settings → Privacy & Security → Developer Tools**, though for a menu-bar app this is rarely needed.

## Uninstall

```bash
# Quit from menu bar first
rm -rf /Applications/Proxymate.app
rm -rf ~/Library/Application\ Support/Proxymate
rm -rf ~/Library/Caches/com.fabriziosalmi.proxymate
# Remove CA from keychain
security delete-certificate -c "Proxymate Root CA" ~/Library/Keychains/login.keychain-db
```

The system-proxy settings are cleared automatically when Proxymate quits, so you don't need to reset them manually.
