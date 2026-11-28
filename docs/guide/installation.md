# Installation

## Requirements

- macOS 26 (Tahoe) or newer
- Apple Silicon (M1 / M2 / M3 / M4). Intel is not a supported target.
- ~150 MB free disk (bundled mitmproxy sidecar is 88 MB on its own)

## Homebrew (recommended)

Proxymate ships in a personal Homebrew tap. Submission to `homebrew-cask` core will follow once the main repo meets Homebrew's notability threshold (≥75 stars or equivalent).

```bash
brew tap fabriziosalmi/proxymate
brew install --cask proxymate
```

That's it — `proxymate.app` appears in `/Applications` and is available from the menu bar on next launch. `brew upgrade --cask proxymate` handles updates.

## DMG

If you prefer to install manually, grab the notarized DMG from the [latest release](https://github.com/fabriziosalmi/proxymate/releases/latest).

::: tip Integrity check
Verify the SHA-256 before mounting, especially if you downloaded from a mirror. Every release publishes a `Proxymate.dmg.sha256` asset next to the DMG, so compare against that file instead of a hash copied from a web page. Set `VERSION` to the release you downloaded:

```bash
VERSION=0.9.60   # the release tag without the leading "v"
cd ~/Downloads
curl -LO "https://github.com/fabriziosalmi/proxymate/releases/download/v${VERSION}/Proxymate.dmg.sha256"
test "$(shasum -a 256 "Proxymate-${VERSION}.dmg" | cut -d' ' -f1)" = "$(cut -d' ' -f1 Proxymate.dmg.sha256)" \
  && echo "checksum OK" || echo "checksum MISMATCH"
```

The DMG carries a stapled notarization ticket, but the DMG itself is not code-signed, so `spctl` rejects the DMG file. Check the app instead, once the DMG is mounted:

```bash
spctl -a -vv /Volumes/Proxymate/proxymate.app
# /Volumes/Proxymate/proxymate.app: accepted
# source=Notarized Developer ID
```
:::

## Install

1. Mount the DMG (double-click).
2. Drag `proxymate.app` into `Applications`.
3. Eject the DMG, launch the app.

The app is signed with a Developer ID and notarized, so macOS does not show the "unidentified developer" warning.

## Grant admin rights

Proxymate needs to modify your system proxy settings (`networksetup`) and install the CA. The first time you enable the proxy or install the CA:

- A native macOS authorization prompt appears ("Proxymate wants to make changes")
- Enter your user password (or authorize with Touch ID)
- Subsequent system-proxy changes within the same wake window reuse the cached authorization

You can revoke at any time from **System Settings → Privacy & Security → Developer Tools**, though for a menu-bar app this is rarely needed.

## Uninstall

Via Homebrew (recommended — cleans user data via the `zap` stanza):

```bash
brew uninstall --cask --zap proxymate
# Optional: remove this tap
brew untap fabriziosalmi/proxymate
```

Manual cleanup (if you installed from DMG):

```bash
# Quit from menu bar first
rm -rf /Applications/Proxymate.app
rm -rf ~/Library/Application\ Support/Proxymate
rm -rf ~/Library/Caches/com.fabriziosalmi.proxymate
```

In either case, to fully remove the Proxymate Root CA from your login keychain:

```bash
security delete-certificate -c "Proxymate Root CA" ~/Library/Keychains/login.keychain-db
```

The system-proxy settings are cleared automatically when Proxymate quits, so you don't need to reset them manually.
