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

If you prefer to install manually, grab the signed, notarized DMG from the [latest release](https://github.com/fabriziosalmi/proxymate/releases/latest).

::: tip Integrity check
Verify the SHA-256 before mounting, especially if you downloaded from a mirror:

```bash
shasum -a 256 ~/Downloads/Proxymate-0.9.51.dmg
# expected: db11e2499397453035a88587032df7355a562e60cd3f9220476de7caabc47f6a
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
