# FAQ

## Will this slow down my Mac?

Not measurably. Proxy overhead is benchmarked at **<1ms added latency** on the hot path. For context: any round-trip over Wi-Fi to your local router is typically 2–5 ms; to the nearest public DNS resolver, 8–20 ms. Proxymate adds less than a rounding error.

## Does it break any apps?

Cert-pinned apps (Signal, WhatsApp, banking apps, mitmproxy itself) will fail TLS if you enable MITM blanket. Proxymate ships with a default exclude list and auto-detects pinning failures — after 3 strikes the host is auto-excluded.

For everything else (browsers, CLIs, Electron apps, system services), traffic flows transparently.

## What about Apple services?

`*.apple.com`, `*.icloud.com`, `*.apple-cloudkit.com`, `push.apple.com` are pre-excluded from MITM by default. These use Apple's own pinning and would refuse to connect through a MITM proxy anyway.

## Is my Mac "opened up" by trusting the CA?

Only to Proxymate. The CA private key sits on your disk, encrypted by a passphrase known only to your local Keychain. It cannot sign certificates for anyone else — a remote attacker would need the key file **and** the Keychain passphrase (which itself requires your login).

If you're ever unsure, **remove the CA from Keychain Access and uninstall**. System trust returns to default immediately.

## Do I need Developer Tools enabled?

No. Proxymate is a plain macOS application. You do not need to install Xcode, the Command Line Tools, Homebrew, or Python. Everything required is bundled in the `.app`.

## Can I use it with my corporate VPN?

Yes. Configure the upstream as `http://corporate.proxy:8080` (or whatever your IT gave you). Proxymate listens locally, forwards through the VPN proxy, applies your rules on top. Bypass list covers `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `*.local` by default.

## Does it work with Cloudflare Warp / Tailscale?

Yes — both run as system network extensions, so they sit below Proxymate in the stack. Traffic flows: app → Proxymate → OS routing → Warp/Tailscale → upstream. No special configuration needed.

## What happens on sleep / wake?

- On sleep: the MITM sidecar is stopped to release ports.
- On wake: Proxymate detects if the system proxy drifted during sleep and re-applies it **only if needed** (no spurious password prompts).
- Network interface changes (Wi-Fi ↔ Ethernet, VPN up/down): same idempotent check.

## Does it work offline?

The proxy itself doesn't need internet to start. Blacklist refresh needs internet (obviously); AI tracking API calls pass through regardless. CA generation is local (uses `openssl` bundled on macOS).

## How do I uninstall cleanly?

```bash
rm -rf /Applications/Proxymate.app
rm -rf ~/Library/Application\ Support/Proxymate
rm -rf ~/Library/Caches/com.fabriziosalmi.proxymate
security delete-certificate -c "Proxymate Root CA" ~/Library/Keychains/login.keychain-db
```

System-proxy settings are cleared automatically when you quit Proxymate before uninstalling.

## Can I contribute / review the code?

The repo is currently private, but every release DMG is signed, notarized, and reproducibly built from a tagged commit. A SECURITY.md describes the responsible-disclosure path. Open-source status is on the roadmap for v1.0.

## Why menu-bar only, no Dock icon?

Proxymate is a daemon with a UI. It runs continuously when enabled; having a Dock icon would be clutter. The menu-bar lives with the system-level tools (Bluetooth, Wi-Fi, Input Sources), which is where it belongs conceptually.

Press ⌘-space and type "Proxymate" if you need to bring the main window to focus.
