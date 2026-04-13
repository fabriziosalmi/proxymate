# Introduction

Proxymate is a local forward proxy that sits between your Mac and the rest of the internet. Every HTTP, HTTPS, and SOCKS request from any app goes through it. Once there, you decide what happens: inspect, rewrite, block, cache, or simply forward.

## Why another proxy?

The existing options fall into two camps. Browser extensions are narrow — they see only browser traffic, not the native apps or CLIs. Heavyweight enterprise proxies (Squid, mitmproxy GUI) solve everything but demand configuration files, install scripts, and a running daemon. Neither fits "a solo developer or privacy-aware Mac user who wants to see and control what their machine is actually sending."

Proxymate is a **menu-bar app**. You install it, toggle it on, and every app on your Mac starts routing through it. Off by default, explicit by design.

## What makes it different

- **Zero dependencies.** Network.framework and Swift NIO only. No Python runtime at the app layer (the optional MITM sidecar is bundled and signed under one Developer ID).
- **Zero telemetry.** The app makes no outbound call to anyone except your traffic and the list-refresh URLs you opt into.
- **Zero-config defaults.** Install the CA, pick an upstream (direct / Squid / mitmproxy / your VPN), toggle on. The sensible rules are pre-populated.
- **Native feel.** Panels use `NSPanel`, preferences via `UserDefaults`, logging via `OSLog`, trust flow via `security add-trusted-cert`. It behaves like a Mac app, because it is one.

## Where to go next

- **[Installation](/guide/installation.md)** — download, verify SHA256, trust the CA
- **[First run](/guide/first-run.md)** — the 30-second onboarding tour
- **[Features overview](/guide/features.md)** — one-page tour of every capability
- **[Security model](/guide/security.md)** — what Proxymate can (and can't) protect you from
