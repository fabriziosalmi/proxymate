# ADR 0001: Distribution strategy

## Status

Accepted, 2026-11-24. Resolves #1.

## Context

Proxymate cannot be submitted to the Mac App Store as it is built today:

- `proxymate/proxymate.entitlements` uses `com.apple.security.cs.allow-unsigned-executable-memory` and `com.apple.security.cs.disable-library-validation`, which the bundled CPython runtime and sidecars need.
- There is no `com.apple.security.app-sandbox` entitlement.
- TLS interception runs through a bundled `mitmproxy` sidecar, and the root CA is installed through an elevated prompt.
- The system proxy is switched through `networksetup`.

Issue #1 laid out three paths:

- **A**: DMG and Homebrew only. No re-architecture, every feature kept, no Mac App Store listing.
- **B**: a dual build, with a reduced "Lite" edition on the Mac App Store.
- **C**: Mac App Store only, after a full re-architecture (NetworkExtension, native MITM, no Python).

## Decision

**A: Proxymate ships as a notarized DMG and as a Homebrew cask, and is not distributed through the Mac App Store.**

This is what the project already does: the README offers `brew install --cask proxymate` (recommended) and the DMG from the releases page, and nothing else.

## Consequences

- No re-architecture is needed to keep shipping, and no feature is cut for a sandboxed edition.
- There is no Mac App Store listing, and so no discovery through it.
- The scope of #2 (privileged helper) and #3 (notarization in CI) does not change: both serve the DMG and Homebrew channels.
- B or C can be reopened in a new ADR if a sandboxed edition is ever wanted; nothing in this decision blocks that.
