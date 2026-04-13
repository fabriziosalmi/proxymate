# Contributing to Proxymate

Thanks for your interest. This document describes how to get involved, what the expectations are, and where the lines are.

## Status: pre-public

The repository is currently private. Source is visible only to a trusted-reviewer circle; external forks and pull requests aren't accepted yet. That will change at the v1.0 public release, expected once the last distribution and docs blockers are cleared.

In the meantime:

- **Bug reports**: if you have access to the repo, open a GitHub issue. If you don't, email the address in [SECURITY.md](SECURITY.md).
- **Security issues**: always via Security Advisory or email. Never a public issue — see below.
- **Feature requests**: open an issue with the `enhancement` label and describe the user-facing problem (not the proposed solution). Solutions often look obvious until the constraint is considered.

## Development setup

```bash
git clone https://github.com/fabriziosalmi/proxymate.git
cd proxymate
open proxymate.xcodeproj
# ⌘R to run a Debug build
# ⌘U to run the XCTest suite (disable parallel testing in the scheme)
```

Requirements:

- macOS 15 (Sequoia) or newer — tested on 26 (Tahoe)
- Xcode 26+
- Apple Silicon. Intel is not a supported target.
- `pnpm` if you're touching `docs/` — the VitePress site

No external runtime dependencies for the app itself. The build pulls `swift-nio` and `swift-nio-ssl` via SPM; the rest is Apple-provided.

## Running the tests

```bash
# Unit + integration (XCTest)
xcodebuild test -project proxymate.xcodeproj -scheme proxymate \
    -destination 'platform=macOS' -parallel-testing-enabled NO

# Static sanity checks (no network)
./scripts/verify-all.sh

# Full end-to-end suite (requires a running Proxymate instance)
./scripts/e2e-full.sh
```

The e2e suite auto-detects the active proxy via `scutil --proxy`. Override with `PROXY_URL=http://127.0.0.1:NNNNN` if you're testing a specific listener.

## Docs

The documentation site lives in `docs/` and is a VitePress project. To preview locally:

```bash
cd docs
pnpm install
pnpm run dev     # http://localhost:5173/proxymate/
pnpm run build   # static output in .vitepress/dist/
```

Every push to `main` that touches `docs/**` redeploys the site via `.github/workflows/docs.yml`.

## Code style

There's no automated linter. Follow existing patterns:

- **Concurrency**: the project uses Swift's `MainActor` default. Non-UI singletons are `nonisolated final class ... @unchecked Sendable`, each with a private serial `DispatchQueue` as the sync boundary. Prefer actors for new singletons if the API shape allows.
- **No external dependencies** unless the Apple stack genuinely can't do the job. Swift NIO is the only exception (needed for event-driven TLS beyond what Network.framework cleanly exposes).
- **No force unwraps** in release paths. Failable inits return nil; call sites handle the failure.
- **Everything privileged goes through `PrivilegedHelper`.** Don't spawn `osascript` or `sudo` from new code paths.
- **New features are feature-flagged** via `UserDefaults` keys prefixed `proxymate.*`. Default off until a tester validates behaviour.

## Commit style

Each commit should be reviewable in isolation and leave the repo in a buildable state. Messages:

- **Subject line** ≤ 70 chars, imperative mood ("Fix timestamp service timeout", not "Fixed…").
- **Body** explains the *why* — hidden constraint, surprising behaviour, past incident. Not the *what* (the diff already shows that).
- **Reference the relevant ROADMAP item or issue** when it exists.

## Security disclosure

Do not open a public issue for suspected vulnerabilities. Preferred paths:

1. **GitHub Security Advisory** — invites private discussion with the maintainer before any public disclosure.
2. **Email** the address in [SECURITY.md](SECURITY.md). PGP key available on request.

Acknowledgment within 72h, initial severity assessment within 7 days, coordinated disclosure timeline agreed case-by-case.

## What would help most right now

In rough order of impact:

- **Running the app for 48 hours on a normal work Mac** and reporting any crash, hang, UX friction, or unexpected proxy behaviour.
- **Testing MITM against a cert-pinned app you actually use** — if the auto-exclude misses it, I need the hostname + app name.
- **Auditing the privilege path** ([PrivilegedHelper.swift](proxymate/PrivilegedHelper.swift), [ProxyManager.swift](proxymate/ProxyManager.swift)) — looking for any input that reaches a shell without validation.
- **Doc prose** — the guide and reference pages in `docs/` are functional but could use another pair of eyes for clarity.

## What this project is not

- An enterprise SASE replacement.
- A drop-in for PAC-only corporate networks (it can chain through them, but doesn't replace them).
- A VPN. It changes what your Mac sends; it doesn't tunnel through someone else's exit.
- Cross-platform. macOS only, for the foreseeable future.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
