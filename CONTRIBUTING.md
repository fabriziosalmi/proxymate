# Contributing to Proxymate

Thanks for your interest in contributing. Proxymate is free, open source, and built with care.

## Quick start

```bash
git clone https://github.com/fabriziosalmi/proxymate.git
cd proxymate
open proxymate.xcodeproj
# Cmd+R to build and run
# Cmd+U to run tests (disable parallel testing in scheme settings)
```

## Requirements

- macOS 15+
- Xcode 26+
- No external dependencies (everything is built on Apple frameworks)

## How to contribute

1. **Fork** the repo and create a branch from `main`
2. **Make your changes** — keep them focused on one thing
3. **Add tests** if you're adding new functionality
4. **Run the test suite**: `xcodebuild test -project proxymate.xcodeproj -scheme proxymate -destination 'platform=macOS' -parallel-testing-enabled NO`
5. **Open a PR** with a clear description

## What we need help with

- **Testing on different macOS versions** (15.x, 14.x)
- **New blacklist sources** with URLs and format descriptions
- **Exfiltration patterns** for additional cloud providers
- **C2 signatures** for offensive tools not yet covered
- **Localization** (the UI is English-only currently)
- **Accessibility** improvements
- **Documentation** and usage guides

## Architecture

The codebase is intentionally flat (no frameworks, no SPM deps):

```
proxymate/
  proxymateApp.swift     # Entry point (MenuBarExtra)
  ContentView.swift      # All UI (7 tabs)
  AppState.swift         # Central state + persistence
  LocalProxy.swift       # HTTP/HTTPS forward proxy (Network.framework)
  Models.swift           # Data models (WAFRule, ProxyConfig, etc.)
  ...                    # Feature modules (one file per feature)
proxymateTests/
  *.swift                # 134 XCTest cases
scripts/
  build-dmg.sh           # Build + notarize + DMG
```

## Code style

- No linter enforced, but follow existing patterns
- `nonisolated` on all `Sendable` structs (project uses `@MainActor` default)
- Thread safety via serial `DispatchQueue` for each manager/singleton
- No external dependencies — if Apple provides it, use it
- Test new features with deterministic unit tests (no singleton deps)

## Security

If you find a security vulnerability, please report it privately via GitHub Security Advisories or email. Do not open a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
