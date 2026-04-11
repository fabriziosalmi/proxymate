# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report them via one of:

1. **GitHub Security Advisories**: Go to the [Security tab](../../security/advisories) and click "Report a vulnerability"
2. **Email**: Contact the maintainer directly

### What to include

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if you have one)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 1 week
- **Fix released**: within 2 weeks for critical issues

## Security design

Proxymate runs entirely on your Mac with no cloud connectivity:

- **Zero telemetry**: no data leaves your machine except your proxied traffic
- **No accounts**: no login, no registration, no cloud sync by default
- **Local storage**: all config in `UserDefaults`, logs in `~/Library/Application Support/Proxymate/`
- **Keychain**: TLS MITM certificates stored in macOS Keychain (hardware-backed when available)
- **Admin auth**: cached `AuthorizationRef`, never stored on disk
- **Hardened runtime**: enabled for all builds

## Threat model

Proxymate is a **local proxy** that processes your traffic. It has access to:

- All HTTP request/response headers passing through it
- All HTTP request/response bodies (when MITM is enabled, also HTTPS)
- System proxy settings (requires admin password once per session)
- macOS Keychain (for TLS certificate storage)
- Network connections to blacklist update URLs (opt-in, configurable)

It does **not** have access to:
- Traffic that doesn't go through the system proxy
- Other users' traffic on the same machine
- Kernel-level network stack
