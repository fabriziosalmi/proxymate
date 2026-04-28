//
//  ProxyManager.swift
//  proxymate
//
//  Applies / clears system-wide HTTP(S) proxy settings via `networksetup`.
//  Uses PrivilegedHelper (cached AuthorizationRef) so the user enters their
//  admin password only once per session.
//

import Foundation
import SystemConfiguration

enum ProxyManagerError: LocalizedError {
    case scriptFailed(String)
    case verificationFailed(expected: String, actual: String)
    case invalidHost(String)
    case invalidPort(Int)
    case invalidPACURL(String)
    var errorDescription: String? {
        switch self {
        case .scriptFailed(let m): return m
        case .verificationFailed(let exp, let act):
            return "System proxy not applied (expected \(exp), got \(act))"
        case .invalidHost(let h):
            return "Invalid proxy host: \(h)"
        case .invalidPort(let p):
            return "Invalid proxy port: \(p)"
        case .invalidPACURL(let u):
            return "Invalid PAC URL: \(u)"
        }
    }
}

enum ProxyManager {

    /// Domains/IPs that bypass the proxy (local networks, localhost, etc.)
    nonisolated private static let bypassDomains = [
        "localhost", "127.0.0.1", "::1",
        "*.local",
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16",
    ].joined(separator: " ")

    nonisolated static func enable(proxy: ProxyConfig, pacURL: String? = nil) async throws {
        // Strict input validation: proxy.host and proxy.port are interpolated
        // into a shell script executed as root. Without validation, a host like
        // `127.0.0.1; rm -rf ~` or `$(whoami)` would execute arbitrary commands
        // with admin privileges.
        try validate(host: proxy.host, port: proxy.port)
        if let pacURL { try validate(pacURL: pacURL) }

        // Idempotent fast-path: if the system already routes to this host/port,
        // there's nothing to apply. Skipping osascript here avoids spurious
        // admin-password prompts on wake-from-sleep and network-interface
        // changes (NWPathMonitor fires on Wi-Fi/Ethernet/VPN transitions),
        // where the settings almost always already match.
        if pacURL == nil,
           let current = await currentProxy(),
           current.host == proxy.host && current.port == proxy.port {
            return
        }

        let httpsBlock = proxy.applyToHTTPS ? """
              networksetup -setsecurewebproxy "$svc" \(proxy.host) \(proxy.port)
              networksetup -setsecurewebproxystate "$svc" on
        """ : ""

        // Optional PAC apply baked into the SAME osascript invocation so
        // enabling the proxy + setting the PAC URL costs ONE admin prompt
        // instead of two. Pre-batching, every PAC-on enable cost two
        // separate networksetup runs and the macOS auth cache wouldn't
        // bridge between them on macOS 26 — users saw 2-3 password prompts
        // per Enable click.
        let pacBlock = pacURL.map { url in """
              networksetup -setautoproxyurl "$svc" "\(url)"
              networksetup -setautoproxystate "$svc" on
        """ } ?? ""

        let shell = """
        networksetup -listallnetworkservices | tail -n +2 | grep -v '^\\*' | while IFS= read -r svc; do
          networksetup -setwebproxy "$svc" \(proxy.host) \(proxy.port)
          networksetup -setwebproxystate "$svc" on
          networksetup -setproxybypassdomains "$svc" \(bypassDomains)
        \(httpsBlock)
        \(pacBlock)
        done
        """
        try await runPrivileged(shell)

        // Verify the change actually took effect. On macOS 26 the legacy
        // `AuthorizationExecuteWithPrivileges` path was silently no-op'ing,
        // leaving stale proxy state while the app reported "enabled".
        // If verification fails we surface a real error instead of lying.
        try await verifyApplied(host: proxy.host, port: proxy.port)
    }

    /// Disable web proxy AND clear PAC autoproxy URL in a single privileged
    /// shell run, so a Disable click costs ONE admin prompt instead of two
    /// (the PAC-clear path was a separate osascript invocation).
    nonisolated static func disable() async throws {
        // Probe both directions: if neither web proxy nor PAC is set,
        // nothing to clear and we skip osascript entirely (no prompt).
        let webOn = await currentProxy() != nil
        let pacOn = await currentPACEnabled()
        if !webOn && !pacOn { return }

        let shell = """
        networksetup -listallnetworkservices | tail -n +2 | grep -v '^\\*' | while IFS= read -r svc; do
          networksetup -setwebproxystate "$svc" off
          networksetup -setsecurewebproxystate "$svc" off
          networksetup -setautoproxystate "$svc" off
          networksetup -setautoproxyurl "$svc" ""
        done
        """
        try await runPrivileged(shell)
    }

    /// True if SCDynamicStore reports an active autoproxy URL configuration.
    /// Used by disable() to decide whether the batched osascript needs to
    /// run at all.
    private nonisolated static func currentPACEnabled() async -> Bool {
        await Task.detached(priority: .utility) { () -> Bool in
            guard let store = SCDynamicStoreCreate(nil, "Proxymate" as CFString, nil, nil),
                  let proxies = SCDynamicStoreCopyProxies(store) as? [String: Any] else { return false }
            let enabled = proxies[kSCPropNetProxiesProxyAutoConfigEnable as String] as? Int ?? 0
            return enabled == 1
        }.value
    }

    /// Reads current HTTP proxy state via SystemConfiguration (no shell, instant).
    nonisolated static func currentProxy() async -> (host: String, port: Int)? {
        await Task.detached(priority: .utility) { () -> (String, Int)? in
            guard let store = SCDynamicStoreCreate(nil, "Proxymate" as CFString, nil, nil),
                  let proxies = SCDynamicStoreCopyProxies(store) as? [String: Any] else { return nil }
            let enabled = proxies[kSCPropNetProxiesHTTPEnable as String] as? Int ?? 0
            guard enabled == 1 else { return nil }
            let host = proxies[kSCPropNetProxiesHTTPProxy as String] as? String ?? ""
            let port = proxies[kSCPropNetProxiesHTTPPort as String] as? Int ?? 0
            return host.isEmpty ? nil : (host, port)
        }.value
    }

    /// Pre-authorize so the first toggle doesn't block.
    /// Can be called at launch to "warm up" the auth without running a command.
    nonisolated static func preAuthorize() async throws {
        try await Task.detached(priority: .userInitiated) {
            try PrivilegedHelper.shared.ensureAuthorized()
        }.value
    }

    /// Validates that a proxy host/port pair is safe to interpolate into a
    /// shell script. Host must look like an IPv4, IPv6, or RFC1123 hostname;
    /// port must be 1–65535. Any character outside the restricted set (shell
    /// metacharacters, whitespace, quotes, backticks, semicolons, etc.) is
    /// rejected.
    private nonisolated static func validate(host: String, port: Int) throws {
        guard (1...65535).contains(port) else {
            throw ProxyManagerError.invalidPort(port)
        }
        // Allowed: letters, digits, dot, hyphen, colon (IPv6). 1–253 chars.
        // Deliberately excludes: spaces, $, `, ", ', \, ;, |, &, newline, etc.
        let charset = CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:")
        guard !host.isEmpty, host.count <= 253,
              host.unicodeScalars.allSatisfy({ charset.contains($0) }) else {
            throw ProxyManagerError.invalidHost(host)
        }
    }

    /// Strict allowlist for PAC URLs that get interpolated into a
    /// double-quoted shell argument running as root. Rejecting anything
    /// outside this set defeats command injection — without this, a URL
    /// like `http://x.test/p"; rm -rf /; echo "` would break out of the
    /// quotes and execute arbitrary commands with admin privileges.
    /// Only http/https + RFC1123 host + port + restricted path/query.
    /// Internal (not private) so unit tests can lock in the parser.
    nonisolated static func validate(pacURL: String) throws {
        guard !pacURL.isEmpty, pacURL.count <= 1024,
              let comps = URLComponents(string: pacURL),
              let scheme = comps.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              let host = comps.host, !host.isEmpty,
              comps.user == nil, comps.password == nil, comps.fragment == nil
        else {
            throw ProxyManagerError.invalidPACURL(pacURL)
        }
        let port = comps.port ?? (scheme == "https" ? 443 : 80)
        try validate(host: host, port: port)

        // Path: ASCII alphanumerics, slash, dot, hyphen, underscore. No
        // spaces, no quotes, no $, `, \, ;, |, &, %, or newlines.
        let pathChars = CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./-_")
        guard comps.path.unicodeScalars.allSatisfy({ pathChars.contains($0) }) else {
            throw ProxyManagerError.invalidPACURL(pacURL)
        }
        if let q = comps.query {
            // Queries are allowed but stay in the same restricted alphabet
            // plus `=` and `&`. Percent-encoding is rejected on purpose —
            // PAC servers under our control don't need it, and allowing %
            // hands the attacker a way to smuggle quote/backslash bytes.
            let queryChars = CharacterSet(charactersIn:
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./-_=&")
            guard q.unicodeScalars.allSatisfy({ queryChars.contains($0) }) else {
                throw ProxyManagerError.invalidPACURL(pacURL)
            }
        }
    }

    private nonisolated static func runPrivileged(_ shell: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            try PrivilegedHelper.shared.runAsRoot(shell)
        }.value
    }

    /// Poll SystemConfiguration briefly until the proxy matches the expected
    /// host/port. Writes by `networksetup` propagate into SC asynchronously,
    /// usually <50ms; we allow up to 2s before giving up.
    private nonisolated static func verifyApplied(host: String, port: Int) async throws {
        let deadline = Date().addingTimeInterval(2.0)
        var last: (host: String, port: Int)? = nil
        while Date() < deadline {
            if let current = await currentProxy() {
                last = current
                if current.host == host && current.port == port { return }
            }
            try? await Task.sleep(nanoseconds: 100_000_000) // 100ms
        }
        let actual = last.map { "\($0.host):\($0.port)" } ?? "disabled"
        throw ProxyManagerError.verificationFailed(
            expected: "\(host):\(port)", actual: actual)
    }
}
