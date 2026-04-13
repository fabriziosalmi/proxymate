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
    var errorDescription: String? {
        switch self {
        case .scriptFailed(let m): return m
        case .verificationFailed(let exp, let act):
            return "System proxy not applied (expected \(exp), got \(act))"
        case .invalidHost(let h):
            return "Invalid proxy host: \(h)"
        case .invalidPort(let p):
            return "Invalid proxy port: \(p)"
        }
    }
}

enum ProxyManager {

    /// Domains/IPs that bypass the proxy (local networks, localhost, etc.)
    private static let bypassDomains = [
        "localhost", "127.0.0.1", "::1",
        "*.local",
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16",
    ].joined(separator: " ")

    nonisolated static func enable(proxy: ProxyConfig) async throws {
        // Strict input validation: proxy.host and proxy.port are interpolated
        // into a shell script executed as root. Without validation, a host like
        // `127.0.0.1; rm -rf ~` or `$(whoami)` would execute arbitrary commands
        // with admin privileges.
        try validate(host: proxy.host, port: proxy.port)

        let httpsBlock = proxy.applyToHTTPS ? """
              networksetup -setsecurewebproxy "$svc" \(proxy.host) \(proxy.port)
              networksetup -setsecurewebproxystate "$svc" on
        """ : ""

        let shell = """
        networksetup -listallnetworkservices | tail -n +2 | grep -v '^\\*' | while IFS= read -r svc; do
          networksetup -setwebproxy "$svc" \(proxy.host) \(proxy.port)
          networksetup -setwebproxystate "$svc" on
          networksetup -setproxybypassdomains "$svc" \(bypassDomains)
        \(httpsBlock)
        done
        """
        try await runPrivileged(shell)

        // Verify the change actually took effect. On macOS 26 the legacy
        // `AuthorizationExecuteWithPrivileges` path was silently no-op'ing,
        // leaving stale proxy state while the app reported "enabled".
        // If verification fails we surface a real error instead of lying.
        try await verifyApplied(host: proxy.host, port: proxy.port)
    }

    nonisolated static func disable() async throws {
        let shell = """
        networksetup -listallnetworkservices | tail -n +2 | grep -v '^\\*' | while IFS= read -r svc; do
          networksetup -setwebproxystate "$svc" off
          networksetup -setsecurewebproxystate "$svc" off
        done
        """
        try await runPrivileged(shell)
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
