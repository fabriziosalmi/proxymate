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
        try await Task.detached(priority: .userInitiated) { try disableNow() }.value
    }

    /// Synchronous disable, for app termination: a Task started from
    /// applicationWillTerminate was measured never to run within its 8 s
    /// wait, so the app exited with the system proxy on.
    nonisolated static func disableNow() throws {
        try clearNow(shell: disableShell, pacOnly: false)
    }

    static let disableShell = """
    networksetup -listallnetworkservices | tail -n +2 | grep -v '^\\*' | while IFS= read -r svc; do
      networksetup -setwebproxystate "$svc" off
      networksetup -setsecurewebproxystate "$svc" off
      networksetup -setautoproxystate "$svc" off
      networksetup -setautoproxyurl "$svc" ""
    done
    """

    /// Runs `shell` as the user first (an admin user may change proxy
    /// settings with networksetup directly) and falls back to the admin
    /// prompt only if a proxy is still on. State is read per network service
    /// from networksetup, not from SystemConfiguration, which reflects only
    /// the primary service.
    private nonisolated static func clearNow(shell: String, pacOnly: Bool) throws {
        if !anyServiceProxyOn(pacOnly: pacOnly) { return }
        PrivilegedHelper.shared.runAsUser(shell)
        if !anyServiceProxyOn(pacOnly: pacOnly) { return }
        try PrivilegedHelper.shared.runAsRoot(shell)
    }

    /// True if any enabled network service has a web, HTTPS or PAC proxy on
    /// (PAC only with `pacOnly`). Read-only, no prompt.
    nonisolated static func anyServiceProxyOn(pacOnly: Bool = false) -> Bool {
        let gets = pacOnly
            ? #"networksetup -getautoproxyurl "$svc""#
            : #"networksetup -getwebproxy "$svc"; networksetup -getsecurewebproxy "$svc"; networksetup -getautoproxyurl "$svc""#
        let out = PrivilegedHelper.shared.runAsUser("""
        networksetup -listallnetworkservices | tail -n +2 | grep -v '^\\*' | while IFS= read -r svc; do
          \(gets)
        done
        """)
        return anyEnabled(inNetworksetupOutput: out)
    }

    /// networksetup prints "Enabled: Yes" for an active web/HTTPS proxy and
    /// for an active auto-proxy URL.
    static func anyEnabled(inNetworksetupOutput out: String) -> Bool {
        out.split(whereSeparator: \.isNewline).contains { $0.trimmingCharacters(in: .whitespaces) == "Enabled: Yes" }
    }

    /// PAC-only variant, for PACServer.clearSystemPAC.
    nonisolated static func clearPAC(shell: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            try clearNow(shell: shell, pacOnly: true)
        }.value
    }

    /// Some network service's web or HTTPS proxy points at a loopback port
    /// nothing listens on: what a Proxymate that exited without cleanup
    /// leaves behind (crash, SIGKILL, or an older build replaced at launch).
    /// Read per service: SystemConfiguration shows only the primary one.
    nonisolated static func pointsAtDeadLoopback() -> Bool {
        let out = PrivilegedHelper.shared.runAsUser("""
        networksetup -listallnetworkservices | tail -n +2 | grep -v '^\\*' | while IFS= read -r svc; do
          networksetup -getwebproxy "$svc"; networksetup -getsecurewebproxy "$svc"
        done
        """)
        return enabledLoopbackPorts(inNetworksetupOutput: out)
            .contains { !MITMProxySidecar.waitForLocalPort($0, timeout: 0.2) }
    }

    /// Ports of enabled web/HTTPS proxies whose server is loopback, from
    /// `networksetup -getwebproxy` style output (Enabled, Server, Port).
    static func enabledLoopbackPorts(inNetworksetupOutput out: String) -> [UInt16] {
        var ports: [UInt16] = []
        var enabled = false, loopback = false
        for raw in out.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Enabled: ") {
                enabled = line == "Enabled: Yes"; loopback = false
            } else if line.hasPrefix("Server: ") {
                loopback = ["127.0.0.1", "localhost", "::1"].contains(String(line.dropFirst(8)))
            } else if line.hasPrefix("Port: "), enabled, loopback,
                      let p = UInt16(line.dropFirst(6)), p > 0 {
                ports.append(p)
            }
        }
        return ports
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

