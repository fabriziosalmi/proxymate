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
    var errorDescription: String? {
        switch self {
        case .scriptFailed(let m): return m
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

    private nonisolated static func runPrivileged(_ shell: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            try PrivilegedHelper.shared.runAsRoot(shell)
        }.value
    }
}
