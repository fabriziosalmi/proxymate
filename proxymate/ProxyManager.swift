//
//  ProxyManager.swift
//  proxymate
//
//  Applies / clears system-wide HTTP(S) proxy settings via `networksetup`.
//  Uses PrivilegedHelper (cached AuthorizationRef) so the user enters their
//  admin password only once per session.
//

import Foundation

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

    /// Reads the current HTTP proxy state from the first enabled network service.
    /// Returns nil if no proxy is set. Doesn't require admin.
    nonisolated static func currentProxy() async -> (host: String, port: Int)? {
        await Task.detached(priority: .utility) { () -> (String, Int)? in
            let p = Process()
            p.launchPath = "/bin/sh"
            p.arguments = ["-c", "networksetup -listallnetworkservices | tail -n +2 | grep -v '^\\*' | head -n 1"]
            let out = Pipe()
            p.standardOutput = out
            p.standardError = Pipe()
            do { try p.run() } catch { return nil }
            p.waitUntilExit()
            guard let svc = String(data: out.fileHandleForReading.readDataToEndOfFile(),
                                   encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
                  !svc.isEmpty else { return nil }

            let q = Process()
            q.launchPath = "/usr/sbin/networksetup"
            q.arguments = ["-getwebproxy", svc]
            let qout = Pipe()
            q.standardOutput = qout
            q.standardError = Pipe()
            do { try q.run() } catch { return nil }
            q.waitUntilExit()
            let raw = String(data: qout.fileHandleForReading.readDataToEndOfFile(),
                             encoding: .utf8) ?? ""
            var enabled = false
            var host = ""
            var port = 0
            for line in raw.split(separator: "\n") {
                let s = line.trimmingCharacters(in: .whitespaces)
                if s.hasPrefix("Enabled:") { enabled = s.contains("Yes") }
                else if s.hasPrefix("Server:") { host = String(s.dropFirst("Server:".count)).trimmingCharacters(in: .whitespaces) }
                else if s.hasPrefix("Port:") { port = Int(s.dropFirst("Port:".count).trimmingCharacters(in: .whitespaces)) ?? 0 }
            }
            return enabled && !host.isEmpty ? (host, port) : nil
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
