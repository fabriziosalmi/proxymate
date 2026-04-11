//
//  PACServer.swift
//  proxymate
//
//  Serves a dynamic PAC (Proxy Auto-Configuration) file on localhost.
//  macOS system proxy can be pointed at this URL via networksetup
//  -setautoproxyurl, which catches apps that respect PAC but ignore
//  HTTP_PROXY env vars (most Electron apps, Python requests, etc.).
//
//  The PAC script routes:
//  - Allowed domains → DIRECT (bypass proxy entirely)
//  - Everything else → PROXY 127.0.0.1:<localPort>
//
//  PAC is regenerated dynamically when rules change.
//

import Foundation
import Network

nonisolated struct PACSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var port: Int = 9280                  // PAC server port
    var mode: PACMode = .allTraffic

    enum PACMode: String, Codable, CaseIterable, Identifiable, Sendable {
        case allTraffic   = "All Traffic"      // everything through proxy
        case smartBypass  = "Smart Bypass"     // allowlist → DIRECT, rest → proxy
        var id: String { rawValue }
    }
}

nonisolated final class PACServer: @unchecked Sendable {

    static let shared = PACServer()

    private let queue = DispatchQueue(label: "proxymate.pac", qos: .userInitiated)
    private var listener: NWListener?
    private var proxyPort: UInt16 = 0
    private var directDomains: [String] = []
    private var socks5Port: UInt16 = 0
    private var settings = PACSettings()

    // MARK: - Lifecycle

    func start(settings: PACSettings, proxyPort: UInt16, socks5Port: UInt16,
               directDomains: [String]) {
        queue.async { [weak self] in
            guard let self else { return }
            self.stop()
            self.settings = settings
            self.proxyPort = proxyPort
            self.socks5Port = socks5Port
            self.directDomains = directDomains

            guard settings.port > 0 && settings.port <= 65535,
                  let nwPort = NWEndpoint.Port(rawValue: UInt16(settings.port)) else { return }

            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: nwPort)

            guard let l = try? NWListener(using: params) else { return }
            l.newConnectionHandler = { [weak self] conn in
                self?.handleRequest(conn)
            }
            l.start(queue: self.queue)
            self.listener = l
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    func updateDirectDomains(_ domains: [String]) {
        queue.async { [weak self] in
            self?.directDomains = domains
        }
    }

    func updateProxyPort(_ port: UInt16) {
        queue.async { [weak self] in
            self?.proxyPort = port
        }
    }

    // MARK: - HTTP handler

    private func handleRequest(_ conn: NWConnection) {
        conn.start(queue: queue)
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, _, _ in
            guard let self else { conn.cancel(); return }
            let pac = self.generatePAC()
            let response = """
            HTTP/1.1 200 OK\r
            Content-Type: application/x-ns-proxy-autoconfig\r
            Content-Length: \(pac.utf8.count)\r
            Cache-Control: no-cache\r
            Connection: close\r
            \r
            \(pac)
            """
            conn.send(content: response.data(using: .utf8), completion: .contentProcessed { _ in
                conn.cancel()
            })
        }
    }

    // MARK: - PAC generation

    private func generatePAC() -> String {
        let proxy = "PROXY 127.0.0.1:\(proxyPort)"
        let socks = socks5Port > 0 ? "; SOCKS5 127.0.0.1:\(socks5Port)" : ""
        let fallback = "\(proxy)\(socks); DIRECT"

        switch settings.mode {
        case .allTraffic:
            return """
            function FindProxyForURL(url, host) {
                // Localhost always direct
                if (isPlainHostName(host) ||
                    shExpMatch(host, "localhost") ||
                    shExpMatch(host, "127.*") ||
                    shExpMatch(host, "10.*") ||
                    shExpMatch(host, "172.16.*") ||
                    shExpMatch(host, "192.168.*")) {
                    return "DIRECT";
                }
                return "\(fallback)";
            }
            """

        case .smartBypass:
            let conditions = directDomains.map { domain -> String in
                if domain.hasPrefix("*.") {
                    let suffix = String(domain.dropFirst(2))
                    return "    if (dnsDomainIs(host, \".\(suffix)\") || host == \"\(suffix)\") return \"DIRECT\";"
                } else {
                    return "    if (host == \"\(domain)\" || dnsDomainIs(host, \".\(domain)\")) return \"DIRECT\";"
                }
            }.joined(separator: "\n")

            return """
            function FindProxyForURL(url, host) {
                // Localhost always direct
                if (isPlainHostName(host) ||
                    shExpMatch(host, "localhost") ||
                    shExpMatch(host, "127.*") ||
                    shExpMatch(host, "10.*") ||
                    shExpMatch(host, "172.16.*") ||
                    shExpMatch(host, "192.168.*")) {
                    return "DIRECT";
                }
                // Allowlisted domains bypass proxy
            \(conditions)
                // Everything else through proxy
                return "\(fallback)";
            }
            """
        }
    }

    /// The URL that should be set as the system auto-proxy URL.
    var pacURL: String {
        "http://127.0.0.1:\(settings.port)/proxy.pac"
    }
}

// MARK: - System proxy integration

extension PACServer {

    /// Set the system auto-proxy URL to our PAC server.
    static func applySystemPAC(port: Int) async throws {
        let shell = """
        networksetup -listallnetworkservices | tail -n +2 | grep -v '^\\*' | while IFS= read -r svc; do
          networksetup -setautoproxyurl "$svc" "http://127.0.0.1:\(port)/proxy.pac"
          networksetup -setautoproxystate "$svc" on
        done
        """
        try await Task.detached(priority: .userInitiated) {
            try PrivilegedHelper.shared.runAsRoot(shell)
        }.value
    }

    /// Clear the system auto-proxy URL.
    static func clearSystemPAC() async throws {
        let shell = """
        networksetup -listallnetworkservices | tail -n +2 | grep -v '^\\*' | while IFS= read -r svc; do
          networksetup -setautoproxystate "$svc" off
          networksetup -setautoproxyurl "$svc" ""
        done
        """
        try await Task.detached(priority: .userInitiated) {
            try PrivilegedHelper.shared.runAsRoot(shell)
        }.value
    }
}
