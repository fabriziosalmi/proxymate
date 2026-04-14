//
//  MetricsServer.swift
//  proxymate
//
//  Opt-in local HTTP server on 127.0.0.1 exposing Prometheus text format
//  metrics at /metrics. Off by default. No external access.
//

import Foundation
import Network

nonisolated struct MetricsSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var port: Int = 9199
}

nonisolated final class MetricsServer: @unchecked Sendable {

    static let shared = MetricsServer()

    private nonisolated init() {}

    private let queue = DispatchQueue(label: "proxymate.metrics", qos: .utility)
    private var listener: NWListener?
    var statsProvider: (@Sendable () -> String)?

    func start(port: UInt16) {
        queue.async { [weak self] in
            guard let self else { return }
            self.stop()
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            guard let nwPort = NWEndpoint.Port(rawValue: port) else {
                NSLog("[MetricsServer] invalid port \(port) — server not started")
                return
            }
            params.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: nwPort)
            let listener: NWListener
            do {
                listener = try NWListener(using: params)
            } catch {
                // Before today: UI toggle stayed green when port already
                // bound; users thought Prometheus scrape was live but
                // curl got connection refused.
                NSLog("[MetricsServer] bind on :\(port) failed: \(error.localizedDescription)")
                return
            }
            listener.newConnectionHandler = { [weak self] conn in
                self?.handle(conn)
            }
            listener.start(queue: self.queue)
            self.listener = listener
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    private func handle(_ conn: NWConnection) {
        conn.start(queue: queue)
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] _, _, _, _ in
            let body = self?.statsProvider?() ?? ""
            let response = """
            HTTP/1.1 200 OK\r
            Content-Type: text/plain; version=0.0.4; charset=utf-8\r
            Content-Length: \(body.utf8.count)\r
            Connection: close\r
            \r
            \(body)
            """
            conn.send(content: response.data(using: .utf8), completion: .contentProcessed { _ in
                conn.cancel()
            })
        }
    }
}

// MARK: - Prometheus text format generator

nonisolated extension MetricsServer {

    static func generatePrometheusMetrics(state: AppState.Stats,
                                           cache: CacheManager.Stats,
                                           disk: DiskCache.Stats,
                                           dns: DNSResolver.DNSStats) -> String {
        var lines: [String] = []
        func gauge(_ name: String, _ help: String, _ value: Any) {
            lines.append("# HELP \(name) \(help)")
            lines.append("# TYPE \(name) gauge")
            lines.append("\(name) \(value)")
        }
        func counter(_ name: String, _ help: String, _ value: Any) {
            lines.append("# HELP \(name) \(help)")
            lines.append("# TYPE \(name) counter")
            lines.append("\(name) \(value)")
        }

        counter("proxymate_requests_allowed_total", "Total allowed requests", state.requestsAllowed)
        counter("proxymate_requests_blocked_total", "Total WAF blocked requests", state.requestsBlocked)
        counter("proxymate_blacklist_blocked_total", "Total blacklist blocked requests", state.blacklistBlocked)
        counter("proxymate_exfiltration_blocked_total", "Total exfiltration blocked requests", state.exfiltrationBlocked)
        counter("proxymate_privacy_actions_total", "Total privacy header actions", state.privacyActions)
        counter("proxymate_ai_requests_total", "Total AI provider requests", state.aiRequests)
        counter("proxymate_ai_blocked_total", "Total AI budget-blocked requests", state.aiBlocked)
        gauge("proxymate_ai_cost_usd", "Total AI cost in USD this session", String(format: "%.6f", state.aiTotalCostUSD))
        counter("proxymate_mitm_intercepted_total", "Total MITM intercepted connections", state.mitmIntercepted)

        // Cache
        counter("proxymate_cache_l1_hits_total", "L1 RAM cache hits", cache.hits)
        counter("proxymate_cache_l1_misses_total", "L1 RAM cache misses", cache.misses)
        gauge("proxymate_cache_l1_entries", "L1 cache entry count", cache.currentEntries)
        gauge("proxymate_cache_l1_size_bytes", "L1 cache size in bytes", Int(cache.currentSizeMB * 1024 * 1024))
        counter("proxymate_cache_l2_hits_total", "L2 disk cache hits", disk.hits)
        counter("proxymate_cache_l2_misses_total", "L2 disk cache misses", disk.misses)
        gauge("proxymate_cache_l2_size_bytes", "L2 disk cache size in bytes", disk.sizeBytes)

        // DNS
        counter("proxymate_dns_queries_total", "Total DoH DNS queries", dns.queries)
        counter("proxymate_dns_cache_hits_total", "DNS cache hits", dns.cacheHits)
        counter("proxymate_dns_errors_total", "DNS query errors", dns.errors)

        return lines.joined(separator: "\n") + "\n"
    }
}
