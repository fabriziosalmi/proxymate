//
//  HostMemory.swift
//  proxymate
//
//  Tracks per-host behavior: response status codes, latency, error rate.
//  Used by the Judge pipeline to flag unhealthy or suspicious hosts.
//

import Foundation

nonisolated final class HostMemory: @unchecked Sendable {

    static let shared = HostMemory()

    private let queue = DispatchQueue(label: "proxymate.hostmemory", qos: .utility)
    private var hosts: [String: HostProfile] = [:]

    struct HostProfile: Sendable {
        var requestCount: Int = 0
        var lastSeen: Date = Date()
        var statusCodes: [Int] = []        // last 20
        var latencies: [Double] = []       // last 20 (seconds)
        var errorCount: Int = 0            // 4xx + 5xx total
        var totalBytes: Int = 0

        var errorRate: Double {
            guard requestCount > 0 else { return 0 }
            return Double(errorCount) / Double(requestCount)
        }

        var avgLatency: Double {
            guard !latencies.isEmpty else { return 0 }
            return latencies.reduce(0, +) / Double(latencies.count)
        }

        var isUnhealthy: Bool {
            // >50% errors in last 20 requests
            let recent = statusCodes.suffix(20)
            guard recent.count >= 5 else { return false }
            let errors = recent.filter { $0 >= 400 }.count
            return Double(errors) / Double(recent.count) > 0.5
        }
    }

    // MARK: - Record

    private static let maxHosts = 50_000
    private static let staleThreshold: TimeInterval = 24 * 3600 // 24h

    func recordRequest(host: String) {
        queue.async { [weak self] in
            guard let self else { return }
            var p = self.hosts[host.lowercased()] ?? HostProfile()
            p.requestCount += 1
            p.lastSeen = Date()
            self.hosts[host.lowercased()] = p
            self.pruneIfNeeded()
        }
    }

    private func pruneIfNeeded() {
        guard hosts.count > Self.maxHosts else { return }
        let cutoff = Date().addingTimeInterval(-Self.staleThreshold)
        hosts = hosts.filter { $0.value.lastSeen > cutoff }
    }

    func recordResponse(host: String, statusCode: Int, latency: Double, bytes: Int) {
        queue.async { [weak self] in
            // Single early-exit on `self` so the read of `hosts[h]` and
            // the write `hosts[h] = p` can't straddle a deallocation.
            // Without this, an interleave where self dies between the
            // two would silently lose the update; the recordRequest
            // path above already uses this pattern.
            guard let self else { return }
            let h = host.lowercased()
            var p = self.hosts[h] ?? HostProfile()
            p.statusCodes.append(statusCode)
            if p.statusCodes.count > 20 { p.statusCodes.removeFirst() }
            p.latencies.append(latency)
            if p.latencies.count > 20 { p.latencies.removeFirst() }
            if statusCode >= 400 { p.errorCount += 1 }
            p.totalBytes += bytes
            self.hosts[h] = p
        }
    }

    // MARK: - Query

    func profile(for host: String) -> HostProfile? {
        queue.sync { hosts[host.lowercased()] }
    }

    func isUnhealthy(_ host: String) -> Bool {
        queue.sync { hosts[host.lowercased()]?.isUnhealthy ?? false }
    }

    func topHosts(limit: Int = 10) -> [(host: String, profile: HostProfile)] {
        queue.sync {
            hosts.sorted { $0.value.requestCount > $1.value.requestCount }
                .prefix(limit)
                .map { ($0.key, $0.value) }
        }
    }

    var totalHosts: Int {
        queue.sync { hosts.count }
    }

    func reset() {
        queue.async { [weak self] in self?.hosts.removeAll() }
    }
}
