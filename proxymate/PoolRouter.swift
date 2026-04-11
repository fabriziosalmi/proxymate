//
//  PoolRouter.swift
//  proxymate
//
//  Selects an upstream from a pool based on the configured strategy.
//  Manages health checks, connection counts, and latency tracking.
//  Thread-safe via serial queue.
//

import Foundation
import Network

nonisolated final class PoolRouter: @unchecked Sendable {

    static let shared = PoolRouter()

    private let queue = DispatchQueue(label: "proxymate.poolrouter", qos: .userInitiated)

    private var pools: [UUID: UpstreamPool] = [:]
    private var overrides: [PoolOverride] = []
    private var defaultPoolId: UUID?
    private var health: [UUID: MemberHealth] = [:]     // keyed by PoolMember.id
    private var roundRobinIndex: [UUID: Int] = [:]     // keyed by pool id
    private var healthCheckTimers: [UUID: DispatchSourceTimer] = [:]

    var onEvent: (@Sendable (Event) -> Void)?

    enum Event: Sendable {
        case healthChanged(memberId: UUID, memberHost: String, healthy: Bool, latencyMs: Double?)
        case log(LogEntry.Level, String)
    }

    struct Selected: Sendable {
        let host: String
        let port: UInt16
        let memberId: UUID
    }

    // MARK: - Configuration

    func configure(pools: [UpstreamPool], overrides: [PoolOverride]) {
        queue.async { [weak self] in
            guard let self else { return }
            self.pools = Dictionary(uniqueKeysWithValues: pools.map { ($0.id, $0) })
            self.overrides = overrides
            self.defaultPoolId = pools.first(where: { $0.isDefault })?.id ?? pools.first?.id

            // Initialize health for new members
            for pool in pools {
                for member in pool.members {
                    if self.health[member.id] == nil {
                        self.health[member.id] = MemberHealth()
                    }
                }
            }

            self.restartHealthChecks()
        }
    }

    // MARK: - Selection

    /// Select an upstream for the given request host. Uses override chain
    /// first, then falls back to the default pool.
    func select(forHost host: String) -> Selected? {
        queue.sync {
            let poolId = resolvePool(forHost: host)
            guard let pool = pools[poolId] else { return nil }
            return pickMember(from: pool)
        }
    }

    /// Track connection start (for least-connections strategy).
    func connectionStarted(memberId: UUID) {
        queue.async { [weak self] in
            self?.health[memberId]?.activeConnections += 1
        }
    }

    /// Track connection end.
    func connectionEnded(memberId: UUID) {
        queue.async { [weak self] in
            guard let self else { return }
            if let count = self.health[memberId]?.activeConnections, count > 0 {
                self.health[memberId]?.activeConnections = count - 1
            }
        }
    }

    // MARK: - Health info (for UI)

    func getHealth() -> [UUID: MemberHealth] {
        queue.sync { health }
    }

    // MARK: - Pool resolution

    private func resolvePool(forHost host: String) -> UUID {
        let h = host.lowercased()
        for override in overrides {
            if matchesPattern(host: h, pattern: override.hostPattern.lowercased()) {
                return override.poolId
            }
        }
        return defaultPoolId ?? UUID()
    }

    private func matchesPattern(host: String, pattern: String) -> Bool {
        if host == pattern { return true }
        if pattern.hasPrefix("*.") {
            let suffix = String(pattern.dropFirst(2))
            return host == suffix || host.hasSuffix("." + suffix)
        }
        return false
    }

    // MARK: - Strategy-based member selection

    private func pickMember(from pool: UpstreamPool) -> Selected? {
        let eligible = pool.members.filter { m in
            m.enabled && (health[m.id]?.isHealthy ?? true)
        }
        guard !eligible.isEmpty else {
            // All down — try any enabled member as last resort
            guard let fallback = pool.members.first(where: { $0.enabled }),
                  let port = UInt16(exactly: fallback.port) else { return nil }
            return Selected(host: fallback.host, port: port, memberId: fallback.id)
        }

        let member: PoolMember
        switch pool.strategy {
        case .roundRobin:
            let idx = (roundRobinIndex[pool.id] ?? 0) % eligible.count
            member = eligible[idx]
            roundRobinIndex[pool.id] = idx + 1

        case .weighted:
            member = weightedRandom(eligible)

        case .failover:
            // First eligible member in order (primary → backup)
            member = eligible[0]

        case .latencyBased:
            member = eligible.min(by: { a, b in
                (health[a.id]?.lastLatencyMs ?? 999) < (health[b.id]?.lastLatencyMs ?? 999)
            }) ?? eligible[0]

        case .leastConns:
            member = eligible.min(by: { a, b in
                (health[a.id]?.activeConnections ?? 0) < (health[b.id]?.activeConnections ?? 0)
            }) ?? eligible[0]

        case .random:
            member = eligible.randomElement() ?? eligible[0]
        }

        guard let port = UInt16(exactly: member.port) else { return nil }
        return Selected(host: member.host, port: port, memberId: member.id)
    }

    private func weightedRandom(_ members: [PoolMember]) -> PoolMember {
        let totalWeight = members.reduce(0) { $0 + $1.weight }
        guard totalWeight > 0 else { return members[0] }
        var r = Int.random(in: 0..<totalWeight)
        for m in members {
            r -= m.weight
            if r < 0 { return m }
        }
        return members[0]
    }

    // MARK: - Health checks

    private func restartHealthChecks() {
        for (_, timer) in healthCheckTimers { timer.cancel() }
        healthCheckTimers.removeAll()

        for (_, pool) in pools where pool.healthCheck.enabled {
            for member in pool.members where member.enabled {
                startHealthCheck(member: member, config: pool.healthCheck)
            }
        }
    }

    private func startHealthCheck(member: PoolMember, config: HealthCheckConfig) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        let interval = Double(max(config.intervalSeconds, 5))
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in
            self?.performHealthCheck(member: member, config: config)
        }
        timer.resume()
        healthCheckTimers[member.id] = timer
    }

    private func performHealthCheck(member: PoolMember, config: HealthCheckConfig) {
        guard let port = NWEndpoint.Port(rawValue: UInt16(member.port)) else { return }
        let conn = NWConnection(
            host: NWEndpoint.Host(member.host),
            port: port,
            using: .tcp
        )
        let start = DispatchTime.now()
        let timeout = DispatchTimeInterval.seconds(config.timeoutSeconds)

        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { conn.cancel(); return }
            switch state {
            case .ready:
                let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000
                conn.cancel()
                self.queue.async {
                    self.recordHealthResult(memberId: member.id, memberHost: member.host,
                                           success: true, latencyMs: elapsed, config: config)
                }
            case .failed, .cancelled:
                self.queue.async {
                    self.recordHealthResult(memberId: member.id, memberHost: member.host,
                                           success: false, latencyMs: nil, config: config)
                }
            default:
                break
            }
        }
        conn.start(queue: DispatchQueue.global(qos: .utility))

        // Timeout
        queue.asyncAfter(deadline: .now() + timeout) {
            if conn.state != .ready && conn.state != .cancelled {
                conn.cancel()
            }
        }
    }

    private func recordHealthResult(memberId: UUID, memberHost: String,
                                     success: Bool, latencyMs: Double?,
                                     config: HealthCheckConfig) {
        var h = health[memberId] ?? MemberHealth()
        h.lastCheckTime = Date()
        if let ms = latencyMs { h.lastLatencyMs = ms }

        let wasHealthy = h.isHealthy
        if success {
            h.consecutiveFailures = 0
            h.consecutiveSuccesses += 1
            if !h.isHealthy && h.consecutiveSuccesses >= config.healthyThreshold {
                h.isHealthy = true
            }
        } else {
            h.consecutiveSuccesses = 0
            h.consecutiveFailures += 1
            if h.isHealthy && h.consecutiveFailures >= config.unhealthyThreshold {
                h.isHealthy = false
            }
        }
        health[memberId] = h

        if wasHealthy != h.isHealthy {
            onEvent?(.healthChanged(memberId: memberId, memberHost: memberHost,
                                     healthy: h.isHealthy, latencyMs: latencyMs))
        }
    }

    func stop() {
        queue.async { [weak self] in
            for (_, timer) in self?.healthCheckTimers ?? [:] { timer.cancel() }
            self?.healthCheckTimers.removeAll()
        }
    }
}
