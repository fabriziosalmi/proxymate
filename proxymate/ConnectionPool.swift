//
//  ConnectionPool.swift
//  proxymate
//
//  Reuses TCP connections to upstream proxies. Keeps idle connections
//  alive for a configurable timeout, avoiding TCP handshake + TLS
//  negotiation overhead on every request.
//
//  Thread-safe via serial queue.
//

import Foundation
import Network

nonisolated final class ConnectionPool: @unchecked Sendable {

    static let shared = ConnectionPool()

    private let queue = DispatchQueue(label: "proxymate.connpool", qos: .userInitiated)
    private var pool: [String: [PooledConnection]] = [:]
    private var maxIdlePerHost = 4
    private var idleTimeout: TimeInterval = 30
    private var cleanupTimer: DispatchSourceTimer?

    private struct PooledConnection {
        let connection: NWConnection
        let idleSince: Date
    }

    // Stats
    private var _hits = 0
    private var _misses = 0
    private var _evictions = 0

    struct Stats: Sendable {
        var hits: Int
        var misses: Int
        var evictions: Int
        var activeConnections: Int
    }

    var stats: Stats {
        queue.sync {
            let active = pool.values.reduce(0) { $0 + $1.count }
            return Stats(hits: _hits, misses: _misses,
                         evictions: _evictions, activeConnections: active)
        }
    }

    init() {
        startCleanupTimer()
    }

    // MARK: - Get / return connections

    /// Get a reusable connection to host:port, or nil if none available.
    func get(host: String, port: UInt16) -> NWConnection? {
        let key = "\(host):\(port)"
        return queue.sync { () -> NWConnection? in
            guard var conns = pool[key], !conns.isEmpty else {
                _misses += 1
                return nil
            }
            // Take the most recently idle connection (least likely to be stale)
            let entry = conns.removeLast()
            pool[key] = conns

            // Check if still alive
            if entry.connection.state == .ready {
                _hits += 1
                return entry.connection
            } else {
                entry.connection.cancel()
                _misses += 1
                return nil
            }
        }
    }

    /// Return a connection to the pool for reuse.
    func put(host: String, port: UInt16, connection: NWConnection) {
        let key = "\(host):\(port)"
        queue.async { [weak self] in
            guard let self else { connection.cancel(); return }
            guard connection.state == .ready else {
                connection.cancel()
                return
            }
            var conns = self.pool[key] ?? []
            if conns.count >= self.maxIdlePerHost {
                // Evict oldest
                let old = conns.removeFirst()
                old.connection.cancel()
                self._evictions += 1
            }
            conns.append(PooledConnection(connection: connection, idleSince: Date()))
            self.pool[key] = conns
        }
    }

    /// Drain all pooled connections.
    func drain() {
        queue.async { [weak self] in
            guard let self else { return }
            for (_, conns) in self.pool {
                for c in conns { c.connection.cancel() }
            }
            self.pool.removeAll()
        }
    }

    func configure(maxIdle: Int, timeout: TimeInterval) {
        queue.async { [weak self] in
            self?.maxIdlePerHost = maxIdle
            self?.idleTimeout = timeout
        }
    }

    // MARK: - Cleanup

    private func startCleanupTimer() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 10, repeating: 10)
        timer.setEventHandler { [weak self] in
            self?.evictExpired()
        }
        timer.resume()
        cleanupTimer = timer
    }

    private func evictExpired() {
        let now = Date()
        for (key, conns) in pool {
            let alive = conns.filter { entry in
                let expired = now.timeIntervalSince(entry.idleSince) > idleTimeout
                if expired || entry.connection.state != .ready {
                    entry.connection.cancel()
                    _evictions += 1
                    return false
                }
                return true
            }
            if alive.isEmpty {
                pool.removeValue(forKey: key)
            } else {
                pool[key] = alive
            }
        }
    }

    deinit {
        cleanupTimer?.cancel()
        for (_, conns) in pool {
            for c in conns { c.connection.cancel() }
        }
    }
}
