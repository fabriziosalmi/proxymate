//
//  PoolModels.swift
//  proxymate
//
//  Upstream pool definitions: a named group of N upstreams with a selection
//  strategy, health check config, and optional host-pattern overrides.
//

import Foundation

nonisolated struct UpstreamPool: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var name: String
    var members: [PoolMember]
    var strategy: Strategy
    var healthCheck: HealthCheckConfig
    var isDefault: Bool = false

    enum Strategy: String, Codable, CaseIterable, Identifiable, Sendable {
        case roundRobin      = "Round Robin"
        case weighted        = "Weighted"
        case failover        = "Failover"
        case latencyBased    = "Lowest Latency"
        case leastConns      = "Least Connections"
        case random          = "Random"
        var id: String { rawValue }
    }
}

nonisolated struct PoolMember: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var host: String
    var port: Int
    var weight: Int = 1          // used by Weighted strategy
    var enabled: Bool = true
}

nonisolated struct HealthCheckConfig: Codable, Hashable, Sendable {
    var enabled: Bool = true
    var intervalSeconds: Int = 30
    var timeoutSeconds: Int = 5
    var unhealthyThreshold: Int = 3    // failures before marking down
    var healthyThreshold: Int = 1      // successes before marking up
}

/// Runtime health state for a pool member (not persisted).
nonisolated struct MemberHealth: Sendable {
    var isHealthy: Bool = true
    var consecutiveFailures: Int = 0
    var consecutiveSuccesses: Int = 0
    var lastCheckTime: Date?
    var lastLatencyMs: Double?
    var activeConnections: Int = 0
}

/// Maps host patterns to a specific pool for override routing.
nonisolated struct PoolOverride: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var hostPattern: String      // e.g. "*.github.com", "api.openai.com"
    var poolId: UUID
}
