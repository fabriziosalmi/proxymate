//
//  AgentLoopBreaker.swift
//  proxymate
//
//  Detects and kills runaway AI agent loops:
//
//  1. **Identical request loop**: same (host, body_hash) repeated N times
//     in M seconds → the LLM is stuck retrying the same prompt
//  2. **Rapid-fire loop**: same host hit > N times in M seconds regardless
//     of content → agent spinning out of control
//  3. **MCP router loop**: same MCP method+args repeated → broken tool chain
//  4. **Cost runaway**: spend rate exceeding threshold per minute
//
//  On detection: block with 429 Too Many Requests + notification + webhook.
//  Auto-resets after a cooldown period.
//
//  Thread-safe via serial queue.
//

import Foundation
import CommonCrypto

nonisolated struct LoopBreakerSettings: Codable, Hashable, Sendable {
    var enabled: Bool = true

    // Identical content loop (very conservative — must be truly stuck)
    var identicalThreshold: Int = 20      // same body hash N times before WARNING
    var identicalBlockThreshold: Int = 30 // same body hash N times before BLOCK
    var identicalWindowSeconds: Int = 120 // within this window

    // Rapid-fire (any content) — very high to avoid false positives on normal browsing
    var rapidFireThreshold: Int = 200     // requests to same host → WARNING
    var rapidFireBlockThreshold: Int = 500 // requests to same host → BLOCK
    var rapidFireWindowSeconds: Int = 60  // within this window

    // MCP loop — moderate, MCP calls are distinct and structured
    var mcpRepeatThreshold: Int = 5       // same method+args → WARNING
    var mcpBlockThreshold: Int = 8        // same method+args → BLOCK
    var mcpWindowSeconds: Int = 60

    // Cost runaway
    var maxCostPerMinuteUSD: Double = 2.0 // $2/min = $120/hr hard cap (generous)

    // Cooldown after block trip
    var cooldownSeconds: Int = 30         // block for 30s after loop blocked
}

nonisolated final class AgentLoopBreaker: @unchecked Sendable {

    static let shared = AgentLoopBreaker()

    private let queue = DispatchQueue(label: "proxymate.loopbreaker", qos: .userInitiated)
    private(set) var settings = LoopBreakerSettings()

    // Tracking state
    private var identicalHistory: [String: [Date]] = [:]  // body_hash → timestamps
    private var hostHistory: [String: [Date]] = [:]        // host → timestamps
    private var mcpHistory: [String: [Date]] = [:]         // method+args_hash → timestamps
    private var costHistory: [(Date, Double)] = []          // (time, cost)
    private var cooldowns: [String: Date] = [:]             // key → blocked until

    struct LoopDetection: Sendable {
        let kind: Kind
        let severity: Severity
        let host: String
        let detail: String
        let count: Int

        enum Kind: String, Sendable {
            case identicalLoop = "Identical Request Loop"
            case rapidFire     = "Rapid-Fire Loop"
            case mcpLoop       = "MCP Router Loop"
            case costRunaway   = "Cost Runaway"
        }

        /// warn = log + notify but DO NOT block (zero false positive policy)
        /// block = actually return 429 (only after repeated warn threshold exceeded)
        enum Severity: String, Sendable {
            case warn  = "Warning"
            case block = "Blocked"
        }
    }

    func configure(_ s: LoopBreakerSettings) {
        queue.async { [weak self] in self?.settings = s }
    }

    // MARK: - Check (called on every AI-bound request)

    /// Returns a detection if a loop is detected. Severity levels:
    /// - `.warn`: log + notify the user, but DO NOT block (zero false positive policy)
    /// - `.block`: actually return 429 (only when count far exceeds warn threshold)
    /// Returns nil if everything looks normal.
    func check(host: String, bodyData: Data?, mcpMethod: String? = nil,
               cost: Double = 0) -> LoopDetection? {
        return queue.sync { () -> LoopDetection? in
            guard settings.enabled else { return nil }
            let now = Date()
            let h = host.lowercased()

            // Check cooldown first (only active after a block-level detection)
            if let until = cooldowns[h], now < until {
                return LoopDetection(kind: .rapidFire, severity: .block, host: h,
                                      detail: "Blocked for \(settings.cooldownSeconds)s after loop detection", count: 0)
            }

            // 1. Identical content loop
            if let body = bodyData, !body.isEmpty {
                let hash = sha256Short(body)
                let key = "\(h)|\(hash)"
                var times = identicalHistory[key] ?? []
                times.append(now)
                times = times.filter { now.timeIntervalSince($0) < Double(settings.identicalWindowSeconds) }
                identicalHistory[key] = times

                if times.count >= settings.identicalBlockThreshold {
                    trip(host: h)
                    return LoopDetection(kind: .identicalLoop, severity: .block, host: h,
                                          detail: "Identical request body repeated \(times.count)x in \(settings.identicalWindowSeconds)s (hash: \(hash))",
                                          count: times.count)
                }
                if times.count >= settings.identicalThreshold {
                    return LoopDetection(kind: .identicalLoop, severity: .warn, host: h,
                                          detail: "Identical request body repeated \(times.count)x in \(settings.identicalWindowSeconds)s — possible stuck agent (hash: \(hash))",
                                          count: times.count)
                }
            }

            // 2. Rapid-fire to same host
            var hostTimes = hostHistory[h] ?? []
            hostTimes.append(now)
            hostTimes = hostTimes.filter { now.timeIntervalSince($0) < Double(settings.rapidFireWindowSeconds) }
            hostHistory[h] = hostTimes

            if hostTimes.count >= settings.rapidFireBlockThreshold {
                trip(host: h)
                return LoopDetection(kind: .rapidFire, severity: .block, host: h,
                                      detail: "\(hostTimes.count) requests to \(h) in \(settings.rapidFireWindowSeconds)s",
                                      count: hostTimes.count)
            }
            if hostTimes.count >= settings.rapidFireThreshold {
                return LoopDetection(kind: .rapidFire, severity: .warn, host: h,
                                      detail: "\(hostTimes.count) requests to \(h) in \(settings.rapidFireWindowSeconds)s — possible runaway agent",
                                      count: hostTimes.count)
            }

            // 3. MCP method repeat
            if let method = mcpMethod {
                let argsHash = bodyData.map { sha256Short($0) } ?? ""
                let key = "\(h)|\(method)|\(argsHash)"
                var times = mcpHistory[key] ?? []
                times.append(now)
                times = times.filter { now.timeIntervalSince($0) < Double(settings.mcpWindowSeconds) }
                mcpHistory[key] = times

                if times.count >= settings.mcpBlockThreshold {
                    trip(host: h)
                    return LoopDetection(kind: .mcpLoop, severity: .block, host: h,
                                          detail: "MCP \(method) repeated \(times.count)x in \(settings.mcpWindowSeconds)s",
                                          count: times.count)
                }
                if times.count >= settings.mcpRepeatThreshold {
                    return LoopDetection(kind: .mcpLoop, severity: .warn, host: h,
                                          detail: "MCP \(method) repeated \(times.count)x in \(settings.mcpWindowSeconds)s — possible tool loop",
                                          count: times.count)
                }
            }

            // 4. Cost runaway — always blocks (this is a hard safety cap)
            if cost > 0 {
                costHistory.append((now, cost))
                costHistory = costHistory.filter { now.timeIntervalSince($0.0) < 60 }
                let minuteCost = costHistory.reduce(0) { $0 + $1.1 }
                if settings.maxCostPerMinuteUSD > 0 && minuteCost >= settings.maxCostPerMinuteUSD {
                    trip(host: h)
                    return LoopDetection(kind: .costRunaway, severity: .block, host: h,
                                          detail: "$\(String(format: "%.2f", minuteCost))/min exceeds $\(String(format: "%.2f", settings.maxCostPerMinuteUSD))/min limit",
                                          count: costHistory.count)
                }
            }

            // Prune stale entries periodically or when key count grows too large
            let totalKeys = identicalHistory.count + hostHistory.count + mcpHistory.count
            if totalKeys > 50_000 || Int.random(in: 0..<100) == 0 { prune() }
            return nil
        }
    }

    /// Record a cost event (called after AI usage extraction).
    func recordCost(_ cost: Double) {
        guard cost > 0 else { return }
        queue.async { [weak self] in
            self?.costHistory.append((Date(), cost))
        }
    }

    func reset() {
        queue.async { [weak self] in
            self?.identicalHistory.removeAll()
            self?.hostHistory.removeAll()
            self?.mcpHistory.removeAll()
            self?.costHistory.removeAll()
            self?.cooldowns.removeAll()
        }
    }

    // MARK: - Internal

    private func trip(host: String) {
        let until = Date().addingTimeInterval(Double(settings.cooldownSeconds))
        cooldowns[host] = until
    }

    private func prune() {
        let now = Date()
        let maxWindow = Double(max(settings.identicalWindowSeconds,
                                    settings.rapidFireWindowSeconds,
                                    settings.mcpWindowSeconds))
        identicalHistory = identicalHistory.filter { !$0.value.allSatisfy { now.timeIntervalSince($0) > maxWindow } }
        hostHistory = hostHistory.filter { !$0.value.allSatisfy { now.timeIntervalSince($0) > maxWindow } }
        mcpHistory = mcpHistory.filter { !$0.value.allSatisfy { now.timeIntervalSince($0) > maxWindow } }
        cooldowns = cooldowns.filter { now < $0.value }
    }

    private func sha256Short(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: 32)
        _ = data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
    }
}
