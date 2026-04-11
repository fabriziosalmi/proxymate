//
//  ProcessResolver.swift
//  proxymate
//
//  Maps local TCP connections to the originating process (PID → bundle ID).
//  Uses `lsof` to find which process owns a given local port. This enables
//  per-app proxy rules (e.g. "Slack always direct", "block Adobe telemetry").
//
//  Caches results for 5 seconds to avoid calling lsof on every request.
//

import Foundation

nonisolated struct ProcessRule: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var bundleId: String         // e.g. "com.slack.Slack"
    var appName: String          // display name
    var action: Action
    var enabled: Bool = true

    enum Action: String, Codable, CaseIterable, Identifiable, Sendable {
        case allow  = "Always Allow"
        case block  = "Always Block"
        case direct = "Direct (bypass proxy)"
        var id: String { rawValue }
    }
}

nonisolated final class ProcessResolver: @unchecked Sendable {

    static let shared = ProcessResolver()

    private let queue = DispatchQueue(label: "proxymate.processresolver", qos: .utility)
    private var cache: [UInt16: CacheEntry] = [:]  // local port → process info
    private let cacheTTL: TimeInterval = 5

    struct CacheEntry {
        let pid: Int32
        let bundleId: String
        let timestamp: Date
        var isExpired: Bool { Date().timeIntervalSince(timestamp) > 5 }
    }

    struct ProcessInfo: Sendable {
        let pid: Int32
        let bundleId: String
    }

    // MARK: - Resolve

    /// Resolve which process owns the given local source port.
    func resolve(localPort: UInt16) -> ProcessInfo? {
        // Check cache
        if let cached = cache[localPort], !cached.isExpired {
            return ProcessInfo(pid: cached.pid, bundleId: cached.bundleId)
        }

        // Use lsof to find the process
        let output = runLsof(port: localPort)
        guard let (pid, name) = parseLsofOutput(output) else { return nil }

        // Get bundle ID from PID
        let bundleId = bundleIdForPID(pid) ?? name

        let entry = CacheEntry(pid: pid, bundleId: bundleId, timestamp: Date())
        queue.async { [weak self] in
            self?.cache[localPort] = entry
            // Prune old entries
            self?.cache = self?.cache.filter { !$0.value.isExpired } ?? [:]
        }

        return ProcessInfo(pid: pid, bundleId: bundleId)
    }

    /// Check if a process is affected by any process rule.
    func checkRules(bundleId: String, rules: [ProcessRule]) -> ProcessRule.Action? {
        for rule in rules where rule.enabled {
            if bundleId.lowercased() == rule.bundleId.lowercased() ||
               bundleId.lowercased().contains(rule.bundleId.lowercased()) {
                return rule.action
            }
        }
        return nil
    }

    // MARK: - lsof

    private func runLsof(port: UInt16) -> String {
        let p = Process()
        p.launchPath = "/usr/sbin/lsof"
        p.arguments = ["-i", "TCP:\(port)", "-sTCP:ESTABLISHED", "-n", "-P", "-F", "pc"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        do { try p.run() } catch { return "" }
        p.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(),
                      encoding: .utf8) ?? ""
    }

    private func parseLsofOutput(_ output: String) -> (Int32, String)? {
        var pid: Int32?
        var name: String?
        for line in output.split(separator: "\n") {
            if line.hasPrefix("p") {
                pid = Int32(line.dropFirst())
            } else if line.hasPrefix("c") {
                name = String(line.dropFirst())
            }
        }
        guard let pid, let name else { return nil }
        return (pid, name)
    }

    private func bundleIdForPID(_ pid: Int32) -> String? {
        guard let app = NSRunningApplication(processIdentifier: pid) else { return nil }
        return app.bundleIdentifier
    }
}

import AppKit
