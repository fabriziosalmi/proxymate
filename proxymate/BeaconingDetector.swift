//
//  BeaconingDetector.swift
//  proxymate
//
//  Detects beaconing patterns: when the same (host, path) pair is requested
//  at fixed intervals (± jitter) for N consecutive times. This is a common
//  indicator of C2 implants, malware check-ins, and data exfiltration.
//
//  Thread-safe via serial queue. Called from LocalProxy on every request.
//

import Foundation

nonisolated struct BeaconingSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var minConsecutive: Int = 5         // consecutive interval-matches before alert
    var jitterTolerancePercent: Int = 20 // ±20% of interval counts as "same"
    var minIntervalSeconds: Double = 5  // ignore intervals < 5s (too noisy)
    var maxIntervalSeconds: Double = 3600 // ignore intervals > 1h
    var action: Action = .alert

    enum Action: String, Codable, CaseIterable, Identifiable, Sendable {
        case alert = "Alert Only"
        case block = "Block"
        var id: String { rawValue }
    }
}

nonisolated final class BeaconingDetector: @unchecked Sendable {

    static let shared = BeaconingDetector()

    private let queue = DispatchQueue(label: "proxymate.beaconing", qos: .utility)
    private var trackers: [String: Tracker] = [:]  // key = "host|path"
    private var settings = BeaconingSettings()

    private struct Tracker {
        var timestamps: [Date] = []
        var intervals: [TimeInterval] = []
        var consecutiveMatches: Int = 0
        var alerted: Bool = false
    }

    struct Detection: Sendable {
        let host: String
        let path: String
        let intervalSeconds: Double
        let consecutiveCount: Int
    }

    func configure(_ s: BeaconingSettings) {
        queue.async { [weak self] in self?.settings = s }
    }

    /// Record a request and check for beaconing. Returns a detection if
    /// the threshold is met.
    func record(host: String, path: String) -> Detection? {
        let key = "\(host.lowercased())|\(path)"
        let now = Date()

        return queue.sync { () -> Detection? in
            guard settings.enabled else { return nil }
            // Prune if trackers grow too large (prevent unbounded memory)
            if trackers.count > 10_000 { pruneTrackers() }

            var tracker = trackers[key] ?? Tracker()
            tracker.timestamps.append(now)

            // Keep last 20 timestamps
            if tracker.timestamps.count > 20 {
                tracker.timestamps.removeFirst(tracker.timestamps.count - 20)
            }

            guard tracker.timestamps.count >= 3,
                  let latest = tracker.timestamps.last,
                  tracker.timestamps.count >= 2 else {
                trackers[key] = tracker
                return nil
            }

            let prev = tracker.timestamps[tracker.timestamps.count - 2]
            let interval = latest.timeIntervalSince(prev)

            // Ignore if outside configured bounds
            guard interval >= settings.minIntervalSeconds &&
                  interval <= settings.maxIntervalSeconds else {
                tracker.consecutiveMatches = 0
                trackers[key] = tracker
                return nil
            }

            // Check if interval matches the previous interval (within jitter)
            if tracker.intervals.isEmpty {
                tracker.intervals.append(interval)
                tracker.consecutiveMatches = 1
            } else if let prevInterval = tracker.intervals.last {
                let tolerance = prevInterval * Double(settings.jitterTolerancePercent) / 100.0
                if abs(interval - prevInterval) <= tolerance {
                    tracker.consecutiveMatches += 1
                    tracker.intervals.append(interval)
                } else {
                    // Reset — interval changed significantly
                    tracker.consecutiveMatches = 1
                    tracker.intervals = [interval]
                }
            }

            // Keep intervals bounded
            if tracker.intervals.count > 20 {
                tracker.intervals.removeFirst()
            }

            trackers[key] = tracker

            if tracker.consecutiveMatches >= settings.minConsecutive && !tracker.alerted {
                tracker.alerted = true
                trackers[key] = tracker
                let avgInterval = tracker.intervals.suffix(settings.minConsecutive)
                    .reduce(0, +) / Double(settings.minConsecutive)
                return Detection(host: host, path: path,
                                 intervalSeconds: avgInterval,
                                 consecutiveCount: tracker.consecutiveMatches)
            }

            return nil
        }
    }

    func reset() {
        queue.async { [weak self] in self?.trackers.removeAll() }
    }

    /// Prune trackers to prevent unbounded growth from unique host|path keys.
    private func pruneTrackers() {
        guard trackers.count > 10_000 else { return }
        // Remove trackers with no recent activity (older than max window)
        let maxWindow = Double(max(settings.minIntervalSeconds * Double(settings.minConsecutive + 5),
                                    Double(settings.maxIntervalSeconds)))
        let now = Date()
        trackers = trackers.filter { _, tracker in
            guard let last = tracker.timestamps.last else { return false }
            return now.timeIntervalSince(last) < maxWindow
        }
    }
}
