//
//  StatsTimeSeries.swift
//  proxymate
//
//  Rolling time-series data for the Stats charts. Stores per-second
//  snapshots for the last 60 seconds. Updated by AppState on each event.
//

import Foundation
import Combine

@MainActor
final class StatsTimeSeries: ObservableObject {

    struct DataPoint: Identifiable {
        let id = UUID()
        let timestamp: Date
        let allowed: Int
        let blocked: Int
    }

    @Published var points: [DataPoint] = []
    private let maxPoints = 60  // 60 seconds of history

    private var currentSecond: Date = Date()
    private var allowedThisSecond: Int = 0
    private var blockedThisSecond: Int = 0
    private var timer: Timer?

    init() {
        // Seed with zeros
        let now = Date()
        for i in (0..<maxPoints).reversed() {
            points.append(DataPoint(
                timestamp: now.addingTimeInterval(-Double(i)),
                allowed: 0, blocked: 0
            ))
        }
        // Tick every second
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.tick()
            }
        }
    }

    func recordAllowed() { allowedThisSecond += 1 }
    func recordBlocked() { blockedThisSecond += 1 }

    private func tick() {
        let point = DataPoint(
            timestamp: Date(),
            allowed: allowedThisSecond,
            blocked: blockedThisSecond
        )
        points.append(point)
        if points.count > maxPoints {
            points.removeFirst(points.count - maxPoints)
        }
        allowedThisSecond = 0
        blockedThisSecond = 0
    }
}
