//
//  NotificationManager.swift
//  proxymate
//
//  Sends macOS user notifications on first block per rule per session.
//  Avoids spamming by tracking which rules have already triggered.
//

import Foundation
import UserNotifications

@MainActor
final class NotificationManager {

    static let shared = NotificationManager()

    private var notifiedRules: Set<String> = []
    private var authorized = false

    func setup() {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            Task { @MainActor in
                self.authorized = granted
            }
        }
    }

    func notifyBlock(host: String, ruleName: String) {
        guard authorized else { return }
        let key = ruleName
        guard !notifiedRules.contains(key) else { return }
        notifiedRules.insert(key)

        let content = UNMutableNotificationContent()
        content.title = "Proxymate Blocked"
        content.body = "\(host) blocked by \(ruleName)"
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: "block-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }

    func notifyExfiltration(host: String, patternName: String) {
        guard authorized else { return }
        let key = "exfil-\(patternName)"
        guard !notifiedRules.contains(key) else { return }
        notifiedRules.insert(key)

        let content = UNMutableNotificationContent()
        content.title = "Exfiltration Blocked"
        content.body = "Secret leak detected: \(patternName) → \(host)"
        content.sound = .defaultCritical

        let request = UNNotificationRequest(
            identifier: "exfil-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }

    func notifyBudget(provider: String, reason: String) {
        guard authorized else { return }
        let key = "budget-\(provider)"
        guard !notifiedRules.contains(key) else { return }
        notifiedRules.insert(key)

        let content = UNMutableNotificationContent()
        content.title = "AI Budget Exceeded"
        content.body = "\(provider): \(reason)"
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: "budget-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }

    func resetSession() {
        notifiedRules.removeAll()
    }
}
