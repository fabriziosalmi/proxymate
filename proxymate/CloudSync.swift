//
//  CloudSync.swift
//  proxymate
//
//  Syncs WAF rules and allowlist between Macs via iCloud
//  (NSUbiquitousKeyValueStore). Opt-in. Max 1 MB total.
//
//  Strategy: last-write-wins merge. On remote change notification,
//  merge incoming rules with local ones (union by pattern, prefer
//  newer enabled state).
//

import Foundation

nonisolated struct CloudSyncSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var syncRules: Bool = true
    var syncAllowlist: Bool = true
    var lastSyncDate: Date?
}

@MainActor
final class CloudSync {

    static let shared = CloudSync()

    private let store = NSUbiquitousKeyValueStore.default
    private let rulesKey = "proxymate.cloud.rules"
    private let allowlistKey = "proxymate.cloud.allowlist"
    private var observer: NSObjectProtocol?

    var onRemoteChange: (([WAFRule], [AllowEntry]) -> Void)?

    func start() {
        // Listen for remote changes
        observer = NotificationCenter.default.addObserver(
            forName: NSUbiquitousKeyValueStore.didChangeExternallyNotification,
            object: store,
            queue: .main
        ) { [weak self] notification in
            self?.handleRemoteChange(notification)
        }
        store.synchronize()
    }

    func stop() {
        if let observer {
            NotificationCenter.default.removeObserver(observer)
        }
        observer = nil
    }

    // MARK: - Push

    func pushRules(_ rules: [WAFRule]) {
        guard let data = try? JSONEncoder().encode(rules) else { return }
        store.set(data, forKey: rulesKey)
        store.synchronize()
    }

    func pushAllowlist(_ entries: [AllowEntry]) {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        store.set(data, forKey: allowlistKey)
        store.synchronize()
    }

    // MARK: - Pull + merge

    private func handleRemoteChange(_ notification: Notification) {
        guard let userInfo = notification.userInfo,
              let reason = userInfo[NSUbiquitousKeyValueStoreChangeReasonKey] as? Int,
              reason == NSUbiquitousKeyValueStoreServerChange ||
              reason == NSUbiquitousKeyValueStoreInitialSyncChange else { return }

        var remoteRules: [WAFRule] = []
        var remoteAllow: [AllowEntry] = []

        if let data = store.data(forKey: rulesKey),
           let rules = try? JSONDecoder().decode([WAFRule].self, from: data) {
            remoteRules = rules
        }
        if let data = store.data(forKey: allowlistKey),
           let entries = try? JSONDecoder().decode([AllowEntry].self, from: data) {
            remoteAllow = entries
        }

        onRemoteChange?(remoteRules, remoteAllow)
    }

    // MARK: - Merge logic

    /// Merge remote rules into local. Union by pattern, keep local if conflict.
    static func mergeRules(local: [WAFRule], remote: [WAFRule]) -> [WAFRule] {
        var result = local
        let localPatterns = Set(local.map { $0.pattern.lowercased() })
        for rule in remote {
            if !localPatterns.contains(rule.pattern.lowercased()) {
                result.append(rule)
            }
        }
        return result
    }

    static func mergeAllowlist(local: [AllowEntry], remote: [AllowEntry]) -> [AllowEntry] {
        var result = local
        let localPatterns = Set(local.map { $0.pattern.lowercased() })
        for entry in remote {
            if !localPatterns.contains(entry.pattern.lowercased()) {
                result.append(entry)
            }
        }
        return result
    }
}
