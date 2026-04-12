//
//  WebhookManager.swift
//  proxymate
//
//  Sends JSON POST webhook events on block, exfiltration, and budget
//  triggers. Supports multiple webhook URLs. Debounces to avoid spam.
//

import Foundation

nonisolated struct WebhookSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var urls: [String] = []      // POST targets
    var onBlock: Bool = true
    var onExfiltration: Bool = true
    var onBudget: Bool = true
    var debounceSeconds: Int = 5
}

nonisolated final class WebhookManager: @unchecked Sendable {

    static let shared = WebhookManager()

    private let queue = DispatchQueue(label: "proxymate.webhook", qos: .utility)
    private var settings = WebhookSettings()
    private var lastSent: [String: Date] = [:]  // event key → last sent time

    func configure(_ s: WebhookSettings) {
        queue.async { [weak self] in self?.settings = s }
    }

    // MARK: - Event senders

    func sendBlock(host: String, ruleName: String) {
        send(event: "block", key: "block-\(ruleName)", guard: \.onBlock, payload: [
            "event": "block",
            "host": host,
            "rule": ruleName,
            "timestamp": ISO8601DateFormatter().string(from: Date()),
        ])
    }

    func sendExfiltration(host: String, patternName: String, severity: String, preview: String) {
        send(event: "exfiltration", key: "exfil-\(patternName)", guard: \.onExfiltration, payload: [
            "event": "exfiltration",
            "host": host,
            "pattern": patternName,
            "severity": severity,
            "preview": preview,
            "timestamp": ISO8601DateFormatter().string(from: Date()),
        ])
    }

    func sendBudget(provider: String, reason: String) {
        send(event: "budget", key: "budget-\(provider)", guard: \.onBudget, payload: [
            "event": "budget_exceeded",
            "provider": provider,
            "reason": reason,
            "timestamp": ISO8601DateFormatter().string(from: Date()),
        ])
    }

    // MARK: - Internal

    private func send(event: String, key: String, guard flag: KeyPath<WebhookSettings, Bool>? = nil, payload: [String: String]) {
        queue.async { [weak self] in
            guard let self else { return }
            // Read settings on queue thread to avoid data race
            guard self.settings.enabled else { return }
            if let flag, !self.settings[keyPath: flag] { return }

            // Debounce
            let debounce = TimeInterval(self.settings.debounceSeconds)
            if let last = self.lastSent[key], Date().timeIntervalSince(last) < debounce { return }
            self.lastSent[key] = Date()

            guard let body = try? JSONSerialization.data(withJSONObject: payload) else { return }

            for urlString in self.settings.urls {
                guard let url = URL(string: urlString) else { continue }
                var request = URLRequest(url: url, timeoutInterval: 10)
                request.httpMethod = "POST"
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                request.setValue("Proxymate/1.0", forHTTPHeaderField: "User-Agent")
                request.httpBody = body
                let config = URLSessionConfiguration.default
                config.connectionProxyDictionary = [:]
                URLSession(configuration: config).dataTask(with: request).resume()
            }
        }
    }
}
