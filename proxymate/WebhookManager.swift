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
    /// Number of retry attempts currently scheduled. Bounded so a stuck
    /// receiver can't grow the in-flight retry pile without limit.
    private var pendingRetries = 0
    private let maxAttempts = 3                 // initial + 2 retries
    private let maxPendingRetries = 100
    /// Backoff schedule indexed by attempt number (1-based for the *next*
    /// attempt: attempt 2 waits 5s, attempt 3 waits 30s).
    private let retryDelays: [TimeInterval] = [5, 30]

    /// Shared URLSession that bypasses system proxy.
    private let directSession: URLSession = {
        let config = URLSessionConfiguration.default
        config.connectionProxyDictionary = [:]
        config.timeoutIntervalForRequest = 10
        return URLSession(configuration: config)
    }()

    /// Reject webhook URLs that embed `user:pass@` in the userinfo
    /// component. Without this, a string like
    /// `https://api:secret@hooks.example.com/foo` ends up in
    /// `WebhookSettings.urls`, JSON-encoded, and persisted to UserDefaults
    /// in plaintext (anyone with read access to the user's defaults plist
    /// reads the secret). Returns the URL unchanged when safe, nil
    /// otherwise. Operators that need Basic Auth must use a header-based
    /// scheme; secrets do not belong in URL strings.
    static func isAcceptable(_ urlString: String) -> Bool {
        guard let comps = URLComponents(string: urlString),
              let scheme = comps.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              comps.host?.isEmpty == false,
              comps.user == nil, comps.password == nil
        else { return false }
        return true
    }

    func configure(_ s: WebhookSettings) {
        // Defense-in-depth: even if a user:pass URL slipped through input
        // validation (older settings file, hand-edited plist), drop it
        // here before it gets a chance to be POSTed.
        var cleaned = s
        let original = cleaned.urls
        cleaned.urls = original.filter { Self.isAcceptable($0) }
        let dropped = original.count - cleaned.urls.count
        queue.async { [weak self] in
            self?.settings = cleaned
            if dropped > 0 {
                NSLog("[Webhook] dropped \(dropped) URL(s) failing validation (userinfo / non-http scheme / empty host)")
            }
        }
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
        // Resolve the flag KeyPath against a snapshot of settings BEFORE
        // entering the `@Sendable` closure. Capturing the KeyPath itself
        // would warn (KeyPath isn't Sendable). The snapshot read is safe
        // because the canonical settings live on the queue and we re-check
        // `settings.enabled` once we're on the queue.
        let flagAllows = flag.map { settings[keyPath: $0] } ?? true
        queue.async { [weak self] in
            guard let self else { return }
            // Read settings on queue thread to avoid data race
            guard self.settings.enabled else { return }
            guard flagAllows else { return }

            // Debounce + prune stale entries to prevent unbounded growth
            let debounce = TimeInterval(self.settings.debounceSeconds)
            if let last = self.lastSent[key], Date().timeIntervalSince(last) < debounce { return }
            self.lastSent[key] = Date()
            if self.lastSent.count > 1000 {
                let cutoff = Date().addingTimeInterval(-debounce * 2)
                self.lastSent = self.lastSent.filter { $0.value > cutoff }
            }

            guard let body = try? JSONSerialization.data(withJSONObject: payload) else { return }

            for urlString in self.settings.urls {
                self.deliver(urlString: urlString, body: body, attempt: 1)
            }
        }
    }

    /// Send one webhook POST. On transient failure (transport error or
    /// 5xx) schedule a bounded retry on the same queue with exponential
    /// backoff; 4xx is treated as terminal (the receiver rejected the
    /// payload — retrying won't help). The total in-flight retry count
    /// is capped at `maxPendingRetries` so a long outage on the receiver
    /// can't grow the pile without limit.
    private func deliver(urlString: String, body: Data, attempt: Int) {
        guard let url = URL(string: urlString) else { return }
        var request = URLRequest(url: url, timeoutInterval: 10)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Proxymate/1.0", forHTTPHeaderField: "User-Agent")
        request.httpBody = body

        directSession.dataTask(with: request) { [weak self] _, response, error in
            guard let self else { return }
            let transient: Bool
            let label: String
            if let error {
                transient = true
                label = "transport error: \(error.localizedDescription)"
            } else if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                transient = (500...599).contains(http.statusCode)
                label = "HTTP \(http.statusCode)"
            } else {
                return // 2xx — done.
            }

            self.queue.async {
                if !transient || attempt >= self.maxAttempts {
                    NSLog("[Webhook] POST \(urlString) failed after \(attempt) attempt(s) (\(label))")
                    return
                }
                if self.pendingRetries >= self.maxPendingRetries {
                    NSLog("[Webhook] retry queue full (\(self.maxPendingRetries)) — dropping \(urlString) after attempt \(attempt) (\(label))")
                    return
                }
                let delay = self.retryDelays[min(attempt - 1, self.retryDelays.count - 1)]
                self.pendingRetries += 1
                NSLog("[Webhook] POST \(urlString) \(label); retry \(attempt + 1)/\(self.maxAttempts) in \(Int(delay))s")
                self.queue.asyncAfter(deadline: .now() + delay) { [weak self] in
                    guard let self else { return }
                    self.pendingRetries -= 1
                    self.deliver(urlString: urlString, body: body, attempt: attempt + 1)
                }
            }
        }.resume()
    }
}
