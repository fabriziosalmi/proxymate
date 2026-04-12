//
//  AITracker.swift
//  proxymate
//
//  Tracks AI/LLM API usage: detects provider from host, extracts token
//  counts from response bodies (JSON), calculates cost estimates.
//  Thread-safe via serial queue.
//

import Foundation

nonisolated final class AITracker: @unchecked Sendable {

    static let shared = AITracker()

    private let queue = DispatchQueue(label: "proxymate.aitracker", qos: .utility)
    private var providers: [AIProvider] = AIProvider.builtIn
    private var stats: [String: AIProviderStats] = [:]  // keyed by provider id
    private var settings = AISettings()
    private var dailySpend: Double = 0
    private var dailyResetDate: Date = Calendar.current.startOfDay(for: Date())
    private var monthlySpend: Double = 0
    private var monthlyResetYearMonth: Int = {
        let cal = Calendar.current; let now = Date()
        return cal.component(.year, from: now) * 100 + cal.component(.month, from: now)
    }()

    // MARK: - Configuration

    func configure(providers: [AIProvider], settings: AISettings) {
        queue.async { [weak self] in
            self?.providers = providers
            self?.settings = settings
        }
    }

    func updateSettings(_ s: AISettings) {
        queue.async { [weak self] in self?.settings = s }
    }

    // MARK: - Detection

    struct DetectResult: Sendable {
        let provider: AIProvider
    }

    /// Check if a host belongs to a known AI provider. Returns nil if not AI.
    func detect(host: String) -> DetectResult? {
        let snapshot = queue.sync { providers }
        for p in snapshot where p.matchesHost(host) {
            return DetectResult(provider: p)
        }
        return nil
    }

    /// Check if a provider is blocked (by user or budget exceeded).
    func isBlocked(providerId: String) -> (blocked: Bool, reason: String?) {
        queue.sync {
            if settings.blockedProviders.contains(providerId) {
                return (true, "Provider blocked by user")
            }
            if settings.dailyBudgetUSD > 0 {
                resetDailyIfNeeded()
                if dailySpend >= settings.dailyBudgetUSD {
                    return (true, "Daily budget exceeded ($\(String(format: "%.2f", settings.dailyBudgetUSD)))")
                }
            }
            if settings.monthlyBudgetUSD > 0 {
                resetMonthlyIfNeeded()
                if monthlySpend >= settings.monthlyBudgetUSD {
                    return (true, "Monthly budget exceeded ($\(String(format: "%.2f", settings.monthlyBudgetUSD)))")
                }
            }
            return (false, nil)
        }
    }

    /// Check if a specific model is allowed. Call with the model name
    /// extracted from the request body.
    func isModelBlocked(_ model: String) -> (blocked: Bool, reason: String?) {
        let s = queue.sync { settings }
        let m = model.lowercased()

        // Blocklist takes priority
        if s.modelBlocklist.contains(where: { m.contains($0.lowercased()) }) {
            return (true, "Model '\(model)' is blocklisted")
        }

        // If allowlist is non-empty, model must match at least one entry
        if !s.modelAllowlist.isEmpty {
            let allowed = s.modelAllowlist.contains(where: { m.contains($0.lowercased()) })
            if !allowed {
                return (true, "Model '\(model)' not in allowlist")
            }
        }

        return (false, nil)
    }

    /// Extract the "model" field from a request body (JSON).
    /// Used to check model allowlist before forwarding.
    func extractModelFromRequest(_ body: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let model = json["model"] as? String else { return nil }
        return model
    }

    // MARK: - Token extraction from response body

    struct UsageResult: Sendable {
        let providerId: String
        let model: String
        let promptTokens: Int
        let completionTokens: Int
        let estimatedCost: Double
    }

    /// Parse a completed response body to extract token usage.
    /// Handles both regular JSON responses and SSE streams (concatenates
    /// the last `data:` line which typically contains the usage summary).
    func extractUsage(provider: AIProvider, responseBody: Data) -> UsageResult? {
        guard let text = String(data: responseBody, encoding: .utf8) else { return nil }

        // For SSE streams, find the last `data: {...}` line with usage info
        let jsonText: String
        if text.contains("data: ") {
            let lines = text.components(separatedBy: "\n")
            let dataLines = lines.compactMap { line -> String? in
                guard line.hasPrefix("data: ") else { return nil }
                let payload = String(line.dropFirst(6))
                return payload == "[DONE]" ? nil : payload
            }
            // Usage is typically in the last data chunk
            jsonText = dataLines.last ?? text
        } else {
            jsonText = text
        }

        guard let jsonData = jsonText.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            return nil
        }

        let prompt = extractInt(from: json, path: provider.promptTokenPath) ?? 0
        let completion = extractInt(from: json, path: provider.responseTokenPath) ?? 0
        guard prompt > 0 || completion > 0 else { return nil }

        let model = (json["model"] as? String) ?? "unknown"
        let pricing = AIModelPricing.find(model: model, provider: provider.id)
        let cost = pricing?.cost(promptTokens: prompt, completionTokens: completion) ?? 0

        // Update stats
        queue.async { [weak self] in
            self?.record(providerId: provider.id, prompt: prompt, completion: completion, cost: cost)
        }

        return UsageResult(
            providerId: provider.id,
            model: model,
            promptTokens: prompt,
            completionTokens: completion,
            estimatedCost: cost
        )
    }

    // MARK: - Stats

    func getStats() -> [String: AIProviderStats] {
        queue.sync { stats }
    }

    func getTotalSpend() -> (daily: Double, monthly: Double) {
        queue.sync {
            resetDailyIfNeeded()
            resetMonthlyIfNeeded()
            return (dailySpend, monthlySpend)
        }
    }

    func resetStats() {
        queue.async { [weak self] in
            self?.stats.removeAll()
            self?.dailySpend = 0
            self?.monthlySpend = 0
        }
    }

    // MARK: - Internal

    private func record(providerId: String, prompt: Int, completion: Int, cost: Double) {
        var s = stats[providerId] ?? AIProviderStats(providerId: providerId)
        s.requests += 1
        s.promptTokens += prompt
        s.completionTokens += completion
        s.estimatedCostUSD += cost
        s.lastSeen = Date()
        stats[providerId] = s

        resetDailyIfNeeded()
        resetMonthlyIfNeeded()
        dailySpend += cost
        monthlySpend += cost
    }

    private func resetDailyIfNeeded() {
        let today = Calendar.current.startOfDay(for: Date())
        if today > dailyResetDate {
            dailySpend = 0
            dailyResetDate = today
        }
    }

    private func resetMonthlyIfNeeded() {
        let cal = Calendar.current
        let now = Date()
        let year = cal.component(.year, from: now)
        let month = cal.component(.month, from: now)
        let yearMonth = year * 100 + month
        if yearMonth != monthlyResetYearMonth {
            monthlySpend = 0
            monthlyResetYearMonth = yearMonth
        }
    }

    /// Navigate a dot-separated JSON key path like "usage.completion_tokens".
    private func extractInt(from json: [String: Any], path: String) -> Int? {
        let keys = path.split(separator: ".").map(String.init)
        var current: Any = json
        for key in keys {
            if let dict = current as? [String: Any], let next = dict[key] {
                current = next
            } else {
                return nil
            }
        }
        if let i = current as? Int { return i }
        if let d = current as? Double { return Int(d) }
        if let s = current as? String { return Int(s) }
        return nil
    }
}
