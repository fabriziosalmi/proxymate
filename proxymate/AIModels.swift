//
//  AIModels.swift
//  proxymate
//
//  AI/LLM provider definitions, pricing table, and per-provider stats.
//

import Foundation

// MARK: - Provider definitions

nonisolated struct AIProvider: Identifiable, Codable, Hashable, Sendable {
    let id: String
    let name: String
    let icon: String               // SF Symbol name
    let hostPatterns: [String]     // matched against request host
    let responseTokenPath: String  // JSON key path for completion tokens
    let promptTokenPath: String    // JSON key path for prompt tokens
    var blocked: Bool = false

    static let builtIn: [AIProvider] = [
        .init(id: "openai", name: "OpenAI", icon: "brain",
              hostPatterns: ["api.openai.com"],
              responseTokenPath: "usage.completion_tokens",
              promptTokenPath: "usage.prompt_tokens"),
        .init(id: "anthropic", name: "Anthropic", icon: "brain.head.profile",
              hostPatterns: ["api.anthropic.com"],
              responseTokenPath: "usage.output_tokens",
              promptTokenPath: "usage.input_tokens"),
        .init(id: "google", name: "Google AI", icon: "g.circle",
              hostPatterns: ["generativelanguage.googleapis.com", "aiplatform.googleapis.com"],
              responseTokenPath: "usageMetadata.candidatesTokenCount",
              promptTokenPath: "usageMetadata.promptTokenCount"),
        .init(id: "mistral", name: "Mistral", icon: "wind",
              hostPatterns: ["api.mistral.ai"],
              responseTokenPath: "usage.completion_tokens",
              promptTokenPath: "usage.prompt_tokens"),
        .init(id: "cohere", name: "Cohere", icon: "waveform",
              hostPatterns: ["api.cohere.ai", "api.cohere.com"],
              responseTokenPath: "meta.billed_units.output_tokens",
              promptTokenPath: "meta.billed_units.input_tokens"),
        .init(id: "together", name: "Together", icon: "square.stack.3d.up",
              hostPatterns: ["api.together.xyz"],
              responseTokenPath: "usage.completion_tokens",
              promptTokenPath: "usage.prompt_tokens"),
        .init(id: "groq", name: "Groq", icon: "bolt",
              hostPatterns: ["api.groq.com"],
              responseTokenPath: "usage.completion_tokens",
              promptTokenPath: "usage.prompt_tokens"),
        .init(id: "deepseek", name: "DeepSeek", icon: "magnifyingglass",
              hostPatterns: ["api.deepseek.com"],
              responseTokenPath: "usage.completion_tokens",
              promptTokenPath: "usage.prompt_tokens"),
        .init(id: "perplexity", name: "Perplexity", icon: "questionmark.circle",
              hostPatterns: ["api.perplexity.ai"],
              responseTokenPath: "usage.completion_tokens",
              promptTokenPath: "usage.prompt_tokens"),
        .init(id: "xai", name: "xAI", icon: "xmark.circle",
              hostPatterns: ["api.x.ai"],
              responseTokenPath: "usage.completion_tokens",
              promptTokenPath: "usage.prompt_tokens"),
        .init(id: "ollama", name: "Ollama (local)", icon: "desktopcomputer",
              hostPatterns: ["localhost", "127.0.0.1"],
              responseTokenPath: "eval_count",
              promptTokenPath: "prompt_eval_count"),
    ]

    func matchesHost(_ host: String) -> Bool {
        let h = host.lowercased()
        return hostPatterns.contains(where: { pattern in
            h == pattern || h.hasSuffix("." + pattern)
        })
    }
}

// MARK: - Pricing (per 1M tokens, USD)

nonisolated struct AIModelPricing: Codable, Hashable, Sendable {
    let model: String
    let provider: String
    let inputPer1M: Double
    let outputPer1M: Double

    /// Cost for a given token count.
    func cost(promptTokens: Int, completionTokens: Int) -> Double {
        (Double(promptTokens) / 1_000_000 * inputPer1M) +
        (Double(completionTokens) / 1_000_000 * outputPer1M)
    }

    static let builtIn: [AIModelPricing] = [
        // OpenAI
        .init(model: "gpt-4o",       provider: "openai", inputPer1M: 2.50, outputPer1M: 10.00),
        .init(model: "gpt-4o-mini",  provider: "openai", inputPer1M: 0.15, outputPer1M: 0.60),
        .init(model: "gpt-4-turbo",  provider: "openai", inputPer1M: 10.0, outputPer1M: 30.0),
        .init(model: "o1",           provider: "openai", inputPer1M: 15.0, outputPer1M: 60.0),
        .init(model: "o1-mini",      provider: "openai", inputPer1M: 3.00, outputPer1M: 12.0),
        .init(model: "o3-mini",      provider: "openai", inputPer1M: 1.10, outputPer1M: 4.40),
        // Anthropic
        .init(model: "claude-opus-4", provider: "anthropic", inputPer1M: 15.0, outputPer1M: 75.0),
        .init(model: "claude-sonnet-4", provider: "anthropic", inputPer1M: 3.00, outputPer1M: 15.0),
        .init(model: "claude-haiku-4", provider: "anthropic", inputPer1M: 0.80, outputPer1M: 4.00),
        // Google
        .init(model: "gemini-2.5-pro", provider: "google", inputPer1M: 1.25, outputPer1M: 10.0),
        .init(model: "gemini-2.5-flash", provider: "google", inputPer1M: 0.15, outputPer1M: 0.60),
        // Mistral
        .init(model: "mistral-large", provider: "mistral", inputPer1M: 2.00, outputPer1M: 6.00),
        .init(model: "mistral-small", provider: "mistral", inputPer1M: 0.10, outputPer1M: 0.30),
        // DeepSeek
        .init(model: "deepseek-chat", provider: "deepseek", inputPer1M: 0.14, outputPer1M: 0.28),
        .init(model: "deepseek-reasoner", provider: "deepseek", inputPer1M: 0.55, outputPer1M: 2.19),
        // Groq
        .init(model: "llama-3.3-70b", provider: "groq", inputPer1M: 0.59, outputPer1M: 0.79),
        // Together
        .init(model: "meta-llama/Meta-Llama-3.1-405B", provider: "together", inputPer1M: 3.50, outputPer1M: 3.50),
    ]

    /// Find best-matching pricing for a model string + provider.
    static func find(model: String, provider: String) -> AIModelPricing? {
        let m = model.lowercased()
        return builtIn.first { m.contains($0.model.lowercased()) && $0.provider == provider }
            ?? builtIn.first { m.contains($0.model.lowercased()) }
    }
}

// MARK: - Per-provider runtime stats

nonisolated struct AIProviderStats: Codable, Hashable, Sendable {
    var providerId: String
    var requests: Int = 0
    var promptTokens: Int = 0
    var completionTokens: Int = 0
    var estimatedCostUSD: Double = 0
    var lastSeen: Date?
}

// MARK: - AI settings

nonisolated struct AISettings: Codable, Hashable, Sendable {
    var enabled: Bool = true
    var dailyBudgetUSD: Double = 0     // 0 = no cap
    var monthlyBudgetUSD: Double = 0   // 0 = no cap
    var blockedProviders: [String] = []
    var modelAllowlist: [String] = []  // empty = allow all; non-empty = only these models
    var modelBlocklist: [String] = []  // always block these models (checked first)
}
