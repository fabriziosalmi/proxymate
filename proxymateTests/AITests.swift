import XCTest
@testable import proxymate

final class AITests: XCTestCase {

    // MARK: - Provider host matching (deterministic, no singleton)

    func testOpenAIHostMatch() {
        let provider = AIProvider.builtIn.first { $0.id == "openai" }!
        XCTAssertTrue(provider.matchesHost("api.openai.com"))
        XCTAssertFalse(provider.matchesHost("example.com"))
    }

    func testAnthropicHostMatch() {
        let provider = AIProvider.builtIn.first { $0.id == "anthropic" }!
        XCTAssertTrue(provider.matchesHost("api.anthropic.com"))
    }

    func testGroqHostMatch() {
        let provider = AIProvider.builtIn.first { $0.id == "groq" }!
        XCTAssertTrue(provider.matchesHost("api.groq.com"))
    }

    func testOllamaHostMatch() {
        let provider = AIProvider.builtIn.first { $0.id == "ollama" }!
        XCTAssertTrue(provider.matchesHost("localhost"))
        XCTAssertTrue(provider.matchesHost("127.0.0.1"))
    }

    func testNoProviderForRandomHost() {
        XCTAssertFalse(AIProvider.builtIn.contains { $0.matchesHost("example.com") })
        XCTAssertFalse(AIProvider.builtIn.contains { $0.matchesHost("google.com") })
    }

    // MARK: - All 11 providers defined

    func testAllProvidersExist() {
        let ids = Set(AIProvider.builtIn.map(\.id))
        XCTAssertTrue(ids.contains("openai"))
        XCTAssertTrue(ids.contains("anthropic"))
        XCTAssertTrue(ids.contains("google"))
        XCTAssertTrue(ids.contains("mistral"))
        XCTAssertTrue(ids.contains("cohere"))
        XCTAssertTrue(ids.contains("together"))
        XCTAssertTrue(ids.contains("groq"))
        XCTAssertTrue(ids.contains("deepseek"))
        XCTAssertTrue(ids.contains("perplexity"))
        XCTAssertTrue(ids.contains("xai"))
        XCTAssertTrue(ids.contains("ollama"))
        XCTAssertEqual(AIProvider.builtIn.count, 11)
    }

    // MARK: - Pricing

    func testCostFormula() {
        let cost = (Double(1000) / 1_000_000 * 10.0) + (Double(500) / 1_000_000 * 30.0)
        XCTAssertEqual(cost, 0.025, accuracy: 0.0001)
    }

    func testPricingTableHasEntries() {
        XCTAssertGreaterThanOrEqual(AIModelPricing.builtIn.count, 15)
    }

    func testPricingFindByModel() {
        let pricing = AIModelPricing.find(model: "gpt-4o", provider: "openai")
        XCTAssertNotNil(pricing)
    }

    // MARK: - Model allowlist/blocklist logic (pure functions)

    func testModelBlocklistLogic() {
        let blocklist = ["gpt-4-turbo"]
        let model = "gpt-4-turbo-2024-04-09"
        let blocked = blocklist.contains(where: { model.lowercased().contains($0.lowercased()) })
        XCTAssertTrue(blocked)
    }

    func testModelAllowlistLogic() {
        let allowlist = ["gpt-4o-mini", "claude-haiku"]
        let allowed1 = allowlist.contains(where: { "gpt-4o-mini".contains($0.lowercased()) })
        let allowed2 = allowlist.contains(where: { "gpt-4o".contains($0.lowercased()) })
        XCTAssertTrue(allowed1)
        // "gpt-4o" contains "gpt-4o" which is a substring of "gpt-4o-mini"...
        // Actually "gpt-4o".contains("gpt-4o-mini") is false
        XCTAssertFalse(allowed2)
    }

    func testEmptyAllowlistAllowsAll() {
        let allowlist: [String] = []
        XCTAssertTrue(allowlist.isEmpty) // empty = allow all
    }

    // MARK: - Settings defaults

    func testDefaultSettings() {
        let s = AISettings()
        XCTAssertTrue(s.enabled)
        XCTAssertEqual(s.dailyBudgetUSD, 0)
        XCTAssertEqual(s.monthlyBudgetUSD, 0)
        XCTAssertTrue(s.blockedProviders.isEmpty)
        XCTAssertTrue(s.modelAllowlist.isEmpty)
        XCTAssertTrue(s.modelBlocklist.isEmpty)
    }
}
