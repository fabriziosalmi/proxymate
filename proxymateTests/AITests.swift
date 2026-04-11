import XCTest
@testable import proxymate

final class AITests: XCTestCase {

    // MARK: - Provider detection

    func testDetectOpenAI() {
        let result = AITracker.shared.detect(host: "api.openai.com")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.provider.id, "openai")
    }

    func testDetectAnthropic() {
        let result = AITracker.shared.detect(host: "api.anthropic.com")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.provider.id, "anthropic")
    }

    func testDetectGroq() {
        let result = AITracker.shared.detect(host: "api.groq.com")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.provider.id, "groq")
    }

    func testNoDetectionForRandomHost() {
        XCTAssertNil(AITracker.shared.detect(host: "example.com"))
        XCTAssertNil(AITracker.shared.detect(host: "google.com"))
    }

    // MARK: - Token extraction

    func testExtractOpenAIUsage() {
        let json = """
        {"id":"chatcmpl-123","model":"gpt-4o","usage":{"prompt_tokens":50,"completion_tokens":100}}
        """
        let provider = AIProvider.builtIn.first { $0.id == "openai" }!
        let result = AITracker.shared.extractUsage(provider: provider,
                                                     responseBody: json.data(using: .utf8)!)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.promptTokens, 50)
        XCTAssertEqual(result?.completionTokens, 100)
        XCTAssertEqual(result?.model, "gpt-4o")
    }

    func testExtractAnthropicUsage() {
        let json = """
        {"id":"msg_01","model":"claude-sonnet-4","usage":{"input_tokens":30,"output_tokens":200}}
        """
        let provider = AIProvider.builtIn.first { $0.id == "anthropic" }!
        let result = AITracker.shared.extractUsage(provider: provider,
                                                     responseBody: json.data(using: .utf8)!)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.promptTokens, 30)
        XCTAssertEqual(result?.completionTokens, 200)
    }

    func testExtractFromSSEStream() {
        let stream = """
        data: {"choices":[{"delta":{"content":"Hi"}}]}

        data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5},"model":"gpt-4o-mini"}

        data: [DONE]
        """
        let provider = AIProvider.builtIn.first { $0.id == "openai" }!
        let result = AITracker.shared.extractUsage(provider: provider,
                                                     responseBody: stream.data(using: .utf8)!)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.completionTokens, 5)
    }

    func testNoUsageInNonAIResponse() {
        let html = "<html><body>Hello</body></html>"
        let provider = AIProvider.builtIn.first { $0.id == "openai" }!
        let result = AITracker.shared.extractUsage(provider: provider,
                                                     responseBody: html.data(using: .utf8)!)
        XCTAssertNil(result)
    }

    // MARK: - Model allowlist/blocklist

    func testModelBlocklist() {
        AITracker.shared.updateSettings(AISettings(
            modelBlocklist: ["gpt-4-turbo"]
        ))
        let (blocked, _) = AITracker.shared.isModelBlocked("gpt-4-turbo-2024-04-09")
        XCTAssertTrue(blocked)
    }

    func testModelAllowlist() {
        AITracker.shared.updateSettings(AISettings(
            modelAllowlist: ["gpt-4o-mini", "claude-haiku"]
        ))
        let (blocked1, _) = AITracker.shared.isModelBlocked("gpt-4o-mini")
        XCTAssertFalse(blocked1)
        let (blocked2, _) = AITracker.shared.isModelBlocked("gpt-4o")
        XCTAssertTrue(blocked2) // not in allowlist
    }

    func testEmptyAllowlistAllowsAll() {
        AITracker.shared.updateSettings(AISettings(modelAllowlist: []))
        let (blocked, _) = AITracker.shared.isModelBlocked("any-model")
        XCTAssertFalse(blocked)
    }

    // MARK: - Pricing

    func testFindPricing() {
        let pricing = AIModelPricing.find(model: "gpt-4o", provider: "openai")
        XCTAssertNotNil(pricing)
        XCTAssertEqual(pricing?.inputPer1M, 2.50)
    }

    func testCostCalculation() {
        let pricing = AIModelPricing(model: "test", provider: "test",
                                      inputPer1M: 10.0, outputPer1M: 30.0)
        let cost = pricing.cost(promptTokens: 1000, completionTokens: 500)
        // 1000/1M * 10 + 500/1M * 30 = 0.01 + 0.015 = 0.025
        XCTAssertEqual(cost, 0.025, accuracy: 0.001)
    }
}
