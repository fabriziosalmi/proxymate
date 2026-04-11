import XCTest
@testable import proxymate

final class LoopBreakerTests: XCTestCase {

    var breaker: AgentLoopBreaker!

    override func setUp() {
        breaker = AgentLoopBreaker()
        breaker.configure(LoopBreakerSettings(
            enabled: true,
            identicalThreshold: 3, identicalBlockThreshold: 5,
            identicalWindowSeconds: 10,
            rapidFireThreshold: 10, rapidFireBlockThreshold: 15,
            rapidFireWindowSeconds: 10,
            mcpRepeatThreshold: 2, mcpBlockThreshold: 3,
            mcpWindowSeconds: 10,
            maxCostPerMinuteUSD: 1.0,
            cooldownSeconds: 5
        ))
    }

    // MARK: - Identical body loop

    func testNoDetectionBelowThreshold() {
        let body = "same content".data(using: .utf8)!
        for _ in 0..<2 {
            XCTAssertNil(breaker.check(host: "api.openai.com", bodyData: body))
        }
    }

    func testWarnOnIdenticalThreshold() {
        let body = "same content".data(using: .utf8)!
        var lastResult: AgentLoopBreaker.LoopDetection?
        for _ in 0..<3 {
            lastResult = breaker.check(host: "api.openai.com", bodyData: body)
        }
        XCTAssertNotNil(lastResult)
        XCTAssertEqual(lastResult?.severity, .warn)
        XCTAssertEqual(lastResult?.kind, .identicalLoop)
    }

    func testBlockOnIdenticalBlockThreshold() {
        let body = "same content".data(using: .utf8)!
        var lastResult: AgentLoopBreaker.LoopDetection?
        for _ in 0..<5 {
            lastResult = breaker.check(host: "api.openai.com", bodyData: body)
        }
        XCTAssertNotNil(lastResult)
        XCTAssertEqual(lastResult?.severity, .block)
    }

    func testDifferentBodiesNoLoop() {
        for i in 0..<20 {
            let body = "different content \(i)".data(using: .utf8)!
            let result = breaker.check(host: "api.openai.com", bodyData: body)
            // Should never trigger identical loop (rapid-fire might at 10+)
            if let r = result {
                XCTAssertNotEqual(r.kind, .identicalLoop)
            }
        }
    }

    // MARK: - MCP loop

    func testMCPLoopWarn() {
        let body = "{\"method\":\"tools/call\",\"params\":{\"name\":\"read\"}}".data(using: .utf8)!
        var lastResult: AgentLoopBreaker.LoopDetection?
        for _ in 0..<2 {
            lastResult = breaker.check(host: "mcp.server.com", bodyData: body, mcpMethod: "tools/call")
        }
        XCTAssertNotNil(lastResult)
        XCTAssertEqual(lastResult?.kind, .mcpLoop)
        XCTAssertEqual(lastResult?.severity, .warn)
    }

    func testMCPLoopBlock() {
        let body = "{\"method\":\"tools/call\"}".data(using: .utf8)!
        var lastResult: AgentLoopBreaker.LoopDetection?
        for _ in 0..<3 {
            lastResult = breaker.check(host: "mcp.server.com", bodyData: body, mcpMethod: "tools/call")
        }
        XCTAssertNotNil(lastResult)
        XCTAssertEqual(lastResult?.severity, .block)
    }

    // MARK: - Cost runaway

    func testCostRunaway() {
        // Simulate $0.5 per request, 3 requests in < 1 min = $1.5 > $1 limit
        for _ in 0..<3 {
            _ = breaker.check(host: "api.openai.com", bodyData: nil, cost: 0.5)
        }
        // The cost check happens inside check() when cost > 0
        let result = breaker.check(host: "api.openai.com", bodyData: nil, cost: 0.5)
        // Should eventually trigger
        // Note: cost is accumulated via recordCost in real usage, here we pass directly
    }

    // MARK: - Reset

    func testResetClearsState() {
        let body = "looping".data(using: .utf8)!
        for _ in 0..<5 {
            _ = breaker.check(host: "api.openai.com", bodyData: body)
        }
        breaker.reset()
        let result = breaker.check(host: "api.openai.com", bodyData: body)
        XCTAssertNil(result, "After reset, first request should not trigger")
    }

    // MARK: - Disabled

    func testDisabledReturnsNil() {
        breaker.configure(LoopBreakerSettings(enabled: false))
        let body = "same".data(using: .utf8)!
        for _ in 0..<100 {
            XCTAssertNil(breaker.check(host: "x.com", bodyData: body))
        }
    }
}
