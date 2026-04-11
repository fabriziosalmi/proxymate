import XCTest
@testable import proxymate

final class AgentEnforcerTests: XCTestCase {

    // MARK: - Agent detection

    func testDetectClaudeCode() {
        let headers = "User-Agent: claude-code/1.0\r\nHost: api.anthropic.com\r\n"
        let result = AIAgentEnforcer.detectAgent(headers: headers, host: "api.anthropic.com")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.agentId, "claude-code")
        XCTAssertEqual(result?.confidence, "high")
    }

    func testDetectCursor() {
        let headers = "User-Agent: cursor/0.42\r\nHost: api2.cursor.sh\r\n"
        let result = AIAgentEnforcer.detectAgent(headers: headers, host: "api2.cursor.sh")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.agentId, "cursor")
    }

    func testDetectCopilotByHost() {
        let headers = "User-Agent: GithubCopilot/1.0\r\n"
        let result = AIAgentEnforcer.detectAgent(headers: headers,
                                                  host: "copilot-proxy.githubusercontent.com")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.agentId, "copilot")
    }

    func testDetectAnthropicByHeader() {
        let headers = "x-api-key: sk-ant-xxx\r\nanthropic-version: 2024-01-01\r\n"
        let result = AIAgentEnforcer.detectAgent(headers: headers, host: "api.anthropic.com")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.agentId, "claude-code")
    }

    func testNoDetectionForBrowser() {
        let headers = "User-Agent: Mozilla/5.0 (Macintosh) Chrome/120\r\n"
        let result = AIAgentEnforcer.detectAgent(headers: headers, host: "example.com")
        XCTAssertNil(result)
    }

    // MARK: - MCP detection

    func testDetectMCPToolsCall() {
        let body = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\"}}".data(using: .utf8)!
        let result = AIAgentEnforcer.detectMCP(body: body, host: "mcp.server.com")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.method, "tools/call")
    }

    func testDetectMCPResourcesRead() {
        let body = "{\"jsonrpc\":\"2.0\",\"method\":\"resources/read\",\"params\":{}}".data(using: .utf8)!
        let result = AIAgentEnforcer.detectMCP(body: body, host: "mcp.server.com")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.method, "resources/read")
    }

    func testNoMCPInNormalJSON() {
        let body = "{\"action\":\"login\",\"user\":\"admin\"}".data(using: .utf8)!
        let result = AIAgentEnforcer.detectMCP(body: body, host: "api.example.com")
        XCTAssertNil(result)
    }

    func testNoMCPInNonJSON() {
        let body = "just plain text".data(using: .utf8)!
        let result = AIAgentEnforcer.detectMCP(body: body, host: "x.com")
        XCTAssertNil(result)
    }

    // MARK: - MCP allowlist

    func testMCPAllowed() {
        let policies = [MCPPolicy(serverPattern: "trusted.server.com", allowed: true)]
        let (allowed, _) = AIAgentEnforcer.isMCPAllowed(serverHost: "trusted.server.com",
                                                          policies: policies, blockUnknown: true)
        XCTAssertTrue(allowed)
    }

    func testMCPBlockedByPolicy() {
        let policies = [MCPPolicy(serverPattern: "evil.server.com", allowed: false)]
        let (allowed, reason) = AIAgentEnforcer.isMCPAllowed(serverHost: "evil.server.com",
                                                              policies: policies, blockUnknown: false)
        XCTAssertFalse(allowed)
        XCTAssertNotNil(reason)
    }

    func testMCPBlockUnknown() {
        let (allowed, _) = AIAgentEnforcer.isMCPAllowed(serverHost: "unknown.com",
                                                          policies: [], blockUnknown: true)
        XCTAssertFalse(allowed)
    }

    func testMCPAllowUnknown() {
        let (allowed, _) = AIAgentEnforcer.isMCPAllowed(serverHost: "unknown.com",
                                                          policies: [], blockUnknown: false)
        XCTAssertTrue(allowed)
    }

    // MARK: - Policy lookup

    func testGetActionDefault() {
        let settings = AIAgentSettings()
        let action = AIAgentEnforcer.getAction(agentId: "claude-code", settings: settings)
        XCTAssertEqual(action, .audit)
    }
}
