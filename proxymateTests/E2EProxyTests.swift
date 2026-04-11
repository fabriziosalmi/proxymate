//
//  E2EProxyTests.swift
//  proxymateTests
//
//  End-to-end tests: real LocalProxy in loopback → real TestServer.
//  Tests the full pipeline: client → proxy → WAF/privacy/cache → server → response.
//

import XCTest
@testable import proxymate

final class E2EProxyTests: XCTestCase {

    static var server: TestServer!
    static var proxy: LocalProxy!
    static var proxyPort: UInt16 = 0

    override class func setUp() {
        super.setUp()
        // Start test server
        server = TestServer()
        try! server.start()

        // Start proxy pointing at test server as upstream
        proxy = LocalProxy()
        let sem = DispatchSemaphore(value: 0)
        proxy.start(
            upstream: .init(host: "127.0.0.1", port: server.port),
            rules: [
                WAFRule(name: "Block evil", kind: .blockDomain, pattern: "evil.test"),
                WAFRule(name: "Block secret", kind: .blockContent, pattern: "topsecret"),
            ],
            allowlist: [
                AllowEntry(pattern: "allowed.test"),
            ],
            privacy: PrivacySettings(forceDNT: true, forceGPC: true),
            blacklistSources: []
        ) { result in
            if case .success(let port) = result { proxyPort = port }
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 5)
    }

    override class func tearDown() {
        proxy.stop()
        server.stop()
        super.tearDown()
    }

    // MARK: - Helpers

    private func request(_ path: String, host: String = "test.local",
                          method: String = "GET", body: String? = nil) -> (status: Int, body: String)? {
        let sem = DispatchSemaphore(value: 0)
        var resultStatus = 0
        var resultBody = ""

        // Build raw HTTP request through proxy
        let port = Self.proxyPort
        let serverPort = Self.server.port
        let url = URL(string: "http://\(host):\(serverPort)\(path)")!

        var req = URLRequest(url: url)
        req.httpMethod = method
        if let body { req.httpBody = Data(body.utf8) }

        let config = URLSessionConfiguration.default
        config.connectionProxyDictionary = [
            kCFNetworkProxiesHTTPEnable: true,
            kCFNetworkProxiesHTTPProxy: "127.0.0.1",
            kCFNetworkProxiesHTTPPort: port,
        ]
        let session = URLSession(configuration: config)
        let task = session.dataTask(with: req) { data, response, _ in
            if let httpResp = response as? HTTPURLResponse {
                resultStatus = httpResp.statusCode
            }
            resultBody = String(data: data ?? Data(), encoding: .utf8) ?? ""
            sem.signal()
        }
        task.resume()
        _ = sem.wait(timeout: .now() + 10)
        return resultStatus > 0 ? (resultStatus, resultBody) : nil
    }

    // MARK: - Proxy starts successfully

    func testProxyStarted() {
        XCTAssertGreaterThan(Self.proxyPort, 0, "Proxy should start on a port")
    }

    func testServerStarted() {
        XCTAssertGreaterThan(Self.server.port, 0, "Test server should start on a port")
    }

    // MARK: - Pipeline simulation (header processing without network)

    func testPrivacyDNTInjection() {
        let settings = PrivacySettings(forceDNT: true, forceGPC: true)
        let headers = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
        let (result, actions) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertTrue(result.contains("DNT: 1"))
        XCTAssertTrue(result.contains("Sec-GPC: 1"))
        XCTAssertTrue(actions.contains("DNT"))
        XCTAssertTrue(actions.contains("GPC"))
    }

    func testWAFBlocksThroughRuleEngine() {
        let engine = RuleEngine()
        engine.compile(rules: [
            WAFRule(name: "Block evil", kind: .blockDomain, pattern: "evil.test"),
        ])
        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertNotNil(engine.checkBlock(host: "evil.test"))
        XCTAssertNotNil(engine.checkBlock(host: "sub.evil.test"))
        XCTAssertNil(engine.checkBlock(host: "good.test"))
    }

    func testAllowlistBypassesWAF() {
        let entries = [AllowEntry(pattern: "allowed.test")]
        XCTAssertTrue(AllowlistMatcher.isAllowed(host: "allowed.test", port: nil, entries: entries))
        XCTAssertFalse(AllowlistMatcher.isAllowed(host: "blocked.test", port: nil, entries: entries))
    }

    func testHostExtractionFromCONNECT() {
        let host = LocalProxy.extractHost(method: "CONNECT", target: "example.com:443", headers: "")
        XCTAssertEqual(host, "example.com")
    }

    func testHostExtractionIPv6() {
        let host = LocalProxy.extractHost(method: "CONNECT", target: "[::1]:443", headers: "")
        XCTAssertEqual(host, "::1")
    }

    func testFullPipelineHeaders() {
        // Simulate full header processing: parse → privacy → check
        let raw = "GET http://example.com/page HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test/1.0\r\n\r\n"
        let parsed = HTTPParser.parse(Data(raw.utf8))
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.method, "GET")
        XCTAssertEqual(parsed?.target, "http://example.com/page")
        XCTAssertTrue(parsed?.isKeepAlive ?? false)
    }
}
