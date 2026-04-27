import XCTest
@testable import proxymate

final class HardeningTests: XCTestCase {

    // MARK: - WebhookManager.isAcceptable

    func testWebhookAcceptsPlainHTTPS() {
        XCTAssertTrue(WebhookManager.isAcceptable("https://hooks.example.com/abc"))
        XCTAssertTrue(WebhookManager.isAcceptable("http://localhost:8080/wh"))
        XCTAssertTrue(WebhookManager.isAcceptable("https://example.com:9443/p?x=1"))
    }

    func testWebhookRejectsUserinfo() {
        // The whole point of #6: secrets in user:pass@ end up in
        // UserDefaults plaintext. Must be filtered out.
        XCTAssertFalse(WebhookManager.isAcceptable("https://api:secret@hooks.example.com/abc"))
        XCTAssertFalse(WebhookManager.isAcceptable("http://user@example.com/wh"))
        XCTAssertFalse(WebhookManager.isAcceptable("https://:token@hooks.example.com/wh"))
    }

    func testWebhookRejectsForeignSchemes() {
        XCTAssertFalse(WebhookManager.isAcceptable("file:///etc/passwd"))
        XCTAssertFalse(WebhookManager.isAcceptable("ftp://example.com/wh"))
        XCTAssertFalse(WebhookManager.isAcceptable("javascript:alert(1)"))
        XCTAssertFalse(WebhookManager.isAcceptable("data:application/json,{}"))
    }

    func testWebhookRejectsMissingHost() {
        XCTAssertFalse(WebhookManager.isAcceptable(""))
        XCTAssertFalse(WebhookManager.isAcceptable("https://"))
        XCTAssertFalse(WebhookManager.isAcceptable("not a url"))
    }

    // MARK: - MetricsServer browser-request gate

    func testMetricsAcceptsCurlPrometheusStyle() {
        // A typical Prometheus / curl scrape — no Origin, no Sec-Fetch-*.
        let raw = """
        GET /metrics HTTP/1.1\r
        Host: 127.0.0.1:9199\r
        User-Agent: Prometheus/2.48\r
        Accept: text/plain\r
        \r
        """
        XCTAssertFalse(MetricsServer.looksLikeBrowserRequest(raw))
    }

    func testMetricsBlocksOriginHeader() {
        let raw = """
        GET /metrics HTTP/1.1\r
        Host: 127.0.0.1:9199\r
        Origin: http://evil.example\r
        \r
        """
        XCTAssertTrue(MetricsServer.looksLikeBrowserRequest(raw))
    }

    func testMetricsBlocksSecFetchHeaders() {
        let raw = """
        GET /metrics HTTP/1.1\r
        Host: 127.0.0.1:9199\r
        Sec-Fetch-Site: cross-site\r
        Sec-Fetch-Mode: no-cors\r
        Sec-Fetch-Dest: image\r
        \r
        """
        XCTAssertTrue(MetricsServer.looksLikeBrowserRequest(raw))
    }

    func testMetricsBlocksReferer() {
        let raw = """
        GET /metrics HTTP/1.1\r
        Host: 127.0.0.1:9199\r
        Referer: http://localhost/some-page\r
        \r
        """
        XCTAssertTrue(MetricsServer.looksLikeBrowserRequest(raw))
    }

    func testMetricsCaseInsensitive() {
        // RFC 7230: header names are case-insensitive. Browsers send
        // "Origin"; a malicious page can't sneak past with "ORIGIN".
        let raw = "GET / HTTP/1.1\r\nHOST: 127.0.0.1\r\nORIGIN: http://x\r\n\r\n"
        XCTAssertTrue(MetricsServer.looksLikeBrowserRequest(raw))
    }
}
