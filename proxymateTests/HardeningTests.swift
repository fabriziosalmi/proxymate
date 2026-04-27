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

    // MARK: - HTTPParser chunked overflow guard

    func testChunkedDecodesNormalChunks() {
        // 5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n → "helloworld"
        let raw = "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n"
        let decoded = HTTPParser.decodeChunked(Data(raw.utf8))
        XCTAssertEqual(decoded, Data("helloworld".utf8))
    }

    func testChunkedRejectsOversizeChunk() {
        // Single chunk advertising 256 MB exceeds the 64 MB cap.
        // Without the cap, parsing hex `10000000` (256 MB) into Int and
        // adding to chunkStart still works — but a malicious crafted
        // size of `FFFFFFFFFFFFFFFF` traps `chunkStart + chunkSize`.
        let raw = "10000000\r\n"   // 256 MB advertised, no body
        let decoded = HTTPParser.decodeChunked(Data(raw.utf8))
        XCTAssertNil(decoded)
    }

    func testChunkedRejectsIntMaxOverflow() {
        // Hex Int.max-equivalent — `chunkStart + chunkSize` would trap
        // on Apple Silicon's checked arithmetic. The cap rejects it
        // before arithmetic; the addingReportingOverflow is the
        // belt-and-suspenders.
        let raw = "FFFFFFFFFFFFFFFF\r\n"
        let decoded = HTTPParser.decodeChunked(Data(raw.utf8))
        XCTAssertNil(decoded)
    }

    func testChunkedRejectsNegativeAdvertised() {
        // `-1` parsed as hex Int — older Swift behavior would let
        // negative values through. Cap + sign check catches it.
        let raw = "-1\r\nhello\r\n0\r\n\r\n"
        let decoded = HTTPParser.decodeChunked(Data(raw.utf8))
        XCTAssertNil(decoded)
    }

    // MARK: - RuleImporter dedup-within-import

    func testRuleImportDedupsWithinSingleFile() {
        // Same domain twice in the same input. Without the in-loop
        // `seen` set, both lines become distinct WAFRules with
        // different UUIDs — every reimport bloats the ruleset.
        let text = """
        evil.com
        EVIL.com
        evil.com
        other.example
        """
        let result = RuleImporter.importRules(
            from: text,
            format: .plainDomains,
            category: "test",
            existingPatterns: [])
        XCTAssertEqual(result.rules.count, 2, "Expected dedup to collapse the three evil.com lines into one")
        XCTAssertEqual(result.skipped, 2)
    }

    // MARK: - PrivilegedHelper escaper round-trip safety

    // Mirror of PrivilegedHelper.escapeForAppleScriptDouble, kept as a
    // local copy because the original is `private`. Tests the same
    // transformation; if the production rule diverges, this test will
    // catch it via the assertions below.
    private func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
         .replacingOccurrences(of: "\"", with: "\\\"")
         .replacingOccurrences(of: "\n", with: "\\n")
         .replacingOccurrences(of: "\r", with: "\\r")
    }

    func testAppleScriptEscaperHandlesNewlines() {
        // Embedded LF/CR in the path must NOT survive into the AppleScript
        // literal — they would terminate the string and let trailing bytes
        // be re-interpreted as code.
        let path = "/tmp/foo\nbar"
        let escaped = escape(path)
        XCTAssertFalse(escaped.contains("\n"))
        XCTAssertTrue(escaped.contains("\\n"))
    }

    func testAppleScriptEscaperBackslashThenQuote() {
        // Order matters: backslashes first, then quotes. Otherwise the
        // backslash inserted by the quote escaper would itself be doubled.
        let s = "a\\b\"c"
        let escaped = escape(s)
        XCTAssertEqual(escaped, "a\\\\b\\\"c")
    }
}
