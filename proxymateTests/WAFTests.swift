import XCTest
@testable import proxymate

final class WAFTests: XCTestCase {

    // MARK: - Domain matching

    func testExactDomainMatch() {
        let rule = WAFRule(name: "test", kind: .blockDomain, pattern: "evil.com")
        XCTAssertTrue(LocalProxy.matches(rule: rule, host: "evil.com", target: "", headers: ""))
    }

    func testSubdomainMatch() {
        let rule = WAFRule(name: "test", kind: .blockDomain, pattern: "evil.com")
        XCTAssertTrue(LocalProxy.matches(rule: rule, host: "sub.evil.com", target: "", headers: ""))
        XCTAssertTrue(LocalProxy.matches(rule: rule, host: "deep.sub.evil.com", target: "", headers: ""))
    }

    func testDomainNoFalsePositive() {
        let rule = WAFRule(name: "test", kind: .blockDomain, pattern: "evil.com")
        XCTAssertFalse(LocalProxy.matches(rule: rule, host: "notevil.com", target: "", headers: ""))
        XCTAssertFalse(LocalProxy.matches(rule: rule, host: "evil.com.hacker.io", target: "", headers: ""))
    }

    func testCaseInsensitive() {
        let rule = WAFRule(name: "test", kind: .blockDomain, pattern: "Evil.COM")
        XCTAssertTrue(LocalProxy.matches(rule: rule, host: "evil.com", target: "", headers: ""))
        XCTAssertTrue(LocalProxy.matches(rule: rule, host: "EVIL.COM", target: "", headers: ""))
    }

    // MARK: - IP matching

    func testExactIPMatch() {
        let rule = WAFRule(name: "test", kind: .blockIP, pattern: "1.2.3.4")
        XCTAssertTrue(LocalProxy.matches(rule: rule, host: "1.2.3.4", target: "", headers: ""))
        XCTAssertFalse(LocalProxy.matches(rule: rule, host: "1.2.3.5", target: "", headers: ""))
    }

    // MARK: - Content matching

    func testContentInTarget() {
        let rule = WAFRule(name: "test", kind: .blockContent, pattern: "malware.exe")
        XCTAssertTrue(LocalProxy.matches(rule: rule, host: "", target: "http://x.com/malware.exe", headers: ""))
        XCTAssertFalse(LocalProxy.matches(rule: rule, host: "", target: "http://x.com/safe.txt", headers: ""))
    }

    func testContentInHeaders() {
        let rule = WAFRule(name: "test", kind: .blockContent, pattern: "badheader")
        XCTAssertTrue(LocalProxy.matches(rule: rule, host: "", target: "", headers: "X-Custom: badheader\r\n"))
    }

    // MARK: - Allow rules don't match in block path

    func testAllowRuleDoesNotBlock() {
        let rule = WAFRule(name: "test", kind: .allowDomain, pattern: "good.com")
        XCTAssertFalse(LocalProxy.matches(rule: rule, host: "good.com", target: "", headers: ""))
    }

    // MARK: - Empty pattern

    func testEmptyPatternNeverMatches() {
        let rule = WAFRule(name: "test", kind: .blockDomain, pattern: "")
        XCTAssertFalse(LocalProxy.matches(rule: rule, host: "anything.com", target: "", headers: ""))
    }

    // MARK: - Host extraction

    func testExtractHostFromCONNECT() {
        let host = LocalProxy.extractHost(method: "CONNECT", target: "example.com:443", headers: "")
        XCTAssertEqual(host, "example.com")
    }

    func testExtractHostFromAbsoluteURL() {
        let host = LocalProxy.extractHost(method: "GET", target: "http://example.com/path", headers: "")
        XCTAssertEqual(host, "example.com")
    }

    func testExtractHostFromHostHeader() {
        let host = LocalProxy.extractHost(method: "GET", target: "/path",
                                           headers: "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        XCTAssertEqual(host, "example.com")
    }

    func testExtractHostWithPort() {
        let host = LocalProxy.extractHost(method: "GET", target: "/",
                                           headers: "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n")
        XCTAssertEqual(host, "example.com")
    }

    // MARK: - matchesDomain helper

    func testMatchesDomainExact() {
        XCTAssertTrue(LocalProxy.matchesDomain(host: "evil.com", pattern: "evil.com"))
    }

    func testMatchesDomainSuffix() {
        XCTAssertTrue(LocalProxy.matchesDomain(host: "sub.evil.com", pattern: "evil.com"))
        XCTAssertFalse(LocalProxy.matchesDomain(host: "notevil.com", pattern: "evil.com"))
    }
}
