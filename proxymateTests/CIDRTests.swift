import XCTest
@testable import proxymate

final class CIDRTests: XCTestCase {

    // MARK: - CIDR matching

    func testCIDR8() {
        XCTAssertTrue(AllowlistMatcher.matchesCIDR(ip: "10.0.0.1", cidr: "10.0.0.0/8"))
        XCTAssertTrue(AllowlistMatcher.matchesCIDR(ip: "10.255.255.255", cidr: "10.0.0.0/8"))
        XCTAssertFalse(AllowlistMatcher.matchesCIDR(ip: "11.0.0.1", cidr: "10.0.0.0/8"))
    }

    func testCIDR16() {
        XCTAssertTrue(AllowlistMatcher.matchesCIDR(ip: "192.168.0.1", cidr: "192.168.0.0/16"))
        XCTAssertTrue(AllowlistMatcher.matchesCIDR(ip: "192.168.255.255", cidr: "192.168.0.0/16"))
        XCTAssertFalse(AllowlistMatcher.matchesCIDR(ip: "192.169.0.1", cidr: "192.168.0.0/16"))
    }

    func testCIDR24() {
        XCTAssertTrue(AllowlistMatcher.matchesCIDR(ip: "192.168.1.100", cidr: "192.168.1.0/24"))
        XCTAssertFalse(AllowlistMatcher.matchesCIDR(ip: "192.168.2.1", cidr: "192.168.1.0/24"))
    }

    func testCIDR32() {
        XCTAssertTrue(AllowlistMatcher.matchesCIDR(ip: "1.2.3.4", cidr: "1.2.3.4/32"))
        XCTAssertFalse(AllowlistMatcher.matchesCIDR(ip: "1.2.3.5", cidr: "1.2.3.4/32"))
    }

    func testCIDR0MatchesAll() {
        XCTAssertTrue(AllowlistMatcher.matchesCIDR(ip: "1.2.3.4", cidr: "0.0.0.0/0"))
        XCTAssertTrue(AllowlistMatcher.matchesCIDR(ip: "255.255.255.255", cidr: "0.0.0.0/0"))
    }

    // MARK: - IP to UInt32

    func testIPConversion() {
        XCTAssertEqual(AllowlistMatcher.ipToUInt32("0.0.0.0"), 0)
        XCTAssertEqual(AllowlistMatcher.ipToUInt32("255.255.255.255"), 0xFFFFFFFF)
        XCTAssertEqual(AllowlistMatcher.ipToUInt32("10.0.0.1"), 0x0A000001)
        XCTAssertNil(AllowlistMatcher.ipToUInt32("not.an.ip"))
        XCTAssertNil(AllowlistMatcher.ipToUInt32("256.0.0.0"))
    }

    // MARK: - Allowlist matching

    func testAllowExactIP() {
        let entries = [AllowEntry(pattern: "1.2.3.4")]
        XCTAssertTrue(AllowlistMatcher.isAllowed(host: "1.2.3.4", port: nil, entries: entries))
        XCTAssertFalse(AllowlistMatcher.isAllowed(host: "1.2.3.5", port: nil, entries: entries))
    }

    func testAllowCIDR() {
        let entries = [AllowEntry(pattern: "10.0.0.0/8")]
        XCTAssertTrue(AllowlistMatcher.isAllowed(host: "10.50.100.200", port: nil, entries: entries))
        XCTAssertFalse(AllowlistMatcher.isAllowed(host: "11.0.0.1", port: nil, entries: entries))
    }

    func testAllowDomain() {
        let entries = [AllowEntry(pattern: "example.com")]
        XCTAssertTrue(AllowlistMatcher.isAllowed(host: "example.com", port: nil, entries: entries))
        XCTAssertTrue(AllowlistMatcher.isAllowed(host: "sub.example.com", port: nil, entries: entries))
        XCTAssertFalse(AllowlistMatcher.isAllowed(host: "notexample.com", port: nil, entries: entries))
    }

    func testAllowWildcard() {
        let entries = [AllowEntry(pattern: "*.corp.com")]
        XCTAssertTrue(AllowlistMatcher.isAllowed(host: "mail.corp.com", port: nil, entries: entries))
        XCTAssertTrue(AllowlistMatcher.isAllowed(host: "corp.com", port: nil, entries: entries))
        XCTAssertFalse(AllowlistMatcher.isAllowed(host: "evil.com", port: nil, entries: entries))
    }

    func testAllowDisabledEntry() {
        let entries = [AllowEntry(pattern: "1.2.3.4", enabled: false)]
        XCTAssertFalse(AllowlistMatcher.isAllowed(host: "1.2.3.4", port: nil, entries: entries))
    }

    func testAllowWithPort() {
        let entries = [AllowEntry(pattern: "1.2.3.4", port: 443)]
        XCTAssertTrue(AllowlistMatcher.isAllowed(host: "1.2.3.4", port: 443, entries: entries))
        XCTAssertFalse(AllowlistMatcher.isAllowed(host: "1.2.3.4", port: 80, entries: entries))
    }
}
