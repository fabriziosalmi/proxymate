import XCTest
@testable import proxymate

final class IPv6Tests: XCTestCase {

    func testParseIPv6Bracketed() {
        let (host, port) = IPv6Support.parseHostPort("[::1]:8080")
        XCTAssertEqual(host, "::1")
        XCTAssertEqual(port, 8080)
    }

    func testParseIPv6BracketedNoPort() {
        let (host, port) = IPv6Support.parseHostPort("[2001:db8::1]")
        XCTAssertEqual(host, "2001:db8::1")
        XCTAssertNil(port)
    }

    func testParseIPv4WithPort() {
        let (host, port) = IPv6Support.parseHostPort("1.2.3.4:443")
        XCTAssertEqual(host, "1.2.3.4")
        XCTAssertEqual(port, 443)
    }

    func testParsePlainHostname() {
        let (host, port) = IPv6Support.parseHostPort("example.com")
        XCTAssertEqual(host, "example.com")
        XCTAssertNil(port)
    }

    func testIsIPv6() {
        XCTAssertTrue(IPv6Support.isIPv6("::1"))
        XCTAssertTrue(IPv6Support.isIPv6("2001:db8::1"))
        XCTAssertFalse(IPv6Support.isIPv6("1.2.3.4"))
        XCTAssertFalse(IPv6Support.isIPv6("example.com"))
    }

    func testExpandIPv6() {
        XCTAssertEqual(IPv6Support.expandIPv6("::1"),
                       "0000:0000:0000:0000:0000:0000:0000:0001")
        XCTAssertNotNil(IPv6Support.expandIPv6("2001:db8::1"))
    }

    func testIPv6CIDR() {
        XCTAssertTrue(IPv6Support.matchesCIDR6(ip: "fd00::1", cidr: "fd00::/8"))
        XCTAssertTrue(IPv6Support.matchesCIDR6(ip: "fd12:3456::1", cidr: "fd00::/8"))
        XCTAssertFalse(IPv6Support.matchesCIDR6(ip: "2001:db8::1", cidr: "fd00::/8"))
    }

    func testIPv6Loopback() {
        XCTAssertTrue(IPv6Support.matchesCIDR6(ip: "::1", cidr: "::1/128"))
    }
}
