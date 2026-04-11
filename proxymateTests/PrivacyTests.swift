import XCTest
@testable import proxymate

final class PrivacyTests: XCTestCase {

    // MARK: - DNT / GPC injection

    func testInjectDNT() {
        let settings = PrivacySettings(forceDNT: true, forceGPC: false)
        let headers = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        let (result, actions) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertTrue(result.contains("DNT: 1"))
        XCTAssertTrue(actions.contains("DNT"))
    }

    func testInjectGPC() {
        let settings = PrivacySettings(forceGPC: true)
        let headers = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        let (result, actions) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertTrue(result.contains("Sec-GPC: 1"))
        XCTAssertTrue(actions.contains("GPC"))
    }

    func testNoDuplicateDNT() {
        let settings = PrivacySettings(forceDNT: true)
        let headers = "GET / HTTP/1.1\r\nHost: x.com\r\nDNT: 1\r\n\r\n"
        let (result, actions) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        let count = result.components(separatedBy: "DNT: 1").count - 1
        XCTAssertEqual(count, 1, "Should not duplicate existing DNT header")
        XCTAssertFalse(actions.contains("DNT"))
    }

    // MARK: - User-Agent replacement

    func testStripUA() {
        let settings = PrivacySettings(stripUserAgent: true, customUserAgent: "Custom/1.0")
        let headers = "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 Evil\r\nHost: x.com\r\n\r\n"
        let (result, actions) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertTrue(result.contains("User-Agent: Custom/1.0"))
        XCTAssertFalse(result.contains("Evil"))
        XCTAssertTrue(actions.contains("UA"))
    }

    func testNoStripUAWhenDisabled() {
        let settings = PrivacySettings(stripUserAgent: false)
        let headers = "GET / HTTP/1.1\r\nUser-Agent: Original/1.0\r\nHost: x.com\r\n\r\n"
        let (result, _) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertTrue(result.contains("User-Agent: Original/1.0"))
    }

    // MARK: - Referer stripping

    func testStripRefererCompletely() {
        let settings = PrivacySettings(stripReferer: true, refererPolicy: .strip)
        let headers = "GET / HTTP/1.1\r\nReferer: https://secret.com/private/page\r\nHost: x.com\r\n\r\n"
        let (result, actions) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertFalse(result.contains("Referer:"))
        XCTAssertTrue(actions.contains("Ref-strip"))
    }

    func testRefererOriginOnly() {
        let settings = PrivacySettings(stripReferer: true, refererPolicy: .originOnly)
        let headers = "GET / HTTP/1.1\r\nReferer: https://secret.com/private/page?q=1\r\nHost: x.com\r\n\r\n"
        let (result, actions) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertTrue(result.contains("Referer: https://secret.com/"))
        XCTAssertFalse(result.contains("/private/page"))
        XCTAssertTrue(actions.contains("Ref-origin"))
    }

    // MARK: - Tracking cookie stripping

    func testStripTrackingCookies() {
        let settings = PrivacySettings(stripTrackingCookies: true)
        let headers = "GET / HTTP/1.1\r\nCookie: _ga=123; session=abc; _fbp=456; lang=en\r\nHost: x.com\r\n\r\n"
        let (result, actions) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertFalse(result.contains("_ga="))
        XCTAssertFalse(result.contains("_fbp="))
        XCTAssertTrue(result.contains("session=abc"))
        XCTAssertTrue(result.contains("lang=en"))
        XCTAssertTrue(actions.first(where: { $0.hasPrefix("Cookie(") }) != nil)
    }

    func testStripAllTrackingCookiesRemovesHeader() {
        let settings = PrivacySettings(stripTrackingCookies: true)
        let headers = "GET / HTTP/1.1\r\nCookie: _ga=123; _fbp=456\r\nHost: x.com\r\n\r\n"
        let (result, _) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertFalse(result.contains("Cookie:"))
    }

    // MARK: - ETag stripping

    func testStripETag() {
        let settings = PrivacySettings(stripETag: true)
        let headers = "GET / HTTP/1.1\r\nIf-None-Match: \"abc123\"\r\nHost: x.com\r\n\r\n"
        let (result, actions) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertFalse(result.contains("If-None-Match"))
        XCTAssertTrue(actions.contains("ETag"))
    }

    // MARK: - No changes when all disabled

    func testNoChangesWhenDisabled() {
        let settings = PrivacySettings(stripUserAgent: false, stripReferer: false,
                                        stripTrackingCookies: false, forceDNT: false,
                                        forceGPC: false, stripETag: false)
        let headers = "GET / HTTP/1.1\r\nHost: x.com\r\n\r\n"
        let (_, actions) = LocalProxy.applyPrivacy(headerString: headers, settings: settings)
        XCTAssertTrue(actions.isEmpty)
    }
}
