import XCTest
@testable import proxymate

final class CacheTests: XCTestCase {

    // MARK: - Cache-Control parsing

    func testParseMaxAge() {
        let cc = CacheManager.parseCacheControl("max-age=300")
        XCTAssertEqual(cc.maxAge, 300)
        XCTAssertFalse(cc.noStore)
    }

    func testParseNoStore() {
        let cc = CacheManager.parseCacheControl("no-store")
        XCTAssertTrue(cc.noStore)
    }

    func testParseNoCache() {
        let cc = CacheManager.parseCacheControl("no-cache")
        XCTAssertTrue(cc.noCache)
    }

    func testParsePrivate() {
        let cc = CacheManager.parseCacheControl("private, max-age=0")
        XCTAssertTrue(cc.private_)
        XCTAssertEqual(cc.maxAge, 0)
    }

    func testParseSMaxAge() {
        let cc = CacheManager.parseCacheControl("public, s-maxage=600, max-age=300")
        XCTAssertEqual(cc.sMaxAge, 600)
        XCTAssertEqual(cc.maxAge, 300)
        XCTAssertTrue(cc.public_)
    }

    func testParseStaleWhileRevalidate() {
        let cc = CacheManager.parseCacheControl("max-age=300, stale-while-revalidate=60")
        XCTAssertEqual(cc.staleWhileRevalidate, 60)
    }

    // MARK: - Status code extraction

    func testExtractStatusCode() {
        XCTAssertEqual(CacheManager.extractStatusCode("HTTP/1.1 200 OK"), 200)
        XCTAssertEqual(CacheManager.extractStatusCode("HTTP/1.1 404 Not Found"), 404)
        XCTAssertEqual(CacheManager.extractStatusCode("HTTP/1.1 301 Moved"), 301)
    }

    // MARK: - Header parsing

    func testParseHeaderMap() {
        let headers = "Content-Type: text/html\r\nCache-Control: max-age=300\r\nVary: Accept-Encoding"
        let map = CacheManager.parseHeaderMap(headers)
        XCTAssertEqual(map["content-type"], "text/html")
        XCTAssertEqual(map["cache-control"], "max-age=300")
        XCTAssertEqual(map["vary"], "Accept-Encoding")
    }

    // MARK: - Tracking param stripping

    func testStripUTMParams() {
        let url = "https://example.com/page?utm_source=google&utm_medium=cpc&real=1"
        let stripped = CacheManager.stripTracking(url: url)
        XCTAssertTrue(stripped.contains("real=1"))
        XCTAssertFalse(stripped.contains("utm_source"))
        XCTAssertFalse(stripped.contains("utm_medium"))
    }

    func testStripFbclid() {
        let url = "https://example.com/page?fbclid=abc123&id=5"
        let stripped = CacheManager.stripTracking(url: url)
        XCTAssertFalse(stripped.contains("fbclid"))
        XCTAssertTrue(stripped.contains("id=5"))
    }

    func testNoParamsUntouched() {
        let url = "https://example.com/page"
        XCTAssertEqual(CacheManager.stripTracking(url: url), url)
    }

    // MARK: - HTTP date parsing

    func testParseHTTPDate() {
        let date = CacheManager.parseHTTPDate("Thu, 01 Jan 2026 00:00:00 GMT")
        XCTAssertNotNil(date)
    }

    func testParseInvalidDate() {
        XCTAssertNil(CacheManager.parseHTTPDate("not a date"))
    }
}
