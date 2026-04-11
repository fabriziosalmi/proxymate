import XCTest
@testable import proxymate

final class HTTPParserTests: XCTestCase {

    func testParseSimpleGET() {
        let raw = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
        let parsed = HTTPParser.parse(Data(raw.utf8))
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.method, "GET")
        XCTAssertEqual(parsed?.target, "/path")
        XCTAssertEqual(parsed?.version, "HTTP/1.1")
        XCTAssertTrue(parsed?.isKeepAlive ?? false) // HTTP/1.1 default
    }

    func testParsePOSTWithBody() {
        let raw = "POST /api HTTP/1.1\r\nHost: api.com\r\nContent-Length: 5\r\n\r\nhello"
        let parsed = HTTPParser.parse(Data(raw.utf8))
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.method, "POST")
        XCTAssertEqual(parsed?.contentLength, 5)
        XCTAssertEqual(parsed?.bodyData.count, 5)
    }

    func testParseCONNECT() {
        let raw = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        let parsed = HTTPParser.parse(Data(raw.utf8))
        XCTAssertEqual(parsed?.method, "CONNECT")
        XCTAssertEqual(parsed?.target, "example.com:443")
    }

    func testParseChunkedHeader() {
        let raw = "POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        let parsed = HTTPParser.parse(Data(raw.utf8))
        XCTAssertTrue(parsed?.isChunked ?? false)
    }

    func testParse100Continue() {
        let raw = "POST /upload HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 1000\r\n\r\n"
        let parsed = HTTPParser.parse(Data(raw.utf8))
        XCTAssertTrue(parsed?.expects100Continue ?? false)
    }

    func testParseConnectionClose() {
        let raw = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n"
        let parsed = HTTPParser.parse(Data(raw.utf8))
        XCTAssertFalse(parsed?.isKeepAlive ?? true)
    }

    func testParseHTTP10NotKeepAlive() {
        let raw = "GET / HTTP/1.0\r\nHost: x.com\r\n\r\n"
        let parsed = HTTPParser.parse(Data(raw.utf8))
        XCTAssertFalse(parsed?.isKeepAlive ?? true)
    }

    func testParseLFOnly() {
        let raw = "GET / HTTP/1.1\nHost: x.com\n\n"
        let parsed = HTTPParser.parse(Data(raw.utf8))
        XCTAssertNotNil(parsed, "Should handle LF-only line endings")
    }

    func testMalformedReturnsNil() {
        XCTAssertNil(HTTPParser.parse(Data("garbage".utf8)))
        XCTAssertNil(HTTPParser.parse(Data()))
    }

    // MARK: - Chunked decoding

    func testDecodeChunked() {
        let chunked = "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n"
        let decoded = HTTPParser.decodeChunked(Data(chunked.utf8))
        XCTAssertEqual(String(data: decoded ?? Data(), encoding: .utf8), "Hello World")
    }

    func testDecodeChunkedEmpty() {
        let chunked = "0\r\n\r\n"
        let decoded = HTTPParser.decodeChunked(Data(chunked.utf8))
        XCTAssertNil(decoded)
    }

    // MARK: - Validation

    func testValidateGoodHeaders() {
        let raw = Data("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)
        XCTAssertTrue(HTTPParser.validateHeaders(raw))
    }

    func testValidateBadMethod() {
        let raw = Data("INVALID / HTTP/1.1\r\n\r\n".utf8)
        XCTAssertFalse(HTTPParser.validateHeaders(raw))
    }

    func testValidateTooLarge() {
        let huge = Data(repeating: 0x41, count: 70000)
        XCTAssertFalse(HTTPParser.validateHeaders(huge))
    }

    func testValidateEmpty() {
        XCTAssertFalse(HTTPParser.validateHeaders(Data()))
    }
}
