import XCTest
@testable import proxymate

final class WebSocketTests: XCTestCase {

    // MARK: - Frame parsing

    func testParseTextFrame() throws {
        let payload = Data("Hello".utf8)
        var frame = Data([0x81]) // FIN + text opcode
        frame.append(UInt8(payload.count))
        frame.append(payload)

        let parsed = try XCTUnwrap(WebSocketInspector.parseFrame(frame))
        XCTAssertTrue(parsed.fin)
        XCTAssertEqual(parsed.opcode, .text)
        XCTAssertEqual(String(data: parsed.payload, encoding: .utf8), "Hello")
        XCTAssertEqual(parsed.totalLength, 2 + 5)
    }

    func testParseMaskedFrame() throws {
        let payload = Data("Hi".utf8)
        let mask: [UInt8] = [0x12, 0x34, 0x56, 0x78]
        var masked = payload
        for i in 0..<masked.count { masked[i] ^= mask[i % 4] }

        var frame = Data([0x81])
        frame.append(0x80 | UInt8(payload.count))
        frame.append(contentsOf: mask)
        frame.append(masked)

        let parsed = try XCTUnwrap(WebSocketInspector.parseFrame(frame))
        XCTAssertEqual(String(data: parsed.payload, encoding: .utf8), "Hi")
    }

    func testParseCloseFrame() throws {
        var frame = Data([0x88, 0x02])
        frame.append(contentsOf: [0x03, 0xE8])

        let parsed = try XCTUnwrap(WebSocketInspector.parseFrame(frame))
        XCTAssertEqual(parsed.opcode, .close)
    }

    func testParseIncompleteFrame() {
        let frame = Data([0x81])
        XCTAssertNil(WebSocketInspector.parseFrame(frame))
    }

    func testParseBinaryFrame() throws {
        var frame = Data([0x82, 0x03])
        frame.append(contentsOf: [0xFF, 0x00, 0xAB])

        let parsed = try XCTUnwrap(WebSocketInspector.parseFrame(frame))
        XCTAssertEqual(parsed.opcode, .binary)
        XCTAssertEqual(parsed.payload.count, 3)
    }

    // MARK: - Extended length

    func testParse16BitLength() throws {
        let payload = Data(repeating: 0x41, count: 200)
        var frame = Data([0x81, 126])
        frame.append(UInt8(0))
        frame.append(UInt8(200))
        frame.append(payload)

        let parsed = try XCTUnwrap(WebSocketInspector.parseFrame(frame))
        XCTAssertEqual(parsed.payload.count, 200)
    }

    // MARK: - Inspection

    func testInspectCleanText() {
        let frame = WebSocketInspector.Frame(fin: true, opcode: .text,
                                              payload: Data("normal message".utf8), totalLength: 0)
        let result = WebSocketInspector.inspect(frame: frame, host: "example.com", rules: [])
        XCTAssertFalse(result.blocked)
    }

    func testInspectBlockedContent() {
        let rule = WAFRule(name: "test", kind: .blockContent, pattern: "malicious")
        let frame = WebSocketInspector.Frame(fin: true, opcode: .text,
                                              payload: Data("this is malicious data".utf8), totalLength: 0)
        let result = WebSocketInspector.inspect(frame: frame, host: "example.com", rules: [rule])
        XCTAssertTrue(result.blocked)
    }

    func testInspectBinarySkipped() {
        let rule = WAFRule(name: "test", kind: .blockContent, pattern: "anything")
        let frame = WebSocketInspector.Frame(fin: true, opcode: .binary,
                                              payload: Data("anything".utf8), totalLength: 0)
        let result = WebSocketInspector.inspect(frame: frame, host: "example.com", rules: [rule])
        XCTAssertFalse(result.blocked)
    }

    // MARK: - Upgrade detection

    func testUpgradeDetection() {
        let headers = "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        XCTAssertTrue(WebSocketInspector.isUpgradeRequest(headers))
    }

    func testNonUpgrade() {
        let headers = "GET / HTTP/1.1\r\nHost: example.com\r\n"
        XCTAssertFalse(WebSocketInspector.isUpgradeRequest(headers))
    }

    // MARK: - Close frame building

    func testBuildCloseFrame() {
        let frame = WebSocketInspector.closeFrame(code: 1008, reason: "policy")
        XCTAssertEqual(frame[0], 0x88)
        let code = UInt16(frame[2]) << 8 | UInt16(frame[3])
        XCTAssertEqual(code, 1008)
    }
}
