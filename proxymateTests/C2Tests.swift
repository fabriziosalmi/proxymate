import XCTest
@testable import proxymate

final class C2Tests: XCTestCase {

    let settings = C2Settings(enabled: true, action: .block)

    // MARK: - Cobalt Strike

    func testCobaltStrikeDefaultUA() {
        let headers = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n"
        let result = C2Detector.scan(headers: headers, target: "/", settings: settings)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.framework, "Cobalt Strike")
    }

    func testCobaltStrikeBeaconPath() {
        let result = C2Detector.scan(headers: "User-Agent: Chrome\r\n",
                                      target: "/pixel.gif", settings: settings)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.framework, "Cobalt Strike")
    }

    func testCobaltStrikeMSTSCookie() {
        let headers = "Cookie: mstsauthtoken=abc123; session=xyz\r\n"
        let result = C2Detector.scan(headers: headers, target: "/", settings: settings)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.framework, "Cobalt Strike")
    }

    // MARK: - Mythic

    func testMythicPath() {
        let result = C2Detector.scan(headers: "User-Agent: Chrome\r\n",
                                      target: "/api/v1/tasking", settings: settings)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.framework, "Mythic")
    }

    // MARK: - Havoc

    func testHavocUA() {
        let headers = "User-Agent: HavocC2 Agent\r\n"
        let result = C2Detector.scan(headers: headers, target: "/", settings: settings)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.framework, "Havoc")
    }

    // MARK: - Clean traffic

    func testNormalBrowserUA() {
        let headers = "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
        let result = C2Detector.scan(headers: headers, target: "/index.html", settings: settings)
        XCTAssertNil(result)
    }

    func testCurlUA() {
        let headers = "User-Agent: curl/8.4.0\r\n"
        let result = C2Detector.scan(headers: headers, target: "/api/data", settings: settings)
        XCTAssertNil(result)
    }

    // MARK: - Disabled

    func testDisabledReturnsNil() {
        let disabled = C2Settings(enabled: false)
        let headers = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n"
        XCTAssertNil(C2Detector.scan(headers: headers, target: "/", settings: disabled))
    }
}
