import XCTest
@testable import proxymate

final class BeaconingTests: XCTestCase {

    func testSettingsDefaults() {
        let s = BeaconingSettings()
        XCTAssertFalse(s.enabled)
        XCTAssertEqual(s.minConsecutive, 5)
        XCTAssertEqual(s.jitterTolerancePercent, 20)
        XCTAssertEqual(s.minIntervalSeconds, 5)
        XCTAssertEqual(s.maxIntervalSeconds, 3600)
    }

    func testDetectionModelFields() {
        let d = BeaconingDetector.Detection(host: "evil.com", path: "/beacon",
                                             intervalSeconds: 30, consecutiveCount: 5)
        XCTAssertEqual(d.host, "evil.com")
        XCTAssertEqual(d.path, "/beacon")
        XCTAssertEqual(d.intervalSeconds, 30)
        XCTAssertEqual(d.consecutiveCount, 5)
    }

    func testDisabledReturnsNil() {
        let detector = BeaconingDetector()
        detector.configure(BeaconingSettings(enabled: false))
        for _ in 0..<100 {
            XCTAssertNil(detector.record(host: "x.com", path: "/"))
        }
    }
}
