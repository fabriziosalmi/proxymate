import XCTest
@testable import proxymate

final class PoolModelTests: XCTestCase {

    // MARK: - Pool model

    func testPoolStrategies() {
        XCTAssertEqual(UpstreamPool.Strategy.allCases.count, 6)
    }

    func testPoolMemberDefaults() {
        let member = PoolMember(host: "test.com", port: 8080)
        XCTAssertEqual(member.weight, 1)
        XCTAssertTrue(member.enabled)
    }

    func testHealthCheckDefaults() {
        let hc = HealthCheckConfig()
        XCTAssertTrue(hc.enabled)
        XCTAssertEqual(hc.intervalSeconds, 30)
        XCTAssertEqual(hc.timeoutSeconds, 5)
        XCTAssertEqual(hc.unhealthyThreshold, 3)
        XCTAssertEqual(hc.healthyThreshold, 1)
    }

    func testMemberHealthDefaults() {
        let h = MemberHealth()
        XCTAssertTrue(h.isHealthy)
        XCTAssertEqual(h.consecutiveFailures, 0)
        XCTAssertEqual(h.activeConnections, 0)
    }

    func testPoolOverride() {
        let poolId = UUID()
        let o = PoolOverride(hostPattern: "*.github.com", poolId: poolId)
        XCTAssertEqual(o.hostPattern, "*.github.com")
        XCTAssertEqual(o.poolId, poolId)
    }

    // MARK: - Override pattern matching

    func testWildcardPattern() {
        let pattern = "*.github.com"
        let suffix = String(pattern.dropFirst(2)) // "github.com"
        XCTAssertTrue("api.github.com".hasSuffix("." + suffix))
        XCTAssertTrue("github.com" == suffix)
        XCTAssertFalse("example.com".hasSuffix("." + suffix))
    }
}
