import XCTest
@testable import proxymate

final class PoolRouterTests: XCTestCase {

    // MARK: - Round Robin

    func testRoundRobin() {
        let pool = UpstreamPool(
            name: "test",
            members: [
                PoolMember(host: "a.com", port: 8080),
                PoolMember(host: "b.com", port: 8080),
                PoolMember(host: "c.com", port: 8080),
            ],
            strategy: .roundRobin,
            healthCheck: HealthCheckConfig(enabled: false),
            isDefault: true
        )
        let router = PoolRouter()
        router.configure(pools: [pool], overrides: [])

        var hosts: [String] = []
        for _ in 0..<6 {
            if let sel = router.select(forHost: "any.com") {
                hosts.append(sel.host)
            }
        }
        // Should cycle a, b, c, a, b, c
        XCTAssertEqual(hosts, ["a.com", "b.com", "c.com", "a.com", "b.com", "c.com"])
    }

    // MARK: - Failover

    func testFailoverSelectsFirst() {
        let pool = UpstreamPool(
            name: "test",
            members: [
                PoolMember(host: "primary.com", port: 80),
                PoolMember(host: "backup.com", port: 80),
            ],
            strategy: .failover,
            healthCheck: HealthCheckConfig(enabled: false),
            isDefault: true
        )
        let router = PoolRouter()
        router.configure(pools: [pool], overrides: [])

        let sel = router.select(forHost: "any.com")
        XCTAssertEqual(sel?.host, "primary.com")
    }

    // MARK: - Override chain

    func testOverrideRouting() {
        let poolA = UpstreamPool(
            name: "Default", members: [PoolMember(host: "default.com", port: 80)],
            strategy: .failover, healthCheck: HealthCheckConfig(enabled: false), isDefault: true
        )
        let poolB = UpstreamPool(
            name: "GitHub", members: [PoolMember(host: "fast-github.com", port: 80)],
            strategy: .failover, healthCheck: HealthCheckConfig(enabled: false)
        )
        let override = PoolOverride(hostPattern: "*.github.com", poolId: poolB.id)

        let router = PoolRouter()
        router.configure(pools: [poolA, poolB], overrides: [override])

        let sel1 = router.select(forHost: "api.github.com")
        XCTAssertEqual(sel1?.host, "fast-github.com")

        let sel2 = router.select(forHost: "example.com")
        XCTAssertEqual(sel2?.host, "default.com")
    }

    // MARK: - Disabled members

    func testDisabledMemberSkipped() {
        let pool = UpstreamPool(
            name: "test",
            members: [
                PoolMember(host: "disabled.com", port: 80, enabled: false),
                PoolMember(host: "active.com", port: 80),
            ],
            strategy: .failover,
            healthCheck: HealthCheckConfig(enabled: false),
            isDefault: true
        )
        let router = PoolRouter()
        router.configure(pools: [pool], overrides: [])

        let sel = router.select(forHost: "any.com")
        XCTAssertEqual(sel?.host, "active.com")
    }

    // MARK: - No pools returns nil

    func testNoPoolsReturnsNil() {
        let router = PoolRouter()
        router.configure(pools: [], overrides: [])
        XCTAssertNil(router.select(forHost: "any.com"))
    }

    // MARK: - Connection tracking

    func testConnectionTracking() {
        let member = PoolMember(host: "test.com", port: 80)
        let pool = UpstreamPool(
            name: "test", members: [member],
            strategy: .leastConns,
            healthCheck: HealthCheckConfig(enabled: false),
            isDefault: true
        )
        let router = PoolRouter()
        router.configure(pools: [pool], overrides: [])

        let sel = router.select(forHost: "any.com")
        XCTAssertNotNil(sel)
        router.connectionStarted(memberId: sel!.memberId)
        let health = router.getHealth()
        XCTAssertEqual(health[sel!.memberId]?.activeConnections, 1)
        router.connectionEnded(memberId: sel!.memberId)
    }
}
