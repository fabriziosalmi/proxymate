import XCTest
@testable import proxymate

final class CloudSyncTests: XCTestCase {

    // MARK: - Merge logic (pure, no iCloud dependency)

    func testMergeRulesUnion() {
        let local = [
            WAFRule(name: "A", kind: .blockDomain, pattern: "a.com"),
            WAFRule(name: "B", kind: .blockDomain, pattern: "b.com"),
        ]
        let remote = [
            WAFRule(name: "B", kind: .blockDomain, pattern: "b.com"),
            WAFRule(name: "C", kind: .blockDomain, pattern: "c.com"),
        ]
        let merged = CloudSync.mergeRules(local: local, remote: remote)
        XCTAssertEqual(merged.count, 3) // A + B + C (B deduped)
        let patterns = Set(merged.map(\.pattern))
        XCTAssertTrue(patterns.contains("a.com"))
        XCTAssertTrue(patterns.contains("b.com"))
        XCTAssertTrue(patterns.contains("c.com"))
    }

    func testMergeRulesKeepsLocal() {
        let local = [WAFRule(name: "Local", kind: .blockDomain, pattern: "x.com")]
        let remote = [WAFRule(name: "Remote", kind: .blockIP, pattern: "x.com")]
        let merged = CloudSync.mergeRules(local: local, remote: remote)
        // Same pattern (case insensitive) → keep local only
        XCTAssertEqual(merged.count, 1)
        XCTAssertEqual(merged[0].name, "Local")
    }

    func testMergeAllowlistUnion() {
        let local = [AllowEntry(pattern: "10.0.0.0/8")]
        let remote = [AllowEntry(pattern: "192.168.0.0/16")]
        let merged = CloudSync.mergeAllowlist(local: local, remote: remote)
        XCTAssertEqual(merged.count, 2)
    }

    func testMergeAllowlistDedup() {
        let local = [AllowEntry(pattern: "10.0.0.0/8")]
        let remote = [AllowEntry(pattern: "10.0.0.0/8")]
        let merged = CloudSync.mergeAllowlist(local: local, remote: remote)
        XCTAssertEqual(merged.count, 1)
    }

    func testMergeEmptyRemote() {
        let local = [WAFRule(name: "A", kind: .blockDomain, pattern: "a.com")]
        let merged = CloudSync.mergeRules(local: local, remote: [])
        XCTAssertEqual(merged.count, 1)
    }

    func testMergeEmptyLocal() {
        let remote = [WAFRule(name: "A", kind: .blockDomain, pattern: "a.com")]
        let merged = CloudSync.mergeRules(local: [], remote: remote)
        XCTAssertEqual(merged.count, 1)
    }
}
