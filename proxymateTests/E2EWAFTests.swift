//
//  E2EWAFTests.swift
//  proxymateTests
//
//  E2E tests for WAF blocking, caching behavior, and rule import.
//

import XCTest
@testable import proxymate

final class E2EWAFTests: XCTestCase {

    // Helper: compile and wait for completion (no Thread.sleep).
    private func compileAndWait(_ engine: RuleEngine, rules: [WAFRule],
                                 timeout: TimeInterval = 2.0) {
        let ex = expectation(description: "compile")
        engine.compile(rules: rules) { ex.fulfill() }
        wait(for: [ex], timeout: timeout)
    }

    // MARK: - WAF rule matching (unit-level but through RuleEngine)

    func testRuleEngineBlockDomain() {
        let engine = RuleEngine()
        compileAndWait(engine, rules: [
            WAFRule(name: "Block evil", kind: .blockDomain, pattern: "evil.com"),
        ])

        XCTAssertNotNil(engine.checkBlock(host: "evil.com"))
        XCTAssertNotNil(engine.checkBlock(host: "sub.evil.com"))
        XCTAssertNil(engine.checkBlock(host: "good.com"))
    }

    func testRuleEngineAllowBypass() {
        let engine = RuleEngine()
        compileAndWait(engine, rules: [
            WAFRule(name: "Allow good", kind: .allowDomain, pattern: "good.com"),
            WAFRule(name: "Block all", kind: .blockDomain, pattern: "good.com"),
        ])

        XCTAssertTrue(engine.isAllowed(host: "good.com"))
        // Note: the block is still there, but allow is checked first in LocalProxy
    }

    func testRuleEngineBlockIP() {
        let engine = RuleEngine()
        compileAndWait(engine, rules: [
            WAFRule(name: "Block IP", kind: .blockIP, pattern: "1.2.3.4"),
        ])

        XCTAssertNotNil(engine.checkBlock(host: "1.2.3.4"))
        XCTAssertNil(engine.checkBlock(host: "1.2.3.5"))
    }

    func testRuleEngineBlockContent() {
        let engine = RuleEngine()
        compileAndWait(engine, rules: [
            WAFRule(name: "Block secret", kind: .blockContent, pattern: "topsecret"),
        ])

        XCTAssertNotNil(engine.checkContent(target: "http://x.com/topsecret", headers: ""))
        XCTAssertNotNil(engine.checkContent(target: "", headers: "X-Data: topsecret\r\n"))
        XCTAssertNil(engine.checkContent(target: "http://x.com/safe", headers: ""))
    }

    func testRuleEngineCompilePerformance() {
        let engine = RuleEngine()
        let rules = (0..<10000).map {
            WAFRule(name: "rule\($0)", kind: .blockDomain, pattern: "domain\($0).com")
        }
        compileAndWait(engine, rules: rules, timeout: 5.0)

        XCTAssertEqual(engine.compiledRuleCount, 10000)
        XCTAssertLessThan(engine.lastCompileTimeMs, 1000, "10K rules should compile in <1s")
    }

    // MARK: - Cache behavior

    func testCacheControlParsing() {
        let cc = CacheManager.parseCacheControl("max-age=300, public")
        XCTAssertEqual(cc.maxAge, 300)
        XCTAssertTrue(cc.public_)
    }

    // MARK: - Rule import integration

    func testImportAndCompile() {
        let text = "evil1.com\nevil2.com\nevil3.com"
        let result = RuleImporter.importRules(from: text, format: .plainDomains,
                                               category: "Test", existingPatterns: [])
        XCTAssertEqual(result.rules.count, 3)

        let engine = RuleEngine()
        compileAndWait(engine, rules: result.rules)

        XCTAssertNotNil(engine.checkBlock(host: "evil1.com"))
        XCTAssertNotNil(engine.checkBlock(host: "evil2.com"))
        XCTAssertNil(engine.checkBlock(host: "safe.com"))
    }

    func testImportHostsAndCompile() {
        let text = "0.0.0.0 ads.tracker.com\n0.0.0.0 bad.analytics.io"
        let result = RuleImporter.importRules(from: text, format: .hosts,
                                               category: "Ads", existingPatterns: [])
        XCTAssertEqual(result.rules.count, 2)

        let engine = RuleEngine()
        compileAndWait(engine, rules: result.rules)

        XCTAssertNotNil(engine.checkBlock(host: "ads.tracker.com"))
        XCTAssertNotNil(engine.checkBlock(host: "sub.ads.tracker.com"))
    }

    // MARK: - HSTS preload

    func testHSTSPreloadedDomains() {
        XCTAssertTrue(HSTSPreload.isPreloaded("google.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("accounts.google.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("github.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("paypal.com"))
        XCTAssertFalse(HSTSPreload.isPreloaded("example.com"))
        XCTAssertFalse(HSTSPreload.isPreloaded("mysite.io"))
    }

    // MARK: - Connection pool

    func testConnectionPoolStats() {
        let pool = ConnectionPool()
        let stats = pool.stats
        XCTAssertEqual(stats.hits, 0)
        XCTAssertEqual(stats.misses, 0)
        XCTAssertEqual(stats.activeConnections, 0)
    }

    func testConnectionPoolMiss() {
        let pool = ConnectionPool()
        let conn = pool.get(host: "nonexistent.com", port: 80)
        XCTAssertNil(conn)
        XCTAssertEqual(pool.stats.misses, 1)
    }
}
