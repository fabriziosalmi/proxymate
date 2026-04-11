import XCTest
@testable import proxymate

final class RuleImportTests: XCTestCase {

    // MARK: - Hosts file parsing

    func testParseHostsFile() {
        let text = """
        # comment
        0.0.0.0 ads.example.com
        127.0.0.1 tracker.io
        0.0.0.0 localhost
        0.0.0.0 evil.com # inline comment
        """
        let result = RuleImporter.importRules(from: text, format: .hosts,
                                               category: "Test", existingPatterns: [])
        XCTAssertEqual(result.rules.count, 3) // localhost skipped
        XCTAssertTrue(result.rules.allSatisfy { $0.kind == .blockDomain })
        XCTAssertTrue(result.rules.contains { $0.pattern == "ads.example.com" })
        XCTAssertTrue(result.rules.contains { $0.pattern == "evil.com" })
    }

    // MARK: - Adblock Plus parsing

    func testParseAdblockPlus() {
        let text = """
        ! Title: Test List
        ||ads.example.com^
        ||tracker.io^
        ||evil.com
        ! comment
        """
        let result = RuleImporter.importRules(from: text, format: .adblockPlus,
                                               category: "Test", existingPatterns: [])
        XCTAssertEqual(result.rules.count, 3)
        XCTAssertTrue(result.rules.contains { $0.pattern == "ads.example.com" })
    }

    // MARK: - Plain domains

    func testParsePlainDomains() {
        let text = "evil.com\ntracker.io\n\n# comment\nbad.site"
        let result = RuleImporter.importRules(from: text, format: .plainDomains,
                                               category: "Test", existingPatterns: [])
        XCTAssertEqual(result.rules.count, 3)
    }

    // MARK: - Plain IPs

    func testParsePlainIPs() {
        let text = "1.2.3.4\n5.6.7.8\nnot-an-ip"
        let result = RuleImporter.importRules(from: text, format: .plainIPs,
                                               category: "Test", existingPatterns: [])
        XCTAssertEqual(result.rules.count, 2)
        XCTAssertTrue(result.rules.allSatisfy { $0.kind == .blockIP })
        XCTAssertEqual(result.skipped, 1)
    }

    // MARK: - Deduplication

    func testDedup() {
        let text = "evil.com\ntracker.io"
        let result = RuleImporter.importRules(from: text, format: .plainDomains,
                                               category: "Test",
                                               existingPatterns: ["evil.com"])
        XCTAssertEqual(result.rules.count, 1)
        XCTAssertEqual(result.skipped, 1)
    }

    // MARK: - Auto-detect

    func testAutoDetectHosts() {
        let text = "0.0.0.0 evil.com\n0.0.0.0 bad.com"
        let format = RuleImporter.detectFormat(text)
        XCTAssertEqual(format, .hosts)
    }

    func testAutoDetectABP() {
        let text = "||evil.com^\n||bad.com^"
        let format = RuleImporter.detectFormat(text)
        XCTAssertEqual(format, .adblockPlus)
    }

    func testAutoDetectIPs() {
        let text = "1.2.3.4\n5.6.7.8\n9.10.11.12"
        let format = RuleImporter.detectFormat(text)
        XCTAssertEqual(format, .plainIPs)
    }

    // MARK: - Export

    func testExportHosts() {
        let rules = [
            WAFRule(name: "a", kind: .blockDomain, pattern: "evil.com"),
            WAFRule(name: "b", kind: .blockIP, pattern: "1.2.3.4"),
        ]
        let output = RuleImporter.exportAsHosts(rules)
        XCTAssertTrue(output.contains("0.0.0.0 evil.com"))
        XCTAssertFalse(output.contains("1.2.3.4")) // IPs not exported as hosts
    }

    // MARK: - Category assignment

    func testCategoryAssigned() {
        let text = "evil.com"
        let result = RuleImporter.importRules(from: text, format: .plainDomains,
                                               category: "Malware", existingPatterns: [])
        XCTAssertEqual(result.rules.first?.category, "Malware")
    }
}
