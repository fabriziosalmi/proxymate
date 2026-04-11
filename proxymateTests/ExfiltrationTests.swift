import XCTest
@testable import proxymate

final class ExfiltrationTests: XCTestCase {

    override func setUp() {
        ExfiltrationScanner.shared.loadPacks(ExfiltrationPack.builtIn)
    }

    // MARK: - AWS Keys

    func testDetectsAWSAccessKey() {
        let headers = "Authorization: AKIAIOSFODNN7EXAMPLE"
        let result = ExfiltrationScanner.shared.scan(headers: headers, target: "")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.packId, "aws-keys")
    }

    func testNoFalsePositiveOnShortString() {
        let headers = "Authorization: AKIA123"  // too short
        let result = ExfiltrationScanner.shared.scan(headers: headers, target: "")
        XCTAssertNil(result)
    }

    // MARK: - GitHub Tokens

    func testDetectsGitHubPAT() {
        let target = "https://api.github.com/repos?token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
        let result = ExfiltrationScanner.shared.scan(headers: "", target: target)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.packId, "github-tokens")
    }

    func testDetectsGitHubFinegrained() {
        let target = "github_pat_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEF"
        let result = ExfiltrationScanner.shared.scan(headers: "", target: target)
        XCTAssertNotNil(result)
    }

    // MARK: - Stripe Keys

    func testDetectsStripeLiveKey() {
        let headers = "Authorization: Bearer sk_live_51ABC123DEF456GHI789JKL"
        let result = ExfiltrationScanner.shared.scan(headers: headers, target: "")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.packId, "stripe-keys")
    }

    // MARK: - Slack Tokens

    func testDetectsSlackBotToken() {
        let headers = "Authorization: Bearer xoxb-1234567890-1234567890-ABCDEFGHIJKLMNOPQRSTUVwx"
        let result = ExfiltrationScanner.shared.scan(headers: headers, target: "")
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.packId, "slack-tokens")
    }

    // MARK: - Generic Secrets

    func testDetectsPrivateKey() {
        ExfiltrationScanner.shared.loadPacks(ExfiltrationPack.builtIn.map {
            var p = $0; p.enabled = true; return p
        })
        let headers = "-----BEGIN RSA PRIVATE KEY-----"
        let result = ExfiltrationScanner.shared.scan(headers: headers, target: "")
        XCTAssertNotNil(result)
    }

    func testDetectsPasswordInURL() {
        ExfiltrationScanner.shared.loadPacks(ExfiltrationPack.builtIn.map {
            var p = $0; p.enabled = true; return p
        })
        let target = "https://user:secretpassword@database.example.com/db"
        let result = ExfiltrationScanner.shared.scan(headers: "", target: target)
        XCTAssertNotNil(result)
    }

    // MARK: - No false positives on normal traffic

    func testNormalTrafficClean() {
        let headers = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n"
        let result = ExfiltrationScanner.shared.scan(headers: headers, target: "http://example.com/page")
        XCTAssertNil(result)
    }

    // MARK: - Redacted preview

    func testPreviewIsRedacted() {
        let headers = "Authorization: AKIAIOSFODNN7EXAMPLEKEY"
        let result = ExfiltrationScanner.shared.scan(headers: headers, target: "")
        XCTAssertNotNil(result)
        if let preview = result?.matchPreview {
            XCTAssertTrue(preview.contains("****"), "Preview should be redacted: \(preview)")
            XCTAssertFalse(preview.contains("AKIAIOSFODNN7EXAMPLEKEY"), "Full key should not appear")
        }
    }
}
