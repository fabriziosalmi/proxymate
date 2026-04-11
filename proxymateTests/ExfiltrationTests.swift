import XCTest
@testable import proxymate

final class ExfiltrationTests: XCTestCase {

    // MARK: - Regex pattern validation (no singleton, no race conditions)

    func testAWSKeyRegex() {
        let regex = try! NSRegularExpression(pattern: #"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)"#)
        let valid = " AKIAIOSFODNN7EXAMPLE "
        let short = " AKIA1234 "
        XCTAssertNotNil(regex.firstMatch(in: valid, range: NSRange(valid.startIndex..., in: valid)))
        XCTAssertNil(regex.firstMatch(in: short, range: NSRange(short.startIndex..., in: short)))
    }

    func testGitHubPATRegex() {
        let regex = try! NSRegularExpression(pattern: #"ghp_[A-Za-z0-9]{36}"#)
        let token = "ghp_" + String(repeating: "A", count: 36)
        XCTAssertNotNil(regex.firstMatch(in: token, range: NSRange(token.startIndex..., in: token)))
    }

    func testGitHubOAuthRegex() {
        let regex = try! NSRegularExpression(pattern: #"gho_[A-Za-z0-9]{36}"#)
        let token = "gho_" + String(repeating: "X", count: 36)
        XCTAssertNotNil(regex.firstMatch(in: token, range: NSRange(token.startIndex..., in: token)))
    }

    func testStripeKeyRegex() {
        let regex = try! NSRegularExpression(pattern: #"sk_live_[A-Za-z0-9]{24,}"#)
        let key = "sk_live_" + String(repeating: "a", count: 24)
        XCTAssertNotNil(regex.firstMatch(in: key, range: NSRange(key.startIndex..., in: key)))
    }

    func testSlackBotTokenRegex() {
        let regex = try! NSRegularExpression(pattern: #"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}"#)
        let token = "xoxb-1234567890-1234567890-" + String(repeating: "A", count: 24)
        XCTAssertNotNil(regex.firstMatch(in: token, range: NSRange(token.startIndex..., in: token)))
    }

    func testPrivateKeyRegex() {
        let regex = try! NSRegularExpression(pattern: #"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"#)
        let rsa = "-----BEGIN RSA PRIVATE KEY-----"
        let generic = "-----BEGIN PRIVATE KEY-----"
        XCTAssertNotNil(regex.firstMatch(in: rsa, range: NSRange(rsa.startIndex..., in: rsa)))
        XCTAssertNotNil(regex.firstMatch(in: generic, range: NSRange(generic.startIndex..., in: generic)))
    }

    func testPasswordInURLRegex() {
        let regex = try! NSRegularExpression(pattern: #"[a-z]+://[^:]+:[^@]{3,}@[a-z0-9]"#)
        let url = "https://admin:s3cretP4ss@db.example.com"
        XCTAssertNotNil(regex.firstMatch(in: url, range: NSRange(url.startIndex..., in: url)))
    }

    func testIBANRegex() {
        let regex = try! NSRegularExpression(pattern: #"[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){2,7}[A-Z0-9]{1,4}"#)
        let iban = "DE89370400440532013000"
        XCTAssertNotNil(regex.firstMatch(in: iban, range: NSRange(iban.startIndex..., in: iban)))
    }

    func testItalianFiscalCodeRegex() {
        let regex = try! NSRegularExpression(pattern: #"[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]"#)
        let cf = "RSSMRA85M01H501Z"
        XCTAssertNotNil(regex.firstMatch(in: cf, range: NSRange(cf.startIndex..., in: cf)))
    }

    // MARK: - All built-in regex patterns compile

    func testAllPatternsCompile() {
        for pack in ExfiltrationPack.builtIn {
            for pattern in pack.patterns {
                XCTAssertNoThrow(
                    try NSRegularExpression(pattern: pattern.regex),
                    "Pattern '\(pattern.name)' in pack '\(pack.name)' should compile"
                )
            }
        }
    }

    // MARK: - Normal strings don't match

    func testNormalTextNoMatch() {
        let patterns = ExfiltrationPack.builtIn.flatMap(\.patterns)
        let normal = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n"
        for pattern in patterns {
            let regex = try! NSRegularExpression(pattern: pattern.regex)
            let match = regex.firstMatch(in: normal, range: NSRange(normal.startIndex..., in: normal))
            XCTAssertNil(match, "Pattern '\(pattern.name)' should not match normal HTTP traffic")
        }
    }
}
