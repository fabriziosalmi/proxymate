import XCTest
@testable import proxymate

final class HSTSTests: XCTestCase {

    // MARK: - Preloaded domains

    func testGooglePreloaded() {
        XCTAssertTrue(HSTSPreload.isPreloaded("google.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("accounts.google.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("mail.google.com"))
    }

    func testApplePreloaded() {
        XCTAssertTrue(HSTSPreload.isPreloaded("apple.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("icloud.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("developer.apple.com"))
    }

    func testBankingPreloaded() {
        XCTAssertTrue(HSTSPreload.isPreloaded("paypal.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("stripe.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("revolut.com"))
    }

    func testSecurityToolsPreloaded() {
        XCTAssertTrue(HSTSPreload.isPreloaded("1password.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("bitwarden.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("signal.org"))
        XCTAssertTrue(HSTSPreload.isPreloaded("proton.me"))
    }

    func testDevPlatformsPreloaded() {
        XCTAssertTrue(HSTSPreload.isPreloaded("github.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("gitlab.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("npmjs.com"))
    }

    func testSubdomainMatching() {
        XCTAssertTrue(HSTSPreload.isPreloaded("sub.github.com"))
        XCTAssertTrue(HSTSPreload.isPreloaded("deep.sub.google.com"))
    }

    func testNotPreloaded() {
        XCTAssertFalse(HSTSPreload.isPreloaded("example.com"))
        XCTAssertFalse(HSTSPreload.isPreloaded("mysite.io"))
        XCTAssertFalse(HSTSPreload.isPreloaded("random-domain.xyz"))
    }

    func testCaseInsensitive() {
        XCTAssertTrue(HSTSPreload.isPreloaded("Google.COM"))
        XCTAssertTrue(HSTSPreload.isPreloaded("GITHUB.COM"))
    }
}
