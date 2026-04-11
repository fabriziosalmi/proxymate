import XCTest
@testable import proxymate

final class LocalizationTests: XCTestCase {

    // Verify all string constants are non-empty
    func testAllStringsNonEmpty() {
        let strings: [String] = [
            Strings.appName, Strings.enabled, Strings.disabled,
            Strings.cancel, Strings.add, Strings.delete, Strings.save, Strings.quit,
            Strings.proxies, Strings.logs, Strings.stats, Strings.rules,
            Strings.ai, Strings.cache, Strings.privacy,
            Strings.welcome, Strings.chooseProfile, Strings.startProxying,
            Strings.next, Strings.back, Strings.ready,
            Strings.profilePrivacy, Strings.profileDeveloper,
            Strings.profileEnterprise, Strings.profileFamily, Strings.profileMinimal,
            Strings.allowed, Strings.blocked, Strings.status,
            Strings.activeSince, Strings.cacheHitRate, Strings.logEntries,
            Strings.dntHeader, Strings.gpcHeader, Strings.stripUA,
            Strings.stripReferer, Strings.stripCookies, Strings.stripETag,
            Strings.today, Strings.thisMonth, Strings.session,
            Strings.providers, Strings.budgetCaps, Strings.loopBreaker, Strings.resetStats,
            Strings.madeBy, Strings.zeroTelemetry, Strings.runWizardAgain,
            Strings.blockedNotifTitle, Strings.exfilNotifTitle, Strings.budgetNotifTitle,
        ]
        for s in strings {
            XCTAssertFalse(s.isEmpty, "String constant should not be empty: '\(s)'")
        }
    }

    func testAppName() {
        XCTAssertEqual(Strings.appName, "Proxymate")
    }
}
