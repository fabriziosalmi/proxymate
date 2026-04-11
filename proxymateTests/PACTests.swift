import XCTest
@testable import proxymate

final class PACTests: XCTestCase {

    func testPACSettingsDefaults() {
        let s = PACSettings()
        XCTAssertFalse(s.enabled)
        XCTAssertEqual(s.port, 9280)
        XCTAssertEqual(s.mode, .allTraffic)
    }

    func testPACModes() {
        XCTAssertEqual(PACSettings.PACMode.allCases.count, 2)
    }

    func testSOCKS5SettingsDefaults() {
        let s = SOCKS5Settings()
        XCTAssertFalse(s.enabled)
        XCTAssertEqual(s.port, 1080)
    }

    func testDiskCacheSettingsDefaults() {
        let s = DiskCacheSettings()
        XCTAssertFalse(s.enabled)
        XCTAssertEqual(s.maxSizeMB, 512)
    }

    func testMetricsSettingsDefaults() {
        let s = MetricsSettings()
        XCTAssertFalse(s.enabled)
        XCTAssertEqual(s.port, 9199)
    }

    func testWebhookSettingsDefaults() {
        let s = WebhookSettings()
        XCTAssertFalse(s.enabled)
        XCTAssertTrue(s.urls.isEmpty)
        XCTAssertTrue(s.onBlock)
        XCTAssertTrue(s.onExfiltration)
        XCTAssertTrue(s.onBudget)
        XCTAssertEqual(s.debounceSeconds, 5)
    }

    func testCloudSyncSettingsDefaults() {
        let s = CloudSyncSettings()
        XCTAssertFalse(s.enabled)
        XCTAssertTrue(s.syncRules)
        XCTAssertTrue(s.syncAllowlist)
    }

    func testMITMSettingsDefaults() {
        let s = MITMSettings()
        XCTAssertFalse(s.enabled)
        XCTAssertFalse(s.caInstalled)
        XCTAssertTrue(s.excludeHosts.contains("*.apple.com"))
        XCTAssertTrue(s.excludeHosts.contains("*.banking.*"))
    }

    func testDNSSettingsDefaults() {
        let s = DNSSettings()
        XCTAssertFalse(s.enabled)
        XCTAssertEqual(s.provider, .cloudflare)
        XCTAssertEqual(s.cacheTTL, 300)
    }

    func testDNSProviderURLs() {
        XCTAssertTrue(DNSSettings.DoHProvider.cloudflare.url.contains("1.1.1.1"))
        XCTAssertTrue(DNSSettings.DoHProvider.quad9.url.contains("quad9"))
        XCTAssertTrue(DNSSettings.DoHProvider.google.url.contains("dns.google"))
        XCTAssertTrue(DNSSettings.DoHProvider.custom.url.isEmpty)
    }
}
