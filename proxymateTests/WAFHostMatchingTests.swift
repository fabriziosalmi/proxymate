//
//  WAFHostMatchingTests.swift
//  proxymateTests
//
//  Host forms that must not slip past blocklists, content rules or the PAC.
//

import XCTest
import JavaScriptCore
@testable import proxymate

final class WAFHostMatchingTests: XCTestCase {

    // MARK: - Content rules and local-development suppression

    private func engine(with rules: [WAFRule]) -> RuleEngine {
        let engine = RuleEngine()
        let ex = expectation(description: "compile")
        engine.compile(rules: rules) { ex.fulfill() }
        wait(for: [ex], timeout: 2)
        return engine
    }

    /// Local development traffic skips content rules, but only for real
    /// loopback / private IP literals: a public name that starts with
    /// "10." or "127." is attacker-controlled and must be checked.
    func testContentRulesApplyToNamesThatLookLikePrivateIPs() {
        let e = engine(with: [WAFRule(name: "secret", kind: .blockContent, pattern: "topsecret")])
        for host in ["10.evil.com", "127.evil.net", "192.168.evil.org", "10.0.0.1.evil.com"] {
            XCTAssertNotNil(e.checkContent(target: "/x?q=topsecret", headers: "", host: host), host)
        }
        for host in ["10.0.0.5", "127.0.0.1", "192.168.1.20", "localhost", "printer.local"] {
            XCTAssertNil(e.checkContent(target: "/x?q=topsecret", headers: "", host: host), host)
        }
    }

    // MARK: - PAC local bypass

    private func findProxy(_ pac: String, host: String) -> String {
        let ctx = JSContext()!
        // Minimal PAC runtime: isInNet is only reached for IPv4 literals.
        ctx.evaluateScript("""
        function isPlainHostName(h) { return h.indexOf('.') < 0; }
        function shExpMatch(s, p) { return new RegExp('^' + p.replace(/\\./g, '\\\\.').replace(/\\*/g, '.*') + '$').test(s); }
        function dnsDomainIs(h, d) { return h.length >= d.length && h.substring(h.length - d.length) == d; }
        function isInNet(h, net, mask) {
            function n(ip) { var p = ip.split('.'); return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + (+p[3]); }
            if (!/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(h)) throw new Error('isInNet would resolve ' + h);
            return ((n(h) & n(mask)) >>> 0) == ((n(net) & n(mask)) >>> 0);
        }
        """)
        ctx.evaluateScript(pac)
        if let ex = ctx.exception { XCTFail("PAC error: \(ex)") }
        return ctx.objectForKeyedSubscript("FindProxyForURL")
            .call(withArguments: ["http://\(host)/", host]).toString()
    }

    func testPACSendsOnlyRealLocalAddressesDirect() {
        for mode in PACSettings.PACMode.allCases {
            let pac = PACServer.script(mode: mode, proxyPort: 8888, socks5Port: 0, directDomains: [])
            for host in ["10.evil.com", "127.evil.net", "172.16.evil.org", "192.168.evil.org"] {
                XCTAssertTrue(findProxy(pac, host: host).hasPrefix("PROXY 127.0.0.1:8888"), "\(mode) \(host)")
            }
            for host in ["10.1.2.3", "127.0.0.1", "172.16.4.5", "192.168.0.9", "localhost", "intranet"] {
                XCTAssertEqual(findProxy(pac, host: host), "DIRECT", "\(mode) \(host)")
            }
        }
    }

    // MARK: - Blacklist lookup

    func testBlacklistBlocksSubdomainsOfListedDomains() {
        let source = BlacklistSource(name: "t-dom", url: "https://example.invalid/d", category: .malware, format: .plainDomains)
        BlacklistManager.shared.install(sourceID: source.id, domains: ["evil-test-domain.com"], ips: [])
        XCTAssertNotNil(BlacklistManager.shared.lookup(host: "evil-test-domain.com", enabledSources: [source]))
        XCTAssertNotNil(BlacklistManager.shared.lookup(host: "a.b.evil-test-domain.com", enabledSources: [source]))
        XCTAssertNil(BlacklistManager.shared.lookup(host: "notevil-test-domain.com", enabledSources: [source]))
    }

    func testBlacklistBlocksListedIPs() {
        let source = BlacklistSource(name: "t-ip", url: "https://example.invalid/i", category: .torExits, format: .plainIPs)
        BlacklistManager.shared.install(sourceID: source.id, domains: [], ips: ["203.0.113.77"])
        XCTAssertNotNil(BlacklistManager.shared.lookup(host: "203.0.113.77", enabledSources: [source]))
        XCTAssertNil(BlacklistManager.shared.lookup(host: "203.0.113.78", enabledSources: [source]))
    }
    // MARK: - Allowlist CIDR

    /// The onboarding "Corporate LAN" option allowlists 10.0.0.0/8, and an
    /// allow entry overrides every block. Only real IPv4 literals may match.
    func testAllowlistCIDROnlyMatchesIPv4Literals() {
        let entries = [AllowEntry(pattern: "10.0.0.0/8"), AllowEntry(pattern: "192.168.0.0/16")]
        for host in ["10.0.0.1.evil.com", "10.0.0.1.2", "evil.10.0.0.1", "192.168.1.x.1.evil.com", "10.0.0.+1"] {
            XCTAssertFalse(AllowlistMatcher.isAllowed(host: host, port: nil, entries: entries), host)
        }
        for host in ["10.0.0.1", "10.255.3.4", "192.168.1.1"] {
            XCTAssertTrue(AllowlistMatcher.isAllowed(host: host, port: nil, entries: entries), host)
        }
    }
}
