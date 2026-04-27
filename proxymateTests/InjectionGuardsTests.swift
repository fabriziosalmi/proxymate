import XCTest
@testable import proxymate

/// Lock-in tests for the two security-critical input validators that
/// guard shell-as-root and openssl shell-out interpolation. A regression
/// here is a remote-code-execution / cert-forgery vector — these tests
/// must stay in tree.
final class InjectionGuardsTests: XCTestCase {

    // MARK: - TLSManager.validateHostname

    func testHostnameAcceptsTypicalHosts() throws {
        XCTAssertEqual(try TLSManager.validateHostname("example.com"), "example.com")
        XCTAssertEqual(try TLSManager.validateHostname("Example.COM"), "example.com")
        XCTAssertEqual(try TLSManager.validateHostname("a.b.c.example.co.uk"), "a.b.c.example.co.uk")
        XCTAssertEqual(try TLSManager.validateHostname("xn--bcher-kva.example"), "xn--bcher-kva.example")
        XCTAssertEqual(try TLSManager.validateHostname("127.0.0.1"), "127.0.0.1")
    }

    func testHostnameRejectsNewlineSANInjection() {
        // Without sanitization, this hostname injects a second SAN entry
        // into the openssl ext.cnf, forging trust for victim.com.
        let payload = "evil.com\nsubjectAltName = DNS:victim.com"
        XCTAssertThrowsError(try TLSManager.validateHostname(payload))
        XCTAssertThrowsError(try TLSManager.validateHostname("a.com\r\nDNS:victim"))
        XCTAssertThrowsError(try TLSManager.validateHostname("a.com\n"))
        XCTAssertThrowsError(try TLSManager.validateHostname("\n"))
    }

    func testHostnameRejectsSubjFlagInjection() {
        // /CN=...  /-subj continuation attempts.
        XCTAssertThrowsError(try TLSManager.validateHostname("evil.com/CN=victim.com"))
        XCTAssertThrowsError(try TLSManager.validateHostname("a b"))
        XCTAssertThrowsError(try TLSManager.validateHostname("a;b"))
        XCTAssertThrowsError(try TLSManager.validateHostname("$(whoami).com"))
        XCTAssertThrowsError(try TLSManager.validateHostname("`id`.com"))
    }

    func testHostnameRejectsEdgeCases() {
        XCTAssertThrowsError(try TLSManager.validateHostname(""))
        XCTAssertThrowsError(try TLSManager.validateHostname("."))
        XCTAssertThrowsError(try TLSManager.validateHostname(".example.com"))
        XCTAssertThrowsError(try TLSManager.validateHostname("example.com."))
        XCTAssertThrowsError(try TLSManager.validateHostname("a..b"))
        XCTAssertThrowsError(try TLSManager.validateHostname("*.example.com"))
        XCTAssertThrowsError(try TLSManager.validateHostname(String(repeating: "a", count: 254)))
    }

    // MARK: - ProxyManager.validate(pacURL:)

    func testPACURLAcceptsLocalhostHTTP() throws {
        XCTAssertNoThrow(try ProxyManager.validate(pacURL: "http://127.0.0.1:9280/proxy.pac"))
        XCTAssertNoThrow(try ProxyManager.validate(pacURL: "http://localhost:9280/proxy.pac"))
        XCTAssertNoThrow(try ProxyManager.validate(pacURL: "https://pac.internal/wpad.dat"))
    }

    func testPACURLRejectsShellInjection() {
        // Closing the double-quote and chaining commands would let the
        // attacker run arbitrary code as root via networksetup -setautoproxyurl.
        XCTAssertThrowsError(try ProxyManager.validate(
            pacURL: #"http://127.0.0.1:9280/p"; rm -rf /; echo ""#))
        XCTAssertThrowsError(try ProxyManager.validate(
            pacURL: "http://127.0.0.1:9280/$(whoami)"))
        XCTAssertThrowsError(try ProxyManager.validate(
            pacURL: "http://127.0.0.1:9280/`id`"))
        XCTAssertThrowsError(try ProxyManager.validate(
            pacURL: "http://127.0.0.1:9280/proxy.pac\nmalicious"))
        XCTAssertThrowsError(try ProxyManager.validate(
            pacURL: "http://127.0.0.1:9280/p\\x"))
    }

    func testPACURLRejectsForeignSchemes() {
        XCTAssertThrowsError(try ProxyManager.validate(pacURL: "file:///etc/passwd"))
        XCTAssertThrowsError(try ProxyManager.validate(pacURL: "javascript:alert(1)"))
        XCTAssertThrowsError(try ProxyManager.validate(pacURL: "data:text/javascript,alert(1)"))
        XCTAssertThrowsError(try ProxyManager.validate(pacURL: "ftp://example.com/p.pac"))
    }

    func testPACURLRejectsCredentialsAndFragment() {
        XCTAssertThrowsError(try ProxyManager.validate(
            pacURL: "http://user:pass@127.0.0.1:9280/proxy.pac"))
        XCTAssertThrowsError(try ProxyManager.validate(
            pacURL: "http://127.0.0.1:9280/proxy.pac#frag"))
    }

    func testPACURLRejectsBadHostOrPort() {
        XCTAssertThrowsError(try ProxyManager.validate(pacURL: "http://"))
        XCTAssertThrowsError(try ProxyManager.validate(
            pacURL: "http://127.0.0.1:0/proxy.pac"))
        XCTAssertThrowsError(try ProxyManager.validate(
            pacURL: "http://127.0.0.1:99999/proxy.pac"))
        XCTAssertThrowsError(try ProxyManager.validate(
            pacURL: "http://evil host/proxy.pac"))
    }

    func testPACURLRejectsOversize() {
        let big = "http://127.0.0.1:9280/" + String(repeating: "a", count: 1100)
        XCTAssertThrowsError(try ProxyManager.validate(pacURL: big))
    }
}
