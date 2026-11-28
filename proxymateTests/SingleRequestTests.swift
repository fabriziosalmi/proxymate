//
//  SingleRequestTests.swift
//  proxymateTests
//
//  Regression tests for three proxy boundaries:
//  - the main listener accepts loopback clients only;
//  - a request that follows the checked one on the same client connection
//    (pipelined or keep-alive) never reaches the upstream unchecked;
//  - the mitmproxy sidecar listens on loopback and verifies origin TLS.
//

import XCTest
import Network
import Darwin
@testable import proxymate

/// Upstream stand-in that records every byte it receives. It deliberately
/// ignores `Connection: close` and keeps connections alive, which is the
/// worst case for request bounding.
final class RecordingUpstream {
    enum Mode {
        /// Answer every header block with this status line, keep the connection open.
        case respond(String)
        /// Answer the first header block with this status line, then echo raw bytes.
        case tunnel(String)
    }

    private var listener: NWListener?
    private let queue = DispatchQueue(label: "recording-upstream")
    private let lock = NSLock()
    private var received = Data()
    private let mode: Mode
    private(set) var port: UInt16 = 0

    init(mode: Mode) { self.mode = mode }

    var bytes: Data { lock.lock(); defer { lock.unlock() }; return received }
    var text: String { String(decoding: bytes, as: UTF8.self) }

    func start() throws {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        let l = try NWListener(using: params)
        let sem = DispatchSemaphore(value: 0)
        l.stateUpdateHandler = { s in
            if case .ready = s, let p = l.port?.rawValue { self.port = p; sem.signal() }
        }
        l.newConnectionHandler = { [weak self] c in
            guard let self else { return }
            c.start(queue: self.queue)
            self.read(c, pending: Data(), tunnelling: false)
        }
        l.start(queue: queue)
        listener = l
        _ = sem.wait(timeout: .now() + 5)
    }

    func stop() { listener?.cancel() }

    private func read(_ c: NWConnection, pending: Data, tunnelling: Bool) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, done, err in
            guard let self else { return }
            var buf = pending
            var tunnelling = tunnelling
            if let data, !data.isEmpty {
                self.lock.lock(); self.received.append(data); self.lock.unlock()
                if tunnelling {
                    c.send(content: data, completion: .contentProcessed { _ in })
                } else {
                    buf.append(data)
                }
            }
            let sep = Data("\r\n\r\n".utf8)
            while !tunnelling, let r = buf.range(of: sep) {
                buf.removeSubrange(..<r.upperBound)
                switch self.mode {
                case .respond(let status):
                    let body = "ok\n"
                    let resp = "\(status)\r\nContent-Length: \(body.utf8.count)\r\nConnection: keep-alive\r\n\r\n\(body)"
                    c.send(content: Data(resp.utf8), completion: .contentProcessed { _ in })
                case .tunnel(let status):
                    c.send(content: Data("\(status)\r\n\r\n".utf8), completion: .contentProcessed { _ in })
                    tunnelling = true
                    if !buf.isEmpty {
                        c.send(content: buf, completion: .contentProcessed { _ in })
                        buf.removeAll()
                    }
                }
            }
            if done || err != nil { c.cancel(); return }
            self.read(c, pending: buf, tunnelling: tunnelling)
        }
    }
}

/// Sends `payload` to 127.0.0.1:`port` (optionally `then` after the first
/// response bytes) and collects whatever comes back within `seconds`.
func exchange(port: UInt16, host: String = "127.0.0.1", payload: Data, then: Data? = nil,
              later: [Data] = [], halfClose: Bool = false, seconds: Double = 1.5) -> (connected: Bool, response: Data) {
    let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
    let q = DispatchQueue(label: "exchange-client")
    let lock = NSLock()
    var response = Data()
    var connected = false
    var sentThen = false
    let ready = DispatchSemaphore(value: 0)
    conn.stateUpdateHandler = { state in
        switch state {
        case .ready: lock.lock(); connected = true; lock.unlock(); ready.signal()
        case .failed, .waiting: ready.signal()
        default: break
        }
    }
    conn.start(queue: q)
    _ = ready.wait(timeout: .now() + 2)
    lock.lock(); let isUp = connected; lock.unlock()
    guard isUp else { conn.cancel(); return (false, Data()) }
    conn.send(content: payload, completion: .contentProcessed { _ in })
    if halfClose {
        // Shut down our write side (FIN) but keep reading.
        conn.send(content: nil, contentContext: .finalMessage, isComplete: true,
                  completion: .contentProcessed { _ in })
    }
    func receiveLoop() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, done, err in
            if let data, !data.isEmpty {
                lock.lock(); response.append(data)
                let shouldSend = !sentThen && then != nil
                if shouldSend { sentThen = true }
                lock.unlock()
                if shouldSend, let then { conn.send(content: then, completion: .contentProcessed { _ in }) }
            }
            if done || err != nil { return }
            receiveLoop()
        }
    }
    receiveLoop()
    for chunk in later {
        // Separate writes, so they arrive after the header block was routed.
        Thread.sleep(forTimeInterval: 0.2)
        conn.send(content: chunk, completion: .contentProcessed { _ in })
    }
    Thread.sleep(forTimeInterval: seconds)
    conn.cancel()
    lock.lock(); defer { lock.unlock() }
    return (true, response)
}

final class SingleRequestTests: XCTestCase {

    private func startProxy(upstreamPort: UInt16) -> (LocalProxy, UInt16) {
        let proxy = LocalProxy()
        var port: UInt16 = 0
        let sem = DispatchSemaphore(value: 0)
        proxy.start(
            upstream: .init(host: "127.0.0.1", port: upstreamPort),
            rules: [WAFRule(name: "Block evil", kind: .blockDomain, pattern: "evil.test")],
            allowlist: [],
            privacy: PrivacySettings(),
            blacklistSources: []
        ) { r in if case .success(let p) = r { port = p }; sem.signal() }
        _ = sem.wait(timeout: .now() + 5)
        return (proxy, port)
    }

    private func withProxy(_ mode: RecordingUpstream.Mode,
                           _ body: (_ proxyPort: UInt16, _ upstream: RecordingUpstream) throws -> Void) throws {
        let upstream = RecordingUpstream(mode: mode)
        try upstream.start()
        let (proxy, port) = startProxy(upstreamPort: upstream.port)
        defer { proxy.stop(); upstream.stop() }
        XCTAssertGreaterThan(port, 0)
        try body(port, upstream)
    }

    private let evil = "GET http://evil.test/smuggled HTTP/1.1\r\nHost: evil.test\r\n\r\n"

    // MARK: - Listener binding

    func testMainListenerBindsLoopbackOnly() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, _ in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
            p.arguments = ["-nP", "-a", "-p", "\(getpid())", "-iTCP:\(port)", "-sTCP:LISTEN"]
            let pipe = Pipe(); p.standardOutput = pipe
            try p.run(); p.waitUntilExit()
            let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            XCTAssertTrue(out.contains("127.0.0.1:\(port)"), "listener not on loopback:\n\(out)")
            XCTAssertFalse(out.contains("*:\(port)"), "listener bound to all interfaces:\n\(out)")
        }
    }

    func testMainListenerRefusesNonLoopbackAddress() throws {
        guard let lan = Self.firstNonLoopbackIPv4() else {
            throw XCTSkip("no non-loopback IPv4 interface on this host")
        }
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, upstream in
            let payload = Data("GET http://allowed.example/lan HTTP/1.1\r\nHost: allowed.example\r\n\r\n".utf8)
            let r = exchange(port: port, host: lan, payload: payload, seconds: 1)
            XCTAssertFalse(r.connected && !r.response.isEmpty, "proxy answered on \(lan)")
            XCTAssertFalse(upstream.text.contains("allowed.example/lan"))
        }
    }

    // MARK: - One request per connection

    func testPipelinedRequestAfterBodylessRequestIsNotForwarded() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, upstream in
            let first = "GET http://good.example/one HTTP/1.1\r\nHost: good.example\r\nConnection: keep-alive\r\n\r\n"
            _ = exchange(port: port, payload: Data((first + evil).utf8))
            XCTAssertTrue(upstream.text.contains("good.example/one"))
            XCTAssertTrue(upstream.text.contains("Connection: close"))
            XCTAssertFalse(upstream.text.lowercased().contains("connection: keep-alive"))
            XCTAssertFalse(upstream.text.contains("evil.test"), "upstream saw:\n\(upstream.text)")
        }
    }

    func testKeepAliveRequestSentLaterIsNotForwarded() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, upstream in
            let first = "GET http://good.example/one HTTP/1.1\r\nHost: good.example\r\n\r\n"
            _ = exchange(port: port, payload: Data(first.utf8), then: Data(evil.utf8))
            XCTAssertTrue(upstream.text.contains("good.example/one"))
            XCTAssertFalse(upstream.text.contains("evil.test"), "upstream saw:\n\(upstream.text)")
        }
    }

    func testPipelinedRequestAfterContentLengthBodyIsNotForwarded() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, upstream in
            let first = "POST http://good.example/form HTTP/1.1\r\nHost: good.example\r\nContent-Length: 5\r\n\r\nhello"
            _ = exchange(port: port, payload: Data((first + evil).utf8))
            XCTAssertTrue(upstream.text.hasSuffix("\r\n\r\nhello"), "upstream saw:\n\(upstream.text)")
            XCTAssertFalse(upstream.text.contains("evil.test"))
        }
    }

    func testPipelinedRequestAfterChunkedBodyIsNotForwarded() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, upstream in
            let body = "5;ext=1\r\nhello\r\n0\r\nX-Trailer: t\r\n\r\n"
            let first = "POST http://good.example/up HTTP/1.1\r\nHost: good.example\r\nTransfer-Encoding: chunked\r\n\r\n"
            _ = exchange(port: port, payload: Data((first + body + evil).utf8))
            XCTAssertTrue(upstream.text.hasSuffix(body), "upstream saw:\n\(upstream.text)")
            XCTAssertFalse(upstream.text.contains("evil.test"))
        }
    }

    func testResponseIsDeliveredAfterClientHalfClose() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, _ in
            let r = exchange(port: port, payload: Data((
                "GET http://good.example/ HTTP/1.1\r\nHost: good.example\r\n\r\n" + evil).utf8), halfClose: true)
            let resp = String(decoding: r.response, as: UTF8.self)
            XCTAssertTrue(resp.hasPrefix("HTTP/1.1 200 OK"), "got: \(resp.debugDescription)")
        }
    }

    func testUpgradeWithoutSwitchingProtocolsKeepsClientSideClosed() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, upstream in
            let first = "GET http://good.example/ws HTTP/1.1\r\nHost: good.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            _ = exchange(port: port, payload: Data((first + evil).utf8))
            XCTAssertTrue(upstream.text.contains("good.example/ws"))
            XCTAssertTrue(upstream.text.contains("Connection: Upgrade"))
            XCTAssertFalse(upstream.text.contains("evil.test"), "upstream saw:\n\(upstream.text)")
        }
    }

    func testUpgradeWithSwitchingProtocolsBecomesAStream() throws {
        try withProxy(.tunnel("HTTP/1.1 101 Switching Protocols")) { port, upstream in
            let first = "GET http://good.example/ws HTTP/1.1\r\nHost: good.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            let r = exchange(port: port, payload: Data(first.utf8), then: Data("FRAME-BYTES".utf8))
            XCTAssertTrue(upstream.text.contains("FRAME-BYTES"))
            XCTAssertTrue(String(decoding: r.response, as: UTF8.self).contains("FRAME-BYTES"))
        }
    }

    func testConnectTunnelStillCarriesBytesAfter200() throws {
        try withProxy(.tunnel("HTTP/1.1 200 Connection Established")) { port, upstream in
            let connect = "CONNECT good.example:443 HTTP/1.1\r\nHost: good.example:443\r\n\r\n"
            let r = exchange(port: port, payload: Data(connect.utf8), then: Data("TLS-CLIENT-HELLO".utf8))
            XCTAssertTrue(upstream.text.contains("TLS-CLIENT-HELLO"))
            XCTAssertTrue(String(decoding: r.response, as: UTF8.self).contains("TLS-CLIENT-HELLO"))
        }
    }

    func testRefusedConnectForwardsNothingMore() throws {
        try withProxy(.respond("HTTP/1.1 403 Forbidden")) { port, upstream in
            let connect = "CONNECT good.example:443 HTTP/1.1\r\nHost: good.example:443\r\n\r\n"
            _ = exchange(port: port, payload: Data(connect.utf8), then: Data(evil.utf8))
            XCTAssertTrue(upstream.text.contains("CONNECT good.example:443"))
            XCTAssertFalse(upstream.text.contains("evil.test"), "upstream saw:\n\(upstream.text)")
        }
    }

    // MARK: - Bodies that arrive in later segments

    func testContentLengthBodySplitAcrossWritesStopsAtItsEnd() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, upstream in
            let head = "POST http://good.example/form HTTP/1.1\r\nHost: good.example\r\nContent-Length: 10\r\n\r\n"
            _ = exchange(port: port, payload: Data(head.utf8),
                         later: [Data("hello".utf8), Data(("world" + evil).utf8)])
            XCTAssertTrue(upstream.text.hasSuffix("\r\n\r\nhelloworld"), "upstream saw:\n\(upstream.text)")
            XCTAssertFalse(upstream.text.contains("evil.test"))
        }
    }

    func testChunkedBodySplitAcrossWritesStopsAtItsEnd() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, upstream in
            let head = "POST http://good.example/up HTTP/1.1\r\nHost: good.example\r\nTransfer-Encoding: chunked\r\n\r\n"
            _ = exchange(port: port, payload: Data(head.utf8),
                         later: [Data("5\r\nhel".utf8), Data(("lo\r\n0\r\n\r\n" + evil).utf8)])
            XCTAssertTrue(upstream.text.hasSuffix("5\r\nhello\r\n0\r\n\r\n"), "upstream saw:\n\(upstream.text)")
            XCTAssertFalse(upstream.text.contains("evil.test"))
        }
    }

    // MARK: - Non-strict syntax is refused before anything is forwarded

    func testNonStrictHeadsAreRejectedWith400() throws {
        let heads = [
            // bare LF ends the head for a lenient upstream: hides a second request
            "GET http://good.example/ HTTP/1.1\r\nHost: good.example\r\n\n" + "GET http://evil.test/ HTTP/1.1\r\nHost: evil.test\r\n\r\n",
            // whitespace before the colon
            "POST http://good.example/ HTTP/1.1\r\nHost: good.example\r\nContent-Length : 5\r\n\r\n",
            // obs-fold continuation carrying a framing header
            "POST http://good.example/ HTTP/1.1\r\nHost: good.example\r\nX-A: a\r\n Transfer-Encoding: chunked\r\n\r\n",
            // non-token byte in a field name (NBSP)
            "POST http://good.example/ HTTP/1.1\r\nHost: good.example\r\nTransfer-Encoding\u{A0}: chunked\r\n\r\n",
            // Transfer-Encoding on HTTP/1.0
            "POST http://good.example/ HTTP/1.0\r\nHost: good.example\r\nTransfer-Encoding: chunked\r\n\r\n",
            // lone CR inside a value
            "GET http://good.example/ HTTP/1.1\r\nHost: good.example\r\nX-A: a\rb\r\n\r\n",
        ]
        for head in heads {
            try withProxy(.respond("HTTP/1.1 200 OK")) { port, upstream in
                let r = exchange(port: port, payload: Data(head.utf8), seconds: 0.6)
                let resp = String(decoding: r.response, as: UTF8.self)
                XCTAssertTrue(resp.hasPrefix("HTTP/1.1 400"), "head \(head.debugDescription) got: \(resp)")
                XCTAssertTrue(upstream.bytes.isEmpty, "upstream saw:\n\(upstream.text)")
            }
        }
    }

    func testStrictHeadAccepted() {
        XCTAssertTrue(LocalProxy.isStrictRequestHead(Data("GET http://h/ HTTP/1.1\r\nHost: h\r\nX-T: a\tb\r\n\r\n".utf8)))
        XCTAssertTrue(LocalProxy.isStrictRequestHead(Data("CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n".utf8)))
        XCTAssertFalse(LocalProxy.isStrictRequestHead(Data("GET http://h/ HTTP/2\r\nHost: h\r\n\r\n".utf8)))
        XCTAssertFalse(LocalProxy.isStrictRequestHead(Data("GET  http://h/ HTTP/1.1\r\n\r\n".utf8)))
    }

    // MARK: - The client is told not to reuse the connection

    func testResponseToClientCarriesConnectionClose() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, _ in
            let r = exchange(port: port, payload: Data("GET http://good.example/ HTTP/1.1\r\nHost: good.example\r\n\r\n".utf8))
            let resp = String(decoding: r.response, as: UTF8.self)
            XCTAssertTrue(resp.hasPrefix("HTTP/1.1 200 OK\r\n"), resp)
            XCTAssertTrue(resp.contains("\r\nConnection: close\r\n"), resp)
            XCTAssertFalse(resp.lowercased().contains("keep-alive"), resp)
            XCTAssertTrue(resp.hasSuffix("\r\n\r\nok\n"), resp)
        }
    }

    func testDeclinedUpgradeResponseCarriesConnectionClose() throws {
        try withProxy(.respond("HTTP/1.1 200 OK")) { port, _ in
            let head = "GET http://good.example/ws HTTP/1.1\r\nHost: good.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            let r = exchange(port: port, payload: Data(head.utf8))
            let resp = String(decoding: r.response, as: UTF8.self)
            XCTAssertTrue(resp.contains("\r\nConnection: close\r\n"), resp)
        }
    }

    // MARK: - Framing and header rewriting

    func testRequestFraming() {
        typealias F = ProxySession.RequestFraming
        func f(_ headers: String, _ method: String = "POST") -> F? {
            LocalProxy.requestFraming(method: method, headers: "\(method) http://h/ HTTP/1.1\r\n" + headers + "\r\n")
        }
        XCTAssertEqual(f("Host: h\r\n", "GET"), F.none)
        XCTAssertEqual(f("Content-Length: 0\r\n"), F.none)
        XCTAssertEqual(f("Content-Length: 12\r\n"), .length(12))
        XCTAssertEqual(f("Content-Length: 12\r\nContent-Length: 12\r\n"), .length(12))
        XCTAssertNil(f("Content-Length: 12\r\nContent-Length: 13\r\n"))
        XCTAssertNil(f("Content-Length: 12, 13\r\n"))
        XCTAssertNil(f("Content-Length: -1\r\n"))
        XCTAssertNil(f("Content-Length: 0x10\r\n"))
        XCTAssertEqual(f("Transfer-Encoding: chunked\r\n"), .chunked)
        XCTAssertEqual(f("Transfer-Encoding: gzip, chunked\r\n"), .chunked)
        XCTAssertNil(f("Transfer-Encoding: chunked\r\nContent-Length: 5\r\n"))
        XCTAssertNil(f("Transfer-Encoding: gzip\r\n"))
        XCTAssertEqual(f("Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n", "GET"), .streamAfterStatus(["101"]))
        XCTAssertEqual(f("Upgrade: websocket\r\n", "GET"), F.none)
        XCTAssertEqual(LocalProxy.requestFraming(method: "CONNECT", headers: "CONNECT h:443 HTTP/1.1\r\n\r\n"),
                       .streamAfterStatus(["2"]))
    }

    func testChunkedScannerAcrossSplits() {
        let body = Data("4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\nT: 1\r\n\r\n".utf8)
        let extra = Data("GET http://evil.test/ HTTP/1.1\r\n\r\n".utf8)
        let all = body + extra
        for split in 1..<all.count {
            var s = ProxySession.ChunkedScanner()
            let a = s.consume(all.prefix(split))
            let b = s.isDone ? 0 : s.consume(all.dropFirst(split))
            XCTAssertEqual(a + b, body.count, "split at \(split)")
            XCTAssertTrue(s.isDone)
            XCTAssertFalse(s.malformed)
        }
    }

    func testChunkedScannerStopsOnMalformedInput() {
        var s = ProxySession.ChunkedScanner()
        _ = s.consume(Data("zz\r\nabc".utf8))
        XCTAssertTrue(s.isDone)
        XCTAssertTrue(s.malformed)
        var t = ProxySession.ChunkedScanner()
        _ = t.consume(Data("3\r\nabcXY".utf8))
        XCTAssertTrue(t.malformed)
        for bad in ["-0\r\n\r\n", "+5\r\nhello\r\n0\r\n\r\n", ";5\r\nhello\r\n", " 5\r\nhello\r\n"] {
            var s = ProxySession.ChunkedScanner()
            _ = s.consume(Data(bad.utf8))
            XCTAssertTrue(s.malformed, bad.debugDescription)
        }
    }

    func testForceSingleRequestRewritesConnectionHeaders() {
        let h = "GET http://h/ HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\n"
        let out = LocalProxy.forceSingleRequest(headerString: h, keepUpgrade: false)
        XCTAssertEqual(out, "GET http://h/ HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
        let up = LocalProxy.forceSingleRequest(
            headerString: "GET http://h/ HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade, keep-alive\r\n\r\n",
            keepUpgrade: true)
        XCTAssertEqual(up, "GET http://h/ HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
    }

    // MARK: - mitmproxy sidecar

    func testMitmdumpListensOnLoopbackAndVerifiesOriginTLS() {
        let args = MITMProxySidecar.launchArguments(
            upstreamHost: "127.0.0.1", upstreamPort: 3128, listenPort: 18080,
            confDir: "/tmp/conf", addonPath: nil)
        XCTAssertFalse(args.contains("--ssl-insecure"))
        XCTAssertFalse(args.contains { $0.contains("ssl_insecure") })
        guard let i = args.firstIndex(of: "--listen-host") else {
            return XCTFail("no --listen-host in \(args)")
        }
        XCTAssertEqual(args[i + 1], "127.0.0.1")
    }

    // MARK: - Helpers

    static func firstNonLoopbackIPv4() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            let ifa = cur.pointee
            if let sa = ifa.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET),
               (ifa.ifa_flags & UInt32(IFF_UP)) != 0, (ifa.ifa_flags & UInt32(IFF_LOOPBACK)) == 0 {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count),
                               nil, 0, NI_NUMERICHOST) == 0 {
                    let ip = String(cString: host)
                    if !ip.hasPrefix("169.254.") { return ip }
                }
            }
            p = ifa.ifa_next
        }
        return nil
    }
}
