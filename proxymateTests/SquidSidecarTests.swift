//
//  SquidSidecarTests.swift
//  proxymateTests
//

import XCTest
@testable import proxymate

final class SquidSidecarTests: XCTestCase {

    /// `squid -z` without -N daemonizes while it builds the cache, so the
    /// launch that follows hits a fresh PID file and exits on first run.
    func testCacheInitRunsInTheForeground() {
        let args = SquidSidecar.initArguments(configPath: "/tmp/squid.conf")
        XCTAssertEqual(args.first, "-z")
        XCTAssertTrue(args.contains("-N"))
        XCTAssertEqual(Array(args.suffix(2)), ["-f", "/tmp/squid.conf"])
    }
    /// The default shutdown_lifetime (30 s) keeps the port bound after quit,
    /// and a relaunch in that window adopts the dying squid.
    func testConfigExitsPromptlyAndListensOnLoopback() {
        let conf = SquidSidecar.config(port: 3128, cacheDir: "/c", logDir: "/l", runDir: "/r")
        XCTAssertTrue(conf.contains("\nshutdown_lifetime 1 seconds\n"))
        XCTAssertTrue(conf.contains("\nhttp_port 127.0.0.1:3128\n"))
    }

    func testTerminateAndWaitKillsAProcessThatIgnoresSIGTERM() throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/perl")
        // Print only after the handler is set, so SIGTERM never arrives first.
        p.arguments = ["-e", "$| = 1; $SIG{TERM}='IGNORE'; print \"ready\\n\"; sleep 30"]
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        XCTAssertEqual(out.fileHandleForReading.availableDataLine(), "ready")
        let started = Date()
        MITMProxySidecar.terminateAndWait(p, timeout: 0.5)
        p.waitUntilExit()
        XCTAssertFalse(p.isRunning)
        XCTAssertEqual(p.terminationReason, .uncaughtSignal)
        XCTAssertEqual(p.terminationStatus, SIGKILL)
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
    }

    func testReapOrphanKillsOnlyItsOwnExecutable() throws {
        let pidFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("reap-\(UUID().uuidString).pid").path
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sleep")
        p.arguments = ["30"]
        try p.run()
        defer { if p.isRunning { p.terminate() } }

        MITMProxySidecar.writePIDFile(pidFile, pid: p.processIdentifier)
        XCTAssertFalse(MITMProxySidecar.reapOrphan(pidFile: pidFile, expectedPath: "/usr/bin/true"))
        XCTAssertTrue(p.isRunning, "a PID running another executable is left alone")

        MITMProxySidecar.writePIDFile(pidFile, pid: p.processIdentifier)
        XCTAssertTrue(MITMProxySidecar.reapOrphan(pidFile: pidFile, expectedPath: "/bin/sleep"))
        p.waitUntilExit()
        XCTAssertFalse(FileManager.default.fileExists(atPath: pidFile))
    }

    /// networksetup output for one service with the web proxy off, HTTPS on,
    /// and the auto-proxy URL off; then everything off.
    func testNetworksetupOutputParsing() {
        let on = """
        Enabled: No
        Server: 127.0.0.1
        Port: 61320
        Authenticated Proxy Enabled: 0
        Enabled: Yes
        Server: 127.0.0.1
        Port: 61320
        Authenticated Proxy Enabled: 0
        URL: (null)
        Enabled: No
        """
        XCTAssertTrue(ProxyManager.anyEnabled(inNetworksetupOutput: on))
        XCTAssertFalse(ProxyManager.anyEnabled(inNetworksetupOutput: on.replacingOccurrences(of: "Enabled: Yes", with: "Enabled: No")))
        XCTAssertFalse(ProxyManager.anyEnabled(inNetworksetupOutput: "Authenticated Proxy Enabled: 1\n"))
    }

    func testLoopbackPortsOnlyFromEnabledLoopbackProxies() {
        let out = """
        Enabled: Yes
        Server: 127.0.0.1
        Port: 9
        Authenticated Proxy Enabled: 0
        Enabled: No
        Server: 127.0.0.1
        Port: 61320
        Authenticated Proxy Enabled: 0
        Enabled: Yes
        Server: proxy.corp.example
        Port: 8080
        Authenticated Proxy Enabled: 0
        """
        XCTAssertEqual(ProxyManager.enabledLoopbackPorts(inNetworksetupOutput: out), [9])
    }
}

private extension FileHandle {
    /// Reads until the first newline (blocking); returns the line without it.
    func availableDataLine() -> String {
        var bytes = Data()
        while true {
            let d = readData(ofLength: 1)
            if d.isEmpty || d == Data([0x0A]) { break }
            bytes.append(d)
        }
        return String(data: bytes, encoding: .utf8) ?? ""
    }
}
