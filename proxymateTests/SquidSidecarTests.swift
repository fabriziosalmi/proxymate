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
}
