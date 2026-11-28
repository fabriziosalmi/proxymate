//
//  SquidSidecar.swift
//  proxymate
//
//  Manages Squid as a bundled sidecar process for upstream HTTP caching.
//  Proxymate chains: Browser → LocalProxy (Swift) → Squid → Internet.
//  Squid runs with a minimal config in a per-user temp directory.
//

import Foundation

nonisolated final class SquidSidecar: @unchecked Sendable {

    static let shared = SquidSidecar()

    private let queue = DispatchQueue(label: "proxymate.squid", qos: .userInitiated)
    private var process: Process?
    private(set) var port: UInt16 = 0
    private(set) var isRunning = false

    private let workDir: URL = {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("proxymate-squid", isDirectory: true)
        try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        return tmp
    }()

    private let pidFile: String = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".proxymate/squid.pid").path

    var onEvent: ((@Sendable (String) -> Void))?

    // MARK: - Lifecycle

    func start(listenPort: UInt16 = 3128) throws -> UInt16 {
        try queue.sync {
            guard !isRunning else { return port }

            // Reap our own orphan first: a squid left behind by a killed or
            // crashed parent still holds the port, and the check below would
            // otherwise adopt it as an "external" squid, with the previous
            // build's binary and config. Path-checked against the bundled
            // squid so a recycled PID can't redirect the kill.
            if let squidPath = findSquid(),
               MITMProxySidecar.reapOrphan(pidFile: pidFile, expectedPath: squidPath) {
                Self.waitForPortToClose(listenPort, timeout: 2)
            }

            // If something else is already serving on the requested port
            // (the most common case: the user has `brew services start
            // squid` running on 3128), don't try to launch our bundled
            // copy on top of it. Without this short-circuit, the bundled
            // squid's bind() fails, `squid -z` may end up wedged in
            // uninterruptible kernel I/O on cache_dir init, and every
            // subsequent enable() spawns another orphan. Reusing the
            // listening squid is exactly what the upstream config
            // (Local Squid → 127.0.0.1:3128) describes anyway, so this
            // is a no-op for the proxy chain.
            if MITMProxySidecar.waitForLocalPort(listenPort, timeout: 0.5) {
                onEvent?("squid: external listener detected on :\(listenPort), reusing")
                port = listenPort
                isRunning = true
                return listenPort
            }

            guard let squidPath = findSquid() else {
                throw SquidError.notInstalled
            }

            // Generate minimal config
            let configPath = workDir.appendingPathComponent("squid.conf").path
            try generateConfig(port: listenPort, path: configPath)

            // Prepare directories squid needs
            let cacheDir = workDir.appendingPathComponent("cache")
            let logDir = workDir.appendingPathComponent("logs")
            let runDir = workDir.appendingPathComponent("run")
            for dir in [cacheDir, logDir, runDir] {
                try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            }

            // Initialize cache dirs (squid -z)
            let initProc = Process()
            initProc.executableURL = URL(fileURLWithPath: squidPath)
            // -N keeps -z in the foreground. Without it squid daemonizes while it
            // creates the cache directories, and the launch below finds a fresh
            // PID file and exits with "Squid is already running" on first run.
            initProc.arguments = Self.initArguments(configPath: configPath)
            initProc.standardOutput = Pipe()
            initProc.standardError = Pipe()
            // Set DYLD_LIBRARY_PATH for bundled OpenSSL
            var env = ProcessInfo.processInfo.environment
            let libDir = URL(fileURLWithPath: squidPath).deletingLastPathComponent().appendingPathComponent("lib").path
            if FileManager.default.fileExists(atPath: libDir) {
                env["DYLD_LIBRARY_PATH"] = libDir
            }
            initProc.environment = env
            try? initProc.run()
            initProc.waitUntilExit()

            // Launch squid
            let p = Process()
            p.executableURL = URL(fileURLWithPath: squidPath)
            p.arguments = ["-N", "-f", configPath]  // -N = no daemon (foreground)
            p.standardOutput = Pipe()
            p.standardError = Pipe()
            p.environment = env

            p.terminationHandler = { [weak self] proc in
                self?.queue.async {
                    self?.isRunning = false
                    self?.port = 0
                    if proc.terminationStatus != 0 {
                        self?.onEvent?("squid exited with code \(proc.terminationStatus)")
                    }
                }
            }

            do {
                try p.run()
            } catch {
                throw SquidError.launchFailed(error.localizedDescription)
            }

            // Gate success on Squid actually accepting connections. Squid's
            // cold start (config parse, cache_dir init, DNS warmup) takes
            // longer than mitmdump's; the first CONNECT from LocalProxy
            // otherwise fails with "Connection refused" and the user sees
            // 502 on the first request. 15 s ceiling accommodates a cold
            // disk_cache init on a slow filesystem.
            guard MITMProxySidecar.waitForLocalPort(listenPort, timeout: 15) else {
                p.terminate()
                throw SquidError.launchFailed("squid didn't accept connections on :\(listenPort) within 15 s")
            }

            process = p
            port = listenPort
            isRunning = true
            MITMProxySidecar.writePIDFile(pidFile, pid: p.processIdentifier)
            onEvent?("squid started on port \(listenPort) (PID \(p.processIdentifier))")
            return listenPort
        }
    }

    func stop() {
        queue.async { [weak self] in
            self?.stopLocked(waitFor: nil)
        }
    }

    /// Synchronous stop for app termination. The async stop() may never run
    /// before the app exits, which leaves squid holding the port.
    func stopAndWait(timeout: TimeInterval = 3) {
        queue.sync { stopLocked(waitFor: timeout) }
    }

    private func stopLocked(waitFor timeout: TimeInterval?) {
        if let p = process, p.isRunning {
            if let timeout {
                MITMProxySidecar.terminateAndWait(p, timeout: timeout)
            } else {
                p.terminate()
            }
        }
        process = nil
        isRunning = false
        port = 0
        MITMProxySidecar.clearPIDFile(pidFile)
    }

    /// Polls until nothing accepts connections on 127.0.0.1:`port`, so a
    /// reaped squid's socket is gone before the port is probed again.
    static func waitForPortToClose(_ port: UInt16, timeout: TimeInterval) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if !MITMProxySidecar.waitForLocalPort(port, timeout: 0.05) { return }
            usleep(50_000)
        }
    }

    static func initArguments(configPath: String) -> [String] {
        ["-z", "-N", "-f", configPath]
    }

    // MARK: - Find squid

    private func findSquid() -> String? {
        // 1. Bundled binary (preferred)
        let bundledPaths = [
            Bundle.main.path(forResource: "squid", ofType: nil, inDirectory: "bin"),
            Bundle.main.path(forResource: "squid", ofType: nil),
            Bundle.main.bundlePath + "/Contents/Resources/bin/squid",
        ]
        for case let path? in bundledPaths {
            if FileManager.default.isExecutableFile(atPath: path) { return path }
        }

        // 2. System-installed fallback
        let candidates = [
            "/opt/homebrew/sbin/squid",
            "/usr/local/sbin/squid",
            "/usr/sbin/squid",
        ]
        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) { return path }
        }
        return nil
    }

    // MARK: - Config generation

    private func generateConfig(port: UInt16, path: String) throws {
        let config = Self.config(port: port,
                                 cacheDir: workDir.appendingPathComponent("cache").path,
                                 logDir: workDir.appendingPathComponent("logs").path,
                                 runDir: workDir.appendingPathComponent("run").path)
        try config.write(toFile: path, atomically: true, encoding: .utf8)
    }

    static func config(port: UInt16, cacheDir: String, logDir: String, runDir: String) -> String {
        """
        # Proxymate auto-generated squid.conf
        http_port 127.0.0.1:\(port)

        # Only accept connections from localhost
        acl localnet src 127.0.0.0/8
        acl localnet src ::1
        http_access allow localnet
        http_access deny all

        # Minimal cache (256 MB disk, 64 MB RAM)
        cache_dir ufs \(cacheDir) 256 16 256
        cache_mem 64 MB
        maximum_object_size 32 MB
        maximum_object_size_in_memory 2 MB

        # Logging (minimal)
        access_log \(logDir)/access.log
        cache_log \(logDir)/cache.log
        pid_filename \(runDir)/squid.pid

        # Exit within a second of SIGTERM. The default 30 s keeps the port
        # bound after Proxymate quits, and a relaunch in that window would
        # adopt the dying squid as an external listener.
        shutdown_lifetime 1 seconds

        # Performance
        dns_nameservers 1.1.1.1 8.8.8.8
        connect_timeout 10 seconds
        read_timeout 30 seconds
        request_timeout 30 seconds
        client_lifetime 5 minutes
        pconn_timeout 30 seconds

        # Strip identifying headers
        via off
        forwarded_for delete

        # Coredumps off
        coredump_dir none
        """
    }

    // MARK: - Errors

    enum SquidError: LocalizedError {
        case notInstalled
        case launchFailed(String)

        var errorDescription: String? {
            switch self {
            case .notInstalled: return "squid not found. Install: brew install squid"
            case .launchFailed(let m): return "squid launch failed: \(m)"
            }
        }
    }
}
