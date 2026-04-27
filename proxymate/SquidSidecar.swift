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

            guard let squidPath = findSquid() else {
                throw SquidError.notInstalled
            }

            // Reap any orphan squid from a hard-quit parent. Path-checked
            // against `squidPath` so a recycled PID can't redirect the kill.
            MITMProxySidecar.reapOrphan(pidFile: pidFile, expectedPath: squidPath)

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
            initProc.arguments = ["-z", "-f", configPath]
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
            guard let self else { return }
            if let p = self.process, p.isRunning {
                p.terminate()
            }
            self.process = nil
            self.isRunning = false
            self.port = 0
            MITMProxySidecar.clearPIDFile(self.pidFile)
        }
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
        let cacheDir = workDir.appendingPathComponent("cache").path
        let logDir = workDir.appendingPathComponent("logs").path
        let runDir = workDir.appendingPathComponent("run").path

        let config = """
        # Proxymate auto-generated squid.conf
        http_port \(port)

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
        try config.write(toFile: path, atomically: true, encoding: .utf8)
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
