//
//  MITMProxySidecar.swift
//  proxymate
//
//  Manages mitmdump as a sidecar process for TLS interception.
//  Proxymate chains CONNECT requests to mitmdump, which handles
//  all TLS (battle-tested, zero fd leaks, zero crashes).
//
//  Communication: Unix socket at ~/.proxymate/mitm.sock
//  mitmdump sends JSON events (request/response/ai_usage)
//  Proxymate reads and processes them.
//

import Foundation
import Network
import CommonCrypto
import Darwin

nonisolated final class MITMProxySidecar: @unchecked Sendable {

    static let shared = MITMProxySidecar()

    private let queue = DispatchQueue(label: "proxymate.mitmproxy", qos: .userInitiated)
    private var process: Process?
    private var socketListener: Int32 = -1
    private var _port: UInt16 = 0
    private var _isRunning = false
    var port: UInt16 { queue.sync { _port } }
    var isRunning: Bool { queue.sync { _isRunning } }
    private var heartbeatTimer: DispatchSourceTimer?
    /// Known SHA-256 hash of the trusted mitmdump binary (set on first verified launch).
    private var trustedHash: String?

    private let socketPath: String = {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".proxymate")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("mitm.sock").path
    }()

    private let pidFile: String = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".proxymate/mitmdump.pid").path

    var onEvent: ((@Sendable (LocalProxy.Event) -> Void))?

    // MARK: - Lifecycle

    func start(upstreamHost: String, upstreamPort: UInt16,
               listenPort: UInt16 = 18080) throws -> UInt16 {
        try queue.sync {
            guard !_isRunning else { return _port }

            // Find mitmdump
            let mitmdumpPath = findMitmdump()
            guard let path = mitmdumpPath else {
                throw SidecarError.notInstalled
            }

            // Verify binary integrity (supply-chain protection)
            let currentHash = Self.sha256OfFile(atPath: path)
            if let trusted = trustedHash, trusted != currentHash {
                throw SidecarError.integrityFailed
            }
            trustedHash = currentHash

            // Reap any orphan from a previous parent process that didn't
            // get to call stop() (force-quit, crash). Path-checked so a
            // recycled PID belonging to an unrelated process is never
            // killed.
            Self.reapOrphan(pidFile: pidFile, expectedPath: path)

            // Find addon script
            let addonPath = Bundle.main.path(forResource: "proxymate_addon",
                                              ofType: "py",
                                              inDirectory: "scripts/mitmproxy")
                ?? findAddonInRepo()

            // Clean up old socket
            try? FileManager.default.removeItem(atPath: socketPath)

            // Start Unix socket listener for events
            startSocketListener()

            // Launch mitmdump
            let p = Process()
            p.executableURL = URL(fileURLWithPath: path)
            var args = [
                "--mode", "upstream:http://\(upstreamHost):\(upstreamPort)",
                "--listen-port", "\(listenPort)",
                "--set", "confdir=\(FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".proxymate/mitmproxy-conf").path)",
                "--ssl-insecure",  // don't verify upstream (Squid) certs
                "--set", "connection_strategy=lazy",
                "--set", "flow_detail=0",
                // Disable HTTP/2. With H/2 enabled downstream, browsers (Firefox
                // in particular, per Bugzilla 1420777) coalesce connections
                // across different hosts that share IPs / wildcard certs —
                // e.g. github.com + github.githubassets.com on Fastly, or
                // www.linkedin.com + static.licdn.com. The browser then sends
                // subresource requests with an :authority that doesn't match
                // the stream's origin, mitmproxy resets the stream, and the
                // browser surfaces the failure as "CORS request failed,
                // status=(null)" on <script type="module" crossorigin>.
                // Forcing H/1.1 downstream means browsers open separate
                // connections per host, which eliminates coalescing entirely.
                // The upstream leg (mitmproxy → Squid) is already H/1.1, so
                // there's no protocol downgrade on that side.
                "--set", "http2=false",
                "--quiet",
            ]
            if let addon = addonPath {
                args += ["--script", addon]
            }
            p.arguments = args
            let stderrPipe = Pipe()
            p.standardOutput = Pipe()
            p.standardError = stderrPipe
            p.terminationHandler = { [weak self] proc in
                let stderrData = stderrPipe.fileHandleForReading.availableData
                let stderr = String(data: stderrData, encoding: .utf8) ?? ""
                self?.queue.async {
                    self?._isRunning = false
                    self?._port = 0
                    if proc.terminationStatus != 0 && !stderr.isEmpty {
                        self?.onEvent?(.log(.error, "mitmproxy error: \(stderr.prefix(200))"))
                    }
                    self?.onEvent?(.log(.warn, "mitmproxy exited (code \(proc.terminationStatus))"))
                }
            }

            do {
                try p.run()
            } catch {
                stopSocketListener()
                throw SidecarError.launchFailed(error.localizedDescription)
            }

            // Block until mitmdump has actually bound its listener. Without
            // this wait, start() returned "success" while the process was
            // still in its CPython import / TLS setup phase — the first
            // CONNECT into the sidecar hit `Connection refused` and surfaced
            // in Console.app as nw_socket_handle_socket_event SO_ERROR 61.
            // Cold-start is normally ~1.5 s, but on macOS under memory
            // pressure (frequent flushes) the CPython import phase can take
            // 10–15 s. Bumped 10 → 20 s after a tester report where the
            // 10 s ceiling fired even when mitmdump eventually came up.
            guard Self.waitForLocalPort(listenPort, timeout: 20) else {
                p.terminate()
                stopSocketListener()
                throw SidecarError.launchFailed("mitmdump didn't accept connections on :\(listenPort) within 20 s")
            }

            process = p
            _port = listenPort
            _isRunning = true
            Self.writePIDFile(pidFile, pid: p.processIdentifier)
            startHeartbeat()

            onEvent?(.log(.info, "mitmproxy sidecar on port \(listenPort) (PID \(p.processIdentifier))"))
            return listenPort
        }
    }

    /// Reap any sidecar process left behind by the previous parent
    /// (force-quit, crash, kernel panic). Without this, `Process()`-spawned
    /// children get reparented to launchd on parent death and accumulate
    /// across enable/quit cycles, holding onto their listen ports and
    /// blocking the next launch's bind. macOS doesn't expose
    /// `prctl(PR_SET_PDEATHSIG)` so we can't make the kernel kill them
    /// for us — instead we leave a PID-file breadcrumb at start and
    /// clean it up on the next launch's start path.
    ///
    /// PID-recycling safety: before sending SIGTERM, verify the live
    /// process at that PID is still running our recorded executable
    /// (`expectedPath`). If a recycled PID belongs to an unrelated
    /// process, the path won't match and we leave it alone.
    static func reapOrphan(pidFile: String, expectedPath: String) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: pidFile)),
              let str = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
              let pid = Int32(str), pid > 1
        else {
            try? FileManager.default.removeItem(atPath: pidFile)
            return
        }
        defer { try? FileManager.default.removeItem(atPath: pidFile) }

        // kill(pid, 0) probes existence without sending a signal: 0 ⇒
        // alive, -1 with errno = ESRCH ⇒ gone, EPERM ⇒ alive but not ours.
        if Darwin.kill(pid, 0) != 0 { return }

        let bufLen = Int(MAXPATHLEN)
        let buf = UnsafeMutablePointer<CChar>.allocate(capacity: bufLen)
        defer { buf.deallocate() }
        let n = proc_pidpath(pid, buf, UInt32(bufLen))
        guard n > 0 else { return }
        let actual = String(cString: buf)
        guard actual == expectedPath else { return }

        _ = Darwin.kill(pid, SIGTERM)
        // 1s grace before SIGKILL.
        for _ in 0..<10 {
            usleep(100_000)
            if Darwin.kill(pid, 0) != 0 { return }
        }
        _ = Darwin.kill(pid, SIGKILL)
    }

    /// Persist `pid` to `pidFile` so the next launch's `reapOrphan` can
    /// find it if we never get a chance to clean up.
    static func writePIDFile(_ pidFile: String, pid: Int32) {
        let dir = (pidFile as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try? "\(pid)".write(toFile: pidFile, atomically: true, encoding: .utf8)
    }

    static func clearPIDFile(_ pidFile: String) {
        try? FileManager.default.removeItem(atPath: pidFile)
    }

    /// Poll 127.0.0.1:<port> with TCP connect() every 100 ms until either
    /// the peer accepts (returns true) or `timeout` elapses (returns false).
    /// Used to gate sidecar `start()` behind proof-of-readiness so callers
    /// that immediately try to forward don't race the subprocess's own
    /// bind() call. Reused from SquidSidecar to avoid duplicating the
    /// Darwin-socket boilerplate; internal access so it stays out of the
    /// public API but is visible across the module.
    static func waitForLocalPort(_ port: UInt16, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let sock = Darwin.socket(AF_INET, SOCK_STREAM, 0)
            if sock >= 0 {
                var addr = sockaddr_in()
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = in_port_t(port).bigEndian
                addr.sin_addr.s_addr = inet_addr("127.0.0.1")
                let rc = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                Darwin.close(sock)
                if rc == 0 { return true }
            }
            usleep(100_000)  // 100 ms
        }
        return false
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.stopHeartbeat()
            self.process?.terminate()
            self.process = nil
            self._isRunning = false
            self._port = 0
            self.stopSocketListener()
            try? FileManager.default.removeItem(atPath: self.socketPath)
            Self.clearPIDFile(self.pidFile)
        }
    }

    // MARK: - Heartbeat (process liveness check)

    private func startHeartbeat() {
        stopHeartbeat()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in
            guard let self, let p = self.process else { return }
            if !p.isRunning {
                self.onEvent?(.log(.error, "mitmproxy heartbeat: process died unexpectedly"))
                self._isRunning = false
                self._port = 0
                self.stopHeartbeat()
            }
        }
        timer.resume()
        heartbeatTimer = timer
    }

    private func stopHeartbeat() {
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
    }

    // MARK: - Find mitmdump

    private func findMitmdump() -> String? {
        // 1. Bundled mitmproxy.app (preferred — no external dependency).
        //    mitmdump is PyInstaller-packaged and needs its sibling
        //    Python.framework + stdlib, so the whole .app is embedded.
        let resources = Bundle.main.bundlePath + "/Contents/Resources"
        let bundledPaths = [
            resources + "/bin/mitmproxy.app/Contents/MacOS/mitmdump",
            resources + "/mitmproxy.app/Contents/MacOS/mitmdump",
            // Legacy flat-binary paths (kept for backward compat during rollout)
            Bundle.main.path(forResource: "mitmdump", ofType: nil, inDirectory: "bin"),
            Bundle.main.path(forResource: "mitmdump", ofType: nil),
            resources + "/bin/mitmdump",
        ]
        for case let path? in bundledPaths {
            if FileManager.default.isExecutableFile(atPath: path) { return path }
        }

        // 2. System-installed fallback
        let candidates = [
            "/opt/homebrew/bin/mitmdump",
            "/usr/local/bin/mitmdump",
            "/usr/bin/mitmdump",
        ]
        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) { return path }
        }
        // 3. PATH search
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        p.arguments = ["mitmdump"]
        let pipe = Pipe()
        p.standardOutput = pipe
        try? p.run()
        p.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let path = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let path, !path.isEmpty, FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
        return nil
    }

    private func findAddonInRepo() -> String? {
        let bundlePath = Bundle.main.bundlePath
        let appDir = URL(fileURLWithPath: bundlePath).deletingLastPathComponent()
        // Check relative to app
        let candidates = [
            appDir.appendingPathComponent("scripts/mitmproxy/proxymate_addon.py").path,
            // Dev mode: project root
            URL(fileURLWithPath: #file).deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("scripts/mitmproxy/proxymate_addon.py").path,
        ]
        for path in candidates {
            if FileManager.default.fileExists(atPath: path) { return path }
        }
        return nil
    }

    // MARK: - Unix Socket Listener (receive events from addon)

    private func startSocketListener() {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            let bound = ptr.withMemoryRebound(to: CChar.self, capacity: 104) { dest in
                pathBytes.withUnsafeBufferPointer { src in
                    let count = min(src.count, 104)
                    dest.update(from: src.baseAddress!, count: count)
                    return count
                }
            }
            _ = bound
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                _ = Darwin.bind(fd, sockPtr, addrLen)
            }
        }
        Darwin.listen(fd, 5)
        // Restrict socket to owner only — prevent other apps/users from sniffing IPC
        chmod(socketPath, 0o600)
        socketListener = fd

        // Accept connections on high-priority thread — IPC must never compete with UI
        DispatchQueue.global(qos: .userInteractive).async { [weak self] in
            self?.acceptLoop(fd: fd)
        }
    }

    private func stopSocketListener() {
        if socketListener >= 0 {
            Darwin.close(socketListener)
            socketListener = -1
        }
    }

    private func acceptLoop(fd: Int32) {
        while true {
            let client = Darwin.accept(fd, nil, nil)
            guard client >= 0 else { break }
            DispatchQueue.global(qos: .userInteractive).async { [weak self] in
                self?.readEvents(fd: client)
            }
        }
    }

    private func readEvents(fd: Int32) {
        var buffer = Data()
        let chunk = UnsafeMutablePointer<UInt8>.allocate(capacity: 8192)
        defer { chunk.deallocate(); Darwin.close(fd) }

        while true {
            let n = Darwin.read(fd, chunk, 8192)
            guard n > 0 else { break }
            buffer.append(chunk, count: n)

            // Process complete lines
            while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = buffer[buffer.startIndex..<newline]
                buffer = Data(buffer[buffer.index(after: newline)...])
                processEvent(data: Data(line))
            }
        }
    }

    // AI provider detection table — authoritative source in Swift (#3)
    private static let aiProviders: [(domain: String, name: String)] = [
        ("api.openai.com", "OpenAI"),
        ("api.anthropic.com", "Anthropic"),
        ("generativelanguage.googleapis.com", "Google AI"),
        ("api.mistral.ai", "Mistral"),
        ("api.cohere.ai", "Cohere"),
        ("api.together.xyz", "Together"),
        ("api.groq.com", "Groq"),
        ("api.fireworks.ai", "Fireworks"),
        ("api.perplexity.ai", "Perplexity"),
        ("api.deepseek.com", "DeepSeek"),
    ]

    private static func detectAI(host: String) -> String? {
        let h = host.lowercased()
        for (domain, name) in aiProviders {
            if h == domain || h.hasSuffix("." + domain) { return name }
        }
        return nil
    }

    private func processEvent(data: Data) {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String else { return }

        let host = json["host"] as? String ?? ""

        switch type {
        case "request":
            // Swift-side AI detection: Python may or may not have detected it
            let provider = (json["ai_provider"] as? String) ?? Self.detectAI(host: host)
            if let provider {
                onEvent?(.aiDetected(host: host, provider: provider))
            }

        case "response":
            if let usage = json["ai_usage"] as? [String: Any] {
                let provider = usage["provider"] as? String ?? Self.detectAI(host: host) ?? ""
                let model = usage["model"] as? String ?? "unknown"
                let prompt = usage["prompt_tokens"] as? Int ?? 0
                let completion = usage["completion_tokens"] as? Int ?? 0
                let cost = Double(prompt + completion) * 0.000003
                onEvent?(.aiUsage(provider: provider, model: model,
                                   promptTokens: prompt, completionTokens: completion,
                                   cost: cost))
            }

            if let preview = json["body_preview"] as? String, !preview.isEmpty {
                onEvent?(.log(.info, "MITM response: \(host) (\(json["status"] ?? 0))"))
            }

        default:
            break
        }
    }

    // MARK: - Errors

    // MARK: - Binary integrity

    private static func sha256OfFile(atPath path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    enum SidecarError: LocalizedError {
        case notInstalled
        case launchFailed(String)
        case integrityFailed

        var errorDescription: String? {
            switch self {
            case .notInstalled: return "mitmdump not found. Install: brew install mitmproxy"
            case .launchFailed(let m): return "mitmproxy launch failed: \(m)"
            case .integrityFailed: return "mitmdump binary hash changed — possible tampering"
            }
        }
    }
}
