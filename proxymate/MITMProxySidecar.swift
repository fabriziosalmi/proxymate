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

nonisolated final class MITMProxySidecar: @unchecked Sendable {

    static let shared = MITMProxySidecar()

    private let queue = DispatchQueue(label: "proxymate.mitmproxy", qos: .userInitiated)
    private var process: Process?
    private var socketListener: Int32 = -1
    private(set) var port: UInt16 = 0
    private(set) var isRunning = false

    private let socketPath: String = {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".proxymate")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("mitm.sock").path
    }()

    var onEvent: ((@Sendable (LocalProxy.Event) -> Void))?

    // MARK: - Lifecycle

    func start(upstreamHost: String, upstreamPort: UInt16,
               listenPort: UInt16 = 8888) throws -> UInt16 {
        try queue.sync {
            guard !isRunning else { return port }

            // Find mitmdump
            let mitmdumpPath = findMitmdump()
            guard let path = mitmdumpPath else {
                throw SidecarError.notInstalled
            }

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
                "--quiet",
            ]
            if let addon = addonPath {
                args += ["--script", addon]
            }
            p.arguments = args
            p.standardOutput = Pipe()
            p.standardError = Pipe()

            p.terminationHandler = { [weak self] proc in
                self?.queue.async {
                    self?.isRunning = false
                    self?.port = 0
                    self?.onEvent?(.log(.warn, "mitmproxy exited (code \(proc.terminationStatus))"))
                }
            }

            do {
                try p.run()
            } catch {
                stopSocketListener()
                throw SidecarError.launchFailed(error.localizedDescription)
            }

            process = p
            port = listenPort
            isRunning = true

            onEvent?(.log(.info, "mitmproxy sidecar on port \(listenPort) (PID \(p.processIdentifier))"))
            return listenPort
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.process?.terminate()
            self.process = nil
            self.isRunning = false
            self.port = 0
            self.stopSocketListener()
            try? FileManager.default.removeItem(atPath: self.socketPath)
        }
    }

    // MARK: - Find mitmdump

    private func findMitmdump() -> String? {
        let candidates = [
            "/opt/homebrew/bin/mitmdump",
            "/usr/local/bin/mitmdump",
            "/usr/bin/mitmdump",
        ]
        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        // Try which
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
        socketListener = fd

        // Accept connections in background
        DispatchQueue.global(qos: .utility).async { [weak self] in
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
            DispatchQueue.global(qos: .utility).async { [weak self] in
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

    private func processEvent(data: Data) {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String else { return }

        let host = json["host"] as? String ?? ""

        switch type {
        case "request":
            if let provider = json["ai_provider"] as? String {
                onEvent?(.aiDetected(host: host, provider: provider))
            }

        case "response":
            if let usage = json["ai_usage"] as? [String: Any] {
                let provider = usage["provider"] as? String ?? ""
                let model = usage["model"] as? String ?? "unknown"
                let prompt = usage["prompt_tokens"] as? Int ?? 0
                let completion = usage["completion_tokens"] as? Int ?? 0
                // Simple cost estimate
                let cost = Double(prompt + completion) * 0.000003
                onEvent?(.aiUsage(provider: provider, model: model,
                                   promptTokens: prompt, completionTokens: completion,
                                   cost: cost))
            }

            // WAF on response body
            if let preview = json["body_preview"] as? String, !preview.isEmpty {
                // Will be checked by AppState against rules
                onEvent?(.log(.info, "MITM response: \(host) (\(json["status"] ?? 0))"))
            }

        default:
            break
        }
    }

    // MARK: - Errors

    enum SidecarError: LocalizedError {
        case notInstalled
        case launchFailed(String)

        var errorDescription: String? {
            switch self {
            case .notInstalled: return "mitmdump not found. Install: brew install mitmproxy"
            case .launchFailed(let m): return "mitmproxy launch failed: \(m)"
            }
        }
    }
}
