//
//  ProxySession.swift
//  proxymate
//
//  Per-connection session. Each client connection gets its own ProxySession
//  with a dedicated serial queue. Manages the full lifecycle:
//  client → parse → WAF → upstream → pipe → close.
//
//  Replaces the old forward()/pipe()/pipeAndBuffer() methods in LocalProxy
//  which shared a single queue and leaked connections.
//

import Foundation
import Network

final class ProxySession: @unchecked Sendable {

    private let client: NWConnection
    private var upstream: NWConnection?
    private let queue: DispatchQueue
    private let onEvent: (@Sendable (LocalProxy.Event) -> Void)?
    private var isDone = false

    // Optional response buffering for cache/AI
    private var responseBuffer: Data?
    private let maxBuffer = 2 * 1024 * 1024 // 2 MB
    private var cacheContext: CacheContext?
    private var aiContext: AIContext?

    struct CacheContext {
        let method: String
        let url: String
        let requestHeaders: String
    }

    struct AIContext {
        let provider: AIProvider
    }

    init(client: NWConnection, sessionID: Int,
         onEvent: (@Sendable (LocalProxy.Event) -> Void)?) {
        self.client = client
        self.onEvent = onEvent
        self.queue = DispatchQueue(label: "proxymate.session.\(sessionID)", qos: .userInitiated)
    }

    // MARK: - Connect to upstream and start piping

    func connectAndForward(
        headerData: Data,
        leftover: Data,
        upstreamHost: String,
        upstreamPort: UInt16,
        cacheContext: CacheContext? = nil,
        aiContext: AIContext? = nil
    ) {
        self.cacheContext = cacheContext
        self.aiContext = aiContext
        if cacheContext != nil || aiContext != nil {
            responseBuffer = Data()
        }

        guard let port = NWEndpoint.Port(rawValue: upstreamPort) else {
            finish(); return
        }

        let conn = NWConnection(host: .init(upstreamHost), port: port, using: .tcp)
        self.upstream = conn

        conn.stateUpdateHandler = { [weak self] state in
            guard let self, !self.isDone else { return }
            switch state {
            case .ready:
                self.sendToUpstream(headerData: headerData, leftover: leftover)
            case .failed(let err):
                self.onEvent?(.log(.error, "Upstream failed: \(err.localizedDescription)"))
                self.sendError(status: "502 Bad Gateway",
                               body: "Upstream failed: \(err.localizedDescription)\n")
            case .cancelled:
                self.finish()
            default: break
            }
        }
        conn.start(queue: queue)
    }

    // MARK: - CONNECT tunnel (passthrough, no header rewriting)

    func tunnel(upstreamHost: String, upstreamPort: UInt16) {
        guard let port = NWEndpoint.Port(rawValue: upstreamPort) else {
            finish(); return
        }

        let conn = NWConnection(host: .init(upstreamHost), port: port, using: .tcp)
        self.upstream = conn

        conn.stateUpdateHandler = { [weak self] state in
            guard let self, !self.isDone else { return }
            switch state {
            case .ready:
                // Send "200 Connection Established" then start bidirectional pipe
                let established = Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)
                self.client.send(content: established, completion: .contentProcessed { [weak self] _ in
                    guard let self, !self.isDone else { return }
                    self.startPipe(from: self.client, to: conn)
                    self.startPipe(from: conn, to: self.client)
                })
            case .failed:
                self.finish()
            default: break
            }
        }
        conn.start(queue: queue)
    }

    // MARK: - Send headers + body to upstream, then pipe

    private func sendToUpstream(headerData: Data, leftover: Data) {
        guard let upstream, !isDone else { return }

        upstream.send(content: headerData, completion: .contentProcessed { [weak self] err in
            guard let self, !self.isDone else { return }
            if let err {
                self.onEvent?(.log(.error, "Upstream send failed: \(err.localizedDescription)"))
                self.sendError(status: "502 Bad Gateway",
                               body: "Upstream send failed\n")
                return
            }

            let startPipes = { [weak self] in
                guard let self, let upstream = self.upstream, !self.isDone else { return }
                // client → upstream (request body continuation)
                self.startPipe(from: self.client, to: upstream)
                // upstream → client (response)
                self.startPipe(from: upstream, to: self.client)
            }

            if leftover.isEmpty {
                startPipes()
            } else {
                upstream.send(content: leftover, completion: .contentProcessed { _ in
                    startPipes()
                })
            }
        })
    }

    // MARK: - Pipe (one direction, fire-and-forget sends)

    private func startPipe(from: NWConnection, to: NWConnection) {
        pipeLoop(from: from, to: to)
    }

    private func pipeLoop(from: NWConnection, to: NWConnection) {
        guard !isDone else { return }

        from.receive(minimumIncompleteLength: 1, maximumLength: 262_144) { [weak self] data, _, isComplete, error in
            guard let self, !self.isDone else { return }

            if let data, !data.isEmpty {
                // Buffer response if needed (upstream → client direction only)
                if from === self.upstream, var buf = self.responseBuffer {
                    if buf.count + data.count <= self.maxBuffer {
                        buf.append(data)
                        self.responseBuffer = buf
                    } else {
                        // Exceeded buffer limit, stop buffering
                        self.responseBuffer = nil
                    }
                }

                // Fire-and-forget send
                to.send(content: data, completion: .contentProcessed { [weak self] err in
                    if err != nil { self?.finish() }
                })
            }

            if isComplete || error != nil {
                // This direction is done
                if from === self.upstream {
                    // Upstream finished sending — process buffered response
                    self.processBufferedResponse()
                }
                self.finish()
                return
            }

            // Continue reading
            self.pipeLoop(from: from, to: to)
        }
    }

    // MARK: - Response processing (cache + AI)

    private func processBufferedResponse() {
        guard let buffer = responseBuffer, !buffer.isEmpty else { return }

        if let ctx = cacheContext {
            guard let headerEnd = buffer.range(of: Data("\r\n\r\n".utf8)) else { return }
            let headerPart = buffer[..<headerEnd.lowerBound]
            let body = buffer[headerEnd.upperBound...]
            guard let headerStr = String(data: headerPart, encoding: .utf8) else { return }
            let lines = headerStr.split(separator: "\r\n", maxSplits: 1, omittingEmptySubsequences: false)
            guard let statusLine = lines.first else { return }
            let responseHeaders = lines.count > 1 ? String(lines[1]) : ""
            CacheManager.shared.store(
                method: ctx.method, url: ctx.url, requestHeaders: ctx.requestHeaders,
                statusLine: String(statusLine), responseHeaders: responseHeaders, body: Data(body))
        }

        if let ai = aiContext {
            let _ = AITracker.shared.extractUsage(provider: ai.provider, responseBody: buffer)
        }
    }

    // MARK: - Error response

    private func sendError(status: String, body: String) {
        let headers = "HTTP/1.1 \(status)\r\nContent-Type: text/plain\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n"
        var data = Data(headers.utf8)
        data.append(Data(body.utf8))
        client.send(content: data, completion: .contentProcessed { [weak self] _ in
            self?.finish()
        })
    }

    private var doneLock = os_unfair_lock()

    // MARK: - Cleanup (atomic, once only)

    func finish() {
        os_unfair_lock_lock(&doneLock)
        let alreadyDone = isDone
        isDone = true
        os_unfair_lock_unlock(&doneLock)
        guard !alreadyDone else { return }
        // Cancel connections (thread-safe) then nil-out state on session queue
        client.cancel()
        upstream?.cancel()
        queue.async { [weak self] in
            self?.upstream = nil
            self?.responseBuffer = nil
        }
    }

    deinit {
        finish()
    }
}
