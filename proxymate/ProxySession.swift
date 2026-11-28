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

nonisolated final class ProxySession: @unchecked Sendable {

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

    /// How many client bytes belong to the one request this session was
    /// checked for. Policy runs on the first request of a connection only, so
    /// any client byte past that request (a pipelined or keep-alive request)
    /// must never reach the upstream.
    enum RequestFraming: Equatable {
        /// No body: nothing after the header block is forwarded.
        case none
        /// Content-Length body of exactly this many bytes.
        case length(Int)
        /// Transfer-Encoding: chunked body, forwarded up to its last chunk and trailer.
        case chunked
        /// CONNECT or protocol upgrade: client bytes are held until the upstream
        /// answers with a status starting with one of these prefixes ("2" for
        /// CONNECT, "101" for an upgrade), then the connection becomes an opaque
        /// stream. Any other answer keeps the client side closed.
        case streamAfterStatus([String])
    }

    /// Incremental Transfer-Encoding: chunked scanner. It does not decode; it
    /// only tells how many of the offered bytes still belong to the body.
    struct ChunkedScanner {
        private enum State { case size, data(Int), dataCRLF(Int), trailer, done }
        private var state: State = .size
        private var line = Data()
        private static let maxLine = 4096
        private(set) var malformed = false

        var isDone: Bool { if case .done = state { return true }; return false }

        /// Returns how many leading bytes of `bytes` belong to the chunked body.
        mutating func consume(_ bytes: Data) -> Int {
            var i = bytes.startIndex
            while i < bytes.endIndex {
                switch state {
                case .done:
                    return i - bytes.startIndex
                case .size, .trailer:
                    let b = bytes[i]
                    i += 1
                    line.append(b)
                    if line.count > Self.maxLine { fail(); return i - bytes.startIndex }
                    guard line.count >= 2, line[line.count - 2] == 0x0D, line[line.count - 1] == 0x0A else { continue }
                    let text = String(data: line.dropLast(2), encoding: .ascii) ?? ""
                    line.removeAll(keepingCapacity: true)
                    if case .trailer = state {
                        if text.isEmpty { state = .done }
                        continue
                    }
                    // chunk-size is 1*HEXDIG, optionally followed by ";ext". No
                    // sign, no whitespace, no empty size.
                    let sizeField = text.split(separator: ";", maxSplits: 1,
                                               omittingEmptySubsequences: false).first.map(String.init) ?? ""
                    guard !sizeField.isEmpty, sizeField.count <= 15,
                          sizeField.allSatisfy(\.isHexDigit),
                          let size = Int(sizeField, radix: 16) else {
                        fail(); return i - bytes.startIndex
                    }
                    state = size == 0 ? .trailer : .data(size)
                case .data(let remaining):
                    let take = min(remaining, bytes.endIndex - i)
                    i += take
                    state = remaining - take == 0 ? .dataCRLF(2) : .data(remaining - take)
                case .dataCRLF(let need):
                    let expected: UInt8 = need == 2 ? 0x0D : 0x0A
                    guard bytes[i] == expected else { fail(); return i - bytes.startIndex }
                    i += 1
                    state = need == 2 ? .dataCRLF(1) : .size
                }
            }
            return i - bytes.startIndex
        }

        private mutating func fail() { malformed = true; state = .done }
    }

    // Client → upstream request bounding (see RequestFraming).
    private var framing: RequestFraming = .none
    private var bodyRemaining = 0
    private var chunked = ChunkedScanner()
    private var requestComplete = false
    private var streamOpen = false
    private var heldClientBytes = Data()
    private var statusChecked = false
    private var statusPrefixBuffer = Data()
    // Upstream → client: the response head is rewritten to Connection: close
    // so the client never reuses this connection for a request we would not
    // forward.
    private var responseHeadDone = false
    private var responseHeadBuffer = Data()
    private static let maxResponseHead = 65_536

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
        framing: RequestFraming,
        cacheContext: CacheContext? = nil,
        aiContext: AIContext? = nil
    ) {
        self.cacheContext = cacheContext
        self.aiContext = aiContext
        self.framing = framing
        switch framing {
        case .none: requestComplete = true
        case .length(let n): bodyRemaining = n; requestComplete = n == 0
        case .chunked, .streamAfterStatus: break
        }
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
                // client → upstream: only the rest of the checked request;
                // after that, client bytes are read only to notice a close.
                if !self.isStreamFraming {
                    self.boundedClientLoop(to: upstream)
                }
                // upstream → client (response)
                self.startPipe(from: upstream, to: self.client)
            }

            let allowed = self.admitClientBytes(leftover)
            if allowed.isEmpty {
                startPipes()
            } else {
                upstream.send(content: allowed, completion: .contentProcessed { _ in
                    startPipes()
                })
            }
        })
    }

    private var isStreamFraming: Bool {
        if case .streamAfterStatus = framing { return true }
        return false
    }

    /// Returns the part of `data` that belongs to the checked request and may
    /// go upstream now. Bytes past the end of the request are dropped; bytes of
    /// a CONNECT/upgrade are held until the upstream status opens the stream.
    private func admitClientBytes(_ data: Data) -> Data {
        guard !data.isEmpty else { return data }
        if streamOpen { return data }
        if requestComplete { return Data() }
        switch framing {
        case .none:
            return Data()
        case .length:
            let take = min(bodyRemaining, data.count)
            bodyRemaining -= take
            if bodyRemaining == 0 { requestComplete = true }
            return data.prefix(take)
        case .chunked:
            let take = chunked.consume(data)
            if chunked.isDone { requestComplete = true }
            if chunked.malformed {
                onEvent?(.log(.warn, "Malformed chunked request body: forwarding stopped"))
            }
            return data.prefix(take)
        case .streamAfterStatus:
            guard heldClientBytes.count + data.count <= 65_536 else {
                // Dropping bytes would corrupt the stream: end the session.
                onEvent?(.log(.warn, "Client sent >64 KB before the upstream answered CONNECT/upgrade"))
                finish()
                return Data()
            }
            heldClientBytes.append(data)
            return Data()
        }
    }

    /// Client → upstream loop. Bytes of the checked request are forwarded;
    /// anything after it (a pipelined or keep-alive request) is discarded,
    /// never forwarded without its own policy check. Reading continues only
    /// so that a client close ends the session.
    private func boundedClientLoop(to upstream: NWConnection) {
        guard !isDone else { return }
        client.receive(minimumIncompleteLength: 1, maximumLength: 262_144) { [weak self] data, _, isComplete, error in
            guard let self, !self.isDone else { return }
            if let data, !data.isEmpty {
                let allowed = self.admitClientBytes(data)
                if !allowed.isEmpty {
                    upstream.send(content: allowed, completion: .contentProcessed { [weak self] err in
                        if err != nil { self?.finish() }
                    })
                }
            }
            if error != nil {
                self.finish()
                return
            }
            if isComplete {
                // A client half-close after a complete request is legal HTTP:
                // keep the session so the response can still be delivered;
                // the upstream close ends it. A close in the middle of the
                // request body aborts the request.
                if !self.requestComplete { self.finish() }
                return
            }
            self.boundedClientLoop(to: upstream)
        }
    }

    /// Called with the first upstream bytes of a CONNECT/upgrade session. If the
    /// status opens the stream, held client bytes are flushed and the client
    /// side becomes a raw pipe; otherwise the client side stays closed.
    private func checkStreamStatus(_ data: Data) {
        guard case .streamAfterStatus(let prefixes) = framing, !statusChecked else { return }
        statusPrefixBuffer.append(data.prefix(64))
        let text = String(decoding: statusPrefixBuffer, as: UTF8.self)
        guard text.contains("\r\n") || statusPrefixBuffer.count >= 64 else { return }
        statusChecked = true
        statusPrefixBuffer = Data()
        // "HTTP/1.1 200 Connection Established" → second token is the code
        let parts = text.split(separator: " ", maxSplits: 2)
        let code = parts.count >= 2 ? String(parts[1]) : ""
        guard text.hasPrefix("HTTP/"), prefixes.contains(where: { code.hasPrefix($0) }),
              let upstream else {
            // Not opened: the response goes back with Connection: close, and
            // the client side is read only to notice its close.
            heldClientBytes = Data()
            requestComplete = true
            if let upstream { boundedClientLoop(to: upstream) }
            return
        }
        streamOpen = true
        let held = heldClientBytes
        heldClientBytes = Data()
        if !held.isEmpty {
            upstream.send(content: held, completion: .contentProcessed { [weak self] err in
                if err != nil { self?.finish() }
            })
        }
        startPipe(from: client, to: upstream)
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
                if from === self.upstream, self.isStreamFraming, !self.statusChecked {
                    self.checkStreamStatus(data)
                }
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

                // Fire-and-forget send (response head rewritten first)
                let out = from === self.upstream ? self.rewriteResponseHead(data) : data
                if !out.isEmpty {
                    to.send(content: out, completion: .contentProcessed { [weak self] err in
                        if err != nil { self?.finish() }
                    })
                }
            }

            if isComplete || error != nil {
                // This direction is done
                if from === self.upstream {
                    // Flush a head that never completed, unchanged.
                    if !self.responseHeadDone, !self.responseHeadBuffer.isEmpty {
                        to.send(content: self.responseHeadBuffer, completion: .contentProcessed { _ in })
                        self.responseHeadBuffer = Data()
                    }
                    // Upstream finished sending — process buffered response
                    self.processBufferedResponse()
                    if error == nil {
                        // Close only after every queued byte reached the
                        // client: finish() cancels the connection, which
                        // discards sends still in flight and truncated the
                        // tail of a response the upstream closed right after.
                        to.send(content: nil, contentContext: .finalMessage, isComplete: true,
                                completion: .contentProcessed { [weak self] _ in self?.finish() })
                        return
                    }
                } else if error == nil, self.streamOpen {
                    // Client half-closed an open tunnel: pass the FIN on and
                    // keep reading the upstream; its close ends the session.
                    to.send(content: nil, contentContext: .finalMessage, isComplete: true,
                            completion: .contentProcessed { _ in })
                    return
                }
                self.finish()
                return
            }

            // Continue reading
            self.pipeLoop(from: from, to: to)
        }
    }

    /// Returns the upstream bytes to send to the client now. Until the final
    /// (non-1xx) response head has been seen it is buffered and its
    /// connection fields are replaced by `Connection: close`. Opened streams
    /// (CONNECT 2xx, 101) pass through untouched.
    private func rewriteResponseHead(_ data: Data) -> Data {
        if responseHeadDone || streamOpen {
            responseHeadDone = true
            if responseHeadBuffer.isEmpty { return data }
            let out = responseHeadBuffer + data
            responseHeadBuffer = Data()
            return out
        }
        responseHeadBuffer.append(data)
        var out = Data()
        let sep = Data("\r\n\r\n".utf8)
        while !responseHeadDone, let r = responseHeadBuffer.range(of: sep) {
            let head = responseHeadBuffer[..<r.upperBound]
            let rest = responseHeadBuffer[r.upperBound...]
            let text = String(decoding: head, as: UTF8.self)
            let code = text.split(separator: " ", maxSplits: 2).dropFirst().first.map(String.init) ?? ""
            if code.hasPrefix("1") && code != "101" {
                // Interim response (100 Continue): pass through, keep looking.
                out.append(head)
                responseHeadBuffer = Data(rest)
                continue
            }
            responseHeadDone = true
            if streamOpen {
                out.append(head)
            } else {
                out.append(Data(LocalProxy.forceSingleRequest(headerString: text, keepUpgrade: false).utf8))
            }
            out.append(rest)
            responseHeadBuffer = Data()
        }
        if !responseHeadDone && responseHeadBuffer.count > Self.maxResponseHead {
            // Not HTTP we can parse: pass through unchanged.
            responseHeadDone = true
            out.append(responseHeadBuffer)
            responseHeadBuffer = Data()
        }
        return out
    }

    // MARK: - Response processing (cache + AI)

    private func processBufferedResponse() {
        guard let buffer = responseBuffer, !buffer.isEmpty else { return }

        // Parse headers once; both cache and AI need them.
        guard let headerEnd = buffer.range(of: Data("\r\n\r\n".utf8)) else { return }
        let headerPart = buffer[..<headerEnd.lowerBound]
        let body = Data(buffer[headerEnd.upperBound...])
        guard let headerStr = String(data: headerPart, encoding: .utf8) else { return }

        if let ctx = cacheContext {
            let lines = headerStr.split(separator: "\r\n", maxSplits: 1, omittingEmptySubsequences: false)
            guard let statusLine = lines.first else { return }
            let responseHeaders = lines.count > 1 ? String(lines[1]) : ""
            CacheManager.shared.store(
                method: ctx.method, url: ctx.url, requestHeaders: ctx.requestHeaders,
                statusLine: String(statusLine), responseHeaders: responseHeaders, body: body)
        }

        if let ai = aiContext {
            // Decode Content-Encoding (gzip/deflate/br) before token extraction.
            // Upstream AI APIs almost always compress; without this, every
            // extractUsage call failed to parse JSON and token tracking was
            // silently zero.
            let encoding = Self.headerValue(in: headerStr, name: "Content-Encoding") ?? ""
            let bodyForAI: Data
            if encoding.isEmpty {
                bodyForAI = body
            } else {
                let (decoded, ok) = BodyDecompressor.decompress(body, encoding: encoding)
                bodyForAI = ok ? decoded : body
            }
            _ = AITracker.shared.extractUsage(provider: ai.provider, responseBody: bodyForAI)
        }
    }

    /// Case-insensitive header value lookup on a pre-parsed header block.
    /// Returns the trimmed value of the first matching header, or nil.
    private static func headerValue(in headerBlock: String, name: String) -> String? {
        let lowerName = name.lowercased() + ":"
        for rawLine in headerBlock.split(separator: "\r\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            if line.lowercased().hasPrefix(lowerName) {
                let after = line.dropFirst(lowerName.count)
                return after.trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
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
