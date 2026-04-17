//
//  MITMHandler.swift
//  proxymate
//
//  Active TLS MITM interception for CONNECT tunnels.
//  v0.9.1: Each handler owns a dedicated serial queue. SSLContext operations
//  are strictly serialized per-handler. Atomic isDone prevents double-close.
//  Global semaphore caps concurrent MITM sessions.
//

import Foundation
import Network

// MARK: - Global concurrency control

/// Max simultaneous MITM handshakes. Released after handshake completes
/// (success or failure), NOT held for the full session lifetime.
/// This prevents persistent connections (WebSocket, SSE) from starving
/// new handshakes.
nonisolated(unsafe) private var mitmHandshakeSemaphore = DispatchSemaphore(value: 20)

/// Active session count — protected by handlersLock for thread safety.
nonisolated(unsafe) private var activeSessionCount: Int = 0  // guarded by handlersLock

/// Registry of active MITM handlers. SSLContext callbacks use the handler ID
/// (stored as the SSLConnectionRef) to look up the handler safely.
nonisolated(unsafe) private var activeHandlers: [Int: MITMHandler] = [:]
nonisolated(unsafe) private var handlersLock = NSLock()
nonisolated(unsafe) private var nextHandlerID: Int = 1

/// Sendable wrapper for SSLContext (C pointer, not Sendable by default).
/// Safety: all access serialized on MITMHandler's dedicated handlerQueue.
nonisolated private struct SSLBox: @unchecked Sendable {
    let ctx: SSLContext
    let idPtr: UnsafeMutableRawPointer
}

nonisolated final class MITMHandler: @unchecked Sendable {

    fileprivate let clientConn: NWConnection
    private let hostname: String
    private let port: UInt16
    private let onEvent: (@Sendable (LocalProxy.Event) -> Void)?
    private let rules: [WAFRule]
    private let privacy: PrivacySettings
    private let startTime = Date()
    fileprivate let handlerID: Int

    /// Dedicated serial queue — ALL SSLContext operations happen here.
    private let handlerQueue: DispatchQueue

    /// Server-side NWConnection (to real upstream). Stored for cleanup.
    private var serverConn: NWConnection?

    fileprivate var readBuffer = Data()
    fileprivate let readLock = NSLock()
    fileprivate let writeLock = NSLock()
    fileprivate var pendingWrites = Data()
    private var handshakeRetries = 0
    private let maxHandshakeRetries = 20
    private let handshakeTimeout: TimeInterval = 15

    /// Atomic done flag — prevents double SSLClose / double CFRelease.
    private var isDone = false
    private let doneLock = NSLock()

    /// Whether we acquired the semaphore (must release exactly once).
    private var acquiredSemaphore = false

    /// Request features for threat scoring (set in processRequest, used in inspectResponse).
    private var requestFeatures: FeatureExtractor.RequestFeatures?
    private var requestStartTime = Date()

    init(clientConn: NWConnection, hostname: String, port: UInt16,
         rules: [WAFRule], privacy: PrivacySettings,
         onEvent: (@Sendable (LocalProxy.Event) -> Void)?) {
        self.clientConn = clientConn
        self.hostname = hostname
        self.port = port
        self.rules = rules
        self.privacy = privacy
        self.onEvent = onEvent

        // Each handler gets a unique serial queue
        handlersLock.lock()
        self.handlerID = nextHandlerID
        nextHandlerID += 1
        handlersLock.unlock()

        self.handlerQueue = DispatchQueue(
            label: "proxymate.mitm.\(handlerID)",
            qos: .userInitiated
        )

        // Register in global registry
        handlersLock.lock()
        activeHandlers[self.handlerID] = self
        handlersLock.unlock()
    }

    // MARK: - Start

    func start() {
        // Acquire handshake semaphore — released after handshake, not session end.
        if mitmHandshakeSemaphore.wait(timeout: .now() + 2) == .timedOut {
            onEvent?(.log(.warn, "MITM: too many concurrent handshakes, skipping \(hostname)"))
            passthrough()
            return
        }
        acquiredSemaphore = true

        onEvent?(.mitmIntercepted(host: hostname))

        handlerQueue.async { [self] in
            let identity: SecIdentity
            do {
                identity = try TLSManager.shared.identityForHost(hostname)
            } catch {
                onEvent?(.log(.error, "MITM cert failed for \(hostname): \(error.localizedDescription)"))
                cleanup()
                return
            }

            guard let ctxUnmanaged = MITMCreateSSLContext(.serverSide, .streamType) else {
                onEvent?(.log(.error, "MITM SSLCreateContext failed for \(hostname)"))
                cleanup()
                return
            }
            // takeUnretainedValue: MITMClose owns the CFRelease, not Swift ARC.
            // Using takeRetainedValue caused double-free (ARC + MITMClose both release).
            let ctx = ctxUnmanaged.takeUnretainedValue()

            // Build cert chain: [identity, CA cert]
            // The CA cert is needed for clients to verify the chain.
            var chain: [Any] = [identity]
            if let caDER = TLSManager.shared.exportCACertDER(),
               let caCert = SecCertificateCreateWithData(nil, caDER as CFData) {
                chain.append(caCert)
            }
            guard MITMSetCertificate(ctx, chain as NSArray) == errSecSuccess else { cleanup(); return }

            guard let idPtr = UnsafeMutableRawPointer(bitPattern: handlerID) else {
                cleanup(); return
            }
            guard MITMSetConnection(ctx, idPtr) == errSecSuccess,
                  MITMSetIOFuncs(ctx, mitmReadCB, mitmWriteCB) == errSecSuccess else {
                cleanup()
                return
            }

            let ssl = SSLBox(ctx: ctx, idPtr: idPtr)

            // Start receiving client bytes on OUR queue (not LocalProxy's)
            self.pumpClient()
            self.handshake(ssl: ssl)
        }
    }

    /// Fallback: if MITM is not possible, just tunnel bytes raw (no inspection).
    private func passthrough() {
        cleanup()
    }

    // MARK: - Client byte pump

    /// Receives raw bytes from the client NWConnection and appends to readBuffer.
    /// The NWConnection receive callback is dispatched on handlerQueue.
    private func pumpClient() {
        guard !checkDone() else { return }
        clientConn.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, isComplete, error in
            guard let self, !self.checkDone() else { return }
            if let data, !data.isEmpty {
                self.readLock.lock()
                self.readBuffer.append(data)
                self.readLock.unlock()
            }
            if !isComplete && error == nil {
                self.pumpClient()
            }
        }
    }

    private func flushWrites() {
        writeLock.lock()
        let data = pendingWrites
        pendingWrites = Data()
        writeLock.unlock()
        if !data.isEmpty {
            clientConn.send(content: data, completion: .contentProcessed { _ in })
        }
    }

    // MARK: - TLS handshake

    /// Release the handshake semaphore. Called once after handshake completes
    /// (success or failure). The session continues without holding the slot.
    private func releaseHandshakeSemaphore() {
        if acquiredSemaphore {
            acquiredSemaphore = false
            mitmHandshakeSemaphore.signal()
        }
    }

    private func handshake(ssl: SSLBox) {
        guard !checkDone() else { return }

        if Date().timeIntervalSince(startTime) > handshakeTimeout {
            onEvent?(.log(.warn, "MITM handshake timeout for \(hostname) after \(handshakeRetries) retries"))
            releaseHandshakeSemaphore()
            done(ssl: ssl); return
        }

        handlerQueue.asyncAfter(deadline: .now() + 0.01) { [weak self] in
            guard let self, !self.checkDone() else { return }

            let status = MITMHandshake(ssl.ctx)
            self.flushWrites()

            switch Int32(status) {
            case errSecSuccess:
                self.releaseHandshakeSemaphore()
                // TLS OK — no log needed, success is the norm
                self.readDecrypted(ssl: ssl)

            case errSSLWouldBlock:
                self.handshakeRetries += 1
                if self.handshakeRetries >= self.maxHandshakeRetries {
                    // Record as failure so host gets auto-excluded after threshold
                    let shouldExclude = TLSManager.shared.recordHandshakeFailure(host: self.hostname)
                    if shouldExclude {
                        self.onEvent?(.log(.warn, "MITM: auto-excluding \(self.hostname) (max retries)"))
                        TLSManager.shared.addRuntimeExclude(host: self.hostname)
                    }
                    self.done(ssl: ssl)
                } else {
                    let delay = min(0.1, 0.01 * Double(self.handshakeRetries / 10 + 1))
                    self.handlerQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
                        self?.handshake(ssl: ssl)
                    }
                }

            case errSSLPeerHandshakeFail, errSSLPeerCertUnknown, errSSLPeerBadCert, errSSLPeerCertRevoked:
                let shouldExclude = TLSManager.shared.recordHandshakeFailure(host: self.hostname)
                if shouldExclude {
                    self.onEvent?(.log(.warn, "MITM: cert pinning detected for \(self.hostname), auto-excluding"))
                    TLSManager.shared.addRuntimeExclude(host: self.hostname)
                } else {
                    // Only log on first failure, not every retry
                    if TLSManager.shared.failureCount(for: self.hostname) == 1 {
                        self.onEvent?(.log(.info, "MITM: handshake failed for \(self.hostname) (status: \(status))"))
                    }
                }
                self.done(ssl: ssl)

            case errSSLClosedGraceful, errSSLClosedAbort:
                self.done(ssl: ssl)

            default:
                self.onEvent?(.log(.warn, "MITM error \(self.hostname): OSStatus \(status) (\(self.errorCodeDescription(status)))"))
                self.done(ssl: ssl)
            }
        }
    }

    private func errorCodeDescription(_ code: OSStatus) -> String {
        switch Int32(code) {
        case errSSLProtocol: return "Protocol error"
        case errSSLNegotiation: return "Negotiation failure"
        case errSSLFatalAlert: return "Fatal alert"
        case errSSLSessionNotFound: return "Session not found"
        case errSSLConnectionRefused: return "Connection refused"
        case errSSLDecryptionFail: return "Decryption failed"
        case errSSLBadRecordMac: return "Bad record MAC"
        case errSSLRecordOverflow: return "Record overflow"
        case errSSLBadCert: return "Bad certificate"
        default: return "Unknown"
        }
    }

    // MARK: - Decrypted traffic

    /// Max session duration (5 min). Prevents zombie MITM connections from
    /// holding resources indefinitely (e.g., WebSocket/SSE streams).
    private static let maxSessionDuration: TimeInterval = 300

    private func readDecrypted(ssl: SSLBox) {
        guard !checkDone() else { return }
        // Session timeout — close stale connections
        if Date().timeIntervalSince(startTime) > Self.maxSessionDuration {
            onEvent?(.log(.info, "MITM: session timeout for \(hostname) after \(Int(Self.maxSessionDuration))s"))
            done(ssl: ssl); return
        }
        handlerQueue.asyncAfter(deadline: .now() + 0.01) { [weak self] in
            guard let self, !self.checkDone() else { return }
            var buf = [UInt8](repeating: 0, count: 16384)
            var processed = 0
            let status = MITMRead(ssl.ctx, &buf, buf.count, &processed)
            if processed > 0 {
                self.processRequest(Data(buf[0..<processed]), ssl: ssl)
                return
            }
            if Int32(status) == errSSLWouldBlock {
                self.readDecrypted(ssl: ssl)
                return
            }
            self.done(ssl: ssl)
        }
    }

    private func processRequest(_ data: Data, ssl: SSLBox) {
        guard let text = String(data: data, encoding: .utf8) else {
            done(ssl: ssl); return
        }
        let parts = (text.split(separator: "\r\n").first ?? "").split(separator: " ", maxSplits: 2)
        let method = parts.count > 0 ? String(parts[0]) : "?"
        let target = parts.count > 1 ? String(parts[1]) : "/"

        // WebSocket upgrade — log the FQDN but don't keep MITM active
        // (SSLContext crashes on long-lived bidirectional streams)
        if WebSocketInspector.isUpgradeRequest(text) {
            onEvent?(.log(.info, "WebSocket upgrade: \(hostname)\(target)"))
            // Auto-exclude from future MITM to avoid repeated handshake overhead
            TLSManager.shared.addRuntimeExclude(host: hostname)
            // Forward the upgrade request then close MITM gracefully
            forwardToServer(requestData: data, ssl: ssl)
            return
        }

        if let hit = rules.first(where: {
            $0.enabled && LocalProxy.matches(rule: $0, host: hostname, target: target, headers: text)
        }) {
            let label = hit.name.isEmpty ? hit.pattern : hit.name
            onEvent?(.blocked(host: hostname, ruleName: "MITM: \(label)"))
            sendEncrypted(ssl: ssl, text: "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            done(ssl: ssl); return
        }

        if let hit = ExfiltrationScanner.shared.scan(headers: text, target: target) {
            onEvent?(.exfiltration(host: hostname, patternName: hit.patternName,
                                   severity: hit.severity.rawValue, preview: hit.matchPreview))
            sendEncrypted(ssl: ssl, text: "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            done(ssl: ssl); return
        }

        // Extract request features for threat scoring
        requestFeatures = FeatureExtractor.extractRequest(
            host: hostname, target: target, headers: text, bodySize: data.count)
        requestStartTime = Date()

        var finalData = data
        let (rewritten, actions) = LocalProxy.applyPrivacy(headerString: text, settings: privacy)
        if !actions.isEmpty {
            onEvent?(.privacyStripped(host: hostname, actions: actions))
            finalData = Data(rewritten.utf8)
        }

        onEvent?(.allowed(host: hostname, method: method))
        forwardToServer(requestData: finalData, ssl: ssl)
    }

    // MARK: - Forward to server

    private func forwardToServer(requestData: Data, ssl: SSLBox) {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, cb in cb(true) }, handlerQueue)
        let params = NWParameters(tls: tls)
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { done(ssl: ssl); return }

        let server = NWConnection(host: .init(hostname), port: nwPort, using: params)
        self.serverConn = server
        server.stateUpdateHandler = { [weak self] state in
            guard let self, !self.checkDone() else { server.cancel(); return }
            switch state {
            case .ready:
                server.send(content: requestData, completion: .contentProcessed { [weak self] err in
                    guard let self, !self.checkDone() else { server.cancel(); return }
                    if err != nil { self.done(ssl: ssl); server.cancel(); return }
                    self.bufferServerResponse(server: server, ssl: ssl)
                })
            case .failed:
                self.done(ssl: ssl)
            default: break
            }
        }
        server.start(queue: handlerQueue)
    }

    /// Max response buffer for WAF inspection. Responses larger than this
    /// are streamed directly to client without body inspection (prevents OOM).
    private static let maxResponseBuffer = 10 * 1024 * 1024 // 10 MB

    /// Minimum body bytes needed to run the magic-byte corroboration.
    /// Largest offset+length in the pattern table is MP4 ftyp (4+4=8 bytes).
    /// 16 gives slack without materially delaying the streaming decision.
    private static let magicMinBytes = 16

    /// Buffer complete server response, apply WAF on body, then send encrypted to client
    private func bufferServerResponse(server: NWConnection, ssl: SSLBox) {
        var responseBuffer = Data()
        var headersComplete = false
        var contentLength: Int?
        var isChunked = false
        var streamingMode = false // true = too large for inspection, stream directly

        // Streaming-media detection carries across chunks: we learn the
        // Content-Type on the header-complete chunk but may not yet have
        // enough body bytes to magic-check. These flags persist the
        // decision state so we don't re-evaluate on every chunk.
        var streamingContentType: String?      // set on header parse, cleared once decided
        var streamingMagicPending = false      // true = CT detected, waiting for body bytes

        func receiveChunk() {
            server.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
                guard let self, !self.checkDone() else { server.cancel(); return }

                if let data, !data.isEmpty {
                    // If already in streaming mode, send chunks directly
                    if streamingMode {
                        self.sendEncrypted(ssl: ssl, data: data)
                        if isComplete || error != nil {
                            server.cancel()
                            self.done(ssl: ssl)
                        } else {
                            receiveChunk()
                        }
                        return
                    }

                    responseBuffer.append(data)

                    // Switch to streaming if buffer exceeds cap
                    if responseBuffer.count > Self.maxResponseBuffer {
                        // Large response — stream without WAF. No log (routine for media/downloads).
                        // Flush what we have (headers already parsed, send as-is)
                        self.sendEncrypted(ssl: ssl, data: responseBuffer)
                        responseBuffer = Data()
                        streamingMode = true
                        if isComplete || error != nil {
                            server.cancel()
                            self.done(ssl: ssl)
                        } else {
                            receiveChunk()
                        }
                        return
                    }

                    // Parse headers to determine content length and streaming Content-Type
                    if !headersComplete, let headerEnd = responseBuffer.range(of: Data("\r\n\r\n".utf8)) {
                        headersComplete = true
                        let headerData = responseBuffer[..<headerEnd.upperBound]
                        if let headerString = String(data: headerData, encoding: .utf8) {
                            var hasContentEncoding = false
                            let lines = headerString.split(separator: "\r\n")
                            for line in lines.dropFirst() {
                                let lower = line.lowercased()
                                if lower.hasPrefix("content-length:") {
                                    contentLength = Int(line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces))
                                } else if lower.hasPrefix("transfer-encoding:") && lower.contains("chunked") {
                                    isChunked = true
                                } else if lower.hasPrefix("content-encoding:") {
                                    hasContentEncoding = true
                                } else if lower.hasPrefix("content-type:") {
                                    let value = String(line.dropFirst("content-type:".count))
                                    if TLSManager.isStreamingMediaContentType(value) {
                                        streamingContentType = value.split(separator: ";", maxSplits: 1).first
                                            .map { $0.trimmingCharacters(in: .whitespaces) } ?? value
                                    }
                                }
                            }
                            // Content-Encoding on a streaming Content-Type is an
                            // evasion signal (real media is never gzipped). Refuse
                            // the pass-through — WAF inspects normally.
                            if streamingContentType != nil && hasContentEncoding {
                                self.onEvent?(.log(.warn,
                                    "MITM: streaming Content-Type from \(self.hostname) with Content-Encoding — refusing pass-through"))
                                streamingContentType = nil
                            }
                            if streamingContentType != nil {
                                streamingMagicPending = true
                            }
                        }
                    }

                    // Streaming-media decision. Requires headers parsed AND
                    // enough body bytes to run the magic check.
                    if streamingMagicPending,
                       let headerEnd = responseBuffer.range(of: Data("\r\n\r\n".utf8)) {
                        let bodySoFar = responseBuffer.suffix(from: headerEnd.upperBound)
                        if bodySoFar.count >= Self.magicMinBytes || isComplete {
                            let bodyData = Data(bodySoFar)
                            let ct = streamingContentType ?? ""
                            if TLSManager.matchesStreamingMagic(bodyData, contentType: ct) {
                                // Genuine media. Record toward threshold and, if
                                // the response is unbounded, flip to pass-through.
                                let graduated = TLSManager.shared.recordStreamingMediaResponse(host: self.hostname)
                                if graduated {
                                    self.onEvent?(.log(.info,
                                        "MITM: streaming media (\(ct)) from \(self.hostname), auto-excluding"))
                                }
                                streamingMagicPending = false
                                streamingContentType = nil

                                // For unbounded streams (no Content-Length, chunked
                                // or close-delimited), flush and pass through. Small
                                // bounded responses (e.g. HLS manifests) fall through
                                // to the normal completion path below — they fit in
                                // the buffer and WAF on manifest text is cheap.
                                let unbounded = (contentLength == nil) || (contentLength ?? 0) > Self.maxResponseBuffer
                                if unbounded {
                                    self.sendEncrypted(ssl: ssl, data: responseBuffer)
                                    responseBuffer = Data()
                                    streamingMode = true
                                    if isComplete || error != nil {
                                        server.cancel()
                                        self.done(ssl: ssl)
                                    } else {
                                        receiveChunk()
                                    }
                                    return
                                }
                            } else {
                                // Magic mismatch on a streaming Content-Type is an
                                // attempted WAF bypass. Log, mark rejected, let
                                // the normal buffer/WAF path handle the response.
                                let head = bodyData.prefix(32).map { String(format: "%02x", $0) }.joined()
                                self.onEvent?(.log(.warn,
                                    "MITM: magic mismatch for \(ct) from \(self.hostname) (body starts \(head)) — refusing pass-through"))
                                streamingMagicPending = false
                                streamingContentType = nil
                            }
                        } else {
                            // Not enough bytes yet to magic-check. Wait for next chunk.
                            if isComplete || error != nil {
                                server.cancel()
                                let finalResponse = self.inspectResponse(responseBuffer)
                                self.sendEncrypted(ssl: ssl, data: finalResponse)
                                self.done(ssl: ssl)
                            } else {
                                receiveChunk()
                            }
                            return
                        }
                    }

                    // Check if response is complete
                    if headersComplete {
                        var complete = false
                        if let cl = contentLength {
                            if let headerEnd = responseBuffer.range(of: Data("\r\n\r\n".utf8)) {
                                let bodyReceived = responseBuffer.count - headerEnd.upperBound
                                if bodyReceived >= cl { complete = true }
                            }
                        } else if isChunked {
                            let terminator = Data("0\r\n\r\n".utf8)
                            if responseBuffer.count >= terminator.count &&
                               responseBuffer.suffix(terminator.count) == terminator {
                                complete = true
                            }
                        } else if isComplete {
                            complete = true
                        }

                        if complete {
                            server.cancel()
                            let finalResponse = self.inspectResponse(responseBuffer)
                            self.sendEncrypted(ssl: ssl, data: finalResponse)
                            self.done(ssl: ssl)
                            return
                        }
                    }
                }

                if isComplete || error != nil {
                    server.cancel()
                    let finalResponse = self.inspectResponse(responseBuffer)
                    self.sendEncrypted(ssl: ssl, data: finalResponse)
                    self.done(ssl: ssl)
                } else {
                    receiveChunk()
                }
            }
        }

        receiveChunk()
    }

    /// Inspect response body for WAF rules (Block Content on responses).
    /// Decompresses gzip/deflate bodies for inspection, but forwards the
    /// original compressed body to the client (no re-compression needed).
    private func inspectResponse(_ responseData: Data) -> Data {
        guard let headerEnd = responseData.range(of: Data("\r\n\r\n".utf8)) else {
            return responseData
        }

        let headerData = responseData[..<headerEnd.upperBound]
        let bodyData = responseData[headerEnd.upperBound...]

        guard let headerString = String(data: headerData, encoding: .utf8) else {
            return responseData
        }

        // Decompress body if Content-Encoding is present
        let inspectionBody: Data
        if let encoding = BodyDecompressor.extractContentEncoding(headerString) {
            let (decompressed, wasCompressed) = BodyDecompressor.decompress(Data(bodyData), encoding: encoding)
            if wasCompressed {
                // Decompression succeeded — no log (routine)
            }
            inspectionBody = decompressed
        } else {
            inspectionBody = Data(bodyData)
        }

        // Check content WAF rules on (decompressed) response body
        if let bodyString = String(data: inspectionBody, encoding: .utf8) {
            for rule in rules where rule.enabled && rule.kind == .blockContent {
                let pattern = rule.pattern.lowercased()
                if bodyString.lowercased().contains(pattern) {
                    let label = rule.name.isEmpty ? rule.pattern : rule.name
                    onEvent?(.blocked(host: hostname, ruleName: "MITM Response: \(label)"))

                    let body = "Blocked by Proxymate: Response contained forbidden content (\(label))\n"
                    return Data("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)".utf8)
                }
            }

            // Extract AI usage from SSE streaming responses
            if bodyString.contains("data: ") {
                let aiResult = AITracker.shared.detect(host: hostname)
                if let provider = aiResult?.provider {
                    let _ = AITracker.shared.extractUsage(provider: provider, responseBody: inspectionBody)
                }
            }
        }

        // Feature extraction: combine request + response for threat scoring
        if let reqFeatures = requestFeatures {
            let statusCode = parseStatusCode(headerString)
            let latencyMs = Date().timeIntervalSince(requestStartTime) * 1000
            let respFeatures = FeatureExtractor.extractResponse(
                statusCode: statusCode, headers: headerString,
                bodySize: bodyData.count, latencyMs: latencyMs)
            let combined = FeatureExtractor.combine(request: reqFeatures, response: respFeatures)

            if combined.threatScore >= 0.6 {
                onEvent?(.log(.warn, "MITM threat score \(String(format: "%.2f", combined.threatScore)) for \(hostname)"
                    + (combined.isBeaconLike ? " [beacon]" : "")
                    + (combined.isExfilLike ? " [exfil]" : "")))
            }

            // Record response in host memory
            HostMemory.shared.recordResponse(
                host: hostname, statusCode: statusCode,
                latency: latencyMs / 1000, bytes: bodyData.count)
        }

        // Strip response headers if privacy settings require
        if privacy.stripServerHeaders {
            var modifiedHeaders = ""

            for (idx, line) in headerString.split(separator: "\r\n").enumerated() {
                if idx == 0 {
                    modifiedHeaders += line + "\r\n"
                    continue
                }

                let lower = line.lowercased()
                if lower.hasPrefix("server:") ||
                   lower.hasPrefix("x-powered-by:") ||
                   lower.hasPrefix("x-aspnet-version:") ||
                   lower.hasPrefix("x-runtime:") ||
                   lower.hasPrefix("x-version:") {
                    onEvent?(.privacyStripped(host: hostname, actions: ["Response header: \(line.split(separator: ":").first ?? "")"]))
                    continue
                }
                modifiedHeaders += line + "\r\n"
            }

            modifiedHeaders += "\r\n"
            var finalData = Data(modifiedHeaders.utf8)
            finalData.append(bodyData)
            return finalData
        }

        return responseData
    }

    /// Parse HTTP status code from first line (e.g. "HTTP/1.1 200 OK" -> 200).
    private func parseStatusCode(_ headers: String) -> Int {
        let firstLine = headers.split(separator: "\r\n").first ?? ""
        let parts = firstLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else { return 0 }
        return Int(parts[1]) ?? 0
    }

    // MARK: - SSL helpers

    private func sendEncrypted(ssl: SSLBox, text: String) {
        sendEncrypted(ssl: ssl, data: Data(text.utf8))
    }

    private func sendEncrypted(ssl: SSLBox, data: Data) {
        guard !checkDone() else { return }
        data.withUnsafeBytes { buf in
            guard let base = buf.baseAddress else { return }
            var offset = 0
            var maxIter = data.count + 100
            while offset < data.count && maxIter > 0 {
                maxIter -= 1
                var processed = 0
                let s = MITMWrite(ssl.ctx, base.advanced(by: offset), data.count - offset, &processed)
                if processed == 0 { break }
                offset += processed
                if Int32(s) != errSecSuccess && Int32(s) != errSSLWouldBlock { break }
            }
        }
        flushWrites()
    }

    // MARK: - Lifecycle

    /// Check if this handler has already been torn down.
    private func checkDone() -> Bool {
        doneLock.lock()
        let d = isDone
        doneLock.unlock()
        return d
    }

    private func done(ssl: SSLBox) {
        doneLock.lock()
        if isDone { doneLock.unlock(); return }
        isDone = true
        doneLock.unlock()

        // Unregister from handler registry FIRST — IO callbacks will
        // find no handler and return errSSLClosedAbort.
        handlersLock.lock()
        activeHandlers.removeValue(forKey: handlerID)
        handlersLock.unlock()

        // MITMClose does SSLClose + CFRelease (single owner — we used
        // takeUnretainedValue so Swift ARC won't double-release).
        MITMClose(ssl.ctx)
        clientConn.stateUpdateHandler = nil
        serverConn?.stateUpdateHandler = nil
        clientConn.cancel()
        serverConn?.cancel()
        serverConn = nil
        releaseHandshakeSemaphore()
    }

    /// Cleanup for early exit paths (before SSLContext is created).
    private func cleanup() {
        doneLock.lock()
        if !isDone { isDone = true }
        doneLock.unlock()

        handlersLock.lock()
        activeHandlers.removeValue(forKey: handlerID)
        handlersLock.unlock()

        // Break retain cycles: nil handlers before cancel
        clientConn.stateUpdateHandler = nil
        serverConn?.stateUpdateHandler = nil
        clientConn.cancel()
        serverConn?.cancel()
        serverConn = nil
        releaseHandshakeSemaphore()
    }

    // SSLContext deprecated since macOS 10.15 but still functional on macOS 26.
    // .serverSide/.streamType deprecation warnings are Apple SDK, not our code.
}

// MARK: - SSLContext IO callbacks (use handler registry, no Unmanaged)

nonisolated func mitmReadCB(_ connection: SSLConnectionRef,
                             _ data: UnsafeMutableRawPointer,
                             _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let handlerID = Int(bitPattern: connection)
    handlersLock.lock()
    guard let handler = activeHandlers[handlerID] else {
        handlersLock.unlock()
        dataLength.pointee = 0
        return errSSLClosedAbort
    }
    handlersLock.unlock()

    handler.readLock.lock()
    let available = handler.readBuffer.count
    if available == 0 {
        handler.readLock.unlock()
        dataLength.pointee = 0
        return errSSLWouldBlock
    }
    let requested = dataLength.pointee
    let n = min(available, requested)
    handler.readBuffer.copyBytes(to: data.assumingMemoryBound(to: UInt8.self), count: n)
    handler.readBuffer.removeFirst(n)
    handler.readLock.unlock()
    dataLength.pointee = n
    return n < requested ? errSSLWouldBlock : errSecSuccess
}

nonisolated func mitmWriteCB(_ connection: SSLConnectionRef,
                              _ data: UnsafeRawPointer,
                              _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let handlerID = Int(bitPattern: connection)
    handlersLock.lock()
    guard let handler = activeHandlers[handlerID] else {
        handlersLock.unlock()
        return errSSLClosedAbort
    }
    handlersLock.unlock()

    handler.writeLock.lock()
    handler.pendingWrites.append(Data(bytes: data, count: dataLength.pointee))
    handler.writeLock.unlock()
    return errSecSuccess
}
