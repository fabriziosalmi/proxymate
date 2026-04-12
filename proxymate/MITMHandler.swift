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

/// Max simultaneous MITM handshakes/sessions. Prevents resource exhaustion.
private let mitmSemaphore = DispatchSemaphore(value: 20)

/// Registry of active MITM handlers. SSLContext callbacks use the handler ID
/// (stored as the SSLConnectionRef) to look up the handler safely.
nonisolated(unsafe) private var activeHandlers: [Int: MITMHandler] = [:]
private let handlersLock = NSLock()
nonisolated(unsafe) private var nextHandlerID: Int = 1

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
    /// Each handler gets its own queue so concurrent MITM sessions never
    /// interleave SSLContext calls.
    private let handlerQueue: DispatchQueue

    fileprivate var readBuffer = Data()
    fileprivate let readLock = NSLock()
    fileprivate let writeLock = NSLock()
    fileprivate var pendingWrites = Data()
    private var handshakeRetries = 0
    private let maxHandshakeRetries = 80
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
        // Acquire semaphore (non-blocking check, blocking with short timeout)
        if mitmSemaphore.wait(timeout: .now() + 2) == .timedOut {
            onEvent?(.log(.warn, "MITM: too many concurrent sessions, skipping \(hostname)"))
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
            let ctx = ctxUnmanaged.takeRetainedValue()

            var cert: SecCertificate?
            SecIdentityCopyCertificate(identity, &cert)
            guard let cert else { cleanup(); return }

            let chain: NSArray = [identity, cert]
            guard MITMSetCertificate(ctx, chain) == errSecSuccess else { cleanup(); return }

            // Pass handler ID as connection ref (cast Int to pointer)
            guard let idPtr = UnsafeMutableRawPointer(bitPattern: handlerID) else {
                cleanup(); return
            }
            guard MITMSetConnection(ctx, idPtr) == errSecSuccess,
                  MITMSetIOFuncs(ctx, mitmReadCB, mitmWriteCB) == errSecSuccess else {
                cleanup()
                return
            }

            // Start receiving client bytes on OUR queue (not LocalProxy's)
            self.pumpClient()
            self.handshake(ctx: ctx)
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
        clientConn.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, isComplete, error in
            guard let self else { return }
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

    private func handshake(ctx: SSLContext) {
        // All handshake calls are already on handlerQueue (called from start() or recursion)
        guard !checkDone() else { return }

        if Date().timeIntervalSince(startTime) > handshakeTimeout {
            onEvent?(.log(.warn, "MITM handshake timeout for \(hostname) after \(handshakeRetries) retries"))
            done(ctx: ctx); return
        }

        // Small delay to let client bytes arrive
        handlerQueue.asyncAfter(deadline: .now() + 0.01) { [weak self] in
            guard let self, !self.checkDone() else { return }

            let status = MITMHandshake(ctx)
            self.flushWrites()

            switch Int32(status) {
            case errSecSuccess:
                self.onEvent?(.log(.info, "MITM TLS OK: \(self.hostname) (\(self.handshakeRetries) retries)"))
                self.readDecrypted(ctx: ctx)

            case errSSLWouldBlock:
                self.handshakeRetries += 1
                if self.handshakeRetries >= self.maxHandshakeRetries {
                    self.onEvent?(.log(.error, "MITM handshake max retries for \(self.hostname)"))
                    self.done(ctx: ctx)
                } else {
                    let delay = min(0.1, 0.01 * Double(self.handshakeRetries / 10 + 1))
                    self.handlerQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
                        self?.handshake(ctx: ctx)
                    }
                }

            case errSSLPeerHandshakeFail, errSSLPeerCertUnknown, errSSLPeerBadCert, errSSLPeerCertRevoked:
                let shouldExclude = TLSManager.shared.recordHandshakeFailure(host: self.hostname)
                if shouldExclude {
                    self.onEvent?(.log(.warn, "MITM: cert pinning detected for \(self.hostname), auto-excluding"))
                    TLSManager.shared.addRuntimeExclude(host: self.hostname)
                } else {
                    self.onEvent?(.log(.info, "MITM: handshake failed for \(self.hostname) (status: \(status), count: \(TLSManager.shared.failureCount(for: self.hostname)))"))
                }
                self.done(ctx: ctx)

            case errSSLClosedGraceful, errSSLClosedAbort:
                self.done(ctx: ctx)

            default:
                self.onEvent?(.log(.warn, "MITM error \(self.hostname): OSStatus \(status) (\(self.errorCodeDescription(status)))"))
                self.done(ctx: ctx)
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

    private func readDecrypted(ctx: SSLContext) {
        guard !checkDone() else { return }
        handlerQueue.asyncAfter(deadline: .now() + 0.01) { [weak self] in
            guard let self, !self.checkDone() else { return }
            var buf = [UInt8](repeating: 0, count: 16384)
            var processed = 0
            let status = MITMRead(ctx, &buf, buf.count, &processed)
            if processed > 0 {
                self.processRequest(Data(buf[0..<processed]), ctx: ctx)
                return
            }
            if Int32(status) == errSSLWouldBlock {
                self.readDecrypted(ctx: ctx)
                return
            }
            self.done(ctx: ctx)
        }
    }

    private func processRequest(_ data: Data, ctx: SSLContext) {
        guard let text = String(data: data, encoding: .utf8) else {
            done(ctx: ctx); return
        }
        let parts = (text.split(separator: "\r\n").first ?? "").split(separator: " ", maxSplits: 2)
        let method = parts.count > 0 ? String(parts[0]) : "?"
        let target = parts.count > 1 ? String(parts[1]) : "/"

        if let hit = rules.first(where: {
            $0.enabled && LocalProxy.matches(rule: $0, host: hostname, target: target, headers: text)
        }) {
            let label = hit.name.isEmpty ? hit.pattern : hit.name
            onEvent?(.blocked(host: hostname, ruleName: "MITM: \(label)"))
            sendEncrypted(ctx: ctx, text: "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            done(ctx: ctx); return
        }

        if let hit = ExfiltrationScanner.shared.scan(headers: text, target: target) {
            onEvent?(.exfiltration(host: hostname, patternName: hit.patternName,
                                   severity: hit.severity.rawValue, preview: hit.matchPreview))
            sendEncrypted(ctx: ctx, text: "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            done(ctx: ctx); return
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
        forwardToServer(requestData: finalData, ctx: ctx)
    }

    // MARK: - Forward to server

    private func forwardToServer(requestData: Data, ctx: SSLContext) {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, cb in cb(true) }, handlerQueue)
        let params = NWParameters(tls: tls)
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { done(ctx: ctx); return }

        let server = NWConnection(host: .init(hostname), port: nwPort, using: params)
        server.stateUpdateHandler = { [weak self] state in
            guard let self, !self.checkDone() else { server.cancel(); return }
            switch state {
            case .ready:
                server.send(content: requestData, completion: .contentProcessed { [weak self] err in
                    guard let self, !self.checkDone() else { server.cancel(); return }
                    if err != nil { self.done(ctx: ctx); server.cancel(); return }
                    self.bufferServerResponse(server: server, ctx: ctx)
                })
            case .failed:
                self.done(ctx: ctx)
            default: break
            }
        }
        server.start(queue: handlerQueue)
    }

    /// Max response buffer for WAF inspection. Responses larger than this
    /// are streamed directly to client without body inspection (prevents OOM).
    private static let maxResponseBuffer = 10 * 1024 * 1024 // 10 MB

    /// Buffer complete server response, apply WAF on body, then send encrypted to client
    private func bufferServerResponse(server: NWConnection, ctx: SSLContext) {
        var responseBuffer = Data()
        var headersComplete = false
        var contentLength: Int?
        var isChunked = false
        var streamingMode = false // true = too large for inspection, stream directly

        func receiveChunk() {
            server.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
                guard let self, !self.checkDone() else { server.cancel(); return }

                if let data, !data.isEmpty {
                    // If already in streaming mode, send chunks directly
                    if streamingMode {
                        self.sendEncrypted(ctx: ctx, data: data)
                        if isComplete || error != nil {
                            server.cancel()
                            self.done(ctx: ctx)
                        } else {
                            receiveChunk()
                        }
                        return
                    }

                    responseBuffer.append(data)

                    // Switch to streaming if buffer exceeds cap
                    if responseBuffer.count > Self.maxResponseBuffer {
                        self.onEvent?(.log(.info, "MITM: response too large for \(self.hostname), streaming without inspection"))
                        // Flush what we have (headers already parsed, send as-is)
                        self.sendEncrypted(ctx: ctx, data: responseBuffer)
                        responseBuffer = Data()
                        streamingMode = true
                        if isComplete || error != nil {
                            server.cancel()
                            self.done(ctx: ctx)
                        } else {
                            receiveChunk()
                        }
                        return
                    }

                    // Parse headers to determine content length
                    if !headersComplete, let headerEnd = responseBuffer.range(of: Data("\r\n\r\n".utf8)) {
                        headersComplete = true
                        let headerData = responseBuffer[..<headerEnd.upperBound]
                        if let headerString = String(data: headerData, encoding: .utf8) {
                            let lines = headerString.split(separator: "\r\n")
                            for line in lines.dropFirst() {
                                let lower = line.lowercased()
                                if lower.hasPrefix("content-length:") {
                                    contentLength = Int(line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces))
                                } else if lower.hasPrefix("transfer-encoding:") && lower.contains("chunked") {
                                    isChunked = true
                                }
                            }
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
                            self.sendEncrypted(ctx: ctx, data: finalResponse)
                            self.done(ctx: ctx)
                            return
                        }
                    }
                }

                if isComplete || error != nil {
                    server.cancel()
                    let finalResponse = self.inspectResponse(responseBuffer)
                    self.sendEncrypted(ctx: ctx, data: finalResponse)
                    self.done(ctx: ctx)
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
                onEvent?(.log(.info, "MITM: decompressed \(encoding) body for \(hostname) (\(bodyData.count) -> \(decompressed.count) bytes)"))
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
            let contentType = BodyDecompressor.extractContentEncoding(headerString) ?? ""
            let hasSetCookie = headerString.lowercased().contains("set-cookie:")

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

    private func sendEncrypted(ctx: SSLContext, text: String) {
        sendEncrypted(ctx: ctx, data: Data(text.utf8))
    }

    private func sendEncrypted(ctx: SSLContext, data: Data) {
        guard !checkDone() else { return }
        data.withUnsafeBytes { buf in
            guard let base = buf.baseAddress else { return }
            var offset = 0
            var maxIter = data.count + 100
            while offset < data.count && maxIter > 0 {
                maxIter -= 1
                var processed = 0
                let s = MITMWrite(ctx, base.advanced(by: offset), data.count - offset, &processed)
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

    private func done(ctx: SSLContext) {
        doneLock.lock()
        if isDone { doneLock.unlock(); return }
        isDone = true
        doneLock.unlock()

        MITMClose(ctx)
        clientConn.cancel()
        cleanup()
    }

    private func cleanup() {
        doneLock.lock()
        if !isDone { isDone = true }
        doneLock.unlock()

        handlersLock.lock()
        activeHandlers.removeValue(forKey: handlerID)
        handlersLock.unlock()

        if acquiredSemaphore {
            acquiredSemaphore = false
            mitmSemaphore.signal()
        }
    }
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
