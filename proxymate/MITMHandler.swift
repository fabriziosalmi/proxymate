//
//  MITMHandler.swift
//  proxymate
//
//  Active TLS MITM interception for CONNECT tunnels.
//  v0.2.0: reliable handshake with timeout, error mapping, retry limits,
//  response body inspection with decompression, HSTS/pinning awareness.
//

import Foundation
import Network
import Compression

nonisolated final class MITMHandler: @unchecked Sendable {

    fileprivate let clientConn: NWConnection
    private let hostname: String
    private let port: UInt16
    private let queue: DispatchQueue
    private let onEvent: (@Sendable (LocalProxy.Event) -> Void)?
    private let rules: [WAFRule]
    private let privacy: PrivacySettings
    private let startTime = Date()

    fileprivate var readBuffer = Data()
    fileprivate var readLock = NSLock()
    fileprivate var writeLock = NSLock()
    fileprivate var pendingWrites = Data()
    private var handshakeRetries = 0
    private let maxHandshakeRetries = 50   // 50 * 20ms = 1s max
    private let handshakeTimeout: TimeInterval = 10

    init(clientConn: NWConnection, hostname: String, port: UInt16,
         queue: DispatchQueue, rules: [WAFRule], privacy: PrivacySettings,
         onEvent: (@Sendable (LocalProxy.Event) -> Void)?) {
        self.clientConn = clientConn
        self.hostname = hostname
        self.port = port
        self.queue = queue
        self.rules = rules
        self.privacy = privacy
        self.onEvent = onEvent
    }

    // MARK: - Start

    func start() {
        onEvent?(.mitmIntercepted(host: hostname))

        let identity: SecIdentity
        do {
            identity = try TLSManager.shared.identityForHost(hostname)
        } catch {
            onEvent?(.log(.error, "MITM cert failed for \(hostname): \(error.localizedDescription)"))
            clientConn.cancel()
            return
        }

        guard let ctxUnmanaged = MITMCreateSSLContext(.serverSide, .streamType) else {
            onEvent?(.log(.error, "MITM SSLCreateContext failed for \(hostname)"))
            clientConn.cancel()
            return
        }
        let ctx = ctxUnmanaged.takeRetainedValue()

        var cert: SecCertificate?
        SecIdentityCopyCertificate(identity, &cert)
        guard let cert else {
            onEvent?(.log(.error, "MITM cert extract failed for \(hostname)"))
            clientConn.cancel()
            return
        }

        let chain: NSArray = [identity, cert]
        guard MITMSetCertificate(ctx, chain) == errSecSuccess else {
            onEvent?(.log(.error, "MITM SetCertificate failed for \(hostname)"))
            clientConn.cancel()
            return
        }

        let ptr = Unmanaged.passRetained(self).toOpaque()
        guard MITMSetConnection(ctx, ptr) == errSecSuccess,
              MITMSetIOFuncs(ctx, mitmRead, mitmWrite) == errSecSuccess else {
            Unmanaged<MITMHandler>.fromOpaque(ptr).release()
            clientConn.cancel()
            return
        }

        pumpClient()
        handshake(ctx: ctx, ptr: ptr)
    }

    // MARK: - Client byte pump

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

    // MARK: - TLS handshake (with timeout + retry limit)

    private func handshake(ctx: SSLContext, ptr: UnsafeMutableRawPointer) {
        // Timeout check
        if Date().timeIntervalSince(startTime) > handshakeTimeout {
            onEvent?(.log(.warn, "MITM handshake timeout for \(hostname) after \(handshakeTimeout)s"))
            done(ctx: ctx, ptr: ptr)
            return
        }

        queue.asyncAfter(deadline: .now() + 0.02) { [weak self] in
            guard let self else {
                Unmanaged<MITMHandler>.fromOpaque(ptr).release()
                return
            }

            let status = MITMHandshake(ctx)
            self.flushWrites()

            switch Int32(status) {
            case errSecSuccess:
                self.onEvent?(.log(.info, "MITM TLS OK: \(self.hostname)"))
                self.readDecrypted(ctx: ctx, ptr: ptr)

            case errSSLWouldBlock:
                self.handshakeRetries += 1
                if self.handshakeRetries >= self.maxHandshakeRetries {
                    self.onEvent?(.log(.warn, "MITM handshake max retries for \(self.hostname)"))
                    self.done(ctx: ctx, ptr: ptr)
                } else {
                    self.handshake(ctx: ctx, ptr: ptr)
                }

            case errSSLPeerHandshakeFail, errSSLPeerCertUnknown, errSSLPeerBadCert:
                let shouldExclude = TLSManager.shared.recordHandshakeFailure(host: self.hostname)
                if shouldExclude {
                    self.onEvent?(.log(.warn, "MITM: cert pinning detected for \(self.hostname) — auto-excluding"))
                } else {
                    self.onEvent?(.log(.warn, "MITM: \(self.hostname) rejected cert (\(Self.sslErrorName(status)))"))
                }
                self.done(ctx: ctx, ptr: ptr)

            case errSSLClosedAbort, errSSLClosedGraceful, errSSLClosedNoNotify:
                self.onEvent?(.log(.info, "MITM: \(self.hostname) closed during handshake"))
                self.done(ctx: ctx, ptr: ptr)

            default:
                self.onEvent?(.log(.warn, "MITM handshake error \(self.hostname): \(Self.sslErrorName(status))"))
                self.done(ctx: ctx, ptr: ptr)
            }
        }
    }

    // MARK: - Read decrypted HTTP

    private func readDecrypted(ctx: SSLContext, ptr: UnsafeMutableRawPointer) {
        queue.asyncAfter(deadline: .now() + 0.01) { [weak self] in
            guard let self else {
                Unmanaged<MITMHandler>.fromOpaque(ptr).release()
                return
            }
            var buf = [UInt8](repeating: 0, count: 16384)
            var processed = 0
            let status = MITMRead(ctx, &buf, buf.count, &processed)

            if processed > 0 {
                let data = Data(buf[0..<processed])
                self.processRequest(data, ctx: ctx, ptr: ptr)
                return
            }
            if Int32(status) == errSSLWouldBlock {
                self.readDecrypted(ctx: ctx, ptr: ptr)
                return
            }
            self.done(ctx: ctx, ptr: ptr)
        }
    }

    // MARK: - Process decrypted request

    private func processRequest(_ data: Data, ctx: SSLContext, ptr: UnsafeMutableRawPointer) {
        guard let text = String(data: data, encoding: .utf8) else {
            done(ctx: ctx, ptr: ptr); return
        }
        let firstLineEnd = text.range(of: "\r\n")?.lowerBound ?? text.endIndex
        let parts = text[text.startIndex..<firstLineEnd].split(separator: " ", maxSplits: 2)
        let method = parts.count > 0 ? String(parts[0]) : "?"
        let target = parts.count > 1 ? String(parts[1]) : "/"

        // WAF on decrypted content
        if let hit = rules.first(where: {
            $0.enabled && LocalProxy.matches(rule: $0, host: hostname, target: target, headers: text)
        }) {
            let label = hit.name.isEmpty ? hit.pattern : hit.name
            onEvent?(.blocked(host: hostname, ruleName: "MITM: \(label)"))
            sendEncrypted(ctx: ctx, text: "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            done(ctx: ctx, ptr: ptr)
            return
        }

        // Exfiltration on decrypted content
        if let hit = ExfiltrationScanner.shared.scan(headers: text, target: target) {
            onEvent?(.exfiltration(host: hostname, patternName: hit.patternName,
                                   severity: hit.severity.rawValue, preview: hit.matchPreview))
            sendEncrypted(ctx: ctx, text: "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            done(ctx: ctx, ptr: ptr)
            return
        }

        // Privacy
        var finalData = data
        let (rewritten, actions) = LocalProxy.applyPrivacy(headerString: text, settings: privacy)
        if !actions.isEmpty {
            onEvent?(.privacyStripped(host: hostname, actions: actions))
            finalData = Data(rewritten.utf8)
        }

        onEvent?(.allowed(host: hostname, method: method))
        forwardToServer(requestData: finalData, ctx: ctx, ptr: ptr)
    }

    // MARK: - Forward to real server

    private func forwardToServer(requestData: Data, ctx: SSLContext, ptr: UnsafeMutableRawPointer) {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, cb in cb(true) }, queue)
        let params = NWParameters(tls: tls)

        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            done(ctx: ctx, ptr: ptr); return
        }
        let server = NWConnection(host: .init(hostname), port: nwPort, using: params)
        server.stateUpdateHandler = { [weak self] state in
            guard let self else { server.cancel(); return }
            switch state {
            case .ready:
                server.send(content: requestData, completion: .contentProcessed { [weak self] err in
                    guard let self else { server.cancel(); return }
                    if err != nil { self.done(ctx: ctx, ptr: ptr); server.cancel(); return }
                    self.bufferServerResponse(server: server, ctx: ctx, ptr: ptr, buffer: Data())
                })
            case .failed(let err):
                self.onEvent?(.log(.error, "MITM server failed \(self.hostname): \(err)"))
                self.done(ctx: ctx, ptr: ptr)
            case .cancelled:
                break
            default: break
            }
        }
        server.start(queue: queue)
    }

    // MARK: - Response buffering + inspection + stripping

    private func bufferServerResponse(server: NWConnection, ctx: SSLContext,
                                       ptr: UnsafeMutableRawPointer, buffer: Data) {
        server.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { server.cancel(); return }
            var buf = buffer
            if let data, !data.isEmpty {
                buf.append(data)
            }

            // If we have headers and haven't sent them yet, process now
            if let headerEnd = buf.range(of: Data("\r\n\r\n".utf8)) {
                let headerData = buf.subdata(in: 0..<headerEnd.lowerBound)
                let afterHeaders = buf.subdata(in: headerEnd.upperBound..<buf.count)

                // Strip response headers
                let strippedHeaders = self.stripResponseHeaders(headerData)

                // Check Content-Encoding for decompression
                let headerStr = String(data: headerData, encoding: .utf8) ?? ""
                let needsDecompress = headerStr.lowercased().contains("content-encoding: gzip") ||
                                      headerStr.lowercased().contains("content-encoding: deflate")

                // Send modified headers
                var toSend = strippedHeaders
                toSend.append(Data("\r\n\r\n".utf8))
                toSend.append(afterHeaders)
                self.sendEncrypted(ctx: ctx, data: toSend)

                if isComplete || error != nil {
                    server.cancel()
                    // Inspect full response body
                    self.inspectResponseBody(headerStr: headerStr, body: afterHeaders,
                                              needsDecompress: needsDecompress)
                    self.done(ctx: ctx, ptr: ptr)
                    return
                }

                // Stream remaining body directly
                self.streamServerBody(server: server, ctx: ctx, ptr: ptr,
                                       bodyAccum: afterHeaders, headerStr: headerStr,
                                       needsDecompress: needsDecompress)
                return
            }

            // Headers not complete yet, keep buffering (max 32KB)
            if buf.count > 32768 {
                // Headers too large, send raw and give up on inspection
                self.sendEncrypted(ctx: ctx, data: buf)
                self.streamRaw(server: server, ctx: ctx, ptr: ptr)
                return
            }

            if isComplete || error != nil {
                server.cancel()
                self.sendEncrypted(ctx: ctx, data: buf)
                self.done(ctx: ctx, ptr: ptr)
                return
            }

            self.bufferServerResponse(server: server, ctx: ctx, ptr: ptr, buffer: buf)
        }
    }

    private func streamServerBody(server: NWConnection, ctx: SSLContext,
                                   ptr: UnsafeMutableRawPointer,
                                   bodyAccum: Data, headerStr: String,
                                   needsDecompress: Bool) {
        server.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { server.cancel(); return }
            var accum = bodyAccum
            if let data, !data.isEmpty {
                accum.append(data)
                self.sendEncrypted(ctx: ctx, data: data)
            }
            if isComplete || error != nil {
                server.cancel()
                // Cap inspection at 2MB
                if accum.count <= 2 * 1024 * 1024 {
                    self.inspectResponseBody(headerStr: headerStr, body: accum,
                                              needsDecompress: needsDecompress)
                }
                self.done(ctx: ctx, ptr: ptr)
                return
            }
            // Stop accumulating body after 2MB but keep streaming
            let nextAccum = accum.count <= 2 * 1024 * 1024 ? accum : Data()
            self.streamServerBody(server: server, ctx: ctx, ptr: ptr,
                                   bodyAccum: nextAccum, headerStr: headerStr,
                                   needsDecompress: needsDecompress)
        }
    }

    private func streamRaw(server: NWConnection, ctx: SSLContext, ptr: UnsafeMutableRawPointer) {
        server.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { server.cancel(); return }
            if let data, !data.isEmpty {
                self.sendEncrypted(ctx: ctx, data: data)
            }
            if isComplete || error != nil {
                server.cancel()
                self.done(ctx: ctx, ptr: ptr)
                return
            }
            self.streamRaw(server: server, ctx: ctx, ptr: ptr)
        }
    }

    // MARK: - Response inspection

    private func inspectResponseBody(headerStr: String, body: Data, needsDecompress: Bool) {
        var inspectionBody = body
        if needsDecompress, let decompressed = Self.decompressGzip(body) {
            inspectionBody = decompressed
        }

        // AI token extraction
        if let det = AITracker.shared.detect(host: hostname) {
            if let usage = AITracker.shared.extractUsage(provider: det.provider, responseBody: inspectionBody) {
                onEvent?(.aiUsage(provider: usage.providerId, model: usage.model,
                                  promptTokens: usage.promptTokens,
                                  completionTokens: usage.completionTokens,
                                  cost: usage.estimatedCost))
            }
        }

        // Content WAF on response body
        if let bodyStr = String(data: inspectionBody.prefix(65536), encoding: .utf8) {
            for rule in rules where rule.enabled && rule.kind == .blockContent {
                if bodyStr.lowercased().contains(rule.pattern.lowercased()) {
                    let label = rule.name.isEmpty ? rule.pattern : rule.name
                    onEvent?(.log(.warn, "MITM: response body matched WAF rule '\(label)' from \(hostname)"))
                }
            }
        }
    }

    /// Strip fingerprinting response headers.
    private func stripResponseHeaders(_ headerData: Data) -> Data {
        guard privacy.stripServerHeaders,
              let text = String(data: headerData, encoding: .utf8) else {
            return headerData
        }
        let stripNames = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
        let lines = text.split(separator: "\r\n", omittingEmptySubsequences: false)
        var stripped = 0
        let filtered = lines.filter { line in
            let lower = line.lowercased()
            let shouldStrip = stripNames.contains(where: { lower.hasPrefix($0 + ":") })
            if shouldStrip { stripped += 1 }
            return !shouldStrip
        }
        if stripped > 0 {
            onEvent?(.log(.info, "MITM: stripped \(stripped) response headers from \(hostname)"))
        }
        return Data(filtered.joined(separator: "\r\n").utf8)
    }

    // MARK: - Gzip decompression

    static func decompressGzip(_ data: Data) -> Data? {
        guard data.count > 2 else { return nil }
        // Use compression_decode_buffer with ZLIB algorithm
        let decompressedSize = data.count * 4  // estimate
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: decompressedSize)
        defer { buffer.deallocate() }

        // Skip gzip header if present (0x1f 0x8b)
        let srcData: Data
        if data[0] == 0x1f && data[1] == 0x8b && data.count > 10 {
            srcData = data.subdata(in: 10..<data.count)
        } else {
            srcData = data
        }

        let result = srcData.withUnsafeBytes { srcBuf -> Int in
            guard let srcPtr = srcBuf.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return compression_decode_buffer(buffer, decompressedSize,
                                              srcPtr, srcData.count,
                                              nil, COMPRESSION_ZLIB)
        }
        guard result > 0 else { return nil }
        return Data(bytes: buffer, count: result)
    }

    // MARK: - SSL write helpers

    private func sendEncrypted(ctx: SSLContext, text: String) {
        sendEncrypted(ctx: ctx, data: Data(text.utf8))
    }

    private func sendEncrypted(ctx: SSLContext, data: Data) {
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

    private func done(ctx: SSLContext, ptr: UnsafeMutableRawPointer) {
        MITMClose(ctx)
        Unmanaged<MITMHandler>.fromOpaque(ptr).release()
        clientConn.cancel()
    }

    // MARK: - Error name helper

    static func sslErrorName(_ status: OSStatus) -> String {
        switch Int32(status) {
        case errSSLProtocol:            return "errSSLProtocol"
        case errSSLNegotiation:         return "errSSLNegotiation"
        case errSSLFatalAlert:          return "errSSLFatalAlert"
        case errSSLWouldBlock:          return "errSSLWouldBlock"
        case errSSLSessionNotFound:     return "errSSLSessionNotFound"
        case errSSLClosedGraceful:      return "errSSLClosedGraceful"
        case errSSLClosedAbort:         return "errSSLClosedAbort"
        case errSSLClosedNoNotify:      return "errSSLClosedNoNotify"
        case errSSLPeerHandshakeFail:   return "errSSLPeerHandshakeFail"
        case errSSLPeerBadCert:         return "errSSLPeerBadCert"
        case errSSLPeerCertUnknown:     return "errSSLPeerCertUnknown"
        case errSSLPeerCertExpired:     return "errSSLPeerCertExpired"
        case errSSLPeerCertRevoked:     return "errSSLPeerCertRevoked"
        case errSSLPeerUnexpectedMsg:   return "errSSLPeerUnexpectedMsg"
        case errSSLInternal:            return "errSSLInternal"
        default:                        return "OSStatus(\(status))"
        }
    }
}

// MARK: - SSLContext IO callbacks

nonisolated func mitmRead(_ connection: SSLConnectionRef,
                           _ data: UnsafeMutableRawPointer,
                           _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let handler = Unmanaged<MITMHandler>.fromOpaque(connection).takeUnretainedValue()
    handler.readLock.lock()
    let available = handler.readBuffer.count
    if available == 0 {
        handler.readLock.unlock()
        dataLength.pointee = 0
        return errSSLWouldBlock
    }
    let n = min(available, dataLength.pointee)
    handler.readBuffer.copyBytes(to: data.assumingMemoryBound(to: UInt8.self), count: n)
    handler.readBuffer.removeFirst(n)
    handler.readLock.unlock()
    dataLength.pointee = n
    return n < dataLength.pointee ? errSSLWouldBlock : errSecSuccess
}

nonisolated func mitmWrite(_ connection: SSLConnectionRef,
                            _ data: UnsafeRawPointer,
                            _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let handler = Unmanaged<MITMHandler>.fromOpaque(connection).takeUnretainedValue()
    handler.writeLock.lock()
    handler.pendingWrites.append(Data(bytes: data, count: dataLength.pointee))
    handler.writeLock.unlock()
    return errSecSuccess
}
