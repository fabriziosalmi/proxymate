//
//  MITMHandler.swift
//  proxymate
//
//  Handles MITM TLS interception for CONNECT tunnels.
//
//  Flow:
//  1. Client sends CONNECT → proxy replies "200 Connection Established"
//  2. MITMHandler terminates client's TLS using forged leaf cert (SSLContext)
//  3. Opens TLS connection to real server (NWConnection)
//  4. Decrypted HTTP is inspected (WAF, exfiltration, privacy, AI)
//  5. Response streamed back encrypted to client
//

import Foundation
import Network

nonisolated final class MITMHandler: @unchecked Sendable {

    fileprivate let clientConn: NWConnection
    private let hostname: String
    private let port: UInt16
    private let queue: DispatchQueue
    private let onEvent: (@Sendable (LocalProxy.Event) -> Void)?
    private let rules: [WAFRule]
    private let privacy: PrivacySettings

    fileprivate var readBuffer = Data()
    fileprivate var readLock = NSLock()
    fileprivate var writeLock = NSLock()
    fileprivate var pendingWrites = Data()

    init(clientConn: NWConnection,
         hostname: String,
         port: UInt16,
         queue: DispatchQueue,
         rules: [WAFRule],
         privacy: PrivacySettings,
         onEvent: (@Sendable (LocalProxy.Event) -> Void)?) {
        self.clientConn = clientConn
        self.hostname = hostname
        self.port = port
        self.queue = queue
        self.rules = rules
        self.privacy = privacy
        self.onEvent = onEvent
    }

    func start() {
        onEvent?(.mitmIntercepted(host: hostname))

        // Forge cert
        let identity: SecIdentity
        do {
            identity = try TLSManager.shared.identityForHost(hostname)
        } catch {
            onEvent?(.log(.error, "MITM cert failed for \(hostname): \(error.localizedDescription)"))
            clientConn.cancel()
            return
        }

        // Create server-side SSLContext
        guard let ctxUnmanaged = MITMCreateSSLContext(.serverSide, .streamType) else {
            onEvent?(.log(.error, "MITM SSLCreateContext failed"))
            clientConn.cancel()
            return
        }
        let ctx = ctxUnmanaged.takeRetainedValue()

        // Set cert
        var cert: SecCertificate?
        SecIdentityCopyCertificate(identity, &cert)
        guard let cert else {
            onEvent?(.log(.error, "MITM cert extract failed"))
            clientConn.cancel()
            return
        }
        let chain: NSArray = [identity, cert]
        guard MITMSetCertificate(ctx, chain) == errSecSuccess else {
            onEvent?(.log(.error, "MITM SetCertificate failed"))
            clientConn.cancel()
            return
        }

        // Set IO callbacks with self as connection ref
        let ptr = Unmanaged.passRetained(self).toOpaque()
        guard MITMSetConnection(ctx, ptr) == errSecSuccess,
              MITMSetIOFuncs(ctx, mitmRead, mitmWrite) == errSecSuccess else {
            Unmanaged<MITMHandler>.fromOpaque(ptr).release()
            clientConn.cancel()
            return
        }

        // Pump raw bytes from client, then handshake
        pumpClient()
        handshake(ctx: ctx, ptr: ptr)
    }

    // MARK: - Client raw byte pump

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

    private func handshake(ctx: SSLContext, ptr: UnsafeMutableRawPointer) {
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
                self.handshake(ctx: ctx, ptr: ptr)
            default:
                self.onEvent?(.log(.warn, "MITM handshake fail \(self.hostname): \(status)"))
                self.done(ctx: ctx, ptr: ptr)
            }
        }
    }

    // MARK: - Read decrypted HTTP from client

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
            // Closed or error
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
            guard let self else { return }
            switch state {
            case .ready:
                server.send(content: requestData, completion: .contentProcessed { [weak self] err in
                    guard let self else { return }
                    if err != nil { self.done(ctx: ctx, ptr: ptr); server.cancel(); return }
                    self.pipeServerToClient(server: server, ctx: ctx, ptr: ptr, buffer: Data())
                })
            case .failed:
                self.done(ctx: ctx, ptr: ptr)
            default: break
            }
        }
        server.start(queue: queue)
    }

    private func pipeServerToClient(server: NWConnection, ctx: SSLContext,
                                     ptr: UnsafeMutableRawPointer, buffer: Data,
                                     headersSent: Bool = false) {
        server.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            var buf = buffer
            var sent = headersSent
            if let data, !data.isEmpty {
                buf.append(data)

                if !sent, let range = buf.range(of: Data("\r\n\r\n".utf8)) {
                    // We have full response headers — strip and send
                    let headerData = buf.subdata(in: 0..<range.lowerBound)
                    let afterHeaders = buf.subdata(in: range.upperBound..<buf.count)

                    let stripped = self.stripResponseHeaders(headerData)
                    var toSend = stripped
                    toSend.append(Data("\r\n\r\n".utf8))
                    toSend.append(afterHeaders)
                    self.sendEncrypted(ctx: ctx, data: toSend)
                    sent = true
                    // Keep the full buffer for post-inspection
                } else if sent {
                    // Headers already sent, stream body directly
                    self.sendEncrypted(ctx: ctx, data: data)
                }
                // If !sent and no \r\n\r\n yet, buffer more
            }
            if isComplete || error != nil {
                server.cancel()
                self.inspectResponse(buf)
                self.done(ctx: ctx, ptr: ptr)
                return
            }
            self.pipeServerToClient(server: server, ctx: ctx, ptr: ptr,
                                     buffer: buf, headersSent: sent)
        }
    }

    /// Strip Server, X-Powered-By, and other fingerprinting headers.
    private func stripResponseHeaders(_ headerData: Data) -> Data {
        guard privacy.stripServerHeaders,
              let text = String(data: headerData, encoding: .utf8) else {
            return headerData
        }
        let stripped = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
        let lines = text.split(separator: "\r\n", omittingEmptySubsequences: false)
        let filtered = lines.filter { line in
            let lower = line.lowercased()
            return !stripped.contains(where: { lower.hasPrefix($0 + ":") })
        }
        if filtered.count < lines.count {
            onEvent?(.log(.info, "MITM: stripped \(lines.count - filtered.count) response headers from \(hostname)"))
        }
        return Data(filtered.joined(separator: "\r\n").utf8)
    }

    // MARK: - Response inspection

    private func inspectResponse(_ data: Data) {
        guard let headerEnd = data.range(of: Data("\r\n\r\n".utf8)) else { return }

        // AI token extraction on HTTPS responses
        if let det = AITracker.shared.detect(host: hostname) {
            let body = data.subdata(in: headerEnd.upperBound..<data.count)
            if let usage = AITracker.shared.extractUsage(provider: det.provider, responseBody: body) {
                onEvent?(.aiUsage(provider: usage.providerId, model: usage.model,
                                  promptTokens: usage.promptTokens,
                                  completionTokens: usage.completionTokens,
                                  cost: usage.estimatedCost))
            }
        }
    }

    // MARK: - SSL write helpers

    private func sendEncrypted(ctx: SSLContext, text: String) {
        sendEncrypted(ctx: ctx, data: Data(text.utf8))
    }

    private func sendEncrypted(ctx: SSLContext, data: Data) {
        data.withUnsafeBytes { buf in
            guard let base = buf.baseAddress else { return }
            var offset = 0
            var maxIterations = data.count + 100  // safety cap against infinite loop
            while offset < data.count && maxIterations > 0 {
                maxIterations -= 1
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
}

// MARK: - SSLContext IO callbacks

/// Reads raw (encrypted) TLS bytes from the client via the read buffer.
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

/// Buffers encrypted bytes for sending to the client.
nonisolated func mitmWrite(_ connection: SSLConnectionRef,
                        _ data: UnsafeRawPointer,
                        _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let handler = Unmanaged<MITMHandler>.fromOpaque(connection).takeUnretainedValue()
    handler.writeLock.lock()
    handler.pendingWrites.append(Data(bytes: data, count: dataLength.pointee))
    handler.writeLock.unlock()
    return errSecSuccess
}
