//
//  MITMHandler.swift
//  proxymate
//
//  Active TLS MITM interception for CONNECT tunnels.
//  v0.8.16: No Unmanaged pointers. Uses static registry for SSLContext callbacks.
//

import Foundation
import Network

/// Registry of active MITM handlers. SSLContext callbacks use the handler ID
/// (stored as the SSLConnectionRef) to look up the handler safely.
/// This eliminates Unmanaged pointer lifetime issues that caused crashes.
private var activeHandlers: [Int: MITMHandler] = [:]
private let handlersLock = NSLock()
private var nextHandlerID: Int = 1

private struct TLSSession: @unchecked Sendable {
    nonisolated(unsafe) let ctx: SSLContext
    let handlerID: Int
}

nonisolated final class MITMHandler: @unchecked Sendable {

    fileprivate let clientConn: NWConnection
    private let hostname: String
    private let port: UInt16
    private let queue: DispatchQueue
    private let onEvent: (@Sendable (LocalProxy.Event) -> Void)?
    private let rules: [WAFRule]
    private let privacy: PrivacySettings
    private let startTime = Date()
    private let handlerID: Int

    fileprivate var readBuffer = Data()
    fileprivate var readLock = NSLock()
    fileprivate var writeLock = NSLock()
    fileprivate var pendingWrites = Data()
    private var handshakeRetries = 0
    private let maxHandshakeRetries = 50
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

        // Register in global registry
        handlersLock.lock()
        self.handlerID = nextHandlerID
        nextHandlerID += 1
        activeHandlers[self.handlerID] = self
        handlersLock.unlock()
    }

    // MARK: - Start

    func start() {
        onEvent?(.mitmIntercepted(host: hostname))

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
        let idPtr = UnsafeMutableRawPointer(bitPattern: handlerID)!
        guard MITMSetConnection(ctx, idPtr) == errSecSuccess,
              MITMSetIOFuncs(ctx, mitmReadCB, mitmWriteCB) == errSecSuccess else {
            cleanup()
            return
        }

        let session = TLSSession(ctx: ctx, handlerID: handlerID)
        pumpClient()
        handshake(session: session)
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

    // MARK: - TLS handshake

    private func handshake(session: TLSSession) {
        if Date().timeIntervalSince(startTime) > handshakeTimeout {
            onEvent?(.log(.warn, "MITM handshake timeout for \(hostname)"))
            done(session: session); return
        }

        queue.asyncAfter(deadline: .now() + 0.02) { [weak self] in
            guard let self else { return }
            let status = MITMHandshake(session.ctx)
            self.flushWrites()

            switch Int32(status) {
            case errSecSuccess:
                self.onEvent?(.log(.info, "MITM TLS OK: \(self.hostname)"))
                self.readDecrypted(session: session)
            case errSSLWouldBlock:
                self.handshakeRetries += 1
                if self.handshakeRetries >= self.maxHandshakeRetries {
                    self.done(session: session)
                } else {
                    self.handshake(session: session)
                }
            case errSSLPeerHandshakeFail, errSSLPeerCertUnknown, errSSLPeerBadCert:
                let shouldExclude = TLSManager.shared.recordHandshakeFailure(host: self.hostname)
                if shouldExclude {
                    self.onEvent?(.log(.warn, "MITM: cert pinning detected for \(self.hostname)"))
                }
                self.done(session: session)
            default:
                self.onEvent?(.log(.warn, "MITM error \(self.hostname): \(status)"))
                self.done(session: session)
            }
        }
    }

    // MARK: - Decrypted traffic

    private func readDecrypted(session: TLSSession) {
        queue.asyncAfter(deadline: .now() + 0.01) { [weak self] in
            guard let self else { return }
            var buf = [UInt8](repeating: 0, count: 16384)
            var processed = 0
            let status = MITMRead(session.ctx, &buf, buf.count, &processed)
            if processed > 0 {
                self.processRequest(Data(buf[0..<processed]), session: session)
                return
            }
            if Int32(status) == errSSLWouldBlock {
                self.readDecrypted(session: session)
                return
            }
            self.done(session: session)
        }
    }

    private func processRequest(_ data: Data, session: TLSSession) {
        guard let text = String(data: data, encoding: .utf8) else {
            done(session: session); return
        }
        let parts = (text.split(separator: "\r\n").first ?? "").split(separator: " ", maxSplits: 2)
        let method = parts.count > 0 ? String(parts[0]) : "?"
        let target = parts.count > 1 ? String(parts[1]) : "/"

        if let hit = rules.first(where: {
            $0.enabled && LocalProxy.matches(rule: $0, host: hostname, target: target, headers: text)
        }) {
            let label = hit.name.isEmpty ? hit.pattern : hit.name
            onEvent?(.blocked(host: hostname, ruleName: "MITM: \(label)"))
            sendEncrypted(session: session, text: "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            done(session: session); return
        }

        if let hit = ExfiltrationScanner.shared.scan(headers: text, target: target) {
            onEvent?(.exfiltration(host: hostname, patternName: hit.patternName,
                                   severity: hit.severity.rawValue, preview: hit.matchPreview))
            sendEncrypted(session: session, text: "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            done(session: session); return
        }

        var finalData = data
        let (rewritten, actions) = LocalProxy.applyPrivacy(headerString: text, settings: privacy)
        if !actions.isEmpty {
            onEvent?(.privacyStripped(host: hostname, actions: actions))
            finalData = Data(rewritten.utf8)
        }

        onEvent?(.allowed(host: hostname, method: method))
        forwardToServer(requestData: finalData, session: session)
    }

    // MARK: - Forward to server

    private func forwardToServer(requestData: Data, session: TLSSession) {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, cb in cb(true) }, queue)
        let params = NWParameters(tls: tls)
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { done(session: session); return }

        let server = NWConnection(host: .init(hostname), port: nwPort, using: params)
        server.stateUpdateHandler = { [weak self] state in
            guard let self else { server.cancel(); return }
            switch state {
            case .ready:
                server.send(content: requestData, completion: .contentProcessed { [weak self] err in
                    guard let self else { server.cancel(); return }
                    if err != nil { self.done(session: session); server.cancel(); return }
                    self.pipeResponse(server: server, session: session)
                })
            case .failed:
                self.done(session: session)
            default: break
            }
        }
        server.start(queue: queue)
    }

    private func pipeResponse(server: NWConnection, session: TLSSession) {
        server.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { server.cancel(); return }
            if let data, !data.isEmpty {
                self.sendEncrypted(session: session, data: data)
            }
            if isComplete || error != nil {
                server.cancel()
                self.done(session: session)
                return
            }
            self.pipeResponse(server: server, session: session)
        }
    }

    // MARK: - SSL helpers

    private func sendEncrypted(session: TLSSession, text: String) {
        sendEncrypted(session: session, data: Data(text.utf8))
    }

    private func sendEncrypted(session: TLSSession, data: Data) {
        data.withUnsafeBytes { buf in
            guard let base = buf.baseAddress else { return }
            var offset = 0
            var maxIter = data.count + 100
            while offset < data.count && maxIter > 0 {
                maxIter -= 1
                var processed = 0
                let s = MITMWrite(session.ctx, base.advanced(by: offset), data.count - offset, &processed)
                if processed == 0 { break }
                offset += processed
                if Int32(s) != errSecSuccess && Int32(s) != errSSLWouldBlock { break }
            }
        }
        flushWrites()
    }

    private func done(session: TLSSession) {
        MITMClose(session.ctx)
        clientConn.cancel()
        cleanup()
    }

    private func cleanup() {
        handlersLock.lock()
        activeHandlers.removeValue(forKey: handlerID)
        handlersLock.unlock()
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
    let n = min(available, dataLength.pointee)
    handler.readBuffer.copyBytes(to: data.assumingMemoryBound(to: UInt8.self), count: n)
    handler.readBuffer.removeFirst(n)
    handler.readLock.unlock()
    dataLength.pointee = n
    return n < dataLength.pointee ? errSSLWouldBlock : errSecSuccess
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
