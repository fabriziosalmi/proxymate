//
//  NIOTLSProxy.swift
//  proxymate
//
//  SwiftNIO-SSL MITM proxy. Runs as a local NIO server on 127.0.0.1.
//  LocalProxy tunnels CONNECT clients here for TLS interception.
//
//  Architecture:
//    Client → LocalProxy (NWConnection) → "200 OK" → pipe to NIOTLSProxy
//    NIOTLSProxy: [NIOSSLServerHandler] → [HTTPDecoder] → [InspectHandler]
//    InspectHandler → [NIOSSLClientHandler] → real server
//
//  This isolates all TLS handling in NIO's event-driven pipeline —
//  no SSLContext, no C wrappers, no manual IO callbacks.
//

import Foundation
import NIOCore
import NIOPosix
import NIOHTTP1
import NIOSSL

// MARK: - NIOTLSProxy

nonisolated final class NIOTLSProxy: @unchecked Sendable {

    static let shared = NIOTLSProxy()

    private let group: MultiThreadedEventLoopGroup
    private var serverChannel: Channel?
    private(set) var port: Int = 0

    private var rules: [WAFRule] = []
    private var privacy = PrivacySettings()
    private var onEvent: (@Sendable (LocalProxy.Event) -> Void)?
    private let lock = NSLock()

    private init() {
        group = MultiThreadedEventLoopGroup(numberOfThreads: 4)
    }

    // MARK: - Lifecycle

    func start(rules: [WAFRule], privacy: PrivacySettings,
               onEvent: (@Sendable (LocalProxy.Event) -> Void)?) throws -> Int {
        lock.lock()
        self.rules = rules
        self.privacy = privacy
        self.onEvent = onEvent
        lock.unlock()

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .childChannelInitializer { [weak self] channel in
                channel.pipeline.addHandler(ConnectReceiver(proxy: self))
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)

        let channel = try bootstrap.bind(host: "127.0.0.1", port: 0).wait()
        serverChannel = channel
        port = channel.localAddress?.port ?? 0
        return port
    }

    func stop() {
        try? serverChannel?.close().wait()
        serverChannel = nil
        port = 0
    }

    func updateRules(_ r: [WAFRule]) {
        lock.lock(); rules = r; lock.unlock()
    }

    func updatePrivacy(_ p: PrivacySettings) {
        lock.lock(); privacy = p; lock.unlock()
    }

    fileprivate func currentConfig() -> (rules: [WAFRule], privacy: PrivacySettings,
                                          onEvent: (@Sendable (LocalProxy.Event) -> Void)?) {
        lock.lock()
        defer { lock.unlock() }
        return (rules, privacy, onEvent)
    }

    deinit {
        stop()
        try? group.syncShutdownGracefully()
    }
}

// MARK: - Step 1: Receive raw bytes from client, detect hostname, start TLS

/// First handler in the pipeline. Reads a hostname header sent by LocalProxy
/// ("MITM hostname\n") before the client's TLS ClientHello arrives.
/// Configures TLS server handler with forged cert, then lets NIO handle TLS.
private final class ConnectReceiver: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer

    weak var proxy: NIOTLSProxy?
    private var hostnameBuffer = ""
    private var configured = false

    init(proxy: NIOTLSProxy?) {
        self.proxy = proxy
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)

        // First message: "MITM hostname\n" from LocalProxy
        if !configured {
            if let str = buf.readString(length: buf.readableBytes) {
                hostnameBuffer += str
            }
            guard let newlineIdx = hostnameBuffer.firstIndex(of: "\n") else { return }
            let hostname = String(hostnameBuffer[hostnameBuffer.startIndex..<newlineIdx])
                .trimmingCharacters(in: .whitespaces)
            // Any bytes after the newline are the ClientHello
            let afterNewline = hostnameBuffer.index(after: newlineIdx)
            let remainder = String(hostnameBuffer[afterNewline...])

            configured = true
            setupTLS(context: context, hostname: hostname, remainder: remainder)
            return
        }

        // After configuration, forward to pipeline
        context.fireChannelRead(data)
    }

    private func setupTLS(context: ChannelHandlerContext, hostname: String, remainder: String) {
        guard let proxy else { context.close(promise: nil); return }
        let config = proxy.currentConfig()

        let serverTLSContext: NIOSSLContext
        do {
            let pem = try TLSManager.shared.pemForHost(hostname)
            let cert = try NIOSSLCertificate(bytes: Array(pem.cert.utf8), format: .pem)
            let key = try NIOSSLPrivateKey(bytes: Array(pem.key.utf8), format: .pem)
            var chain: [NIOSSLCertificateSource] = [.certificate(cert)]
            if let caPem = try? NIOSSLCertificate(bytes: Array(pem.caCert.utf8), format: .pem) {
                chain.append(.certificate(caPem))
            }
            var serverConf = TLSConfiguration.makeServerConfiguration(
                certificateChain: chain, privateKey: .privateKey(key))
            serverConf.minimumTLSVersion = .tlsv12
            serverTLSContext = try NIOSSLContext(configuration: serverConf)
        } catch {
            config.onEvent?(.log(.error, "NIO MITM cert failed \(hostname): \(error)"))
            context.close(promise: nil)
            return
        }

        config.onEvent?(.mitmIntercepted(host: hostname))

        // Build pipeline: SSL → HTTP decode → Inspect
        let sslHandler = NIOSSLServerHandler(context: serverTLSContext)
        context.pipeline.addHandler(sslHandler, position: .first).flatMap {
            context.pipeline.addHandler(ByteToMessageHandler(HTTPRequestDecoder()))
        }.flatMap {
            context.pipeline.addHandler(HTTPResponseEncoder())
        }.flatMap {
            context.pipeline.addHandler(
                MITMInspectHandler(hostname: hostname, config: config, group: context.eventLoop))
        }.flatMap {
            context.pipeline.removeHandler(self)
        }.whenComplete { result in
            switch result {
            case .success:
                // If we have leftover bytes (ClientHello), feed them in
                if !remainder.isEmpty {
                    var buf = context.channel.allocator.buffer(capacity: remainder.utf8.count)
                    buf.writeString(remainder)
                    context.channel.pipeline.fireChannelRead(NIOAny(buf))
                }
            case .failure(let err):
                config.onEvent?(.log(.error, "NIO MITM pipeline failed \(hostname): \(err)"))
                context.close(promise: nil)
            }
        }
    }
}

// MARK: - Step 2: Inspect decrypted HTTP + forward to upstream

private final class MITMInspectHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    let hostname: String
    let config: (rules: [WAFRule], privacy: PrivacySettings,
                 onEvent: (@Sendable (LocalProxy.Event) -> Void)?)
    let group: EventLoop

    private var upstreamChannel: Channel?
    private var bufferedHead: HTTPRequestHead?

    init(hostname: String,
         config: (rules: [WAFRule], privacy: PrivacySettings,
                  onEvent: (@Sendable (LocalProxy.Event) -> Void)?),
         group: EventLoop) {
        self.hostname = hostname
        self.config = config
        self.group = group
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)

        switch part {
        case .head(let req):
            // WAF check on request
            let target = req.uri
            let headerString = req.headers.map { "\($0.name): \($0.value)" }.joined(separator: "\r\n")

            // Check WAF rules
            for rule in config.rules where rule.enabled {
                if LocalProxy.matches(rule: rule, host: hostname, target: target, headers: headerString) {
                    let label = rule.name.isEmpty ? rule.pattern : rule.name
                    config.onEvent?(.blocked(host: hostname, ruleName: "MITM: \(label)"))
                    send403(context: context, reason: label)
                    return
                }
            }

            // Exfiltration check
            if let hit = ExfiltrationScanner.shared.scan(headers: headerString, target: target) {
                config.onEvent?(.exfiltration(host: hostname, patternName: hit.patternName,
                                               severity: hit.severity.rawValue, preview: hit.matchPreview))
                send403(context: context, reason: hit.patternName)
                return
            }

            // WebSocket upgrade detection
            if req.headers.contains(name: "upgrade") {
                let upgradeVal = req.headers[canonicalForm: "upgrade"].joined()
                if upgradeVal.lowercased().contains("websocket") {
                    config.onEvent?(.log(.info, "WebSocket upgrade: \(hostname)\(target)"))
                    TLSManager.shared.addRuntimeExclude(host: hostname)
                }
            }

            config.onEvent?(.allowed(host: hostname, method: req.method.rawValue))

            // Connect upstream and forward
            bufferedHead = req
            connectUpstream(context: context, host: hostname, port: 443)

        case .body(let buf):
            upstreamChannel?.writeAndFlush(HTTPClientRequestPart.body(.byteBuffer(buf)), promise: nil)

        case .end:
            upstreamChannel?.writeAndFlush(HTTPClientRequestPart.end(nil), promise: nil)
        }
    }

    private func connectUpstream(context: ChannelHandlerContext, host: String, port: Int) {
        if let existing = upstreamChannel, existing.isActive {
            // Reuse existing connection
            forwardRequest(context: context)
            return
        }

        var clientTLS = TLSConfiguration.makeClientConfiguration()
        clientTLS.certificateVerification = .none

        let clientCtx: NIOSSLContext
        do {
            clientCtx = try NIOSSLContext(configuration: clientTLS)
        } catch {
            config.onEvent?(.log(.error, "NIO MITM client TLS failed: \(error)"))
            context.close(promise: nil)
            return
        }

        let clientChannel = context.channel

        ClientBootstrap(group: group)
            .channelInitializer { channel in
                let sslHandler = try! NIOSSLClientHandler(context: clientCtx, serverHostname: host)
                return channel.pipeline.addHandler(sslHandler).flatMap {
                    channel.pipeline.addHandler(HTTPRequestEncoder())
                }.flatMap {
                    channel.pipeline.addHandler(ByteToMessageHandler(HTTPResponseDecoder()))
                }.flatMap {
                    channel.pipeline.addHandler(
                        UpstreamRelayHandler(clientChannel: clientChannel, config: self.config, hostname: host))
                }
            }
            .connect(host: host, port: port)
            .whenComplete { [weak self] result in
                switch result {
                case .success(let channel):
                    self?.upstreamChannel = channel
                    self?.forwardRequest(context: context)
                case .failure(let err):
                    self?.config.onEvent?(.log(.error, "NIO MITM upstream failed \(host): \(err)"))
                    context.close(promise: nil)
                }
            }
    }

    private func forwardRequest(context: ChannelHandlerContext) {
        guard let head = bufferedHead, let upstream = upstreamChannel else { return }
        upstream.write(HTTPClientRequestPart.head(head), promise: nil)
        bufferedHead = nil
    }

    private func send403(context: ChannelHandlerContext, reason: String) {
        let body = "Blocked by Proxymate: \(reason)\n"
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "text/plain")
        headers.add(name: "Content-Length", value: "\(body.utf8.count)")
        headers.add(name: "Connection", value: "close")
        let head = HTTPResponseHead(version: .http1_1, status: .forbidden, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        var buf = context.channel.allocator.buffer(capacity: body.utf8.count)
        buf.writeString(body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buf))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            context.close(promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        upstreamChannel?.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // Cert pinning detected
        if error is NIOSSLError || error is BoringSSLError {
            let shouldExclude = TLSManager.shared.recordHandshakeFailure(host: hostname)
            if shouldExclude {
                config.onEvent?(.log(.warn, "NIO MITM: cert pinning detected \(hostname), auto-excluding"))
                TLSManager.shared.addRuntimeExclude(host: hostname)
            }
        }
        context.close(promise: nil)
    }
}

// MARK: - Step 3: Relay responses from upstream back to client

private final class UpstreamRelayHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPClientResponsePart

    let clientChannel: Channel
    let config: (rules: [WAFRule], privacy: PrivacySettings,
                 onEvent: (@Sendable (LocalProxy.Event) -> Void)?)
    let hostname: String

    init(clientChannel: Channel,
         config: (rules: [WAFRule], privacy: PrivacySettings,
                  onEvent: (@Sendable (LocalProxy.Event) -> Void)?),
         hostname: String) {
        self.clientChannel = clientChannel
        self.config = config
        self.hostname = hostname
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)

        switch part {
        case .head(let resp):
            var headers = resp.headers
            // Strip server fingerprint headers if privacy enabled
            if config.privacy.stripServerHeaders {
                headers.remove(name: "Server")
                headers.remove(name: "X-Powered-By")
                headers.remove(name: "X-AspNet-Version")
                headers.remove(name: "X-Runtime")
                headers.remove(name: "X-Version")
            }
            let modified = HTTPResponseHead(
                version: resp.version, status: resp.status, headers: headers)
            clientChannel.write(HTTPServerResponsePart.head(modified), promise: nil)

            // Record in host memory
            HostMemory.shared.recordResponse(
                host: hostname, statusCode: Int(resp.status.code),
                latency: 0, bytes: 0)

        case .body(let buf):
            // WAF content inspection on response body
            if let str = buf.getString(at: buf.readerIndex, length: buf.readableBytes) {
                for rule in config.rules where rule.enabled && rule.kind == .blockContent {
                    if str.lowercased().contains(rule.pattern.lowercased()) {
                        let label = rule.name.isEmpty ? rule.pattern : rule.name
                        config.onEvent?(.blocked(host: hostname, ruleName: "MITM Response: \(label)"))
                        // Can't easily replace response mid-stream, just log
                    }
                }
            }
            clientChannel.write(HTTPServerResponsePart.body(.byteBuffer(buf)), promise: nil)

        case .end:
            clientChannel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        clientChannel.close(promise: nil)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        config.onEvent?(.log(.error, "NIO MITM upstream error \(hostname): \(error)"))
        clientChannel.close(promise: nil)
        context.close(promise: nil)
    }
}
