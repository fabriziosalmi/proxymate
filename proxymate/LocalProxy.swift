//
//  LocalProxy.swift
//  proxymate
//
//  In-process HTTP/HTTPS forward proxy. Bound to 127.0.0.1 on a random port.
//  When the user enables Proxymate, the OS proxy is set to point at this
//  listener; we apply the WAF + privacy header stripping, then forward the
//  raw request to the upstream proxy chosen by the user.
//
//  Built on Network.framework — no third-party dependencies.
//

import Foundation
import Network

nonisolated final class LocalProxy: @unchecked Sendable {

    // MARK: - Public types

    struct Upstream: Sendable, Equatable {
        let host: String
        let port: UInt16
    }

    enum Event: Sendable {
        case started(port: UInt16)
        case stopped
        case allowed(host: String, method: String)
        case blocked(host: String, ruleName: String)
        case blacklisted(host: String, sourceName: String, category: String)
        case exfiltration(host: String, patternName: String, severity: String, preview: String)
        case privacyStripped(host: String, actions: [String])
        case cacheHit(host: String, url: String)
        case cacheMiss(host: String, url: String)
        case mitmIntercepted(host: String)
        case beaconing(host: String, path: String, intervalSec: Double, count: Int)
        case c2Detected(host: String, framework: String, indicator: String, confidence: String)
        case agentDetected(host: String, agent: String, indicator: String)
        case mcpDetected(host: String, method: String)
        case aiDetected(host: String, provider: String)
        case aiBlocked(host: String, provider: String, reason: String)
        case aiUsage(provider: String, model: String, promptTokens: Int, completionTokens: Int, cost: Double)
        case log(LogEntry.Level, String)
    }

    enum LocalProxyError: LocalizedError {
        case alreadyRunning
        case listenerFailed(String)
        var errorDescription: String? {
            switch self {
            case .alreadyRunning: return "Local proxy is already running"
            case .listenerFailed(let m): return m
            }
        }
    }

    // MARK: - State (queue-confined)

    private let queue = DispatchQueue(label: "proxymate.localproxy", qos: .userInitiated)
    private var listener: NWListener?
    private var rulesSnapshot: [WAFRule] = []
    private var allowlistSnapshot: [AllowEntry] = []
    private var privacySnapshot = PrivacySettings()
    private var blacklistSourcesSnapshot: [BlacklistSource] = []
    private var mitmSnapshot = MITMSettings()
    private var beaconingSettings = BeaconingSettings()
    private var c2Settings = C2Settings()
    private let ruleEngine = RuleEngine()
    private var upstream: Upstream?
    private var startCompletion: (@Sendable (Result<UInt16, Error>) -> Void)?

    var onEvent: (@Sendable (Event) -> Void)?

    // MARK: - Lifecycle

    func start(upstream: Upstream,
               rules: [WAFRule],
               allowlist: [AllowEntry] = [],
               privacy: PrivacySettings,
               blacklistSources: [BlacklistSource],
               mitm: MITMSettings = MITMSettings(),
               completion: @escaping @Sendable (Result<UInt16, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.listener != nil {
                completion(.failure(LocalProxyError.alreadyRunning))
                return
            }
            self.upstream = upstream
            self.rulesSnapshot = rules
            self.ruleEngine.compile(rules: rules)
            self.allowlistSnapshot = allowlist
            self.privacySnapshot = privacy
            self.blacklistSourcesSnapshot = blacklistSources
            self.mitmSnapshot = mitm
            self.startCompletion = completion
            do {
                let params = NWParameters.tcp
                params.allowLocalEndpointReuse = true
                let listener = try NWListener(using: params)
                listener.stateUpdateHandler = { [weak self] state in
                    self?.handleListenerState(state, listener: listener)
                }
                listener.newConnectionHandler = { [weak self] conn in
                    self?.handle(client: conn)
                }
                self.listener = listener
                listener.start(queue: self.queue)

                // Start NIO TLS proxy if MITM enabled
                if mitm.enabled {
                    do {
                        let nioPort = try NIOTLSProxy.shared.start(
                            rules: rules, privacy: privacy, onEvent: self.onEvent)
                        self.onEvent?(.log(.info, "NIO MITM proxy on 127.0.0.1:\(nioPort)"))
                    } catch {
                        self.onEvent?(.log(.error, "NIO MITM start failed: \(error)"))
                    }
                }
            } catch {
                self.startCompletion = nil
                completion(.failure(error))
            }
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.listener?.cancel()
            self.listener = nil
            self.upstream = nil
            NIOTLSProxy.shared.stop()
            self.onEvent?(.stopped)
        }
    }

    func updateRules(_ rules: [WAFRule]) {
        queue.async { [weak self] in
            self?.rulesSnapshot = rules
            self?.ruleEngine.compile(rules: rules)
        }
    }

    func updateAllowlist(_ entries: [AllowEntry]) {
        queue.async { [weak self] in self?.allowlistSnapshot = entries }
    }

    func updateUpstream(_ upstream: Upstream) {
        queue.async { [weak self] in self?.upstream = upstream }
    }

    func updatePrivacy(_ privacy: PrivacySettings) {
        queue.async { [weak self] in self?.privacySnapshot = privacy }
    }

    func updateBlacklistSources(_ sources: [BlacklistSource]) {
        queue.async { [weak self] in self?.blacklistSourcesSnapshot = sources }
    }

    func updateMITM(_ settings: MITMSettings) {
        queue.async { [weak self] in self?.mitmSnapshot = settings }
    }

    private func handleListenerState(_ state: NWListener.State, listener: NWListener) {
        switch state {
        case .ready:
            if let cb = startCompletion, let port = listener.port?.rawValue {
                startCompletion = nil
                onEvent?(.started(port: port))
                cb(.success(port))
            }
        case .failed(let err):
            if let cb = startCompletion {
                startCompletion = nil
                cb(.failure(LocalProxyError.listenerFailed(err.localizedDescription)))
            }
            onEvent?(.log(.error, "Listener failed: \(err.localizedDescription)"))
            self.listener = nil
        case .cancelled:
            self.listener = nil
        default:
            break
        }
    }

    // MARK: - Per-connection

    private func handle(client: NWConnection) {
        client.start(queue: queue)
        readHeaders(connection: client) { [weak self] result in
            guard let self else { client.cancel(); return }
            switch result {
            case .failure(let err):
                self.onEvent?(.log(.warn, "Header read failed: \(err.localizedDescription)"))
                client.cancel()
            case .success(let (headerData, leftover)):
                self.routeRequest(client: client, headerData: headerData, leftover: leftover)
            }
        }
    }

    private func readHeaders(connection: NWConnection,
                             accumulator: Data = Data(),
                             completion: @escaping @Sendable (Result<(Data, Data), Error>) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, isComplete, error in
            if let error {
                completion(.failure(error))
                return
            }
            var acc = accumulator
            if let data { acc.append(data) }
            if let range = acc.range(of: Data("\r\n\r\n".utf8)) {
                let headers = acc.subdata(in: 0..<range.upperBound)
                let leftover = acc.subdata(in: range.upperBound..<acc.count)
                completion(.success((headers, leftover)))
                return
            }
            if isComplete || acc.count >= 65_536 {
                completion(.failure(NSError(
                    domain: "Proxymate.LocalProxy", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Headers too large (>\(acc.count) bytes)"])))
                return
            }
            self?.readHeaders(connection: connection, accumulator: acc, completion: completion)
        }
    }

    private func routeRequest(client: NWConnection, headerData: Data, leftover: Data) {
        // Defensive: validate headers before parsing
        guard HTTPParser.validateHeaders(headerData) else {
            onEvent?(.log(.warn, "Malformed request rejected (invalid headers)"))
            sendErrorResponse(client: client, status: "400 Bad Request", body: "Malformed HTTP request\n")
            return
        }

        guard let headerString = String(data: headerData, encoding: .utf8) else {
            client.cancel()
            return
        }
        let firstLineEnd = headerString.range(of: "\r\n")?.lowerBound ?? headerString.endIndex
        let firstLine = String(headerString[headerString.startIndex..<firstLineEnd])
        let parts = firstLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2 else {
            sendErrorResponse(client: client, status: "400 Bad Request", body: "Invalid request line\n")
            return
        }
        let method = String(parts[0])
        let target = String(parts[1])

        // URL length check
        guard target.count <= HTTPParser.maxURLLength else {
            sendErrorResponse(client: client, status: "414 URI Too Long", body: "URL exceeds \(HTTPParser.maxURLLength) bytes\n")
            return
        }

        let host = Self.extractHost(method: method, target: target, headers: headerString)

        // Allow check: RuleEngine (O(1) domain) + allowlist (CIDR)
        let isAllowed = ruleEngine.isAllowed(host: host)
            || AllowlistMatcher.isAllowed(host: host, port: nil, entries: allowlistSnapshot)

        // Mock check: stealth 200 OK (before block — mock takes priority)
        if !isAllowed && ruleEngine.checkMock(host: host) {
            onEvent?(.blocked(host: host, ruleName: "Mock: \(host)"))
            sendMockResponse(client: client, host: host)
            return
        }

        // WAF check: RuleEngine fast path (Set for domains/IPs, then content)
        if !isAllowed {
            if let blockReason = ruleEngine.checkBlock(host: host) {
                onEvent?(.blocked(host: host, ruleName: blockReason))
                sendBlockedResponse(client: client, ruleName: blockReason)
                return
            }
            let bodyStr = leftover.isEmpty ? "" : (String(data: leftover.prefix(8192), encoding: .utf8) ?? "")
            if let contentReason = ruleEngine.checkContent(target: target, headers: headerString, body: bodyStr) {
                onEvent?(.blocked(host: host, ruleName: contentReason))
                sendBlockedResponse(client: client, ruleName: contentReason)
                return
            }
        }

        // Blacklist check (skipped if explicitly allowed)
        if !isAllowed, let hit = BlacklistManager.shared.lookup(host: host, enabledSources: blacklistSourcesSnapshot) {
            onEvent?(.blacklisted(host: host, sourceName: hit.sourceName, category: hit.category.rawValue))
            sendBlockedResponse(client: client, ruleName: "\(hit.sourceName) [\(hit.category.rawValue)]")
            return
        }

        // DNS-level blocking: check cached DNS only (never blocks).
        // resolveAsync populates cache for future requests.
        if !isAllowed {
            DNSResolver.shared.resolveAsync(host)
            let resolvedIPs = DNSResolver.shared.lookupCacheOnly(host)
            for ip in resolvedIPs {
                if let hit = BlacklistManager.shared.lookup(host: ip, enabledSources: blacklistSourcesSnapshot) {
                    onEvent?(.blacklisted(host: host, sourceName: "\(hit.sourceName) (resolved IP \(ip))",
                                          category: hit.category.rawValue))
                    sendBlockedResponse(client: client, ruleName: "DNS→IP: \(hit.sourceName) [\(ip)]")
                    return
                }
            }
        }

        // Exfiltration scan (headers + URL only, not body)
        if let hit = ExfiltrationScanner.shared.scan(headers: headerString, target: target) {
            onEvent?(.exfiltration(host: host, patternName: hit.patternName,
                                   severity: hit.severity.rawValue, preview: hit.matchPreview))
            sendBlockedResponse(client: client, ruleName: "Exfiltration: \(hit.patternName)")
            return
        }

        // C2 framework detection
        if let c2 = C2Detector.scan(headers: headerString, target: target, settings: c2Settings) {
            onEvent?(.c2Detected(host: host, framework: c2.framework,
                                  indicator: c2.indicator, confidence: c2.confidence.rawValue))
            if c2Settings.action == .block {
                sendBlockedResponse(client: client, ruleName: "C2: \(c2.framework) (\(c2.indicator))")
                return
            }
        }

        // AI Agent enforcement (Claude Code, Cursor, MCP, etc.)
        var detectedMCPMethod: String?
        if let agentDetection = AIAgentEnforcer.detectAgent(headers: headerString, host: host) {
            onEvent?(.agentDetected(host: host, agent: agentDetection.agentName,
                                     indicator: agentDetection.indicator))
            // MCP detection on request body
            if !leftover.isEmpty, let mcp = AIAgentEnforcer.detectMCP(body: leftover, host: host) {
                onEvent?(.mcpDetected(host: host, method: mcp.method))
                detectedMCPMethod = mcp.method
            }
        }

        // Loop breaker: only runs on AI/agent traffic (not normal browsing)
        if detectedMCPMethod != nil || AIAgentEnforcer.detectAgent(headers: headerString, host: host) != nil || AITracker.shared.detect(host: host) != nil,
           let loop = AgentLoopBreaker.shared.check(
            host: host, bodyData: leftover.isEmpty ? nil : leftover,
            mcpMethod: detectedMCPMethod
        ) {
            switch loop.severity {
            case .warn:
                // Log first warning only, suppress repeats (count changes each time)
                if loop.count == AgentLoopBreaker.shared.settings.rapidFireThreshold {
                    onEvent?(.log(.warn, "LOOP WARNING [\(loop.kind.rawValue)] \(host): \(loop.detail)"))
                }
            case .block:
                // Actually block — threshold far exceeded, definitely a loop
                onEvent?(.log(.error, "LOOP BLOCKED [\(loop.kind.rawValue)] \(host): \(loop.detail)"))
                sendErrorResponse(client: client, status: "429 Too Many Requests",
                                  body: "Proxymate Loop Breaker: \(loop.kind.rawValue)\n\n\(loop.detail)\n\nThis request was blocked because it matched a runaway loop pattern.\nThe block will auto-expire in \(AgentLoopBreaker.shared.settings.cooldownSeconds)s.\n")
                return
            }
        }

        // Beaconing detection
        let path = target.components(separatedBy: "?").first ?? target
        if let beacon = BeaconingDetector.shared.record(host: host, path: path) {
            onEvent?(.beaconing(host: host, path: beacon.path,
                                intervalSec: beacon.intervalSeconds, count: beacon.consecutiveCount))
            if beaconingSettings.action == .block {
                sendBlockedResponse(client: client, ruleName: "Beaconing: \(host)\(path) every \(Int(beacon.intervalSeconds))s")
                return
            }
        }

        // WebSocket upgrade detection (log only — frame inspection requires MITM)
        if method.uppercased() != "CONNECT" && WebSocketInspector.isUpgradeRequest(headerString) {
            onEvent?(.log(.info, "WebSocket upgrade: \(host)"))
        }

        // Privacy header stripping (only for plain HTTP, not CONNECT tunnels)
        var finalHeaderData = headerData
        if method.uppercased() != "CONNECT" {
            let (rewritten, actions) = Self.applyPrivacy(
                headerString: headerString,
                settings: privacySnapshot
            )
            if !actions.isEmpty {
                onEvent?(.privacyStripped(host: host, actions: actions))
                finalHeaderData = Data(rewritten.utf8)
            }
        }

        onEvent?(.allowed(host: host, method: method))

        // Host memory + fingerprint (skip CONNECT — tunnel setup has minimal headers by design)
        HostMemory.shared.recordRequest(host: host)
        if method.uppercased() != "CONNECT" {
            let fp = RequestFingerprint.compute(headerString)
            if let suspicion = RequestFingerprint.isSuspicious(fp) {
                onEvent?(.log(.warn, "Suspicious fingerprint \(host): \(suspicion) [fp:\(fp.hash)]"))
            }
        }

        // MITM interception for CONNECT tunnels (NIO-SSL)
        if method.uppercased() == "CONNECT" &&
           TLSManager.shared.shouldIntercept(host: host, settings: mitmSnapshot) &&
           NIOTLSProxy.shared.port > 0 {
            // First connect to NIO MITM proxy, THEN tell client "200 OK"
            let nioPort = NWEndpoint.Port(rawValue: UInt16(NIOTLSProxy.shared.port))!
            let nioConn = NWConnection(host: .ipv4(.loopback), port: nioPort, using: .tcp)
            nioConn.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    // NIO side ready — now tell client tunnel is established
                    let established = Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)
                    client.send(content: established, completion: .contentProcessed { _ in
                        // Bidirectional pipe: client ↔ NIO MITM proxy
                        self.pipe(from: client, to: nioConn)
                        self.pipe(from: nioConn, to: client)
                    })
                case .failed:
                    self.onEvent?(.log(.error, "MITM NIO connect failed for \(host)"))
                    client.cancel()
                default: break
                }
            }
            nioConn.start(queue: self.queue)
            return
        }

        // Cache check (plain HTTP GET only)
        if method.uppercased() == "GET" {
            let headerStr = String(data: finalHeaderData, encoding: .utf8) ?? headerString
            if let cached = CacheManager.shared.lookup(method: method, url: target, requestHeaders: headerStr) {
                onEvent?(.cacheHit(host: host, url: target))
                let response = "\(cached.statusLine)\r\n\(cached.responseHeaders)\r\n\r\n"
                var responseData = Data(response.utf8)
                responseData.append(cached.body)
                client.send(content: responseData, completion: .contentProcessed { _ in
                    client.cancel()
                })
                return
            }
            onEvent?(.cacheMiss(host: host, url: target))
        }

        // Resolve upstream: pool router first, then legacy single upstream
        let selected = PoolRouter.shared.select(forHost: host)
        let resolvedHost: String
        let resolvedPort: UInt16
        let memberId: UUID?
        if let sel = selected {
            resolvedHost = sel.host
            resolvedPort = sel.port
            memberId = sel.memberId
            PoolRouter.shared.connectionStarted(memberId: sel.memberId)
        } else if let up = upstream {
            resolvedHost = up.host
            resolvedPort = up.port
            memberId = nil
        } else {
            sendErrorResponse(client: client, status: "502 Bad Gateway", body: "No upstream configured.")
            return
        }
        let resolvedUpstream = Upstream(host: resolvedHost, port: resolvedPort)

        // Pass cache context for GET requests so the response gets stored
        // AI provider detection + budget blocking
        var aiProvider: AIProvider?
        if let detection = AITracker.shared.detect(host: host) {
            aiProvider = detection.provider
            onEvent?(.aiDetected(host: host, provider: detection.provider.name))
            let (blocked, reason) = AITracker.shared.isBlocked(providerId: detection.provider.id)
            if blocked {
                onEvent?(.aiBlocked(host: host, provider: detection.provider.name,
                                     reason: reason ?? "blocked"))
                sendBlockedResponse(client: client,
                                     ruleName: "AI Budget: \(reason ?? "blocked")")
                return
            }
            // Model allowlist/blocklist check (extract from request body in leftover)
            if let model = AITracker.shared.extractModelFromRequest(leftover) {
                let (modelBlocked, modelReason) = AITracker.shared.isModelBlocked(model)
                if modelBlocked {
                    onEvent?(.aiBlocked(host: host, provider: detection.provider.name,
                                         reason: modelReason ?? "model blocked"))
                    sendBlockedResponse(client: client,
                                         ruleName: "AI Model: \(modelReason ?? "blocked")")
                    return
                }
            }
        }

        let cacheCtx: CacheContext? = (method.uppercased() == "GET")
            ? CacheContext(method: method, url: target,
                           requestHeaders: String(data: finalHeaderData, encoding: .utf8) ?? headerString)
            : nil
        let aiCtx: AIContext? = aiProvider.map { AIContext(provider: $0) }
        forward(client: client, headerData: finalHeaderData, leftover: leftover,
                upstream: resolvedUpstream, cacheContext: cacheCtx, aiContext: aiCtx,
                memberId: memberId)
    }

    private struct CacheContext {
        let method: String
        let url: String
        let requestHeaders: String
    }

    private struct AIContext {
        let provider: AIProvider
    }

    // MARK: - Privacy header rewriting

    static func applyPrivacy(headerString: String, settings: PrivacySettings) -> (String, [String]) {
        var actions: [String] = []
        var lines = headerString.split(separator: "\r\n", omittingEmptySubsequences: false)
            .map(String.init)
        guard lines.count > 1 else { return (headerString, []) }

        // Track which headers we need to inject
        var hasDNT = false
        var hasGPC = false

        var i = 1  // skip request line
        while i < lines.count {
            let lower = lines[i].lowercased()

            // User-Agent
            if lower.hasPrefix("user-agent:") && settings.stripUserAgent {
                lines[i] = "User-Agent: \(settings.customUserAgent)"
                actions.append("UA")
            }

            // Referer
            if lower.hasPrefix("referer:") || lower.hasPrefix("referrer:") {
                if settings.stripReferer {
                    switch settings.refererPolicy {
                    case .strip:
                        lines.remove(at: i)
                        actions.append("Ref-strip")
                        continue
                    case .originOnly:
                        let val = lines[i].drop(while: { $0 != ":" }).dropFirst()
                            .trimmingCharacters(in: .whitespaces)
                        if let url = URL(string: val),
                           let scheme = url.scheme, let host = url.host {
                            let port = url.port.map { ":\($0)" } ?? ""
                            lines[i] = "Referer: \(scheme)://\(host)\(port)/"
                            actions.append("Ref-origin")
                        }
                    }
                }
            }

            // Cookie — strip tracking cookies
            if lower.hasPrefix("cookie:") && settings.stripTrackingCookies {
                let colonIdx = lines[i].firstIndex(of: ":") ?? lines[i].startIndex
                let rawValue = String(lines[i][lines[i].index(after: colonIdx)...])
                    .trimmingCharacters(in: .whitespaces)
                let cookies = rawValue.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
                let filtered = cookies.filter { cookie in
                    let name = String(cookie.prefix(while: { $0 != "=" })).lowercased()
                    return !PrivacySettings.trackingCookiePrefixes.contains(where: { name.hasPrefix($0) })
                }
                if filtered.count < cookies.count {
                    actions.append("Cookie(\(cookies.count - filtered.count))")
                    if filtered.isEmpty {
                        lines.remove(at: i)
                        continue
                    } else {
                        // Preserve original header name casing
                        let headerName = String(lines[i][..<colonIdx])
                        lines[i] = headerName + ": " + filtered.joined(separator: "; ")
                    }
                }
            }

            // ETag (If-None-Match in request — supercookie tracking)
            if (lower.hasPrefix("if-none-match:") || lower.hasPrefix("if-match:")) && settings.stripETag {
                lines.remove(at: i)
                actions.append("ETag")
                continue
            }

            // Detect existing DNT / GPC
            if lower.hasPrefix("dnt:") { hasDNT = true }
            if lower.hasPrefix("sec-gpc:") { hasGPC = true }

            i += 1
        }

        // Inject DNT and Sec-GPC before the header/body separator (\r\n\r\n).
        // Find the first empty line (the separator) — insert before it.
        let insertIdx: Int
        if let emptyIdx = lines.firstIndex(of: "") {
            insertIdx = emptyIdx
        } else {
            insertIdx = lines.count
        }
        if settings.forceDNT && !hasDNT {
            lines.insert("DNT: 1", at: insertIdx)
            actions.append("DNT")
        }
        if settings.forceGPC && !hasGPC {
            lines.insert("Sec-GPC: 1", at: insertIdx + (settings.forceDNT && !hasDNT ? 1 : 0))
            actions.append("GPC")
        }

        if actions.isEmpty {
            return (headerString, [])
        }
        return (lines.joined(separator: "\r\n"), actions)
    }

    // MARK: - Forwarding

    private func forward(client: NWConnection,
                         headerData: Data,
                         leftover: Data,
                         upstream: Upstream,
                         cacheContext: CacheContext? = nil,
                         aiContext: AIContext? = nil,
                         memberId: UUID? = nil) {
        guard let port = NWEndpoint.Port(rawValue: upstream.port) else {
            client.cancel()
            return
        }
        // Try connection pool first
        let pooled = ConnectionPool.shared.get(host: upstream.host, port: port.rawValue)
        let upstreamConn = pooled ?? NWConnection(
            host: NWEndpoint.Host(upstream.host),
            port: port,
            using: .tcp
        )
        upstreamConn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                upstreamConn.send(content: headerData, completion: .contentProcessed { [weak self] err in
                    if let err {
                        self?.onEvent?(.log(.error, "Upstream send failed: \(err.localizedDescription)"))
                        self?.sendErrorResponse(client: client, status: "502 Bad Gateway",
                                                body: "Upstream send failed: \(err.localizedDescription)\n")
                        upstreamConn.cancel()
                        return
                    }
                    let startPipes = { [weak self] in
                        self?.pipe(from: client, to: upstreamConn)
                        // Buffer response if we need to cache or extract AI tokens
                        if cacheContext != nil || aiContext != nil {
                            self?.pipeAndBuffer(from: upstreamConn, to: client,
                                                buffer: Data(),
                                                cacheContext: cacheContext,
                                                aiContext: aiContext)
                        } else {
                            self?.pipe(from: upstreamConn, to: client)
                        }
                    }
                    if leftover.isEmpty {
                        startPipes()
                    } else {
                        upstreamConn.send(content: leftover, completion: .contentProcessed { _ in
                            startPipes()
                        })
                    }
                })
            case .failed(let err):
                self?.onEvent?(.log(.error, "Upstream connect failed: \(err.localizedDescription)"))
                if let mid = memberId { PoolRouter.shared.connectionEnded(memberId: mid) }
                self?.sendErrorResponse(client: client, status: "502 Bad Gateway",
                                        body: "Upstream connection failed: \(err.localizedDescription)\n")
            case .cancelled:
                if let mid = memberId { PoolRouter.shared.connectionEnded(memberId: mid) }
                client.cancel()
            default:
                break
            }
        }
        if pooled != nil {
            // Already connected — trigger the handler directly
            upstreamConn.stateUpdateHandler?(.ready)
        } else {
            upstreamConn.start(queue: queue)
        }
    }

    private func pipe(from: NWConnection, to: NWConnection) {
        from.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                to.send(content: data, completion: .contentProcessed { [weak self] err in
                    if err != nil || isComplete {
                        from.cancel()
                        to.cancel()
                    } else {
                        self?.pipe(from: from, to: to)
                    }
                })
            } else if isComplete || error != nil {
                from.cancel()
                to.cancel()
            } else {
                // No data, not complete, no error — keep reading
                self.pipe(from: from, to: to)
            }
        }
    }

    /// Like `pipe` but accumulates the full response. On completion:
    /// 1. Stores in cache if cacheContext is provided
    /// 2. Extracts AI token usage if aiContext is provided
    /// Caps buffering at 2 MB; falls back to plain pipe if exceeded.
    private func pipeAndBuffer(from: NWConnection, to: NWConnection,
                               buffer: Data,
                               cacheContext: CacheContext?,
                               aiContext: AIContext?) {
        let maxBuffer = 2 * 1024 * 1024  // 2 MB
        from.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            var buf = buffer
            if let data, !data.isEmpty {
                buf.append(data)
                to.send(content: data, completion: .contentProcessed { [weak self] err in
                    guard let self else { return }
                    if err != nil || isComplete {
                        self.finishBuffer(from: from, to: to, buffer: buf,
                                          cacheContext: cacheContext, aiContext: aiContext)
                    } else if buf.count > maxBuffer {
                        self.pipe(from: from, to: to)
                    } else {
                        self.pipeAndBuffer(from: from, to: to, buffer: buf,
                                           cacheContext: cacheContext, aiContext: aiContext)
                    }
                })
            } else if isComplete {
                self.finishBuffer(from: from, to: to, buffer: buf,
                                  cacheContext: cacheContext, aiContext: aiContext)
            } else if error != nil {
                from.cancel(); to.cancel()
            } else {
                self.pipeAndBuffer(from: from, to: to, buffer: buf,
                                   cacheContext: cacheContext, aiContext: aiContext)
            }
        }
    }

    private func finishBuffer(from: NWConnection, to: NWConnection,
                               buffer: Data, cacheContext: CacheContext?,
                               aiContext: AIContext?) {
        // Return upstream to pool or cancel
        if let endpoint = from.currentPath?.remoteEndpoint,
           case .hostPort(let host, let port) = endpoint {
            ConnectionPool.shared.put(host: "\(host)", port: port.rawValue, connection: from)
        } else {
            from.cancel()
        }
        to.cancel()
        if let ctx = cacheContext {
            Self.storeInCache(responseData: buffer, context: ctx)
        }
        if let ai = aiContext {
            extractAIUsage(responseData: buffer, context: ai)
        }
    }

    /// Parses a buffered HTTP response into status line, headers, and body,
    /// then stores it in the cache.
    private static func storeInCache(responseData: Data, context: CacheContext) {
        guard let headerEnd = responseData.range(of: Data("\r\n\r\n".utf8)) else { return }
        let headerPart = responseData.subdata(in: 0..<headerEnd.lowerBound)
        let body = responseData.subdata(in: headerEnd.upperBound..<responseData.count)
        guard let headerStr = String(data: headerPart, encoding: .utf8) else { return }

        let lines = headerStr.split(separator: "\r\n", maxSplits: 1, omittingEmptySubsequences: false)
        guard let statusLine = lines.first else { return }
        let responseHeaders = lines.count > 1 ? String(lines[1]) : ""

        CacheManager.shared.store(
            method: context.method,
            url: context.url,
            requestHeaders: context.requestHeaders,
            statusLine: String(statusLine),
            responseHeaders: responseHeaders,
            body: body
        )
    }

    private func extractAIUsage(responseData: Data, context: AIContext) {
        // Skip response headers, get body only
        guard let headerEnd = responseData.range(of: Data("\r\n\r\n".utf8)) else { return }
        let body = responseData.subdata(in: headerEnd.upperBound..<responseData.count)
        guard let usage = AITracker.shared.extractUsage(provider: context.provider,
                                                         responseBody: body) else { return }
        onEvent?(.aiUsage(provider: usage.providerId, model: usage.model,
                          promptTokens: usage.promptTokens,
                          completionTokens: usage.completionTokens,
                          cost: usage.estimatedCost))
    }

    private func sendBlockedResponse(client: NWConnection, ruleName: String) {
        let body = "Blocked by Proxymate: \(ruleName)\n"
        let headers = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n"
        var data = Data(headers.utf8)
        data.append(Data(body.utf8))
        client.send(content: data, completion: .contentProcessed { _ in
            client.cancel()
        })
    }

    /// Stealth mock: return fake 200 OK so the tracker thinks it succeeded.
    private func sendMockResponse(client: NWConnection, host: String) {
        // Return realistic responses based on common tracker patterns
        let contentType: String
        let body: Data
        if host.contains("analytics") || host.contains("collect") || host.contains("pixel") {
            // Tracking pixel — return 1x1 transparent GIF
            contentType = "image/gif"
            body = Data([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
                         0x01, 0x00, 0x80, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
                         0x00, 0x00, 0x00, 0x21, 0xF9, 0x04, 0x01, 0x00,
                         0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00,
                         0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
                         0x01, 0x00, 0x3B]) // 1x1 transparent GIF
        } else if host.contains("tag") || host.contains("gtm") || host.contains("js") {
            // Script tag — return empty JS
            contentType = "application/javascript"
            body = Data("/* */".utf8)
        } else {
            // Generic — return empty JSON
            contentType = "application/json"
            body = Data("{}".utf8)
        }
        let response = "HTTP/1.1 200 OK\r\nContent-Type: \(contentType)\r\nContent-Length: \(body.count)\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n"
        var full = Data(response.utf8)
        full.append(body)
        client.send(content: full, completion: .contentProcessed { _ in
            client.cancel()
        })
    }

    private func sendErrorResponse(client: NWConnection, status: String, body: String) {
        let headers = "HTTP/1.1 \(status)\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n"
        var data = Data(headers.utf8)
        data.append(Data(body.utf8))
        client.send(content: data, completion: .contentProcessed { _ in
            client.cancel()
        })
    }

    // MARK: - Parsing helpers

    static func extractHost(method: String, target: String, headers: String) -> String {
        var host: String
        if method.uppercased() == "CONNECT" {
            host = IPv6Support.parseHostPort(target).host
        } else if let url = URL(string: target), let h = url.host {
            host = h
        } else {
            host = ""
            for line in headers.split(separator: "\r\n", omittingEmptySubsequences: false) {
                if line.lowercased().hasPrefix("host:") {
                    let value = line.dropFirst("host:".count).trimmingCharacters(in: .whitespaces)
                    host = IPv6Support.parseHostPort(value).host
                    break
                }
            }
        }
        // Strip trailing dot (valid DNS, but breaks rule matching and cache keys)
        if host.hasSuffix(".") { host = String(host.dropLast()) }
        return host
    }

    static func matchesDomain(host: String, pattern: String) -> Bool {
        let h = host.lowercased()
        let p = pattern.lowercased()
        return h == p || h.hasSuffix("." + p)
    }

    static func matches(rule: WAFRule, host: String, target: String, headers: String) -> Bool {
        let pat = rule.pattern.lowercased()
        guard !pat.isEmpty else { return false }
        let h  = host.lowercased()
        let t  = target.lowercased()
        let hd = headers.lowercased()
        switch rule.kind {
        case .allowDomain:
            return false  // allow rules are checked separately, not in the block path
        case .blockIP:
            return h == pat
        case .blockDomain:
            return h == pat || h.hasSuffix("." + pat)
        case .blockContent:
            return t.contains(pat) || hd.contains(pat)
        case .blockRegex:
            guard let regex = try? NSRegularExpression(pattern: rule.pattern, options: []) else { return false }
            let combined = t + "\n" + hd
            return regex.firstMatch(in: combined, range: NSRange(combined.startIndex..., in: combined)) != nil
        case .mockDomain:
            return false  // mock handled separately via checkMock, not in block path
        }
    }
}
