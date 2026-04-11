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
    private var privacySnapshot = PrivacySettings()
    private var blacklistSourcesSnapshot: [BlacklistSource] = []
    private var mitmSnapshot = MITMSettings()
    private var upstream: Upstream?
    private var startCompletion: (@Sendable (Result<UInt16, Error>) -> Void)?

    var onEvent: (@Sendable (Event) -> Void)?

    // MARK: - Lifecycle

    func start(upstream: Upstream,
               rules: [WAFRule],
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
            self.onEvent?(.stopped)
        }
    }

    func updateRules(_ rules: [WAFRule]) {
        queue.async { [weak self] in self?.rulesSnapshot = rules }
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
            if isComplete || acc.count >= 16_384 {
                completion(.failure(NSError(
                    domain: "Proxymate.LocalProxy", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Headers truncated or too large"])))
                return
            }
            self?.readHeaders(connection: connection, accumulator: acc, completion: completion)
        }
    }

    private func routeRequest(client: NWConnection, headerData: Data, leftover: Data) {
        guard let headerString = String(data: headerData, encoding: .utf8) else {
            client.cancel()
            return
        }
        let firstLineEnd = headerString.range(of: "\r\n")?.lowerBound ?? headerString.endIndex
        let firstLine = String(headerString[headerString.startIndex..<firstLineEnd])
        let parts = firstLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2 else {
            client.cancel()
            return
        }
        let method = String(parts[0])
        let target = String(parts[1])
        let host = Self.extractHost(method: method, target: target, headers: headerString)

        // Allow check (higher priority — skip WAF + blacklist if matched)
        let isAllowed = rulesSnapshot.contains(where: {
            $0.enabled && $0.kind == .allowDomain && Self.matchesDomain(host: host, pattern: $0.pattern)
        })

        // WAF check
        if !isAllowed, let blocking = rulesSnapshot.first(where: {
            $0.enabled && Self.matches(rule: $0, host: host, target: target, headers: headerString)
        }) {
            let label = blocking.name.isEmpty ? blocking.pattern : blocking.name
            onEvent?(.blocked(host: host, ruleName: label))
            sendBlockedResponse(client: client, ruleName: label)
            return
        }

        // Blacklist check (skipped if explicitly allowed)
        if !isAllowed, let hit = BlacklistManager.shared.lookup(host: host, enabledSources: blacklistSourcesSnapshot) {
            onEvent?(.blacklisted(host: host, sourceName: hit.sourceName, category: hit.category.rawValue))
            sendBlockedResponse(client: client, ruleName: "\(hit.sourceName) [\(hit.category.rawValue)]")
            return
        }

        // Exfiltration scan (headers + URL only, not body)
        if let hit = ExfiltrationScanner.shared.scan(headers: headerString, target: target) {
            onEvent?(.exfiltration(host: host, patternName: hit.patternName,
                                   severity: hit.severity.rawValue, preview: hit.matchPreview))
            sendBlockedResponse(client: client, ruleName: "Exfiltration: \(hit.patternName)")
            return
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

        // Cache check (plain HTTP GET only)
        if method.uppercased() == "GET" && method.uppercased() != "CONNECT" {
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
        }

        let cacheCtx: CacheContext? = (method.uppercased() == "GET" && method.uppercased() != "CONNECT")
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
                let prefix = "Cookie: "
                let rawValue = String(lines[i].dropFirst(prefix.count))
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
                        lines[i] = prefix + filtered.joined(separator: "; ")
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

        // Inject DNT and Sec-GPC before the final empty line
        let insertIdx = max(lines.count - 1, 1)
        if settings.forceDNT && !hasDNT {
            lines.insert("DNT: 1", at: insertIdx)
            actions.append("DNT")
        }
        if settings.forceGPC && !hasGPC {
            lines.insert("Sec-GPC: 1", at: insertIdx)
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
        let upstreamConn = NWConnection(
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
                        client.cancel()
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
                client.cancel()
            case .cancelled:
                if let mid = memberId { PoolRouter.shared.connectionEnded(memberId: mid) }
                client.cancel()
            default:
                break
            }
        }
        upstreamConn.start(queue: queue)
    }

    private func pipe(from: NWConnection, to: NWConnection) {
        from.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            if let data, !data.isEmpty {
                to.send(content: data, completion: .contentProcessed { [weak self] err in
                    if err != nil {
                        from.cancel()
                        to.cancel()
                        return
                    }
                    self?.pipe(from: from, to: to)
                })
            }
            if isComplete {
                to.send(content: nil, isComplete: true, completion: .contentProcessed { _ in })
                from.cancel()
                return
            }
            if error != nil {
                from.cancel()
                to.cancel()
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
            var buf = buffer
            if let data, !data.isEmpty {
                buf.append(data)
                to.send(content: data, completion: .contentProcessed { [weak self] err in
                    if err != nil {
                        from.cancel(); to.cancel(); return
                    }
                    if buf.count > maxBuffer {
                        self?.pipe(from: from, to: to)
                    } else {
                        self?.pipeAndBuffer(from: from, to: to, buffer: buf,
                                            cacheContext: cacheContext, aiContext: aiContext)
                    }
                })
            }
            if isComplete {
                to.send(content: nil, isComplete: true, completion: .contentProcessed { _ in })
                from.cancel()
                // Cache store
                if let ctx = cacheContext {
                    Self.storeInCache(responseData: buf, context: ctx)
                }
                // AI token extraction
                if let ai = aiContext {
                    self?.extractAIUsage(responseData: buf, context: ai)
                }
                return
            }
            if error != nil {
                from.cancel(); to.cancel()
            }
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
        let response = """
        HTTP/1.1 403 Forbidden\r
        Content-Type: text/plain; charset=utf-8\r
        Content-Length: \(body.utf8.count)\r
        Connection: close\r
        \r
        \(body)
        """
        client.send(content: response.data(using: .utf8), completion: .contentProcessed { _ in
            client.cancel()
        })
    }

    private func sendErrorResponse(client: NWConnection, status: String, body: String) {
        let response = """
        HTTP/1.1 \(status)\r
        Content-Type: text/plain; charset=utf-8\r
        Content-Length: \(body.utf8.count)\r
        Connection: close\r
        \r
        \(body)
        """
        client.send(content: response.data(using: .utf8), completion: .contentProcessed { _ in
            client.cancel()
        })
    }

    // MARK: - Parsing helpers

    static func extractHost(method: String, target: String, headers: String) -> String {
        if method.uppercased() == "CONNECT" {
            return String(target.split(separator: ":").first ?? "")
        }
        if let url = URL(string: target), let h = url.host {
            return h
        }
        for line in headers.split(separator: "\r\n", omittingEmptySubsequences: false) {
            if line.lowercased().hasPrefix("host:") {
                let value = line.dropFirst("host:".count).trimmingCharacters(in: .whitespaces)
                return String(value.split(separator: ":").first ?? "")
            }
        }
        return ""
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
        }
    }
}
