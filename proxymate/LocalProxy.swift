//
//  LocalProxy.swift
//  proxymate
//
//  In-process HTTP/HTTPS forward proxy. Bound to 127.0.0.1 on a random port.
//  When the user enables Proxymate, the OS proxy is set to point at this
//  listener; we apply the WAF, then forward the raw request to the upstream
//  proxy chosen by the user. HTTPS comes through as `CONNECT host:port`,
//  which we WAF-check on the host (we cannot inspect the encrypted body) and
//  then tunnel transparently.
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
    private var upstream: Upstream?
    private var startCompletion: (@Sendable (Result<UInt16, Error>) -> Void)?

    var onEvent: (@Sendable (Event) -> Void)?

    // MARK: - Lifecycle

    func start(upstream: Upstream,
               rules: [WAFRule],
               completion: @escaping @Sendable (Result<UInt16, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.listener != nil {
                completion(.failure(LocalProxyError.alreadyRunning))
                return
            }
            self.upstream = upstream
            self.rulesSnapshot = rules
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
        queue.async { [weak self] in
            self?.rulesSnapshot = rules
        }
    }

    func updateUpstream(_ upstream: Upstream) {
        queue.async { [weak self] in
            self?.upstream = upstream
        }
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

    /// Read from `connection` until we hit `\r\n\r\n` or 16KB. Anything past
    /// the header terminator is returned in `leftover` so we can forward it
    /// on to the upstream as part of the request body / first packet.
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

        // WAF
        if let blocking = rulesSnapshot.first(where: {
            $0.enabled && Self.matches(rule: $0, host: host, target: target, headers: headerString)
        }) {
            let label = blocking.name.isEmpty ? blocking.pattern : blocking.name
            onEvent?(.blocked(host: host, ruleName: label))
            sendBlockedResponse(client: client, ruleName: label)
            return
        }

        onEvent?(.allowed(host: host, method: method))

        guard let up = upstream else {
            sendErrorResponse(client: client, status: "502 Bad Gateway", body: "No upstream configured.")
            return
        }
        forward(client: client, headerData: headerData, leftover: leftover, upstream: up)
    }

    private func forward(client: NWConnection,
                         headerData: Data,
                         leftover: Data,
                         upstream: Upstream) {
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
                        self?.pipe(from: upstreamConn, to: client)
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
                client.cancel()
            case .cancelled:
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
            // target = "host:port"
            return String(target.split(separator: ":").first ?? "")
        }
        if let url = URL(string: target), let h = url.host {
            return h
        }
        // Fallback: Host: header
        for line in headers.split(separator: "\r\n", omittingEmptySubsequences: false) {
            if line.lowercased().hasPrefix("host:") {
                let value = line.dropFirst("host:".count).trimmingCharacters(in: .whitespaces)
                return String(value.split(separator: ":").first ?? "")
            }
        }
        return ""
    }

    static func matches(rule: WAFRule, host: String, target: String, headers: String) -> Bool {
        let pat = rule.pattern.lowercased()
        guard !pat.isEmpty else { return false }
        let h  = host.lowercased()
        let t  = target.lowercased()
        let hd = headers.lowercased()
        switch rule.kind {
        case .blockIP:
            return h == pat
        case .blockDomain:
            return h == pat || h.hasSuffix("." + pat)
        case .blockContent:
            return t.contains(pat) || hd.contains(pat)
        }
    }
}
