//
//  SOCKS5Listener.swift
//  proxymate
//
//  SOCKS5 proxy listener (RFC 1928). Runs alongside the HTTP proxy on a
//  separate port. Supports CONNECT command (TCP relay), no auth.
//  Shares the same WAF/blacklist/allowlist/privacy/AI pipeline via
//  LocalProxy events.
//

import Foundation
import Network

nonisolated struct SOCKS5Settings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var port: Int = 1080
}

nonisolated final class SOCKS5Listener: @unchecked Sendable {

    private let queue = DispatchQueue(label: "proxymate.socks5", qos: .userInitiated)
    private var listener: NWListener?
    private var rulesSnapshot: [WAFRule] = []
    private var allowlistSnapshot: [AllowEntry] = []
    private var blacklistSourcesSnapshot: [BlacklistSource] = []

    var onEvent: (@Sendable (LocalProxy.Event) -> Void)?

    func start(port: UInt16,
               rules: [WAFRule],
               allowlist: [AllowEntry],
               blacklistSources: [BlacklistSource]) {
        queue.async { [weak self] in
            guard let self else { return }
            self.stop()
            self.rulesSnapshot = rules
            self.allowlistSnapshot = allowlist
            self.blacklistSourcesSnapshot = blacklistSources

            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback),
                                                      port: NWEndpoint.Port(rawValue: port)!)
            guard let l = try? NWListener(using: params) else { return }
            l.newConnectionHandler = { [weak self] conn in
                self?.handleClient(conn)
            }
            l.stateUpdateHandler = { [weak self] state in
                if case .ready = state, let p = l.port?.rawValue {
                    self?.onEvent?(.log(.info, "SOCKS5 listening on 127.0.0.1:\(p)"))
                }
            }
            self.listener = l
            l.start(queue: self.queue)
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    func updateRules(_ r: [WAFRule]) { queue.async { [weak self] in self?.rulesSnapshot = r } }
    func updateAllowlist(_ a: [AllowEntry]) { queue.async { [weak self] in self?.allowlistSnapshot = a } }
    func updateBlacklists(_ b: [BlacklistSource]) { queue.async { [weak self] in self?.blacklistSourcesSnapshot = b } }

    // MARK: - SOCKS5 handshake (RFC 1928)

    private func handleClient(_ client: NWConnection) {
        client.start(queue: queue)
        // Read greeting: VER | NMETHODS | METHODS
        client.receive(minimumIncompleteLength: 3, maximumLength: 257) { [weak self] data, _, _, error in
            guard let self, let data, data.count >= 3, error == nil else {
                client.cancel(); return
            }
            let ver = data[0]
            guard ver == 0x05 else { client.cancel(); return } // Must be SOCKS5

            // Reply: no auth required (VER=5, METHOD=0)
            let reply = Data([0x05, 0x00])
            client.send(content: reply, completion: .contentProcessed { [weak self] _ in
                self?.readRequest(client)
            })
        }
    }

    private func readRequest(_ client: NWConnection) {
        // Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
        client.receive(minimumIncompleteLength: 4, maximumLength: 512) { [weak self] data, _, _, error in
            guard let self, let data, data.count >= 4, error == nil else {
                client.cancel(); return
            }
            guard data[0] == 0x05, data[1] == 0x01 else {
                // Only support CONNECT (0x01)
                self.sendReply(client, rep: 0x07) // command not supported
                return
            }

            guard data.count >= 5 else { client.cancel(); return }
            let atyp = data[3] // skip RSV at index 2
            var host = ""
            var portOffset = 0

            switch atyp {
            case 0x01: // IPv4: 4 bytes addr + 2 bytes port
                guard data.count >= 10 else { client.cancel(); return }
                host = (4...7).map { "\(data[$0])" }.joined(separator: ".")
                portOffset = 8
            case 0x03: // Domain: 1 byte len + N bytes + 2 bytes port
                let len = Int(data[4])
                guard len > 0, data.count >= 5 + len + 2 else { client.cancel(); return }
                host = String(data: data[5..<(5+len)], encoding: .utf8) ?? ""
                portOffset = 5 + len
            case 0x04: // IPv6: 16 bytes addr + 2 bytes port
                guard data.count >= 22 else { client.cancel(); return }
                host = stride(from: 4, to: 20, by: 2).map {
                    String(format: "%02x%02x", data[$0], data[$0+1])
                }.joined(separator: ":")
                portOffset = 20
            default:
                self.sendReply(client, rep: 0x08) // address type not supported
                return
            }

            let port = UInt16(data[portOffset]) << 8 | UInt16(data[portOffset + 1])

            self.connectAndRelay(client: client, host: host, port: port)
        }
    }

    private func connectAndRelay(client: NWConnection, host: String, port: UInt16) {
        // WAF / allowlist / blacklist checks
        let isAllowed = AllowlistMatcher.isAllowed(host: host, port: Int(port), entries: allowlistSnapshot)

        if !isAllowed {
            if let hit = rulesSnapshot.first(where: {
                $0.enabled && LocalProxy.matches(rule: $0, host: host, target: host, headers: "")
            }) {
                let label = hit.name.isEmpty ? hit.pattern : hit.name
                onEvent?(.blocked(host: host, ruleName: "SOCKS5: \(label)"))
                sendReply(client, rep: 0x02) // connection not allowed
                return
            }
            if let hit = BlacklistManager.shared.lookup(host: host, enabledSources: blacklistSourcesSnapshot) {
                onEvent?(.blacklisted(host: host, sourceName: "SOCKS5: \(hit.sourceName)",
                                       category: hit.category.rawValue))
                sendReply(client, rep: 0x02)
                return
            }
        }

        onEvent?(.allowed(host: host, method: "SOCKS5"))

        // Connect to target
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            sendReply(client, rep: 0x01); return
        }
        let target = NWConnection(host: .init(host), port: nwPort, using: .tcp)
        target.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                // Success reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
                let reply = Data([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                client.send(content: reply, completion: .contentProcessed { [weak self] _ in
                    self?.pipe(from: client, to: target)
                    self?.pipe(from: target, to: client)
                })
            case .failed:
                self?.sendReply(client, rep: 0x05) // connection refused
                target.cancel()
            default: break
            }
        }
        target.start(queue: queue)
    }

    private func sendReply(_ client: NWConnection, rep: UInt8) {
        let reply = Data([0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        client.send(content: reply, completion: .contentProcessed { _ in
            client.cancel()
        })
    }

    private func pipe(from: NWConnection, to: NWConnection) {
        from.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            if let data, !data.isEmpty {
                to.send(content: data, completion: .contentProcessed { [weak self] err in
                    if err != nil { from.cancel(); to.cancel(); return }
                    self?.pipe(from: from, to: to)
                })
            }
            if isComplete { to.send(content: nil, isComplete: true, completion: .contentProcessed { _ in }); from.cancel(); return }
            if error != nil { from.cancel(); to.cancel() }
        }
    }
}
