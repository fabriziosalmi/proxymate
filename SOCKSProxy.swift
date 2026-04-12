//
//  SOCKSProxy.swift
//  proxymate
//
//  RFC 1928 SOCKS5 proxy server. Runs alongside the HTTP proxy on a separate port.
//  Supports CONNECT command only (no BIND or UDP ASSOCIATE).
//
//  Authentication: None (0x00) — local loopback only, no auth required.
//  Address types: IPv4 (0x01), Domain (0x03), IPv6 (0x04).
//

import Foundation
import Network

nonisolated final class SOCKSProxy: @unchecked Sendable {
    
    // MARK: - Public types
    
    enum Event: Sendable {
        case started(port: UInt16)
        case stopped
        case allowed(host: String, port: UInt16)
        case blocked(host: String, ruleName: String)
        case log(LogEntry.Level, String)
    }
    
    enum SOCKSError: LocalizedError {
        case alreadyRunning
        case listenerFailed(String)
        var errorDescription: String? {
            switch self {
            case .alreadyRunning: return "SOCKS proxy is already running"
            case .listenerFailed(let m): return m
            }
        }
    }
    
    // MARK: - State
    
    private let queue = DispatchQueue(label: "proxymate.socks", qos: .userInitiated)
    private var listener: NWListener?
    private var rulesSnapshot: [WAFRule] = []
    private var allowlistSnapshot: [AllowEntry] = []
    private var blacklistSourcesSnapshot: [BlacklistSource] = []
    
    var onEvent: (@Sendable (Event) -> Void)?
    
    // MARK: - Lifecycle
    
    func start(rules: [WAFRule],
               allowlist: [AllowEntry] = [],
               blacklistSources: [BlacklistSource],
               completion: @escaping @Sendable (Result<UInt16, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.listener != nil {
                completion(.failure(SOCKSError.alreadyRunning))
                return
            }
            
            self.rulesSnapshot = rules
            self.allowlistSnapshot = allowlist
            self.blacklistSourcesSnapshot = blacklistSources
            
            do {
                let params = NWParameters.tcp
                params.allowLocalEndpointReuse = true
                let listener = try NWListener(using: params)
                
                listener.newConnectionHandler = { [weak self] newConn in
                    self?.handleNewConnection(newConn)
                }
                
                listener.stateUpdateHandler = { [weak self] state in
                    guard let self else { return }
                    switch state {
                    case .ready:
                        if let port = listener.port?.rawValue {
                            self.onEvent?(.started(port: port))
                            completion(.success(port))
                        }
                    case .failed(let error):
                        self.onEvent?(.log(.error, "SOCKS listener failed: \(error.localizedDescription)"))
                        completion(.failure(SOCKSError.listenerFailed(error.localizedDescription)))
                        self.listener = nil
                    default:
                        break
                    }
                }
                
                listener.start(queue: self.queue)
                self.listener = listener
            } catch {
                completion(.failure(error))
            }
        }
    }
    
    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.listener?.cancel()
            self.listener = nil
            self.onEvent?(.stopped)
        }
    }
    
    // MARK: - Connection Handling
    
    private func handleNewConnection(_ conn: NWConnection) {
        conn.start(queue: queue)
        
        // Read SOCKS5 handshake (version + nmethods + methods)
        conn.receive(minimumIncompleteLength: 2, maximumLength: 257) { [weak self] data, _, _, _ in
            guard let self, let data, data.count >= 2 else {
                conn.cancel()
                return
            }
            
            let version = data[0]
            guard version == 0x05 else {
                self.onEvent?(.log(.warn, "SOCKS: unsupported version \(version)"))
                conn.cancel()
                return
            }
            
            let nmethods = Int(data[1])
            guard data.count >= 2 + nmethods else {
                conn.cancel()
                return
            }
            
            // We only support NO AUTHENTICATION (0x00)
            let methods = data[2..<(2 + nmethods)]
            guard methods.contains(0x00) else {
                // No acceptable methods — send 0xFF
                conn.send(content: Data([0x05, 0xFF]), completion: .contentProcessed { _ in })
                conn.cancel()
                return
            }
            
            // Accept NO AUTH
            conn.send(content: Data([0x05, 0x00]), completion: .contentProcessed { _ in
                self.readRequest(conn)
            })
        }
    }
    
    // MARK: - SOCKS5 Request Parsing (RFC 1928)
    
    private func readRequest(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 4, maximumLength: 262) { [weak self] data, _, _, _ in
            guard let self, let data, data.count >= 4 else {
                conn.cancel()
                return
            }
            
            let version = data[0]
            let cmd = data[1]
            let reserved = data[2]
            let addrType = data[3]
            
            guard version == 0x05 else {
                self.sendReply(conn: conn, status: 0x01) // General failure
                return
            }
            
            guard reserved == 0x00 else {
                self.sendReply(conn: conn, status: 0x01)
                return
            }
            
            // We only support CONNECT (0x01)
            guard cmd == 0x01 else {
                self.sendReply(conn: conn, status: 0x07) // Command not supported
                return
            }
            
            // Parse destination address
            var offset = 4
            let destHost: String
            
            switch addrType {
            case 0x01: // IPv4 (4 bytes)
                guard data.count >= offset + 4 + 2 else {
                    self.sendReply(conn: conn, status: 0x01)
                    return
                }
                let ipv4 = data[offset..<(offset + 4)]
                destHost = ipv4.map { String($0) }.joined(separator: ".")
                offset += 4
                
            case 0x03: // Domain name (1 byte length + variable)
                guard data.count >= offset + 1 else {
                    self.sendReply(conn: conn, status: 0x01)
                    return
                }
                let domainLen = Int(data[offset])
                offset += 1
                guard data.count >= offset + domainLen + 2 else {
                    self.sendReply(conn: conn, status: 0x01)
                    return
                }
                let domainBytes = data[offset..<(offset + domainLen)]
                destHost = String(decoding: domainBytes, as: UTF8.self)
                offset += domainLen
                
            case 0x04: // IPv6 (16 bytes)
                guard data.count >= offset + 16 + 2 else {
                    self.sendReply(conn: conn, status: 0x01)
                    return
                }
                let ipv6Bytes = data[offset..<(offset + 16)]
                // Format as standard IPv6 string
                var groups: [String] = []
                for i in stride(from: 0, to: 16, by: 2) {
                    let word = UInt16(ipv6Bytes[ipv6Bytes.startIndex + i]) << 8 | UInt16(ipv6Bytes[ipv6Bytes.startIndex + i + 1])
                    groups.append(String(format: "%x", word))
                }
                destHost = groups.joined(separator: ":")
                offset += 16
                
            default:
                self.sendReply(conn: conn, status: 0x08) // Address type not supported
                return
            }
            
            // Parse port (2 bytes, big-endian)
            guard data.count >= offset + 2 else {
                self.sendReply(conn: conn, status: 0x01)
                return
            }
            let portHigh = UInt16(data[offset])
            let portLow = UInt16(data[offset + 1])
            let destPort = (portHigh << 8) | portLow
            
            // Apply WAF rules and blacklists
            if let blockReason = self.shouldBlock(host: destHost, port: destPort) {
                self.onEvent?(.blocked(host: destHost, ruleName: blockReason))
                self.sendReply(conn: conn, status: 0x02) // Connection not allowed
                return
            }
            
            // Establish connection to destination
            self.onEvent?(.allowed(host: destHost, port: destPort))
            self.connectToDestination(clientConn: conn, destHost: destHost, destPort: destPort)
        }
    }
    
    // MARK: - WAF & Blacklist Checks
    
    private func shouldBlock(host: String, port: UInt16) -> String? {
        let h = host.lowercased()
        
        // Check allowlist first
        for entry in allowlistSnapshot where entry.enabled {
            if matchesAllowEntry(host: h, port: port, entry: entry) {
                return nil // Explicitly allowed
            }
        }
        
        // Check WAF rules
        for rule in rulesSnapshot where rule.enabled {
            switch rule.kind {
            case .blockDomain:
                if matchesDomain(host: h, pattern: rule.pattern.lowercased()) {
                    return rule.name.isEmpty ? "Domain: \(rule.pattern)" : rule.name
                }
            case .blockIP:
                if h == rule.pattern.lowercased() {
                    return rule.name.isEmpty ? "IP: \(rule.pattern)" : rule.name
                }
            default:
                continue
            }
        }
        
        // Check blacklists
        if let hit = BlacklistManager.shared.lookup(host: h, enabledSources: blacklistSourcesSnapshot) {
            return "Blacklist: \(hit.sourceName)"
        }
        
        return nil
    }
    
    private func matchesDomain(host: String, pattern: String) -> Bool {
        if host == pattern { return true }
        if pattern.hasPrefix("*.") {
            let suffix = String(pattern.dropFirst(2))
            return host == suffix || host.hasSuffix("." + suffix)
        }
        return false
    }
    
    private func matchesAllowEntry(host: String, port: UInt16, entry: AllowEntry) -> Bool {
        let h = host.lowercased()
        let p = entry.pattern.lowercased()
        
        // Check pattern match
        let patternMatches = (h == p) || (p.hasPrefix("*.") && (h == String(p.dropFirst(2)) || h.hasSuffix("." + String(p.dropFirst(2)))))
        guard patternMatches else { return false }
        
        // Check port scope
        if let allowedPort = entry.port {
            return allowedPort == Int(port)
        }
        
        return true
    }
    
    // MARK: - Destination Connection & Relay
    
    private func connectToDestination(clientConn: NWConnection, destHost: String, destPort: UInt16) {
        guard let nwPort = NWEndpoint.Port(rawValue: destPort) else {
            sendReply(conn: clientConn, status: 0x01)
            return
        }
        
        let destConn = NWConnection(
            host: NWEndpoint.Host(destHost),
            port: nwPort,
            using: .tcp
        )
        
        destConn.stateUpdateHandler = { [weak self] state in
            guard let self else { destConn.cancel(); return }
            switch state {
            case .ready:
                // Send success reply to client
                self.sendReply(conn: clientConn, status: 0x00) // Success
                
                // Start bidirectional relay
                self.relay(client: clientConn, server: destConn)
                
            case .failed(let error):
                self.onEvent?(.log(.error, "SOCKS: failed to connect to \(destHost):\(destPort) — \(error.localizedDescription)"))
                
                // Map NWError to SOCKS5 reply code
                let replyCode: UInt8
                if error.localizedDescription.contains("refused") {
                    replyCode = 0x05 // Connection refused
                } else if error.localizedDescription.contains("unreachable") {
                    replyCode = 0x04 // Host unreachable
                } else if error.localizedDescription.contains("network") {
                    replyCode = 0x03 // Network unreachable
                } else {
                    replyCode = 0x01 // General failure
                }
                
                self.sendReply(conn: clientConn, status: replyCode)
                
            case .cancelled:
                clientConn.cancel()
                
            default:
                break
            }
        }
        
        destConn.start(queue: queue)
    }
    
    /// Send SOCKS5 reply (version, status, reserved, addrType, bindAddr, bindPort)
    private func sendReply(conn: NWConnection, status: UInt8) {
        // RFC 1928: reply with bind address 0.0.0.0:0
        var reply = Data([
            0x05,        // Version
            status,      // Reply code
            0x00,        // Reserved
            0x01         // IPv4
        ])
        reply.append(contentsOf: [0, 0, 0, 0])  // 0.0.0.0
        reply.append(contentsOf: [0, 0])        // Port 0
        
        conn.send(content: reply, completion: .contentProcessed { _ in
            if status != 0x00 {
                conn.cancel()
            }
        })
    }
    
    // MARK: - Bidirectional Relay
    
    private func relay(client: NWConnection, server: NWConnection) {
        // Client → Server
        pipeData(from: client, to: server)
        
        // Server → Client
        pipeData(from: server, to: client)
    }
    
    private func pipeData(from source: NWConnection, to destination: NWConnection) {
        source.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else {
                source.cancel()
                destination.cancel()
                return
            }
            
            if let data, !data.isEmpty {
                destination.send(content: data, completion: .contentProcessed { sendError in
                    if sendError != nil {
                        source.cancel()
                        destination.cancel()
                    }
                })
            }
            
            if isComplete || error != nil {
                destination.send(content: nil, isComplete: true, completion: .contentProcessed { _ in })
                source.cancel()
                destination.cancel()
                return
            }
            
            // Continue reading
            self.pipeData(from: source, to: destination)
        }
    }
}
