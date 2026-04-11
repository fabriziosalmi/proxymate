//
//  Allowlist.swift
//  proxymate
//
//  IP/domain allowlist with CIDR range support, optional port and protocol
//  scoping. Allow entries have the highest priority — they override all
//  block rules, blacklists, and exfiltration scans.
//

import Foundation

nonisolated struct AllowEntry: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var pattern: String        // IP, CIDR (10.0.0.0/8), or domain
    var port: Int?             // nil = any port
    var proto: Proto?          // nil = any protocol
    var note: String = ""
    var enabled: Bool = true

    enum Proto: String, Codable, CaseIterable, Identifiable, Sendable {
        case http  = "HTTP"
        case https = "HTTPS"
        case any   = "Any"
        var id: String { rawValue }
    }
}

nonisolated enum AllowlistMatcher {

    /// Check if a host:port is allowed by any entry in the allowlist.
    static func isAllowed(host: String, port: Int?, entries: [AllowEntry]) -> Bool {
        let h = host.lowercased()
        for entry in entries where entry.enabled {
            if matchesPattern(host: h, port: port, entry: entry) {
                return true
            }
        }
        return false
    }

    private static func matchesPattern(host: String, port: Int?, entry: AllowEntry) -> Bool {
        // Port check
        if let ep = entry.port, let rp = port, ep != rp { return false }

        let pattern = entry.pattern.lowercased().trimmingCharacters(in: .whitespaces)

        // CIDR check (IPv4 and IPv6)
        if pattern.contains("/") {
            if pattern.contains(":") {
                return IPv6Support.matchesCIDR6(ip: host, cidr: pattern)
            }
            return matchesCIDR(ip: host, cidr: pattern)
        }

        // Exact IP match
        if isIPv4(pattern) {
            return host == pattern
        }

        // Domain match (exact or suffix)
        if pattern.hasPrefix("*.") {
            let suffix = String(pattern.dropFirst(2))
            return host == suffix || host.hasSuffix("." + suffix)
        }
        return host == pattern || host.hasSuffix("." + pattern)
    }

    // MARK: - CIDR matching

    static func matchesCIDR(ip: String, cidr: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefix = Int(parts[1]),
              prefix >= 0 && prefix <= 32 else { return false }

        guard let ipNum = ipToUInt32(String(parts[0])),
              let targetNum = ipToUInt32(ip) else { return false }

        if prefix == 0 { return true }
        let mask: UInt32 = ~0 << (32 - prefix)
        return (ipNum & mask) == (targetNum & mask)
    }

    static func ipToUInt32(_ ip: String) -> UInt32? {
        let octets = ip.split(separator: ".").compactMap { UInt8($0) }
        guard octets.count == 4 else { return nil }
        return (UInt32(octets[0]) << 24) |
               (UInt32(octets[1]) << 16) |
               (UInt32(octets[2]) << 8)  |
                UInt32(octets[3])
    }

    private static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        return parts.count == 4 && parts.allSatisfy { UInt8($0) != nil }
    }
}
