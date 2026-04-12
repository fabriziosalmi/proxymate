//
//  IPv6Support.swift
//  proxymate
//
//  IPv6 parsing, CIDR matching, and host extraction helpers.
//  Handles [::1]:8080 in Host headers, IPv6 CONNECT targets,
//  and IPv6 CIDR ranges in allowlists.
//

import Foundation

nonisolated enum IPv6Support {

    /// Parse host from potentially IPv6-bracketed string.
    /// "[::1]:8080" → ("::1", 8080)
    /// "example.com:443" → ("example.com", 443)
    /// "[2001:db8::1]" → ("2001:db8::1", nil)
    static func parseHostPort(_ input: String) -> (host: String, port: Int?) {
        let s = input.trimmingCharacters(in: .whitespaces)

        // IPv6 bracketed: [addr]:port or [addr]
        if s.hasPrefix("[") {
            if let closeBracket = s.firstIndex(of: "]") {
                let addr = String(s[s.index(after: s.startIndex)..<closeBracket])
                let after = s[s.index(after: closeBracket)...]
                if after.hasPrefix(":"), let port = Int(after.dropFirst()) {
                    return (addr, port)
                }
                return (addr, nil)
            }
        }

        // Regular host:port (only if single colon — multiple colons = bare IPv6)
        let colonCount = s.filter { $0 == ":" }.count
        if colonCount == 1, let colon = s.lastIndex(of: ":") {
            let host = String(s[s.startIndex..<colon])
            let port = Int(s[s.index(after: colon)...])
            return (host, port)
        }

        // Bare IPv6 or plain hostname
        return (s, nil)
    }

    /// Check if a string is an IPv6 address.
    static func isIPv6(_ s: String) -> Bool {
        s.contains(":") && !s.contains("://")
    }

    /// Check if a string is an IPv4 address.
    static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        return parts.count == 4 && parts.allSatisfy { UInt8($0) != nil }
    }

    /// Expand a short IPv6 to full 8-group form for comparison.
    /// "::1" → "0000:0000:0000:0000:0000:0000:0000:0001"
    static func expandIPv6(_ addr: String) -> String? {
        // Handle :: expansion
        var left: [String] = []
        var right: [String] = []

        if addr.contains("::") {
            let halves = addr.components(separatedBy: "::")
            guard halves.count == 2 else { return nil }
            left = halves[0].isEmpty ? [] : halves[0].split(separator: ":").map(String.init)
            right = halves[1].isEmpty ? [] : halves[1].split(separator: ":").map(String.init)
            let missing = 8 - left.count - right.count
            guard missing >= 0 else { return nil }
            let mid = Array(repeating: "0000", count: missing)
            left = left + mid + right
        } else {
            left = addr.split(separator: ":").map(String.init)
        }

        guard left.count == 8 else { return nil }
        return left.map { $0.leftPad(toLength: 4, withPad: "0") }.joined(separator: ":")
    }

    /// Match IPv6 CIDR range. e.g. "fd00::/8"
    static func matchesCIDR6(ip: String, cidr: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let prefix = Int(parts[1]),
              prefix >= 0 && prefix <= 128 else { return false }

        guard let expanded = expandIPv6(String(parts[0])),
              let target = expandIPv6(ip) else { return false }

        let expandedBits = hexToBits(expanded.replacingOccurrences(of: ":", with: ""))
        let targetBits = hexToBits(target.replacingOccurrences(of: ":", with: ""))

        guard expandedBits.count >= prefix && targetBits.count >= prefix else { return false }
        return expandedBits.prefix(prefix) == targetBits.prefix(prefix)
    }

    private static func hexToBits(_ hex: String) -> String {
        hex.compactMap { char -> String? in
            guard let val = UInt8(String(char), radix: 16) else { return nil }
            return String(val, radix: 2).leftPad(toLength: 4, withPad: "0")
        }.joined()
    }
}

private extension String {
    nonisolated func leftPad(toLength length: Int, withPad pad: String) -> String {
        let deficit = length - count
        if deficit <= 0 { return self }
        return String(repeating: pad, count: deficit) + self
    }
}
