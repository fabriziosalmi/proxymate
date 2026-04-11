//
//  C2Detector.swift
//  proxymate
//
//  Detects known Command & Control (C2) framework signatures in HTTP
//  headers. Checks User-Agent strings, header patterns, and URL paths
//  against known defaults for Cobalt Strike, Sliver, Mythic, Empire,
//  Havoc, Metasploit, and other common offensive tools.
//

import Foundation

nonisolated struct C2Settings: Codable, Hashable, Sendable {
    var enabled: Bool = true
    var action: Action = .block

    enum Action: String, Codable, CaseIterable, Identifiable, Sendable {
        case alert = "Alert Only"
        case block = "Block"
        var id: String { rawValue }
    }
}

nonisolated enum C2Detector {

    struct Detection: Sendable {
        let framework: String
        let indicator: String
        let confidence: Confidence
    }

    enum Confidence: String, Sendable {
        case high, medium, low
    }

    /// Check HTTP headers for C2 indicators. Returns nil if clean.
    static func scan(headers: String, target: String, settings: C2Settings) -> Detection? {
        guard settings.enabled else { return nil }

        let lower = headers.lowercased()
        let ua = extractHeader(lower, name: "user-agent")

        // --- Cobalt Strike ---
        // Default malleable C2 User-Agents
        for sig in cobaltStrikeUA {
            if let ua, ua.contains(sig) {
                return Detection(framework: "Cobalt Strike", indicator: "UA: \(sig)", confidence: .high)
            }
        }
        // Default beacon paths
        for path in ["/pixel.gif", "/submit.php", "/__utm.gif", "/ga.js", "/fwlink"] {
            if target.lowercased().contains(path) {
                return Detection(framework: "Cobalt Strike", indicator: "Path: \(path)", confidence: .medium)
            }
        }
        // Named pipe indicator in cookies
        if lower.contains("cookie:") && lower.contains("mstsauthtoken=") {
            return Detection(framework: "Cobalt Strike", indicator: "MSTS cookie", confidence: .high)
        }

        // --- Sliver ---
        if let ua, (ua.contains("mozilla/5.0 (windows nt 10.0; win64; x64; rv:55.0)") ||
                     ua == "") {
            // Empty UA is suspicious but low confidence alone
            if ua.isEmpty && lower.contains("content-type: application/octet-stream") {
                return Detection(framework: "Sliver", indicator: "Empty UA + octet-stream", confidence: .medium)
            }
        }

        // --- Mythic ---
        for path in ["/api/v1/crypto", "/api/v1/tasking"] {
            if target.lowercased().contains(path) {
                return Detection(framework: "Mythic", indicator: "Path: \(path)", confidence: .high)
            }
        }

        // --- Empire ---
        if lower.contains("cookie:") && lower.contains("session=") &&
           lower.contains("user-agent:") && (ua?.contains("mozilla/5.0") ?? false) {
            for path in ["/login/process.php", "/admin/get.php", "/news.php"] {
                if target.lowercased().contains(path) {
                    return Detection(framework: "Empire", indicator: "Path: \(path)", confidence: .medium)
                }
            }
        }

        // --- Havoc ---
        if let ua, ua.contains("havocc2") {
            return Detection(framework: "Havoc", indicator: "UA contains havocc2", confidence: .high)
        }

        // --- Metasploit Meterpreter ---
        for path in ["/INITM", "/_init"] {
            if target.contains(path) && lower.contains("content-type: application/octet-stream") {
                return Detection(framework: "Metasploit", indicator: "Meterpreter init path", confidence: .medium)
            }
        }

        // --- Generic suspicious patterns ---
        // Empty User-Agent to non-API host (heuristic)
        if ua?.isEmpty ?? true {
            let host = extractHeader(lower, name: "host") ?? ""
            let isAPI = host.contains("api.") || host.contains("cdn.") || host.contains("static.")
            if !isAPI && lower.contains("content-type: application/octet-stream") {
                return Detection(framework: "Unknown", indicator: "Empty UA + binary POST", confidence: .low)
            }
        }

        return nil
    }

    // MARK: - Known Cobalt Strike default UAs

    private static let cobaltStrikeUA: [String] = [
        "mozilla/5.0 (compatible; msie 9.0; windows nt 6.1; trident/5.0)",
        "mozilla/5.0 (compatible; msie 10.0; windows nt 6.2; wow64; trident/6.0)",
        "mozilla/4.0 (compatible; msie 7.0; windows nt 5.1)",
        "mozilla/4.0 (compatible; msie 8.0; windows nt 6.1; trident/4.0)",
        "mozilla/5.0 (windows nt 6.1; wow64; trident/7.0; rv:11.0)",
    ]

    // MARK: - Helpers

    private static func extractHeader(_ headers: String, name: String) -> String? {
        for line in headers.split(separator: "\r\n", omittingEmptySubsequences: false) {
            let l = line.lowercased()
            if l.hasPrefix(name + ":") {
                return String(line.dropFirst(name.count + 1)).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }
}
