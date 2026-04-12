//
//  RequestFingerprint.swift
//  proxymate
//
//  Computes a signature from HTTP header order + presence.
//  Same URL with different header order = different client.
//  Detects bots pretending to be browsers, agents switching identity.
//

import Foundation
import CommonCrypto

nonisolated enum RequestFingerprint {

    struct Fingerprint: Sendable, Hashable {
        let hash: String           // short hex hash of header order
        let headerCount: Int
        let hasUserAgent: Bool
        let hasAcceptLanguage: Bool
        let hasCookie: Bool
        let hasReferer: Bool
    }

    /// Compute fingerprint from raw HTTP headers.
    static func compute(_ headers: String) -> Fingerprint {
        let lines = headers.split(separator: "\r\n", omittingEmptySubsequences: true)
        var headerNames: [String] = []
        var hasUA = false, hasLang = false, hasCookie = false, hasRef = false

        for line in lines.dropFirst() { // skip request line
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[line.startIndex..<colon]).lowercased().trimmingCharacters(in: .whitespaces)
            headerNames.append(name)
            switch name {
            case "user-agent": hasUA = true
            case "accept-language": hasLang = true
            case "cookie": hasCookie = true
            case "referer": hasRef = true
            default: break
            }
        }

        // Hash the ordered header name list
        let joined = headerNames.joined(separator: "|")
        let hash = sha256Short(joined)

        return Fingerprint(
            hash: hash,
            headerCount: headerNames.count,
            hasUserAgent: hasUA,
            hasAcceptLanguage: hasLang,
            hasCookie: hasCookie,
            hasReferer: hasRef
        )
    }

    /// Detect suspicious fingerprint patterns.
    static func isSuspicious(_ fp: Fingerprint) -> String? {
        // No User-Agent at all — very unusual for legitimate clients
        if !fp.hasUserAgent && fp.headerCount > 2 {
            return "No User-Agent header"
        }
        // Very few headers — likely a script or bot
        if fp.headerCount <= 2 {
            return "Minimal headers (\(fp.headerCount))"
        }
        return nil
    }

    private static func sha256Short(_ input: String) -> String {
        var hash = [UInt8](repeating: 0, count: 32)
        let data = Data(input.utf8)
        _ = data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return hash.prefix(4).map { String(format: "%02x", $0) }.joined()
    }
}
