//
//  ExfiltrationScanner.swift
//  proxymate
//
//  Scans outbound HTTP request headers, URLs, and query strings for
//  credential/secret exfiltration patterns. Regex patterns are compiled
//  once when packs are loaded, not per-request.
//
//  Performance budget: 50µs per pattern max. If a pattern exceeds this
//  limit N times, it's disabled for the remainder of the session.
//

import Foundation

nonisolated final class ExfiltrationScanner: @unchecked Sendable {

    static let shared = ExfiltrationScanner()

    private let queue = DispatchQueue(label: "proxymate.exfiltration", qos: .userInitiated)

    /// Compiled patterns with their metadata.
    private struct CompiledPattern: Sendable {
        let id: UUID
        let name: String
        let packId: String
        let severity: ExfiltrationPattern.Severity
        let regex: NSRegularExpression
        var failureCount: Int = 0
        var disabled: Bool = false
    }

    private var compiled: [CompiledPattern] = []
    private let maxFailures = 5

    struct ScanResult: Sendable {
        let patternName: String
        let packId: String
        let severity: ExfiltrationPattern.Severity
        let matchPreview: String  // redacted snippet around the match
    }

    // MARK: - Load packs

    func loadPacks(_ packs: [ExfiltrationPack]) {
        queue.async { [weak self] in
            guard let self else { return }
            var newCompiled: [CompiledPattern] = []
            for pack in packs where pack.enabled {
                for pattern in pack.patterns {
                    guard let regex = try? NSRegularExpression(pattern: pattern.regex, options: []) else {
                        continue
                    }
                    newCompiled.append(CompiledPattern(
                        id: pattern.id,
                        name: pattern.name,
                        packId: pack.id,
                        severity: pattern.severity,
                        regex: regex
                    ))
                }
            }
            self.compiled = newCompiled
        }
    }

    // MARK: - Scan

    /// Scans the full header block (request line + headers). Returns the first
    /// match found, or nil if clean. Fast path: if no packs loaded, returns nil
    /// immediately.
    func scan(headers: String, target: String) -> ScanResult? {
        // Synchronous read — we're on the proxy queue when called from
        // routeRequest, and compiled array is only mutated on self.queue.
        // We accept the (tiny) race window for perf; at worst we miss a
        // freshly added pattern for one request.
        let patterns = compiled
        guard !patterns.isEmpty else { return nil }

        // Combine target URL + headers into one string to scan
        let haystack = target + "\n" + headers
        let nsRange = NSRange(haystack.startIndex..<haystack.endIndex, in: haystack)

        for i in patterns.indices {
            if patterns[i].disabled { continue }

            let start = DispatchTime.now()
            let match = patterns[i].regex.firstMatch(in: haystack, range: nsRange)
            let elapsed = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds

            // Budget check: 50µs = 50_000ns
            if elapsed > 50_000 {
                queue.async { [weak self] in
                    guard let self, i < self.compiled.count else { return }
                    self.compiled[i].failureCount += 1
                    if self.compiled[i].failureCount >= self.maxFailures {
                        self.compiled[i].disabled = true
                    }
                }
            }

            if let match {
                let matchRange = Range(match.range, in: haystack) ?? haystack.startIndex..<haystack.startIndex
                let preview = Self.redactedPreview(haystack: haystack, range: matchRange)
                return ScanResult(
                    patternName: patterns[i].name,
                    packId: patterns[i].packId,
                    severity: patterns[i].severity,
                    matchPreview: preview
                )
            }
        }
        return nil
    }

    // MARK: - Helpers

    /// Returns a short preview around the match with the actual secret redacted.
    private static func redactedPreview(haystack: String, range: Range<String.Index>) -> String {
        let matchStr = String(haystack[range])
        let redacted: String
        if matchStr.count > 8 {
            let prefix = String(matchStr.prefix(4))
            let suffix = String(matchStr.suffix(4))
            redacted = "\(prefix)****\(suffix)"
        } else {
            redacted = "****"
        }

        // Context: up to 10 chars before
        let contextStart = haystack.index(range.lowerBound, offsetBy: -10, limitedBy: haystack.startIndex) ?? haystack.startIndex
        let before = String(haystack[contextStart..<range.lowerBound])
            .replacingOccurrences(of: "\r\n", with: " ")
            .replacingOccurrences(of: "\n", with: " ")

        return "\(before)\(redacted)"
    }
}
