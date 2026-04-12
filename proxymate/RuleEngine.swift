//
//  RuleEngine.swift
//  proxymate
//
//  Pre-compiled rule sets for O(1) domain lookups and fast content matching.
//  Replaces the linear array scan in LocalProxy.matches() for the hot path.
//
//  Compiled once when rules change, not per-request.
//  All reads go through an immutable snapshot swapped atomically.
//

import Foundation
import os

nonisolated final class RuleEngine: @unchecked Sendable {

    private let queue = DispatchQueue(label: "proxymate.ruleengine", qos: .userInitiated)

    /// Immutable snapshot of all compiled rule sets. Swapped atomically.
    private struct Snapshot {
        let allowDomains: Set<String>
        let allowSuffixes: [String]
        let blockDomains: Set<String>
        let blockSuffixes: [String]
        let blockIPs: Set<String>
        let mockDomains: Set<String>
        let mockSuffixes: [String]
        let contentAC: AhoCorasick
        let regexRules: [(name: String, regex: NSRegularExpression)]
        let ruleCount: Int
        let compileTime: TimeInterval

        static let empty = Snapshot(
            allowDomains: [], allowSuffixes: [],
            blockDomains: [], blockSuffixes: [],
            blockIPs: [], mockDomains: [], mockSuffixes: [],
            contentAC: AhoCorasick(), regexRules: [],
            ruleCount: 0, compileTime: 0
        )
    }

    /// The current compiled snapshot. Protected by lock for atomic swap.
    /// OSAllocatedUnfairLock: fastest lock on Apple Silicon, no priority inversion.
    private let _snapshot = OSAllocatedUnfairLock(initialState: Snapshot.empty)

    var compiledRuleCount: Int {
        _snapshot.withLock { $0.ruleCount }
    }

    var lastCompileTimeMs: Double {
        _snapshot.withLock { $0.compileTime * 1000 }
    }

    // MARK: - Compile

    /// Compile rules into optimized sets. Called when rules change.
    /// Optional completion fires on the internal queue after swap.
    func compile(rules: [WAFRule], completion: (() -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            let start = CFAbsoluteTimeGetCurrent()

            let count = rules.count
            var ad = Set<String>(minimumCapacity: count)
            var as_ = [String]()
            as_.reserveCapacity(count)
            var bd = Set<String>(minimumCapacity: count)
            var bs = [String]()
            bs.reserveCapacity(count)
            var bi = Set<String>(minimumCapacity: count)
            var md = Set<String>(minimumCapacity: count)
            var ms = [String]()
            ms.reserveCapacity(count)
            let ac = AhoCorasick()
            var rx: [(String, NSRegularExpression)] = []
            rx.reserveCapacity(count)

            for rule in rules where rule.enabled {
                let pat = rule.pattern.lowercased()
                guard !pat.isEmpty else { continue }

                switch rule.kind {
                case .allowDomain:
                    ad.insert(pat)
                    as_.append("." + pat)

                case .blockDomain:
                    bd.insert(pat)
                    bs.append("." + pat)

                case .blockIP:
                    bi.insert(pat)

                case .mockDomain:
                    md.insert(pat)
                    ms.append("." + pat)

                case .blockContent:
                    let name = rule.name.isEmpty ? rule.pattern : rule.name
                    ac.addPattern(name: name, pattern: pat)

                case .blockRegex:
                    let name = rule.name.isEmpty ? rule.pattern : rule.name
                    if let regex = try? NSRegularExpression(pattern: rule.pattern, options: []) {
                        rx.append((name, regex))
                    }
                }
            }
            ac.compile()

            let elapsed = CFAbsoluteTimeGetCurrent() - start
            let newSnapshot = Snapshot(
                allowDomains: ad, allowSuffixes: as_,
                blockDomains: bd, blockSuffixes: bs,
                blockIPs: bi, mockDomains: md, mockSuffixes: ms,
                contentAC: ac, regexRules: rx,
                ruleCount: rules.count, compileTime: elapsed
            )

            self._snapshot.withLock { $0 = newSnapshot }

            completion?()
        }
    }

    // MARK: - Fast checks (snapshot read, thread-safe)

    /// Grab current snapshot for reads. Lock held only during pointer copy.
    private func current() -> Snapshot {
        _snapshot.withLock { $0 }
    }

    /// Check if a host is allowed. O(1) for exact match, O(N) for suffix.
    func isAllowed(host: String) -> Bool {
        let s = current()
        let h = host.lowercased()
        if s.allowDomains.contains(h) { return true }
        for suffix in s.allowSuffixes {
            if h.hasSuffix(suffix) { return true }
        }
        return false
    }

    /// Check if a host is blocked by domain or IP rules.
    /// Returns the rule name if blocked, nil if allowed.
    func checkBlock(host: String) -> String? {
        let s = current()
        let h = host.lowercased()

        // IP block: O(1)
        if s.blockIPs.contains(h) { return "Block IP: \(h)" }

        // Domain block: O(1) exact + O(N) suffix
        if s.blockDomains.contains(h) { return "Block Domain: \(h)" }
        for suffix in s.blockSuffixes {
            if h.hasSuffix(suffix) {
                return "Block Domain: \(String(suffix.dropFirst()))"
            }
        }

        return nil
    }

    /// Check if a host should be mocked (stealth 200 OK).
    func checkMock(host: String) -> Bool {
        let s = current()
        let h = host.lowercased()
        if s.mockDomains.contains(h) { return true }
        for suffix in s.mockSuffixes {
            if h.hasSuffix(suffix) { return true }
        }
        return false
    }

    /// Contextual score multiplier: localhost/dev traffic gets low weight,
    /// sensitive destinations (banks, payment) get high weight (#18).
    private static func contextMultiplier(for host: String) -> Double {
        let h = host.lowercased()
        // Development / local — suppress false positives
        if h == "localhost" || h.hasSuffix(".local") || h.hasPrefix("127.") || h.hasPrefix("192.168.") || h.hasPrefix("10.") {
            return 0.0
        }
        // High-value targets — amplify detections
        let sensitive = ["bank", "pay", "finance", "trade", "invest", "wallet", "crypto"]
        for keyword in sensitive {
            if h.contains(keyword) { return 2.0 }
        }
        return 1.0
    }

    /// Check if content (target URL + headers + body) matches any content rule.
    /// Aho-Corasick for substrings, NSRegularExpression for regex rules.
    /// Applies double URL decoding to defeat encoding evasion attacks (#14).
    /// Uses contextual scoring (#18): local/dev traffic suppressed, sensitive targets amplified.
    func checkContent(target: String, headers: String, body: String = "", host: String = "") -> String? {
        // Skip content checks entirely for local development traffic
        if !host.isEmpty && Self.contextMultiplier(for: host) == 0.0 { return nil }
        let s = current()
        guard !s.contentAC.isEmpty || !s.regexRules.isEmpty else { return nil }
        // Double URL-decode to catch %25-encoded attacks (e.g. %253Cscript%253E → <script>)
        let decodedTarget = target.removingPercentEncoding?.removingPercentEncoding ?? target
        let decodedBody = body.removingPercentEncoding?.removingPercentEncoding ?? body
        // Single allocation: pre-compute total size, build combined string once
        var combined = String()
        combined.reserveCapacity(decodedTarget.count + headers.count + decodedBody.count + 2)
        combined.append(decodedTarget)
        combined.append("\n")
        combined.append(headers)
        combined.append("\n")
        combined.append(decodedBody)
        // Aho-Corasick: O(text_length) for all substring patterns
        if let match = s.contentAC.search(combined) {
            return match.name
        }
        // Regex rules (compiled at load time)
        let nsRange = NSRange(combined.startIndex..., in: combined)
        for (name, regex) in s.regexRules {
            if regex.firstMatch(in: combined, range: nsRange) != nil {
                return name
            }
        }
        return nil
    }
}
