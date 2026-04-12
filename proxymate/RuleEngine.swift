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

    /// The current compiled snapshot. Protected by snapshotLock for atomic swap.
    private var snapshot = Snapshot.empty
    private let snapshotLock = NSLock()

    var compiledRuleCount: Int {
        snapshotLock.lock()
        let n = snapshot.ruleCount
        snapshotLock.unlock()
        return n
    }

    var lastCompileTimeMs: Double {
        snapshotLock.lock()
        let t = snapshot.compileTime * 1000
        snapshotLock.unlock()
        return t
    }

    // MARK: - Compile

    /// Compile rules into optimized sets. Called when rules change.
    /// Optional completion fires on the internal queue after swap.
    func compile(rules: [WAFRule], completion: (() -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            let start = CFAbsoluteTimeGetCurrent()

            var ad = Set<String>()
            var as_ = [String]()
            var bd = Set<String>()
            var bs = [String]()
            var bi = Set<String>()
            var md = Set<String>()
            var ms = [String]()
            let ac = AhoCorasick()
            var rx: [(String, NSRegularExpression)] = []

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

            self.snapshotLock.lock()
            self.snapshot = newSnapshot
            self.snapshotLock.unlock()

            completion?()
        }
    }

    // MARK: - Fast checks (snapshot read, thread-safe)

    /// Grab current snapshot for reads. Lock held only during pointer copy.
    private func current() -> Snapshot {
        snapshotLock.lock()
        let s = snapshot
        snapshotLock.unlock()
        return s
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

    /// Check if content (target URL + headers + body) matches any content rule.
    /// Aho-Corasick for substrings, NSRegularExpression for regex rules.
    func checkContent(target: String, headers: String, body: String = "") -> String? {
        let s = current()
        let combined = target + "\n" + headers + "\n" + body
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
