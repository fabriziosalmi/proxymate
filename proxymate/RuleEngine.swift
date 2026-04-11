//
//  RuleEngine.swift
//  proxymate
//
//  Pre-compiled rule sets for O(1) domain lookups and fast content matching.
//  Replaces the linear array scan in LocalProxy.matches() for the hot path.
//
//  Compiled once when rules change, not per-request.
//

import Foundation

nonisolated final class RuleEngine: @unchecked Sendable {

    private let queue = DispatchQueue(label: "proxymate.ruleengine", qos: .userInitiated)

    // Pre-compiled sets for O(1) lookup
    private var allowDomains = Set<String>()     // exact domain → allow
    private var allowSuffixes: [String] = []     // .suffix → allow (for subdomain match)
    private var blockDomains = Set<String>()     // exact domain → block
    private var blockSuffixes: [String] = []     // .suffix → block
    private var blockIPs = Set<String>()         // exact IP → block
    private var contentAC = AhoCorasick()        // Aho-Corasick automaton for content rules
    private var regexRules: [(name: String, regex: NSRegularExpression)] = []

    // Stats
    private var _compiledRuleCount = 0
    private var _lastCompileTime: TimeInterval = 0

    var compiledRuleCount: Int { _compiledRuleCount }
    var lastCompileTimeMs: Double { _lastCompileTime * 1000 }

    // MARK: - Compile

    /// Compile rules into optimized sets. Called when rules change.
    func compile(rules: [WAFRule]) {
        queue.async { [weak self] in
            guard let self else { return }
            let start = CFAbsoluteTimeGetCurrent()

            var ad = Set<String>()
            var as_ = [String]()
            var bd = Set<String>()
            var bs = [String]()
            var bi = Set<String>()
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

            self.allowDomains = ad
            self.allowSuffixes = as_
            self.blockDomains = bd
            self.blockSuffixes = bs
            self.blockIPs = bi
            self.contentAC = ac
            self.regexRules = rx
            self._compiledRuleCount = rules.count
            self._lastCompileTime = CFAbsoluteTimeGetCurrent() - start
        }
    }

    // MARK: - Fast checks (called from proxy queue, lock-free read)

    /// Check if a host is allowed. O(1) for exact match, O(N) for suffix.
    func isAllowed(host: String) -> Bool {
        let h = host.lowercased()
        if allowDomains.contains(h) { return true }
        for suffix in allowSuffixes {
            if h.hasSuffix(suffix) { return true }
        }
        return false
    }

    /// Check if a host is blocked by domain or IP rules.
    /// Returns the rule name if blocked, nil if allowed.
    func checkBlock(host: String) -> String? {
        let h = host.lowercased()

        // IP block: O(1)
        if blockIPs.contains(h) { return "Block IP: \(h)" }

        // Domain block: O(1) exact + O(N) suffix
        if blockDomains.contains(h) { return "Block Domain: \(h)" }
        for suffix in blockSuffixes {
            if h.hasSuffix(suffix) {
                return "Block Domain: \(String(suffix.dropFirst()))"
            }
        }

        return nil
    }

    /// Check if content (target URL + headers + body) matches any content rule.
    /// Aho-Corasick for substrings, NSRegularExpression for regex rules.
    func checkContent(target: String, headers: String, body: String = "") -> String? {
        let combined = target + "\n" + headers + "\n" + body
        // Aho-Corasick: O(text_length) for all substring patterns
        if let match = contentAC.search(combined) {
            return match.name
        }
        // Regex rules (compiled at load time)
        let nsRange = NSRange(combined.startIndex..., in: combined)
        for (name, regex) in regexRules {
            if regex.firstMatch(in: combined, range: nsRange) != nil {
                return name
            }
        }
        return nil
    }
}
