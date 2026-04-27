//
//  RuleImporter.swift
//  proxymate
//
//  Imports block rules from external list formats:
//  - Hosts file (0.0.0.0 / 127.0.0.1 domain)
//  - Adblock Plus (||domain.com^)
//  - Plain domains (one per line)
//  - Plain IPs (one per line)
//
//  Supports import from local file, URL (one-shot), or auto-updating URL.
//

import Foundation

nonisolated enum RuleImporter {

    enum ImportFormat: String, CaseIterable, Identifiable, Sendable {
        case hosts        = "Hosts File"
        case adblockPlus  = "Adblock Plus"
        case plainDomains = "Plain Domains"
        case plainIPs     = "Plain IPs"
        case autoDetect   = "Auto-detect"
        var id: String { rawValue }
    }

    struct ImportResult: Sendable {
        let rules: [WAFRule]
        let format: ImportFormat
        let skipped: Int
    }

    // MARK: - Import from text

    static func importRules(from text: String,
                             format: ImportFormat,
                             category: String,
                             existingPatterns: Set<String>) -> ImportResult {
        let detected = format == .autoDetect ? detectFormat(text) : format
        var rules: [WAFRule] = []
        var skipped = 0
        // Dedup against existing rules AND against earlier lines within
        // the same import. Without `seen`, duplicate entries inside a
        // single hosts/adblock file produce duplicate WAFRule objects
        // (distinct UUIDs, same pattern) — every re-import bloats the
        // ruleset by the count of dup'd lines in the source file.
        var seen = existingPatterns

        let lines = text.split(omittingEmptySubsequences: true, whereSeparator: \.isNewline)

        for rawLine in lines {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("!") || line.hasPrefix("//") { continue }

            let parsed: (kind: WAFRule.Kind, pattern: String)?
            switch detected {
            case .hosts:
                parsed = parseHostsLine(line)
            case .adblockPlus:
                parsed = parseAdblockLine(line)
            case .plainDomains:
                let d = line.lowercased()
                parsed = isValidDomain(d) ? (.blockDomain, d) : nil
            case .plainIPs:
                let ip = line.lowercased()
                parsed = isValidIP(ip) ? (.blockIP, ip) : nil
            case .autoDetect:
                parsed = nil  // already resolved above
            }

            guard let (kind, pattern) = parsed else {
                skipped += 1
                continue
            }
            let key = pattern.lowercased()
            if seen.contains(key) {
                skipped += 1
                continue
            }
            seen.insert(key)
            rules.append(WAFRule(
                name: "",
                kind: kind,
                pattern: pattern,
                category: category.isEmpty ? "Imported" : category
            ))
        }

        return ImportResult(rules: rules, format: detected, skipped: skipped)
    }

    // MARK: - Import from URL

    static func importFromURL(_ urlString: String,
                               format: ImportFormat,
                               category: String,
                               existingPatterns: Set<String>,
                               completion: @escaping @Sendable (Result<ImportResult, Error>) -> Void) {
        guard let url = URL(string: urlString) else {
            completion(.failure(ImportError.invalidURL))
            return
        }
        // URLSession holds onto delegate queues and connection pools for the
        // lifetime of the session; without invalidateAndCancel() every rule
        // import leaked a session plus a worker thread. Invalidate once the
        // dataTask completion fires so everything goes away after one use.
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        let session = URLSession(configuration: config)
        let task = session.dataTask(with: url) { data, _, error in
            defer { session.finishTasksAndInvalidate() }
            if let error {
                completion(.failure(error))
                return
            }
            guard let data, let text = String(data: data, encoding: .utf8) else {
                completion(.failure(ImportError.parseError))
                return
            }
            let result = importRules(from: text, format: format, category: category,
                                      existingPatterns: existingPatterns)
            completion(.success(result))
        }
        task.resume()
    }

    // MARK: - Import from file (for drag-drop or open panel)

    static func importFromFile(_ url: URL,
                                format: ImportFormat,
                                category: String,
                                existingPatterns: Set<String>) -> Result<ImportResult, Error> {
        do {
            let text = try String(contentsOf: url, encoding: .utf8)
            return .success(importRules(from: text, format: format, category: category,
                                         existingPatterns: existingPatterns))
        } catch {
            return .failure(error)
        }
    }

    // MARK: - Export

    static func exportRules(_ rules: [WAFRule]) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(rules) else { return "[]" }
        return String(data: data, encoding: .utf8) ?? "[]"
    }

    static func exportAsHosts(_ rules: [WAFRule]) -> String {
        rules.filter { $0.kind == .blockDomain }
            .map { "0.0.0.0 \($0.pattern)" }
            .joined(separator: "\n")
    }

    // MARK: - Format detection

    static func detectFormat(_ text: String) -> ImportFormat {
        let sample = text.split(omittingEmptySubsequences: true, whereSeparator: \.isNewline)
            .prefix(50)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.hasPrefix("#") && !$0.hasPrefix("!") && !$0.isEmpty }

        var hostsCount = 0, abpCount = 0, domainCount = 0, ipCount = 0
        for line in sample {
            if line.hasPrefix("0.0.0.0 ") || line.hasPrefix("127.0.0.1 ") { hostsCount += 1 }
            else if line.hasPrefix("||") { abpCount += 1 }
            else if isValidIP(line) { ipCount += 1 }
            else if isValidDomain(line.lowercased()) { domainCount += 1 }
        }
        let max = max(hostsCount, abpCount, domainCount, ipCount)
        if max == 0 { return .plainDomains }
        if hostsCount == max { return .hosts }
        if abpCount == max { return .adblockPlus }
        if ipCount == max { return .plainIPs }
        return .plainDomains
    }

    // MARK: - Line parsers

    private static func parseHostsLine(_ line: String) -> (WAFRule.Kind, String)? {
        let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard parts.count == 2 else { return nil }
        let addr = parts[0]
        guard addr == "0.0.0.0" || addr == "127.0.0.1" else { return nil }
        let domain = String(parts[1])
            .components(separatedBy: "#").first?
            .trimmingCharacters(in: .whitespaces)
            .lowercased() ?? ""
        if domain.isEmpty || domain == "localhost" || !isValidDomain(domain) { return nil }
        return (.blockDomain, domain)
    }

    private static func parseAdblockLine(_ line: String) -> (WAFRule.Kind, String)? {
        guard line.hasPrefix("||") else { return nil }
        var domain = String(line.dropFirst(2))
        if domain.hasSuffix("^") { domain = String(domain.dropLast()) }
        // Strip path if present
        if let slash = domain.firstIndex(of: "/") { domain = String(domain[..<slash]) }
        domain = domain.lowercased()
        if !isValidDomain(domain) { return nil }
        return (.blockDomain, domain)
    }

    private static func isValidDomain(_ s: String) -> Bool {
        !s.isEmpty && s.contains(".") && !s.contains(" ") && s.count < 256
    }

    private static func isValidIP(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        return parts.count == 4 && parts.allSatisfy { UInt8($0) != nil }
    }

    enum ImportError: LocalizedError {
        case invalidURL
        case parseError
        var errorDescription: String? {
            switch self {
            case .invalidURL: return "Invalid URL"
            case .parseError: return "Failed to parse content"
            }
        }
    }
}
