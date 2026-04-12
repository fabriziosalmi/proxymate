//
//  BlacklistManager.swift
//  proxymate
//
//  Downloads, parses, and caches bulk blacklists (TOR exits, ad domains,
//  malware, etc.). Uses Set<String> for O(1) lookups. Persists parsed
//  sets to disk so restarts don't require re-downloading.
//

import Foundation

nonisolated final class BlacklistManager: @unchecked Sendable {

    static let shared = BlacklistManager()

    private let queue = DispatchQueue(label: "proxymate.blacklist", qos: .utility)
    private let cacheDir: URL

    /// domain → set of source IDs that block it
    private var domainSets: [UUID: Set<String>] = [:]
    /// IP → set of source IDs that block it
    private var ipSets: [UUID: Set<String>] = [:]
    /// Lock for reading domainSets/ipSets from non-queue threads.
    private let setsLock = NSLock()

    /// URLSession that bypasses system proxy (avoids circular dependency).
    private let directSession: URLSession = {
        let config = URLSessionConfiguration.default
        config.connectionProxyDictionary = [:]  // empty = no proxy
        config.timeoutIntervalForRequest = 30
        return URLSession(configuration: config)
    }()

    private init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        cacheDir = appSupport.appendingPathComponent("Proxymate/blacklists", isDirectory: true)
        try? FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
    }

    // MARK: - Lookup (called from proxy queue, must be fast)

    struct BlockResult: Sendable {
        let sourceName: String
        let category: BlacklistSource.BlacklistCategory
    }

    /// Check if a host (domain or IP) is in any enabled blacklist.
    func lookup(host: String, enabledSources: [BlacklistSource]) -> BlockResult? {
        let h = host.lowercased()
        setsLock.lock()
        let domains = domainSets
        let ips = ipSets
        setsLock.unlock()
        for source in enabledSources where source.enabled {
            if let d = domains[source.id] {
                if d.contains(h) || Self.matchesParentDomain(h, in: d) {
                    return BlockResult(sourceName: source.name, category: source.category)
                }
            }
            if let i = ips[source.id], i.contains(h) {
                return BlockResult(sourceName: source.name, category: source.category)
            }
        }
        return nil
    }

    private static func matchesParentDomain(_ host: String, in domains: Set<String>) -> Bool {
        var parts = host.split(separator: ".")
        while parts.count > 2 {
            parts.removeFirst()
            if domains.contains(parts.joined(separator: ".")) { return true }
        }
        return false
    }

    // MARK: - Download & parse

    func refresh(source: BlacklistSource,
                 completion: @escaping @Sendable (Result<Int, Error>) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            guard let url = URL(string: source.url) else {
                completion(.failure(BLError.invalidURL))
                return
            }
            let task = self.directSession.dataTask(with: url) { [weak self] data, response, error in
                guard let self else { return }
                self.queue.async {
                    if let error {
                        // Fall back to cache
                        let count = self.loadFromDisk(source: source)
                        if count > 0 {
                            completion(.success(count))
                        } else {
                            completion(.failure(error))
                        }
                        return
                    }
                    guard let data,
                          let text = String(data: data, encoding: .utf8) else {
                        completion(.failure(BLError.parseError))
                        return
                    }

                    let entries = Self.parse(text: text, format: source.format)
                    let count = entries.domains.count + entries.ips.count

                    self.setsLock.lock()
                    if !entries.domains.isEmpty {
                        self.domainSets[source.id] = entries.domains
                    }
                    if !entries.ips.isEmpty {
                        self.ipSets[source.id] = entries.ips
                    }
                    self.setsLock.unlock()

                    // Cache to disk
                    self.saveToDisk(source: source, entries: entries)

                    completion(.success(count))
                }
            }
            task.resume()
        }
    }

    /// Load all enabled sources from disk cache (called at app startup).
    func loadCachedSources(_ sources: [BlacklistSource]) {
        queue.async { [weak self] in
            guard let self else { return }
            for source in sources where source.enabled {
                _ = self.loadFromDisk(source: source)
            }
        }
    }

    func clearSource(_ id: UUID) {
        queue.async { [weak self] in
            self?.setsLock.lock()
            self?.domainSets.removeValue(forKey: id)
            self?.ipSets.removeValue(forKey: id)
            self?.setsLock.unlock()
        }
    }

    func entryCount(for id: UUID) -> Int {
        setsLock.lock()
        let n = (domainSets[id]?.count ?? 0) + (ipSets[id]?.count ?? 0)
        setsLock.unlock()
        return n
    }

    /// Total entries across all sources (may include duplicates across sources).
    var totalEntries: Int {
        setsLock.lock()
        let n = domainSets.values.reduce(0) { $0 + $1.count } +
                ipSets.values.reduce(0) { $0 + $1.count }
        setsLock.unlock()
        return n
    }

    /// Unique entries (deduplicated across all sources).
    var uniqueEntries: Int {
        var allDomains = Set<String>()
        for set in domainSets.values { allDomains.formUnion(set) }
        var allIPs = Set<String>()
        for set in ipSets.values { allIPs.formUnion(set) }
        return allDomains.count + allIPs.count
    }

    /// Number of active sources.
    var activeSourceCount: Int {
        domainSets.count + ipSets.count
    }

    // MARK: - Parsing

    private struct ParsedEntries {
        var domains: Set<String> = []
        var ips: Set<String> = []
    }

    private static func parse(text: String, format: BlacklistSource.ListFormat) -> ParsedEntries {
        var result = ParsedEntries()
        let lines = text.split(omittingEmptySubsequences: true, whereSeparator: \.isNewline)

        for rawLine in lines {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("!") { continue }

            switch format {
            case .plainDomains:
                let domain = line.lowercased()
                if Self.isValidDomain(domain) { result.domains.insert(domain) }

            case .plainIPs:
                let ip = line.lowercased()
                if Self.isValidIP(ip) { result.ips.insert(ip) }

            case .hosts:
                // Format: 0.0.0.0 domain  or  127.0.0.1 domain
                let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                guard parts.count == 2 else { continue }
                let addr = parts[0]
                guard addr == "0.0.0.0" || addr == "127.0.0.1" else { continue }
                let domain = String(parts[1]).lowercased()
                    .trimmingCharacters(in: .whitespaces)
                    .components(separatedBy: "#").first?
                    .trimmingCharacters(in: .whitespaces) ?? ""
                if domain != "localhost" && Self.isValidDomain(domain) {
                    result.domains.insert(domain)
                }

            case .adblockPlus:
                // Format: ||domain.com^ or ||domain.com
                if line.hasPrefix("||") {
                    var domain = String(line.dropFirst(2))
                    if domain.hasSuffix("^") { domain = String(domain.dropLast()) }
                    domain = domain.lowercased()
                    if Self.isValidDomain(domain) { result.domains.insert(domain) }
                }
            }
        }

        return result
    }

    private static func isValidDomain(_ s: String) -> Bool {
        !s.isEmpty && s.contains(".") && !s.contains(" ") && s.count < 256
    }

    private static func isValidIP(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        return parts.count == 4 && parts.allSatisfy { UInt8($0) != nil }
    }

    // MARK: - Disk cache

    private func cacheFile(for source: BlacklistSource) -> URL {
        cacheDir.appendingPathComponent("\(source.id.uuidString).txt")
    }

    private func saveToDisk(source: BlacklistSource, entries: ParsedEntries) {
        let all = entries.domains.union(entries.ips)
        let text = all.joined(separator: "\n")
        try? text.write(to: cacheFile(for: source), atomically: true, encoding: .utf8)
    }

    @discardableResult
    private func loadFromDisk(source: BlacklistSource) -> Int {
        let path = cacheFile(for: source)
        guard let text = try? String(contentsOf: path, encoding: .utf8) else { return 0 }
        let entries = Self.parse(text: text, format: .plainDomains) // cached as plain list
        // Also try IPs
        let ipEntries = Self.parse(text: text, format: .plainIPs)
        setsLock.lock()
        if !entries.domains.isEmpty { domainSets[source.id] = entries.domains }
        if !ipEntries.ips.isEmpty { ipSets[source.id] = ipEntries.ips }
        setsLock.unlock()
        return entries.domains.count + ipEntries.ips.count
    }

    enum BLError: LocalizedError {
        case invalidURL
        case parseError
        var errorDescription: String? {
            switch self {
            case .invalidURL: return "Invalid blacklist URL"
            case .parseError: return "Failed to parse blacklist"
            }
        }
    }
}
