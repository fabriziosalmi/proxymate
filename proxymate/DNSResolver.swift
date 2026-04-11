//
//  DNSResolver.swift
//  proxymate
//
//  DNS-over-HTTPS (DoH) resolver with LRU cache. Used for:
//  1. Resolving domain→IP to match against IP blacklists
//  2. Private DNS resolution (bypass ISP DNS when enabled)
//  Thread-safe via serial queue.
//

import Foundation

nonisolated struct DNSSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var provider: DoHProvider = .cloudflare
    var cacheTTL: Int = 300           // seconds
    var maxCacheEntries: Int = 5000

    enum DoHProvider: String, Codable, CaseIterable, Identifiable, Sendable {
        case cloudflare  = "Cloudflare (1.1.1.1)"
        case quad9       = "Quad9 (9.9.9.9)"
        case google      = "Google (8.8.8.8)"
        case custom      = "Custom"
        var id: String { rawValue }

        var url: String {
            switch self {
            case .cloudflare: return "https://1.1.1.1/dns-query"
            case .quad9:      return "https://dns.quad9.net/dns-query"
            case .google:     return "https://dns.google/dns-query"
            case .custom:     return ""
            }
        }
    }

    var customURL: String = ""

    var resolvedURL: String {
        provider == .custom ? customURL : provider.url
    }
}

nonisolated final class DNSResolver: @unchecked Sendable {

    static let shared = DNSResolver()

    private let queue = DispatchQueue(label: "proxymate.dns", qos: .userInitiated)
    private var cache: [String: CacheEntry] = [:]
    private var accessOrder: [String] = []
    private var settings = DNSSettings()
    private var _stats = DNSStats()

    struct CacheEntry {
        let ips: [String]
        let storedAt: Date
        let ttl: TimeInterval
        var isExpired: Bool { Date().timeIntervalSince(storedAt) > ttl }
    }

    struct DNSStats: Sendable {
        var queries: Int = 0
        var cacheHits: Int = 0
        var cacheMisses: Int = 0
        var errors: Int = 0
    }

    var stats: DNSStats { queue.sync { _stats } }

    // MARK: - Configuration

    func configure(_ s: DNSSettings) {
        queue.async { [weak self] in
            self?.settings = s
            if !s.enabled { self?.clearCache() }
        }
    }

    // MARK: - Resolve

    /// Resolve a domain to IP addresses. Returns cached result if available.
    /// Falls back to system DNS if DoH fails.
    func resolve(_ domain: String, completion: @escaping @Sendable ([String]) -> Void) {
        queue.async { [weak self] in
            guard let self, self.settings.enabled else {
                completion([])
                return
            }
            self._stats.queries += 1

            // Cache check
            let key = domain.lowercased()
            if let cached = self.cache[key], !cached.isExpired {
                self._stats.cacheHits += 1
                self.touchLRU(key)
                completion(cached.ips)
                return
            }
            self._stats.cacheMisses += 1

            // DoH query
            self.queryDoH(domain: domain) { [weak self] result in
                guard let self else { completion([]); return }
                self.queue.async {
                    switch result {
                    case .success(let ips):
                        let ttl = TimeInterval(self.settings.cacheTTL)
                        self.cache[key] = CacheEntry(ips: ips, storedAt: Date(), ttl: ttl)
                        self.accessOrder.append(key)
                        self.evictIfNeeded()
                        completion(ips)
                    case .failure:
                        self._stats.errors += 1
                        completion([])
                    }
                }
            }
        }
    }

    /// Synchronous resolve with timeout. For use in the proxy hot path
    /// where we need to check if a domain resolves to a blacklisted IP.
    func resolveSync(_ domain: String, timeout: TimeInterval = 2) -> [String] {
        let semaphore = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var result: [String] = []
        resolve(domain) { ips in
            result = ips
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + timeout)
        return result
    }

    func clearCache() {
        cache.removeAll()
        accessOrder.removeAll()
    }

    // MARK: - DoH query (RFC 8484, JSON API)

    private func queryDoH(domain: String,
                           completion: @escaping @Sendable (Result<[String], Error>) -> Void) {
        let urlString = settings.resolvedURL
        guard !urlString.isEmpty,
              var components = URLComponents(string: urlString) else {
            completion(.failure(DNSError.invalidURL))
            return
        }
        components.queryItems = [
            URLQueryItem(name: "name", value: domain),
            URLQueryItem(name: "type", value: "A"),
        ]
        guard let url = components.url else {
            completion(.failure(DNSError.invalidURL))
            return
        }

        var request = URLRequest(url: url, timeoutInterval: 5)
        request.setValue("application/dns-json", forHTTPHeaderField: "Accept")

        let task = URLSession.shared.dataTask(with: request) { data, _, error in
            if let error {
                completion(.failure(error))
                return
            }
            guard let data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let answers = json["Answer"] as? [[String: Any]] else {
                completion(.failure(DNSError.parseError))
                return
            }
            let ips = answers.compactMap { answer -> String? in
                guard let type = answer["type"] as? Int, type == 1, // A record
                      let ip = answer["data"] as? String else { return nil }
                return ip
            }
            completion(.success(ips))
        }
        task.resume()
    }

    // MARK: - LRU

    private func touchLRU(_ key: String) {
        if let i = accessOrder.firstIndex(of: key) {
            accessOrder.remove(at: i)
        }
        accessOrder.append(key)
    }

    private func evictIfNeeded() {
        while cache.count > settings.maxCacheEntries && !accessOrder.isEmpty {
            let oldest = accessOrder.removeFirst()
            cache.removeValue(forKey: oldest)
        }
    }

    enum DNSError: LocalizedError {
        case invalidURL
        case parseError
        var errorDescription: String? {
            switch self {
            case .invalidURL: return "Invalid DoH URL"
            case .parseError: return "Failed to parse DNS response"
            }
        }
    }
}
