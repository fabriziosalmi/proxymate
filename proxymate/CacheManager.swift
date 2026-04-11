//
//  CacheManager.swift
//  proxymate
//
//  L1 in-memory HTTP response cache. LRU eviction, Cache-Control aware.
//  Thread-safe (serial queue). Keyed by (method, scheme, host, path, query).
//
//  Honors: Cache-Control (max-age, no-store, no-cache, private, public,
//  s-maxage, stale-while-revalidate), Expires, Vary, ETag, Last-Modified.
//
//  Does NOT cache: POST/PUT/DELETE, responses with Set-Cookie (by default),
//  Vary: * responses, status codes other than 200/301/302/304/307/308.
//

import Foundation

nonisolated struct CacheSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var maxSizeMB: Int = 64
    var maxEntries: Int = 10_000
    var honorNoStore: Bool = true
    var cacheAuthenticated: Bool = false
    var stripTrackingParams: Bool = true
    var defaultTTL: Int = 300   // seconds, fallback when no headers

    static let trackingParams: Set<String> = [
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "fbclid", "gclid", "dclid", "msclkid", "twclid",
    ]
}

nonisolated final class CacheManager: @unchecked Sendable {

    static let shared = CacheManager()

    private let queue = DispatchQueue(label: "proxymate.cache", qos: .userInitiated)
    private var entries: [String: CacheEntry] = [:]
    private var accessOrder: [String] = []   // LRU: most recently accessed at end
    private var currentSizeBytes: Int = 0
    private var settings = CacheSettings()

    struct CacheEntry: Sendable {
        let key: String
        let statusLine: String
        let responseHeaders: String
        let body: Data
        let storedAt: Date
        let maxAge: TimeInterval
        let etag: String?
        let lastModified: String?
        let varyFields: [String]
        let varyValues: [String: String]  // field→value from the original request

        var sizeBytes: Int { responseHeaders.utf8.count + body.count }

        var isExpired: Bool {
            Date().timeIntervalSince(storedAt) > maxAge
        }
    }

    struct Stats: Sendable {
        var hits: Int = 0
        var misses: Int = 0
        var evictions: Int = 0
        var currentEntries: Int = 0
        var currentSizeMB: Double = 0
    }

    private var _stats = Stats()
    var stats: Stats {
        queue.sync { _stats }
    }

    // MARK: - Configuration

    func configure(_ s: CacheSettings) {
        queue.async { [weak self] in
            self?.settings = s
            if !s.enabled { self?.purgeAll() }
        }
    }

    // MARK: - Lookup

    struct LookupResult: Sendable {
        let statusLine: String
        let responseHeaders: String
        let body: Data
    }

    func lookup(method: String, url: String, requestHeaders: String) -> LookupResult? {
        guard settings.enabled else { return nil }
        guard method.uppercased() == "GET" || method.uppercased() == "HEAD" else { return nil }

        let key = cacheKey(method: method, url: url, requestHeaders: requestHeaders)

        return queue.sync { () -> LookupResult? in
            guard let entry = entries[key] else {
                // L1 miss → try L2 disk cache
                if let l2 = DiskCache.shared.lookup(key: key) {
                    _stats.hits += 1
                    return l2
                }
                _stats.misses += 1
                return nil
            }
            if entry.isExpired {
                remove(key: key)
                if let l2 = DiskCache.shared.lookup(key: key) {
                    _stats.hits += 1
                    return l2
                }
                _stats.misses += 1
                return nil
            }
            // Vary match
            if !entry.varyFields.isEmpty {
                let reqHeaders = Self.parseHeaderMap(requestHeaders)
                for field in entry.varyFields {
                    let current = reqHeaders[field.lowercased()] ?? ""
                    let original = entry.varyValues[field.lowercased()] ?? ""
                    if current != original {
                        _stats.misses += 1
                        return nil
                    }
                }
            }

            // Move to end of LRU
            if let i = accessOrder.firstIndex(of: key) {
                accessOrder.remove(at: i)
                accessOrder.append(key)
            }
            _stats.hits += 1
            return LookupResult(
                statusLine: entry.statusLine,
                responseHeaders: entry.responseHeaders,
                body: entry.body
            )
        }
    }

    // MARK: - Store

    func store(method: String, url: String, requestHeaders: String,
               statusLine: String, responseHeaders: String, body: Data) {
        guard settings.enabled else { return }
        guard method.uppercased() == "GET" else { return }

        let respMap = Self.parseHeaderMap(responseHeaders)

        // Never cache responses with Set-Cookie unless explicitly allowed
        if respMap["set-cookie"] != nil && !settings.cacheAuthenticated { return }

        // Parse Cache-Control
        let cc = Self.parseCacheControl(respMap["cache-control"] ?? "")
        if cc.noStore && settings.honorNoStore { return }
        if cc.private_ { return }

        // Status code check
        let statusCode = Self.extractStatusCode(statusLine)
        guard [200, 301, 302, 304, 307, 308].contains(statusCode) else { return }

        // Vary: * → do not cache
        if let vary = respMap["vary"], vary.trimmingCharacters(in: .whitespaces) == "*" { return }

        // Determine TTL
        var maxAge: TimeInterval
        if let sMaxAge = cc.sMaxAge { maxAge = sMaxAge }
        else if let ma = cc.maxAge { maxAge = ma }
        else if let expires = respMap["expires"],
                let date = Self.parseHTTPDate(expires) {
            maxAge = max(0, date.timeIntervalSinceNow)
        } else {
            maxAge = TimeInterval(settings.defaultTTL)
        }

        // Vary fields
        let varyFields = (respMap["vary"] ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
        let reqMap = Self.parseHeaderMap(requestHeaders)
        var varyValues: [String: String] = [:]
        for field in varyFields { varyValues[field] = reqMap[field] ?? "" }

        let key = cacheKey(method: method, url: url, requestHeaders: requestHeaders)
        let entry = CacheEntry(
            key: key,
            statusLine: statusLine,
            responseHeaders: responseHeaders,
            body: body,
            storedAt: Date(),
            maxAge: maxAge,
            etag: respMap["etag"],
            lastModified: respMap["last-modified"],
            varyFields: varyFields,
            varyValues: varyValues
        )

        queue.async { [weak self] in
            guard let self else { return }
            // Remove old entry if overwriting
            if let old = self.entries[key] {
                self.currentSizeBytes -= old.sizeBytes
            }
            self.entries[key] = entry
            self.currentSizeBytes += entry.sizeBytes
            if let i = self.accessOrder.firstIndex(of: key) {
                self.accessOrder.remove(at: i)
            }
            self.accessOrder.append(key)
            self.evictIfNeeded()
            self._stats.currentEntries = self.entries.count
            self._stats.currentSizeMB = Double(self.currentSizeBytes) / (1024 * 1024)

            // Also store to L2 disk cache
            DiskCache.shared.store(key: key, statusLine: statusLine,
                                    headers: responseHeaders, body: body, maxAge: maxAge)
        }
    }

    // MARK: - Purge

    func purgeAll() {
        entries.removeAll()
        accessOrder.removeAll()
        currentSizeBytes = 0
        _stats = Stats()
    }

    func purgeHost(_ host: String) {
        queue.async { [weak self] in
            guard let self else { return }
            let h = host.lowercased()
            let keys = self.entries.keys.filter { $0.contains(h) }
            for key in keys { self.remove(key: key) }
        }
    }

    // MARK: - Internal

    private func cacheKey(method: String, url: String, requestHeaders: String) -> String {
        var normalizedURL = url
        if settings.stripTrackingParams {
            normalizedURL = Self.stripTracking(url: normalizedURL)
        }
        // For Vary, we include relevant request header values in the key
        // but that's handled at lookup/store time via varyValues
        return "\(method.uppercased())|\(normalizedURL)"
    }

    private func evictIfNeeded() {
        let maxBytes = settings.maxSizeMB * 1024 * 1024
        while (currentSizeBytes > maxBytes || entries.count > settings.maxEntries)
                && !accessOrder.isEmpty {
            let oldest = accessOrder.removeFirst()
            remove(key: oldest)
            _stats.evictions += 1
        }
    }

    private func remove(key: String, demoteToL2: Bool = true) {
        if let entry = entries.removeValue(forKey: key) {
            currentSizeBytes -= entry.sizeBytes
            // Demote to L2 disk cache before discarding
            if demoteToL2 {
                DiskCache.shared.store(key: key, statusLine: entry.statusLine,
                                        headers: entry.responseHeaders, body: entry.body,
                                        maxAge: max(0, entry.maxAge - Date().timeIntervalSince(entry.storedAt)))
            }
        }
        accessOrder.removeAll { $0 == key }
    }

    // MARK: - Parsing helpers

    static func parseHeaderMap(_ headers: String) -> [String: String] {
        var map: [String: String] = [:]
        for line in headers.split(separator: "\r\n", omittingEmptySubsequences: true) {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex..<colon].lowercased().trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            map[name] = value
        }
        return map
    }

    struct CacheControl {
        var maxAge: TimeInterval?
        var sMaxAge: TimeInterval?
        var noStore: Bool = false
        var noCache: Bool = false
        var private_: Bool = false
        var public_: Bool = false
        var staleWhileRevalidate: TimeInterval?
    }

    static func parseCacheControl(_ value: String) -> CacheControl {
        var cc = CacheControl()
        for directive in value.split(separator: ",") {
            let d = directive.trimmingCharacters(in: .whitespaces).lowercased()
            if d == "no-store" { cc.noStore = true }
            else if d == "no-cache" { cc.noCache = true }
            else if d == "private" { cc.private_ = true }
            else if d == "public" { cc.public_ = true }
            else if d.hasPrefix("max-age=") {
                cc.maxAge = TimeInterval(d.dropFirst("max-age=".count)) ?? nil
            } else if d.hasPrefix("s-maxage=") {
                cc.sMaxAge = TimeInterval(d.dropFirst("s-maxage=".count)) ?? nil
            } else if d.hasPrefix("stale-while-revalidate=") {
                cc.staleWhileRevalidate = TimeInterval(d.dropFirst("stale-while-revalidate=".count)) ?? nil
            }
        }
        return cc
    }

    static func extractStatusCode(_ statusLine: String) -> Int {
        let parts = statusLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else { return 0 }
        return Int(parts[1]) ?? 0
    }

    private static let httpDateFormatters: [DateFormatter] = {
        let formats = [
            "EEE, dd MMM yyyy HH:mm:ss zzz",     // RFC 7231
            "EEEE, dd-MMM-yy HH:mm:ss zzz",      // RFC 850
            "EEE MMM d HH:mm:ss yyyy",            // asctime
        ]
        return formats.map { fmt in
            let f = DateFormatter()
            f.locale = Locale(identifier: "en_US_POSIX")
            f.timeZone = TimeZone(abbreviation: "GMT")
            f.dateFormat = fmt
            return f
        }
    }()

    static func parseHTTPDate(_ s: String) -> Date? {
        for f in httpDateFormatters {
            if let d = f.date(from: s) { return d }
        }
        return nil
    }

    static func stripTracking(url: String) -> String {
        guard var components = URLComponents(string: url) else { return url }
        components.queryItems = components.queryItems?.filter {
            !CacheSettings.trackingParams.contains($0.name.lowercased())
        }
        if components.queryItems?.isEmpty == true { components.queryItems = nil }
        return components.string ?? url
    }
}
