//
//  DiskCache.swift
//  proxymate
//
//  L2 disk cache backed by SQLite for metadata + filesystem for bodies.
//  Sits behind CacheManager: on L1 miss, checks L2. On L1 eviction,
//  demotes to L2. Thread-safe via serial queue.
//

import Foundation
import SQLite3

nonisolated struct DiskCacheSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var maxSizeMB: Int = 512
    var directory: String = ""  // empty = default ~/Library/Caches/Proxymate/http

    var resolvedDirectory: URL {
        if !directory.isEmpty { return URL(fileURLWithPath: directory) }
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return caches.appendingPathComponent("Proxymate/http", isDirectory: true)
    }
}

nonisolated final class DiskCache: @unchecked Sendable {

    static let shared = DiskCache()

    private let queue = DispatchQueue(label: "proxymate.diskcache", qos: .utility)
    private var db: OpaquePointer?
    private var settings = DiskCacheSettings()
    private var currentSizeBytes: Int64 = 0
    private var _stats = Stats()

    struct Stats: Sendable {
        var hits: Int = 0
        var misses: Int = 0
        var writes: Int = 0
        var evictions: Int = 0
        var sizeBytes: Int64 = 0
    }

    var stats: Stats { queue.sync { _stats } }

    // MARK: - Configure

    func configure(_ s: DiskCacheSettings) {
        queue.async { [weak self] in
            guard let self else { return }
            self.settings = s
            if s.enabled {
                self.openDB()
            } else {
                self.closeDB()
            }
        }
    }

    // MARK: - Lookup

    func lookup(key: String) -> CacheManager.LookupResult? {
        guard settings.enabled, db != nil else { return nil }
        return queue.sync {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            let sql = "SELECT status_line, headers, body_hash, expires_at FROM cache WHERE key = ? AND expires_at > ? LIMIT 1"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
            sqlite3_bind_text(stmt, 1, key, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            sqlite3_bind_double(stmt, 2, Date().timeIntervalSince1970)

            guard sqlite3_step(stmt) == SQLITE_ROW else {
                _stats.misses += 1
                return nil
            }

            let statusLine = String(cString: sqlite3_column_text(stmt, 0))
            let headers = String(cString: sqlite3_column_text(stmt, 1))
            let bodyHash = String(cString: sqlite3_column_text(stmt, 2))

            guard let body = readBody(hash: bodyHash) else {
                _stats.misses += 1
                return nil
            }

            // Update last_accessed
            updateAccess(key: key)
            _stats.hits += 1

            return CacheManager.LookupResult(
                statusLine: statusLine,
                responseHeaders: headers,
                body: body
            )
        }
    }

    // MARK: - Store

    func store(key: String, statusLine: String, headers: String, body: Data,
               maxAge: TimeInterval) {
        guard settings.enabled, db != nil else { return }
        queue.async { [weak self] in
            guard let self else { return }

            let bodyHash = Self.sha256Hex(body)
            self.writeBody(hash: bodyHash, data: body)

            let sql = """
            INSERT OR REPLACE INTO cache (key, status_line, headers, body_hash, body_size, expires_at, last_accessed)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_prepare_v2(self.db, sql, -1, &stmt, nil) == SQLITE_OK else { return }

            sqlite3_bind_text(stmt, 1, key, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            sqlite3_bind_text(stmt, 2, statusLine, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            sqlite3_bind_text(stmt, 3, headers, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            sqlite3_bind_text(stmt, 4, bodyHash, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            sqlite3_bind_int64(stmt, 5, Int64(body.count))
            sqlite3_bind_double(stmt, 6, Date().timeIntervalSince1970 + maxAge)
            sqlite3_bind_double(stmt, 7, Date().timeIntervalSince1970)

            sqlite3_step(stmt)
            self.currentSizeBytes += Int64(body.count)
            self._stats.writes += 1
            self._stats.sizeBytes = self.currentSizeBytes
            self.evictIfNeeded()
        }
    }

    // MARK: - Purge

    func purgeAll() {
        queue.async { [weak self] in
            guard let self, self.db != nil else { return }
            sqlite3_exec(self.db, "DELETE FROM cache", nil, nil, nil)
            // Remove body files
            let dir = self.settings.resolvedDirectory.appendingPathComponent("bodies")
            try? FileManager.default.removeItem(at: dir)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            self.currentSizeBytes = 0
            self._stats = Stats()
        }
    }

    // MARK: - DB management

    private func openDB() {
        let dir = settings.resolvedDirectory
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let bodiesDir = dir.appendingPathComponent("bodies")
        try? FileManager.default.createDirectory(at: bodiesDir, withIntermediateDirectories: true)

        let dbPath = dir.appendingPathComponent("cache.db").path
        guard sqlite3_open(dbPath, &db) == SQLITE_OK else { return }

        let createTable = """
        CREATE TABLE IF NOT EXISTS cache (
            key TEXT PRIMARY KEY,
            status_line TEXT NOT NULL,
            headers TEXT NOT NULL,
            body_hash TEXT NOT NULL,
            body_size INTEGER NOT NULL DEFAULT 0,
            expires_at REAL NOT NULL,
            last_accessed REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_expires ON cache(expires_at);
        CREATE INDEX IF NOT EXISTS idx_accessed ON cache(last_accessed);
        """
        sqlite3_exec(db, createTable, nil, nil, nil)
        computeCurrentSize()
    }

    private func closeDB() {
        if let db { sqlite3_close(db) }
        db = nil
    }

    private func computeCurrentSize() {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "SELECT COALESCE(SUM(body_size),0) FROM cache", -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else { return }
        currentSizeBytes = sqlite3_column_int64(stmt, 0)
        _stats.sizeBytes = currentSizeBytes
    }

    private func updateAccess(key: String) {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "UPDATE cache SET last_accessed = ? WHERE key = ?", -1, &stmt, nil) == SQLITE_OK else { return }
        sqlite3_bind_double(stmt, 1, Date().timeIntervalSince1970)
        sqlite3_bind_text(stmt, 2, key, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        sqlite3_step(stmt)
    }

    private func evictIfNeeded() {
        let maxBytes = Int64(settings.maxSizeMB) * 1024 * 1024
        guard currentSizeBytes > maxBytes else { return }

        // Delete expired first (prepared statement, not string interpolation)
        var expStmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "DELETE FROM cache WHERE expires_at < ?", -1, &expStmt, nil) == SQLITE_OK {
            sqlite3_bind_double(expStmt, 1, Date().timeIntervalSince1970)
            sqlite3_step(expStmt)
        }
        sqlite3_finalize(expStmt)
        computeCurrentSize()
        if currentSizeBytes <= maxBytes { return }

        // LRU eviction
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db,
            "SELECT key, body_hash, body_size FROM cache ORDER BY last_accessed ASC LIMIT 100",
            -1, &stmt, nil) == SQLITE_OK else { return }

        var keysToDelete: [(String, String, Int64)] = []
        while sqlite3_step(stmt) == SQLITE_ROW && currentSizeBytes > maxBytes {
            let key = String(cString: sqlite3_column_text(stmt, 0))
            let hash = String(cString: sqlite3_column_text(stmt, 1))
            let size = sqlite3_column_int64(stmt, 2)
            keysToDelete.append((key, hash, size))
            currentSizeBytes -= size
            _stats.evictions += 1
        }

        for (key, hash, _) in keysToDelete {
            var delStmt: OpaquePointer?
            sqlite3_prepare_v2(db, "DELETE FROM cache WHERE key = ?", -1, &delStmt, nil)
            sqlite3_bind_text(delStmt, 1, key, -1, nil)
            sqlite3_step(delStmt)
            sqlite3_finalize(delStmt)
            deleteBody(hash: hash)
        }
        _stats.sizeBytes = currentSizeBytes
    }

    // MARK: - Body file storage

    private func bodyPath(hash: String) -> URL {
        let shard = String(hash.prefix(2))
        let dir = settings.resolvedDirectory
            .appendingPathComponent("bodies/\(shard)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent(hash)
    }

    private func writeBody(hash: String, data: Data) {
        try? data.write(to: bodyPath(hash: hash), options: .atomic)
    }

    private func readBody(hash: String) -> Data? {
        try? Data(contentsOf: bodyPath(hash: hash))
    }

    private func deleteBody(hash: String) {
        try? FileManager.default.removeItem(at: bodyPath(hash: hash))
    }

    // MARK: - SHA256

    private static func sha256Hex(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { buf in
            _ = CC_SHA256(buf.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    deinit {
        closeDB()
    }
}

import CommonCrypto
