//
//  PersistentLogger.swift
//  proxymate
//
//  Writes log entries to rotating JSONL files + mirrors to OSLog.
//  Thread-safe (serial queue). Reads happen from AppState on MainActor
//  via loadPersistedLogs().
//

import Foundation
import OSLog

nonisolated final class PersistentLogger: @unchecked Sendable {

    static let shared = PersistentLogger()

    private let queue = DispatchQueue(label: "proxymate.logger", qos: .utility)
    private let osLog = Logger(subsystem: "com.fabriziosalmi.proxymate", category: "proxy")
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    private let logDir: URL
    private let maxFileSize: Int = 2 * 1024 * 1024   // 2 MB per file
    private let maxFiles: Int = 5                      // keep 5 rotations → 10 MB total
    private var fileHandle: FileHandle?
    private var currentFileSize: Int = 0

    init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        logDir = appSupport.appendingPathComponent("Proxymate/logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
        openCurrentFile()
    }

    // MARK: - Write

    func write(_ entry: LogEntry) {
        queue.async { [weak self] in
            guard let self else { return }

            // OSLog mirror
            switch entry.level {
            case .info:  self.osLog.info("\(entry.message, privacy: .public)")
            case .warn:  self.osLog.warning("\(entry.message, privacy: .public)")
            case .error: self.osLog.error("\(entry.message, privacy: .public)")
            }

            // JSONL
            guard var data = try? self.encoder.encode(entry) else { return }
            data.append(contentsOf: "\n".utf8)
            self.fileHandle?.write(data)
            self.currentFileSize += data.count

            if self.currentFileSize >= self.maxFileSize {
                self.rotate()
            }
        }
    }

    // MARK: - Read persisted logs (called from MainActor, executes on queue)

    func loadPersistedLogs(limit: Int = 200) async -> [LogEntry] {
        await withCheckedContinuation { (cont: CheckedContinuation<[LogEntry], Never>) in
            queue.async { [weak self] in
                guard let self else { cont.resume(returning: []); return }
                self.fileHandle?.synchronizeFile()
                var entries: [LogEntry] = []
                let files = self.sortedLogFiles()
                outer: for file in files {
                    guard let data = try? Data(contentsOf: file) else { continue }
                    let lines = data.split(separator: UInt8(ascii: "\n"))
                    for line in lines.reversed() {
                        if let entry = try? self.decoder.decode(LogEntry.self, from: Data(line)) {
                            entries.append(entry)
                            if entries.count >= limit { break outer }
                        }
                    }
                }
                cont.resume(returning: entries)
            }
        }
    }

    // MARK: - File management

    private func currentFilePath() -> URL {
        logDir.appendingPathComponent("proxymate.log")
    }

    private func openCurrentFile() {
        let path = currentFilePath()
        if !FileManager.default.fileExists(atPath: path.path) {
            FileManager.default.createFile(atPath: path.path, contents: nil)
        }
        fileHandle = try? FileHandle(forWritingTo: path)
        fileHandle?.seekToEndOfFile()
        currentFileSize = Int(fileHandle?.offsetInFile ?? 0)
    }

    private func rotate() {
        fileHandle?.closeFile()
        fileHandle = nil

        let fm = FileManager.default
        let current = currentFilePath()
        let ts = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let rotated = logDir.appendingPathComponent("proxymate-\(ts).log")
        try? fm.moveItem(at: current, to: rotated)

        // Prune old files beyond maxFiles
        let files = sortedLogFiles().filter { $0.lastPathComponent != "proxymate.log" }
        if files.count > maxFiles {
            for old in files.suffix(from: maxFiles) {
                try? fm.removeItem(at: old)
            }
        }

        openCurrentFile()
    }

    /// Returns log files sorted newest first.
    private func sortedLogFiles() -> [URL] {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(at: logDir, includingPropertiesForKeys: [.contentModificationDateKey]) else {
            return []
        }
        return files
            .filter { $0.pathExtension == "log" }
            .sorted { a, b in
                let da = (try? a.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                let db = (try? b.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                return da > db
            }
    }
}
