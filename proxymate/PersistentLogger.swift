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
    private var buffer: [LogEntry] = []
    private var flushTimer: DispatchSourceTimer?

    init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        logDir = appSupport.appendingPathComponent("Proxymate/logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
        openCurrentFile()
        startFlushTimer()
    }

    // MARK: - Write (batched)

    func write(_ entry: LogEntry) {
        queue.async { [weak self] in
            guard let self else { return }

            // OSLog mirror (immediate — survives crashes)
            switch entry.level {
            case .info:  self.osLog.info("\(entry.message, privacy: .public)")
            case .warn:  self.osLog.warning("\(entry.message, privacy: .public)")
            case .error: self.osLog.error("\(entry.message, privacy: .public)")
            }

            // Buffer for batch JSONL write
            self.buffer.append(entry)

            // Flush immediately on errors or when buffer is large
            if entry.level == .error || self.buffer.count >= 50 {
                self.flushBuffer()
            }
        }
    }

    /// Force-flush any buffered entries synchronously. Called from
    /// applicationWillTerminate so the last few log lines before quit
    /// reach disk — under normal operation the 0.5s timer covers this,
    /// but a quit within the tick window would drop them.
    func flushNow() {
        queue.sync { self.flushBuffer() }
    }

    private func flushBuffer() {
        // Must be called on self.queue
        guard !buffer.isEmpty else { return }
        var batchData = Data()
        batchData.reserveCapacity(buffer.count * 200) // ~200 bytes per entry estimate
        for entry in buffer {
            if var data = try? encoder.encode(entry) {
                data.append(contentsOf: "\n".utf8)
                batchData.append(data)
            }
        }
        buffer.removeAll(keepingCapacity: true)
        fileHandle?.write(batchData)
        currentFileSize += batchData.count
        if currentFileSize >= maxFileSize { rotate() }
    }

    private func startFlushTimer() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 0.5, repeating: 0.5)
        timer.setEventHandler { [weak self] in self?.flushBuffer() }
        timer.resume()
        flushTimer = timer
    }

    deinit {
        // Stop the repeating timer so the queue doesn't keep firing at a
        // dangling self, and flush any remaining buffered entries.
        flushTimer?.cancel()
        flushTimer = nil
        queue.sync {
            self.flushBuffer()
            try? self.fileHandle?.close()
            self.fileHandle = nil
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
