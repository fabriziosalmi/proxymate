//
//  ProcessResolver.swift
//  proxymate
//
//  Maps local TCP connections to the originating process (PID → bundle ID).
//  Uses native proc_pidinfo / libproc instead of shelling out to lsof.
//  Caches results in an LRU with 5-second TTL to avoid syscall on every request.
//

import Foundation
import Darwin

nonisolated struct ProcessRule: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var bundleId: String         // e.g. "com.slack.Slack"
    var appName: String          // display name
    var action: Action
    var enabled: Bool = true

    enum Action: String, Codable, CaseIterable, Identifiable, Sendable {
        case allow  = "Always Allow"
        case block  = "Always Block"
        case direct = "Direct (bypass proxy)"
        var id: String { rawValue }
    }
}

nonisolated final class ProcessResolver: @unchecked Sendable {

    static let shared = ProcessResolver()

    private let queue = DispatchQueue(label: "proxymate.processresolver", qos: .utility)
    private var cache: [UInt16: CacheEntry] = [:]
    private let cacheTTL: TimeInterval = 5
    private let maxCacheSize = 512

    struct CacheEntry {
        let pid: Int32
        let bundleId: String
        let timestamp: Date
        var isExpired: Bool { Date().timeIntervalSince(timestamp) > 5 }
    }

    struct ProcessInfo: Sendable {
        let pid: Int32
        let bundleId: String
    }

    // MARK: - Resolve

    /// Resolve which process owns the given local source port.
    func resolve(localPort: UInt16) -> ProcessInfo? {
        // Check cache first
        if let cached = queue.sync(execute: { cache[localPort] }), !cached.isExpired {
            return ProcessInfo(pid: cached.pid, bundleId: cached.bundleId)
        }

        // Use native proc_pidinfo to find the process
        guard let (pid, bundleId) = findPIDForPort(localPort) else { return nil }

        let entry = CacheEntry(pid: pid, bundleId: bundleId, timestamp: Date())
        queue.async { [weak self] in
            guard let self else { return }
            self.cache[localPort] = entry
            // LRU eviction: prune expired + cap size
            if self.cache.count > self.maxCacheSize {
                self.cache = self.cache.filter { !$0.value.isExpired }
            }
        }

        return ProcessInfo(pid: pid, bundleId: bundleId)
    }

    /// Check if a process is affected by any process rule.
    func checkRules(bundleId: String, rules: [ProcessRule]) -> ProcessRule.Action? {
        for rule in rules where rule.enabled {
            if bundleId.lowercased() == rule.bundleId.lowercased() ||
               bundleId.lowercased().contains(rule.bundleId.lowercased()) {
                return rule.action
            }
        }
        return nil
    }

    // MARK: - Native process lookup via proc_pidinfo

    /// Find which PID owns a local TCP port using proc_pidinfo (no shell, no lsof).
    private func findPIDForPort(_ port: UInt16) -> (Int32, String)? {
        // Get all PIDs on the system
        let bufferSize = proc_listallpids(nil, 0)
        guard bufferSize > 0 else { return nil }

        var pids = [Int32](repeating: 0, count: Int(bufferSize))
        let actual = proc_listallpids(&pids, Int32(MemoryLayout<Int32>.size * pids.count))
        guard actual > 0 else { return nil }

        let networkPort = port.bigEndian

        for i in 0..<Int(actual) {
            let pid = pids[i]
            guard pid > 0 else { continue }

            // Get file descriptor info size
            let fdSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            guard fdSize > 0 else { continue }

            let fdCount = fdSize / Int32(MemoryLayout<proc_fdinfo>.size)
            var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(fdCount))
            let actualFdSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, fdSize)
            guard actualFdSize > 0 else { continue }

            let actualFdCount = Int(actualFdSize) / MemoryLayout<proc_fdinfo>.size

            for j in 0..<actualFdCount {
                let fd = fds[j]
                guard fd.proc_fdtype == PROX_FDTYPE_SOCKET else { continue }

                var socketInfo = socket_fdinfo()
                let siSize = proc_pidfdinfo(pid, fd.proc_fd,
                                            PROC_PIDFDSOCKETINFO,
                                            &socketInfo,
                                            Int32(MemoryLayout<socket_fdinfo>.size))
                guard siSize == MemoryLayout<socket_fdinfo>.size else { continue }

                let si = socketInfo.psi
                // Check TCP + IPv4/IPv6
                guard si.soi_kind == SOCKINFO_TCP else { continue }

                let localPort4 = si.soi_proto.pri_tcp.tcpsi_ini.insi_lport
                if localPort4 == networkPort {
                    let bundleId = bundleIdForPID(pid) ?? processNameForPID(pid)
                    return (pid, bundleId)
                }
            }
        }
        return nil
    }

    private func processNameForPID(_ pid: Int32) -> String {
        var name = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        proc_name(pid, &name, UInt32(MAXPATHLEN))
        return String(cString: name)
    }

    private func bundleIdForPID(_ pid: Int32) -> String? {
        guard let app = NSRunningApplication(processIdentifier: pid) else { return nil }
        return app.bundleIdentifier
    }
}

import AppKit

// MARK: - App Icon Cache (#25)
// Extracts app icons on background thread and caches to disk.

extension ProcessResolver {

    private static let iconCacheDir: URL = {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let dir = caches.appendingPathComponent("Proxymate/icons", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    /// Get app icon for a bundle ID. Returns cached PNG or extracts async.
    func appIcon(bundleId: String, size: CGFloat = 32, completion: @escaping @Sendable (NSImage?) -> Void) {
        let cacheFile = Self.iconCacheDir.appendingPathComponent("\(bundleId).png")

        // Check disk cache first
        if let data = try? Data(contentsOf: cacheFile), let img = NSImage(data: data) {
            completion(img)
            return
        }

        // Extract on background thread
        DispatchQueue.global(qos: .utility).async {
            guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleId) else {
                completion(nil)
                return
            }
            let icon = NSWorkspace.shared.icon(forFile: appURL.path)
            icon.size = NSSize(width: size, height: size)

            // Cache to disk as PNG
            if let tiffData = icon.tiffRepresentation,
               let rep = NSBitmapImageRep(data: tiffData),
               let pngData = rep.representation(using: .png, properties: [:]) {
                try? pngData.write(to: cacheFile, options: .atomic)
            }
            completion(icon)
        }
    }
}
