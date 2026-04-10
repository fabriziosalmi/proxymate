//
//  AppState.swift
//  proxymate
//

import Foundation
import Combine

@MainActor
final class AppState: ObservableObject {

    // MARK: - Published state

    @Published var proxies: [ProxyConfig] = []
    @Published var rules: [WAFRule] = []
    @Published var privacy = PrivacySettings()
    @Published var selectedProxyID: ProxyConfig.ID?
    @Published var isEnabled: Bool = false
    @Published var isBusy: Bool = false
    @Published var localPort: UInt16?
    @Published var logs: [LogEntry] = []
    @Published var stats = Stats()

    struct Stats {
        var requestsAllowed: Int = 0
        var requestsBlocked: Int = 0
        var privacyActions: Int = 0
        var enabledSince: Date?
    }

    // MARK: - Persistence keys

    private let proxiesKey  = "proxymate.proxies.v1"
    private let rulesKey    = "proxymate.rules.v1"
    private let selectedKey = "proxymate.selected.v1"
    private let privacyKey  = "proxymate.privacy.v1"

    // MARK: - Local proxy

    private let localProxy = LocalProxy()

    // MARK: - Init

    init() {
        load()
        if proxies.isEmpty {
            proxies = [
                ProxyConfig(name: "Local Squid",      host: "127.0.0.1", port: 3128, applyToHTTPS: true),
                ProxyConfig(name: "Local mitmproxy",  host: "127.0.0.1", port: 8080, applyToHTTPS: true),
            ]
        }
        if selectedProxyID == nil {
            selectedProxyID = proxies.first?.id
        }
        log(.info, "Proxymate ready")

        // Load persisted logs from disk
        Task { [weak self] in
            let persisted = await PersistentLogger.shared.loadPersistedLogs(limit: 200)
            await MainActor.run {
                guard let self else { return }
                // Merge: persisted go behind current in-memory entries
                let existingIDs = Set(self.logs.map(\.id))
                let fresh = persisted.filter { !existingIDs.contains($0.id) }
                self.logs.append(contentsOf: fresh)
            }
        }

        // Bridge LocalProxy events into MainActor state.
        localProxy.onEvent = { [weak self] event in
            Task { @MainActor [weak self] in
                self?.handle(event: event)
            }
        }
    }

    // MARK: - Selection

    var selectedProxy: ProxyConfig? {
        guard let id = selectedProxyID else { return nil }
        return proxies.first { $0.id == id }
    }

    func select(_ id: ProxyConfig.ID) {
        selectedProxyID = id
        save()
        if isEnabled, let p = selectedProxy, let port = UInt16(exactly: p.port) {
            localProxy.updateUpstream(.init(host: p.host, port: port))
            log(.info, "Switched upstream to \(p.name)")
        }
    }

    // MARK: - Toggle

    func toggle() async {
        if isEnabled { await disable() } else { await enable() }
    }

    func enable() async {
        guard let proxy = selectedProxy else {
            log(.warn, "No proxy selected")
            return
        }
        guard let upstreamPort = UInt16(exactly: proxy.port) else {
            log(.error, "Invalid upstream port \(proxy.port)")
            return
        }

        isBusy = true
        defer { isBusy = false }

        let port: UInt16
        do {
            port = try await startLocalProxy(
                upstream: .init(host: proxy.host, port: upstreamPort),
                rules: rules,
                privacy: privacy
            )
        } catch {
            log(.error, "Local proxy start failed: \(error.localizedDescription)")
            return
        }
        localPort = port

        let synthetic = ProxyConfig(
            name: "Proxymate (local)",
            host: "127.0.0.1",
            port: Int(port),
            applyToHTTPS: true
        )
        do {
            try await ProxyManager.enable(proxy: synthetic)
        } catch {
            log(.error, "System proxy apply failed: \(error.localizedDescription)")
            localProxy.stop()
            localPort = nil
            return
        }

        isEnabled = true
        stats.enabledSince = Date()
        log(.info, "Enabled — local 127.0.0.1:\(port) → upstream \(proxy.name) (\(proxy.host):\(proxy.port))")
    }

    func disable() async {
        isBusy = true
        defer { isBusy = false }
        do { try await ProxyManager.disable() } catch {
            log(.error, "System proxy disable failed: \(error.localizedDescription)")
        }
        localProxy.stop()
        localPort = nil
        isEnabled = false
        stats.enabledSince = nil
        log(.info, "Disabled")
    }

    private func startLocalProxy(upstream: LocalProxy.Upstream,
                                 rules: [WAFRule],
                                 privacy: PrivacySettings) async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<UInt16, Error>) in
            localProxy.start(upstream: upstream, rules: rules, privacy: privacy) { result in
                cont.resume(with: result)
            }
        }
    }

    // MARK: - LocalProxy events

    private func handle(event: LocalProxy.Event) {
        switch event {
        case .started(let port):
            log(.info, "Local proxy listening on 127.0.0.1:\(port)")
        case .stopped:
            log(.info, "Local proxy stopped")
        case .allowed(let host, let method):
            stats.requestsAllowed += 1
            log(.info, "\(method) \(host)", host: host)
        case .blocked(let host, let ruleName):
            stats.requestsBlocked += 1
            log(.warn, "BLOCKED \(host) — \(ruleName)", host: host)
        case .privacyStripped(let host, let actions):
            stats.privacyActions += 1
            log(.info, "Privacy [\(actions.joined(separator: ", "))] \(host)", host: host)
        case .log(let level, let message):
            log(level, message)
        }
    }

    // MARK: - Privacy

    func updatePrivacy(_ p: PrivacySettings) {
        privacy = p
        save()
        if isEnabled { localProxy.updatePrivacy(privacy) }
    }

    // MARK: - Proxy CRUD

    func addProxy(_ p: ProxyConfig) { proxies.append(p); save() }

    func removeProxy(_ id: ProxyConfig.ID) {
        proxies.removeAll { $0.id == id }
        if selectedProxyID == id { selectedProxyID = proxies.first?.id }
        save()
    }

    func updateProxy(_ p: ProxyConfig) {
        if let i = proxies.firstIndex(where: { $0.id == p.id }) {
            proxies[i] = p; save()
        }
    }

    // MARK: - Rule CRUD

    func addRule(_ r: WAFRule) {
        rules.append(r); save()
        if isEnabled { localProxy.updateRules(rules) }
    }

    func removeRule(_ id: WAFRule.ID) {
        rules.removeAll { $0.id == id }; save()
        if isEnabled { localProxy.updateRules(rules) }
    }

    func toggleRule(_ id: WAFRule.ID) {
        if let i = rules.firstIndex(where: { $0.id == id }) {
            rules[i].enabled.toggle(); save()
            if isEnabled { localProxy.updateRules(rules) }
        }
    }

    func loadExampleRules() {
        let existingPatterns = Set(rules.map { $0.pattern.lowercased() })
        let new = WAFRule.examples.filter { !existingPatterns.contains($0.pattern.lowercased()) }
        rules.append(contentsOf: new); save()
        if isEnabled { localProxy.updateRules(rules) }
        log(.info, "Loaded \(new.count) example rules")
    }

    // MARK: - Logging

    func log(_ level: LogEntry.Level, _ message: String, host: String = "") {
        let entry = LogEntry(timestamp: Date(), level: level, message: message, host: host)
        logs.insert(entry, at: 0)
        if logs.count > 500 { logs = Array(logs.prefix(500)) }
        PersistentLogger.shared.write(entry)
    }

    func clearLogs() { logs.removeAll() }

    // MARK: - Persistence

    private func save() {
        let d = UserDefaults.standard
        if let data = try? JSONEncoder().encode(proxies) { d.set(data, forKey: proxiesKey) }
        if let data = try? JSONEncoder().encode(rules)   { d.set(data, forKey: rulesKey) }
        if let data = try? JSONEncoder().encode(privacy) { d.set(data, forKey: privacyKey) }
        if let id = selectedProxyID { d.set(id.uuidString, forKey: selectedKey) }
    }

    private func load() {
        let d = UserDefaults.standard
        if let data = d.data(forKey: proxiesKey),
           let arr = try? JSONDecoder().decode([ProxyConfig].self, from: data) {
            proxies = arr
        }
        if let data = d.data(forKey: rulesKey),
           let arr = try? JSONDecoder().decode([WAFRule].self, from: data) {
            rules = arr
        }
        if let data = d.data(forKey: privacyKey),
           let p = try? JSONDecoder().decode(PrivacySettings.self, from: data) {
            privacy = p
        }
        if let s = d.string(forKey: selectedKey), let uuid = UUID(uuidString: s) {
            selectedProxyID = uuid
        }
    }
}
