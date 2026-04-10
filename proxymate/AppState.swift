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
    @Published var cacheSettings = CacheSettings()
    @Published var mitmSettings = MITMSettings()
    @Published var blacklistSources: [BlacklistSource] = []
    @Published var exfiltrationPacks: [ExfiltrationPack] = []
    @Published var selectedProxyID: ProxyConfig.ID?
    @Published var isEnabled: Bool = false
    @Published var isBusy: Bool = false
    @Published var localPort: UInt16?
    @Published var logs: [LogEntry] = []
    @Published var stats = Stats()

    struct Stats {
        var requestsAllowed: Int = 0
        var requestsBlocked: Int = 0
        var blacklistBlocked: Int = 0
        var exfiltrationBlocked: Int = 0
        var privacyActions: Int = 0
        var cacheHits: Int = 0
        var cacheMisses: Int = 0
        var mitmIntercepted: Int = 0
        var enabledSince: Date?
    }

    // MARK: - Persistence keys

    private let proxiesKey     = "proxymate.proxies.v1"
    private let rulesKey       = "proxymate.rules.v1"
    private let selectedKey    = "proxymate.selected.v1"
    private let privacyKey     = "proxymate.privacy.v1"
    private let cacheKey       = "proxymate.cache.v1"
    private let mitmKey        = "proxymate.mitm.v1"
    private let blacklistKey   = "proxymate.blacklists.v1"
    private let exfilPacksKey  = "proxymate.exfiltration.v1"

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
        if exfiltrationPacks.isEmpty {
            exfiltrationPacks = ExfiltrationPack.builtIn
        }
        log(.info, "Proxymate ready")

        // Configure cache
        CacheManager.shared.configure(cacheSettings)

        // Check MITM CA status
        mitmSettings.caInstalled = TLSManager.shared.isCAInstalled

        // Load cached blacklists from disk, then refresh stale ones
        BlacklistManager.shared.loadCachedSources(blacklistSources)
        refreshStaleBlacklists()
        scheduleBlacklistRefresh()

        // Compile exfiltration patterns
        ExfiltrationScanner.shared.loadPacks(exfiltrationPacks)

        // Load persisted logs from disk
        Task { [weak self] in
            let persisted = await PersistentLogger.shared.loadPersistedLogs(limit: 200)
            await MainActor.run {
                guard let self else { return }
                let existingIDs = Set(self.logs.map(\.id))
                let fresh = persisted.filter { !existingIDs.contains($0.id) }
                self.logs.append(contentsOf: fresh)
            }
        }

        // Bridge LocalProxy events
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
            log(.warn, "No proxy selected"); return
        }
        guard let upstreamPort = UInt16(exactly: proxy.port) else {
            log(.error, "Invalid upstream port \(proxy.port)"); return
        }

        isBusy = true
        defer { isBusy = false }

        let port: UInt16
        do {
            port = try await startLocalProxy(
                upstream: .init(host: proxy.host, port: upstreamPort),
                rules: rules,
                privacy: privacy,
                blacklistSources: blacklistSources,
                mitm: mitmSettings
            )
        } catch {
            log(.error, "Local proxy start failed: \(error.localizedDescription)"); return
        }
        localPort = port

        let synthetic = ProxyConfig(
            name: "Proxymate (local)", host: "127.0.0.1",
            port: Int(port), applyToHTTPS: true
        )
        do {
            try await ProxyManager.enable(proxy: synthetic)
        } catch {
            log(.error, "System proxy apply failed: \(error.localizedDescription)")
            localProxy.stop(); localPort = nil; return
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
                                 privacy: PrivacySettings,
                                 blacklistSources: [BlacklistSource],
                                 mitm: MITMSettings) async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<UInt16, Error>) in
            localProxy.start(upstream: upstream, rules: rules, privacy: privacy,
                             blacklistSources: blacklistSources, mitm: mitm) { result in
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
        case .blacklisted(let host, let sourceName, let category):
            stats.blacklistBlocked += 1
            log(.warn, "BLACKLIST \(host) — \(sourceName) [\(category)]", host: host)
        case .exfiltration(let host, let patternName, let severity, let preview):
            stats.exfiltrationBlocked += 1
            log(.error, "EXFILTRATION [\(severity)] \(patternName) → \(host) | \(preview)", host: host)
        case .privacyStripped(let host, let actions):
            stats.privacyActions += 1
            log(.info, "Privacy [\(actions.joined(separator: ", "))] \(host)", host: host)
        case .cacheHit(let host, _):
            stats.cacheHits += 1
            log(.info, "CACHE HIT \(host)", host: host)
        case .cacheMiss(_, _):
            stats.cacheMisses += 1
        case .mitmIntercepted(let host):
            stats.mitmIntercepted += 1
            log(.info, "MITM \(host)", host: host)
        case .log(let level, let message):
            log(level, message)
        }
    }

    // MARK: - Privacy

    func updatePrivacy(_ p: PrivacySettings) {
        privacy = p; save()
        if isEnabled { localProxy.updatePrivacy(privacy) }
    }

    // MARK: - Cache

    func updateCache(_ s: CacheSettings) {
        cacheSettings = s; save()
        CacheManager.shared.configure(s)
    }

    func purgeCache() {
        CacheManager.shared.purgeAll()
        log(.info, "Cache purged")
    }

    // MARK: - MITM

    func updateMITM(_ s: MITMSettings) {
        mitmSettings = s; save()
        if isEnabled { localProxy.updateMITM(s) }
    }

    func generateMITMCA() {
        do {
            _ = try TLSManager.shared.generateCA()
            mitmSettings.caInstalled = true
            save()
            log(.info, "Root CA generated and stored in Keychain")
        } catch {
            log(.error, "CA generation failed: \(error.localizedDescription)")
        }
    }

    func removeMITMCA() {
        TLSManager.shared.removeCA()
        mitmSettings.caInstalled = false
        mitmSettings.enabled = false
        save()
        if isEnabled { localProxy.updateMITM(mitmSettings) }
        log(.info, "Root CA removed from Keychain")
    }

    func trustMITMCA() {
        TLSManager.shared.promptUserToTrust()
    }

    // MARK: - Blacklists

    func addBlacklistSource(_ s: BlacklistSource) {
        blacklistSources.append(s); save()
        if isEnabled { localProxy.updateBlacklistSources(blacklistSources) }
    }

    func removeBlacklistSource(_ id: UUID) {
        blacklistSources.removeAll { $0.id == id }
        BlacklistManager.shared.clearSource(id)
        save()
        if isEnabled { localProxy.updateBlacklistSources(blacklistSources) }
    }

    func toggleBlacklistSource(_ id: UUID) {
        if let i = blacklistSources.firstIndex(where: { $0.id == id }) {
            blacklistSources[i].enabled.toggle()
            save()
            if isEnabled { localProxy.updateBlacklistSources(blacklistSources) }
        }
    }

    func loadBuiltInBlacklists() {
        let existing = Set(blacklistSources.map { $0.url.lowercased() })
        let new = BlacklistSource.builtIn.filter { !existing.contains($0.url.lowercased()) }
        blacklistSources.append(contentsOf: new)
        save()
        if isEnabled { localProxy.updateBlacklistSources(blacklistSources) }
        log(.info, "Added \(new.count) built-in blacklist sources")
    }

    func refreshBlacklist(_ id: UUID) {
        guard let source = blacklistSources.first(where: { $0.id == id }) else { return }
        log(.info, "Refreshing \(source.name)...")
        BlacklistManager.shared.refresh(source: source) { [weak self] result in
            Task { @MainActor [weak self] in
                guard let self else { return }
                switch result {
                case .success(let count):
                    if let i = self.blacklistSources.firstIndex(where: { $0.id == id }) {
                        self.blacklistSources[i].lastUpdated = Date()
                        self.blacklistSources[i].entryCount = count
                        self.save()
                    }
                    self.log(.info, "\(source.name): \(count) entries loaded")
                case .failure(let err):
                    self.log(.error, "\(source.name) refresh failed: \(err.localizedDescription)")
                }
            }
        }
    }

    func refreshAllBlacklists() {
        for source in blacklistSources where source.enabled {
            refreshBlacklist(source.id)
        }
    }

    /// Refresh blacklists that haven't been updated in over 6 hours.
    private func refreshStaleBlacklists() {
        let sixHours: TimeInterval = 6 * 3600
        for source in blacklistSources where source.enabled {
            let stale = source.lastUpdated.map { Date().timeIntervalSince($0) > sixHours } ?? true
            if stale { refreshBlacklist(source.id) }
        }
    }

    private var blacklistTimer: Timer?

    /// Schedule a repeating timer that refreshes stale blacklists every 6 hours.
    private func scheduleBlacklistRefresh() {
        blacklistTimer?.invalidate()
        blacklistTimer = Timer.scheduledTimer(withTimeInterval: 6 * 3600, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.refreshStaleBlacklists()
            }
        }
    }

    // MARK: - Exfiltration

    func toggleExfiltrationPack(_ id: String) {
        if let i = exfiltrationPacks.firstIndex(where: { $0.id == id }) {
            exfiltrationPacks[i].enabled.toggle()
            save()
            ExfiltrationScanner.shared.loadPacks(exfiltrationPacks)
        }
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

    func addAllowRule(_ host: String) {
        let rule = WAFRule(name: "Allow \(host)", kind: .allowDomain,
                           pattern: host, category: "Allowlist")
        addRule(rule)
        log(.info, "Allowlisted \(host)")
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
        if let data = try? JSONEncoder().encode(cacheSettings) { d.set(data, forKey: cacheKey) }
        if let data = try? JSONEncoder().encode(mitmSettings) { d.set(data, forKey: mitmKey) }
        if let data = try? JSONEncoder().encode(blacklistSources) { d.set(data, forKey: blacklistKey) }
        if let data = try? JSONEncoder().encode(exfiltrationPacks) { d.set(data, forKey: exfilPacksKey) }
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
        if let data = d.data(forKey: cacheKey),
           let c = try? JSONDecoder().decode(CacheSettings.self, from: data) {
            cacheSettings = c
        }
        if let data = d.data(forKey: mitmKey),
           let m = try? JSONDecoder().decode(MITMSettings.self, from: data) {
            mitmSettings = m
        }
        if let data = d.data(forKey: blacklistKey),
           let arr = try? JSONDecoder().decode([BlacklistSource].self, from: data) {
            blacklistSources = arr
        }
        if let data = d.data(forKey: exfilPacksKey),
           let arr = try? JSONDecoder().decode([ExfiltrationPack].self, from: data) {
            exfiltrationPacks = arr
        }
        if let s = d.string(forKey: selectedKey), let uuid = UUID(uuidString: s) {
            selectedProxyID = uuid
        }
    }
}
