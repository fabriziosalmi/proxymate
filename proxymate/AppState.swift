//
//  AppState.swift
//  proxymate
//

import Foundation
import Combine
import SwiftUI

@MainActor
final class AppState: ObservableObject {

    // MARK: - Published state

    @Published var proxies: [ProxyConfig] = []
    @Published var pools: [UpstreamPool] = []
    @Published var poolOverrides: [PoolOverride] = []
    @Published var poolHealth: [UUID: MemberHealth] = [:]
    @Published var rules: [WAFRule] = []
    @Published var privacy = PrivacySettings()
    @Published var cacheSettings = CacheSettings()
    @Published var mitmSettings = MITMSettings()
    @Published var allowlist: [AllowEntry] = []
    @Published var dnsSettings = DNSSettings()
    @Published var diskCacheSettings = DiskCacheSettings()
    @Published var metricsSettings = MetricsSettings()
    @Published var webhookSettings = WebhookSettings()
    @Published var cloudSyncSettings = CloudSyncSettings()
    @Published var socks5Settings = SOCKS5Settings()
    @Published var beaconingSettings = BeaconingSettings()
    @Published var c2Settings = C2Settings()
    @Published var loopBreakerSettings = LoopBreakerSettings()
    @Published var processRules: [ProcessRule] = []
    @Published var aiSettings = AISettings()
    @Published var aiProviderStats: [String: AIProviderStats] = [:]
    @Published var blacklistSources: [BlacklistSource] = []
    @Published var exfiltrationPacks: [ExfiltrationPack] = []
    @Published var selectedProxyID: ProxyConfig.ID?
    @Published var isEnabled: Bool = false
    @Published var isBusy: Bool = false
    @Published var localPort: UInt16?
    @Published var logs: [LogEntry] = []
    @Published var stats = Stats()
    let timeSeries = StatsTimeSeries()

    struct Stats {
        var requestsAllowed: Int = 0
        var requestsBlocked: Int = 0
        var blacklistBlocked: Int = 0
        var exfiltrationBlocked: Int = 0
        var privacyActions: Int = 0
        var cacheHits: Int = 0
        var cacheMisses: Int = 0
        var mitmIntercepted: Int = 0
        var aiRequests: Int = 0
        var aiBlocked: Int = 0
        var aiTotalCostUSD: Double = 0
        var beaconingAlerts: Int = 0
        var c2Detections: Int = 0
        var enabledSince: Date?
    }

    // MARK: - Persistence keys

    private let proxiesKey     = "proxymate.proxies.v1"
    private let poolsKey       = "proxymate.pools.v1"
    private let overridesKey   = "proxymate.overrides.v1"
    private let rulesKey       = "proxymate.rules.v1"
    private let selectedKey    = "proxymate.selected.v1"
    private let privacyKey     = "proxymate.privacy.v1"
    private let cacheKey       = "proxymate.cache.v1"
    private let mitmKey        = "proxymate.mitm.v1"
    private let socks5Key      = "proxymate.socks5.v1"
    private let beaconingKey   = "proxymate.beaconing.v1"
    private let c2Key          = "proxymate.c2.v1"
    private let loopBreakerKey = "proxymate.loopbreaker.v1"
    private let processRulesKey = "proxymate.processrules.v1"
    private let cloudSyncKey   = "proxymate.cloudsync.v1"
    private let diskCacheKey   = "proxymate.diskcache.v1"
    private let metricsKey     = "proxymate.metrics.v1"
    private let webhookKey     = "proxymate.webhook.v1"
    private let allowlistKey   = "proxymate.allowlist.v1"
    private let dnsKey         = "proxymate.dns.v1"
    private let aiSettingsKey  = "proxymate.ai.v1"
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
        NotificationManager.shared.setup()

        // Configure pool router
        PoolRouter.shared.configure(pools: pools, overrides: poolOverrides)
        PoolRouter.shared.onEvent = { [weak self] event in
            Task { @MainActor [weak self] in
                self?.handlePoolEvent(event)
            }
        }

        // Configure cache + AI tracker
        CacheManager.shared.configure(cacheSettings)
        AITracker.shared.configure(providers: AIProvider.builtIn, settings: aiSettings)
        DNSResolver.shared.configure(dnsSettings)
        DiskCache.shared.configure(diskCacheSettings)
        WebhookManager.shared.configure(webhookSettings)
        if metricsSettings.enabled {
            startMetrics()
        }
        BeaconingDetector.shared.configure(beaconingSettings)
        AgentLoopBreaker.shared.configure(loopBreakerSettings)
        if cloudSyncSettings.enabled {
            startCloudSync()
        }

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
                allowlist: allowlist,
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

        // Start SOCKS5 if enabled
        if socks5Settings.enabled {
            startSOCKS5()
        }
    }

    private let socks5Listener = SOCKS5Listener()

    private func startSOCKS5() {
        guard socks5Settings.port > 0 && socks5Settings.port <= 65535 else {
            log(.error, "Invalid SOCKS5 port: \(socks5Settings.port)")
            return
        }
        socks5Listener.onEvent = { [weak self] event in
            Task { @MainActor [weak self] in self?.handle(event: event) }
        }
        socks5Listener.start(port: UInt16(socks5Settings.port),
                              rules: rules, allowlist: allowlist,
                              blacklistSources: blacklistSources)
    }

    func disable() async {
        isBusy = true
        defer { isBusy = false }
        do { try await ProxyManager.disable() } catch {
            log(.error, "System proxy disable failed: \(error.localizedDescription)")
        }
        localProxy.stop()
        socks5Listener.stop()
        PoolRouter.shared.stop()
        blacklistTimer?.invalidate()
        blacklistTimer = nil
        localPort = nil
        isEnabled = false
        stats.enabledSince = nil
        log(.info, "Disabled")
    }

    private func startLocalProxy(upstream: LocalProxy.Upstream,
                                 rules: [WAFRule],
                                 allowlist: [AllowEntry],
                                 privacy: PrivacySettings,
                                 blacklistSources: [BlacklistSource],
                                 mitm: MITMSettings) async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<UInt16, Error>) in
            localProxy.start(upstream: upstream, rules: rules, allowlist: allowlist,
                             privacy: privacy, blacklistSources: blacklistSources,
                             mitm: mitm) { result in
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
            timeSeries.recordAllowed()
            log(.info, "\(method) \(host)", host: host)
        case .blocked(let host, let ruleName):
            stats.requestsBlocked += 1
            timeSeries.recordBlocked()
            log(.warn, "BLOCKED \(host) — \(ruleName)", host: host)
            NotificationManager.shared.notifyBlock(host: host, ruleName: ruleName)
            WebhookManager.shared.sendBlock(host: host, ruleName: ruleName)
        case .blacklisted(let host, let sourceName, let category):
            stats.blacklistBlocked += 1
            timeSeries.recordBlocked()
            log(.warn, "BLACKLIST \(host) — \(sourceName) [\(category)]", host: host)
            NotificationManager.shared.notifyBlock(host: host, ruleName: "\(sourceName) [\(category)]")
            WebhookManager.shared.sendBlock(host: host, ruleName: "\(sourceName) [\(category)]")
        case .exfiltration(let host, let patternName, let severity, let preview):
            stats.exfiltrationBlocked += 1
            log(.error, "EXFILTRATION [\(severity)] \(patternName) → \(host) | \(preview)", host: host)
            NotificationManager.shared.notifyExfiltration(host: host, patternName: patternName)
            WebhookManager.shared.sendExfiltration(host: host, patternName: patternName, severity: severity, preview: preview)
        case .privacyStripped(let host, let actions):
            stats.privacyActions += 1
            log(.info, "Privacy [\(actions.joined(separator: ", "))] \(host)", host: host)
        case .cacheHit(let host, _):
            stats.cacheHits += 1
            log(.info, "CACHE HIT \(host)", host: host)
        case .cacheMiss(_, _):
            stats.cacheMisses += 1
        case .agentDetected(let host, let agent, let indicator):
            log(.info, "AGENT \(agent) \(host) [\(indicator)]", host: host)
        case .mcpDetected(let host, let method):
            log(.info, "MCP \(method) → \(host)", host: host)
        case .mitmIntercepted(let host):
            stats.mitmIntercepted += 1
            log(.info, "MITM \(host)", host: host)
        case .beaconing(let host, let path, let interval, let count):
            stats.beaconingAlerts += 1
            log(.warn, "BEACONING \(host)\(path) every \(Int(interval))s (\(count)x)", host: host)
            NotificationManager.shared.notifyBlock(host: host, ruleName: "Beaconing detected")
            WebhookManager.shared.sendBlock(host: host, ruleName: "Beaconing: \(host)\(path) every \(Int(interval))s")
        case .c2Detected(let host, let framework, let indicator, let confidence):
            stats.c2Detections += 1
            log(.error, "C2 [\(confidence)] \(framework): \(indicator) → \(host)", host: host)
            NotificationManager.shared.notifyExfiltration(host: host, patternName: "C2: \(framework)")
            WebhookManager.shared.sendExfiltration(host: host, patternName: "C2: \(framework)",
                                                    severity: confidence, preview: indicator)
        case .aiDetected(let host, let provider):
            stats.aiRequests += 1
            log(.info, "AI \(provider) \(host)", host: host)
        case .aiBlocked(let host, let provider, let reason):
            stats.aiBlocked += 1
            log(.warn, "AI BLOCKED \(provider) \(host) — \(reason)", host: host)
            NotificationManager.shared.notifyBudget(provider: provider, reason: reason)
            WebhookManager.shared.sendBudget(provider: provider, reason: reason)
        case .aiUsage(let provider, let model, let prompt, let completion, let cost):
            stats.aiTotalCostUSD += cost
            aiProviderStats = AITracker.shared.getStats()
            AgentLoopBreaker.shared.recordCost(cost)
            log(.info, "AI \(provider)/\(model): \(prompt)+\(completion) tokens, $\(String(format: "%.4f", cost))")
        case .log(let level, let message):
            log(level, message)
        }
        syncMetricsSnapshot()
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

    // MARK: - AI

    func updateAISettings(_ s: AISettings) {
        aiSettings = s; save()
        AITracker.shared.updateSettings(s)
    }

    func resetAIStats() {
        AITracker.shared.resetStats()
        aiProviderStats.removeAll()
        stats.aiRequests = 0
        stats.aiBlocked = 0
        stats.aiTotalCostUSD = 0
    }

    // MARK: - Disk cache, Metrics, Webhooks

    func updateDiskCache(_ s: DiskCacheSettings) {
        diskCacheSettings = s; save()
        DiskCache.shared.configure(s)
    }

    func updateMetrics(_ s: MetricsSettings) {
        metricsSettings = s; save()
        if s.enabled { startMetrics() } else { MetricsServer.shared.stop() }
    }

    func updateWebhook(_ s: WebhookSettings) {
        webhookSettings = s; save()
        WebhookManager.shared.configure(s)
    }

    nonisolated(unsafe) static var latestStats = Stats()

    private func startMetrics() {
        MetricsServer.shared.statsProvider = {
            MetricsServer.generatePrometheusMetrics(
                state: AppState.latestStats,
                cache: CacheManager.shared.stats,
                disk: DiskCache.shared.stats,
                dns: DNSResolver.shared.stats
            )
        }
        MetricsServer.shared.start(port: UInt16(metricsSettings.port))
    }

    /// Call after stat changes to keep the static snapshot fresh.
    private func syncMetricsSnapshot() {
        AppState.latestStats = stats
    }

    // MARK: - Loop breaker

    func updateLoopBreaker(_ s: LoopBreakerSettings) {
        loopBreakerSettings = s; save()
        AgentLoopBreaker.shared.configure(s)
    }

    // MARK: - Cloud sync

    func updateCloudSync(_ s: CloudSyncSettings) {
        cloudSyncSettings = s; save()
        if s.enabled { startCloudSync() } else { CloudSync.shared.stop() }
    }

    private func startCloudSync() {
        CloudSync.shared.onRemoteChange = { [weak self] remoteRules, remoteAllow in
            guard let self else { return }
            if self.cloudSyncSettings.syncRules {
                self.rules = CloudSync.mergeRules(local: self.rules, remote: remoteRules)
            }
            if self.cloudSyncSettings.syncAllowlist {
                self.allowlist = CloudSync.mergeAllowlist(local: self.allowlist, remote: remoteAllow)
            }
            self.save()
            self.syncRulesToListeners()
            self.log(.info, "Cloud sync: merged remote changes")
        }
        CloudSync.shared.start()
    }

    /// Push current rules to iCloud after changes.
    private func pushToCloud() {
        guard cloudSyncSettings.enabled else { return }
        if cloudSyncSettings.syncRules { CloudSync.shared.pushRules(rules) }
        if cloudSyncSettings.syncAllowlist { CloudSync.shared.pushAllowlist(allowlist) }
    }

    // MARK: - Allowlist

    func addAllowEntry(_ entry: AllowEntry) {
        allowlist.append(entry); save(); pushToCloud()
        syncRulesToListeners()
        log(.info, "Allowlisted \(entry.pattern)")
    }

    func removeAllowEntry(_ id: UUID) {
        allowlist.removeAll { $0.id == id }; save()
        syncRulesToListeners()
    }

    func toggleAllowEntry(_ id: UUID) {
        if let i = allowlist.firstIndex(where: { $0.id == id }) {
            allowlist[i].enabled.toggle(); save()
            syncRulesToListeners()
        }
    }

    // MARK: - DNS

    func updateDNS(_ s: DNSSettings) {
        dnsSettings = s; save()
        DNSResolver.shared.configure(s)
    }

    // MARK: - Rule import

    func importRulesFromText(_ text: String, format: RuleImporter.ImportFormat, category: String) {
        let existing = Set(rules.map { $0.pattern.lowercased() })
        let result = RuleImporter.importRules(from: text, format: format,
                                               category: category, existingPatterns: existing)
        rules.append(contentsOf: result.rules)
        save()
        syncRulesToListeners()
        log(.info, "Imported \(result.rules.count) rules (\(result.skipped) skipped, format: \(result.format.rawValue))")
    }

    func importRulesFromURL(_ urlString: String, format: RuleImporter.ImportFormat, category: String) {
        let existing = Set(rules.map { $0.pattern.lowercased() })
        log(.info, "Importing from \(urlString)...")
        RuleImporter.importFromURL(urlString, format: format, category: category,
                                    existingPatterns: existing) { [weak self] result in
            Task { @MainActor [weak self] in
                guard let self else { return }
                switch result {
                case .success(let r):
                    self.rules.append(contentsOf: r.rules)
                    self.save()
                    if self.isEnabled { self.localProxy.updateRules(self.rules) }
                    self.log(.info, "Imported \(r.rules.count) rules from URL (\(r.skipped) skipped)")
                case .failure(let err):
                    self.log(.error, "Import failed: \(err.localizedDescription)")
                }
            }
        }
    }

    func exportRulesJSON() -> String {
        RuleImporter.exportRules(rules)
    }

    func exportRulesHosts() -> String {
        RuleImporter.exportAsHosts(rules)
    }

    // MARK: - Pools

    private func handlePoolEvent(_ event: PoolRouter.Event) {
        switch event {
        case .healthChanged(_, let host, let healthy, let latencyMs):
            let ms = latencyMs.map { String(format: "%.0fms", $0) } ?? ""
            log(healthy ? .info : .warn,
                "Health: \(host) \(healthy ? "UP" : "DOWN") \(ms)")
            poolHealth = PoolRouter.shared.getHealth()
        case .log(let level, let message):
            log(level, message)
        }
    }

    func addPool(_ pool: UpstreamPool) {
        pools.append(pool); save()
        syncPoolRouter()
    }

    func removePool(_ id: UUID) {
        pools.removeAll { $0.id == id }
        poolOverrides.removeAll { $0.poolId == id }
        save(); syncPoolRouter()
    }

    func updatePool(_ pool: UpstreamPool) {
        if let i = pools.firstIndex(where: { $0.id == pool.id }) {
            pools[i] = pool; save(); syncPoolRouter()
        }
    }

    func setDefaultPool(_ id: UUID) {
        for i in pools.indices {
            pools[i].isDefault = (pools[i].id == id)
        }
        save(); syncPoolRouter()
    }

    func addPoolOverride(_ o: PoolOverride) {
        poolOverrides.append(o); save(); syncPoolRouter()
    }

    func removePoolOverride(_ id: UUID) {
        poolOverrides.removeAll { $0.id == id }; save(); syncPoolRouter()
    }

    /// Create a pool from the existing legacy ProxyConfig selection.
    func createPoolFromProxy(_ proxy: ProxyConfig) {
        let pool = UpstreamPool(
            name: proxy.name,
            members: [PoolMember(host: proxy.host, port: proxy.port)],
            strategy: .failover,
            healthCheck: HealthCheckConfig(),
            isDefault: pools.isEmpty
        )
        addPool(pool)
    }

    private func syncPoolRouter() {
        PoolRouter.shared.configure(pools: pools, overrides: poolOverrides)
    }

    /// Syncs rules, allowlist, and blacklists to BOTH localProxy and socks5Listener.
    private func syncRulesToListeners() {
        guard isEnabled else { return }
        localProxy.updateRules(rules)
        localProxy.updateAllowlist(allowlist)
        localProxy.updateBlacklistSources(blacklistSources)
        socks5Listener.updateRules(rules)
        socks5Listener.updateAllowlist(allowlist)
        socks5Listener.updateBlacklists(blacklistSources)
    }

    // MARK: - Blacklists

    func addBlacklistSource(_ s: BlacklistSource) {
        blacklistSources.append(s); save()
        syncRulesToListeners()
    }

    func removeBlacklistSource(_ id: UUID) {
        blacklistSources.removeAll { $0.id == id }
        BlacklistManager.shared.clearSource(id)
        save()
        syncRulesToListeners()
    }

    func toggleBlacklistSource(_ id: UUID) {
        if let i = blacklistSources.firstIndex(where: { $0.id == id }) {
            blacklistSources[i].enabled.toggle()
            save()
            syncRulesToListeners()
        }
    }

    func loadBuiltInBlacklists() {
        let existing = Set(blacklistSources.map { $0.url.lowercased() })
        let new = BlacklistSource.builtIn.filter { !existing.contains($0.url.lowercased()) }
        blacklistSources.append(contentsOf: new)
        save()
        syncRulesToListeners()
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

    func moveProxy(from source: IndexSet, to destination: Int) {
        proxies.move(fromOffsets: source, toOffset: destination); save()
    }

    func deleteProxies(at offsets: IndexSet) {
        let ids = offsets.map { proxies[$0].id }
        proxies.remove(atOffsets: offsets)
        for id in ids where selectedProxyID == id {
            selectedProxyID = proxies.first?.id
        }
        save()
    }

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
        rules.append(r); save(); pushToCloud()
        syncRulesToListeners()
    }

    func moveRule(from source: IndexSet, to destination: Int) {
        rules.move(fromOffsets: source, toOffset: destination); save()
        syncRulesToListeners()
    }

    func deleteRules(at offsets: IndexSet) {
        rules.remove(atOffsets: offsets); save()
        syncRulesToListeners()
    }

    func addAllowRule(_ host: String) {
        let rule = WAFRule(name: "Allow \(host)", kind: .allowDomain,
                           pattern: host, category: "Allowlist")
        addRule(rule)
        log(.info, "Allowlisted \(host)")
    }

    func removeRule(_ id: WAFRule.ID) {
        rules.removeAll { $0.id == id }; save(); pushToCloud()
        syncRulesToListeners()
    }

    func toggleRule(_ id: WAFRule.ID) {
        if let i = rules.firstIndex(where: { $0.id == id }) {
            rules[i].enabled.toggle(); save()
            syncRulesToListeners()
        }
    }

    func loadExampleRules() {
        let existingPatterns = Set(rules.map { $0.pattern.lowercased() })
        let new = WAFRule.examples.filter { !existingPatterns.contains($0.pattern.lowercased()) }
        rules.append(contentsOf: new); save()
        syncRulesToListeners()
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
        if let data = try? JSONEncoder().encode(pools) { d.set(data, forKey: poolsKey) }
        if let data = try? JSONEncoder().encode(poolOverrides) { d.set(data, forKey: overridesKey) }
        if let data = try? JSONEncoder().encode(rules)   { d.set(data, forKey: rulesKey) }
        if let data = try? JSONEncoder().encode(privacy) { d.set(data, forKey: privacyKey) }
        if let data = try? JSONEncoder().encode(cacheSettings) { d.set(data, forKey: cacheKey) }
        if let data = try? JSONEncoder().encode(socks5Settings) { d.set(data, forKey: socks5Key) }
        if let data = try? JSONEncoder().encode(beaconingSettings) { d.set(data, forKey: beaconingKey) }
        if let data = try? JSONEncoder().encode(c2Settings) { d.set(data, forKey: c2Key) }
        if let data = try? JSONEncoder().encode(loopBreakerSettings) { d.set(data, forKey: loopBreakerKey) }
        if let data = try? JSONEncoder().encode(processRules) { d.set(data, forKey: processRulesKey) }
        if let data = try? JSONEncoder().encode(cloudSyncSettings) { d.set(data, forKey: cloudSyncKey) }
        if let data = try? JSONEncoder().encode(diskCacheSettings) { d.set(data, forKey: diskCacheKey) }
        if let data = try? JSONEncoder().encode(metricsSettings) { d.set(data, forKey: metricsKey) }
        if let data = try? JSONEncoder().encode(webhookSettings) { d.set(data, forKey: webhookKey) }
        if let data = try? JSONEncoder().encode(allowlist) { d.set(data, forKey: allowlistKey) }
        if let data = try? JSONEncoder().encode(dnsSettings) { d.set(data, forKey: dnsKey) }
        if let data = try? JSONEncoder().encode(aiSettings) { d.set(data, forKey: aiSettingsKey) }
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
        if let data = d.data(forKey: poolsKey),
           let arr = try? JSONDecoder().decode([UpstreamPool].self, from: data) {
            pools = arr
        }
        if let data = d.data(forKey: overridesKey),
           let arr = try? JSONDecoder().decode([PoolOverride].self, from: data) {
            poolOverrides = arr
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
        if let data = d.data(forKey: socks5Key),
           let s = try? JSONDecoder().decode(SOCKS5Settings.self, from: data) {
            socks5Settings = s
        }
        if let data = d.data(forKey: beaconingKey),
           let s = try? JSONDecoder().decode(BeaconingSettings.self, from: data) {
            beaconingSettings = s
        }
        if let data = d.data(forKey: c2Key),
           let s = try? JSONDecoder().decode(C2Settings.self, from: data) {
            c2Settings = s
        }
        if let data = d.data(forKey: processRulesKey),
           let arr = try? JSONDecoder().decode([ProcessRule].self, from: data) {
            processRules = arr
        }
        if let data = d.data(forKey: loopBreakerKey),
           let s = try? JSONDecoder().decode(LoopBreakerSettings.self, from: data) {
            loopBreakerSettings = s
        }
        if let data = d.data(forKey: cloudSyncKey),
           let s = try? JSONDecoder().decode(CloudSyncSettings.self, from: data) {
            cloudSyncSettings = s
        }
        if let data = d.data(forKey: diskCacheKey),
           let s = try? JSONDecoder().decode(DiskCacheSettings.self, from: data) {
            diskCacheSettings = s
        }
        if let data = d.data(forKey: metricsKey),
           let s = try? JSONDecoder().decode(MetricsSettings.self, from: data) {
            metricsSettings = s
        }
        if let data = d.data(forKey: webhookKey),
           let s = try? JSONDecoder().decode(WebhookSettings.self, from: data) {
            webhookSettings = s
        }
        if let data = d.data(forKey: allowlistKey),
           let arr = try? JSONDecoder().decode([AllowEntry].self, from: data) {
            allowlist = arr
        }
        if let data = d.data(forKey: dnsKey),
           let s = try? JSONDecoder().decode(DNSSettings.self, from: data) {
            dnsSettings = s
        }
        if let data = d.data(forKey: aiSettingsKey),
           let a = try? JSONDecoder().decode(AISettings.self, from: data) {
            aiSettings = a
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
