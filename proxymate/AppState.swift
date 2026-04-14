//
//  AppState.swift
//  proxymate
//

import Foundation
import Combine
import SwiftUI
import IOKit.ps
import os

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
    @Published var pacSettings = PACSettings()
    @Published var socks5Settings = SOCKS5Settings()
    @Published var beaconingSettings = BeaconingSettings()
    @Published var c2Settings = C2Settings()
    @Published var aiAgentSettings = AIAgentSettings()
    @Published var loopBreakerSettings = LoopBreakerSettings()
    @Published var processRules: [ProcessRule] = []
    @Published var aiSettings = AISettings()
    @Published var aiProviderStats: [String: AIProviderStats] = [:]
    @Published var blacklistSources: [BlacklistSource] = []
    @Published var exfiltrationPacks: [ExfiltrationPack] = []
    @Published var selectedProxyID: ProxyConfig.ID?
    @Published var wafShadowMode: Bool = false
    @Published var isLowPowerMode: Bool = false
    @Published var isEnabled: Bool = false
    private var memoryPressureSource: DispatchSourceMemoryPressure?
    @Published var isBusy: Bool = false
    @Published var localPort: UInt16?
    @Published var logs: [LogEntry] = []
    @Published var stats = Stats()
    /// Tracks already-logged agent/AI detections to suppress repeats. Capped to prevent unbounded growth.
    private var seenAgents = Set<String>()
    private let seenAgentsMaxSize = 10_000

    /// Returns true if the key was already seen. Caps set size to prevent unbounded growth.
    private func markSeen(_ key: String) -> Bool {
        if seenAgents.contains(key) { return true }
        if seenAgents.count >= seenAgentsMaxSize { seenAgents.removeAll() }
        seenAgents.insert(key)
        return false
    }
    let timeSeries = StatsTimeSeries()
    /// Keeps Combine forwarders alive for the AppState lifetime.
    /// Used to republish nested ObservableObject changes so the Stats tab
    /// redraws when `timeSeries.points` mutates. SwiftUI's `@EnvironmentObject`
    /// observes only the outer AppState — without this forwarding, the live
    /// req/sec chart never refreshed after the first render.
    private var cancellables = Set<AnyCancellable>()

    /// Monotonic 1 Hz counter views can read (`_ = state.statsTick`) to pick
    /// up changes from singletons that aren't ObservableObject (CacheManager,
    /// DiskCache, DNSResolver, HostMemory). Without this, their UI panels
    /// rendered once and then froze until some other event forced a redraw.
    @Published private(set) var statsTick: Int = 0
    private var statsTickTimer: Timer?

    /// Number of blacklist refreshes currently in flight. The Blacklists
    /// panel binds its Refresh-button spinner to `count > 0` so the
    /// indicator reflects actual work rather than a hardcoded 2s sleep.
    @Published private(set) var refreshingBlacklistsCount: Int = 0

    /// True while the openssl-backed CA generation is running. The Privacy
    /// tab disables and shows a spinner on the Generate button instead of
    /// letting the user double-click during the ~3 s blocking call.
    @Published private(set) var generatingMITMCA: Bool = false

    nonisolated struct Stats: Sendable {
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
    private let mitmKey        = "proxymate.mitm.v2"  // v2: expanded excludes
    private let pacKey         = "proxymate.pac.v1"
    private let socks5Key      = "proxymate.socks5.v1"
    private let beaconingKey   = "proxymate.beaconing.v1"
    private let c2Key          = "proxymate.c2.v1"
    private let loopBreakerKey = "proxymate.loopbreaker.v2"  // v2: raised thresholds
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
    private let aiAgentKey     = "proxymate.aiagent.v1"

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

        // Check CA certificate expiry (#43) — async to avoid blocking main thread
        Task.detached(priority: .utility) {
            let days = TLSManager.shared.caExpiryDays()
            await MainActor.run { [weak self] in
                guard let self, let days, days < 30 else { return }
                if days <= 0 {
                    self.log(.error, "CA certificate has EXPIRED — regenerate to continue MITM interception")
                } else {
                    self.log(.warn, "CA certificate expires in \(days) days — consider regenerating soon")
                }
            }
        }
        startBatteryMonitor()
        registerMemoryPressureHandler()

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

        // Forward nested ObservableObject changes so the Stats tab picks up
        // timeSeries.points mutations (the per-second chart tick). Without
        // this republish, SwiftUI only observed AppState.objectWillChange
        // and ignored timeSeries entirely.
        timeSeries.objectWillChange
            .sink { [weak self] _ in self?.objectWillChange.send() }
            .store(in: &cancellables)

        // 1 Hz tick for panels that read singleton stats (CacheManager /
        // DiskCache / DNSResolver / HostMemory). Their stats structs are not
        // ObservableObject so SwiftUI can't observe them; reading
        // `state.statsTick` in those views establishes a dependency that
        // re-renders once per second.
        statsTickTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.statsTick &+= 1
            }
        }
    }

    deinit {
        statsTickTimer?.invalidate()
        // DispatchSources must be cancelled before release, otherwise
        // pending events can fire after the handler's self goes away.
        // Singleton in practice — but defensive if a future refactor adds
        // a non-singleton instance path (tests, preview, etc.).
        memoryPressureSource?.cancel()
        blacklistTimer?.invalidate()
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
            // Mirror the logic from enable(): if the new upstream points at
            // a bundled sidecar (127.0.0.1:3128 Squid), make sure it's
            // running before we forward requests to it. Without this, a
            // user switching from an external proxy to "Local Squid" while
            // enabled would see every request 502 until they toggled off
            // and back on.
            ensureLocalSidecarForUpstream(host: p.host, port: port)
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

        // If the selected upstream is one of the bundled sidecars (Local Squid
        // on 3128, Local mitmproxy on 8080), make sure the sidecar is running
        // before we forward to it. Otherwise a fresh install with the default
        // "Local Squid" selection would answer every request with 502
        // because nothing is listening on 3128.
        ensureLocalSidecarForUpstream(host: proxy.host, port: upstreamPort)

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
        UserDefaults.standard.set(true, forKey: "proxymate.wasEnabled")
        stats.enabledSince = Date()
        log(.info, "Enabled — local 127.0.0.1:\(port) → upstream \(proxy.name) (\(proxy.host):\(proxy.port))")

        // Start PAC server if enabled
        if pacSettings.enabled {
            startPAC(proxyPort: port)
        }

        // Start SOCKS5 if enabled
        if socks5Settings.enabled {
            startSOCKS5()
        }
    }

    private let socks5Listener = SOCKS5Listener()

    /// Best-effort auto-launch of a bundled sidecar when the user picks an
    /// upstream that points at it. Squid on :3128, mitmproxy on :8080 —
    /// these are the defaults seeded at first run. If the port is already
    /// bound (user has their own Squid via brew, or mitmproxy running in a
    /// terminal) SquidSidecar.start returns the existing port silently
    /// instead of competing for the bind. Any start error is logged, not
    /// fatal: the enable continues and the user gets 502 responses if the
    /// upstream is truly unreachable — which is still better than a silent
    /// failure with no diagnostics.
    private func ensureLocalSidecarForUpstream(host: String, port: UInt16) {
        guard host == "127.0.0.1" || host == "::1" || host == "localhost" else { return }
        if port == 3128 {
            do {
                _ = try SquidSidecar.shared.start(listenPort: port)
            } catch {
                log(.warn, "Local Squid sidecar not started: \(error.localizedDescription) — upstream must be reachable by other means")
            }
        }
        // Local mitmproxy on :8080 is started inside LocalProxy.start when
        // MITM is enabled; no extra bootstrap here to avoid double-launches.
    }

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
        PACServer.shared.stop()
        ConnectionPool.shared.drain()
        // Tear down the auto-started Squid sidecar if it was ours. If a
        // user-managed Squid was reused, stop() is a no-op on the foreign
        // process — SquidSidecar only kills processes it spawned.
        SquidSidecar.shared.stop()
        if pacSettings.enabled {
            Task { [weak self] in
                do { try await PACServer.clearSystemPAC() }
                catch {
                    // Cleanup of `networksetup -setautoproxyurl ... off`
                    // failed — surface the error rather than leaving the
                    // PAC config stuck in the system. Without this log, a
                    // user toggling PAC off could find scutil --proxy
                    // still showing ProxyAutoConfigEnable=1 with no hint.
                    await MainActor.run {
                        self?.log(.warn, "PAC cleanup failed: \(error.localizedDescription)")
                    }
                }
            }
        }
        PoolRouter.shared.stop()
        blacklistTimer?.invalidate()
        blacklistTimer = nil
        localPort = nil
        isEnabled = false
        UserDefaults.standard.set(false, forKey: "proxymate.wasEnabled")
        stats.enabledSince = nil
        seenAgents.removeAll()  // free memory on disable
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
        case .allowed(_, _):
            stats.requestsAllowed += 1
            timeSeries.recordAllowed()
            // No log — allowed requests are the norm, not worth logging individually
        case .blocked(let host, let ruleName):
            stats.requestsBlocked += 1
            timeSeries.recordBlocked()
            let wafKey = "WAF|\(host)|\(ruleName)"
            if !markSeen(wafKey) {
                log(.warn, "BLOCKED \(host) — \(ruleName)", host: host)
                NotificationManager.shared.notifyBlock(host: host, ruleName: ruleName)
                WebhookManager.shared.sendBlock(host: host, ruleName: ruleName)
            }
        case .blacklisted(let host, let sourceName, let category):
            stats.blacklistBlocked += 1
            timeSeries.recordBlocked()
            // Log only first block per host (suppress repeats like exp-tas.com x30)
            let blKey = "BL|\(host)"
            if !markSeen(blKey) {
                log(.warn, "BLACKLIST \(host) — \(sourceName) [\(category)]", host: host)
                NotificationManager.shared.notifyBlock(host: host, ruleName: "\(sourceName) [\(category)]")
                WebhookManager.shared.sendBlock(host: host, ruleName: "\(sourceName) [\(category)]")
            }
        case .exfiltration(let host, let patternName, let severity, let preview):
            stats.exfiltrationBlocked += 1
            log(.error, "EXFILTRATION [\(severity)] \(patternName) → \(host) | \(preview)", host: host)
            NotificationManager.shared.notifyExfiltration(host: host, patternName: patternName)
            WebhookManager.shared.sendExfiltration(host: host, patternName: patternName, severity: severity, preview: preview)
        case .privacyStripped(_, _):
            stats.privacyActions += 1
            // No log — privacy stripping is routine
        case .cacheHit(_, _):
            stats.cacheHits += 1
        case .cacheMiss(_, _):
            stats.cacheMisses += 1
        case .agentDetected(let host, let agent, let indicator):
            // Log only first detection per agent+host (suppress repeats)
            let key = "\(agent)|\(host)"
            if !markSeen(key) {
                log(.info, "AGENT \(agent) \(host) [\(indicator)]", host: host)
            }
        case .mcpDetected(let host, let method):
            log(.info, "MCP \(method) → \(host)", host: host)
        case .mitmIntercepted(_):
            stats.mitmIntercepted += 1
            // No log — MITM interception is routine when enabled
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
            let aiKey = "\(provider)|\(host)"
            if !markSeen(aiKey) {
                log(.info, "AI \(provider) \(host)", host: host)
            }
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

    // MARK: - Memory Pressure (#40)

    private func registerMemoryPressureHandler() {
        let source = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: .main)
        source.setEventHandler { [weak self] in
            guard let self else { return }
            self.log(.warn, "Memory pressure detected — flushing caches")
            CacheManager.shared.purgeAll()
            DiskCache.shared.purgeAll()
        }
        source.resume()
        memoryPressureSource = source  // retain to prevent dealloc-while-resumed crash
    }

    // MARK: - Battery Monitor (#41)

    private func startBatteryMonitor() {
        Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.checkBattery() }
        }
    }

    private func checkBattery() {
        let ps = IOPSCopyPowerSourcesInfo()?.takeRetainedValue()
        let sources = IOPSCopyPowerSourcesList(ps)?.takeRetainedValue() as? [CFTypeRef] ?? []
        for source in sources {
            guard let desc = IOPSGetPowerSourceDescription(ps, source)?.takeUnretainedValue() as? [String: Any],
                  let capacity = desc[kIOPSCurrentCapacityKey] as? Int,
                  let isCharging = desc[kIOPSIsChargingKey] as? Bool else { continue }
            let wasLow = isLowPowerMode
            isLowPowerMode = capacity < 10 && !isCharging
            if isLowPowerMode && !wasLow {
                log(.warn, "Low battery (\(capacity)%) — suspending heavy logging and process resolution")
            } else if !isLowPowerMode && wasLow {
                log(.info, "Battery OK — resuming full operation")
            }
        }
    }

    // MARK: - Shadow Mode

    func syncShadowMode() {
        if isEnabled { localProxy.updateShadowMode(wafShadowMode) }
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
        // Run openssl on a detached Task so the MainActor isn't blocked for
        // the ~3 s subprocess run. UI observes `generatingMITMCA` and shows
        // a spinner instead of going unresponsive mid-click.
        guard !generatingMITMCA else { return }
        generatingMITMCA = true
        Task { [weak self] in
            do {
                _ = try await Task.detached(priority: .userInitiated) {
                    try TLSManager.shared.generateCA()
                }.value
                await MainActor.run {
                    guard let self else { return }
                    self.mitmSettings.caInstalled = true
                    self.save()
                    self.log(.info, "Root CA generated and stored in Keychain")
                    self.generatingMITMCA = false
                }
            } catch {
                await MainActor.run {
                    guard let self else { return }
                    self.log(.error, "CA generation failed: \(error.localizedDescription)")
                    self.generatingMITMCA = false
                }
            }
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

    private nonisolated(unsafe) static let _latestStats = OSAllocatedUnfairLock(initialState: Stats())
    nonisolated static var latestStats: Stats {
        get { _latestStats.withLock { $0 } }
        set { _latestStats.withLock { $0 = newValue } }
    }

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

    // MARK: - PAC

    func updatePAC(_ s: PACSettings) {
        pacSettings = s; save()
        if isEnabled {
            if s.enabled, let port = localPort {
                startPAC(proxyPort: port)
            } else {
                PACServer.shared.stop()
                Task { [weak self] in
                do { try await PACServer.clearSystemPAC() }
                catch {
                    // Cleanup of `networksetup -setautoproxyurl ... off`
                    // failed — surface the error rather than leaving the
                    // PAC config stuck in the system. Without this log, a
                    // user toggling PAC off could find scutil --proxy
                    // still showing ProxyAutoConfigEnable=1 with no hint.
                    await MainActor.run {
                        self?.log(.warn, "PAC cleanup failed: \(error.localizedDescription)")
                    }
                }
            }
            }
        }
    }

    private func startPAC(proxyPort: UInt16) {
        // Collect direct domains from allowlist (domain entries only)
        let directDomains = allowlist.filter(\.enabled).compactMap { entry -> String? in
            let p = entry.pattern
            guard !p.contains("/") else { return nil } // skip CIDR
            return p
        }
        let socks5Port = socks5Settings.enabled ? UInt16(socks5Settings.port) : 0
        PACServer.shared.start(settings: pacSettings, proxyPort: proxyPort,
                                socks5Port: socks5Port, directDomains: directDomains)
        Task {
            do {
                try await PACServer.applySystemPAC(port: pacSettings.port)
                log(.info, "PAC enabled at \(PACServer.shared.pacURL)")
            } catch {
                log(.error, "PAC system apply failed: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Loop breaker

    func updateLoopBreaker(_ s: LoopBreakerSettings) {
        loopBreakerSettings = s; save()
        AgentLoopBreaker.shared.configure(s)
    }

    func updateC2(_ s: C2Settings) {
        c2Settings = s; save()
    }

    func updateBeaconing(_ s: BeaconingSettings) {
        beaconingSettings = s; save()
        BeaconingDetector.shared.configure(s)
    }

    func updateAIAgentSettings(_ s: AIAgentSettings) {
        aiAgentSettings = s; save()
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

    func moveAllowEntries(from source: IndexSet, to destination: Int) {
        allowlist.move(fromOffsets: source, toOffset: destination); save()
    }

    func deleteAllowEntries(at offsets: IndexSet) {
        allowlist.remove(atOffsets: offsets); save()
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
        ToastState.shared.show("Imported \(result.rules.count) rules", icon: "arrow.down.doc")
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
        localProxy.updateShadowMode(wafShadowMode)
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
        refreshingBlacklistsCount += 1
        BlacklistManager.shared.refresh(source: source) { [weak self] result in
            Task { @MainActor [weak self] in
                guard let self else { return }
                defer { self.refreshingBlacklistsCount = max(0, self.refreshingBlacklistsCount - 1) }
                switch result {
                case .success(let count):
                    if let i = self.blacklistSources.firstIndex(where: { $0.id == id }) {
                        self.blacklistSources[i].lastUpdated = Date()
                        self.blacklistSources[i].entryCount = count
                        self.save()
                    }
                    self.log(.info, "\(source.name): \(count) entries loaded")
                    ToastState.shared.show("\(source.name): \(count) entries", icon: "arrow.clockwise")
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
        logs.append(entry)
        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
        PersistentLogger.shared.write(entry)
    }

    func clearLogs() {
        let count = logs.count
        logs.removeAll()
        // Reset the dedupe set too: without this, log events that had already
        // fired once (BLOCKED, BLACKLIST, AGENT, AI) stay in seenAgents and
        // are suppressed the next time they fire — making the Logs tab look
        // dead after Clear even though traffic is actively flowing.
        seenAgents.removeAll()
        ToastState.shared.show("\(count) log entries cleared", icon: "trash", color: .secondary)
    }

    // MARK: - Persistence

    private func save() {
        let d = UserDefaults.standard
        if let data = try? JSONEncoder().encode(proxies) { d.set(data, forKey: proxiesKey) }
        if let data = try? JSONEncoder().encode(pools) { d.set(data, forKey: poolsKey) }
        if let data = try? JSONEncoder().encode(poolOverrides) { d.set(data, forKey: overridesKey) }
        if let data = try? JSONEncoder().encode(rules)   { d.set(data, forKey: rulesKey) }
        if let data = try? JSONEncoder().encode(privacy) { d.set(data, forKey: privacyKey) }
        if let data = try? JSONEncoder().encode(cacheSettings) { d.set(data, forKey: cacheKey) }
        if let data = try? JSONEncoder().encode(pacSettings) { d.set(data, forKey: pacKey) }
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
        if let data = try? JSONEncoder().encode(aiAgentSettings) { d.set(data, forKey: aiAgentKey) }
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
        if let data = d.data(forKey: pacKey),
           let s = try? JSONDecoder().decode(PACSettings.self, from: data) {
            pacSettings = s
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
        if let data = d.data(forKey: aiAgentKey),
           let s = try? JSONDecoder().decode(AIAgentSettings.self, from: data) {
            aiAgentSettings = s
        }
        if let s = d.string(forKey: selectedKey), let uuid = UUID(uuidString: s) {
            selectedProxyID = uuid
        }
    }
}
