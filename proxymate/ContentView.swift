//
//  ContentView.swift
//  proxymate
//
//  Popover content shown by MenuBarExtra. Header (status + master toggle),
//  tab bar, and the five tab bodies.
//

import SwiftUI
import AppKit
import Charts

struct ContentView: View {
    @EnvironmentObject var state: AppState
    @State private var tab: Tab = .proxies
    @State private var showOnboarding = !UserDefaults.standard.bool(forKey: "proxymate.onboarded")
    @State private var showAbout = false
    @State private var showQuitConfirm = false

    enum Tab: String, CaseIterable, Identifiable {
        case proxies = "Proxies"
        case logs    = "Logs"
        case stats   = "Stats"
        case rules   = "Rules"
        case ai      = "AI"
        case cache   = "Cache"
        case privacy = "Privacy"
        var id: String { rawValue }
        var systemImage: String {
            switch self {
            case .proxies: return "network"
            case .logs:    return "list.bullet.rectangle"
            case .stats:   return "chart.bar"
            case .rules:   return "shield.lefthalf.filled"
            case .ai:      return "brain"
            case .cache:   return "internaldrive"
            case .privacy: return "eye.slash"
            }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            ToastOverlay()
            Divider()
            tabBar
            Divider()
            content
                .frame(minHeight: 380, maxHeight: 500)
            CommunityBar()
        }
        .frame(width: 420)
        .animation(.easeInOut(duration: 0.15), value: tab)
        .background(shortcuts)
        .sheet(isPresented: $showAbout) {
            AboutView().environmentObject(state)
        }
        .alert("Quit Proxymate?", isPresented: $showQuitConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Quit", role: .destructive) { NSApplication.shared.terminate(nil) }
        } message: {
            Text(state.isEnabled
                 ? "The proxy is currently active. Quitting will disable it and restore direct connections."
                 : "Are you sure you want to quit?")
        }
        .sheet(isPresented: $showOnboarding) {
            OnboardingView(isPresented: $showOnboarding)
                .environmentObject(state)
                .onDisappear {
                    UserDefaults.standard.set(true, forKey: "proxymate.onboarded")
                }
        }
    }

    /// Hidden buttons that capture keyboard shortcuts within the popover.
    @ViewBuilder
    private var shortcuts: some View {
        Group {
            Button("") { Task { await state.toggle() } }
                .keyboardShortcut("t", modifiers: .command)
            Button("") { tab = .proxies }
                .keyboardShortcut("1", modifiers: .command)
            Button("") { tab = .logs }
                .keyboardShortcut("2", modifiers: .command)
            Button("") { tab = .stats }
                .keyboardShortcut("3", modifiers: .command)
            Button("") { tab = .rules }
                .keyboardShortcut("4", modifiers: .command)
            Button("") { tab = .ai }
                .keyboardShortcut("5", modifiers: .command)
            Button("") { tab = .cache }
                .keyboardShortcut("6", modifiers: .command)
            Button("") { tab = .privacy }
                .keyboardShortcut("7", modifiers: .command)
        }
        .frame(width: 0, height: 0)
        .opacity(0)
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: state.isEnabled
                  ? "shield.lefthalf.filled.trianglebadge.exclamationmark"
                  : "shield.lefthalf.filled")
                .font(.title2)
                .foregroundStyle(state.isEnabled ? .green : .secondary)

            VStack(alignment: .leading, spacing: 2) {
                Button("Proxymate") { showAbout = true }
                    .font(.headline).buttonStyle(.plain)
                    .accessibilityLabel("About Proxymate")
                Text(state.isEnabled
                     ? "Active • \(state.selectedProxy?.name ?? "—")"
                     : "Disabled")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if state.isBusy {
                ProgressView().controlSize(.small)
            }
            // Emergency killswitch: instantly stops everything (#38)
            if state.isEnabled {
                Button {
                    Task { await state.disable() }
                } label: {
                    Image(systemName: "power")
                        .font(.caption.bold())
                        .foregroundStyle(.white)
                        .frame(width: 22, height: 22)
                        .background(Color.red, in: RoundedRectangle(cornerRadius: 5))
                }
                .buttonStyle(.plain)
                .help("KILLSWITCH — immediately stop proxy and restore network")
            }
            Toggle("", isOn: Binding(
                get: { state.isEnabled },
                set: { _ in Task { await state.toggle() } }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
            .disabled(state.selectedProxy == nil || state.isBusy)
            .accessibilityLabel("Toggle Proxy")
            .accessibilityValue(state.isEnabled ? "On" : "Off")
        }
        .padding(12)
    }

    // MARK: - Tab bar

    private var tabBar: some View {
        HStack(spacing: 0) {
            ForEach(Tab.allCases) { t in
                Button {
                    tab = t
                } label: {
                    VStack(spacing: 2) {
                        Image(systemName: t.systemImage)
                            .font(.caption2)
                        Text(t.rawValue).font(.system(size: 9))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 5)
                    .foregroundStyle(tab == t ? Color.accentColor : .secondary)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(t.rawValue) tab")
                .accessibilityAddTraits(tab == t ? .isSelected : [])
            }
        }
    }

    // MARK: - Content router

    @ViewBuilder
    private var content: some View {
        switch tab {
        case .proxies: ProxiesView()
        case .logs:    LogsView()
        case .stats:   StatsView()
        case .rules:   RulesView()
        case .ai:      AIView()
        case .cache:   CacheView()
        case .privacy: PrivacyView()
        }
    }
}

// MARK: - Proxies tab

struct ProxiesView: View {
    @EnvironmentObject var state: AppState
    @State private var section: ProxySection = .proxies

    enum ProxySection: String, CaseIterable, Identifiable {
        case proxies = "Quick"
        case pools   = "Pools"
        case pac     = "PAC"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("Section", selection: $section) {
                ForEach(ProxySection.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .padding(8)
            Divider()
            switch section {
            case .proxies: QuickProxiesSection()
            case .pools:   PoolsSection()
            case .pac:     PACSection()
            }
        }
    }
}

// MARK: Quick proxies (legacy single upstream)

struct QuickProxiesSection: View {
    @EnvironmentObject var state: AppState
    @State private var showingAdd = false

    var body: some View {
        VStack(spacing: 0) {
            if state.proxies.isEmpty {
                VStack(spacing: 8) {
                    Spacer()
                    Image(systemName: "network.slash")
                        .font(.title2).foregroundStyle(.quaternary)
                    Text("No proxies configured").font(.caption).foregroundStyle(.secondary)
                    Text("Add an upstream proxy server to get started.")
                        .font(.caption2).foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center).padding(.horizontal, 20)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                List {
                    ForEach(state.proxies) { p in
                        ProxyRow(proxy: p, isSelected: p.id == state.selectedProxyID)
                            .contentShape(Rectangle())
                            .onTapGesture { state.select(p.id) }
                            .contextMenu {
                                Button("Use this proxy") { state.select(p.id) }
                                Button("Create Pool from this") {
                                    state.createPoolFromProxy(p)
                                }
                                Divider()
                                Button("Delete", role: .destructive) { state.removeProxy(p.id) }
                            }
                            .listRowInsets(EdgeInsets(top: 2, leading: 4, bottom: 2, trailing: 4))
                    }
                    .onMove { state.moveProxy(from: $0, to: $1) }
                    .onDelete { state.deleteProxies(at: $0) }
                }
                .listStyle(.plain)
            }
            Divider()
            HStack {
                Button { showingAdd = true } label: {
                    Label("Add", systemImage: "plus")
                }.buttonStyle(.borderless)
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
                    .buttonStyle(.borderless).foregroundStyle(.secondary)
            }
            .padding(8)
        }
        .sheet(isPresented: $showingAdd) {
            AddProxySheet { p in
                state.addProxy(p)
                state.select(p.id)
            }
        }
    }
}

// MARK: Pools section

struct PoolsSection: View {
    @EnvironmentObject var state: AppState
    @State private var showingAdd = false
    @State private var showingOverride = false

    var body: some View {
        VStack(spacing: 0) {
            if state.pools.isEmpty {
                VStack(spacing: 8) {
                    Spacer()
                    Image(systemName: "square.stack.3d.up")
                        .font(.title2).foregroundStyle(.secondary)
                    Text("No pools configured").foregroundStyle(.secondary)
                    Text("Pools enable multi-upstream routing with failover, load balancing, and health checks.")
                        .font(.caption2).foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center).padding(.horizontal, 20)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 4) {
                        ForEach(state.pools) { pool in
                            PoolRow(pool: pool, health: state.poolHealth)
                                .contextMenu {
                                    Button(pool.isDefault ? "Default Pool" : "Set as Default") {
                                        state.setDefaultPool(pool.id)
                                    }
                                    .disabled(pool.isDefault)
                                    Divider()
                                    Button("Delete", role: .destructive) {
                                        state.removePool(pool.id)
                                    }
                                }
                        }

                        // Override chain
                        if !state.poolOverrides.isEmpty {
                            Text("ROUTING OVERRIDES")
                                .font(.caption2.weight(.bold)).foregroundStyle(.secondary)
                                .padding(.horizontal, 12).padding(.top, 8)
                            ForEach(state.poolOverrides) { ov in
                                OverrideRow(override: ov,
                                            poolName: state.pools.first { $0.id == ov.poolId }?.name ?? "?")
                                    .contextMenu {
                                        Button("Delete", role: .destructive) {
                                            state.removePoolOverride(ov.id)
                                        }
                                    }
                            }
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            Divider()
            HStack {
                Button { showingAdd = true } label: {
                    Label("Pool", systemImage: "plus")
                }.buttonStyle(.borderless)
                if !state.pools.isEmpty {
                    Button { showingOverride = true } label: {
                        Label("Route", systemImage: "arrow.triangle.branch")
                    }.buttonStyle(.borderless)
                }
                Spacer()
                Text(verbatim: "\(state.pools.count) pools")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(8)
        }
        .sheet(isPresented: $showingAdd) {
            AddPoolSheet { state.addPool($0) }
        }
        .sheet(isPresented: $showingOverride) {
            AddOverrideSheet(pools: state.pools) { state.addPoolOverride($0) }
        }
    }
}

struct OverrideRow: View {
    let override: PoolOverride
    let poolName: String
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.triangle.branch")
                .foregroundStyle(.orange).frame(width: 20)
            Text(override.hostPattern)
                .font(.system(.caption, design: .monospaced))
            Image(systemName: "arrow.right")
                .font(.caption2).foregroundStyle(.tertiary)
            Text(poolName)
                .font(.caption.weight(.medium)).foregroundStyle(.blue)
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 4)
    }
}

struct AddOverrideSheet: View {
    @Environment(\.dismiss) private var dismiss
    let pools: [UpstreamPool]
    @State private var pattern = ""
    @State private var selectedPoolId: UUID?
    let onAdd: (PoolOverride) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add Routing Override").font(.headline)
            VStack(alignment: .leading, spacing: 6) {
                Text("Host pattern").font(.caption).foregroundStyle(.secondary)
                TextField("*.github.com", text: $pattern)
                    .textFieldStyle(.roundedBorder)
                Text("Route to Pool").font(.caption).foregroundStyle(.secondary)
                Picker("", selection: $selectedPoolId) {
                    Text("Select...").tag(nil as UUID?)
                    ForEach(pools) { Text($0.name).tag($0.id as UUID?) }
                }
                .labelsHidden()
            }
            Text("Requests matching this pattern will use the selected pool instead of the default.")
                .font(.caption2).foregroundStyle(.tertiary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add") {
                    guard let pid = selectedPoolId else { return }
                    onAdd(PoolOverride(hostPattern: pattern, poolId: pid))
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(pattern.isEmpty || selectedPoolId == nil)
            }
        }
        .padding(16).frame(width: 380)    }
}

// MARK: PAC section

struct PACSection: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Toggle("Enable PAC Server", isOn: pacBinding(\.enabled))
                    .font(.caption).toggleStyle(.switch).controlSize(.small)

                if state.pacSettings.enabled {
                    Text("PAC (Proxy Auto-Configuration) catches apps that ignore HTTP_PROXY env vars. Most Electron apps (Slack, VSCode), Python, and Node.js respect PAC.")
                        .font(.caption2).foregroundStyle(.tertiary)

                    HStack {
                        Text("PAC Port").font(.caption)
                        Spacer()
                        TextField("", value: pacBinding(\.port), format: .number)
                            .textFieldStyle(.roundedBorder).frame(width: 70).font(.caption)
                    }

                    Picker("Mode", selection: pacBinding(\.mode)) {
                        ForEach(PACSettings.PACMode.allCases) { Text($0.rawValue).tag($0) }
                    }.font(.caption)

                    if state.pacSettings.mode == .smartBypass {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("DIRECT BYPASS").font(.caption2.weight(.bold)).foregroundStyle(.secondary)
                            Text("Domains in your Allowlist (Rules → Allow tab) will bypass the proxy entirely via PAC DIRECT.")
                                .font(.caption2).foregroundStyle(.tertiary)
                            let directCount = state.allowlist.filter(\.enabled).filter { !$0.pattern.contains("/") }.count
                            Text(verbatim: "\(directCount) domains configured for DIRECT bypass")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }

                    if state.isEnabled {
                        HStack {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                            Text(verbatim: PACServer.shared.pacURL)
                                .font(.system(.caption2, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("APP COMPATIBILITY").font(.caption2.weight(.bold)).foregroundStyle(.secondary)
                        CompatRow(app: "Safari", works: true)
                        CompatRow(app: "Chrome / Edge", works: true)
                        CompatRow(app: "Electron (Slack, VSCode)", works: true)
                        CompatRow(app: "Python requests / httpx", works: true)
                        CompatRow(app: "Node.js fetch", works: true)
                        CompatRow(app: "curl", works: true)
                        CompatRow(app: "gRPC (Windsurf/Codeium)", works: false)
                    }
                }
            }
            .padding(12)
        }
    }

    private func pacBinding<T>(_ keyPath: WritableKeyPath<PACSettings, T>) -> Binding<T> {
        Binding(
            get: { state.pacSettings[keyPath: keyPath] },
            set: { newVal in
                var s = state.pacSettings
                s[keyPath: keyPath] = newVal
                state.updatePAC(s)
            }
        )
    }
}

struct CompatRow: View {
    let app: String
    let works: Bool
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: works ? "checkmark.circle.fill" : "xmark.circle")
                .font(.caption2)
                .foregroundStyle(works ? .green : .red)
            Text(app).font(.caption2)
        }
    }
}

struct PoolRow: View {
    let pool: UpstreamPool
    let health: [UUID: MemberHealth]

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: pool.isDefault ? "star.fill" : "square.stack.3d.up")
                .foregroundStyle(pool.isDefault ? .yellow : .secondary)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(pool.name)
                        .font(.system(.body, design: .rounded).weight(.medium))
                    if pool.isDefault {
                        Text("DEFAULT")
                            .font(.system(size: 8, weight: .bold))
                            .padding(.horizontal, 4).padding(.vertical, 1)
                            .background(.yellow.opacity(0.2), in: RoundedRectangle(cornerRadius: 3))
                            .foregroundStyle(.yellow)
                    }
                }
                HStack(spacing: 6) {
                    Text(pool.strategy.rawValue)
                    Text(verbatim: "• \(pool.members.count) members")
                    let healthy = pool.members.filter { health[$0.id]?.isHealthy ?? true }.count
                    Text(verbatim: "• \(healthy)/\(pool.members.count) healthy")
                        .foregroundStyle(healthy == pool.members.count ? .green : .orange)
                }
                .font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }
}

struct AddPoolSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var host = ""
    @State private var port = "8080"
    @State private var strategy: UpstreamPool.Strategy = .failover
    let onAdd: (UpstreamPool) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add Pool").font(.headline)
            VStack(alignment: .leading, spacing: 6) {
                Text("Pool Name").font(.caption).foregroundStyle(.secondary)
                TextField("My Pool", text: $name)
                    .textFieldStyle(.roundedBorder)
                Text("First Member Host").font(.caption).foregroundStyle(.secondary)
                TextField("proxy1.example.com", text: $host)
                    .textFieldStyle(.roundedBorder)
                Text("Port").font(.caption).foregroundStyle(.secondary)
                TextField("8080", text: $port)
                    .textFieldStyle(.roundedBorder)
                Text("Strategy").font(.caption).foregroundStyle(.secondary)
                Picker("", selection: $strategy) {
                    ForEach(UpstreamPool.Strategy.allCases) { Text($0.rawValue).tag($0) }
                }
                .labelsHidden()
            }
            Text("You can add more members after creation via right-click.")
                .font(.caption2).foregroundStyle(.tertiary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add") {
                    let pool = UpstreamPool(
                        name: name.isEmpty ? "Pool" : name,
                        members: [PoolMember(host: host, port: Int(port) ?? 8080)],
                        strategy: strategy,
                        healthCheck: HealthCheckConfig()
                    )
                    onAdd(pool)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction).disabled(host.isEmpty)
            }
        }
        .padding(16).frame(width: 340)    }
}

struct ProxyRow: View {
    let proxy: ProxyConfig
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
                .foregroundStyle(isSelected ? Color.accentColor : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(proxy.name)
                    .font(.system(.body, design: .rounded).weight(.medium))
                Text(verbatim: "\(proxy.host):\(proxy.port)\(proxy.applyToHTTPS ? " • HTTPS" : "")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(
            isSelected
            ? Color.accentColor.opacity(0.10)
            : Color.clear,
            in: RoundedRectangle(cornerRadius: 6)
        )
        .padding(.horizontal, 6)
    }
}

struct AddProxySheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var host = ""
    @State private var port = "8080"
    @State private var https = true
    let onAdd: (ProxyConfig) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Add Proxy").font(.headline)

            VStack(alignment: .leading, spacing: 6) {
                Text("Name").font(.caption).foregroundStyle(.secondary)
                TextField("My Proxy", text: $name)
                    .textFieldStyle(.roundedBorder)

                Text("Host").font(.caption).foregroundStyle(.secondary)
                TextField("192.168.1.1 or proxy.example.com", text: $host)
                    .textFieldStyle(.roundedBorder)

                Text("Port").font(.caption).foregroundStyle(.secondary)
                TextField("8080", text: $port)
                    .textFieldStyle(.roundedBorder)

                Toggle("Apply to HTTPS too", isOn: $https)
                    .padding(.top, 4)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Add") {
                    let p = ProxyConfig(
                        name: name.isEmpty ? "Proxy" : name,
                        host: host,
                        port: Int(port) ?? 8080,
                        applyToHTTPS: https
                    )
                    onAdd(p)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(host.isEmpty)
            }
        }
        .padding(16)
        .frame(width: 320)    }
}

// MARK: - Logs tab (search, filter, click-to-rule)

struct LogsView: View {
    @EnvironmentObject var state: AppState
    @State private var search = ""
    @State private var debouncedSearch = ""
    @State private var levelFilter: LogEntry.Level?

    private var filteredLogs: [LogEntry] {
        state.logs.filter { entry in
            if let lf = levelFilter, entry.level != lf { return false }
            if debouncedSearch.isEmpty { return true }
            let q = debouncedSearch.lowercased()
            return entry.message.lowercased().contains(q) ||
                   entry.host.lowercased().contains(q)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Search + filter bar
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                    .font(.caption)
                TextField("Search logs...", text: $search)
                    .textFieldStyle(.plain)
                    .font(.caption)

                ForEach([
                    (nil as LogEntry.Level?, "All", Color.primary),
                    (LogEntry.Level.info,    "I",   Color.blue),
                    (LogEntry.Level.warn,    "W",   Color.orange),
                    (LogEntry.Level.error,   "E",   Color.red)
                ], id: \.1) { (level, label, color) in
                    Button {
                        levelFilter = levelFilter == level ? nil : level
                    } label: {
                        Text(label)
                            .font(.system(.caption2, design: .monospaced).weight(.bold))
                            .foregroundStyle(levelFilter == level ? .white : color)
                            .frame(width: 20, height: 18)
                            .background(
                                levelFilter == level ? color : Color.clear,
                                in: RoundedRectangle(cornerRadius: 3)
                            )
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)

            Divider()

            if filteredLogs.isEmpty {
                Spacer()
                VStack(spacing: 6) {
                    Image(systemName: state.logs.isEmpty ? "doc.text" : "magnifyingglass")
                        .font(.title2).foregroundStyle(.quaternary)
                    Text(state.logs.isEmpty ? "No logs yet" : "No matching logs")
                        .font(.caption).foregroundStyle(.secondary)
                    if state.logs.isEmpty {
                        Text("Logs appear here when the proxy is active")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(filteredLogs.reversed()) { entry in
                            EquatableView(content: LogRow(entry: entry))
                                .contextMenu {
                                    if !entry.host.isEmpty {
                                        Button("Block \(entry.host)") {
                                            state.addRule(WAFRule(
                                                name: "Block \(entry.host)",
                                                kind: .blockDomain,
                                                pattern: entry.host,
                                                category: "Custom"
                                            ))
                                        }
                                        Button("Allow \(entry.host)") {
                                            state.addAllowRule(entry.host)
                                        }
                                        Button("Search: \(entry.host)") {
                                            search = entry.host
                                        }
                                        Divider()
                                    }
                                    Button("Copy") {
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general.setString(entry.message, forType: .string)
                                    }
                                    Button("Copy as JSON") {
                                        let obj: [String: Any] = [
                                            "timestamp": ISO8601DateFormatter().string(from: entry.timestamp),
                                            "level": entry.level.rawValue,
                                            "host": entry.host,
                                            "message": entry.message,
                                        ]
                                        if let data = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]),
                                           let str = String(data: data, encoding: .utf8) {
                                            NSPasteboard.general.clearContents()
                                            NSPasteboard.general.setString(str, forType: .string)
                                        }
                                    }
                                }
                        }
                    }
                    .padding(6)
                }
            }

            Divider()
            HStack {
                Text(verbatim: "\(filteredLogs.count)\(filteredLogs.count != state.logs.count ? " / \(state.logs.count)" : "") entries")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Clear") { state.clearLogs() }
                    .buttonStyle(.borderless)
                    .disabled(state.logs.isEmpty)
            }
            .padding(8)
        }
        .task(id: search) {
            try? await Task.sleep(for: .milliseconds(300))
            if !Task.isCancelled { debouncedSearch = search }
        }
    }
}

struct LogRow: View, Equatable {
    let entry: LogEntry
    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    static func == (lhs: LogRow, rhs: LogRow) -> Bool {
        lhs.entry.id == rhs.entry.id
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(Self.formatter.string(from: entry.timestamp))
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.tertiary)
            Circle()
                .fill(color)
                .frame(width: 5, height: 5)
            Text(entry.message)
                .font(.caption2)
                .textSelection(.enabled)
                .lineLimit(2)
            Spacer(minLength: 0)
        }
        .padding(.vertical, 1)
    }
    private var color: Color {
        switch entry.level {
        case .info:  return .blue
        case .warn:  return .orange
        case .error: return .red
        }
    }
}

// MARK: - Community bar

struct CommunityBar: View {
    @Environment(\.openURL) private var openURL

    private let links: [(icon: String, label: String, url: String)] = [
        ("star",              "Star",    "https://github.com/fabriziosalmi/proxymate"),
        ("ant",               "Bug",     "https://github.com/fabriziosalmi/proxymate/issues/new?labels=bug&template=bug_report.yml"),
        ("plus.bubble",       "Idea",    "https://github.com/fabriziosalmi/proxymate/issues/new?labels=enhancement&template=feature_request.yml"),
        ("text.bubble",       "Discuss", "https://github.com/fabriziosalmi/proxymate/discussions"),
        ("arrow.up.heart",    "Support", "https://github.com/sponsors/fabriziosalmi"),
    ]

    var body: some View {
        Divider()
        HStack(spacing: 0) {
            ForEach(links, id: \.label) { link in
                Button {
                    if let u = URL(string: link.url) { openURL(u) }
                } label: {
                    VStack(spacing: 2) {
                        Image(systemName: link.icon)
                            .font(.system(size: 10, weight: .regular))
                        Text(link.label)
                            .font(.system(size: 8, weight: .medium))
                    }
                    .frame(maxWidth: .infinity)
                    .foregroundStyle(.tertiary)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(link.label)
            }
        }
        .padding(.vertical, 5)
        .padding(.horizontal, 6)
    }
}

// MARK: - Stats tab

struct StatsView: View {
    @EnvironmentObject var state: AppState
    private static let relative = RelativeDateTimeFormatter()

    var body: some View {
        ScrollView {
            VStack(spacing: 10) {
                HStack(spacing: 10) {
                    StatCard(title: "Status",
                             value: state.isEnabled ? "On" : "Off",
                             color: state.isEnabled ? .green : .secondary)
                    StatCard(title: "Active Since",
                             value: state.stats.enabledSince
                                .map { Self.relative.localizedString(for: $0, relativeTo: Date()) }
                                ?? "—",
                             color: .secondary)
                }
                HStack(spacing: 10) {
                    StatCard(title: "Allowed",
                             value: "\(state.stats.requestsAllowed)",
                             color: .blue)
                    StatCard(title: "WAF Blocked",
                             value: "\(state.stats.requestsBlocked)",
                             color: .red)
                }
                HStack(spacing: 10) {
                    StatCard(title: "Blacklisted",
                             value: "\(state.stats.blacklistBlocked)",
                             color: .orange)
                    StatCard(title: "Exfiltration",
                             value: "\(state.stats.exfiltrationBlocked)",
                             color: .red)
                }
                HStack(spacing: 10) {
                    StatCard(title: "Privacy",
                             value: "\(state.stats.privacyActions)",
                             color: .purple)
                    StatCard(title: "MITM",
                             value: "\(state.stats.mitmIntercepted)",
                             color: .indigo)
                }
                HStack(spacing: 10) {
                    let total = state.stats.cacheHits + state.stats.cacheMisses
                    StatCard(title: "Cache Hit Rate",
                             value: total > 0 ? "\(state.stats.cacheHits * 100 / max(total, 1))%" : "—",
                             color: .teal)
                    StatCard(title: "Log Entries",
                             value: "\(state.logs.count)",
                             color: .secondary)
                }

                // Live chart
                VStack(alignment: .leading, spacing: 4) {
                    Text("REQUESTS / SECOND").font(.caption2.weight(.bold)).foregroundStyle(.secondary)
                    Chart(state.timeSeries.points) { point in
                        AreaMark(
                            x: .value("Time", point.timestamp),
                            y: .value("Allowed", point.allowed)
                        )
                        .foregroundStyle(.blue.opacity(0.3))
                        AreaMark(
                            x: .value("Time", point.timestamp),
                            y: .value("Blocked", point.blocked)
                        )
                        .foregroundStyle(.red.opacity(0.3))
                        LineMark(
                            x: .value("Time", point.timestamp),
                            y: .value("Allowed", point.allowed)
                        )
                        .foregroundStyle(.blue)
                        LineMark(
                            x: .value("Time", point.timestamp),
                            y: .value("Blocked", point.blocked)
                        )
                        .foregroundStyle(.red)
                    }
                    .chartXAxis(.hidden)
                    .chartYAxis {
                        AxisMarks(position: .leading) { value in
                            AxisValueLabel {
                                if let v = value.as(Int.self) {
                                    Text(verbatim: "\(v)").font(.caption2)
                                }
                            }
                        }
                    }
                    .frame(height: 80)

                    HStack(spacing: 12) {
                        Label("Allowed", systemImage: "circle.fill")
                            .font(.caption2).foregroundStyle(.blue)
                        Label("Blocked", systemImage: "circle.fill")
                            .font(.caption2).foregroundStyle(.red)
                    }
                }

                // Host profiling
                let _ = state.statsTick  // 1Hz dependency — see AppState.statsTick
                let topHosts = HostMemory.shared.topHosts(limit: 5)
                if !topHosts.isEmpty {
                    Divider()
                    Text("TOP HOSTS").font(.caption2.weight(.bold)).foregroundStyle(.secondary)
                    ForEach(topHosts, id: \.host) { item in
                        HStack(spacing: 6) {
                            Circle()
                                .fill(item.profile.isUnhealthy ? Color.red : .green)
                                .frame(width: 6, height: 6)
                            Text(item.host)
                                .font(.system(.caption2, design: .monospaced))
                                .lineLimit(1)
                            Spacer()
                            Text(verbatim: "\(item.profile.requestCount)")
                                .font(.caption2.weight(.bold)).monospacedDigit()
                            if item.profile.errorRate > 0 {
                                Text(verbatim: "\(Int(item.profile.errorRate * 100))%err")
                                    .font(.system(size: 8)).foregroundStyle(.red)
                            }
                        }
                    }
                    Text(verbatim: "\(HostMemory.shared.totalHosts) unique hosts")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
            }
            .padding(12)
        }
    }
}

struct StatCard: View {
    let title: String
    let value: String
    let color: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value)
                .font(.title3.weight(.semibold))
                .foregroundStyle(color)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
                .contentTransition(.numericText())
                .animation(.easeInOut(duration: 0.3), value: value)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(.quaternary.opacity(0.4),
                    in: RoundedRectangle(cornerRadius: 8))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)")
    }
}

// MARK: - Rules tab (segmented: WAF / Blacklists / Exfiltration)

struct RulesView: View {
    @EnvironmentObject var state: AppState
    @State private var section: RulesSection = .waf

    enum RulesSection: String, CaseIterable, Identifiable {
        case waf          = "WAF"
        case allowlist    = "Allow"
        case blacklists   = "Lists"
        case exfiltration = "Secrets"
        case threats      = "Threats"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("Section", selection: $section) {
                ForEach(RulesSection.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .controlSize(.small)
            .padding(8)

            Divider()

            switch section {
            case .waf:          WAFRulesSection()
            case .allowlist:    AllowlistSection()
            case .blacklists:   BlacklistsSection()
            case .exfiltration: ExfiltrationSection()
            case .threats:      ThreatsSection()
            }
        }
    }
}

// MARK: WAF sub-section

struct WAFRulesSection: View {
    @EnvironmentObject var state: AppState
    @State private var showingAdd = false
    @State private var showingImport = false

    private var grouped: [(category: String, rules: [WAFRule])] {
        let dict = Dictionary(grouping: state.rules) { $0.category.isEmpty ? "Custom" : $0.category }
        return dict.keys.sorted().map { ($0, dict[$0]!) }
    }

    var body: some View {
        VStack(spacing: 0) {
            if state.rules.isEmpty {
                VStack(spacing: 8) {
                    Spacer()
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.title2).foregroundStyle(.quaternary)
                    Text("No rules yet").font(.caption).foregroundStyle(.secondary)
                    Text("Rules control what gets blocked, allowed, or inspected")
                        .font(.caption2).foregroundStyle(.tertiary)
                    Button("Load Examples") { state.loadExampleRules() }
                        .buttonStyle(.bordered).controlSize(.small)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                List {
                    ForEach(state.rules) { rule in
                        HStack(spacing: 0) {
                            RuleRow(rule: rule)
                            Spacer()
                            Toggle("", isOn: Binding(
                                get: { rule.enabled },
                                set: { _ in state.toggleRule(rule.id) }
                            ))
                            .toggleStyle(.switch)
                            .controlSize(.mini)
                            .labelsHidden()
                        }
                        .contextMenu {
                            Button(rule.enabled ? "Disable" : "Enable") {
                                state.toggleRule(rule.id)
                            }
                            Divider()
                            Button("Delete", role: .destructive) {
                                state.removeRule(rule.id)
                            }
                        }
                        .listRowInsets(EdgeInsets(top: 1, leading: 4, bottom: 1, trailing: 8))
                    }
                    .onMove { state.moveRule(from: $0, to: $1) }
                    .onDelete { state.deleteRules(at: $0) }
                }
                .listStyle(.plain)
            }
            Divider()
            HStack {
                Button { showingAdd = true } label: {
                    Label("Add", systemImage: "plus")
                }.buttonStyle(.borderless)
                Button("Examples") { state.loadExampleRules() }
                    .buttonStyle(.borderless).foregroundStyle(.secondary)
                Button("Import") { showingImport = true }
                    .buttonStyle(.borderless).foregroundStyle(.secondary)
                Spacer()
                Toggle("Shadow", isOn: Binding(
                    get: { state.wafShadowMode },
                    set: { state.wafShadowMode = $0; state.syncShadowMode() }
                ))
                .toggleStyle(.switch).controlSize(.mini)
                .help("Shadow mode: log blocks without enforcing (dry run)")
                Text(verbatim: "\(state.rules.filter(\.enabled).count) / \(state.rules.count)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(8)
        }
        .sheet(isPresented: $showingAdd) {
            AddRuleSheet { state.addRule($0) }
        }
        .sheet(isPresented: $showingImport) {
            ImportRulesSheet()
        }
    }
}

struct RuleRow: View {
    let rule: WAFRule
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "shield.lefthalf.filled")
                .foregroundStyle(rule.enabled ? .red : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(rule.name.isEmpty ? rule.pattern : rule.name)
                    .font(.system(.body, design: .rounded).weight(.medium))
                Text("\(rule.kind.rawValue) • \(rule.pattern)")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }
}

struct AddRuleSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var kind: WAFRule.Kind = .blockDomain
    @State private var pattern = ""
    @State private var category = "Custom"
    let onAdd: (WAFRule) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Add Rule").font(.headline)

            VStack(alignment: .leading, spacing: 6) {
                Text("Name (optional)").font(.caption).foregroundStyle(.secondary)
                TextField("My Rule", text: $name)
                    .textFieldStyle(.roundedBorder)

                Text("Type").font(.caption).foregroundStyle(.secondary)
                Picker("", selection: $kind) {
                    ForEach(WAFRule.Kind.allCases) { Text($0.rawValue).tag($0) }
                }
                .labelsHidden()

                Text("Pattern").font(.caption).foregroundStyle(.secondary)
                TextField(placeholder, text: $pattern)
                    .textFieldStyle(.roundedBorder)

                Text("Category").font(.caption).foregroundStyle(.secondary)
                TextField("Custom", text: $category)
                    .textFieldStyle(.roundedBorder)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add") {
                    onAdd(WAFRule(name: name, kind: kind, pattern: pattern,
                                  category: category.isEmpty ? "Custom" : category))
                    dismiss()
                }
                .keyboardShortcut(.defaultAction).disabled(pattern.isEmpty)
            }
        }
        .padding(16).frame(width: 340)    }

    private var placeholder: String {
        switch kind {
        case .allowDomain:  return "example.com"
        case .blockIP:      return "1.2.3.4"
        case .blockDomain:  return "example.com"
        case .blockContent: return "substring"
        case .blockRegex:   return "(?i)union\\s+select"
        case .mockDomain:   return "tracker.example.com"
        }
    }
}

// MARK: Import sheet

struct ImportRulesSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var source: ImportSource = .url
    @State private var urlText = ""
    @State private var pasteText = ""
    @State private var format: RuleImporter.ImportFormat = .autoDetect
    @State private var category = "Imported"

    enum ImportSource: String, CaseIterable { case url = "URL", paste = "Paste" }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Import Rules").font(.headline)
            Picker("Source", selection: $source) {
                ForEach(ImportSource.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }.pickerStyle(.segmented)

            if source == .url {
                TextField("https://example.com/hosts.txt", text: $urlText)
                    .textFieldStyle(.roundedBorder).font(.caption)
            } else {
                TextEditor(text: $pasteText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(height: 100)
                    .border(Color.secondary.opacity(0.3))
            }

            HStack {
                Picker("Format", selection: $format) {
                    ForEach(RuleImporter.ImportFormat.allCases) { Text($0.rawValue).tag($0) }
                }.frame(width: 160)
                TextField("Category", text: $category)
                    .textFieldStyle(.roundedBorder).frame(width: 100)
            }.font(.caption)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Import") {
                    if source == .url {
                        state.importRulesFromURL(urlText, format: format, category: category)
                    } else {
                        state.importRulesFromText(pasteText, format: format, category: category)
                    }
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(source == .url ? urlText.isEmpty : pasteText.isEmpty)
            }
        }
        .padding(16).frame(width: 400)    }
}

// MARK: Allowlist sub-section

struct AllowlistSection: View {
    @EnvironmentObject var state: AppState
    @State private var showingAdd = false

    var body: some View {
        VStack(spacing: 0) {
            if state.allowlist.isEmpty {
                VStack(spacing: 8) {
                    Spacer()
                    Image(systemName: "checkmark.shield")
                        .font(.title2).foregroundStyle(.quaternary)
                    Text("No allowlist entries").font(.caption).foregroundStyle(.secondary)
                    Text("Allowed hosts bypass all block rules, blacklists, and exfiltration scans. Supports IPs, CIDR ranges, and domains.")
                        .font(.caption2).foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center).padding(.horizontal, 16)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                List {
                    ForEach(state.allowlist) { entry in
                        AllowEntryRow(entry: entry)
                            .contextMenu {
                                Button(entry.enabled ? "Disable" : "Enable") {
                                    state.toggleAllowEntry(entry.id)
                                }
                                Divider()
                                Button("Delete", role: .destructive) {
                                    state.removeAllowEntry(entry.id)
                                }
                            }
                            .listRowInsets(EdgeInsets(top: 1, leading: 4, bottom: 1, trailing: 4))
                    }
                    .onMove { state.moveAllowEntries(from: $0, to: $1) }
                    .onDelete { state.deleteAllowEntries(at: $0) }
                }
                .listStyle(.plain)
            }
            Divider()
            HStack {
                Button { showingAdd = true } label: {
                    Label("Add", systemImage: "plus")
                }.buttonStyle(.borderless)
                Spacer()
                Text(verbatim: "\(state.allowlist.filter(\.enabled).count) entries")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(8)
        }
        .sheet(isPresented: $showingAdd) {
            AddAllowEntrySheet { state.addAllowEntry($0) }
        }
    }
}

struct AllowEntryRow: View {
    let entry: AllowEntry
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "checkmark.shield")
                .foregroundStyle(entry.enabled ? .green : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.pattern)
                    .font(.system(.body, design: .monospaced).weight(.medium))
                HStack(spacing: 4) {
                    if let port = entry.port { Text(verbatim: ":\(port)") }
                    if let proto = entry.proto, proto != .any { Text(proto.rawValue) }
                    if !entry.note.isEmpty { Text(entry.note) }
                }
                .font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
            if !entry.enabled {
                Text("OFF").font(.caption2.weight(.bold)).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }
}

struct AddAllowEntrySheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var pattern = ""
    @State private var port = ""
    @State private var proto: AllowEntry.Proto = .any
    @State private var note = ""
    let onAdd: (AllowEntry) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add Allow Entry").font(.headline)
            VStack(alignment: .leading, spacing: 6) {
                Text("Pattern").font(.caption).foregroundStyle(.secondary)
                TextField("IP, CIDR (10.0.0.0/8), or domain", text: $pattern)
                    .textFieldStyle(.roundedBorder)
                HStack(spacing: 8) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Port (optional)").font(.caption).foregroundStyle(.secondary)
                        TextField("Any", text: $port)
                            .textFieldStyle(.roundedBorder).frame(width: 100)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Protocol").font(.caption).foregroundStyle(.secondary)
                        Picker("", selection: $proto) {
                            ForEach(AllowEntry.Proto.allCases) { Text($0.rawValue).tag($0) }
                        }
                        .labelsHidden()
                    }
                }
                Text("Note (optional)").font(.caption).foregroundStyle(.secondary)
                TextField("Why is this allowed?", text: $note)
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add") {
                    onAdd(AllowEntry(
                        pattern: pattern,
                        port: Int(port),
                        proto: proto == .any ? nil : proto,
                        note: note
                    ))
                    dismiss()
                }
                .keyboardShortcut(.defaultAction).disabled(pattern.isEmpty)
            }
        }
        .padding(16).frame(width: 380)    }
}

// MARK: Threats sub-section (C2, Beaconing, Agent policies)

struct ThreatsSection: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                // C2 Detection
                sectionHeader("C2 FRAMEWORK DETECTION")
                Toggle("Enable C2 detection", isOn: c2Binding(\.enabled))
                    .font(.caption).toggleStyle(.switch).controlSize(.small)
                if state.c2Settings.enabled {
                    Picker("Action", selection: c2Binding(\.action)) {
                        ForEach(C2Settings.Action.allCases) { Text($0.rawValue).tag($0) }
                    }.font(.caption).pickerStyle(.segmented)
                    Text("Detects Cobalt Strike, Sliver, Mythic, Empire, Havoc, Metasploit default signatures in HTTP headers and URLs.")
                        .font(.caption2).foregroundStyle(.tertiary)
                    if state.stats.c2Detections > 0 {
                        HStack {
                            Image(systemName: "exclamationmark.shield")
                                .foregroundStyle(.red)
                            Text(verbatim: "\(state.stats.c2Detections) C2 detections this session")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }

                Divider()

                // Beaconing
                sectionHeader("BEACONING DETECTION")
                Toggle("Enable beaconing detection", isOn: beaconBinding(\.enabled))
                    .font(.caption).toggleStyle(.switch).controlSize(.small)
                if state.beaconingSettings.enabled {
                    Picker("Action", selection: beaconBinding(\.action)) {
                        ForEach(BeaconingSettings.Action.allCases) { Text($0.rawValue).tag($0) }
                    }.font(.caption).pickerStyle(.segmented)
                    HStack {
                        Text("Threshold").font(.caption)
                        Spacer()
                        TextField("", value: beaconBinding(\.minConsecutive), format: .number)
                            .textFieldStyle(.roundedBorder).frame(width: 40).font(.caption)
                        Text("intervals").font(.caption2).foregroundStyle(.secondary)
                    }
                    HStack {
                        Text("Jitter tolerance").font(.caption)
                        Spacer()
                        TextField("", value: beaconBinding(\.jitterTolerancePercent), format: .number)
                            .textFieldStyle(.roundedBorder).frame(width: 40).font(.caption)
                        Text("%").font(.caption2).foregroundStyle(.secondary)
                    }
                    Text("Detects same host+path requested at fixed intervals. Typical of malware check-ins and C2 implants.")
                        .font(.caption2).foregroundStyle(.tertiary)
                }

                Divider()

                // Agent policies
                sectionHeader("AI AGENT POLICIES")
                ForEach(state.aiAgentSettings.policies) { policy in
                    HStack {
                        Text(policy.name).font(.caption)
                        Spacer()
                        Picker("", selection: agentPolicyBinding(policy.agentId)) {
                            ForEach(AIAgentPolicy.Action.allCases) { Text($0.rawValue).tag($0) }
                        }
                        .pickerStyle(.menu).frame(width: 100).font(.caption)
                    }
                }
                Text("Controls how each AI coding agent is handled when detected by User-Agent or host pattern.")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
            .padding(12)
        }
    }

    private func sectionHeader(_ title: String) -> some View {
        Text(title).font(.caption2.weight(.bold)).foregroundStyle(.secondary)
    }

    private func c2Binding<T>(_ kp: WritableKeyPath<C2Settings, T>) -> Binding<T> {
        Binding(get: { state.c2Settings[keyPath: kp] },
                set: { var s = state.c2Settings; s[keyPath: kp] = $0; state.updateC2(s) })
    }

    private func beaconBinding<T>(_ kp: WritableKeyPath<BeaconingSettings, T>) -> Binding<T> {
        Binding(get: { state.beaconingSettings[keyPath: kp] },
                set: { var s = state.beaconingSettings; s[keyPath: kp] = $0
                       state.updateBeaconing(s) })
    }

    private func agentPolicyBinding(_ agentId: String) -> Binding<AIAgentPolicy.Action> {
        Binding(
            get: {
                state.aiAgentSettings.policies.first { $0.agentId == agentId }?.action ?? .audit
            },
            set: { newAction in
                var s = state.aiAgentSettings
                if let i = s.policies.firstIndex(where: { $0.agentId == agentId }) {
                    s.policies[i].action = newAction
                    state.updateAIAgentSettings(s)
                }
            }
        )
    }
}

// MARK: Blacklists sub-section

struct BlacklistsSection: View {
    @EnvironmentObject var state: AppState
    @State private var isRefreshing = false
    @State private var showingAddCustom = false

    var body: some View {
        VStack(spacing: 0) {
            if state.blacklistSources.isEmpty {
                VStack(spacing: 8) {
                    Spacer()
                    Image(systemName: "list.bullet.rectangle")
                        .font(.title2).foregroundStyle(.secondary)
                    Text("No blacklists configured").foregroundStyle(.secondary)
                    Button("Add Built-in Lists") { state.loadBuiltInBlacklists() }
                        .buttonStyle(.bordered).controlSize(.small)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 2) {
                        ForEach(state.blacklistSources) { source in
                            BlacklistRow(source: source)
                                .contextMenu {
                                    Button(source.enabled ? "Disable" : "Enable") {
                                        state.toggleBlacklistSource(source.id)
                                    }
                                    Button("Refresh Now") {
                                        state.refreshBlacklist(source.id)
                                    }
                                    Divider()
                                    Button("Remove", role: .destructive) {
                                        state.removeBlacklistSource(source.id)
                                    }
                                }
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            Divider()
            HStack {
                Button("Built-in") { state.loadBuiltInBlacklists() }
                    .buttonStyle(.borderless)
                Button("Custom") { showingAddCustom = true }
                    .buttonStyle(.borderless)
                Spacer()
                Button {
                    guard !isRefreshing else { return }
                    isRefreshing = true
                    state.refreshAllBlacklists()
                    Task {
                        try? await Task.sleep(for: .seconds(2))
                        isRefreshing = false
                    }
                } label: {
                    if isRefreshing {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
                .buttonStyle(.borderless)
            }
            .padding(8)

            // Aggregate stats
            if !state.blacklistSources.isEmpty {
                Divider()
                let _ = state.statsTick  // 1Hz dependency — BlacklistManager is not ObservableObject
                HStack(spacing: 12) {
                    VStack(alignment: .leading) {
                        Text("Total").font(.system(size: 7)).foregroundStyle(.tertiary)
                        Text(verbatim: "\(BlacklistManager.shared.totalEntries)")
                            .font(.caption2.weight(.bold)).monospacedDigit()
                    }
                    VStack(alignment: .leading) {
                        Text("Unique").font(.system(size: 7)).foregroundStyle(.tertiary)
                        Text(verbatim: "\(BlacklistManager.shared.uniqueEntries)")
                            .font(.caption2.weight(.bold)).monospacedDigit()
                    }
                    VStack(alignment: .leading) {
                        Text("Sources").font(.system(size: 7)).foregroundStyle(.tertiary)
                        Text(verbatim: "\(state.blacklistSources.filter(\.enabled).count)")
                            .font(.caption2.weight(.bold)).monospacedDigit()
                    }
                    Spacer()
                }
                .padding(.horizontal, 12).padding(.bottom, 4)
            }
        }
        .sheet(isPresented: $showingAddCustom) {
            AddCustomBlacklistSheet { source in
                state.addBlacklistSource(source)
                state.refreshBlacklist(source.id)
            }
        }
    }
}

struct AddCustomBlacklistSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""
    @State private var category: BlacklistSource.BlacklistCategory = .custom
    @State private var format: BlacklistSource.ListFormat = .hosts
    let onAdd: (BlacklistSource) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add Custom Blacklist").font(.headline)
            VStack(alignment: .leading, spacing: 6) {
                Text("Name").font(.caption).foregroundStyle(.secondary)
                TextField("My List", text: $name)
                    .textFieldStyle(.roundedBorder)
                Text("URL").font(.caption).foregroundStyle(.secondary)
                TextField("https://example.com/blocklist.txt", text: $url)
                    .textFieldStyle(.roundedBorder)
                Text("Category").font(.caption).foregroundStyle(.secondary)
                Picker("", selection: $category) {
                    ForEach(BlacklistSource.BlacklistCategory.allCases) { Text($0.rawValue).tag($0) }
                }
                .labelsHidden()
                Text("Format").font(.caption).foregroundStyle(.secondary)
                Picker("", selection: $format) {
                    ForEach(BlacklistSource.ListFormat.allCases) { Text($0.rawValue).tag($0) }
                }
                .labelsHidden()
            }
            Text("Lists auto-refresh every 6 hours when enabled.")
                .font(.caption2).foregroundStyle(.tertiary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add & Refresh") {
                    onAdd(BlacklistSource(name: name.isEmpty ? "Custom" : name,
                                          url: url, category: category, format: format))
                    dismiss()
                }
                .keyboardShortcut(.defaultAction).disabled(url.isEmpty)
            }
        }
        .padding(16).frame(width: 380)    }
}

struct BlacklistRow: View {
    let source: BlacklistSource
    private static let dateFormatter: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f
    }()

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: source.enabled ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(source.enabled ? categoryColor : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(source.name)
                    .font(.system(.body, design: .rounded).weight(.medium))
                HStack(spacing: 4) {
                    Text(source.category.rawValue)
                    if source.entryCount > 0 {
                        Text(verbatim: "• \(source.entryCount) entries")
                    }
                    if let date = source.lastUpdated {
                        Text(verbatim: "• \(Self.dateFormatter.localizedString(for: date, relativeTo: Date()))")
                    }
                }
                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }

    private var categoryColor: Color {
        switch source.category {
        case .torExits: return .purple
        case .ads: return .orange
        case .malware: return .red
        case .phishing: return .pink
        case .cryptoMiner: return .yellow
        case .telemetry: return .indigo
        case .adult: return .gray
        case .custom: return .blue
        }
    }
}

// MARK: Exfiltration sub-section

struct ExfiltrationSection: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text("SECRET DETECTION")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 12)

                Text("Scans outbound HTTP headers and URLs for leaked credentials, API keys, and tokens. Matching requests are blocked with 403.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 12)

                ForEach(state.exfiltrationPacks) { pack in
                    ExfiltrationPackRow(pack: pack) {
                        state.toggleExfiltrationPack(pack.id)
                    }
                }

                if state.stats.exfiltrationBlocked > 0 {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                        Text(verbatim: "\(state.stats.exfiltrationBlocked) exfiltration attempts blocked this session")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 12)
                }
            }
            .padding(.vertical, 8)
        }
    }
}

struct ExfiltrationPackRow: View {
    let pack: ExfiltrationPack
    let onToggle: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(pack.name)
                    .font(.system(.body, design: .rounded).weight(.medium))
                Text(verbatim: "\(pack.description) (\(pack.patterns.count) patterns)")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
            Toggle("", isOn: Binding(
                get: { pack.enabled },
                set: { _ in onToggle() }
            ))
            .toggleStyle(.switch)
            .controlSize(.small)
            .labelsHidden()
        }
        .padding(.horizontal, 12).padding(.vertical, 4)
    }
}

// MARK: - AI tab

struct AIView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                let mitmEnabled = state.mitmSettings.enabled

                // Agent detection (works without MITM — from CONNECT host)
                sectionHeader("AI AGENT DETECTION")
                HStack(spacing: 8) {
                    StatCard(title: "AI Requests", value: "\(state.stats.aiRequests)", color: .blue)
                    StatCard(title: "AI Blocked", value: "\(state.stats.aiBlocked)", color: .red)
                }
                Text("Detected from CONNECT tunnel hostnames. Works without MITM.")
                    .font(.caption2).foregroundStyle(.tertiary)

                Divider()

                // Cost tracking — only show if MITM is on
                if mitmEnabled {
                    spendSummary
                    Divider()

                    let activeProviders = AIProvider.builtIn.filter { state.aiProviderStats[$0.id] != nil }
                    if !activeProviders.isEmpty {
                        sectionHeader("PROVIDERS")
                        LazyVStack(spacing: 4) {
                            ForEach(activeProviders) { provider in
                                AIProviderRow(
                                    provider: provider,
                                    stats: state.aiProviderStats[provider.id]
                                )
                            }
                        }
                        Divider()
                    }

                    sectionHeader("BUDGET CAPS")
                    budgetSection
                    Divider()

                    sectionHeader("MODEL CONTROLS")
                    modelSection
                    Divider()

                    HStack {
                        Button("Reset Stats") { state.resetAIStats() }
                            .buttonStyle(.bordered).controlSize(.small)
                        Spacer()
                        Text(verbatim: "\(state.stats.aiRequests) requests this session")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Divider()
                } else {
                    VStack(spacing: 8) {
                        Image(systemName: "lock.shield")
                            .font(.title2).foregroundStyle(.tertiary)
                        Text("Token counting, cost tracking, and budget caps require MITM inspection.")
                            .font(.caption).foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                        Text("Enable TLS Interception in the Privacy tab to unlock full AI monitoring.")
                            .font(.caption2).foregroundStyle(.tertiary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 16)
                    Divider()
                }

                // Loop Breaker — works without MITM
                sectionHeader("LOOP BREAKER")
                loopBreakerSection
            }
            .padding(12)
        }
    }

    private var spendSummary: some View {
        let _ = state.statsTick  // 1Hz dependency — AITracker is not ObservableObject
        let (daily, monthly) = AITracker.shared.getTotalSpend()
        return HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Today").font(.caption2).foregroundStyle(.secondary)
                Text(verbatim: "$\(String(format: "%.2f", daily))")
                    .font(.title3.weight(.bold)).foregroundStyle(.blue)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text("This Month").font(.caption2).foregroundStyle(.secondary)
                Text(verbatim: "$\(String(format: "%.2f", monthly))")
                    .font(.title3.weight(.bold)).foregroundStyle(.purple)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text("Session").font(.caption2).foregroundStyle(.secondary)
                Text(verbatim: "$\(String(format: "%.4f", state.stats.aiTotalCostUSD))")
                    .font(.title3.weight(.bold)).foregroundStyle(.green)
            }
        }
    }

    private var budgetSection: some View {
        VStack(spacing: 8) {
            HStack {
                Text("Daily limit").font(.caption)
                Spacer()
                TextField("0 = no limit", value: aiBinding(\.dailyBudgetUSD),
                          format: .currency(code: "USD"))
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 100)
                    .font(.caption)
            }
            HStack {
                Text("Monthly limit").font(.caption)
                Spacer()
                TextField("0 = no limit", value: aiBinding(\.monthlyBudgetUSD),
                          format: .currency(code: "USD"))
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 100)
                    .font(.caption)
            }
            if state.stats.aiBlocked > 0 {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text(verbatim: "\(state.stats.aiBlocked) requests blocked by budget")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    @State private var newAllowModel = ""
    @State private var newBlockModel = ""

    private var modelSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Allowlist (empty = allow all)").font(.caption2).foregroundStyle(.secondary)
            HStack(spacing: 4) {
                TextField("e.g. gpt-4o-mini", text: $newAllowModel)
                    .textFieldStyle(.roundedBorder).font(.caption).frame(maxWidth: .infinity)
                Button("Add") {
                    guard !newAllowModel.isEmpty else { return }
                    var s = state.aiSettings
                    s.modelAllowlist.append(newAllowModel)
                    state.updateAISettings(s)
                    newAllowModel = ""
                }.controlSize(.small)
            }
            FlowTags(items: state.aiSettings.modelAllowlist, color: .green) { model in
                var s = state.aiSettings
                s.modelAllowlist.removeAll { $0 == model }
                state.updateAISettings(s)
            }

            Text("Blocklist (always block)").font(.caption2).foregroundStyle(.secondary)
            HStack(spacing: 4) {
                TextField("e.g. gpt-4-turbo", text: $newBlockModel)
                    .textFieldStyle(.roundedBorder).font(.caption).frame(maxWidth: .infinity)
                Button("Add") {
                    guard !newBlockModel.isEmpty else { return }
                    var s = state.aiSettings
                    s.modelBlocklist.append(newBlockModel)
                    state.updateAISettings(s)
                    newBlockModel = ""
                }.controlSize(.small)
            }
            FlowTags(items: state.aiSettings.modelBlocklist, color: .red) { model in
                var s = state.aiSettings
                s.modelBlocklist.removeAll { $0 == model }
                state.updateAISettings(s)
            }
        }
    }

    private var loopBreakerSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Toggle("Enable Loop Breaker", isOn: lbBinding(\.enabled))
                .font(.caption).toggleStyle(.switch).controlSize(.small)

            if state.loopBreakerSettings.enabled {
                Text("Detects stuck AI agents and runaway loops. First detection warns (no block). Repeated violations block with 429.")
                    .font(.caption2).foregroundStyle(.tertiary)

                Group {
                    lbRow("Identical body WARN after", value: lbBinding(\.identicalThreshold), unit: "repeats")
                    lbRow("Identical body BLOCK after", value: lbBinding(\.identicalBlockThreshold), unit: "repeats")
                    lbRow("Identical window", value: lbBinding(\.identicalWindowSeconds), unit: "seconds")
                }
                Group {
                    lbRow("Rapid-fire WARN after", value: lbBinding(\.rapidFireThreshold), unit: "req")
                    lbRow("Rapid-fire BLOCK after", value: lbBinding(\.rapidFireBlockThreshold), unit: "req")
                    lbRow("Rapid-fire window", value: lbBinding(\.rapidFireWindowSeconds), unit: "seconds")
                }
                Group {
                    lbRow("MCP loop WARN after", value: lbBinding(\.mcpRepeatThreshold), unit: "repeats")
                    lbRow("MCP loop BLOCK after", value: lbBinding(\.mcpBlockThreshold), unit: "repeats")
                }
                HStack {
                    Text("Cost hard cap").font(.caption)
                    Spacer()
                    TextField("$/min", value: lbBinding(\.maxCostPerMinuteUSD), format: .number)
                        .textFieldStyle(.roundedBorder).frame(width: 60).font(.caption)
                    Text("$/min").font(.caption2).foregroundStyle(.secondary)
                }
                lbRow("Cooldown after block", value: lbBinding(\.cooldownSeconds), unit: "seconds")
            }
        }
    }

    private func lbRow(_ label: String, value: Binding<Int>, unit: String) -> some View {
        HStack {
            Text(label).font(.caption)
            Spacer()
            TextField("", value: value, format: .number)
                .textFieldStyle(.roundedBorder).frame(width: 50).font(.caption)
            Text(unit).font(.caption2).foregroundStyle(.secondary).frame(width: 50, alignment: .leading)
        }
    }

    private func lbBinding<T>(_ keyPath: WritableKeyPath<LoopBreakerSettings, T>) -> Binding<T> {
        Binding(
            get: { state.loopBreakerSettings[keyPath: keyPath] },
            set: { newVal in
                var s = state.loopBreakerSettings
                s[keyPath: keyPath] = newVal
                state.updateLoopBreaker(s)
            }
        )
    }

    private func aiBinding<T>(_ keyPath: WritableKeyPath<AISettings, T>) -> Binding<T> {
        Binding(
            get: { state.aiSettings[keyPath: keyPath] },
            set: { newVal in
                var s = state.aiSettings
                s[keyPath: keyPath] = newVal
                state.updateAISettings(s)
            }
        )
    }

    private func sectionHeader(_ title: String) -> some View {
        Text(title).font(.caption2.weight(.bold)).foregroundStyle(.secondary)
    }
}

struct FlowTags: View {
    let items: [String]
    let color: Color
    let onDelete: (String) -> Void
    var body: some View {
        if items.isEmpty {
            EmptyView()
        } else {
            HStack(spacing: 4) {
                ForEach(items, id: \.self) { item in
                    HStack(spacing: 2) {
                        Text(item).font(.caption2)
                        Button { onDelete(item) } label: {
                            Image(systemName: "xmark").font(.system(size: 7, weight: .bold))
                        }.buttonStyle(.plain)
                    }
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(color.opacity(0.15), in: RoundedRectangle(cornerRadius: 4))
                    .foregroundStyle(color)
                }
            }
        }
    }
}

struct AIProviderRow: View {
    let provider: AIProvider
    let stats: AIProviderStats?

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: provider.icon)
                .frame(width: 20)
                .foregroundStyle(stats != nil ? .blue : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(provider.name)
                    .font(.system(.caption, design: .rounded).weight(.medium))
                if let s = stats {
                    HStack(spacing: 8) {
                        Text(verbatim: "\(s.requests) req")
                        Text(verbatim: "\(formatTokens(s.promptTokens + s.completionTokens)) tok")
                        Text(verbatim: "$\(String(format: "%.3f", s.estimatedCostUSD))")
                    }
                    .font(.caption2).foregroundStyle(.secondary)
                } else {
                    Text("No activity").font(.caption2).foregroundStyle(.tertiary)
                }
            }
            Spacer()
            if let s = stats, s.requests > 0 {
                Text(verbatim: "$\(String(format: "%.2f", s.estimatedCostUSD))")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.blue)
            }
        }
        .padding(.horizontal, 8).padding(.vertical, 4)
    }

    private func formatTokens(_ count: Int) -> String {
        if count >= 1_000_000 { return "\(count / 1_000_000)M" }
        if count >= 1_000 { return "\(count / 1_000)K" }
        return "\(count)"
    }
}

// MARK: - Cache tab

struct CacheView: View {
    @EnvironmentObject var state: AppState
    @State private var showPurgeConfirm = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                privacySection("HTTP Response Cache") {
                    Toggle("Enable L1 RAM Cache", isOn: cacheBinding(\.enabled))
                        .font(.caption).toggleStyle(.switch).controlSize(.small)
                }

                if state.cacheSettings.enabled {
                    privacySection("Limits") {
                        HStack {
                            Text("Max size").font(.caption)
                            Spacer()
                            Picker("", selection: cacheBinding(\.maxSizeMB)) {
                                Text("32 MB").tag(32)
                                Text("64 MB").tag(64)
                                Text("128 MB").tag(128)
                                Text("256 MB").tag(256)
                            }
                            .pickerStyle(.menu)
                            .frame(width: 100)
                        }
                        HStack {
                            Text("Max entries").font(.caption)
                            Spacer()
                            Picker("", selection: cacheBinding(\.maxEntries)) {
                                Text("5,000").tag(5_000)
                                Text("10,000").tag(10_000)
                                Text("50,000").tag(50_000)
                            }
                            .pickerStyle(.menu)
                            .frame(width: 100)
                        }
                        HStack {
                            Text("Default TTL").font(.caption)
                            Spacer()
                            Picker("", selection: cacheBinding(\.defaultTTL)) {
                                Text("60s").tag(60)
                                Text("5m").tag(300)
                                Text("30m").tag(1800)
                                Text("1h").tag(3600)
                            }
                            .pickerStyle(.menu)
                            .frame(width: 100)
                        }
                    }

                    privacySection("Behavior") {
                        Toggle("Honor Cache-Control: no-store", isOn: cacheBinding(\.honorNoStore))
                            .font(.caption).toggleStyle(.switch).controlSize(.small)
                            .help("When enabled, responses with no-store are never cached. Disable for aggressive caching.")
                        Toggle("Strip tracking params from cache key (utm_*, fbclid)",
                               isOn: cacheBinding(\.stripTrackingParams))
                            .help("Removes utm_source, fbclid, gclid etc. from cache keys for better hit rate")
                            .font(.caption).toggleStyle(.switch).controlSize(.small)
                    }

                    let _ = state.statsTick  // 1Hz dependency — see AppState.statsTick
                    let cacheStats = CacheManager.shared.stats
                    privacySection("Statistics") {
                        HStack(spacing: 16) {
                            VStack(alignment: .leading) {
                                Text("Hits").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: "\(cacheStats.hits)").font(.caption.weight(.bold)).foregroundStyle(.teal)
                            }
                            VStack(alignment: .leading) {
                                Text("Misses").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: "\(cacheStats.misses)").font(.caption.weight(.bold))
                            }
                            VStack(alignment: .leading) {
                                Text("Size").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: String(format: "%.1f MB", cacheStats.currentSizeMB)).font(.caption.weight(.bold))
                            }
                            VStack(alignment: .leading) {
                                Text("Entries").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: "\(cacheStats.currentEntries)").font(.caption.weight(.bold))
                            }
                        }
                    }

                    Button("Purge L1", role: .destructive) { showPurgeConfirm = true }
                        .buttonStyle(.bordered).controlSize(.small)
                        .confirmationDialog("Purge all cached responses?", isPresented: $showPurgeConfirm) {
                            Button("Purge L1 + L2", role: .destructive) {
                                state.purgeCache()
                                DiskCache.shared.purgeAll()
                                ToastState.shared.show("L1 + L2 cache purged", icon: "trash")
                            }
                        }
                }

                Divider()

                // L2 Disk Cache
                privacySection("L2 DISK CACHE") {
                    Toggle("Enable L2 disk cache", isOn: diskBinding(\.enabled))
                        .font(.caption).toggleStyle(.switch).controlSize(.small)
                        .help("Persists cached responses to disk. Survives app restart.")

                    if state.diskCacheSettings.enabled {
                        HStack {
                            Text("Max size").font(.caption)
                            Spacer()
                            Picker("", selection: diskBinding(\.maxSizeMB)) {
                                Text("128 MB").tag(128)
                                Text("256 MB").tag(256)
                                Text("512 MB").tag(512)
                                Text("1 GB").tag(1024)
                            }.pickerStyle(.menu).frame(width: 100)
                        }

                        let _ = state.statsTick  // 1Hz dependency — see AppState.statsTick
                        let diskStats = DiskCache.shared.stats
                        HStack(spacing: 16) {
                            VStack(alignment: .leading) {
                                Text("L2 Hits").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: "\(diskStats.hits)").font(.caption.weight(.bold)).foregroundStyle(.teal)
                            }
                            VStack(alignment: .leading) {
                                Text("L2 Writes").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: "\(diskStats.writes)").font(.caption.weight(.bold))
                            }
                            VStack(alignment: .leading) {
                                Text("Size").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: "\(diskStats.sizeBytes / 1024 / 1024) MB").font(.caption.weight(.bold))
                            }
                            VStack(alignment: .leading) {
                                Text("Evictions").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: "\(diskStats.evictions)").font(.caption.weight(.bold))
                            }
                        }
                    }
                }
            }
            .padding(12)
        }
    }

    private func cacheBinding<T>(_ keyPath: WritableKeyPath<CacheSettings, T>) -> Binding<T> {
        Binding(
            get: { state.cacheSettings[keyPath: keyPath] },
            set: { var s = state.cacheSettings; s[keyPath: keyPath] = $0; state.updateCache(s) }
        )
    }

    private func diskBinding<T>(_ keyPath: WritableKeyPath<DiskCacheSettings, T>) -> Binding<T> {
        Binding(
            get: { state.diskCacheSettings[keyPath: keyPath] },
            set: { var s = state.diskCacheSettings; s[keyPath: keyPath] = $0; state.updateDiskCache(s) }
        )
    }

    private func privacySection<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased())
                .font(.caption2.weight(.bold))
                .foregroundStyle(.secondary)
            content()
        }
    }
}

// MARK: - Privacy tab

struct PrivacyView: View {
    @EnvironmentObject var state: AppState
    @State private var showWizard = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Section: Signals
                privacySection("Signals") {
                    privacyToggle("Send Do Not Track (DNT: 1)",
                                  isOn: binding(\.forceDNT))
                        .help("Adds DNT: 1 header to all HTTP requests, signaling opt-out from tracking")
                    privacyToggle("Send Global Privacy Control (Sec-GPC: 1)",
                                  isOn: binding(\.forceGPC))
                }

                // Section: Headers
                privacySection("Headers") {
                    privacyToggle("Replace User-Agent",
                                  isOn: binding(\.stripUserAgent))
                        .help("Replaces your browser fingerprint with a generic User-Agent string")
                    if state.privacy.stripUserAgent {
                        TextField("Custom UA", text: binding(\.customUserAgent))
                            .textFieldStyle(.roundedBorder)
                            .font(.caption)
                    }

                    privacyToggle("Strip/reduce Referer",
                                  isOn: binding(\.stripReferer))
                    if state.privacy.stripReferer {
                        Picker("Policy", selection: binding(\.refererPolicy)) {
                            ForEach(PrivacySettings.RefererPolicy.allCases) {
                                Text($0.rawValue).tag($0)
                            }
                        }
                        .pickerStyle(.segmented)
                    }

                    privacyToggle("Strip ETag / If-None-Match (anti-supercookie)",
                                  isOn: binding(\.stripETag))
                }

                // Section: Cookies
                privacySection("Cookies") {
                    privacyToggle("Strip tracking cookies (_ga, _fbp, etc.)",
                                  isOn: binding(\.stripTrackingCookies))
                }

                // Section: Response
                privacySection("Response Cleaning") {
                    privacyToggle("Strip Server / X-Powered-By from responses",
                                  isOn: binding(\.stripServerHeaders))
                    Text("Response header stripping requires TLS MITM (coming soon).")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }

                if state.stats.privacyActions > 0 {
                    HStack {
                        Image(systemName: "checkmark.shield")
                            .foregroundStyle(.purple)
                        Text(verbatim: "\(state.stats.privacyActions) privacy actions applied this session")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                // MITM section
                privacySection("TLS Interception (MITM)") {
                    if state.mitmSettings.caInstalled {
                        HStack {
                            Image(systemName: "checkmark.seal.fill")
                                .foregroundStyle(.green)
                            Text("Root CA installed").font(.caption)
                            Spacer()
                            Button("Trust") { state.trustMITMCA() }
                                .buttonStyle(.bordered).controlSize(.mini)
                            Button("Remove") { state.removeMITMCA() }
                                .buttonStyle(.bordered).controlSize(.mini)
                                .foregroundStyle(.red)
                        }
                        Toggle("Enable MITM Inspection", isOn: mitmBinding(\.enabled))
                            .font(.caption).toggleStyle(.switch).controlSize(.small)

                        if state.mitmSettings.enabled {
                            Text("HTTPS inspection active. Banking, Apple, Google excluded by default. Cert-pinned apps auto-excluded after 3 failures.")
                                .font(.caption2).foregroundStyle(.secondary)

                            // Exclude host input
                            MITMExcludeSection()
                        }
                    } else {
                        Text("Generate a root CA to enable HTTPS body inspection. This allows WAF content rules and exfiltration scanning to work on encrypted traffic.")
                            .font(.caption2).foregroundStyle(.secondary)
                        Button("Generate Root CA") { state.generateMITMCA() }
                            .buttonStyle(.bordered).controlSize(.small)
                    }
                }

                // DNS section
                privacySection("DNS-over-HTTPS") {
                    Toggle("Enable DoH resolver", isOn: dnsBinding(\.enabled))
                        .font(.caption).toggleStyle(.switch).controlSize(.small)
                    if state.dnsSettings.enabled {
                        Picker("Provider", selection: dnsBinding(\.provider)) {
                            ForEach(DNSSettings.DoHProvider.allCases) {
                                Text($0.rawValue).tag($0)
                            }
                        }.font(.caption)
                        if state.dnsSettings.provider == .custom {
                            TextField("DoH URL", text: dnsBinding(\.customURL))
                                .textFieldStyle(.roundedBorder).font(.caption)
                        }
                        let _ = state.statsTick  // 1Hz dependency — see AppState.statsTick
                        let dnsStats = DNSResolver.shared.stats
                        HStack(spacing: 12) {
                            VStack(alignment: .leading) {
                                Text("Queries").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: "\(dnsStats.queries)").font(.caption.weight(.bold))
                            }
                            VStack(alignment: .leading) {
                                Text("Cache").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: "\(dnsStats.cacheHits)H/\(dnsStats.cacheMisses)M").font(.caption.weight(.bold))
                            }
                            VStack(alignment: .leading) {
                                Text("Errors").font(.caption2).foregroundStyle(.secondary)
                                Text(verbatim: "\(dnsStats.errors)").font(.caption.weight(.bold)).foregroundStyle(dnsStats.errors > 0 ? .red : .secondary)
                            }
                        }
                    }
                    Text("When enabled, Proxymate resolves domains via encrypted DNS to bypass ISP snooping and match resolved IPs against blacklists.")
                        .font(.caption2).foregroundStyle(.tertiary)
                }
                // Setup wizard
                Divider()
                Button("Run Setup Wizard Again") {
                    UserDefaults.standard.set(false, forKey: "proxymate.onboarded")
                    showWizard = true
                }
                .buttonStyle(.bordered).controlSize(.small)
                .font(.caption)
            }
            .padding(12)
        }
        .sheet(isPresented: $showWizard) {
            OnboardingView(isPresented: $showWizard)
                .environmentObject(state)
                .onDisappear {
                    UserDefaults.standard.set(true, forKey: "proxymate.onboarded")
                }
        }
    }

    // MARK: - Helpers

    private func binding<T>(_ keyPath: WritableKeyPath<PrivacySettings, T>) -> Binding<T> {
        Binding(
            get: { state.privacy[keyPath: keyPath] },
            set: { newVal in
                var p = state.privacy
                p[keyPath: keyPath] = newVal
                state.updatePrivacy(p)
            }
        )
    }

    private func dnsBinding<T>(_ keyPath: WritableKeyPath<DNSSettings, T>) -> Binding<T> {
        Binding(
            get: { state.dnsSettings[keyPath: keyPath] },
            set: { newVal in
                var s = state.dnsSettings
                s[keyPath: keyPath] = newVal
                state.updateDNS(s)
            }
        )
    }

    private func mitmBinding<T>(_ keyPath: WritableKeyPath<MITMSettings, T>) -> Binding<T> {
        Binding(
            get: { state.mitmSettings[keyPath: keyPath] },
            set: { newVal in
                var s = state.mitmSettings
                s[keyPath: keyPath] = newVal
                state.updateMITM(s)
            }
        )
    }

    private func privacySection<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased())
                .font(.caption2.weight(.bold))
                .foregroundStyle(.secondary)
            content()
        }
    }

    private func privacyToggle(_ label: String, isOn: Binding<Bool>) -> some View {
        Toggle(label, isOn: isOn)
            .font(.caption)
            .toggleStyle(.switch)
            .controlSize(.small)
    }
}

// MARK: - MITM Exclude Section

struct MITMExcludeSection: View {
    @EnvironmentObject var state: AppState
    @State private var newExclude = ""

    private var runtimeExcludes: [String] {
        TLSManager.shared.getRuntimeExcludes()
    }

    var body: some View {
        let _ = state.statsTick  // 1Hz dependency — TLSManager auto-excludes are not ObservableObject
        VStack(alignment: .leading, spacing: 6) {
            Divider().padding(.vertical, 4)
            Text("BYPASS (skip MITM)").font(.caption2.weight(.bold)).foregroundStyle(.secondary)

            // Add new exclude
            HStack(spacing: 4) {
                TextField("domain.com or *.domain.com", text: $newExclude)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)
                Button("Add") {
                    let host = newExclude.trimmingCharacters(in: .whitespaces).lowercased()
                    guard !host.isEmpty else { return }
                    var s = state.mitmSettings
                    if !s.excludeHosts.contains(host) {
                        s.excludeHosts.append(host)
                        state.updateMITM(s)
                    }
                    newExclude = ""
                }
                .buttonStyle(.bordered).controlSize(.mini)
                .disabled(newExclude.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            // User excludes (removable)
            let defaultExcludes = MITMSettings().excludeHosts
            let userExcludes = state.mitmSettings.excludeHosts.filter { !defaultExcludes.contains($0) }
            if !userExcludes.isEmpty {
                Text("User excludes:").font(.caption2).foregroundStyle(.secondary)
                ForEach(userExcludes, id: \.self) { host in
                    HStack(spacing: 4) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.red)
                            .font(.caption2)
                            .onTapGesture {
                                var s = state.mitmSettings
                                s.excludeHosts.removeAll { $0 == host }
                                state.updateMITM(s)
                            }
                        Text(host).font(.system(.caption, design: .monospaced))
                    }
                }
            }

            // Auto-detected excludes (cert pinning)
            if !runtimeExcludes.isEmpty {
                Text("Auto-detected (cert pinning):").font(.caption2).foregroundStyle(.secondary)
                Text(runtimeExcludes.joined(separator: ", "))
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .lineLimit(3)
                Button("Clear auto-excludes") {
                    TLSManager.shared.resetPinningHistory()
                }
                .buttonStyle(.borderless).font(.caption2).foregroundStyle(.secondary)
            }

            // Default excludes (info only)
            DisclosureGroup {
                Text(defaultExcludes.joined(separator: ", "))
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.tertiary)
            } label: {
                Text("Default excludes (\(defaultExcludes.count))").font(.caption2).foregroundStyle(.secondary)
            }
        }
    }
}
