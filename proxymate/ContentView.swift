//
//  ContentView.swift
//  proxymate
//
//  Popover content shown by MenuBarExtra. Header (status + master toggle),
//  tab bar, and the five tab bodies.
//

import SwiftUI
import AppKit

struct ContentView: View {
    @EnvironmentObject var state: AppState
    @State private var tab: Tab = .proxies

    enum Tab: String, CaseIterable, Identifiable {
        case proxies = "Proxies"
        case logs    = "Logs"
        case stats   = "Stats"
        case rules   = "Rules"
        case cache   = "Cache"
        case privacy = "Privacy"
        var id: String { rawValue }
        var systemImage: String {
            switch self {
            case .proxies: return "network"
            case .logs:    return "list.bullet.rectangle"
            case .stats:   return "chart.bar"
            case .rules:   return "shield.lefthalf.filled"
            case .cache:   return "internaldrive"
            case .privacy: return "eye.slash"
            }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            tabBar
            Divider()
            content
                .frame(height: 340)
        }
        .frame(width: 400)
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
                Text("Proxymate").font(.headline)
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
            Toggle("", isOn: Binding(
                get: { state.isEnabled },
                set: { _ in Task { await state.toggle() } }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
            .disabled(state.selectedProxy == nil || state.isBusy)
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
        case .cache:   CacheView()
        case .privacy: PrivacyView()
        }
    }
}

// MARK: - Proxies tab

struct ProxiesView: View {
    @EnvironmentObject var state: AppState
    @State private var showingAdd = false

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                LazyVStack(spacing: 2) {
                    ForEach(state.proxies) { p in
                        ProxyRow(proxy: p, isSelected: p.id == state.selectedProxyID)
                            .contentShape(Rectangle())
                            .onTapGesture { state.select(p.id) }
                            .contextMenu {
                                Button("Use this proxy") { state.select(p.id) }
                                Divider()
                                Button("Delete", role: .destructive) { state.removeProxy(p.id) }
                            }
                    }
                }
                .padding(.vertical, 4)
            }
            Divider()
            HStack {
                Button { showingAdd = true } label: {
                    Label("Add", systemImage: "plus")
                }
                .buttonStyle(.borderless)
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
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
        VStack(alignment: .leading, spacing: 12) {
            Text("Add Proxy").font(.headline)
            Form {
                TextField("Name",  text: $name)
                TextField("Host",  text: $host)
                TextField("Port",  text: $port)
                Toggle("Apply to HTTPS too", isOn: $https)
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
        .frame(width: 320)
    }
}

// MARK: - Logs tab (search, filter, click-to-rule)

struct LogsView: View {
    @EnvironmentObject var state: AppState
    @State private var search = ""
    @State private var levelFilter: LogEntry.Level?

    private var filteredLogs: [LogEntry] {
        state.logs.filter { entry in
            if let lf = levelFilter, entry.level != lf { return false }
            if search.isEmpty { return true }
            let q = search.lowercased()
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
                Text(state.logs.isEmpty ? "No logs yet" : "No matching logs")
                    .foregroundStyle(.secondary)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(filteredLogs) { entry in
                            LogRow(entry: entry)
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
                                        Button("Search: \(entry.host)") {
                                            search = entry.host
                                        }
                                        Divider()
                                    }
                                    Button("Copy") {
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general.setString(entry.message, forType: .string)
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
    }
}

struct LogRow: View {
    let entry: LogEntry
    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
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
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(.quaternary.opacity(0.4),
                    in: RoundedRectangle(cornerRadius: 8))
    }
}

// MARK: - Rules tab (segmented: WAF / Blacklists / Exfiltration)

struct RulesView: View {
    @EnvironmentObject var state: AppState
    @State private var section: RulesSection = .waf

    enum RulesSection: String, CaseIterable, Identifiable {
        case waf          = "WAF"
        case blacklists   = "Lists"
        case exfiltration = "Secrets"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("Section", selection: $section) {
                ForEach(RulesSection.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .padding(8)

            Divider()

            switch section {
            case .waf:          WAFRulesSection()
            case .blacklists:   BlacklistsSection()
            case .exfiltration: ExfiltrationSection()
            }
        }
    }
}

// MARK: WAF sub-section

struct WAFRulesSection: View {
    @EnvironmentObject var state: AppState
    @State private var showingAdd = false

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
                        .font(.title2).foregroundStyle(.secondary)
                    Text("No rules yet").foregroundStyle(.secondary)
                    Button("Load Examples") { state.loadExampleRules() }
                        .buttonStyle(.bordered).controlSize(.small)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(grouped, id: \.category) { group in
                            Text(group.category.uppercased())
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 12).padding(.top, 6)
                            ForEach(group.rules) { rule in
                                RuleRow(rule: rule)
                                    .contextMenu {
                                        Button(rule.enabled ? "Disable" : "Enable") {
                                            state.toggleRule(rule.id)
                                        }
                                        Divider()
                                        Button("Delete", role: .destructive) {
                                            state.removeRule(rule.id)
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
                    Label("Add", systemImage: "plus")
                }.buttonStyle(.borderless)
                Button("Examples") { state.loadExampleRules() }
                    .buttonStyle(.borderless).foregroundStyle(.secondary)
                Spacer()
                Text(verbatim: "\(state.rules.filter(\.enabled).count) / \(state.rules.count)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(8)
        }
        .sheet(isPresented: $showingAdd) {
            AddRuleSheet { state.addRule($0) }
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
            Spacer()
            if !rule.enabled {
                Text("OFF").font(.caption2.weight(.bold)).foregroundStyle(.secondary)
            }
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
        VStack(alignment: .leading, spacing: 12) {
            Text("Add Rule").font(.headline)
            Form {
                TextField("Name (optional)", text: $name)
                Picker("Type", selection: $kind) {
                    ForEach(WAFRule.Kind.allCases) { Text($0.rawValue).tag($0) }
                }
                TextField(placeholder, text: $pattern)
                TextField("Category", text: $category)
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
        .padding(16).frame(width: 340)
    }

    private var placeholder: String {
        switch kind {
        case .blockIP:      return "1.2.3.4"
        case .blockDomain:  return "example.com"
        case .blockContent: return "substring"
        }
    }
}

// MARK: Blacklists sub-section

struct BlacklistsSection: View {
    @EnvironmentObject var state: AppState
    @State private var isRefreshing = false

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
                Button("Add Built-in") { state.loadBuiltInBlacklists() }
                    .buttonStyle(.borderless)
                Spacer()
                Button {
                    isRefreshing = true
                    state.refreshAllBlacklists()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1) { isRefreshing = false }
                } label: {
                    if isRefreshing {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Refresh All", systemImage: "arrow.clockwise")
                    }
                }
                .buttonStyle(.borderless)
            }
            .padding(8)
        }
    }
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
        case .cryptoMiner: return .yellow
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

// MARK: - Cache tab

struct CacheView: View {
    @EnvironmentObject var state: AppState

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
                        Toggle("Strip tracking params from cache key (utm_*, fbclid)",
                               isOn: cacheBinding(\.stripTrackingParams))
                            .font(.caption).toggleStyle(.switch).controlSize(.small)
                    }

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

                    Button("Purge Cache") { state.purgeCache() }
                        .buttonStyle(.bordered).controlSize(.small)
                }
            }
            .padding(12)
        }
    }

    private func cacheBinding<T>(_ keyPath: WritableKeyPath<CacheSettings, T>) -> Binding<T> {
        Binding(
            get: { state.cacheSettings[keyPath: keyPath] },
            set: { newVal in
                var s = state.cacheSettings
                s[keyPath: keyPath] = newVal
                state.updateCache(s)
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
}

// MARK: - Privacy tab

struct PrivacyView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Section: Signals
                privacySection("Signals") {
                    privacyToggle("Send Do Not Track (DNT: 1)",
                                  isOn: binding(\.forceDNT))
                    privacyToggle("Send Global Privacy Control (Sec-GPC: 1)",
                                  isOn: binding(\.forceGPC))
                }

                // Section: Headers
                privacySection("Headers") {
                    privacyToggle("Replace User-Agent",
                                  isOn: binding(\.stripUserAgent))
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
                        Toggle("Enable MITM", isOn: mitmBinding(\.enabled))
                            .font(.caption).toggleStyle(.switch).controlSize(.small)

                        if state.mitmSettings.enabled {
                            Text("HTTPS body inspection is active for non-excluded hosts. Banking, Apple, and Google services are excluded by default.")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    } else {
                        Text("Generate a root CA to enable HTTPS body inspection. This allows WAF content rules and exfiltration scanning to work on encrypted traffic.")
                            .font(.caption2).foregroundStyle(.secondary)
                        Button("Generate Root CA") { state.generateMITMCA() }
                            .buttonStyle(.bordered).controlSize(.small)
                    }
                }
            }
            .padding(12)
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
