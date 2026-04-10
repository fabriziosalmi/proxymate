//
//  ContentView.swift
//  proxymate
//
//  Popover content shown by MenuBarExtra. Header (status + master toggle),
//  tab bar, and the four tab bodies.
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
        var id: String { rawValue }
        var systemImage: String {
            switch self {
            case .proxies: return "network"
            case .logs:    return "list.bullet.rectangle"
            case .stats:   return "chart.bar"
            case .rules:   return "shield.lefthalf.filled"
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
                .frame(height: 300)
        }
        .frame(width: 380)
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
                        Text(t.rawValue).font(.caption)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
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

// MARK: - Logs tab

struct LogsView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        VStack(spacing: 0) {
            if state.logs.isEmpty {
                Spacer()
                Text("No logs yet").foregroundStyle(.secondary)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(state.logs) { LogRow(entry: $0) }
                    }
                    .padding(8)
                }
            }
            Divider()
            HStack {
                Text(verbatim: "\(state.logs.count) entries")
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
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)
            Text(entry.message)
                .font(.caption)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
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
        VStack(spacing: 12) {
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
                StatCard(title: "Blocked",
                         value: "\(state.stats.requestsBlocked)",
                         color: .red)
            }
            Spacer()
            Text("Per-request stats activate once the in-app proxy is wired up.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.bottom, 8)
        }
        .padding(12)
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

// MARK: - Rules tab

struct RulesView: View {
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
                        .font(.title2)
                        .foregroundStyle(.secondary)
                    Text("No rules yet").foregroundStyle(.secondary)
                    Button("Load Examples") { state.loadExampleRules() }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
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
                                .padding(.horizontal, 12)
                                .padding(.top, 6)
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
                }
                .buttonStyle(.borderless)
                Button("Examples") { state.loadExampleRules() }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(verbatim: "\(state.rules.filter(\.enabled).count) / \(state.rules.count) active")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if !rule.enabled {
                Text("OFF")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
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
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Add") {
                    onAdd(WAFRule(name: name, kind: kind, pattern: pattern,
                                  category: category.isEmpty ? "Custom" : category))
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(pattern.isEmpty)
            }
        }
        .padding(16)
        .frame(width: 340)
    }

    private var placeholder: String {
        switch kind {
        case .blockIP:      return "1.2.3.4"
        case .blockDomain:  return "example.com"
        case .blockContent: return "substring"
        }
    }
}
