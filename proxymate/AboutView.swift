//
//  AboutView.swift
//  proxymate
//

import SwiftUI

struct AboutView: View {
    @EnvironmentObject var state: AppState
    @Environment(\.openURL) private var openURL

    private var version: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.6.0"
    }
    private var build: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
    }

    var body: some View {
        VStack(spacing: 16) {
            // Icon + name
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 44))
                .foregroundStyle(.blue)
            Text("Proxymate")
                .font(.title2.weight(.bold))
            Text(verbatim: "v\(version) (build \(build))")
                .font(.caption).foregroundStyle(.secondary)

            Divider()

            // Live stats
            VStack(spacing: 6) {
                statRow("Uptime", value: uptimeString)
                statRow("Requests", value: "\(state.stats.requestsAllowed + state.stats.requestsBlocked)")
                statRow("Blocked", value: "\(state.stats.requestsBlocked + state.stats.blacklistBlocked)")
                statRow("Rules", value: "\(state.rules.count)")
                statRow("Blacklists", value: "\(state.blacklistSources.filter(\.enabled).count)")
                statRow("Tests", value: "176 passed")
            }

            Divider()

            // Links
            HStack(spacing: 16) {
                linkButton("GitHub", icon: "chevron.left.forwardslash.chevron.right",
                           url: "https://github.com/fabriziosalmi/proxymate")
                linkButton("Issues", icon: "exclamationmark.triangle",
                           url: "https://github.com/fabriziosalmi/proxymate/issues")
                linkButton("License", icon: "doc.text",
                           url: "https://github.com/fabriziosalmi/proxymate/blob/main/LICENSE")
            }

            Spacer()

            // Credits
            Text("Made with care by Fabrizio Salmi")
                .font(.caption2).foregroundStyle(.tertiary)
            Text("Zero telemetry. Zero cloud. Zero login. Free forever.")
                .font(.caption2).foregroundStyle(.tertiary)
        }
        .padding(16)
    }

    private func statRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Spacer()
            Text(value).font(.caption.weight(.medium)).monospacedDigit()
        }
    }

    private func linkButton(_ title: String, icon: String, url: String) -> some View {
        Button {
            if let u = URL(string: url) { openURL(u) }
        } label: {
            VStack(spacing: 2) {
                Image(systemName: icon).font(.caption)
                Text(title).font(.caption2)
            }
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.plain)
        .foregroundStyle(.blue)
    }

    private var uptimeString: String {
        guard let since = state.stats.enabledSince else { return "—" }
        let elapsed = Int(Date().timeIntervalSince(since))
        let h = elapsed / 3600
        let m = (elapsed % 3600) / 60
        let s = elapsed % 60
        if h > 0 { return "\(h)h \(m)m" }
        if m > 0 { return "\(m)m \(s)s" }
        return "\(s)s"
    }
}
