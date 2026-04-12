//
//  OnboardingView.swift
//  proxymate
//
//  Multi-step onboarding wizard. 5 steps:
//  1. Welcome + profile selection
//  2. Proxy setup (auto-detect or manual)
//  3. Privacy level slider
//  4. AI tracking opt-in
//  5. Summary + Start
//

import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var state: AppState
    @Binding var isPresented: Bool
    @State private var step = 0
    @State private var selectedProfile: Profile = .privacy
    @State private var privacyLevel: Double = 2  // 0=min, 1=moderate, 2=max
    @State private var enableAI = true
    @State private var enableDNS = true
    @State private var proxyHost = ""
    @State private var proxyPort = "8080"
    @State private var hasUpstream = false

    enum Profile: String, CaseIterable {
        case privacy = "Privacy"
        case developer = "Developer"
        case work = "Enterprise"
        case familySafety = "Family Safety"
        case minimal = "Minimal"

        var icon: String {
            switch self {
            case .privacy: return "eye.slash.fill"
            case .developer: return "hammer.fill"
            case .work: return "briefcase.fill"
            case .familySafety: return "figure.2.and.child.holdinghands"
            case .minimal: return "slider.horizontal.3"
            }
        }
        var color: Color {
            switch self {
            case .privacy: return .purple
            case .developer: return .blue
            case .work: return .green
            case .familySafety: return .orange
            case .minimal: return .secondary
            }
        }
        var subtitle: String {
            switch self {
            case .privacy: return "Block ads, trackers, crypto miners. Strip headers. DoH enabled."
            case .developer: return "AI cost tracking, exfiltration scanner, cache. Minimal blocking."
            case .work: return "Malware + phishing + ads blocked. Corporate LAN allowed."
            case .familySafety: return "Maximum protection. Adult, malware, phishing, ads, telemetry."
            case .minimal: return "Clean slate. Configure everything manually."
            }
        }
    }

    private let totalSteps = 5

    var body: some View {
        VStack(spacing: 0) {
            // Progress
            HStack(spacing: 4) {
                ForEach(0..<totalSteps, id: \.self) { i in
                    Capsule()
                        .fill(i <= step ? Color.accentColor : Color.secondary.opacity(0.3))
                        .frame(height: 3)
                }
            }
            .padding(.horizontal, 20).padding(.top, 12)

            // Content
            Group {
                switch step {
                case 0: stepWelcome
                case 1: stepProxy
                case 2: stepPrivacy
                case 3: stepAI
                default: stepSummary
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .animation(.easeInOut(duration: 0.2), value: step)

            // Navigation
            HStack {
                if step > 0 {
                    Button("Back") { step -= 1 }
                        .buttonStyle(.plain).foregroundStyle(.secondary)
                }
                Spacer()
                if step < totalSteps - 1 {
                    Button("Next") { step += 1 }
                        .buttonStyle(.borderedProminent).controlSize(.small)
                } else {
                    Button("Start Proxying") { applyAndDismiss() }
                        .buttonStyle(.borderedProminent).controlSize(.small)
                }
            }
            .padding(16)
        }
        .frame(width: 380, height: 420)
    }

    // MARK: - Step 1: Welcome + Profile

    private var stepWelcome: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 36)).foregroundStyle(.blue)
            Text("Welcome to Proxymate").font(.title3.weight(.bold))
            Text("Choose a profile to get started.").font(.caption).foregroundStyle(.secondary)

            ScrollView {
                VStack(spacing: 6) {
                    ForEach(Profile.allCases, id: \.self) { profile in
                        Button { selectedProfile = profile } label: {
                            HStack(spacing: 10) {
                                Image(systemName: profile.icon)
                                    .foregroundStyle(profile.color).frame(width: 24)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(profile.rawValue).font(.caption.weight(.semibold))
                                    Text(profile.subtitle).font(.caption2).foregroundStyle(.secondary)
                                        .lineLimit(2)
                                }
                                Spacer()
                                if selectedProfile == profile {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundStyle(.blue)
                                }
                            }
                            .padding(8)
                            .background(selectedProfile == profile ? Color.accentColor.opacity(0.1) : Color.clear,
                                       in: RoundedRectangle(cornerRadius: 6))
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
        .padding(.horizontal, 20).padding(.top, 8)
    }

    // MARK: - Step 2: Proxy

    private var stepProxy: some View {
        VStack(spacing: 14) {
            Image(systemName: "network").font(.title2).foregroundStyle(.blue)
            Text("Upstream Proxy").font(.headline)
            Text("Do you have an existing proxy server?").font(.caption).foregroundStyle(.secondary)

            Toggle("I have an upstream proxy", isOn: $hasUpstream)
                .font(.caption).toggleStyle(.switch).controlSize(.small)

            if hasUpstream {
                HStack {
                    TextField("Host (e.g. 127.0.0.1)", text: $proxyHost)
                        .textFieldStyle(.roundedBorder).font(.caption)
                    TextField("Port", text: $proxyPort)
                        .textFieldStyle(.roundedBorder).font(.caption).frame(width: 60)
                }
            } else {
                Text("Proxymate will work in direct mode with its local proxy for WAF, privacy, and caching.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
            }
            Spacer()
        }
        .padding(.horizontal, 20).padding(.top, 16)
    }

    // MARK: - Step 3: Privacy

    private var stepPrivacy: some View {
        VStack(spacing: 14) {
            Image(systemName: "eye.slash").font(.title2).foregroundStyle(.purple)
            Text("Privacy Level").font(.headline)

            Slider(value: $privacyLevel, in: 0...2, step: 1)
                .padding(.horizontal, 20)

            HStack {
                Text("Minimal").font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Text("Moderate").font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Text("Maximum").font(.caption2).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 4)

            VStack(alignment: .leading, spacing: 4) {
                privacyFeature("DNT + Sec-GPC headers", enabled: privacyLevel >= 0)
                privacyFeature("Strip tracking cookies", enabled: privacyLevel >= 1)
                privacyFeature("Replace User-Agent", enabled: privacyLevel >= 2)
                privacyFeature("Strip Referer to origin", enabled: privacyLevel >= 2)
                privacyFeature("Strip ETag (anti-supercookie)", enabled: privacyLevel >= 2)
            }

            Toggle("Enable DNS-over-HTTPS", isOn: $enableDNS)
                .font(.caption).toggleStyle(.switch).controlSize(.small)

            Spacer()
        }
        .padding(.horizontal, 20).padding(.top, 16)
    }

    private func privacyFeature(_ name: String, enabled: Bool) -> some View {
        HStack(spacing: 6) {
            Image(systemName: enabled ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(enabled ? .green : .secondary).font(.caption)
            Text(name).font(.caption)
        }
    }

    // MARK: - Step 4: AI

    private var stepAI: some View {
        VStack(spacing: 14) {
            Image(systemName: "brain").font(.title2).foregroundStyle(.blue)
            Text("AI Observability").font(.headline)
            Text("Track AI API usage, token costs, and detect coding agents.")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)

            Toggle("Enable AI tracking", isOn: $enableAI)
                .font(.caption).toggleStyle(.switch).controlSize(.small)

            if enableAI {
                VStack(alignment: .leading, spacing: 4) {
                    Text("What we detect:").font(.caption2.weight(.bold)).foregroundStyle(.secondary)
                    aiFeature("OpenAI, Anthropic, Google + 8 more providers")
                    aiFeature("Token counting + cost estimation")
                    aiFeature("Claude Code, Cursor, Copilot agent detection")
                    aiFeature("MCP traffic monitoring")
                    aiFeature("Runaway loop breaker")
                }
            }
            Spacer()
        }
        .padding(.horizontal, 20).padding(.top, 16)
    }

    private func aiFeature(_ text: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "checkmark").foregroundStyle(.blue).font(.caption2)
            Text(text).font(.caption2)
        }
    }

    // MARK: - Step 5: Summary

    private var stepSummary: some View {
        VStack(spacing: 14) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 36)).foregroundStyle(.green)
            Text("Ready to Go").font(.headline)

            VStack(alignment: .leading, spacing: 6) {
                summaryRow("Profile", value: selectedProfile.rawValue)
                summaryRow("Upstream", value: hasUpstream ? "\(proxyHost):\(proxyPort)" : "Direct")
                summaryRow("Privacy", value: privacyLevel >= 2 ? "Maximum" : privacyLevel >= 1 ? "Moderate" : "Minimal")
                summaryRow("DNS-over-HTTPS", value: enableDNS ? "Cloudflare" : "Off")
                summaryRow("AI Tracking", value: enableAI ? "On" : "Off")
            }
            .padding(12)
            .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 8))

            Text("You can change everything later in the app settings.")
                .font(.caption2).foregroundStyle(.tertiary).multilineTextAlignment(.center)
            Spacer()
        }
        .padding(.horizontal, 20).padding(.top, 16)
    }

    private func summaryRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Spacer()
            Text(value).font(.caption.weight(.medium))
        }
    }

    // MARK: - Apply

    private func applyAndDismiss() {
        // Privacy settings based on slider
        var privacy = PrivacySettings()
        privacy.forceDNT = true
        privacy.forceGPC = true
        if privacyLevel >= 1 { privacy.stripTrackingCookies = true }
        if privacyLevel >= 2 {
            privacy.stripUserAgent = true
            privacy.stripReferer = true
            privacy.refererPolicy = .originOnly
            privacy.stripETag = true
        }
        state.updatePrivacy(privacy)

        // DNS
        if enableDNS {
            state.updateDNS(DNSSettings(enabled: true, provider: .cloudflare))
        }

        // Upstream proxy
        if hasUpstream && !proxyHost.isEmpty {
            let proxy = ProxyConfig(name: "Upstream", host: proxyHost,
                                     port: Int(proxyPort) ?? 8080, applyToHTTPS: true)
            state.addProxy(proxy)
            state.select(proxy.id)
        }

        // Profile-specific blacklists
        let categories: [BlacklistSource.BlacklistCategory]
        switch selectedProfile {
        case .privacy:
            categories = [.ads, .telemetry, .cryptoMiner, .malware, .phishing]
        case .developer:
            categories = [.malware, .cryptoMiner]
            state.updateCache(CacheSettings(enabled: true))
        case .work:
            categories = [.malware, .phishing, .ads, .cryptoMiner, .torExits]
            state.addAllowEntry(AllowEntry(pattern: "10.0.0.0/8", note: "Corporate LAN"))
            state.addAllowEntry(AllowEntry(pattern: "172.16.0.0/12", note: "Corporate LAN"))
            state.addAllowEntry(AllowEntry(pattern: "192.168.0.0/16", note: "Local network"))
        case .familySafety:
            categories = [.malware, .phishing, .ads, .cryptoMiner, .telemetry, .adult]
        case .minimal:
            categories = []
        }

        if !categories.isEmpty {
            let existing = Set(state.blacklistSources.map { $0.url.lowercased() })
            let toAdd = BlacklistSource.builtIn.filter {
                categories.contains($0.category) && !existing.contains($0.url.lowercased())
            }
            for s in toAdd { state.addBlacklistSource(s) }
            state.refreshAllBlacklists()
        }

        state.loadExampleRules()
        state.log(.info, "Onboarding complete: \(selectedProfile.rawValue) profile")
        isPresented = false
    }
}

