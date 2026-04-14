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

    @State private var certInstalled = false
    @State private var enableOnFinish = true
    private let totalSteps = 6

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
                case 4: stepCertificate
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
                        .accessibilityLabel("Go back to previous step")
                } else {
                    // On the first step, "Back" becomes "Skip" — closes the
                    // wizard without applying settings but KEEPS the user
                    // un-onboarded so it re-appears on next launch. That
                    // way someone who accidentally opens the wizard doesn't
                    // commit to anything yet — the previous behaviour of
                    // cmd-W dismissing silently marked them done forever.
                    Button("Skip for now") { isPresented = false }
                        .buttonStyle(.plain).foregroundStyle(.tertiary)
                        .accessibilityLabel("Skip the wizard — it will re-appear next launch")
                }
                Spacer()
                if step < totalSteps - 1 {
                    Button("Next") { step += 1 }
                        .buttonStyle(.borderedProminent).controlSize(.small)
                        .disabled(!canAdvance)
                        .accessibilityLabel("Go to next step")
                } else {
                    Button(enableOnFinish ? "Finish & Enable" : "Finish") {
                        applyAndDismiss()
                    }
                    .buttonStyle(.borderedProminent).controlSize(.small)
                    .accessibilityLabel(enableOnFinish
                        ? "Finish setup and enable the proxy"
                        : "Finish setup without enabling")
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
                        .accessibilityLabel("\(profile.rawValue) profile")
                        .accessibilityHint(profile.subtitle)
                        .accessibilityAddTraits(selectedProfile == profile ? [.isSelected] : [])
                    }
                }
            }
            if selectedProfile == .minimal {
                // Flag the empty-starting-state explicitly so users who pick
                // Minimal don't reach the summary wondering why nothing is
                // toggled on. They can still enable pieces manually afterwards.
                Label("No blacklists, no privacy actions, no cache — you configure everything manually.",
                      systemImage: "info.circle")
                    .font(.caption2).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 20).padding(.top, 8)
    }

    // MARK: - Step 2: Proxy

    private var stepProxy: some View {
        VStack(spacing: 14) {
            Image(systemName: "network").font(.title2).foregroundStyle(.blue)
            Text("Upstream Proxy").font(.headline)
            Text("Do you have an existing proxy server you want to route through?")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)

            Toggle("I have an upstream proxy", isOn: $hasUpstream)
                .font(.caption).toggleStyle(.switch).controlSize(.small)

            if hasUpstream {
                HStack {
                    TextField("Host (e.g. 127.0.0.1)", text: $proxyHost)
                        .textFieldStyle(.roundedBorder).font(.caption)
                        .onChange(of: proxyHost) { _, new in
                            // Mild auto-clean: strip whitespace so the validator
                            // doesn't lock users out because of a trailing space
                            // from copy/paste.
                            let trimmed = new.trimmingCharacters(in: .whitespaces)
                            if trimmed != new { proxyHost = trimmed }
                        }
                    TextField("Port", text: $proxyPort)
                        .textFieldStyle(.roundedBorder).font(.caption).frame(width: 60)
                }
                if !canAdvance {
                    Label(hostPortHint, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption2).foregroundStyle(.orange)
                }
            } else {
                Text("Proxymate will use the bundled local proxies (Squid / mitmproxy) so the WAF, privacy, and caching still run. You can always point at a different upstream later.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
            }
            Spacer()
        }
        .padding(.horizontal, 20).padding(.top, 16)
    }

    /// Short user-facing hint shown below the Step-2 inputs when they don't
    /// pass validation. Kept terse — the full rule set is elsewhere.
    private var hostPortHint: String {
        let host = proxyHost.trimmingCharacters(in: .whitespaces)
        if host.isEmpty { return "Host cannot be empty" }
        if !isValidProxyHost(host) { return "Host contains invalid characters" }
        if Int(proxyPort).map({ !(1...65535).contains($0) }) ?? true {
            return "Port must be 1–65535"
        }
        return ""
    }

    // MARK: - Step 3: Privacy

    private var stepPrivacy: some View {
        VStack(spacing: 14) {
            Image(systemName: "eye.slash").font(.title2).foregroundStyle(.purple)
            Text("Privacy Level").font(.headline)

            Slider(value: $privacyLevel, in: 0...2, step: 1)
                .padding(.horizontal, 20)
                .accessibilityLabel("Privacy level")
                .accessibilityValue(
                    privacyLevel >= 2 ? "Maximum"
                    : privacyLevel >= 1 ? "Moderate"
                    : "Minimal")

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

    // MARK: - Step 5: Certificate (#37)

    @State private var certInstalling = false
    @State private var certTrusted = false
    @State private var certError: String?

    private var stepCertificate: some View {
        VStack(spacing: 14) {
            Image(systemName: "lock.shield.fill")
                .font(.title2).foregroundStyle(.orange)
            Text("HTTPS Inspection").font(.headline)
            Text("To inspect encrypted HTTPS traffic, Proxymate needs to install a local root CA. Your admin password will be requested once to add it to the system keychain.")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
                .padding(.horizontal)

            Group {
                if certTrusted {
                    Label("Certificate installed & trusted", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green).font(.caption)
                } else if certInstalled {
                    // Keys + cert generated but system trust pending (user hasn't
                    // entered admin password yet, or cancelled the dialog).
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Waiting for trust confirmation…").font(.caption).foregroundStyle(.secondary)
                    }
                } else if certInstalling {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Generating certificate…").font(.caption).foregroundStyle(.secondary)
                    }
                } else {
                    Button("Install Certificate") { installCertificate() }
                        .buttonStyle(.borderedProminent).controlSize(.small)
                }
            }

            if let err = certError {
                Label(err, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption2).foregroundStyle(.orange)
                    .multilineTextAlignment(.center)
            }

            Text("Optional — HTTP-only monitoring works without it. You can always set this up later in Settings.")
                .font(.caption2).foregroundStyle(.tertiary).multilineTextAlignment(.center)
                .padding(.horizontal)
            Spacer()
        }
        .padding(.horizontal, 20).padding(.top, 16)
        .task {
            // If the CA exists from a previous run, don't pretend trust is
            // settled until we've actually verified it via SecTrust. This
            // prevents stale "installed" checkmarks when a user regenerates
            // the CA without re-trusting.
            refreshCertState()
        }
    }

    private func installCertificate() {
        certError = nil
        certInstalling = true
        Task {
            // Generate CA file on a background queue — openssl subprocess is
            // blocking, we don't want to stall the UI.
            do {
                _ = try await Task.detached {
                    try TLSManager.shared.generateCA()
                }.value
                await MainActor.run {
                    certInstalling = false
                    certInstalled = true
                }
                // Kick off the privileged trust install. promptUserToTrust
                // spawns its own Task; we poll for completion rather than
                // trying to bridge its result directly.
                TLSManager.shared.promptUserToTrust()
                await pollForTrust()
            } catch {
                await MainActor.run {
                    certInstalling = false
                    certError = "Could not generate certificate — check logs."
                }
            }
        }
    }

    /// Polls SecTrustEvaluate every 500 ms for up to 15 s. Succeeds as soon
    /// as the system keychain reports the CA as trusted (i.e. the user
    /// entered their admin password). Gives up silently after the timeout
    /// so a cancelled or ignored prompt doesn't spin forever.
    private func pollForTrust() async {
        for _ in 0..<30 {
            try? await Task.sleep(for: .milliseconds(500))
            if await Task.detached(priority: .utility, operation: {
                TLSManager.shared.isCATrusted()
            }).value {
                await MainActor.run { certTrusted = true }
                return
            }
        }
        await MainActor.run {
            certError = "Admin prompt was cancelled or timed out. Install can be retried from Settings."
            certInstalled = false
        }
    }

    private func refreshCertState() {
        let installed = TLSManager.shared.isCAInstalled
        let trusted = installed && TLSManager.shared.isCATrusted()
        certInstalled = installed
        certTrusted = trusted
    }

    // MARK: - Step 6: Summary

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

            Toggle(isOn: $enableOnFinish) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Enable the proxy now").font(.caption.weight(.medium))
                    Text("Asks for admin password to configure system proxy.")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.switch).controlSize(.small)
            .padding(.horizontal, 4)

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

    // MARK: - Per-step gating

    /// Whether the Next button should be enabled for the current step.
    /// Step 1 (proxy) is the only one that can be put into an invalid state
    /// — everything else either has no input or has a sane default.
    private var canAdvance: Bool {
        switch step {
        case 1:
            if !hasUpstream { return true }
            let host = proxyHost.trimmingCharacters(in: .whitespaces)
            guard !host.isEmpty, isValidProxyHost(host) else { return false }
            guard let p = Int(proxyPort), (1...65535).contains(p) else { return false }
            return true
        default:
            return true
        }
    }

    /// Conservative hostname/IP validator mirroring ProxyManager.validate().
    /// Rejects every shell metacharacter — whitespace, quotes, backticks,
    /// semicolons — so an invalid upstream can't reach the privileged shell
    /// at the other end.
    private func isValidProxyHost(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 253 else { return false }
        let allowed = CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:")
        return s.unicodeScalars.allSatisfy { allowed.contains($0) }
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
        // Persist the completion flag here, inside applyAndDismiss, so a
        // premature sheet dismissal (ESC, click outside, window close) never
        // marks the user as onboarded when no settings were actually applied.
        UserDefaults.standard.set(true, forKey: "proxymate.onboarded")
        isPresented = false

        // Optional: auto-enable the proxy once settings are committed so the
        // user lands in a running state. The admin dialog will appear for the
        // `networksetup` call; that behaviour is called out on the summary
        // screen's toggle label.
        if enableOnFinish {
            Task { await state.enable() }
        }
    }
}

