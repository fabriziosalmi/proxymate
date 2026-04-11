//
//  OnboardingView.swift
//  proxymate
//
//  First-launch wizard. Lets the user pick a profile (Privacy, Dev, Work)
//  which pre-configures privacy settings, WAF examples, and blacklists.
//

import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var state: AppState
    @Binding var isPresented: Bool

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 40))
                .foregroundStyle(.blue)

            Text("Welcome to Proxymate")
                .font(.title2.weight(.bold))

            Text("Choose a profile to get started. You can change everything later.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            VStack(spacing: 10) {
                ProfileButton(
                    title: "Privacy",
                    subtitle: "Block ads, trackers, crypto miners. Strip tracking headers. DoH enabled.",
                    icon: "eye.slash.fill",
                    color: .purple
                ) { applyProfile(.privacy) }

                ProfileButton(
                    title: "Developer",
                    subtitle: "AI cost tracking, exfiltration scanner, cache enabled. Minimal blocking.",
                    icon: "hammer.fill",
                    color: .blue
                ) { applyProfile(.developer) }

                ProfileButton(
                    title: "Work",
                    subtitle: "Balanced. Block malware & phishing, strip trackers, allow corporate ranges.",
                    icon: "briefcase.fill",
                    color: .green
                ) { applyProfile(.work) }

                ProfileButton(
                    title: "Minimal",
                    subtitle: "Start clean. No rules, no lists, no privacy stripping. Configure manually.",
                    icon: "slider.horizontal.3",
                    color: .secondary
                ) { applyProfile(.minimal) }
            }

            Button("Skip") { isPresented = false }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .font(.caption)
        }
        .padding(24)
        .frame(width: 360)
    }

    enum Profile {
        case privacy, developer, work, minimal
    }

    private func applyProfile(_ profile: Profile) {
        switch profile {
        case .privacy:
            state.updatePrivacy(PrivacySettings(
                stripUserAgent: true, stripReferer: true,
                refererPolicy: .originOnly, stripTrackingCookies: true,
                forceDNT: true, forceGPC: true, stripETag: true
            ))
            state.updateDNS(DNSSettings(enabled: true, provider: .cloudflare))
            state.loadExampleRules()
            state.loadBuiltInBlacklists()
            state.log(.info, "Applied Privacy profile")

        case .developer:
            state.updatePrivacy(PrivacySettings(forceDNT: true, forceGPC: true))
            state.updateCache(CacheSettings(enabled: true))
            state.loadExampleRules()
            state.log(.info, "Applied Developer profile")

        case .work:
            state.updatePrivacy(PrivacySettings(
                stripTrackingCookies: true, forceDNT: true, forceGPC: true
            ))
            state.loadBuiltInBlacklists()
            state.addAllowEntry(AllowEntry(pattern: "10.0.0.0/8", note: "Corporate LAN"))
            state.addAllowEntry(AllowEntry(pattern: "172.16.0.0/12", note: "Corporate LAN"))
            state.addAllowEntry(AllowEntry(pattern: "192.168.0.0/16", note: "Local network"))
            state.log(.info, "Applied Work profile")

        case .minimal:
            state.log(.info, "Applied Minimal profile")
        }

        isPresented = false
    }
}

struct ProfileButton: View {
    let title: String
    let subtitle: String
    let icon: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.title3)
                    .foregroundStyle(color)
                    .frame(width: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.body.weight(.semibold))
                    Text(subtitle).font(.caption2).foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption).foregroundStyle(.tertiary)
            }
            .padding(10)
            .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 8))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
