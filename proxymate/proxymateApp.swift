//
//  proxymateApp.swift
//  proxymate
//
//  Menu bar app using NSStatusItem + floating NSPanel.
//  No Dock icon (LSUIElement). Click menu bar icon to toggle panel.
//  The panel is a proper window — sheets, TextFields, focus all work.
//

import SwiftUI
import AppKit
import Network

@main
struct proxymateApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Settings { EmptyView() }
    }
}

// MARK: - AppDelegate (StatusItem + Panel + Cleanup)

final class AppDelegate: NSObject, NSApplicationDelegate {

    private var statusItem: NSStatusItem!
    private let state = AppState()
    private var activity: NSObjectProtocol?
    private var pathMonitor: NWPathMonitor?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Single-instance
        let me = ProcessInfo.processInfo.processIdentifier
        let bid = Bundle.main.bundleIdentifier ?? ""
        for app in NSRunningApplication.runningApplications(withBundleIdentifier: bid)
        where app.processIdentifier != me {
            app.forceTerminate()
        }

        // Multi-user conflict check (#48)
        checkForOtherInstances()

        // Startup cleanup
        if UserDefaults.standard.bool(forKey: "proxymate.wasEnabled") {
            UserDefaults.standard.set(false, forKey: "proxymate.wasEnabled")
            Task {
                try? await ProxyManager.disable()
                try? await PACServer.clearSystemPAC()
            }
        }

        // Create status bar item
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

        if let button = statusItem.button {
            if let img = NSImage(named: "MenuBarIcon") {
                img.isTemplate = true
                button.image = img
            } else {
                button.image = NSImage(systemSymbolName: "shield.lefthalf.filled",
                                        accessibilityDescription: "Proxymate")
            }
            button.action = #selector(togglePanel)
            button.target = self
        }

        // #23 — Prevent App Nap: we manage the network, must never be throttled
        activity = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiated, .latencyCritical],
            reason: "Proxymate manages system proxy — must not be suspended"
        )

        // #24 — Sleep/Wake: stop sidecar on sleep, restart on wake
        let ws = NSWorkspace.shared.notificationCenter
        ws.addObserver(self, selector: #selector(systemWillSleep),
                       name: NSWorkspace.willSleepNotification, object: nil)
        ws.addObserver(self, selector: #selector(systemDidWake),
                       name: NSWorkspace.didWakeNotification, object: nil)

        // #22 — Network interface changes: re-apply proxy on Wi-Fi/Ethernet/VPN switch
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            Task { @MainActor in
                guard self.state.isEnabled else { return }
                if let proxy = self.state.proxies.first(where: { $0.id == self.state.selectedProxyID }) {
                    try? await ProxyManager.enable(proxy: proxy)
                }
            }
        }
        monitor.start(queue: DispatchQueue(label: "proxymate.pathmonitor", qos: .utility))
        pathMonitor = monitor
    }

    private func checkForOtherInstances() {
        // Check if another user on this Mac is running proxymate on the same proxy port
        let lockFile = "/tmp/proxymate-\(NSUserName()).lock"
        let otherLocks = (try? FileManager.default.contentsOfDirectory(atPath: "/tmp"))?
            .filter { $0.hasPrefix("proxymate-") && $0.hasSuffix(".lock") && $0 != "proxymate-\(NSUserName()).lock" } ?? []
        if !otherLocks.isEmpty {
            let otherUser = otherLocks.first?.replacingOccurrences(of: "proxymate-", with: "")
                .replacingOccurrences(of: ".lock", with: "") ?? "unknown"
            Task { @MainActor in
                state.log(.warn, "Another Proxymate instance may be running (user: \(otherUser)) — proxy port conflicts possible")
            }
        }
        FileManager.default.createFile(atPath: lockFile, contents: Data("\(ProcessInfo.processInfo.processIdentifier)".utf8))
    }

    @objc private func togglePanel() {
        PanelManager.shared.toggle(relativeTo: statusItem.button, state: state)
    }

    @objc private func systemWillSleep(_ note: Notification) {
        MITMProxySidecar.shared.stop()
    }

    @objc private func systemDidWake(_ note: Notification) {
        guard state.isEnabled else { return }
        Task { @MainActor in
            if let proxy = state.proxies.first(where: { $0.id == state.selectedProxyID }) {
                if state.mitmSettings.enabled {
                    _ = try? MITMProxySidecar.shared.start(
                        upstreamHost: proxy.host,
                        upstreamPort: UInt16(proxy.port)
                    )
                }
                // Re-apply proxy settings in case interface changed during sleep
                try? await ProxyManager.enable(proxy: proxy)
            }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Clean up multi-user lock file
        try? FileManager.default.removeItem(atPath: "/tmp/proxymate-\(NSUserName()).lock")

        // Stop monitoring
        pathMonitor?.cancel()
        if let activity { ProcessInfo.processInfo.endActivity(activity) }

        // Stop network listeners
        MetricsServer.shared.stop()
        MITMProxySidecar.shared.stop()
        SquidSidecar.shared.stop()

        if UserDefaults.standard.bool(forKey: "proxymate.wasEnabled") {
            UserDefaults.standard.set(false, forKey: "proxymate.wasEnabled")
            // Run cleanup on a detached Task (NOT the main actor) so async
            // hops inside ProxyManager.disable()/PACServer.clearSystemPAC()
            // don't deadlock waiting for the main thread that's blocked on
            // the semaphore below.
            let sem = DispatchSemaphore(value: 0)
            Task.detached(priority: .userInitiated) {
                try? await ProxyManager.disable()
                try? await PACServer.clearSystemPAC()
                sem.signal()
            }
            _ = sem.wait(timeout: .now() + 3)
        }
    }
}
