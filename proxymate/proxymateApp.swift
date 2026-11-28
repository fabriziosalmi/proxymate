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
    private var sigtermSource: DispatchSourceSignal?

    /// XCTest launches the app as its test host; one host must not quit the
    /// user's running Proxymate or a parallel test host.
    static var isTestHost: Bool {
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
    }

    /// Set when termination cleanup starts, so a SIGTERM during it (the
    /// cleanup waits on child processes) does not start a second pass.
    private static var isTerminating = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        // SIGTERM (kill, pkill, launchd) quits through applicationWillTerminate,
        // so the sidecars stop and the system proxy is restored. Without this
        // the default action ends the process with squid and mitmdump still
        // running and the system proxy pointing at a closed port.
        signal(SIGTERM, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        term.setEventHandler { if !AppDelegate.isTerminating { NSApp.terminate(nil) } }
        term.resume()
        sigtermSource = term

        // Single-instance: ask an older instance to quit so it cleans up its
        // sidecars and system proxy; force it only if it does not exit.
        if !Self.isTestHost {
            let me = ProcessInfo.processInfo.processIdentifier
            let bid = Bundle.main.bundleIdentifier ?? ""
            let others = NSRunningApplication.runningApplications(withBundleIdentifier: bid)
                .filter { $0.processIdentifier != me }
            others.forEach { $0.terminate() }
            let deadline = Date().addingTimeInterval(15)
            while others.contains(where: { !$0.isTerminated }), Date() < deadline {
                RunLoop.current.run(until: Date().addingTimeInterval(0.1))
            }
            others.filter { !$0.isTerminated }.forEach { $0.forceTerminate() }
        }

        // Multi-user conflict check (#48)
        checkForOtherInstances()

        // Startup cleanup: a previous run that never cleaned up (crash,
        // SIGKILL, an older build replaced above) leaves the system proxy on
        // a dead loopback port. The flag alone misses the replaced build,
        // which clears it before its own cleanup fails.
        if !Self.isTestHost,
           UserDefaults.standard.bool(forKey: "proxymate.wasEnabled") || ProxyManager.pointsAtDeadLoopback() {
            UserDefaults.standard.set(false, forKey: "proxymate.wasEnabled")
            Task {
                try? await ProxyManager.disable()
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
        monitor.pathUpdateHandler = { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                // CRITICAL: reapply the SYNTHETIC loopback proxy (= our
                // listener), NOT the user-selected upstream. Previous
                // version passed `proxy` (e.g. Local Squid 127.0.0.1:3128)
                // here, which silently rewrote the system proxy back to
                // the upstream and made every browser request bypass
                // Proxymate entirely. See AppState.reapplySystemProxyIfNeeded.
                await self.state.reapplySystemProxyIfNeeded()
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
                // Re-apply system proxy → loopback listener, NOT the user
                // upstream. (Same root cause as the NWPathMonitor handler
                // above; both shared the bug that silently routed traffic
                // around Proxymate after every wake.)
                await state.reapplySystemProxyIfNeeded()
            }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        Self.isTerminating = true

        // Restore the system proxy first: the sidecar stops below can wait
        // for a start() in progress, and a SIGKILL in that window must not
        // find the proxy still pointing at this process.
        if !Self.isTestHost, UserDefaults.standard.bool(forKey: "proxymate.wasEnabled") {
            // Synchronous on the main thread, with no Task and no timeout:
            // a detached Task started here was measured never to run within
            // the previous 8 s wait, and the app quit with the system proxy
            // still pointing at its closed listener, which breaks the
            // network until it is reset by hand. disableNow() clears web,
            // HTTPS and PAC on every service and prompts only if
            // networksetup as the user did not take effect.
            do {
                try ProxyManager.disableNow()
                UserDefaults.standard.set(false, forKey: "proxymate.wasEnabled")
            } catch {
                NSLog("Proxymate quit: disabling the system proxy failed: %@", String(describing: error))
            }
        }

        // Clean up multi-user lock file
        try? FileManager.default.removeItem(atPath: "/tmp/proxymate-\(NSUserName()).lock")

        // Stop monitoring
        pathMonitor?.cancel()
        if let activity { ProcessInfo.processInfo.endActivity(activity) }

        // Stop network listeners
        MetricsServer.shared.stop()
        MITMProxySidecar.shared.stopAndWait()
        SquidSidecar.shared.stopAndWait()

        // Flush any log entries still buffered (the 0.5s timer covers
        // normal operation, but a quit within that tick would drop the
        // last few lines — exactly the lines a tester would want when
        // the quit was itself suspect).
        PersistentLogger.shared.flushNow()
    }
}
