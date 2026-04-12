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

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Single-instance
        let me = ProcessInfo.processInfo.processIdentifier
        let bid = Bundle.main.bundleIdentifier ?? ""
        for app in NSRunningApplication.runningApplications(withBundleIdentifier: bid)
        where app.processIdentifier != me {
            app.forceTerminate()
        }

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
    }

    @objc private func togglePanel() {
        PanelManager.shared.toggle(relativeTo: statusItem.button, state: state)
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Stop network listeners
        MetricsServer.shared.stop()
        MITMProxySidecar.shared.stop()

        if UserDefaults.standard.bool(forKey: "proxymate.wasEnabled") {
            UserDefaults.standard.set(false, forKey: "proxymate.wasEnabled")
            let sem = DispatchSemaphore(value: 0)
            Task {
                try? await ProxyManager.disable()
                try? await PACServer.clearSystemPAC()
                sem.signal()
            }
            _ = sem.wait(timeout: .now() + 3)
        }
    }
}
