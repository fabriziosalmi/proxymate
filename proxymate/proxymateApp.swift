//
//  proxymateApp.swift
//  proxymate
//
//  Menu bar app: no Dock icon, no main window. The popover lives in
//  ContentView and is presented by MenuBarExtra.
//

import SwiftUI
import AppKit

@main
struct proxymateApp: App {
    @StateObject private var state = AppState()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    init() {
        // Single-instance: kill stale copies from previous Xcode runs
        let me = ProcessInfo.processInfo.processIdentifier
        let bid = Bundle.main.bundleIdentifier ?? ""
        for app in NSRunningApplication.runningApplications(withBundleIdentifier: bid)
        where app.processIdentifier != me {
            app.forceTerminate()
        }

        // Startup cleanup: if previous run crashed with proxy enabled,
        // clear system proxy to restore internet connectivity
        if UserDefaults.standard.bool(forKey: "proxymate.wasEnabled") {
            UserDefaults.standard.set(false, forKey: "proxymate.wasEnabled")
            Task {
                try? await ProxyManager.disable()
                try? await PACServer.clearSystemPAC()
            }
        }
    }

    var body: some Scene {
        MenuBarExtra {
            ContentView()
                .environmentObject(state)
        } label: {
            Image("MenuBarIcon")
                .renderingMode(.template)
        }
        .menuBarExtraStyle(.window)
    }
}

/// AppDelegate handles termination to clean up system proxy settings.
final class AppDelegate: NSObject, NSApplicationDelegate {

    func applicationWillTerminate(_ notification: Notification) {
        // Synchronous cleanup: clear system proxy before process exits.
        // This runs on SIGTERM, Cmd+Q, and normal quit. Does NOT run on
        // SIGKILL (kill -9), which is why we also have startup cleanup.
        if UserDefaults.standard.bool(forKey: "proxymate.wasEnabled") {
            UserDefaults.standard.set(false, forKey: "proxymate.wasEnabled")
            let sem = DispatchSemaphore(value: 0)
            Task {
                try? await ProxyManager.disable()
                try? await PACServer.clearSystemPAC()
                sem.signal()
            }
            _ = sem.wait(timeout: .now() + 3) // max 3s for cleanup
        }
    }
}
