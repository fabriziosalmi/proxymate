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

    init() {
        // Single-instance: when re-running from Xcode, LSUIElement apps are
        // not auto-terminated, so each Run leaves a stale menu bar icon. Kill
        // any older copies of ourselves before continuing.
        let me = ProcessInfo.processInfo.processIdentifier
        let bid = Bundle.main.bundleIdentifier ?? ""
        for app in NSRunningApplication.runningApplications(withBundleIdentifier: bid)
        where app.processIdentifier != me {
            app.forceTerminate()
        }
    }

    var body: some Scene {
        MenuBarExtra {
            ContentView()
                .environmentObject(state)
        } label: {
            Image(systemName: state.isEnabled
                  ? "shield.lefthalf.filled.trianglebadge.exclamationmark"
                  : "shield.lefthalf.filled")
        }
        .menuBarExtraStyle(.window)
    }
}
