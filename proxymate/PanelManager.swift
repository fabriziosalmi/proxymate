//
//  PanelManager.swift
//  proxymate
//
//  Manages the main floating panel (NSPanel) instead of MenuBarExtra popover.
//  Clicking the menu bar icon toggles the panel. The panel is a proper window
//  that supports sheets, TextFields, focus, and keyboard navigation.
//
//  Architecture: like Little Snitch, iStat Menus, Bartender.
//

import AppKit
import SwiftUI

/// NSPanel subclass that can become key window (required for TextFields,
/// buttons, sheets, and all interactive SwiftUI content).
final class FloatingPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}

final class PanelManager {
    static let shared = PanelManager()

    private var panel: NSPanel?
    private var hostingView: NSHostingView<AnyView>?

    /// Show or hide the panel, anchored below the status item.
    func toggle(relativeTo button: NSStatusBarButton?, state: AppState) {
        if let panel, panel.isVisible {
            panel.close()
            return
        }
        show(relativeTo: button, state: state)
    }

    func show(relativeTo button: NSStatusBarButton?, state: AppState) {
        if panel == nil {
            createPanel(state: state)
        }

        guard let panel else { return }

        // Position below the menu bar icon
        if let button, let buttonWindow = button.window {
            let buttonFrame = buttonWindow.frame
            let panelWidth = panel.frame.width
            let x = buttonFrame.midX - panelWidth / 2
            let y = buttonFrame.minY - panel.frame.height - 4
            panel.setFrameOrigin(NSPoint(x: x, y: y))
        } else {
            panel.center()
        }

        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func close() {
        panel?.close()
    }

    var isVisible: Bool {
        panel?.isVisible ?? false
    }

    private func createPanel(state: AppState) {
        let content = ContentView()
            .environmentObject(state)

        let hostingView = NSHostingView(rootView: AnyView(content))
        hostingView.frame = NSRect(x: 0, y: 0, width: 420, height: 520)

        let panel = FloatingPanel(
            contentRect: hostingView.frame,
            styleMask: [.titled, .closable, .fullSizeContentView, .resizable],
            backing: .buffered,
            defer: false
        )
        panel.contentView = hostingView
        panel.level = .floating
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovableByWindowBackground = true
        panel.animationBehavior = .utilityWindow
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.isReleasedWhenClosed = false
        panel.backgroundColor = .windowBackgroundColor
        panel.hidesOnDeactivate = false

        self.panel = panel
        self.hostingView = hostingView
    }
}
