//
//  ToastView.swift
//  proxymate
//
//  In-app toast notification overlay. Shows brief messages that
//  auto-dismiss after a timeout. Sits at the top of the popover.
//

import SwiftUI
import Combine

@MainActor
final class ToastState: ObservableObject {
    static let shared = ToastState()

    @Published var message: String?
    @Published var icon: String = "checkmark.circle"
    @Published var color: Color = .green
    private var dismissTask: Task<Void, Never>?

    func show(_ message: String, icon: String = "checkmark.circle", color: Color = .green) {
        self.message = message
        self.icon = icon
        self.color = color
        dismissTask?.cancel()
        dismissTask = Task {
            try? await Task.sleep(for: .seconds(2.5))
            if !Task.isCancelled { self.message = nil }
        }
    }

    func showError(_ message: String) {
        show(message, icon: "xmark.circle", color: .red)
    }

    func showInfo(_ message: String) {
        show(message, icon: "info.circle", color: .blue)
    }
}

struct ToastOverlay: View {
    @ObservedObject var toast = ToastState.shared

    var body: some View {
        if let message = toast.message {
            HStack(spacing: 6) {
                Image(systemName: toast.icon)
                    .font(.caption)
                    .foregroundStyle(toast.color)
                Text(message)
                    .font(.caption2)
                    .lineLimit(2)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 6))
            .transition(.move(edge: .top).combined(with: .opacity))
            .animation(.easeInOut(duration: 0.2), value: toast.message)
            .onTapGesture { toast.message = nil }
        }
    }
}
