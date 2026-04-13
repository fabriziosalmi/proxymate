//
//  PrivilegedHelper.swift
//  proxymate
//
//  Runs shell scripts as root for privileged operations (networksetup,
//  security add-trusted-cert, etc.). Uses `osascript do shell script …
//  with administrator privileges` which is the only path that reliably
//  works on macOS 26 (Tahoe) — AuthorizationExecuteWithPrivileges has
//  been fully removed/no-op since 15+ and silently fails.
//
//  The OS caches admin authorization for ~5 minutes across invocations,
//  so back-to-back privileged calls don't re-prompt.
//

import Foundation
import Security

enum PrivilegedHelperError: LocalizedError {
    case authorizationDenied
    case authorizationCancelled
    case authorizationFailed(OSStatus)
    case executionFailed(Int32)
    case outputError(String)

    var errorDescription: String? {
        switch self {
        case .authorizationDenied:
            return "Authorization denied"
        case .authorizationCancelled:
            return "Authorization cancelled by user"
        case .authorizationFailed(let s):
            return "Authorization failed (OSStatus \(s))"
        case .executionFailed(let s):
            return "Privileged execution failed (exit \(s))"
        case .outputError(let msg):
            return msg
        }
    }
}

nonisolated final class PrivilegedHelper: @unchecked Sendable {

    static let shared = PrivilegedHelper()

    private let lock = NSLock()
    private var hasAuthorizedOnce = false

    // MARK: - Public API

    /// No-op on macOS 26+: there's nothing to pre-authorize because we
    /// invoke `osascript` per-call. The OS caches auth itself for ~5min.
    /// Kept for API compatibility with existing call sites.
    func ensureAuthorized() throws { /* noop */ }

    /// Runs a shell script as root via `osascript do shell script`.
    /// Blocks the calling thread until the script finishes.
    ///
    /// Presents the native macOS admin password/TouchID dialog on first call;
    /// subsequent calls within the OS auth window (~5min) run without UI.
    func runAsRoot(_ script: String) throws {
        // Materialize the script to a temp file. Embedding large, quote-heavy
        // scripts directly inside AppleScript string literals is fragile
        // (escaping rules differ); a temp file sidesteps the issue entirely.
        let tmpDir = FileManager.default.temporaryDirectory
        let tmpURL = tmpDir.appendingPathComponent("proxymate-priv-\(UUID().uuidString).sh")
        let body = "#!/bin/bash\nset -o pipefail\n" + script + "\n"

        try body.write(to: tmpURL, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tmpURL) }
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o700)],
            ofItemAtPath: tmpURL.path
        )

        // AppleScript invocation: quote the path defensively. The path comes
        // from FileManager + UUID so it has no spaces or quotes, but escape
        // anyway to keep this robust if that ever changes.
        let quotedPath = Self.escapeForAppleScriptDouble(tmpURL.path)
        let applescript = "do shell script \"/bin/bash \\\"\(quotedPath)\\\"\" with administrator privileges"

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", applescript]

        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe

        do {
            try proc.run()
        } catch {
            throw PrivilegedHelperError.authorizationFailed(errSecInternalError)
        }
        proc.waitUntilExit()

        let stdoutStr = String(
            data: outPipe.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8) ?? ""
        let stderrStr = String(
            data: errPipe.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8) ?? ""

        if proc.terminationStatus != 0 {
            // AppleScript error -128 == user cancelled the auth prompt.
            if stderrStr.contains("(-128)") || stderrStr.lowercased().contains("user canceled") {
                throw PrivilegedHelperError.authorizationCancelled
            }
            let msg = stderrStr.trimmingCharacters(in: .whitespacesAndNewlines)
            if !msg.isEmpty {
                throw PrivilegedHelperError.outputError(msg)
            }
            throw PrivilegedHelperError.executionFailed(proc.terminationStatus)
        }

        // `networksetup` writes soft errors to stdout without exiting non-zero.
        let combined = stdoutStr + stderrStr
        if combined.lowercased().contains("** error") {
            throw PrivilegedHelperError.outputError(
                combined.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        lock.lock()
        hasAuthorizedOnce = true
        lock.unlock()
    }

    /// Clears our "has authorized once" hint. The OS auth cache is not
    /// user-controllable; this only affects UI state.
    func deauthorize() {
        lock.lock()
        defer { lock.unlock() }
        hasAuthorizedOnce = false
    }

    /// Best-effort indicator of whether we've successfully run a privileged
    /// command in this session. Not authoritative (the OS auth window may
    /// have expired independently).
    var isAuthorized: Bool {
        lock.lock()
        defer { lock.unlock() }
        return hasAuthorizedOnce
    }

    // Escape a string for embedding inside an AppleScript double-quoted literal.
    private static func escapeForAppleScriptDouble(_ s: String) -> String {
        // Backslashes first, then double-quotes.
        s.replacingOccurrences(of: "\\", with: "\\\\")
         .replacingOccurrences(of: "\"", with: "\\\"")
    }
}
