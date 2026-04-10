//
//  PrivilegedHelper.swift
//  proxymate
//
//  Caches an AuthorizationRef so the user enters their admin password only
//  once per session. All subsequent privileged operations (networksetup calls)
//  reuse the cached reference without any UI.
//
//  Uses AuthHelperExecute (C wrapper in AuthHelper.c) which calls the
//  deprecated-but-functional AuthorizationExecuteWithPrivileges under the hood.
//

import Foundation
import Security

enum PrivilegedHelperError: LocalizedError {
    case authorizationDenied
    case authorizationCancelled
    case authorizationFailed(OSStatus)
    case executionFailed(OSStatus)
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
            return "Privileged execution failed (OSStatus \(s))"
        case .outputError(let msg):
            return msg
        }
    }
}

nonisolated final class PrivilegedHelper: @unchecked Sendable {

    static let shared = PrivilegedHelper()

    private let lock = NSLock()
    private var authRef: AuthorizationRef?

    // MARK: - Public API

    /// Ensures an AuthorizationRef exists. The first call presents the native
    /// macOS password dialog. Subsequent calls return immediately.
    func ensureAuthorized() throws {
        lock.lock()
        defer { lock.unlock() }
        if authRef != nil { return }

        var ref: AuthorizationRef?

        // Use kAuthorizationRightExecute as a C string via a local copy so
        // the pointer survives the entire AuthorizationCreate call.
        let rightName = kAuthorizationRightExecute
        var item = rightName.withCString { namePtr -> AuthorizationItem in
            AuthorizationItem(
                name: namePtr,
                valueLength: 0,
                value: nil,
                flags: 0
            )
        }
        var rights = withUnsafeMutablePointer(to: &item) { ptr in
            AuthorizationRights(count: 1, items: ptr)
        }
        let flags: AuthorizationFlags = [
            .interactionAllowed,
            .preAuthorize,
            .extendRights
        ]

        let status = AuthorizationCreate(&rights, nil, flags, &ref)

        switch status {
        case errAuthorizationSuccess:
            authRef = ref
        case errAuthorizationCanceled:
            throw PrivilegedHelperError.authorizationCancelled
        case errAuthorizationDenied:
            throw PrivilegedHelperError.authorizationDenied
        default:
            throw PrivilegedHelperError.authorizationFailed(status)
        }
    }

    /// Runs a shell script as root using the cached authorization.
    /// Blocks the calling thread until the script finishes.
    func runAsRoot(_ script: String) throws {
        try ensureAuthorized()

        lock.lock()
        let ref = authRef!
        lock.unlock()

        // Build argv: /bin/sh -c "script"
        let dashC = strdup("-c")!
        let scriptC = strdup(script)!
        defer { free(dashC); free(scriptC) }

        var args: [UnsafeMutablePointer<CChar>?] = [dashC, scriptC, nil]
        var pipe: UnsafeMutablePointer<FILE>?

        let status = args.withUnsafeMutableBufferPointer { buf -> OSStatus in
            AuthHelperExecute(
                ref,
                "/bin/sh",
                buf.baseAddress!,
                &pipe
            )
        }

        // Read stdout to wait for child completion + capture any error output
        var output = ""
        if let fp = pipe {
            var buf = [CChar](repeating: 0, count: 4096)
            while fgets(&buf, Int32(buf.count), fp) != nil {
                output += String(cString: buf)
            }
            fclose(fp)
        }

        // Reap zombie children (non-blocking)
        var childStatus: Int32 = 0
        while waitpid(-1, &childStatus, WNOHANG) > 0 {}

        guard status == errAuthorizationSuccess else {
            throw PrivilegedHelperError.executionFailed(status)
        }

        // networksetup writes errors to stdout; surface them
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().contains("** error") {
            throw PrivilegedHelperError.outputError(trimmed)
        }
    }

    /// Drops the cached authorization. After this, the next privileged call
    /// will show the password dialog again.
    func deauthorize() {
        lock.lock()
        defer { lock.unlock() }
        if let ref = authRef {
            AuthorizationFree(ref, [.destroyRights])
            authRef = nil
        }
    }

    /// Whether we currently hold a valid authorization.
    var isAuthorized: Bool {
        lock.lock()
        defer { lock.unlock() }
        return authRef != nil
    }

    deinit {
        if let ref = authRef {
            AuthorizationFree(ref, [])
        }
    }
}
