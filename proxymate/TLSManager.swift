//
//  TLSManager.swift
//  proxymate
//
//  Manages a per-installation root CA for TLS MITM interception.
//  v0.8.13: CA key stored on disk (AES-encrypted), NOT in Keychain.
//  Cert stored in Keychain for system trust only.
//  Leaf certs forged on-the-fly via openssl using disk-based CA key.
//

import Foundation
import Security
import AppKit

nonisolated struct MITMSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var interceptHosts: [String] = []
    var excludeHosts: [String] = [
        "*.apple.com", "*.icloud.com", "*.apple-cloudkit.com",
        "*.googleapis.com", "*.gstatic.com", "*.googleusercontent.com",
        "*.banking.*", "*.bank.*",
        // Mozilla services
        "*.firefox.com", "*.mozilla.com", "*.mozilla.org",
        // Cert-pinned apps
        "*.whatsapp.net", "*.whatsapp.com",
        "*.signal.org", "*.signal.com",
        "*.telegram.org",
        // Analytics/CDN (cert-pinned, no value in intercepting)
        "*.datadoghq.com",
    ]
    // WebSocket hosts are auto-excluded at runtime when detected
    // (see MITMHandler.processRequest WebSocket upgrade detection)
    var caInstalled: Bool = false
}

nonisolated final class TLSManager: @unchecked Sendable {

    static let shared = TLSManager()

    private let queue = DispatchQueue(label: "proxymate.tls", qos: .userInitiated)
    private let caLabel = "Proxymate Root CA"

    // Disk paths for CA key + cert
    private let caDir: URL = {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return appSupport.appendingPathComponent("Proxymate/ca", isDirectory: true)
    }()
    private var caKeyPath: String { caDir.appendingPathComponent("ca.key").path }
    private var caCertPath: String { caDir.appendingPathComponent("ca.pem").path }

    // Cached leaf identities
    private var leafCache: [String: SecIdentity] = [:]

    // Pinning detection
    private var pinningFailures: [String: Int] = [:]
    private var runtimeExcludes: Set<String> = []
    private let pinningAutoExcludeThreshold = 3

    // MARK: - CA Lifecycle

    var isCAInstalled: Bool {
        FileManager.default.fileExists(atPath: caKeyPath) &&
        FileManager.default.fileExists(atPath: caCertPath)
    }

    /// Check CA cert expiry. Returns days until expiration, or nil if cert not found.
    func caExpiryDays() -> Int? {
        guard isCAInstalled else { return nil }
        let pipe = Pipe()
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = ["x509", "-enddate", "-noout", "-in", caCertPath]
        p.standardOutput = pipe
        p.standardError = Pipe()
        do { try p.run() } catch { return nil }
        p.waitUntilExit()
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        // Format: notAfter=Mar 15 12:00:00 2035 GMT
        guard let dateStr = output.split(separator: "=").last?.trimmingCharacters(in: .whitespacesAndNewlines) else { return nil }
        let fmt = DateFormatter()
        fmt.locale = Locale(identifier: "en_US_POSIX")
        fmt.dateFormat = "MMM dd HH:mm:ss yyyy 'GMT'"
        fmt.timeZone = TimeZone(identifier: "GMT")
        guard let expiry = fmt.date(from: dateStr) ?? fmt.date(from: String(dateStr)) else { return nil }
        return Calendar.current.dateComponents([.day], from: Date(), to: expiry).day
    }

    /// Generate a new root CA. Key stays on disk, cert goes to Keychain for trust.
    func generateCA() throws -> SecCertificate {
        try queue.sync {
            try? FileManager.default.createDirectory(at: caDir, withIntermediateDirectories: true)

            // Remove old files
            try? FileManager.default.removeItem(atPath: caKeyPath)
            try? FileManager.default.removeItem(atPath: caCertPath)

            // 1. Generate CA key + self-signed cert via openssl
            guard shell("/usr/bin/openssl", args: [
                "req", "-x509", "-new", "-nodes", "-newkey", "rsa:2048",
                "-keyout", caKeyPath, "-out", caCertPath, "-days", "3650",
                "-subj", "/CN=\(caLabel)/O=Proxymate/C=US"
            ]) == 0 else {
                throw TLSError.keyGenFailed("openssl req -x509 failed")
            }

            // Protect key file
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: caKeyPath)

            // 2. Load cert as SecCertificate
            let derPath = caDir.appendingPathComponent("ca.der").path
            guard shell("/usr/bin/openssl", args: [
                "x509", "-in", caCertPath, "-outform", "DER", "-out", derPath
            ]) == 0 else {
                throw TLSError.certCreationFailed
            }
            guard let derData = try? Data(contentsOf: URL(fileURLWithPath: derPath)),
                  let cert = SecCertificateCreateWithData(nil, derData as CFData) else {
                throw TLSError.certCreationFailed
            }

            // 3. Add cert to Keychain (for trust management only, NOT the key)
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecValueRef as String: cert,
                kSecAttrLabel as String: caLabel,
            ]
            SecItemDelete(addQuery as CFDictionary)
            SecItemAdd(addQuery as CFDictionary, nil)

            // Cleanup temp DER
            try? FileManager.default.removeItem(atPath: derPath)

            leafCache.removeAll()
            return cert
        }
    }

    /// Remove CA from disk and Keychain.
    func removeCA() {
        queue.sync {
            try? FileManager.default.removeItem(at: caDir)
            let certQuery: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: caLabel,
            ]
            SecItemDelete(certQuery as CFDictionary)
            leafCache.removeAll()
        }
    }

    /// Export CA cert as DER data.
    func exportCACertDER() -> Data? {
        guard FileManager.default.fileExists(atPath: caCertPath) else { return nil }
        let derPath = caDir.appendingPathComponent("ca_export.der").path
        guard shell("/usr/bin/openssl", args: [
            "x509", "-in", caCertPath, "-outform", "DER", "-out", derPath
        ]) == 0 else { return nil }
        let data = try? Data(contentsOf: URL(fileURLWithPath: derPath))
        try? FileManager.default.removeItem(atPath: derPath)
        return data
    }

    /// Trust the CA system-wide via security add-trusted-cert (admin password).
    func promptUserToTrust() {
        guard FileManager.default.fileExists(atPath: caCertPath) else { return }
        let script = "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"\(caCertPath)\""
        Task {
            try? await Task.detached(priority: .userInitiated) {
                try PrivilegedHelper.shared.runAsRoot(script)
            }.value
        }
    }

    /// Check if CA is trusted by the system.
    func isCATrusted() -> Bool {
        guard let derData = exportCACertDER(),
              let cert = SecCertificateCreateWithData(nil, derData as CFData) else { return false }
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, nil)
        guard SecTrustCreateWithCertificates(cert, policy, &trust) == errSecSuccess,
              let trust else { return false }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }

    // MARK: - Leaf Cert Forging

    /// Persistent leaf cert cache directory.
    private var leafCacheDir: URL {
        caDir.appendingPathComponent("leaves", isDirectory: true)
    }

    /// Returns a SecIdentity for the given hostname. Uses disk-cached P12 if available.
    func identityForHost(_ hostname: String) throws -> SecIdentity {
        try queue.sync {
            // 1. Memory cache
            if let cached = leafCache[hostname] { return cached }

            // 2. Disk cache — check for existing P12
            let safeHostname = hostname.replacingOccurrences(of: "*", with: "_")
                .replacingOccurrences(of: "/", with: "_")
            let diskP12 = leafCacheDir.appendingPathComponent("\(safeHostname).p12")
            if let p12Data = try? Data(contentsOf: diskP12),
               let identity = importP12(p12Data) {
                leafCache[hostname] = identity
                return identity
            }

            // 3. Generate new leaf cert
            guard isCAInstalled else { throw TLSError.noCA }

            try? FileManager.default.createDirectory(at: leafCacheDir, withIntermediateDirectories: true)

            let leafDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("proxymate-leaf-\(hostname.hashValue)", isDirectory: true)
            try? FileManager.default.createDirectory(at: leafDir, withIntermediateDirectories: true)

            let leafKeyPath = leafDir.appendingPathComponent("leaf.key").path
            let leafCSRPath = leafDir.appendingPathComponent("leaf.csr").path
            let leafCertPath = leafDir.appendingPathComponent("leaf.pem").path
            let leafP12Path = leafDir.appendingPathComponent("leaf.p12").path
            let extPath = leafDir.appendingPathComponent("ext.cnf").path

            // SAN extension
            let extCnf = """
            [v3_leaf]
            subjectAltName = DNS:\(hostname)
            basicConstraints = CA:FALSE
            keyUsage = digitalSignature, keyEncipherment
            extendedKeyUsage = serverAuth
            """
            try extCnf.write(toFile: extPath, atomically: true, encoding: .utf8)

            // Generate leaf key
            guard shell("/usr/bin/openssl", args: [
                "genrsa", "-out", leafKeyPath, "2048"
            ]) == 0 else {
                try? FileManager.default.removeItem(at: leafDir)
                throw TLSError.keyGenFailed("Leaf key generation failed")
            }

            // Generate CSR
            guard shell("/usr/bin/openssl", args: [
                "req", "-new", "-key", leafKeyPath, "-out", leafCSRPath,
                "-subj", "/CN=\(hostname)/O=Proxymate MITM"
            ]) == 0 else {
                try? FileManager.default.removeItem(at: leafDir)
                throw TLSError.certCreationFailed
            }

            // Sign with CA (using disk-based key — no Keychain export needed)
            guard shell("/usr/bin/openssl", args: [
                "x509", "-req", "-in", leafCSRPath,
                "-CA", caCertPath, "-CAkey", caKeyPath,
                "-CAcreateserial", "-out", leafCertPath, "-days", "365",
                "-extensions", "v3_leaf", "-extfile", extPath
            ]) == 0 else {
                try? FileManager.default.removeItem(at: leafDir)
                throw TLSError.certCreationFailed
            }

            // Create PKCS12 bundle (LibreSSL on macOS, no -legacy flag needed)
            guard shell("/usr/bin/openssl", args: [
                "pkcs12", "-export", "-des3",
                "-inkey", leafKeyPath, "-in", leafCertPath,
                "-certfile", caCertPath, "-out", leafP12Path, "-passout", "pass:proxymate"
            ]) == 0 else {
                try? FileManager.default.removeItem(at: leafDir)
                throw TLSError.certCreationFailed
            }

            // Import PKCS12 → SecIdentity
            guard let p12Data = try? Data(contentsOf: URL(fileURLWithPath: leafP12Path)) else {
                try? FileManager.default.removeItem(at: leafDir)
                throw TLSError.certCreationFailed
            }

            // Save P12 to disk cache for next time
            try? p12Data.write(to: diskP12, options: .atomic)

            guard let identity = importP12(p12Data) else {
                try? FileManager.default.removeItem(at: leafDir)
                throw TLSError.identityNotFound
            }
            leafCache[hostname] = identity

            // Cleanup temp files
            try? FileManager.default.removeItem(at: leafDir)

            return identity
        }
    }

    // MARK: - PEM for NIO-SSL

    struct PEMBundle {
        let cert: String   // leaf cert PEM
        let key: String    // leaf private key PEM
        let caCert: String // CA cert PEM
    }

    /// Returns PEM strings for a hostname (cert + key + CA).
    /// Uses disk-cached PEM files if available, generates on miss.
    func pemForHost(_ hostname: String) throws -> PEMBundle {
        try queue.sync {
            guard isCAInstalled else { throw TLSError.noCA }

            let safeHostname = hostname.replacingOccurrences(of: "*", with: "_")
                .replacingOccurrences(of: "/", with: "_")
            let certFile = leafCacheDir.appendingPathComponent("\(safeHostname).pem")
            let keyFile = leafCacheDir.appendingPathComponent("\(safeHostname).key")

            // Check PEM cache
            if let certPEM = try? String(contentsOf: certFile, encoding: .utf8),
               let keyPEM = try? String(contentsOf: keyFile, encoding: .utf8),
               let caPEM = try? String(contentsOf: URL(fileURLWithPath: caCertPath), encoding: .utf8) {
                return PEMBundle(cert: certPEM, key: keyPEM, caCert: caPEM)
            }

            // Generate
            try? FileManager.default.createDirectory(at: leafCacheDir, withIntermediateDirectories: true)

            let tmpDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("proxymate-pem-\(hostname.hashValue)", isDirectory: true)
            try? FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: tmpDir) }

            let tmpKey = tmpDir.appendingPathComponent("leaf.key").path
            let tmpCSR = tmpDir.appendingPathComponent("leaf.csr").path
            let tmpCert = tmpDir.appendingPathComponent("leaf.pem").path
            let extPath = tmpDir.appendingPathComponent("ext.cnf").path

            let extCnf = """
            [v3_leaf]
            subjectAltName = DNS:\(hostname)
            basicConstraints = CA:FALSE
            keyUsage = digitalSignature, keyEncipherment
            extendedKeyUsage = serverAuth
            """
            try extCnf.write(toFile: extPath, atomically: true, encoding: .utf8)

            guard shell("/usr/bin/openssl", args: ["genrsa", "-out", tmpKey, "2048"]) == 0 else {
                throw TLSError.keyGenFailed("Leaf key failed")
            }
            guard shell("/usr/bin/openssl", args: [
                "req", "-new", "-key", tmpKey, "-out", tmpCSR,
                "-subj", "/CN=\(hostname)/O=Proxymate MITM"
            ]) == 0 else { throw TLSError.certCreationFailed }

            guard shell("/usr/bin/openssl", args: [
                "x509", "-req", "-in", tmpCSR,
                "-CA", caCertPath, "-CAkey", caKeyPath,
                "-CAcreateserial", "-out", tmpCert, "-days", "365",
                "-extensions", "v3_leaf", "-extfile", extPath
            ]) == 0 else { throw TLSError.certCreationFailed }

            guard let certPEM = try? String(contentsOfFile: tmpCert, encoding: .utf8),
                  let keyPEM = try? String(contentsOfFile: tmpKey, encoding: .utf8),
                  let caPEM = try? String(contentsOfFile: caCertPath, encoding: .utf8) else {
                throw TLSError.certCreationFailed
            }

            // Cache PEM files
            try? certPEM.write(to: certFile, atomically: true, encoding: .utf8)
            try? keyPEM.write(to: keyFile, atomically: true, encoding: .utf8)

            return PEMBundle(cert: certPEM, key: keyPEM, caCert: caPEM)
        }
    }

    /// Import a PKCS12 blob and return the SecIdentity.
    private func importP12(_ data: Data) -> SecIdentity? {
        var items: CFArray?
        let opts: [String: Any] = [kSecImportExportPassphrase as String: "proxymate"]
        guard SecPKCS12Import(data as CFData, opts as CFDictionary, &items) == errSecSuccess,
              let arr = items as? [[String: Any]],
              let ref = arr.first?[kSecImportItemIdentity as String] else {
            return nil
        }
        // SecIdentity is a CF type — cast from Any is safe after the guard above.
        return (ref as! SecIdentity)
    }

    // MARK: - Interception Decision

    func shouldIntercept(host: String, settings: MITMSettings) -> Bool {
        guard settings.enabled else { return false }
        let h = host.lowercased()

        // HSTS preload
        if HSTSPreload.isPreloaded(h) { return false }

        // Runtime excludes (auto-detected cert pinning)
        if runtimeExcludes.contains(h) { return false }

        // Auto-excluded by cert pinning detection
        if (pinningFailures[h] ?? 0) >= pinningAutoExcludeThreshold { return false }

        // User excludes
        for pattern in settings.excludeHosts {
            if matchesWildcard(host: h, pattern: pattern.lowercased()) { return false }
        }

        // If interceptHosts is empty, intercept everything not excluded
        if settings.interceptHosts.isEmpty { return true }

        // Explicit includes
        for pattern in settings.interceptHosts {
            if matchesWildcard(host: h, pattern: pattern.lowercased()) { return true }
        }
        return false
    }

    /// Record handshake failure. Returns true if host should be auto-excluded.
    func recordHandshakeFailure(host: String) -> Bool {
        queue.sync {
            let h = host.lowercased()
            let count = (pinningFailures[h] ?? 0) + 1
            pinningFailures[h] = count
            return count >= pinningAutoExcludeThreshold
        }
    }
    
    /// Get failure count for a host (for logging)
    func failureCount(for host: String) -> Int {
        queue.sync {
            pinningFailures[host.lowercased()] ?? 0
        }
    }
    
    /// Add host to runtime excludes (triggered by cert pinning detection)
    func addRuntimeExclude(host: String) {
        let lower = host.lowercased()
        queue.async { [self] in
            runtimeExcludes.insert(lower)
        }
    }
    
    /// Get current runtime excludes (for UI display)
    func getRuntimeExcludes() -> [String] {
        queue.sync { Array(runtimeExcludes).sorted() }
    }

    func resetPinningHistory() {
        queue.sync { 
            pinningFailures.removeAll()
            runtimeExcludes.removeAll()
        }
    }

    // MARK: - Helpers

    private func matchesWildcard(host: String, pattern: String) -> Bool {
        if pattern == host { return true }
        if pattern.hasPrefix("*.") {
            let suffix = String(pattern.dropFirst(2))
            return host == suffix || host.hasSuffix("." + suffix)
        }
        if pattern.contains("*") {
            let escaped = NSRegularExpression.escapedPattern(for: pattern)
                .replacingOccurrences(of: "\\*", with: ".*")
            return (try? NSRegularExpression(pattern: "^\(escaped)$"))
                .flatMap { $0.firstMatch(in: host, range: NSRange(host.startIndex..., in: host)) } != nil
        }
        return false
    }

    private func shell(_ command: String, args: [String]) -> Int32 {
        let p = Process()
        p.launchPath = command
        p.arguments = args
        p.standardOutput = Pipe()
        let errPipe = Pipe()
        p.standardError = errPipe
        do { try p.run() } catch {
            NSLog("[TLSManager] shell failed to launch \(command): \(error)")
            return -1
        }
        p.waitUntilExit()
        if p.terminationStatus != 0 {
            let stderr = String(data: errPipe.fileHandleForReading.availableData, encoding: .utf8) ?? ""
            NSLog("[TLSManager] shell \(command) exited \(p.terminationStatus): \(stderr)")
        }
        return p.terminationStatus
    }

    enum TLSError: LocalizedError {
        case keyGenFailed(String)
        case certCreationFailed
        case keychainError(OSStatus)
        case noCA
        case identityNotFound

        var errorDescription: String? {
            switch self {
            case .keyGenFailed(let m): return "Key generation failed: \(m)"
            case .certCreationFailed: return "Certificate creation failed"
            case .keychainError(let s): return "Keychain error (OSStatus \(s))"
            case .noCA: return "No root CA installed"
            case .identityNotFound: return "Identity not found"
            }
        }
    }
}
