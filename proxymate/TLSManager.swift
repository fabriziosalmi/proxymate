//
//  TLSManager.swift
//  proxymate
//
//  Manages a per-installation root CA for TLS MITM interception.
//
//  CA private key is stored on disk encrypted with AES-256 (openssl
//  -aes256 PEM envelope). The symmetric passphrase is a 32-byte random
//  blob kept in the user's login Keychain (kSecClassGenericPassword,
//  this-device-only). Result: reading ca.key from backup/malware is
//  useless without Keychain access, and Keychain access requires the
//  user's login password (or TouchID) on modern macOS.
//
//  Leaf P12 bundles use a separate Keychain-stored random passphrase.
//
//  CA cert (public half) goes to the Keychain as a certificate so the
//  user can manage trust via Keychain Access.app. Leaf certs are forged
//  on-the-fly via openssl, signed by the disk-encrypted CA key.
//

import Foundation
import Security
import AppKit

nonisolated struct MITMSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var interceptHosts: [String] = []
    var excludeHosts: [String] = [
        // Apple ecosystem (heavy app-level pinning, MITM breaks Software Update,
        // iCloud sync, Push, Maps, etc.)
        "*.apple.com", "*.icloud.com", "*.apple-cloudkit.com",
        "*.mzstatic.com",
        // Google services that pin
        "*.googleapis.com", "*.gstatic.com", "*.googleusercontent.com",
        // Wildcard banking/finance
        "*.banking.*", "*.bank.*",
        // Mozilla / Firefox sync
        "*.firefox.com", "*.mozilla.com", "*.mozilla.org",
        // Cert-pinned messaging apps
        "*.whatsapp.net", "*.whatsapp.com",
        "*.signal.org", "*.signal.com",
        "*.telegram.org",
        // Analytics / observability that cert-pin
        "*.datadoghq.com",
        // ── Streaming media CDNs (audio/video) ────────────────────────
        // These are media-only hosts where MITM breaks HLS/DASH segments
        // and player handshakes. NOT included on purpose: generic
        // multi-tenant CDNs like *.cloudflare.com, *.cloudfront.net,
        // *.akamai.net — those host millions of non-media sites where
        // MITM works fine and is wanted.
        "*.akamaihd.net", "*.akamaized.net",      // Akamai media-edge subdomains
        "*.googlevideo.com", "*.ytimg.com",       // YouTube
        "*.vimeocdn.com",                         // Vimeo
        "*.ttvnw.net", "*.jtvnw.net", "*.live-video.net",  // Twitch
        "*.scdn.co", "*.spotifycdn.com",          // Spotify (audio CDN)
        "*.nflxvideo.net", "*.nflximg.net",       // Netflix
        "*.disneystreaming.com", "*.bamgrid.com", // Disney+ / Hulu
        "*.dazn.com", "*.dazn-pi.com",            // DAZN
        "*.bcvp.it", "*.brightcove.com",          // Brightcove
        // Italian broadcasters (state-pinned for legitimate reasons)
        "*.rai.it", "*.raiplay.it", "*.raiplaysound.it",
        "*.mediasetplay.mediaset.it", "*.mediaset.it",
        "*.la7.it",
    ]
    // WebSocket hosts are auto-excluded at runtime when detected
    // (see MITMHandler.processRequest WebSocket upgrade detection)
    var caInstalled: Bool = false
}

nonisolated final class TLSManager: @unchecked Sendable {

    static let shared = TLSManager()

    private let queue = DispatchQueue(label: "proxymate.tls", qos: .userInitiated)
    private let caLabel = "Proxymate Root CA"

    // Keychain account names for the random passphrases. Service is the app
    // bundle id so items are scoped to this installation.
    private let keychainService = "fabriziosalmi.proxymate.tls"
    private let caPassphraseAccount = "ca-key-passphrase-v1"
    private let leafPassphraseAccount = "leaf-p12-passphrase-v1"

    // Disk paths for CA key + cert
    private let caDir: URL = {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return appSupport.appendingPathComponent("Proxymate/ca", isDirectory: true)
    }()
    private var caKeyPath: String { caDir.appendingPathComponent("ca.key").path }
    private var caCertPath: String { caDir.appendingPathComponent("ca.pem").path }

    // Cached leaf identities (capped to prevent unbounded memory growth)
    private var leafCache: [String: SecIdentity] = [:]
    private let leafCacheMaxSize = 500

    // Pinning detection (capped to prevent unbounded growth over long sessions)
    private var pinningFailures: [String: Int] = [:]
    private var runtimeExcludes: Set<String> = []
    private let pinningMaxEntries = 5_000
    private let pinningAutoExcludeThreshold = 3

    // MARK: - CA Lifecycle

    /// Thread-safe: filesystem check is inherently racy, but synchronized
    /// with queue to prevent reading mid-generate/delete.
    var isCAInstalled: Bool {
        queue.sync {
            FileManager.default.fileExists(atPath: caKeyPath) &&
            FileManager.default.fileExists(atPath: caCertPath)
        }
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

    /// Generate a new root CA. Key is written to disk encrypted with AES-256;
    /// the symmetric passphrase is stored in Keychain. Cert goes to Keychain
    /// as a certificate item for trust management.
    func generateCA() throws -> SecCertificate {
        try queue.sync {
            try? FileManager.default.createDirectory(at: caDir, withIntermediateDirectories: true)

            // Remove old files and stale Keychain passphrases.
            try? FileManager.default.removeItem(atPath: caKeyPath)
            try? FileManager.default.removeItem(atPath: caCertPath)
            deletePassphrase(account: caPassphraseAccount)
            deletePassphrase(account: leafPassphraseAccount)

            // Fresh random passphrase for the new CA key.
            let caPass = try getOrCreatePassphrase(account: caPassphraseAccount)

            // 1. Generate AES-256-encrypted CA key + self-signed cert via openssl.
            //    Split into two steps (genpkey then req -x509 -key) because
            //    neither LibreSSL nor OpenSSL 3.x accepts `-aes256` as an
            //    inline flag to `req -newkey` — it was removed/renamed.
            //    genpkey + -aes-256-cbc is the portable form that works
            //    against /usr/bin/openssl (LibreSSL on macOS) and brew
            //    OpenSSL 3.x alike.
            //    -pass/-passout env:VAR reads the passphrase from the env
            //    we pass to Process; it never hits argv or the filesystem.
            guard shellWithEnv("/usr/bin/openssl", args: [
                "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:2048",
                "-aes-256-cbc", "-pass", "env:PROXYMATE_CA_PASS",
                "-out", caKeyPath
            ], env: ["PROXYMATE_CA_PASS": caPass]) == 0 else {
                throw TLSError.keyGenFailed("openssl genpkey failed")
            }
            guard shellWithEnv("/usr/bin/openssl", args: [
                "req", "-x509", "-new",
                "-key", caKeyPath, "-passin", "env:PROXYMATE_CA_PASS",
                "-out", caCertPath, "-days", "3650",
                "-subj", "/CN=\(caLabel)/O=Proxymate/C=US"
            ], env: ["PROXYMATE_CA_PASS": caPass]) == 0 else {
                throw TLSError.keyGenFailed("openssl req -x509 failed")
            }

            // Tighten permissions on the (already-encrypted) key file.
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

    /// Remove CA from disk, Keychain (cert + passphrases), and memory cache.
    /// Existing leaf P12 files on disk become unreadable once the leaf
    /// passphrase is deleted; that's the desired behavior (revocation).
    func removeCA() {
        queue.sync {
            try? FileManager.default.removeItem(at: caDir)
            let certQuery: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: caLabel,
            ]
            SecItemDelete(certQuery as CFDictionary)
            deletePassphrase(account: caPassphraseAccount)
            deletePassphrase(account: leafPassphraseAccount)
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
    /// Uses argument array (not shell string) to prevent command injection via caCertPath.
    func promptUserToTrust() {
        guard FileManager.default.fileExists(atPath: caCertPath) else { return }
        // Shell-escape the path to prevent injection from usernames with metacharacters
        let safePath = caCertPath.replacingOccurrences(of: "'", with: "'\\''")
        let script = "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '\(safePath)'"
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

            // Ensure the CA key is encrypted at rest (transparent migration
            // from plaintext keys produced by older builds) and fetch the
            // passphrase from Keychain.
            try ensureCAKeyEncrypted()
            let caPass = try getOrCreatePassphrase(account: caPassphraseAccount)
            let leafPass = try getOrCreatePassphrase(account: leafPassphraseAccount)

            // Sign with the encrypted CA key via -passin env:VAR (passphrase
            // never appears on argv or any temp file).
            guard shellWithEnv("/usr/bin/openssl", args: [
                "x509", "-req", "-in", leafCSRPath,
                "-CA", caCertPath, "-CAkey", caKeyPath,
                "-passin", "env:PROXYMATE_CA_PASS",
                "-CAcreateserial", "-out", leafCertPath, "-days", "365",
                "-extensions", "v3_leaf", "-extfile", extPath
            ], env: ["PROXYMATE_CA_PASS": caPass]) == 0 else {
                try? FileManager.default.removeItem(at: leafDir)
                throw TLSError.certCreationFailed
            }

            // Create PKCS12 bundle with a random, per-installation passphrase
            // stored in Keychain. Identical for all leaves (acceptable — leaves
            // are ephemeral and re-forgeable — and avoids per-file key
            // management complexity).
            guard shellWithEnv("/usr/bin/openssl", args: [
                "pkcs12", "-export", "-des3",
                "-inkey", leafKeyPath, "-in", leafCertPath,
                "-certfile", caCertPath, "-out", leafP12Path,
                "-passout", "env:PROXYMATE_LEAF_PASS"
            ], env: ["PROXYMATE_LEAF_PASS": leafPass]) == 0 else {
                try? FileManager.default.removeItem(at: leafDir)
                throw TLSError.certCreationFailed
            }

            // Import PKCS12 → SecIdentity
            guard let p12Data = try? Data(contentsOf: URL(fileURLWithPath: leafP12Path)) else {
                try? FileManager.default.removeItem(at: leafDir)
                throw TLSError.certCreationFailed
            }

            // Save P12 to disk cache for next time (0o600 perms so other
            // local users can't read the leaf key).
            try? p12Data.write(to: diskP12, options: .atomic)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: diskP12.path)

            guard let identity = importP12(p12Data) else {
                try? FileManager.default.removeItem(at: leafDir)
                throw TLSError.identityNotFound
            }
            if leafCache.count >= leafCacheMaxSize { leafCache.removeAll() }
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

            try ensureCAKeyEncrypted()
            let caPass = try getOrCreatePassphrase(account: caPassphraseAccount)
            guard shellWithEnv("/usr/bin/openssl", args: [
                "x509", "-req", "-in", tmpCSR,
                "-CA", caCertPath, "-CAkey", caKeyPath,
                "-passin", "env:PROXYMATE_CA_PASS",
                "-CAcreateserial", "-out", tmpCert, "-days", "365",
                "-extensions", "v3_leaf", "-extfile", extPath
            ], env: ["PROXYMATE_CA_PASS": caPass]) == 0 else { throw TLSError.certCreationFailed }

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

    /// Import a PKCS12 blob using the Keychain-stored leaf passphrase.
    private func importP12(_ data: Data) -> SecIdentity? {
        guard let leafPass = try? getOrCreatePassphrase(account: leafPassphraseAccount) else {
            return nil
        }
        var items: CFArray?
        let opts: [String: Any] = [kSecImportExportPassphrase as String: leafPass]
        guard SecPKCS12Import(data as CFData, opts as CFDictionary, &items) == errSecSuccess,
              let arr = items as? [[String: Any]],
              let first = arr.first,
              let ref = first[kSecImportItemIdentity as String] else {
            return nil
        }
        return (ref as! SecIdentity)
    }

    // MARK: - Interception Decision

    func shouldIntercept(host: String, settings: MITMSettings) -> Bool {
        guard settings.enabled else { return false }
        let h = host.lowercased()

        // HSTS preload
        if HSTSPreload.isPreloaded(h) { return false }

        // Runtime excludes and pinning failures — read under queue lock to avoid data race
        let excluded: Bool = queue.sync {
            runtimeExcludes.contains(h) ||
            (pinningFailures[h] ?? 0) >= pinningAutoExcludeThreshold
        }
        if excluded { return false }

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
            if pinningFailures.count >= pinningMaxEntries { pinningFailures.removeAll() }
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

    /// Add host to runtime excludes in response to a streaming-media
    /// Content-Type. Returns true on the first call for a given host so
    /// the caller can log once; subsequent calls return false.
    func recordStreamingMediaDetected(host: String) -> Bool {
        queue.sync {
            let lower = host.lowercased()
            if runtimeExcludes.contains(lower) { return false }
            runtimeExcludes.insert(lower)
            return true
        }
    }

    /// Classify a Content-Type header value as a streaming-media type
    /// that Proxymate should not intercept at the body level. Matches the
    /// actual streams (audio/*, video/*) and the manifest formats that
    /// players fetch from the same host before pulling segments.
    static func isStreamingMediaContentType(_ value: String) -> Bool {
        // Value may be "audio/mpeg; charset=..." — compare only the type.
        let t = value.split(separator: ";", maxSplits: 1).first
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            ?? value.lowercased()
        if t.hasPrefix("audio/") || t.hasPrefix("video/") { return true }
        switch t {
        case "application/vnd.apple.mpegurl",    // HLS manifest (m3u8)
             "application/x-mpegurl",            // HLS manifest (legacy)
             "application/dash+xml",             // MPEG-DASH manifest
             "application/vnd.ms-sstr+xml":      // Smooth Streaming manifest
            return true
        default:
            return false
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
        shellWithEnv(command, args: args, env: nil)
    }

    /// Run a subprocess with an explicit environment overlay. Env vars are
    /// added on top of the parent process env (not replacing it), so /usr/bin
    /// PATH and locale stay intact. Used to pass secrets (passphrases) to
    /// openssl without putting them on argv or on disk.
    private func shellWithEnv(_ command: String, args: [String], env: [String: String]?) -> Int32 {
        let p = Process()
        p.launchPath = command
        p.arguments = args
        p.standardOutput = Pipe()
        let errPipe = Pipe()
        p.standardError = errPipe
        if let env {
            var merged = ProcessInfo.processInfo.environment
            for (k, v) in env { merged[k] = v }
            p.environment = merged
        }
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

    // MARK: - Keychain-backed passphrase helpers

    /// Returns the passphrase stored for `account`, generating and storing a
    /// fresh 32-byte random one if none exists. Thread safety: callers hold
    /// `queue`. Keychain itself is thread-safe.
    private func getOrCreatePassphrase(account: String) throws -> String {
        if let existing = readPassphrase(account: account) { return existing }

        var bytes = [UInt8](repeating: 0, count: 32)
        let rc = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard rc == errSecSuccess else {
            throw TLSError.keyGenFailed("SecRandomCopyBytes failed (\(rc))")
        }
        let pass = Data(bytes).base64EncodedString()
        try storePassphrase(pass, account: account)
        return pass
    }

    private func readPassphrase(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let s = String(data: data, encoding: .utf8) else {
            return nil
        }
        return s
    }

    private func storePassphrase(_ passphrase: String, account: String) throws {
        guard let data = passphrase.data(using: .utf8) else {
            throw TLSError.keyGenFailed("passphrase encoding failed")
        }
        let delete: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(delete as CFDictionary)

        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw TLSError.keychainError(status)
        }
    }

    private func deletePassphrase(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Detect an unencrypted CA key from a pre-fix install and re-encrypt it
    /// in place with a fresh Keychain-stored passphrase. No-op once the key
    /// is already encrypted. All leaf caches are invalidated on migration
    /// (leaves were signed without a passphrase — still valid cryptographically
    /// but cached P12s were encrypted under the hardcoded leaf passphrase
    /// and won't import with the new random one).
    /// Public entry point so the migration can be triggered proactively at
    /// app launch (AppState.init), not lazily on first leaf signing. Without
    /// this, a user whose leaf-cert cache is warm from previous sessions
    /// never hits identityForHost's slow path and the plaintext CA stays
    /// plaintext indefinitely. Idempotent — early-returns when the file is
    /// already encrypted, so calling on every launch costs essentially zero.
    func migrateCAEncryptionIfNeeded() {
        queue.sync {
            do { try ensureCAKeyEncrypted() }
            catch { NSLog("[TLSManager] CA encryption migration failed: \(error)") }
        }
    }

    private func ensureCAKeyEncrypted() throws {
        guard FileManager.default.fileExists(atPath: caKeyPath) else { return }
        let head: String
        do {
            let fh = try FileHandle(forReadingFrom: URL(fileURLWithPath: caKeyPath))
            defer { try? fh.close() }
            let snippet = try fh.read(upToCount: 256) ?? Data()
            head = String(data: snippet, encoding: .utf8) ?? ""
        } catch {
            return // unreadable — leave it; caller will fail on use
        }
        // Encrypted PEM envelopes start with either:
        //   -----BEGIN ENCRYPTED PRIVATE KEY-----   (PKCS#8 encrypted)
        //   -----BEGIN RSA PRIVATE KEY-----
        //   Proc-Type: 4,ENCRYPTED                  (traditional OpenSSL)
        if head.contains("ENCRYPTED") { return }

        // Migrate: re-encrypt the plaintext key under a fresh passphrase.
        let pass = try getOrCreatePassphrase(account: caPassphraseAccount)
        let tmp = caKeyPath + ".migrating"
        try? FileManager.default.removeItem(atPath: tmp)
        let rc = shellWithEnv("/usr/bin/openssl", args: [
            "rsa", "-in", caKeyPath, "-out", tmp, "-aes256",
            "-passout", "env:PROXYMATE_CA_PASS"
        ], env: ["PROXYMATE_CA_PASS": pass])
        guard rc == 0, FileManager.default.fileExists(atPath: tmp) else {
            try? FileManager.default.removeItem(atPath: tmp)
            throw TLSError.keyGenFailed("CA key migration failed")
        }
        _ = try? FileManager.default.replaceItemAt(
            URL(fileURLWithPath: caKeyPath), withItemAt: URL(fileURLWithPath: tmp))
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: caKeyPath)
        // Drop caches: old leaf P12s (if any) were encrypted with the legacy
        // hardcoded passphrase and won't import under the new leaf passphrase.
        try? FileManager.default.removeItem(at: leafCacheDir)
        leafCache.removeAll()
        // Also delete any stale leaf passphrase so a fresh one is generated
        // on next signing (old cached files, if any escaped the dir wipe, are
        // useless without the matching passphrase).
        deletePassphrase(account: leafPassphraseAccount)
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
