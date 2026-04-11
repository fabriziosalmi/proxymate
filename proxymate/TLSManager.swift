//
//  TLSManager.swift
//  proxymate
//
//  Manages a per-installation root CA for TLS MITM interception.
//  - Generates a self-signed root CA on first use (RSA 2048, 10-year validity)
//  - Stores private key + cert in the macOS Keychain
//  - Forges leaf certs on-the-fly for intercepted HTTPS hosts (cached by SAN)
//  - Provides SecIdentity for use with Network.framework TLS options
//

import Foundation
import Security

nonisolated struct MITMSettings: Codable, Hashable, Sendable {
    var enabled: Bool = false
    var interceptHosts: [String] = []      // if empty → intercept all (except excludes)
    var excludeHosts: [String] = [         // never MITM these
        "*.apple.com", "*.icloud.com",
        "*.googleapis.com",
        "*.banking.*", "*.bank.*",
    ]
    var caInstalled: Bool = false
}

nonisolated final class TLSManager: @unchecked Sendable {

    static let shared = TLSManager()

    private let queue = DispatchQueue(label: "proxymate.tls", qos: .userInitiated)
    private let caLabel = "Proxymate Root CA"
    private let caTag = "com.fabriziosalmi.proxymate.rootca"

    private var rootKey: SecKey?
    private var rootCert: SecCertificate?
    private var leafCache: [String: SecIdentity] = [:]

    // MARK: - CA lifecycle

    /// Returns true if the root CA already exists in the Keychain.
    var isCAInstalled: Bool {
        queue.sync {
            loadCAFromKeychain()
            return rootKey != nil && rootCert != nil
        }
    }

    /// Generates a new root CA and stores it in the Keychain. Returns the
    /// certificate for display/trust purposes. Overwrites any existing CA.
    func generateCA() throws -> SecCertificate {
        try queue.sync {
            let caDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("proxymate-ca", isDirectory: true)
            try? FileManager.default.createDirectory(at: caDir, withIntermediateDirectories: true)
            let keyPath = caDir.appendingPathComponent("ca.key").path
            let certPath = caDir.appendingPathComponent("ca.pem").path
            let derPath = caDir.appendingPathComponent("ca.der").path
            let p12Path = caDir.appendingPathComponent("ca.p12").path

            // 1. Generate CA key + self-signed cert via openssl
            let genResult = shell("/usr/bin/openssl", args: [
                "req", "-x509", "-new", "-nodes", "-newkey", "rsa:2048",
                "-keyout", keyPath, "-out", certPath, "-days", "3650",
                "-subj", "/CN=\(caLabel)/O=Proxymate/C=US"
            ])
            guard genResult == 0 else {
                throw TLSError.keyGenFailed("openssl req failed with exit code \(genResult)")
            }

            // 2. Convert to DER for SecCertificateCreateWithData
            let derResult = shell("/usr/bin/openssl", args: [
                "x509", "-in", certPath, "-outform", "DER", "-out", derPath
            ])
            guard derResult == 0 else {
                throw TLSError.certCreationFailed
            }

            // 3. Create PKCS12 for import into Keychain (key + cert)
            let p12Result = shell("/usr/bin/openssl", args: [
                "pkcs12", "-export", "-inkey", keyPath, "-in", certPath,
                "-out", p12Path, "-passout", "pass:proxymate"
            ])
            guard p12Result == 0 else {
                throw TLSError.certCreationFailed
            }

            // 4. Load DER cert
            guard let derData = try? Data(contentsOf: URL(fileURLWithPath: derPath)),
                  let cert = SecCertificateCreateWithData(nil, derData as CFData) else {
                throw TLSError.certCreationFailed
            }

            // 5. Import PKCS12 into Keychain (includes private key)
            guard let p12Data = try? Data(contentsOf: URL(fileURLWithPath: p12Path)) else {
                throw TLSError.certCreationFailed
            }
            var items: CFArray?
            let importOptions: [String: Any] = [
                kSecImportExportPassphrase as String: "proxymate"
            ]
            let importStatus = SecPKCS12Import(p12Data as CFData, importOptions as CFDictionary, &items)
            guard importStatus == errSecSuccess else {
                throw TLSError.keychainError(importStatus)
            }

            // Extract private key from imported identity
            if let itemArray = items as? [[String: Any]],
               let identity = itemArray.first?[kSecImportItemIdentity as String] {
                var privateKey: SecKey?
                SecIdentityCopyPrivateKey(identity as! SecIdentity, &privateKey)
                self.rootKey = privateKey
            }

            self.rootCert = cert
            self.leafCache.removeAll()

            // Cleanup temp files
            try? FileManager.default.removeItem(at: caDir)

            return cert
        }
    }

    private func shell(_ command: String, args: [String]) -> Int32 {
        let p = Process()
        p.launchPath = command
        p.arguments = args
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        do { try p.run() } catch { return -1 }
        p.waitUntilExit()
        return p.terminationStatus
    }

    /// Removes the root CA from the Keychain.
    func removeCA() {
        queue.sync {
            // Remove private key
            let keyQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrLabel as String: caLabel,
                kSecAttrApplicationTag as String: caTag.data(using: .utf8)!,
            ]
            SecItemDelete(keyQuery as CFDictionary)

            // Remove certificate
            let certQuery: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: caLabel,
            ]
            SecItemDelete(certQuery as CFDictionary)

            rootKey = nil
            rootCert = nil
            leafCache.removeAll()
        }
    }

    /// Export the root CA certificate as DER data (for display or trust prompts).
    func exportCACertDER() -> Data? {
        queue.sync {
            guard let cert = rootCert else { return nil }
            return SecCertificateCopyData(cert) as Data
        }
    }

    /// Opens System Preferences → Keychain Access to let the user trust the cert.
    /// Opens Keychain Access with the CA cert for manual trust.
    func promptUserToTrust() {
        // The cert is already in the keychain (imported via PKCS12 during generateCA).
        // Opening a .cer file would fail with -25294 (duplicate import).
        // Instead, open Keychain Access so the user can search "Proxymate Root CA"
        // and set trust to "Always Trust".
        let keychainApp = URL(fileURLWithPath: "/System/Applications/Utilities/Keychain Access.app")
        NSWorkspace.shared.open(keychainApp)
    }

    /// Check if the root CA is trusted by the system.
    func isCATrusted() -> Bool {
        guard let cert = rootCert else { return false }
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, nil)
        guard SecTrustCreateWithCertificates(cert, policy, &trust) == errSecSuccess,
              let trust else { return false }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }

    // MARK: - Cert pinning detection

    private var pinningFailures: [String: Int] = [:]
    private let pinningAutoExcludeThreshold = 3

    /// Record a handshake failure for a host. Returns true if the host
    /// should be auto-excluded (cert pinning detected).
    func recordHandshakeFailure(host: String) -> Bool {
        queue.sync {
            let h = host.lowercased()
            let count = (pinningFailures[h] ?? 0) + 1
            pinningFailures[h] = count
            return count >= pinningAutoExcludeThreshold
        }
    }

    /// Clear pinning failure history.
    func resetPinningHistory() {
        queue.sync { pinningFailures.removeAll() }
    }

    // MARK: - Leaf cert forging

    /// Returns a SecIdentity (cert + private key) for the given hostname.
    /// Cached per hostname for the session.
    func identityForHost(_ hostname: String) throws -> SecIdentity {
        try queue.sync {
            if let cached = leafCache[hostname] { return cached }

            guard rootKey != nil, rootCert != nil else {
                throw TLSError.noCA
            }

            // Generate leaf cert signed by CA via openssl
            let leafDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("proxymate-leaf-\(UUID().uuidString)", isDirectory: true)
            try? FileManager.default.createDirectory(at: leafDir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: leafDir) }

            let caKeyPath = leafDir.appendingPathComponent("ca.key").path
            let caCertPath = leafDir.appendingPathComponent("ca.pem").path
            let leafKeyPath = leafDir.appendingPathComponent("leaf.key").path
            let leafCSRPath = leafDir.appendingPathComponent("leaf.csr").path
            let leafCertPath = leafDir.appendingPathComponent("leaf.pem").path
            let leafP12Path = leafDir.appendingPathComponent("leaf.p12").path
            let extPath = leafDir.appendingPathComponent("ext.cnf").path

            // Export CA key+cert from keychain to files for openssl signing
            guard let caKeyData = exportPrivateKey(rootKey!),
                  let caCertData = exportCACertDER() else {
                throw TLSError.certCreationFailed
            }
            try caKeyData.write(to: URL(fileURLWithPath: caKeyPath))
            // Convert DER to PEM for openssl
            let pemHeader = "-----BEGIN CERTIFICATE-----\n"
            let pemFooter = "\n-----END CERTIFICATE-----\n"
            let pemBody = caCertData.base64EncodedString(options: [.lineLength76Characters, .endLineWithLineFeed])
            try (pemHeader + pemBody + pemFooter).write(toFile: caCertPath, atomically: true, encoding: .utf8)

            // SAN extension config
            let extCnf = """
            [v3_leaf]
            subjectAltName = DNS:\(hostname)
            basicConstraints = CA:FALSE
            keyUsage = digitalSignature, keyEncipherment
            extendedKeyUsage = serverAuth
            """
            try extCnf.write(toFile: extPath, atomically: true, encoding: .utf8)

            // Generate leaf key
            guard shell("/usr/bin/openssl", args: ["genrsa", "-out", leafKeyPath, "2048"]) == 0 else {
                throw TLSError.keyGenFailed("Leaf key generation failed")
            }

            // Generate CSR
            guard shell("/usr/bin/openssl", args: [
                "req", "-new", "-key", leafKeyPath, "-out", leafCSRPath,
                "-subj", "/CN=\(hostname)/O=Proxymate MITM"
            ]) == 0 else {
                throw TLSError.certCreationFailed
            }

            // Sign with CA
            guard shell("/usr/bin/openssl", args: [
                "x509", "-req", "-in", leafCSRPath, "-CA", caCertPath, "-CAkey", caKeyPath,
                "-CAcreateserial", "-out", leafCertPath, "-days", "365",
                "-extensions", "v3_leaf", "-extfile", extPath
            ]) == 0 else {
                throw TLSError.certCreationFailed
            }

            // Create PKCS12
            guard shell("/usr/bin/openssl", args: [
                "pkcs12", "-export", "-inkey", leafKeyPath, "-in", leafCertPath,
                "-certfile", caCertPath, "-out", leafP12Path, "-passout", "pass:proxymate"
            ]) == 0 else {
                throw TLSError.certCreationFailed
            }

            // Import PKCS12 to get SecIdentity
            guard let p12Data = try? Data(contentsOf: URL(fileURLWithPath: leafP12Path)) else {
                throw TLSError.certCreationFailed
            }
            var items: CFArray?
            let opts: [String: Any] = [kSecImportExportPassphrase as String: "proxymate"]
            guard SecPKCS12Import(p12Data as CFData, opts as CFDictionary, &items) == errSecSuccess,
                  let arr = items as? [[String: Any]],
                  let identityRef = arr.first?[kSecImportItemIdentity as String] else {
                throw TLSError.identityNotFound
            }

            let identity = identityRef as! SecIdentity
            leafCache[hostname] = identity
            return identity
        }
    }

    /// Export private key as PEM string for openssl.
    private func exportPrivateKey(_ key: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else { return nil }
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n" +
                  data.base64EncodedString(options: [.lineLength76Characters, .endLineWithLineFeed]) +
                  "\n-----END RSA PRIVATE KEY-----\n"
        return pem.data(using: .utf8)
    }

    /// Check if a host should be intercepted based on settings.
    func shouldIntercept(host: String, settings: MITMSettings) -> Bool {
        guard settings.enabled else { return false }
        let h = host.lowercased()

        // HSTS preload — never intercept these
        if HSTSPreload.isPreloaded(h) { return false }

        // Auto-excluded by cert pinning detection
        if (pinningFailures[h] ?? 0) >= pinningAutoExcludeThreshold { return false }

        // Check user excludes
        for pattern in settings.excludeHosts {
            if matchesWildcard(host: h, pattern: pattern.lowercased()) { return false }
        }

        // If interceptHosts is empty, intercept everything not excluded
        if settings.interceptHosts.isEmpty { return true }

        // Check explicit includes
        for pattern in settings.interceptHosts {
            if matchesWildcard(host: h, pattern: pattern.lowercased()) { return true }
        }
        return false
    }

    private func matchesWildcard(host: String, pattern: String) -> Bool {
        if pattern == host { return true }
        if pattern.hasPrefix("*.") {
            let suffix = String(pattern.dropFirst(2))
            return host == suffix || host.hasSuffix("." + suffix)
        }
        if pattern.contains("*") {
            // Simple glob: convert to regex
            let escaped = NSRegularExpression.escapedPattern(for: pattern)
                .replacingOccurrences(of: "\\*", with: ".*")
            return (try? NSRegularExpression(pattern: "^\(escaped)$"))
                .flatMap { $0.firstMatch(in: host, range: NSRange(host.startIndex..., in: host)) } != nil
        }
        return false
    }

    // MARK: - Certificate creation (using Security.framework)

    // Note: macOS Security.framework doesn't have a public Swift API for
    // creating X.509 certs directly. We use a minimal ASN.1/DER builder.
    // For production, consider using OpenSSL or a Swift ASN.1 library.
    // This implementation creates valid self-signed certs that macOS accepts.

    private func createSelfSignedCert(privateKey: SecKey, publicKey: SecKey) throws -> SecCertificate {
        let subject = "CN=\(caLabel),O=Proxymate,C=US"
        let serial = UInt64.random(in: 1...UInt64.max)
        let notBefore = Date()
        let notAfter = Calendar.current.date(byAdding: .year, value: 10, to: notBefore)!

        let der = try DERBuilder.buildSelfSignedCACert(
            subject: subject,
            serial: serial,
            notBefore: notBefore,
            notAfter: notAfter,
            publicKey: publicKey,
            privateKey: privateKey
        )

        guard let cert = SecCertificateCreateWithData(nil, der as CFData) else {
            throw TLSError.certCreationFailed
        }
        return cert
    }

    private func createLeafCert(hostname: String,
                                 leafPrivateKey: SecKey,
                                 leafPublicKey: SecKey,
                                 caKey: SecKey,
                                 caCert: SecCertificate) throws -> SecCertificate {
        let subject = "CN=\(hostname),O=Proxymate MITM"
        let serial = UInt64.random(in: 1...UInt64.max)
        let notBefore = Date()
        let notAfter = Calendar.current.date(byAdding: .year, value: 1, to: notBefore)!

        let der = try DERBuilder.buildLeafCert(
            subject: subject,
            san: hostname,
            serial: serial,
            notBefore: notBefore,
            notAfter: notAfter,
            publicKey: leafPublicKey,
            signingKey: caKey
        )

        guard let cert = SecCertificateCreateWithData(nil, der as CFData) else {
            throw TLSError.certCreationFailed
        }
        return cert
    }

    private func createIdentity(privateKey: SecKey, cert: SecCertificate) throws -> SecIdentity {
        // Add cert and key to keychain temporarily
        let certLabel = "Proxymate Leaf \(UUID().uuidString)"

        let addCert: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: cert,
            kSecAttrLabel as String: certLabel,
        ]
        SecItemAdd(addCert as CFDictionary, nil)

        let addKey: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: privateKey,
            kSecAttrLabel as String: certLabel,
        ]
        SecItemAdd(addKey as CFDictionary, nil)

        // Query for identity
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: certLabel,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let identity = item else {
            throw TLSError.identityNotFound
        }
        return (identity as! SecIdentity)
    }

    private func loadCAFromKeychain() {
        if rootKey != nil && rootCert != nil { return }

        // Load private key
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: caLabel,
            kSecAttrApplicationTag as String: caTag.data(using: .utf8)!,
            kSecReturnRef as String: true,
        ]
        var keyItem: CFTypeRef?
        if SecItemCopyMatching(keyQuery as CFDictionary, &keyItem) == errSecSuccess {
            rootKey = (keyItem as! SecKey)
        }

        // Load certificate
        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: caLabel,
            kSecReturnRef as String: true,
        ]
        var certItem: CFTypeRef?
        if SecItemCopyMatching(certQuery as CFDictionary, &certItem) == errSecSuccess {
            rootCert = (certItem as! SecCertificate)
        }
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
            case .identityNotFound: return "Identity not found in Keychain"
            }
        }
    }
}

// MARK: - Minimal DER/ASN.1 builder for X.509 certificates

// This is a minimal implementation sufficient for generating valid self-signed
// CA certs and leaf certs with SAN extensions. For a production app, consider
// using a full ASN.1 library.

import AppKit

nonisolated enum DERBuilder {

    // MARK: Tags
    private static let tagSequence:    UInt8 = 0x30
    private static let tagSet:         UInt8 = 0x31
    private static let tagInteger:     UInt8 = 0x02
    private static let tagBitString:   UInt8 = 0x03
    private static let tagOctetString: UInt8 = 0x04
    private static let tagNull:        UInt8 = 0x05
    private static let tagOID:         UInt8 = 0x06
    private static let tagUTF8String:  UInt8 = 0x0C
    private static let tagPrintableStr:UInt8 = 0x13
    private static let tagUTCTime:     UInt8 = 0x17
    private static let tagGenTime:     UInt8 = 0x18

    // OIDs
    private static let oidSHA256RSA: [UInt8]  = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
    private static let oidRSAEncryption: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    private static let oidCommonName: [UInt8] = [0x55, 0x04, 0x03]
    private static let oidOrganization: [UInt8] = [0x55, 0x04, 0x0A]
    private static let oidCountry: [UInt8]    = [0x55, 0x04, 0x06]
    private static let oidBasicConstraints: [UInt8] = [0x55, 0x1D, 0x13]
    private static let oidSubjectAltName: [UInt8] = [0x55, 0x1D, 0x11]

    // MARK: Public builders

    static func buildSelfSignedCACert(subject: String,
                                       serial: UInt64,
                                       notBefore: Date,
                                       notAfter: Date,
                                       publicKey: SecKey,
                                       privateKey: SecKey) throws -> Data {
        let tbsCert = try buildTBSCertificate(
            serial: serial,
            issuer: subject,
            subject: subject,
            notBefore: notBefore,
            notAfter: notAfter,
            publicKey: publicKey,
            isCA: true,
            san: nil
        )
        return try signCertificate(tbsCert: tbsCert, signingKey: privateKey)
    }

    static func buildLeafCert(subject: String,
                               san: String,
                               serial: UInt64,
                               notBefore: Date,
                               notAfter: Date,
                               publicKey: SecKey,
                               signingKey: SecKey) throws -> Data {
        let tbsCert = try buildTBSCertificate(
            serial: serial,
            issuer: "CN=Proxymate Root CA,O=Proxymate,C=US",
            subject: subject,
            notBefore: notBefore,
            notAfter: notAfter,
            publicKey: publicKey,
            isCA: false,
            san: san
        )
        return try signCertificate(tbsCert: tbsCert, signingKey: signingKey)
    }

    // MARK: TBS Certificate

    private static func buildTBSCertificate(serial: UInt64,
                                             issuer: String,
                                             subject: String,
                                             notBefore: Date,
                                             notAfter: Date,
                                             publicKey: SecKey,
                                             isCA: Bool,
                                             san: String?) throws -> Data {
        var elements: [Data] = []

        // Version (v3 = 2)
        elements.append(explicit(tag: 0, content: derInteger(Data([0x02]))))

        // Serial number
        elements.append(derInteger(bigEndianBytes(serial)))

        // Signature algorithm (sha256WithRSAEncryption)
        elements.append(derSequence([derOID(oidSHA256RSA), derNull()]))

        // Issuer
        elements.append(buildName(issuer))

        // Validity
        elements.append(derSequence([derUTCTime(notBefore), derUTCTime(notAfter)]))

        // Subject
        elements.append(buildName(subject))

        // Subject Public Key Info
        guard let pubKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw TLSManager.TLSError.keyGenFailed("Cannot export public key")
        }
        let spki = derSequence([
            derSequence([derOID(oidRSAEncryption), derNull()]),
            derBitString(pubKeyData)
        ])
        elements.append(spki)

        // Extensions
        var extensions: [Data] = []
        if isCA {
            // BasicConstraints: CA=TRUE
            let bc = derSequence([
                derOID(oidBasicConstraints),
                Data([0x01, 0x01, 0xFF]),  // critical = TRUE
                derOctetString(derSequence([Data([0x01, 0x01, 0xFF])]))  // CA=TRUE
            ])
            extensions.append(bc)
        }
        if let san {
            // SubjectAltName: dNSName
            let dnsName = Data([0x82]) + derLength(san.utf8.count) + Data(san.utf8)
            let sanExt = derSequence([
                derOID(oidSubjectAltName),
                derOctetString(derSequence([dnsName]))
            ])
            extensions.append(sanExt)
        }
        if !extensions.isEmpty {
            elements.append(explicit(tag: 3, content: derSequence(extensions)))
        }

        return derSequence(elements)
    }

    private static func signCertificate(tbsCert: Data, signingKey: SecKey) throws -> Data {
        // Sign with SHA-256 + RSA
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            signingKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            tbsCert as CFData,
            &error
        ) as Data? else {
            throw TLSManager.TLSError.certCreationFailed
        }

        return derSequence([
            tbsCert,
            derSequence([derOID(oidSHA256RSA), derNull()]),
            derBitString(signature)
        ])
    }

    // MARK: Name building

    private static func buildName(_ dn: String) -> Data {
        // Parse simple "CN=x,O=y,C=z" format
        var rdnSequences: [Data] = []
        for component in dn.split(separator: ",") {
            let kv = component.trimmingCharacters(in: .whitespaces)
            let parts = kv.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces).uppercased()
            let value = parts[1].trimmingCharacters(in: .whitespaces)

            let oid: [UInt8]
            switch key {
            case "CN": oid = oidCommonName
            case "O":  oid = oidOrganization
            case "C":  oid = oidCountry
            default: continue
            }

            let atv = derSequence([derOID(oid), derPrintableString(value)])
            rdnSequences.append(derSet([atv]))
        }
        return derSequence(rdnSequences)
    }

    // MARK: DER primitives

    private static func derLength(_ length: Int) -> Data {
        if length < 0x80 { return Data([UInt8(length)]) }
        let bytes = bigEndianBytes(UInt64(length)).drop(while: { $0 == 0 })
        return Data([0x80 | UInt8(bytes.count)]) + bytes
    }

    private static func derTLV(tag: UInt8, content: Data) -> Data {
        Data([tag]) + derLength(content.count) + content
    }

    private static func derSequence(_ items: [Data]) -> Data {
        let content = items.reduce(Data(), +)
        return derTLV(tag: tagSequence, content: content)
    }

    private static func derSet(_ items: [Data]) -> Data {
        let content = items.reduce(Data(), +)
        return derTLV(tag: tagSet, content: content)
    }

    private static func derInteger(_ bytes: Data) -> Data {
        // Ensure positive by prepending 0x00 if high bit set
        var b = bytes
        if let first = b.first, first & 0x80 != 0 {
            b.insert(0x00, at: 0)
        }
        return derTLV(tag: tagInteger, content: b)
    }

    private static func derBitString(_ data: Data) -> Data {
        // Prepend unused-bits byte (0)
        return derTLV(tag: tagBitString, content: Data([0x00]) + data)
    }

    private static func derOctetString(_ data: Data) -> Data {
        derTLV(tag: tagOctetString, content: data)
    }

    private static func derNull() -> Data {
        Data([tagNull, 0x00])
    }

    private static func derOID(_ oid: [UInt8]) -> Data {
        derTLV(tag: tagOID, content: Data(oid))
    }

    private static func derPrintableString(_ s: String) -> Data {
        derTLV(tag: tagPrintableStr, content: Data(s.utf8))
    }

    private static func derUTCTime(_ date: Date) -> Data {
        let f = DateFormatter()
        f.dateFormat = "yyMMddHHmmss'Z'"
        f.timeZone = TimeZone(abbreviation: "UTC")
        f.locale = Locale(identifier: "en_US_POSIX")
        return derTLV(tag: tagUTCTime, content: Data(f.string(from: date).utf8))
    }

    private static func explicit(tag: UInt8, content: Data) -> Data {
        derTLV(tag: 0xA0 | tag, content: content)
    }

    private static func bigEndianBytes(_ value: UInt64) -> Data {
        var v = value.bigEndian
        return Data(bytes: &v, count: 8)
    }
}
