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
            // 1. Generate RSA 2048 key pair
            let keyParams: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: 2048,
                kSecAttrLabel as String: caLabel,
                kSecAttrApplicationTag as String: caTag.data(using: .utf8)!,
                kSecAttrIsPermanent as String: true,
            ]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(keyParams as CFDictionary, &error) else {
                throw TLSError.keyGenFailed(error?.takeRetainedValue().localizedDescription ?? "unknown")
            }
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                throw TLSError.keyGenFailed("Could not extract public key")
            }

            // 2. Create self-signed certificate
            let cert = try createSelfSignedCert(privateKey: privateKey, publicKey: publicKey)

            // 3. Store certificate in Keychain
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecValueRef as String: cert,
                kSecAttrLabel as String: caLabel,
            ]
            // Remove old cert if exists
            SecItemDelete(addQuery as CFDictionary)
            let status = SecItemAdd(addQuery as CFDictionary, nil)
            guard status == errSecSuccess || status == errSecDuplicateItem else {
                throw TLSError.keychainError(status)
            }

            self.rootKey = privateKey
            self.rootCert = cert
            self.leafCache.removeAll()

            return cert
        }
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
    func promptUserToTrust() {
        guard let certData = exportCACertDER() else { return }
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("ProxymateCA.cer")
        try? certData.write(to: tempURL)
        // Open the cert file which launches Keychain Access
        NSWorkspace.shared.open(tempURL)
    }

    // MARK: - Leaf cert forging

    /// Returns a SecIdentity (cert + private key) for the given hostname.
    /// Cached per hostname for the session.
    func identityForHost(_ hostname: String) throws -> SecIdentity {
        try queue.sync {
            if let cached = leafCache[hostname] { return cached }

            guard let caKey = rootKey, let caCert = rootCert else {
                throw TLSError.noCA
            }

            // Generate leaf key
            let leafKeyParams: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: 2048,
            ]
            var error: Unmanaged<CFError>?
            guard let leafPrivateKey = SecKeyCreateRandomKey(leafKeyParams as CFDictionary, &error) else {
                throw TLSError.keyGenFailed("Leaf key generation failed")
            }
            guard let leafPublicKey = SecKeyCopyPublicKey(leafPrivateKey) else {
                throw TLSError.keyGenFailed("Could not extract leaf public key")
            }

            // Create leaf cert signed by CA
            let leafCert = try createLeafCert(
                hostname: hostname,
                leafPrivateKey: leafPrivateKey,
                leafPublicKey: leafPublicKey,
                caKey: caKey,
                caCert: caCert
            )

            // Create identity by adding to temporary keychain
            let identity = try createIdentity(privateKey: leafPrivateKey, cert: leafCert)
            leafCache[hostname] = identity
            return identity
        }
    }

    /// Check if a host should be intercepted based on settings.
    func shouldIntercept(host: String, settings: MITMSettings) -> Bool {
        guard settings.enabled else { return false }
        let h = host.lowercased()

        // Check excludes first
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
        // swiftlint:disable:next force_cast
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
            rootKey = (keyItem as! SecKey) // swiftlint:disable:this force_cast
        }

        // Load certificate
        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: caLabel,
            kSecReturnRef as String: true,
        ]
        var certItem: CFTypeRef?
        if SecItemCopyMatching(certQuery as CFDictionary, &certItem) == errSecSuccess {
            rootCert = (certItem as! SecCertificate) // swiftlint:disable:this force_cast
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
