//
//  Models.swift
//  proxymate
//

import Foundation

struct ProxyConfig: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var name: String
    var host: String
    var port: Int
    var applyToHTTPS: Bool
}

struct WAFRule: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var name: String
    var kind: Kind
    var pattern: String
    var enabled: Bool = true
    var category: String = "Custom"

    enum Kind: String, Codable, CaseIterable, Identifiable, Sendable {
        case blockIP      = "Block IP"
        case blockDomain  = "Block Domain"
        case blockContent = "Block Content"
        var id: String { rawValue }
    }

    init(id: UUID = UUID(),
         name: String,
         kind: Kind,
         pattern: String,
         enabled: Bool = true,
         category: String = "Custom") {
        self.id = id
        self.name = name
        self.kind = kind
        self.pattern = pattern
        self.enabled = enabled
        self.category = category
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, kind, pattern, enabled, category
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id       = (try? c.decode(UUID.self,    forKey: .id))       ?? UUID()
        self.name     = (try? c.decode(String.self,  forKey: .name))     ?? ""
        self.kind     = try  c.decode(Kind.self,     forKey: .kind)
        self.pattern  = try  c.decode(String.self,   forKey: .pattern)
        self.enabled  = (try? c.decode(Bool.self,    forKey: .enabled))  ?? true
        self.category = (try? c.decode(String.self,  forKey: .category)) ?? "Custom"
    }

    static let examples: [WAFRule] = [
        .init(name: "Google Analytics",  kind: .blockDomain, pattern: "google-analytics.com",   category: "Tracking"),
        .init(name: "Google Tag Manager",kind: .blockDomain, pattern: "googletagmanager.com",   category: "Tracking"),
        .init(name: "Facebook Pixel",    kind: .blockDomain, pattern: "connect.facebook.net",   category: "Tracking"),
        .init(name: "DoubleClick",       kind: .blockDomain, pattern: "doubleclick.net",        category: "Ads"),
        .init(name: "Coinhive",          kind: .blockDomain, pattern: "coinhive.com",           category: "Crypto Miners"),
    ]
}

nonisolated struct LogEntry: Identifiable, Hashable, Codable, Sendable {
    let id: UUID
    let timestamp: Date
    let level: Level
    let message: String
    let host: String

    enum Level: String, Codable, Sendable {
        case info, warn, error
    }

    init(id: UUID = UUID(), timestamp: Date = Date(), level: Level, message: String, host: String = "") {
        self.id = id
        self.timestamp = timestamp
        self.level = level
        self.message = message
        self.host = host
    }
}

// MARK: - Privacy Settings

nonisolated struct PrivacySettings: Codable, Hashable, Sendable {
    var stripUserAgent: Bool = false
    var customUserAgent: String = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    var stripReferer: Bool = false
    var refererPolicy: RefererPolicy = .originOnly
    var stripTrackingCookies: Bool = false
    var forceDNT: Bool = true
    var forceGPC: Bool = true
    var stripETag: Bool = false
    var stripServerHeaders: Bool = false

    enum RefererPolicy: String, Codable, CaseIterable, Identifiable, Sendable {
        case originOnly  = "Origin Only"
        case strip       = "Strip Completely"
        var id: String { rawValue }
    }

    /// Known tracking cookie name prefixes.
    static let trackingCookiePrefixes: [String] = [
        "_ga", "_gid", "_gat", "_gcl", "__utm",     // Google
        "_fbp", "_fbc", "fr",                        // Facebook
        "_pin_unauth",                               // Pinterest
        "_tt_",                                      // TikTok
        "_uet",                                      // Bing/Microsoft
    ]
}
