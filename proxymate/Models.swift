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

struct LogEntry: Identifiable, Hashable, Sendable {
    let id: UUID = UUID()
    let timestamp: Date
    let level: Level
    let message: String

    enum Level: String, Sendable {
        case info, warn, error
    }
}
