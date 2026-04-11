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

nonisolated struct WAFRule: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var name: String
    var kind: Kind
    var pattern: String
    var enabled: Bool = true
    var category: String = "Custom"

    enum Kind: String, Codable, CaseIterable, Identifiable, Sendable {
        case allowDomain     = "Allow Domain"
        case blockIP         = "Block IP"
        case blockDomain     = "Block Domain"
        case blockContent    = "Block Content"
        case blockRegex      = "Block Regex"
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
        // Tracking & Ads
        .init(name: "Google Analytics",  kind: .blockDomain, pattern: "google-analytics.com",   category: "Tracking"),
        .init(name: "Google Tag Manager",kind: .blockDomain, pattern: "googletagmanager.com",   category: "Tracking"),
        .init(name: "Facebook Pixel",    kind: .blockDomain, pattern: "connect.facebook.net",   category: "Tracking"),
        .init(name: "DoubleClick",       kind: .blockDomain, pattern: "doubleclick.net",        category: "Ads"),
        .init(name: "Coinhive",          kind: .blockDomain, pattern: "coinhive.com",           category: "Crypto Miners"),
        // SQL Injection (outbound — detect in URLs and POST bodies)
        .init(name: "SQL Union Select",  kind: .blockRegex, pattern: #"(?i)union\s+(all\s+)?select"#, enabled: false, category: "SQLi"),
        .init(name: "SQL OR 1=1",        kind: .blockRegex, pattern: #"(?i)('\s*or\s+'?\d+'?\s*=\s*'?\d+|"\s*or\s+"?\d+"?\s*=\s*"?\d+)"#, enabled: false, category: "SQLi"),
        .init(name: "SQL Comment",       kind: .blockRegex, pattern: #"(?i)(--\s|/\*|\*/|;--)"#, enabled: false, category: "SQLi"),
        // XSS
        .init(name: "XSS Script Tag",   kind: .blockRegex, pattern: #"(?i)<script[\s>]"#, enabled: false, category: "XSS"),
        .init(name: "XSS Event Handler", kind: .blockRegex, pattern: #"(?i)\s+on\w+\s*=\s*[\"']"#, enabled: false, category: "XSS"),
        .init(name: "XSS Javascript URI",kind: .blockRegex, pattern: #"(?i)javascript\s*:"#, enabled: false, category: "XSS"),
        // Path Traversal
        .init(name: "Path Traversal",    kind: .blockRegex, pattern: #"\.\.[/\\]"#, enabled: false, category: "Traversal"),
        .init(name: "Null Byte",         kind: .blockRegex, pattern: #"%00"#, enabled: false, category: "Traversal"),
        // Command Injection
        .init(name: "Shell Command",     kind: .blockRegex, pattern: #"(?i);\s*(cat|ls|wget|curl|nc|bash|sh|python|perl)\s"#, enabled: false, category: "CmdInject"),
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

    static let trackingCookiePrefixes: [String] = [
        "_ga", "_gid", "_gat", "_gcl", "__utm",
        "_fbp", "_fbc", "fr",
        "_pin_unauth",
        "_tt_",
        "_uet",
    ]
}

// MARK: - Blacklist Sources

nonisolated struct BlacklistSource: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var name: String
    var url: String
    var category: BlacklistCategory
    var format: ListFormat
    var enabled: Bool = true
    var lastUpdated: Date?
    var entryCount: Int = 0

    enum BlacklistCategory: String, Codable, CaseIterable, Identifiable, Sendable {
        case torExits    = "TOR Exits"
        case ads         = "Ads & Tracking"
        case malware     = "Malware & C2"
        case phishing    = "Phishing"
        case cryptoMiner = "Crypto Miners"
        case telemetry   = "Telemetry"
        case adult       = "Adult Content"
        case custom      = "Custom"
        var id: String { rawValue }
    }

    enum ListFormat: String, Codable, CaseIterable, Identifiable, Sendable {
        case plainDomains = "Plain Domains"       // one domain per line
        case plainIPs     = "Plain IPs"           // one IP per line
        case hosts        = "Hosts File"          // 0.0.0.0 domain or 127.0.0.1 domain
        case adblockPlus  = "Adblock Plus"        // ||domain.com^
        var id: String { rawValue }
    }

    // MARK: - Built-in threat intelligence feeds

    static let builtIn: [BlacklistSource] = [
        // TOR
        .init(name: "TOR Exit Nodes", url: "https://check.torproject.org/torbulkexitlist",
              category: .torExits, format: .plainIPs),
        // Malware & C2
        .init(name: "URLhaus Malware", url: "https://urlhaus.abuse.ch/downloads/hostfile/",
              category: .malware, format: .hosts),
        .init(name: "ThreatFox C2/IOC", url: "https://threatfox.abuse.ch/downloads/hostfile/",
              category: .malware, format: .hosts),
        .init(name: "DShield Suspicious", url: "https://www.dshield.org/feeds/suspiciousdomains_Low.txt",
              category: .malware, format: .plainDomains),
        .init(name: "HaGeZi Threat Intel", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
              category: .malware, format: .plainDomains),
        // Phishing
        .init(name: "Phishing Army Extended", url: "https://phishing.army/download/phishing_army_blocklist_extended.txt",
              category: .phishing, format: .plainDomains),
        .init(name: "OpenPhish Community", url: "https://openphish.com/feed.txt",
              category: .phishing, format: .plainDomains),
        .init(name: "StopForumSpam Toxic", url: "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt",
              category: .phishing, format: .plainDomains),
        // Ads & Tracking
        .init(name: "Steven Black Unified", url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
              category: .ads, format: .hosts),
        .init(name: "AdGuard DNS Filter", url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
              category: .ads, format: .adblockPlus),
        .init(name: "EasyList", url: "https://easylist.to/easylist/easylist.txt",
              category: .ads, format: .adblockPlus),
        .init(name: "EasyPrivacy", url: "https://easylist.to/easylist/easyprivacy.txt",
              category: .ads, format: .adblockPlus),
        .init(name: "HaGeZi Multi PRO", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
              category: .ads, format: .plainDomains),
        // Crypto Miners
        .init(name: "NoCoin Filter", url: "https://raw.githubusercontent.com/nicehash/NoCoin/master/hosts.txt",
              category: .cryptoMiner, format: .hosts),
        // Telemetry
        .init(name: "Apple Telemetry", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.apple.txt",
              category: .telemetry, format: .plainDomains),
        .init(name: "Microsoft Telemetry", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.winoffice.txt",
              category: .telemetry, format: .plainDomains),
        .init(name: "TikTok Telemetry", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.tiktok.txt",
              category: .telemetry, format: .plainDomains),
        // Adult (opt-in for Family Safety)
        .init(name: "Steven Black Adult", url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
              category: .adult, format: .hosts),
    ]
}

// MARK: - Exfiltration Scanner

nonisolated struct ExfiltrationPack: Identifiable, Codable, Hashable, Sendable {
    let id: String
    var name: String
    var description: String
    var enabled: Bool
    var patterns: [ExfiltrationPattern]
}

nonisolated struct ExfiltrationPattern: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var name: String
    var regex: String
    var severity: Severity

    enum Severity: String, Codable, Sendable {
        case critical, high, medium
    }
}

extension ExfiltrationPack {
    static let builtIn: [ExfiltrationPack] = [
        .init(
            id: "aws-keys",
            name: "AWS Access Keys",
            description: "Detects AWS access key IDs and secret keys in outbound requests",
            enabled: true,
            patterns: [
                .init(name: "AWS Access Key ID",
                      regex: #"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)"#,
                      severity: .critical),
                .init(name: "AWS Secret Key",
                      regex: #"(?:aws_secret_access_key|secret_?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"#,
                      severity: .critical),
            ]
        ),
        .init(
            id: "github-tokens",
            name: "GitHub Tokens",
            description: "Detects GitHub PATs, fine-grained tokens, and OAuth tokens",
            enabled: true,
            patterns: [
                .init(name: "GitHub PAT (classic)",
                      regex: #"ghp_[A-Za-z0-9]{36}"#,
                      severity: .critical),
                .init(name: "GitHub PAT (fine-grained)",
                      regex: #"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"#,
                      severity: .critical),
                .init(name: "GitHub OAuth",
                      regex: #"gho_[A-Za-z0-9]{36}"#,
                      severity: .high),
            ]
        ),
        .init(
            id: "stripe-keys",
            name: "Stripe API Keys",
            description: "Detects Stripe live and restricted keys",
            enabled: true,
            patterns: [
                .init(name: "Stripe Live Secret",
                      regex: #"sk_live_[A-Za-z0-9]{24,}"#,
                      severity: .critical),
                .init(name: "Stripe Restricted",
                      regex: #"rk_live_[A-Za-z0-9]{24,}"#,
                      severity: .critical),
            ]
        ),
        .init(
            id: "slack-tokens",
            name: "Slack Tokens",
            description: "Detects Slack bot, user, and webhook tokens",
            enabled: true,
            patterns: [
                .init(name: "Slack Bot Token",
                      regex: #"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}"#,
                      severity: .critical),
                .init(name: "Slack User Token",
                      regex: #"xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"#,
                      severity: .critical),
                .init(name: "Slack Webhook",
                      regex: #"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"#,
                      severity: .high),
            ]
        ),
        .init(
            id: "gcp-keys",
            name: "Google Cloud / Firebase",
            description: "Detects GCP service account keys and API keys",
            enabled: false,
            patterns: [
                .init(name: "GCP API Key",
                      regex: #"AIza[0-9A-Za-z_-]{35}"#,
                      severity: .high),
                .init(name: "GCP Service Account",
                      regex: #"\"type\"\s*:\s*\"service_account\""#,
                      severity: .critical),
            ]
        ),
        .init(
            id: "generic-secrets",
            name: "Generic Secrets",
            description: "Detects common secret patterns (API keys, passwords in URLs, private keys)",
            enabled: false,
            patterns: [
                .init(name: "Private Key Header",
                      regex: #"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"#,
                      severity: .critical),
                .init(name: "Password in URL",
                      regex: #"[a-z]+://[^:]+:[^@]{3,}@[a-z0-9]"#,
                      severity: .high),
                .init(name: "Generic API Key Assignment",
                      regex: #"(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"#,
                      severity: .medium),
                .init(name: "Bearer Token (long)",
                      regex: #"[Bb]earer\s+[A-Za-z0-9_\-.]{40,}"#,
                      severity: .medium),
            ]
        ),
        .init(
            id: "pii",
            name: "PII (Personally Identifiable Info)",
            description: "Detects credit cards (Luhn), IBAN, Italian fiscal codes, and US SSN in outbound requests",
            enabled: false,
            patterns: [
                .init(name: "Credit Card (Visa/MC/Amex/Discover)",
                      regex: #"(?:^|[^0-9])([3-6]\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,4})(?:[^0-9]|$)"#,
                      severity: .critical),
                .init(name: "IBAN (EU)",
                      regex: #"[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){2,7}[A-Z0-9]{1,4}"#,
                      severity: .critical),
                .init(name: "Italian Fiscal Code (Codice Fiscale)",
                      regex: #"[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]"#,
                      severity: .high),
                .init(name: "US Social Security Number",
                      regex: #"(?:^|[^0-9])(\d{3}[-\s]?\d{2}[-\s]?\d{4})(?:[^0-9]|$)"#,
                      severity: .critical),
                .init(name: "Email Address (outbound leak)",
                      regex: #"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"#,
                      severity: .medium),
                .init(name: "Phone Number (international)",
                      regex: #"\+\d{1,3}[\s-]?\d{6,14}"#,
                      severity: .medium),
            ]
        ),
    ]
}
