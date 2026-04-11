//
//  HSTSPreload.swift
//  proxymate
//
//  HSTS preload list — domains that must never be MITM intercepted.
//  These use HTTP Strict Transport Security with preloaded pins,
//  meaning browsers will reject any certificate not matching the
//  pinned CA chain. Intercepting these WILL break the connection.
//
//  Source: condensed from Chromium HSTS preload list.
//  We include the top domains that are known to cause issues.
//

import Foundation

nonisolated enum HSTSPreload {

    /// Check if a host is in the HSTS preload list (should never be MITMed).
    static func isPreloaded(_ host: String) -> Bool {
        let h = host.lowercased()
        // Exact match
        if preloadedDomains.contains(h) { return true }
        // Parent domain match (e.g. sub.google.com → google.com)
        let parts = h.split(separator: ".")
        if parts.count > 2 {
            let parent = parts.suffix(2).joined(separator: ".")
            if preloadedDomains.contains(parent) { return true }
        }
        return false
    }

    /// Top HSTS-preloaded domains that are known to break with MITM.
    /// This is not exhaustive (the full Chromium list has ~100K entries)
    /// but covers the domains most likely to cause user-visible breakage.
    private static let preloadedDomains: Set<String> = [
        // Google
        "google.com", "gmail.com", "youtube.com", "googleapis.com",
        "google-analytics.com", "googletagmanager.com", "gstatic.com",
        "accounts.google.com", "play.google.com", "drive.google.com",
        // Apple
        "apple.com", "icloud.com", "itunes.apple.com", "appstoreconnect.apple.com",
        "developer.apple.com", "support.apple.com",
        // Microsoft
        "microsoft.com", "live.com", "outlook.com", "office.com",
        "microsoftonline.com", "azure.com", "windows.net",
        // Banking / Finance (always exclude)
        "paypal.com", "stripe.com", "braintreepayments.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com",
        "hsbc.com", "barclays.com", "revolut.com", "wise.com",
        // Social
        "facebook.com", "instagram.com", "twitter.com", "x.com",
        "linkedin.com", "reddit.com", "tiktok.com",
        // Security
        "1password.com", "bitwarden.com", "lastpass.com",
        "keybase.io", "signal.org", "protonmail.com", "proton.me",
        // Infrastructure
        "cloudflare.com", "fastly.com", "akamai.com",
        "amazonaws.com", "aws.amazon.com",
        // Dev
        "github.com", "gitlab.com", "bitbucket.org",
        "npmjs.com", "pypi.org", "rubygems.org",
        // Other pinned
        "dropbox.com", "mozilla.org", "torproject.org",
        "eff.org", "letsencrypt.org",
    ]
}
