//
//  Localization.swift
//  proxymate
//
//  Centralized user-visible strings. Ready for .xcstrings extraction.
//  Currently English-only; Italian translation prepared as comments
//  for when we add proper .xcstrings localization.
//
//  Usage: Strings.proxyEnabled → "Proxy Enabled"
//  Future: NSLocalizedString wrapper with .xcstrings auto-export.
//

import Foundation

nonisolated enum Strings {
    // MARK: - General
    static let appName = "Proxymate"
    static let enabled = "Enabled"       // IT: "Attivo"
    static let disabled = "Disabled"     // IT: "Disattivo"
    static let cancel = "Cancel"         // IT: "Annulla"
    static let add = "Add"              // IT: "Aggiungi"
    static let delete = "Delete"        // IT: "Elimina"
    static let save = "Save"            // IT: "Salva"
    static let quit = "Quit"            // IT: "Esci"
    static let on = "On"               // IT: "Attivo"
    static let off = "Off"             // IT: "Spento"

    // MARK: - Tabs
    static let proxies = "Proxies"      // IT: "Proxy"
    static let logs = "Logs"           // IT: "Log"
    static let stats = "Stats"         // IT: "Statistiche"
    static let rules = "Rules"         // IT: "Regole"
    static let ai = "AI"              // IT: "IA"
    static let cache = "Cache"         // IT: "Cache"
    static let privacy = "Privacy"     // IT: "Privacy"

    // MARK: - Onboarding
    static let welcome = "Welcome to Proxymate"  // IT: "Benvenuto in Proxymate"
    static let chooseProfile = "Choose a profile to get started."
        // IT: "Scegli un profilo per iniziare."
    static let startProxying = "Start Proxying"
        // IT: "Inizia"
    static let next = "Next"           // IT: "Avanti"
    static let back = "Back"           // IT: "Indietro"
    static let ready = "Ready to Go"   // IT: "Tutto Pronto"

    // MARK: - Profiles
    static let profilePrivacy = "Privacy"
        // IT: "Privacy"
    static let profileDeveloper = "Developer"
        // IT: "Sviluppatore"
    static let profileEnterprise = "Enterprise"
        // IT: "Aziendale"
    static let profileFamily = "Family Safety"
        // IT: "Sicurezza Famiglia"
    static let profileMinimal = "Minimal"
        // IT: "Minimo"

    // MARK: - Stats
    static let allowed = "Allowed"     // IT: "Consentite"
    static let blocked = "Blocked"     // IT: "Bloccate"
    static let status = "Status"       // IT: "Stato"
    static let activeSince = "Active Since"
        // IT: "Attivo da"
    static let cacheHitRate = "Cache Hit Rate"
        // IT: "Hit Rate Cache"
    static let logEntries = "Log Entries"
        // IT: "Voci di Log"

    // MARK: - Privacy
    static let dntHeader = "Send Do Not Track (DNT: 1)"
        // IT: "Invia Do Not Track (DNT: 1)"
    static let gpcHeader = "Send Global Privacy Control (Sec-GPC: 1)"
        // IT: "Invia Global Privacy Control (Sec-GPC: 1)"
    static let stripUA = "Replace User-Agent"
        // IT: "Sostituisci User-Agent"
    static let stripReferer = "Strip/reduce Referer"
        // IT: "Rimuovi/riduci Referer"
    static let stripCookies = "Strip tracking cookies (_ga, _fbp, etc.)"
        // IT: "Rimuovi cookie di tracciamento (_ga, _fbp, ecc.)"
    static let stripETag = "Strip ETag / If-None-Match (anti-supercookie)"
        // IT: "Rimuovi ETag / If-None-Match (anti-supercookie)"

    // MARK: - AI
    static let today = "Today"         // IT: "Oggi"
    static let thisMonth = "This Month"
        // IT: "Questo Mese"
    static let session = "Session"     // IT: "Sessione"
    static let providers = "Providers" // IT: "Provider"
    static let budgetCaps = "Budget Caps"
        // IT: "Limiti di Budget"
    static let loopBreaker = "Loop Breaker"
        // IT: "Interruttore Loop"
    static let resetStats = "Reset Stats"
        // IT: "Azzera Statistiche"

    // MARK: - About
    static let madeBy = "Made with care by Fabrizio Salmi"
        // IT: "Fatto con cura da Fabrizio Salmi"
    static let zeroTelemetry = "Zero telemetry. Zero cloud. Zero login. Free forever."
        // IT: "Zero telemetria. Zero cloud. Zero login. Gratis per sempre."
    static let runWizardAgain = "Run Setup Wizard Again"
        // IT: "Esegui di Nuovo la Configurazione"

    // MARK: - Notifications
    static let blockedNotifTitle = "Proxymate Blocked"
        // IT: "Proxymate Ha Bloccato"
    static let exfilNotifTitle = "Exfiltration Blocked"
        // IT: "Esfiltrazione Bloccata"
    static let budgetNotifTitle = "AI Budget Exceeded"
        // IT: "Budget IA Superato"
}
