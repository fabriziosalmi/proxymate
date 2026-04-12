//
//  AIAgentEnforcer.swift
//  proxymate
//
//  Detects and enforces policies on autonomous AI agent traffic:
//  Claude Code, Cursor, Windsurf, Aider, Copilot, Continue.dev, MCP.
//
//  Detection: User-Agent fingerprinting, API key patterns, JSON-RPC
//  method names (MCP), known agent hostnames.
//
//  Enforcement: per-agent allow/block/audit, MCP server allowlist,
//  outbound DLP scan on request bodies, token budget per agent.
//

import Foundation

// MARK: - Models

nonisolated struct AIAgentPolicy: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var agentId: String         // e.g. "claude-code", "cursor", "mcp"
    var name: String
    var action: Action
    var enabled: Bool = true

    enum Action: String, Codable, CaseIterable, Identifiable, Sendable {
        case allow  = "Allow"
        case audit  = "Audit Only"
        case block  = "Block"
        var id: String { rawValue }
    }
}

nonisolated struct MCPPolicy: Identifiable, Codable, Hashable, Sendable {
    var id: UUID = UUID()
    var serverPattern: String    // URL pattern for allowed MCP servers
    var allowed: Bool = true
    var note: String = ""
}

nonisolated struct AIAgentSettings: Codable, Hashable, Sendable {
    var enabled: Bool = true
    var policies: [AIAgentPolicy] = AIAgentPolicy.defaults
    var mcpPolicies: [MCPPolicy] = []
    var blockUnknownMCP: Bool = true       // block MCP to servers not in allowlist
    var scanRequestBodies: Bool = true     // DLP scan on AI request bodies
    var logFullPrompts: Bool = false        // log full prompt text (privacy concern)
}

nonisolated extension AIAgentPolicy {
    static let defaults: [AIAgentPolicy] = [
        .init(agentId: "claude-code",  name: "Claude Code",     action: .audit),
        .init(agentId: "cursor",       name: "Cursor",          action: .audit),
        .init(agentId: "windsurf",     name: "Windsurf",        action: .audit),
        .init(agentId: "aider",        name: "Aider",           action: .audit),
        .init(agentId: "copilot",      name: "GitHub Copilot",  action: .audit),
        .init(agentId: "continue",     name: "Continue.dev",    action: .audit),
        .init(agentId: "codex-cli",    name: "OpenAI Codex CLI",action: .audit),
        .init(agentId: "mcp",          name: "MCP Connections",  action: .audit),
    ]
}

// MARK: - Known agent signatures

nonisolated struct AgentSignature: Sendable {
    let id: String
    let uaPatterns: [String]        // substrings to match in User-Agent
    let headerPatterns: [(String, String)]  // (header name, value substring)
    let hostPatterns: [String]       // known API hosts
}

nonisolated enum KnownAgents {
    static let signatures: [AgentSignature] = [
        AgentSignature(
            id: "claude-code",
            uaPatterns: ["claude-code", "claude_code", "anthropic-cli"],
            headerPatterns: [("x-api-key", ""), ("anthropic-version", "")],
            hostPatterns: ["api.anthropic.com"]
        ),
        AgentSignature(
            id: "cursor",
            uaPatterns: ["cursor/", "cursor-"],
            headerPatterns: [],
            hostPatterns: ["api2.cursor.sh"]
        ),
        AgentSignature(
            id: "windsurf",
            uaPatterns: ["codeium", "windsurf"],
            headerPatterns: [],
            hostPatterns: ["api.codeium.com", "server.codeium.com"]
        ),
        AgentSignature(
            id: "aider",
            uaPatterns: ["aider/", "aider-chat"],
            headerPatterns: [],
            hostPatterns: []
        ),
        AgentSignature(
            id: "copilot",
            uaPatterns: ["github-copilot", "copilot"],
            headerPatterns: [],
            hostPatterns: ["copilot-proxy.githubusercontent.com"]
        ),
        AgentSignature(
            id: "continue",
            uaPatterns: ["continue-dev", "continue/"],
            headerPatterns: [],
            hostPatterns: []
        ),
        AgentSignature(
            id: "codex-cli",
            uaPatterns: ["codex-cli", "openai-codex"],
            headerPatterns: [],
            hostPatterns: []
        ),
    ]
}

// MARK: - Detector

nonisolated enum AIAgentEnforcer {

    struct Detection: Sendable {
        let agentId: String
        let agentName: String
        let confidence: String   // "high", "medium"
        let indicator: String
    }

    struct MCPDetection: Sendable {
        let serverURL: String
        let method: String       // e.g. "tools/call", "resources/read"
    }

    /// Detect AI agent from request headers.
    static func detectAgent(headers: String, host: String) -> Detection? {
        let lower = headers.lowercased()
        let ua = extractHeaderValue(lower, name: "user-agent") ?? ""

        for sig in KnownAgents.signatures {
            // UA match
            for pattern in sig.uaPatterns {
                if ua.contains(pattern) {
                    return Detection(agentId: sig.id,
                                     agentName: agentDisplayName(sig.id),
                                     confidence: "high",
                                     indicator: "UA: \(pattern)")
                }
            }

            // Host match
            for hostPattern in sig.hostPatterns {
                if host.lowercased() == hostPattern || host.lowercased().hasSuffix("." + hostPattern) {
                    return Detection(agentId: sig.id,
                                     agentName: agentDisplayName(sig.id),
                                     confidence: "medium",
                                     indicator: "Host: \(hostPattern)")
                }
            }

            // Header match
            for (name, value) in sig.headerPatterns {
                if lower.contains(name + ":") {
                    if value.isEmpty || lower.contains(value) {
                        return Detection(agentId: sig.id,
                                         agentName: agentDisplayName(sig.id),
                                         confidence: "medium",
                                         indicator: "Header: \(name)")
                    }
                }
            }
        }

        return nil
    }

    /// Detect MCP JSON-RPC traffic from request body.
    static func detectMCP(body: Data, host: String) -> MCPDetection? {
        guard let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let method = json["method"] as? String else { return nil }

        let mcpMethods = ["tools/list", "tools/call", "resources/list",
                          "resources/read", "prompts/list", "prompts/get",
                          "initialize", "notifications/initialized"]
        guard mcpMethods.contains(method) || method.hasPrefix("notifications/") else { return nil }

        return MCPDetection(serverURL: host, method: method)
    }

    /// Check if an MCP server is allowed by policy.
    static func isMCPAllowed(serverHost: String, policies: [MCPPolicy],
                              blockUnknown: Bool) -> (allowed: Bool, reason: String?) {
        for policy in policies {
            let p = policy.serverPattern.lowercased()
            let h = serverHost.lowercased()
            if h == p || h.contains(p) || (p.hasPrefix("*") && h.hasSuffix(String(p.dropFirst()))) {
                return policy.allowed
                    ? (true, nil)
                    : (false, "MCP server '\(serverHost)' blocked by policy")
            }
        }
        if blockUnknown {
            return (false, "MCP server '\(serverHost)' not in allowlist")
        }
        return (true, nil)
    }

    /// Get the enforcement action for a detected agent.
    static func getAction(agentId: String, settings: AIAgentSettings) -> AIAgentPolicy.Action {
        if let policy = settings.policies.first(where: { $0.agentId == agentId && $0.enabled }) {
            return policy.action
        }
        return .audit
    }

    // MARK: - Helpers

    private static func agentDisplayName(_ id: String) -> String {
        AIAgentPolicy.defaults.first { $0.agentId == id }?.name ?? id
    }

    private static func extractHeaderValue(_ headers: String, name: String) -> String? {
        for line in headers.split(separator: "\r\n", omittingEmptySubsequences: false) {
            let l = line.lowercased()
            if l.hasPrefix(name + ":") {
                return String(line.dropFirst(name.count + 1)).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }
}
