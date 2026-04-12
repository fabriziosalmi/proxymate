//
//  FeatureExtractor.swift
//  proxymate
//
//  Deterministic feature extraction from HTTP request/response metadata.
//  These features feed into the threat scoring pipeline and future ML
//  classifiers. All computation is pure math — no ML, no randomness.
//
//  Features extracted per-request:
//  - URL entropy (randomness of path/query — high = tracking/generated)
//  - Subdomain depth (a.b.c.example.com = 3)
//  - Payload asymmetry (request vs response size ratio)
//  - Header fingerprint hash
//  - Request timing (interval from last request to same host)
//

import Foundation

nonisolated enum FeatureExtractor {

    struct RequestFeatures: Sendable {
        let host: String
        let urlEntropy: Double          // 0.0 = simple, 5.0+ = random/tracking
        let pathLength: Int
        let queryParamCount: Int
        let subdomainDepth: Int         // example.com = 0, a.example.com = 1
        let headerCount: Int
        let fingerprintHash: String
        let contentLength: Int          // request body size
        let timestamp: Date
    }

    struct ResponseFeatures: Sendable {
        let statusCode: Int
        let contentLength: Int          // response body size
        let latencyMs: Double
        let contentType: String
        let hasSetCookie: Bool
    }

    struct CombinedFeatures: Sendable {
        let request: RequestFeatures
        let response: ResponseFeatures?
        let payloadAsymmetry: Double    // request_size / response_size (high = exfil)
        let isBeaconLike: Bool          // small req, small resp, no user content
        let isExfilLike: Bool           // large req, small resp
        let threatScore: Double         // 0.0 = safe, 1.0 = malicious
    }

    // MARK: - Extract request features

    static func extractRequest(host: String, target: String, headers: String,
                                bodySize: Int) -> RequestFeatures {
        let pathQuery = target.components(separatedBy: "?")
        let path = pathQuery.first ?? ""
        let query = pathQuery.count > 1 ? pathQuery[1] : ""

        let queryParams = query.isEmpty ? 0 : query.components(separatedBy: "&").count

        // Subdomain depth: a.b.c.example.com → 3
        let hostParts = host.split(separator: ".")
        let subdomainDepth = max(0, hostParts.count - 2)

        // URL entropy (Shannon entropy of path + query)
        let urlStr = path + query
        let entropy = shannonEntropy(urlStr)

        // Header fingerprint
        let fp = RequestFingerprint.compute(headers)

        // Header count
        let headerCount = headers.split(separator: "\r\n").count - 1

        return RequestFeatures(
            host: host.lowercased(),
            urlEntropy: entropy,
            pathLength: path.count,
            queryParamCount: queryParams,
            subdomainDepth: subdomainDepth,
            headerCount: headerCount,
            fingerprintHash: fp.hash,
            contentLength: bodySize,
            timestamp: Date()
        )
    }

    // MARK: - Extract response features

    static func extractResponse(statusCode: Int, headers: String,
                                 bodySize: Int, latencyMs: Double) -> ResponseFeatures {
        let lower = headers.lowercased()
        let contentType = extractHeaderValue(lower, name: "content-type") ?? ""
        let hasSetCookie = lower.contains("set-cookie:")

        return ResponseFeatures(
            statusCode: statusCode,
            contentLength: bodySize,
            latencyMs: latencyMs,
            contentType: contentType,
            hasSetCookie: hasSetCookie
        )
    }

    // MARK: - Combine + score

    static func combine(request: RequestFeatures,
                          response: ResponseFeatures?) -> CombinedFeatures {
        let respSize = response?.contentLength ?? 0
        let reqSize = max(request.contentLength, 1)

        // Payload asymmetry: reqSize / respSize
        // High = sending more than receiving = potential exfiltration
        let asymmetry = respSize > 0 ? Double(reqSize) / Double(respSize) : Double(reqSize)

        // Beacon detection: small request (<500B), small response (<500B)
        let isBeacon = reqSize < 500 && respSize < 500 && respSize > 0

        // Exfiltration: large request (>1KB), small response (<500B)
        let isExfil = reqSize > 1024 && respSize < 500

        // Threat score: weighted combination of signals
        var score = 0.0

        // URL entropy > 3.5 is suspicious (tracking URLs are high entropy)
        if request.urlEntropy > 4.0 { score += 0.3 }
        else if request.urlEntropy > 3.5 { score += 0.15 }

        // Deep subdomain = tracking infra (a.b.c.tracker.com)
        if request.subdomainDepth >= 3 { score += 0.2 }
        else if request.subdomainDepth >= 2 { score += 0.1 }

        // Many query params = tracking beacon
        if request.queryParamCount >= 5 { score += 0.15 }

        // Payload asymmetry
        if isExfil { score += 0.25 }
        if isBeacon { score += 0.1 }

        // Few headers = bot/script
        if request.headerCount <= 3 { score += 0.1 }

        // Response has Set-Cookie = tracking
        if response?.hasSetCookie ?? false { score += 0.05 }

        // Very long path = generated URL
        if request.pathLength > 100 { score += 0.1 }

        return CombinedFeatures(
            request: request,
            response: response,
            payloadAsymmetry: asymmetry,
            isBeaconLike: isBeacon,
            isExfilLike: isExfil,
            threatScore: min(score, 1.0)
        )
    }

    // MARK: - Shannon Entropy

    /// Shannon entropy of a string. Higher = more random.
    /// "aaaaaa" → 0.0, "/collect?v=2&tid=UA-123&..." → ~4.0
    static func shannonEntropy(_ s: String) -> Double {
        guard !s.isEmpty else { return 0 }
        var freq: [Character: Int] = [:]
        for c in s { freq[c, default: 0] += 1 }
        let len = Double(s.count)
        var entropy = 0.0
        for (_, count) in freq {
            let p = Double(count) / len
            if p > 0 { entropy -= p * log2(p) }
        }
        return entropy
    }

    // MARK: - Helpers

    private static func extractHeaderValue(_ headers: String, name: String) -> String? {
        for line in headers.split(separator: "\r\n") {
            let l = line.lowercased()
            if l.hasPrefix(name + ":") {
                return String(line.dropFirst(name.count + 1)).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }
}
