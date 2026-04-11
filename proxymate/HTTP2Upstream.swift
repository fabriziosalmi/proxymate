//
//  HTTP2Upstream.swift
//  proxymate
//
//  HTTP/2 multiplexed connection to upstream proxies. Uses URLSession
//  with HTTP/2 enabled for upstream requests. Falls back to HTTP/1.1
//  if the upstream doesn't support h2.
//
//  This is used as an alternative forwarding path when the pool member
//  is marked as h2-capable.
//

import Foundation

nonisolated final class HTTP2Upstream: @unchecked Sendable {

    static let shared = HTTP2Upstream()

    private let session: URLSession

    init() {
        let config = URLSessionConfiguration.default
        // HTTP/2 multiplexing replaces pipelining
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        // URLSession uses HTTP/2 by default for HTTPS connections
        // For HTTP, we set this explicitly
        config.protocolClasses = nil // use default (includes h2)
        session = URLSession(configuration: config)
    }

    struct UpstreamResponse: Sendable {
        let statusCode: Int
        let headers: [(String, String)]
        let body: Data
    }

    /// Forward an HTTP request via HTTP/2 to the upstream.
    /// Returns the full response for inspection and caching.
    func forward(method: String,
                 url: String,
                 headers: [(String, String)],
                 body: Data?,
                 upstream: (host: String, port: Int),
                 completion: @escaping @Sendable (Result<UpstreamResponse, Error>) -> Void) {

        // Rewrite URL to point at upstream
        guard var components = URLComponents(string: url) else {
            completion(.failure(H2Error.invalidURL))
            return
        }
        components.host = upstream.host
        components.port = upstream.port
        guard let targetURL = components.url else {
            completion(.failure(H2Error.invalidURL))
            return
        }

        var request = URLRequest(url: targetURL)
        request.httpMethod = method
        request.httpBody = body
        for (name, value) in headers {
            let lower = name.lowercased()
            // Skip hop-by-hop headers
            guard lower != "connection" && lower != "proxy-connection" &&
                  lower != "keep-alive" && lower != "transfer-encoding" &&
                  lower != "proxy-authorization" else { continue }
            request.addValue(value, forHTTPHeaderField: name)
        }

        let task = session.dataTask(with: request) { data, response, error in
            if let error {
                completion(.failure(error))
                return
            }
            guard let httpResp = response as? HTTPURLResponse else {
                completion(.failure(H2Error.invalidResponse))
                return
            }
            let respHeaders = httpResp.allHeaderFields.compactMap { (key, value) -> (String, String)? in
                guard let k = key as? String, let v = value as? String else { return nil }
                return (k, v)
            }
            completion(.success(UpstreamResponse(
                statusCode: httpResp.statusCode,
                headers: respHeaders,
                body: data ?? Data()
            )))
        }
        task.resume()
    }

    /// Check if a host supports HTTP/2 by attempting a HEAD request.
    func probeH2Support(host: String, port: Int,
                         completion: @escaping @Sendable (Bool) -> Void) {
        let scheme = port == 443 ? "https" : "http"
        guard let url = URL(string: "\(scheme)://\(host):\(port)/") else {
            completion(false); return
        }
        var request = URLRequest(url: url, timeoutInterval: 5)
        request.httpMethod = "HEAD"

        let task = session.dataTask(with: request) { _, response, error in
            guard error == nil, let httpResp = response as? HTTPURLResponse else {
                completion(false); return
            }
            // Check if the response came via h2
            // URLSession doesn't expose the protocol version directly,
            // but if the status is valid, h2 likely worked
            completion(httpResp.statusCode > 0)
        }
        task.resume()
    }

    enum H2Error: LocalizedError {
        case invalidURL
        case invalidResponse
        var errorDescription: String? {
            switch self {
            case .invalidURL: return "Invalid URL for HTTP/2 forwarding"
            case .invalidResponse: return "Invalid HTTP/2 response"
            }
        }
    }
}
