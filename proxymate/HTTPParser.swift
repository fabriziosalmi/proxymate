//
//  HTTPParser.swift
//  proxymate
//
//  Defensive HTTP parsing utilities. Handles edge cases that the
//  simple split-based parsing in LocalProxy doesn't cover:
//  - Chunked Transfer-Encoding
//  - Keep-alive connection reuse
//  - Malformed requests (no CRLF, missing version, huge headers)
//  - 100-Continue handling
//  - Request body extraction
//

import Foundation

nonisolated enum HTTPParser {

    struct ParsedRequest {
        let method: String
        let target: String
        let version: String
        let headers: [(name: String, value: String)]
        let headerData: Data       // raw header bytes including request line
        let bodyData: Data         // everything after \r\n\r\n
        let isKeepAlive: Bool
        let contentLength: Int?
        let isChunked: Bool
        let expects100Continue: Bool
    }

    /// Parse an HTTP request from raw data. Returns nil if data is
    /// malformed beyond recovery.
    static func parse(_ data: Data) -> ParsedRequest? {
        guard let headerEnd = data.range(of: Data("\r\n\r\n".utf8)) else {
            // Try LF-only (some broken clients)
            if let lfEnd = data.range(of: Data("\n\n".utf8)) {
                return parseWithSeparator(data, headerEnd: lfEnd, separator: "\n")
            }
            return nil
        }
        return parseWithSeparator(data, headerEnd: headerEnd, separator: "\r\n")
    }

    private static func parseWithSeparator(_ data: Data, headerEnd: Range<Data.Index>,
                                            separator: String) -> ParsedRequest? {
        let headerData = data.subdata(in: 0..<headerEnd.upperBound)
        let bodyData = data.subdata(in: headerEnd.upperBound..<data.count)

        guard let headerStr = String(data: data.subdata(in: 0..<headerEnd.lowerBound),
                                      encoding: .utf8) else { return nil }

        let lines = headerStr.components(separatedBy: separator)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        guard let firstLine = lines.first else { return nil }
        let parts = firstLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2 else { return nil }

        let method = String(parts[0]).uppercased()
        let target = String(parts[1])
        let version = parts.count > 2 ? String(parts[2]) : "HTTP/1.0"

        var headers: [(String, String)] = []
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            headers.append((name, value))
        }

        let connectionHeader = headers.first { $0.0.lowercased() == "connection" }?.1.lowercased() ?? ""
        let isKeepAlive: Bool
        if version.contains("1.1") {
            isKeepAlive = connectionHeader != "close"
        } else {
            isKeepAlive = connectionHeader == "keep-alive"
        }

        let contentLength = headers.first { $0.0.lowercased() == "content-length" }
            .flatMap { Int($0.1) }

        let transferEncoding = headers.first { $0.0.lowercased() == "transfer-encoding" }?.1.lowercased() ?? ""
        let isChunked = transferEncoding.contains("chunked")

        let expect = headers.first { $0.0.lowercased() == "expect" }?.1.lowercased() ?? ""
        let expects100 = expect.contains("100-continue")

        return ParsedRequest(
            method: method,
            target: target,
            version: version,
            headers: headers,
            headerData: headerData,
            bodyData: bodyData,
            isKeepAlive: isKeepAlive,
            contentLength: contentLength,
            isChunked: isChunked,
            expects100Continue: expects100
        )
    }

    // MARK: - Chunked encoding

    /// Decode chunked transfer encoding. Returns the reassembled body.
    /// The chunk size is parsed as hex and is therefore attacker-controlled
    /// up to `Int.max` — without a cap, a chunked request advertising
    /// `FFFFFFFFFFFFFFFF` traps the process at `chunkStart + chunkSize`
    /// (Swift `Int` arithmetic is checked). The 64 MB ceiling is far
    /// larger than any realistic single chunk on a proxy that fronts
    /// browser traffic, but small enough to keep arithmetic well clear
    /// of overflow even when summed with a multi-MB buffer offset.
    static func decodeChunked(_ data: Data) -> Data? {
        let maxChunkSize = 64 * 1024 * 1024
        var result = Data()
        var offset = 0

        while offset < data.count {
            // Find chunk size line
            guard let lineEnd = data.range(of: Data("\r\n".utf8),
                                            in: offset..<data.count) else { break }
            let sizeLine = data.subdata(in: offset..<lineEnd.lowerBound)
            guard let sizeStr = String(data: sizeLine, encoding: .utf8),
                  let chunkSize = Int(sizeStr.trimmingCharacters(in: .whitespaces), radix: 16),
                  chunkSize >= 0, chunkSize <= maxChunkSize
            else { break }

            if chunkSize == 0 { break }  // final chunk

            let chunkStart = lineEnd.upperBound
            let (chunkEnd, overflow) = chunkStart.addingReportingOverflow(chunkSize)
            if overflow { break }
            guard chunkEnd <= data.count else { break }

            result.append(data.subdata(in: chunkStart..<chunkEnd))
            let (next, nextOverflow) = chunkEnd.addingReportingOverflow(2)
            if nextOverflow { break }
            offset = next  // skip trailing \r\n
        }

        return result.isEmpty ? nil : result
    }

    // MARK: - 100 Continue response

    static let continueResponse = Data("HTTP/1.1 100 Continue\r\n\r\n".utf8)

    // MARK: - Header validation

    /// Check if headers are within sane limits and well-formed.
    static func validateHeaders(_ data: Data) -> Bool {
        // Max header size: 64KB
        if data.count > 65536 { return false }

        // Must contain at least one line
        guard let str = String(data: data.prefix(min(data.count, 8192)), encoding: .utf8),
              str.contains(" ") else { return false }

        // Method must be valid
        let method = String(str.prefix(while: { $0 != " " })).uppercased()
        let validMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                            "OPTIONS", "CONNECT", "TRACE"]
        guard validMethods.contains(method) else { return false }

        // Reject HTTP request smuggling: a message MUST NOT carry both a
        // Transfer-Encoding and a Content-Length header (RFC 9112 §6.1).
        // If both are present, proxy and upstream may disagree on body
        // boundary, enabling CL.TE / TE.CL attacks that bypass our WAF.
        guard let fullStr = String(data: data, encoding: .utf8) else { return true }
        var hasTE = false
        var hasCL = false
        var teCount = 0
        var clCount = 0
        for rawLine in fullStr.split(separator: "\r\n", omittingEmptySubsequences: false) {
            let line = rawLine.lowercased()
            if line.hasPrefix("transfer-encoding:") { hasTE = true; teCount += 1 }
            else if line.hasPrefix("content-length:") { hasCL = true; clCount += 1 }
        }
        // Both present → smuggling attempt
        if hasTE && hasCL { return false }
        // Duplicate TE or CL with differing values also smells like smuggling;
        // reject any duplicate since a legitimate client never sends two.
        if teCount > 1 || clCount > 1 { return false }
        return true
    }

    // MARK: - URL length check

    static let maxURLLength = 8192  // 8KB, same as Apache/Nginx default
}
