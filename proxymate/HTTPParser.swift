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
    static func decodeChunked(_ data: Data) -> Data? {
        var result = Data()
        var offset = 0

        while offset < data.count {
            // Find chunk size line
            guard let lineEnd = data.range(of: Data("\r\n".utf8),
                                            in: offset..<data.count) else { break }
            let sizeLine = data.subdata(in: offset..<lineEnd.lowerBound)
            guard let sizeStr = String(data: sizeLine, encoding: .utf8),
                  let chunkSize = Int(sizeStr.trimmingCharacters(in: .whitespaces), radix: 16)
            else { break }

            if chunkSize == 0 { break }  // final chunk

            let chunkStart = lineEnd.upperBound
            let chunkEnd = chunkStart + chunkSize
            guard chunkEnd <= data.count else { break }

            result.append(data.subdata(in: chunkStart..<chunkEnd))
            offset = chunkEnd + 2  // skip trailing \r\n
        }

        return result.isEmpty ? nil : result
    }

    // MARK: - 100 Continue response

    static let continueResponse = Data("HTTP/1.1 100 Continue\r\n\r\n".utf8)

    // MARK: - Header validation

    /// Check if headers are within sane limits.
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
        return validMethods.contains(method)
    }

    // MARK: - URL length check

    static let maxURLLength = 8192  // 8KB, same as Apache/Nginx default
}
