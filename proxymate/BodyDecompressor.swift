//
//  BodyDecompressor.swift
//  proxymate
//
//  Decompresses HTTP response bodies for WAF content inspection.
//  Supports gzip, deflate, and zlib (br requires third-party lib — skipped).
//  Uses Apple's Compression framework (zero dependencies).
//
//  Usage:
//    let (decompressed, wasCompressed) = BodyDecompressor.decompress(body, encoding: "gzip")
//    // inspect decompressed body with WAF rules
//    // forward original compressed body to client (no re-compression needed)
//

import Foundation
import Compression

nonisolated enum BodyDecompressor {

    /// Decompress a response body based on Content-Encoding header value.
    /// Returns (decompressed data, true) if decompression succeeded,
    /// or (original data, false) if encoding is unsupported or decompression failed.
    static func decompress(_ data: Data, encoding: String) -> (Data, Bool) {
        let enc = encoding.lowercased().trimmingCharacters(in: .whitespaces)

        switch enc {
        case "gzip", "x-gzip":
            // gzip = deflate + gzip header. Compression framework handles raw deflate,
            // so we strip the gzip header/trailer first.
            if let stripped = stripGzipHeader(data) {
                return decompressRaw(stripped, algorithm: COMPRESSION_ZLIB)
            }
            return (data, false)

        case "deflate":
            // RFC 7230: "deflate" can be raw deflate or zlib-wrapped.
            // Try zlib-wrapped first; if that fails, try stripping the 2-byte zlib header
            // and decompressing the raw deflate stream.
            let (result, ok) = decompressRaw(data, algorithm: COMPRESSION_ZLIB)
            if ok { return (result, true) }
            // Strip 2-byte zlib header (0x78 ...) and 4-byte Adler-32 trailer, then retry.
            if data.count > 6 {
                let raw = data[2..<(data.count - 4)]
                let (result2, ok2) = decompressRaw(raw, algorithm: COMPRESSION_ZLIB)
                if ok2 { return (result2, true) }
            }
            return (data, false)

        case "identity", "":
            return (data, false) // not compressed

        default:
            // br (Brotli) not supported by Compression.framework
            return (data, false)
        }
    }

    /// Extract Content-Encoding from raw response headers string.
    static func extractContentEncoding(_ headers: String) -> String? {
        for line in headers.split(separator: "\r\n") {
            let lower = line.lowercased()
            if lower.hasPrefix("content-encoding:") {
                return String(line.dropFirst("content-encoding:".count))
                    .trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    // MARK: - Internal

    /// Decompress using Compression framework's buffer API.
    private static func decompressRaw(_ data: Data, algorithm: compression_algorithm) -> (Data, Bool) {
        guard !data.isEmpty else { return (data, false) }

        // Start with 4x input size, grow if needed
        var dstSize = data.count * 4
        let maxSize = 20 * 1024 * 1024 // 20 MB cap to prevent zip bombs

        while dstSize <= maxSize {
            var dst = [UInt8](repeating: 0, count: dstSize)
            let result = data.withUnsafeBytes { srcBuf -> Int in
                guard let src = srcBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
                return compression_decode_buffer(&dst, dstSize, src, data.count, nil, algorithm)
            }

            if result == 0 {
                // Decompression failed
                return (data, false)
            }

            if result < dstSize {
                // Success — output fit in buffer
                return (Data(dst[0..<result]), true)
            }

            // Output buffer was too small, try larger
            dstSize *= 2
        }

        // Exceeded max size — likely a zip bomb, return original
        return (data, false)
    }

    /// Strip gzip header (RFC 1952) to get raw deflate data for Compression framework.
    private static func stripGzipHeader(_ data: Data) -> Data? {
        guard data.count >= 10 else { return nil }
        // Magic: 0x1f 0x8b
        guard data[0] == 0x1F, data[1] == 0x8B else { return nil }
        // Method: 8 = deflate
        guard data[2] == 8 else { return nil }

        let flags = data[3]
        var offset = 10

        // FEXTRA
        if flags & 0x04 != 0 {
            guard data.count > offset + 2 else { return nil }
            let xlen = Int(data[offset]) | (Int(data[offset + 1]) << 8)
            offset += 2 + xlen
        }

        // FNAME
        if flags & 0x08 != 0 {
            while offset < data.count && data[offset] != 0 { offset += 1 }
            offset += 1 // skip null terminator
        }

        // FCOMMENT
        if flags & 0x10 != 0 {
            while offset < data.count && data[offset] != 0 { offset += 1 }
            offset += 1
        }

        // FHCRC
        if flags & 0x02 != 0 { offset += 2 }

        guard offset < data.count else { return nil }

        // Strip 8-byte trailer (CRC32 + ISIZE)
        let end = max(offset, data.count - 8)
        guard end > offset else { return nil }

        return data[offset..<end]
    }
}
