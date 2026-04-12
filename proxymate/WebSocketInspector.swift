//
//  WebSocketInspector.swift
//  proxymate
//
//  Parses WebSocket frames (RFC 6455) from a bidirectional byte stream.
//  Extracts text frames for WAF/exfiltration inspection. Binary frames
//  are passed through without inspection.
//
//  Used by the MITM handler when a WebSocket upgrade is detected.
//

import Foundation

nonisolated enum WebSocketInspector {

    enum Opcode: UInt8 {
        case continuation = 0x0
        case text         = 0x1
        case binary       = 0x2
        case close        = 0x8
        case ping         = 0x9
        case pong         = 0xA
        case unknown      = 0xFF
    }

    struct Frame {
        let fin: Bool
        let opcode: Opcode
        let payload: Data
        let totalLength: Int  // bytes consumed from the stream
    }

    struct InspectionResult: Sendable {
        let blocked: Bool
        let reason: String?
    }

    // MARK: - Frame parsing

    /// Try to parse one WebSocket frame from the beginning of `data`.
    /// Returns nil if there isn't enough data for a complete frame.
    static func parseFrame(_ data: Data) -> Frame? {
        guard data.count >= 2 else { return nil }

        let byte0 = data[0]
        let byte1 = data[1]

        let fin = (byte0 & 0x80) != 0
        let opcodeRaw = byte0 & 0x0F
        let opcode = Opcode(rawValue: opcodeRaw) ?? .unknown
        let masked = (byte1 & 0x80) != 0
        var payloadLength = UInt64(byte1 & 0x7F)
        var offset = 2

        if payloadLength == 126 {
            guard data.count >= 4 else { return nil }
            payloadLength = UInt64(data[2]) << 8 | UInt64(data[3])
            offset = 4
        } else if payloadLength == 127 {
            guard data.count >= 10 else { return nil }
            payloadLength = 0
            for i in 0..<8 {
                payloadLength = payloadLength << 8 | UInt64(data[2 + i])
            }
            offset = 10
        }

        var maskKey: [UInt8] = []
        if masked {
            guard data.count >= offset + 4 else { return nil }
            maskKey = [data[offset], data[offset+1], data[offset+2], data[offset+3]]
            offset += 4
        }

        guard payloadLength <= UInt64(Int.max - offset) else { return nil }
        let totalLength = offset + Int(payloadLength)
        guard data.count >= totalLength else { return nil }

        var payload = Data(data[offset..<totalLength])
        if masked {
            for i in 0..<payload.count {
                payload[i] ^= maskKey[i % 4]
            }
        }

        return Frame(fin: fin, opcode: opcode, payload: payload, totalLength: totalLength)
    }

    // MARK: - Inspection

    /// Inspect a text frame against WAF rules and exfiltration patterns.
    static func inspect(frame: Frame,
                         host: String,
                         rules: [WAFRule]) -> InspectionResult {
        guard frame.opcode == .text,
              let text = String(data: frame.payload, encoding: .utf8) else {
            return InspectionResult(blocked: false, reason: nil)
        }

        // WAF content rules
        for rule in rules where rule.enabled && rule.kind == .blockContent {
            let pat = rule.pattern.lowercased()
            if text.lowercased().contains(pat) {
                let label = rule.name.isEmpty ? rule.pattern : rule.name
                return InspectionResult(blocked: true, reason: "WS WAF: \(label)")
            }
        }

        // Exfiltration scan on WebSocket text
        if let hit = ExfiltrationScanner.shared.scan(headers: text, target: "") {
            return InspectionResult(blocked: true,
                                    reason: "WS Exfil: \(hit.patternName)")
        }

        return InspectionResult(blocked: false, reason: nil)
    }

    // MARK: - Upgrade detection

    /// Check if an HTTP request is a WebSocket upgrade.
    static func isUpgradeRequest(_ headers: String) -> Bool {
        let lower = headers.lowercased()
        return lower.contains("upgrade: websocket") &&
               lower.contains("connection:") &&
               lower.contains("upgrade")
    }

    // MARK: - Frame building

    /// Build a close frame (for sending back to client on block).
    static func closeFrame(code: UInt16 = 1008, reason: String = "") -> Data {
        var payload = Data()
        payload.append(UInt8(code >> 8))
        payload.append(UInt8(code & 0xFF))
        payload.append(Data(reason.utf8))

        var frame = Data()
        frame.append(0x88) // FIN + opcode close
        if payload.count < 126 {
            frame.append(UInt8(payload.count))
        } else {
            frame.append(126)
            frame.append(UInt8(payload.count >> 8))
            frame.append(UInt8(payload.count & 0xFF))
        }
        frame.append(payload)
        return frame
    }
}
