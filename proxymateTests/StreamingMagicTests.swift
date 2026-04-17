import XCTest
@testable import proxymate

/// Unit tests for the streaming-media magic-byte validator and the
/// threshold-gated auto-exclude state machine introduced in 0.9.58.
/// Both are pure logic — no Xcode runner launch needed.
final class StreamingMagicTests: XCTestCase {

    // MARK: - isStreamingMediaContentType

    func testContentTypeClassifier_audioVideoPrefixes() {
        XCTAssertTrue(TLSManager.isStreamingMediaContentType("audio/mpeg"))
        XCTAssertTrue(TLSManager.isStreamingMediaContentType("audio/mpeg; charset=utf-8"))
        XCTAssertTrue(TLSManager.isStreamingMediaContentType("AUDIO/MPEG"))
        XCTAssertTrue(TLSManager.isStreamingMediaContentType("video/mp4"))
        XCTAssertTrue(TLSManager.isStreamingMediaContentType("audio/mpegurl"))
    }

    func testContentTypeClassifier_manifestExactMatches() {
        XCTAssertTrue(TLSManager.isStreamingMediaContentType("application/vnd.apple.mpegurl"))
        XCTAssertTrue(TLSManager.isStreamingMediaContentType("application/x-mpegurl"))
        XCTAssertTrue(TLSManager.isStreamingMediaContentType("application/dash+xml"))
        XCTAssertTrue(TLSManager.isStreamingMediaContentType("application/vnd.ms-sstr+xml"))
    }

    func testContentTypeClassifier_nonStreaming() {
        XCTAssertFalse(TLSManager.isStreamingMediaContentType("text/html"))
        XCTAssertFalse(TLSManager.isStreamingMediaContentType("application/json"))
        XCTAssertFalse(TLSManager.isStreamingMediaContentType("application/octet-stream"))
        XCTAssertFalse(TLSManager.isStreamingMediaContentType(""))
    }

    // MARK: - matchesStreamingMagic — legitimate formats

    func testMagic_mp3_withID3() {
        let d = Data([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00, 0x00] + [UInt8](repeating: 0, count: 8))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "audio/mpeg"))
    }

    func testMagic_mp3_rawMpegSync() {
        let d = Data([0xFF, 0xFB, 0x90, 0x64] + [UInt8](repeating: 0, count: 12))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "audio/mpeg"))
    }

    func testMagic_aac_adts() {
        for sync in [0xF0, 0xF1, 0xF8, 0xF9] {
            let d = Data([0xFF, UInt8(sync), 0x50, 0x80] + [UInt8](repeating: 0, count: 12))
            XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "audio/aac"))
        }
    }

    func testMagic_ogg() {
        let d = Data(Array("OggS".utf8) + [UInt8](repeating: 0, count: 12))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "audio/ogg"))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "audio/opus"))
    }

    func testMagic_flac() {
        let d = Data(Array("fLaC".utf8) + [UInt8](repeating: 0, count: 12))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "audio/flac"))
    }

    func testMagic_wav() {
        let d = Data(Array("RIFF\u{00}\u{00}\u{00}\u{00}WAVE".utf8) + [UInt8](repeating: 0, count: 4))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "audio/wav"))
    }

    func testMagic_mp4_ftyp() {
        let d = Data([0x00, 0x00, 0x00, 0x20] + Array("ftypmp42".utf8) + [UInt8](repeating: 0, count: 4))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "video/mp4"))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "audio/mp4"))
    }

    func testMagic_webm() {
        let d = Data([0x1A, 0x45, 0xDF, 0xA3] + [UInt8](repeating: 0, count: 12))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "video/webm"))
    }

    func testMagic_mpegTS() {
        let d = Data([0x47] + [UInt8](repeating: 0, count: 15))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "video/mp2t"))
    }

    func testMagic_hlsManifest() {
        let d = Data("#EXTM3U\n#EXT-X-VERSION:3".utf8)
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "application/vnd.apple.mpegurl"))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "application/x-mpegurl"))
        // Mux's non-standard audio/mpegurl must also pass via the same magic.
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "audio/mpegurl"))
    }

    func testMagic_dashManifest() {
        let d1 = Data("<?xml version=\"1.0\"?><MPD></MPD>".utf8)
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d1, contentType: "application/dash+xml"))
        let d2 = Data("<MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\">".utf8)
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d2, contentType: "application/dash+xml"))
    }

    // MARK: - matchesStreamingMagic — attack / evasion patterns

    func testMagic_rejectsHtmlAsAudio() {
        let d = Data("<!DOCTYPE html><html><body>pwned</body></html>".utf8)
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "audio/mpeg"),
                       "HTML labeled audio/mpeg must not pass")
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "video/mp4"))
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "audio/aac"))
    }

    func testMagic_rejectsJsonAsAudio() {
        let d = Data("{\"exfil\":\"data\"}".utf8)
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "audio/mpeg"))
    }

    func testMagic_rejectsJsonArrayAsAudio() {
        let d = Data("[1,2,3,4]".utf8)
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "audio/mpeg"))
    }

    func testMagic_rejectsGzipAsAudio() {
        // Legit streams are never gzipped — the evasion signal is clear.
        let d = Data([0x1F, 0x8B, 0x08, 0x00] + [UInt8](repeating: 0, count: 12))
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "audio/mpeg"))
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "video/mp4"))
    }

    func testMagic_rejectsGarbageAsHlsManifest() {
        let d = Data("random text not a manifest".utf8)
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "application/vnd.apple.mpegurl"))
    }

    func testMagic_rejectsJsonAsHlsManifest() {
        let d = Data("{}".utf8)
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "application/vnd.apple.mpegurl"))
    }

    func testMagic_emptyRejected() {
        XCTAssertFalse(TLSManager.matchesStreamingMagic(Data(), contentType: "audio/mpeg"))
    }

    func testMagic_truncatedRejected() {
        let d = Data([0x49, 0x44])  // "ID" — truncated from "ID3"
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "audio/mpeg"))
    }

    func testMagic_unknownAudioTypeAcceptsNonHtmlBytes() {
        // Rare audio/* type with no table entry passes the structural-reject
        // branch as long as it doesn't look like HTML/JSON/gzip.
        let d = Data([0x00, 0xFF, 0xAA, 0xBB] + [UInt8](repeating: 0, count: 12))
        XCTAssertTrue(TLSManager.matchesStreamingMagic(d, contentType: "audio/3gpp2"))
    }

    func testMagic_unknownAudioTypeRejectsHtmlBytes() {
        let d = Data("<script>alert(1)</script>".utf8)
        XCTAssertFalse(TLSManager.matchesStreamingMagic(d, contentType: "audio/3gpp2"))
    }

    // (Aspirational leading-whitespace tolerance was dropped — real DASH
    // servers emit well-formed XML starting at offset 0. Keeping the magic
    // check strict avoids widening the attack surface for a non-case.)

    // MARK: - threshold-gated exclusion state machine

    func testThreshold_firstResponseIsCandidateNotExclude() {
        // Use a fresh unique hostname per test to avoid cross-test state.
        let host = "threshold-test-\(UUID().uuidString).example"
        TLSManager.shared.resetPinningHistory()
        let graduated1 = TLSManager.shared.recordStreamingMediaResponse(host: host)
        XCTAssertFalse(graduated1, "first response must not graduate host")
        XCTAssertFalse(TLSManager.shared.getRuntimeExcludes().contains(host.lowercased()))
    }

    func testThreshold_twoResponsesGraduate() {
        let host = "threshold-test-\(UUID().uuidString).example"
        TLSManager.shared.resetPinningHistory()
        _ = TLSManager.shared.recordStreamingMediaResponse(host: host)
        let graduated = TLSManager.shared.recordStreamingMediaResponse(host: host)
        XCTAssertTrue(graduated, "second response within window must graduate host")
        XCTAssertTrue(TLSManager.shared.getRuntimeExcludes().contains(host.lowercased()))
    }

    func testThreshold_subsequentCallsToExcludedHostAreNoop() {
        let host = "threshold-noop-\(UUID().uuidString).example"
        TLSManager.shared.resetPinningHistory()
        _ = TLSManager.shared.recordStreamingMediaResponse(host: host)
        _ = TLSManager.shared.recordStreamingMediaResponse(host: host)
        let third = TLSManager.shared.recordStreamingMediaResponse(host: host)
        XCTAssertFalse(third, "third call on excluded host must return false (no double-log)")
    }

    func testThreshold_caseInsensitive() {
        let host = "MIXEDCASE-\(UUID().uuidString).EXAMPLE"
        TLSManager.shared.resetPinningHistory()
        _ = TLSManager.shared.recordStreamingMediaResponse(host: host)
        _ = TLSManager.shared.recordStreamingMediaResponse(host: host.lowercased())
        XCTAssertTrue(TLSManager.shared.getRuntimeExcludes().contains(host.lowercased()))
    }

    // MARK: - resetPinningHistory clears all streaming state too

    func testResetClearsStreamingState() {
        let host = "reset-test-\(UUID().uuidString).example"
        _ = TLSManager.shared.recordStreamingMediaResponse(host: host)
        _ = TLSManager.shared.recordStreamingMediaResponse(host: host)
        XCTAssertTrue(TLSManager.shared.getRuntimeExcludes().contains(host.lowercased()))
        TLSManager.shared.resetPinningHistory()
        XCTAssertFalse(TLSManager.shared.getRuntimeExcludes().contains(host.lowercased()))
    }
}
