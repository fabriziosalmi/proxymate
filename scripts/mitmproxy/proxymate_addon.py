"""
Proxymate mitmproxy addon.

Runs inside mitmdump as --script. Sends decrypted request/response
metadata to Proxymate via a local Unix socket or HTTP endpoint.

Events sent:
  - request: host, method, path, headers, body_size
  - response: host, status, headers, body (for WAF inspection)
  - ai_usage: provider, model, tokens (extracted from AI API responses)
"""

import json
import os
import signal
import socket
import sys
import threading
import time
from collections import OrderedDict, deque
from mitmproxy import http, ctx

SOCKET_PATH = os.path.expanduser("~/.proxymate/mitm.sock")
MAX_BODY_SIZE = 2 * 1024 * 1024  # 2 MB max for body inspection
# Full packet capture: set via env var or config file. Default OFF to save storage.
FULL_CAPTURE = os.environ.get("PROXYMATE_FULL_CAPTURE", "0") == "1"
BODY_PREVIEW_SIZE = MAX_BODY_SIZE if FULL_CAPTURE else 4096

# Streaming-media Content-Types that must bypass body buffering. The in-flight
# response is streamed chunk-by-chunk (no 2 MB buffer wait — critical for
# webradio, which sends audio bytes continuously and the player expects them
# in real time). The host is also added to ignore_hosts so subsequent TCP
# connections skip MITM entirely, matching the Swift-native path.
_STREAMING_MEDIA_PREFIXES = ("audio/", "video/")
_STREAMING_MEDIA_EXACT = {
    "application/vnd.apple.mpegurl",   # HLS manifest (m3u8)
    "application/x-mpegurl",           # HLS manifest (legacy)
    "application/dash+xml",            # MPEG-DASH manifest
    "application/vnd.ms-sstr+xml",     # Smooth Streaming manifest
}

# Hardening knobs. See v0.9.58 release notes for the attack model.
#  - STREAMING_THRESHOLD = 2 → a single isolated audio/video fetch
#    (notification ding, podcast one-shot) streams pass-through but
#    does NOT permanently exclude the host. Two responses within the
#    window graduate the host to ignore_hosts.
#  - STREAMING_WINDOW_SEC = 60 → sliding window for counting. Stops
#    an attacker from stockpiling streaming responses over days.
#  - STREAMING_HOSTS_CAP = 256 → LRU cap on the excluded-host set.
#    Prevents unbounded growth across long sessions.
STREAMING_THRESHOLD = 2
STREAMING_WINDOW_SEC = 60
STREAMING_HOSTS_CAP = 256


def _is_streaming_media_content_type(value: str) -> bool:
    # "audio/mpeg; charset=..." -> compare only the type token.
    t = value.split(";", 1)[0].strip().lower()
    if t.startswith(_STREAMING_MEDIA_PREFIXES):
        return True
    return t in _STREAMING_MEDIA_EXACT


# Magic-byte prefixes for the formats we trust. Keyed by Content-Type token;
# value is a list of (offset, expected_bytes) tuples. Response passes the
# check if ANY tuple matches — a format often has multiple valid prefixes.
#
# Why this exists: without corroboration, an attacker-controlled server
# could label a malicious HTML/JSON payload as `audio/mpeg` and ride through
# our WAF body inspection. The magic check is cheap (≤16 bytes), defeats
# trivial spoofing, and still admits every real streaming format we care
# about. Formats whose Content-Type is not in this table fall through to
# a structural rejection (must not look like HTML/JSON).
_MAGIC = {
    # MP3: ID3v2 tag OR raw MPEG-1/2 Layer 3 sync
    "audio/mpeg":  [(0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xf3"), (0, b"\xff\xf2"), (0, b"\xff\xfa")],
    "audio/mp3":   [(0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xf3"), (0, b"\xff\xf2"), (0, b"\xff\xfa")],
    # AAC: ADTS sync word (12 bits of 1s + MPEG version + layer + protection bit)
    "audio/aac":   [(0, b"\xff\xf0"), (0, b"\xff\xf1"), (0, b"\xff\xf8"), (0, b"\xff\xf9"), (0, b"ADIF")],
    "audio/aacp":  [(0, b"\xff\xf0"), (0, b"\xff\xf1"), (0, b"\xff\xf8"), (0, b"\xff\xf9")],
    "audio/x-aac": [(0, b"\xff\xf0"), (0, b"\xff\xf1"), (0, b"\xff\xf8"), (0, b"\xff\xf9")],
    # Ogg container (Vorbis/Opus/FLAC-in-Ogg)
    "audio/ogg":   [(0, b"OggS")],
    "audio/opus":  [(0, b"OggS")],
    "audio/vorbis":[(0, b"OggS")],
    "audio/flac":  [(0, b"fLaC"), (0, b"OggS")],
    "audio/wav":   [(0, b"RIFF")],
    "audio/x-wav": [(0, b"RIFF")],
    "audio/wave":  [(0, b"RIFF")],
    # MP4 (ISO-BMFF) has variable box size in bytes 0..3, then "ftyp" at offset 4
    "audio/mp4":   [(4, b"ftyp")],
    "audio/m4a":   [(4, b"ftyp")],
    "audio/x-m4a": [(4, b"ftyp")],
    "video/mp4":   [(4, b"ftyp")],
    "video/quicktime": [(4, b"ftyp"), (4, b"moov"), (4, b"wide"), (4, b"mdat")],
    # WebM / Matroska EBML header
    "video/webm":  [(0, b"\x1a\x45\xdf\xa3")],
    "video/x-matroska": [(0, b"\x1a\x45\xdf\xa3")],
    # MPEG-TS: 0x47 sync byte (strict test: first byte 0x47 AND 188 bytes later also 0x47)
    "video/mp2t":  [(0, b"\x47")],
    # HLS / DASH / Smooth manifests are text. Require the format's root marker.
    "application/vnd.apple.mpegurl": [(0, b"#EXTM3U")],
    "application/x-mpegurl":         [(0, b"#EXTM3U")],
    "audio/mpegurl":                 [(0, b"#EXTM3U")],          # Mux's non-standard MIME
    "application/dash+xml":          [(0, b"<?xml"), (0, b"<MPD")],
    "application/vnd.ms-sstr+xml":   [(0, b"<?xml"), (0, b"<SmoothStreamingMedia")],
}


def _matches_streaming_magic(chunk: bytes, content_type: str) -> bool:
    """Return True if the first body bytes are consistent with the declared
    streaming Content-Type. Returns False on trivial spoofing (HTML/JSON
    labeled as audio/*). A response that passes this is not *guaranteed*
    legitimate — but it has at minimum gone through the trouble of mimicking
    a real container header, which is already a decent barrier for the
    casual WAF-bypass attempt on a normal site."""
    if not chunk:
        return False

    ct = content_type.split(";", 1)[0].strip().lower()

    # Structural reject: these byte patterns never start a streaming-media
    # response. Catching them early protects the unknown-type path below.
    head = chunk[:16].lstrip()  # tolerate leading whitespace on text manifests
    if head[:1] in (b"<", b"{", b"[") and ct not in (
        "application/dash+xml", "application/vnd.ms-sstr+xml"
    ):
        return False
    if head[:2] == b"\x1f\x8b":  # gzip — streams are never gzipped, this is an evasion signal
        return False

    patterns = _MAGIC.get(ct)
    if patterns is not None:
        for offset, expected in patterns:
            end = offset + len(expected)
            if len(chunk) >= end and chunk[offset:end] == expected:
                return True
        return False

    # No specific table entry. For audio/* and video/* we fall back to the
    # structural reject above (which already filtered HTML/JSON/gzip). That
    # admits legit-but-rare containers (e.g. audio/3gpp2, video/iso.segment)
    # without giving the attacker an easy spoof vector.
    if ct.startswith(_STREAMING_MEDIA_PREFIXES):
        return True
    return False


class ProxymateAddon:
    def __init__(self):
        self.sock = None
        self.lock = threading.Lock()
        self._parent_pid = os.getppid()
        # LRU of hosts that have graduated to ignore_hosts (value is time of
        # admission). Capped at STREAMING_HOSTS_CAP; oldest entry is evicted
        # when full.
        self._streaming_hosts: "OrderedDict[str, float]" = OrderedDict()
        # Hosts that have served ≥1 streaming response with valid magic but
        # have not yet crossed the threshold. Each entry is a sliding window
        # of timestamps (deque); we prune entries older than
        # STREAMING_WINDOW_SEC on each update. Hosts are removed from this
        # dict once they graduate to _streaming_hosts.
        self._streaming_candidates: "dict[str, deque]" = {}
        # Dedicated lock for the streaming state machine — called from the
        # stream-filter closure which runs off the main mitmproxy thread.
        self._streaming_lock = threading.Lock()
        self._connect()
        self._start_orphan_watchdog()

    def _connect(self):
        """Connect to Proxymate Unix socket."""
        try:
            if os.path.exists(SOCKET_PATH):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(SOCKET_PATH)
                self.sock.settimeout(1.0)
                ctx.log.info(f"[proxymate] Connected to {SOCKET_PATH}")
            else:
                ctx.log.warn(f"[proxymate] Socket not found: {SOCKET_PATH}")
                self.sock = None
        except Exception as e:
            ctx.log.warn(f"[proxymate] Socket connect failed: {e}")
            self.sock = None

    def _start_orphan_watchdog(self):
        """Kill ourselves if parent (Proxymate.app) dies — avoid orphaned proxy."""
        def _watch():
            while True:
                threading.Event().wait(timeout=3)
                try:
                    os.kill(self._parent_pid, 0)  # signal 0 = check existence
                except OSError:
                    ctx.log.warn("[proxymate] Parent process gone — shutting down")
                    os._exit(0)
        t = threading.Thread(target=_watch, daemon=True)
        t.start()

    def _send(self, event: dict):
        """Send event to Proxymate (fire-and-forget)."""
        if not self.sock:
            return
        try:
            data = json.dumps(event).encode() + b"\n"
            with self.lock:
                self.sock.sendall(data)
        except (BrokenPipeError, OSError):
            self.sock = None
            self._connect()

    def request(self, flow: http.HTTPFlow):
        """Called for every request (already decrypted by mitmproxy)."""
        req = flow.request
        host = req.pretty_host

        event = {
            "type": "request",
            "host": host,
            "method": req.method,
            "path": req.path,
            "headers": dict(req.headers),
            "body_size": len(req.content) if req.content else 0,
        }

        # Check for AI API requests
        ai_provider = self._detect_ai(host, dict(req.headers))
        if ai_provider:
            event["ai_provider"] = ai_provider
            # Extract model from request body
            if req.content and len(req.content) < MAX_BODY_SIZE:
                try:
                    body = json.loads(req.content)
                    if "model" in body:
                        event["ai_model"] = body["model"]
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        self._send(event)

    def responseheaders(self, flow: http.HTTPFlow):
        """Fires after response headers are received but BEFORE the body.

        Three jobs, executed in order:
          1. If Content-Type matches streaming media, install a stream-filter
             callable that (a) validates the first chunk against the magic-byte
             table and (b) always passes bytes through to the client in real
             time — so the in-flight connection is safe from the 2 MB buffer
             stall regardless of magic outcome.
          2. On valid magic, register the host as a streaming candidate with
             a sliding-window timestamp.
          3. Only after STREAMING_THRESHOLD valid-magic responses within
             STREAMING_WINDOW_SEC does the host graduate to ignore_hosts.
             This defeats the "one MP3 = permanent host-wide MITM bypass"
             false positive.
        """
        resp = flow.response
        if resp is None:
            return
        ct_raw = resp.headers.get("content-type") or resp.headers.get("Content-Type")
        if not ct_raw or not _is_streaming_media_content_type(ct_raw):
            return

        # Gzip on a streaming Content-Type is an evasion signal (real media
        # is never gzipped). Refuse the stream flag entirely so WAF inspects
        # the body normally. The host is not added to any set.
        if resp.headers.get("content-encoding") or resp.headers.get("Content-Encoding"):
            ctx.log.warn(
                f"[proxymate] streaming Content-Type {ct_raw} from "
                f"{flow.request.pretty_host} with Content-Encoding — refusing pass-through"
            )
            return

        host = flow.request.pretty_host
        ct = ct_raw.split(";", 1)[0].strip()

        # Per-flow state held in a closure cell — the callable is invoked
        # multiple times (once per chunk) on an arbitrary mitmproxy worker.
        first_chunk_seen = [False]
        magic_verified = [False]

        def stream_filter(chunk: bytes) -> bytes:
            if not first_chunk_seen[0] and chunk:
                first_chunk_seen[0] = True
                if _matches_streaming_magic(chunk, ct):
                    magic_verified[0] = True
                    self._record_streaming_response(host, ct)
                else:
                    # Magic failed. Still pass this chunk through — the client
                    # may be a legitimate player talking to a buggy server.
                    # But DO NOT count this toward the host's graduation
                    # threshold, and log loudly so the operator can audit.
                    head = chunk[:32]
                    ctx.log.warn(
                        f"[proxymate] magic mismatch: {ct} declared from {host} "
                        f"but body starts with {head!r} — streaming but not excluding"
                    )
            return chunk

        resp.stream = stream_filter

    def _record_streaming_response(self, host: str, ct: str) -> None:
        """Record a magic-verified streaming response from `host`. When
        STREAMING_THRESHOLD entries land inside STREAMING_WINDOW_SEC, the
        host graduates to _streaming_hosts + ignore_hosts."""
        now = time.monotonic()
        graduated = False
        with self._streaming_lock:
            if host in self._streaming_hosts:
                # Already excluded — bump LRU recency.
                self._streaming_hosts.move_to_end(host)
                return
            window = self._streaming_candidates.get(host)
            if window is None:
                window = deque()
                self._streaming_candidates[host] = window
            window.append(now)
            # Prune entries outside the sliding window.
            cutoff = now - STREAMING_WINDOW_SEC
            while window and window[0] < cutoff:
                window.popleft()
            if len(window) < STREAMING_THRESHOLD:
                return
            # Threshold crossed: graduate.
            del self._streaming_candidates[host]
            self._streaming_hosts[host] = now
            # LRU eviction if we're above cap.
            while len(self._streaming_hosts) > STREAMING_HOSTS_CAP:
                evicted, _ = self._streaming_hosts.popitem(last=False)
                # ignore_hosts is additive in this process — we leave the
                # regex in place. Worst case: a long-dead host stays
                # excluded. The upstream LRU is the memory safety valve.
                ctx.log.info(f"[proxymate] streaming-hosts LRU evict: {evicted}")
            graduated = True

        if not graduated:
            return

        # ignore_hosts update is cheap but mutates a mitmproxy option — keep
        # it outside the lock to avoid holding a lock across ctx calls.
        try:
            current = list(ctx.options.ignore_hosts or [])
            pattern = f"^{host.replace('.', r'\.')}$"
            if pattern not in current:
                ctx.options.update(ignore_hosts=current + [pattern])
        except Exception as e:
            ctx.log.warn(f"[proxymate] ignore_hosts update failed for {host}: {e}")

        ctx.log.info(f"[proxymate] streaming media ({ct}) from {host}, auto-excluding")
        self._send({
            "type": "log",
            "level": "info",
            "message": f"MITM: streaming media ({ct}) from {host}, auto-excluding",
        })

    def response(self, flow: http.HTTPFlow):
        """Called for every response (already decrypted by mitmproxy)."""
        req = flow.request
        resp = flow.response
        host = req.pretty_host

        event = {
            "type": "response",
            "host": host,
            "method": req.method,
            "path": req.path,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body_size": len(resp.content) if resp.content else 0,
        }

        # Strip Alt-Svc to prevent HTTP/3 upgrade. macOS network-setup
        # proxies are TCP-only: if the browser upgrades to HTTP/3 (UDP/443)
        # it bypasses mitm entirely and MITM inspection is silently
        # defeated. Symptom: subresources on CDN hosts (e.g. static.licdn.com)
        # fail with status=(null) while the main page loads fine. Removing
        # the header keeps the browser on HTTP/2 inside the proxied tunnel.
        resp.headers.pop("alt-svc", None)
        resp.headers.pop("Alt-Svc", None)

        # Extract AI usage from response
        ai_provider = self._detect_ai(host, dict(req.headers))
        if ai_provider and resp.content and len(resp.content) < MAX_BODY_SIZE:
            usage = self._extract_ai_usage(ai_provider, resp.content, resp.headers)
            if usage:
                event["ai_usage"] = usage

        # WAF content inspection on response body (size controlled by FULL_CAPTURE)
        if resp.content and len(resp.content) < MAX_BODY_SIZE:
            event["body_preview"] = resp.content[:BODY_PREVIEW_SIZE].decode("utf-8", errors="replace")

        self._send(event)

    def _detect_ai(self, host: str, headers: dict) -> str | None:
        """Detect AI provider from host."""
        providers = {
            "api.openai.com": "OpenAI",
            "api.anthropic.com": "Anthropic",
            "generativelanguage.googleapis.com": "Google AI",
            "api.mistral.ai": "Mistral",
            "api.cohere.ai": "Cohere",
            "api.together.xyz": "Together",
            "api.groq.com": "Groq",
            "api.fireworks.ai": "Fireworks",
            "api.perplexity.ai": "Perplexity",
            "api.deepseek.com": "DeepSeek",
        }
        for domain, name in providers.items():
            if host == domain or host.endswith("." + domain):
                return name
        return None

    def _extract_ai_usage(self, provider: str, content: bytes, headers) -> dict | None:
        """Extract token usage from AI API response."""
        try:
            text = content.decode("utf-8", errors="replace")

            # Handle SSE streams (find last data: line with usage)
            if "data: " in text:
                lines = text.strip().split("\n")
                for line in reversed(lines):
                    if line.startswith("data: ") and line != "data: [DONE]":
                        text = line[6:]
                        break

            data = json.loads(text)
            usage = data.get("usage", {})
            prompt = usage.get("prompt_tokens") or usage.get("input_tokens", 0)
            completion = usage.get("completion_tokens") or usage.get("output_tokens", 0)
            model = data.get("model", "unknown")

            if prompt or completion:
                return {
                    "provider": provider,
                    "model": model,
                    "prompt_tokens": prompt,
                    "completion_tokens": completion,
                }
        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
            pass
        return None


addons = [ProxymateAddon()]
