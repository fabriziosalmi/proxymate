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


def _is_streaming_media_content_type(value: str) -> bool:
    # "audio/mpeg; charset=..." -> compare only the type token.
    t = value.split(";", 1)[0].strip().lower()
    if t.startswith(_STREAMING_MEDIA_PREFIXES):
        return True
    return t in _STREAMING_MEDIA_EXACT


class ProxymateAddon:
    def __init__(self):
        self.sock = None
        self.lock = threading.Lock()
        self._parent_pid = os.getppid()
        # Hosts already auto-excluded by streaming-media detection. Kept in-process
        # so we log the decision once per host instead of on every response.
        self._streaming_hosts: set[str] = set()
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

        Two jobs:
          1. If Content-Type says this is streaming media (audio/video/HLS/DASH),
             flip the response to pass-through mode so bytes flow to the client
             in real time instead of being buffered. Without this, webradio
             streams stall waiting for the 2 MB body-size cap.
          2. Add the host to ignore_hosts so future TCP connections to the
             same host skip MITM entirely (no cert forging, no handshake).
        """
        resp = flow.response
        if resp is None:
            return
        ct = resp.headers.get("content-type") or resp.headers.get("Content-Type")
        if not ct or not _is_streaming_media_content_type(ct):
            return

        # In-flight pass-through. mitmproxy streams the body chunk-by-chunk
        # to the client without buffering; the addon will still see the
        # response object but content will be empty (which is fine — we
        # don't want to inspect media bytes).
        resp.stream = True

        host = flow.request.pretty_host
        if host in self._streaming_hosts:
            return
        self._streaming_hosts.add(host)

        # Dynamically bypass this host on future connections via mitmproxy's
        # ignore_hosts option. Pattern is anchored to avoid partial matches.
        try:
            current = list(ctx.options.ignore_hosts or [])
            pattern = f"^{host.replace('.', r'\.')}$"
            if pattern not in current:
                ctx.options.update(ignore_hosts=current + [pattern])
        except Exception as e:
            ctx.log.warn(f"[proxymate] ignore_hosts update failed for {host}: {e}")

        short_ct = ct.split(";", 1)[0].strip()
        ctx.log.info(f"[proxymate] streaming media ({short_ct}) from {host}, auto-excluding")
        self._send({
            "type": "log",
            "level": "info",
            "message": f"MITM: streaming media ({short_ct}) from {host}, auto-excluding",
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
