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
import socket
import threading
from mitmproxy import http, ctx

SOCKET_PATH = os.path.expanduser("~/.proxymate/mitm.sock")
MAX_BODY_SIZE = 2 * 1024 * 1024  # 2 MB max for body inspection


class ProxymateAddon:
    def __init__(self):
        self.sock = None
        self.lock = threading.Lock()
        self._connect()

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

        # Extract AI usage from response
        ai_provider = self._detect_ai(host, dict(req.headers))
        if ai_provider and resp.content and len(resp.content) < MAX_BODY_SIZE:
            usage = self._extract_ai_usage(ai_provider, resp.content, resp.headers)
            if usage:
                event["ai_usage"] = usage

        # WAF content inspection on response body
        if resp.content and len(resp.content) < MAX_BODY_SIZE:
            event["body_preview"] = resp.content[:4096].decode("utf-8", errors="replace")

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
