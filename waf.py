#!/usr/bin/env python3
"""webwaf - a small reverse-proxy web application firewall (standard library only).

Put it in front of a web app:

    python3 waf.py --config waf.json

Clients talk to the WAF on listen_port. Each request is inspected and either
blocked, or forwarded to the upstream application and the response returned.

Features
  * Signature rules for SQL injection, XSS, path traversal, command injection,
    file/stream wrapper inclusion and known attack-tool user agents
  * Detection is done on URL-decoded input (repeatedly), so double-encoded
    payloads such as %253Cscript%253E are caught
  * Per-client-IP rate limiting with temporary bans
  * IP denylist and optional IP allowlist (CIDR notation)
  * HTTP method allowlist, request body size limit
  * Security response headers added to upstream responses
  * JSON-lines audit log of every decision
  * Detect-only mode for tuning rules before enforcing them
"""

import argparse
import ipaddress
import json
import re
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from copy import deepcopy
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 8080,
    "upstream": "http://127.0.0.1:8000",
    "upstream_timeout": 30,
    "block_mode": True,
    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "max_body_bytes": 1048576,
    "inspect_body": True,
    "rate_limit": {"window_seconds": 10, "max_requests": 100, "ban_seconds": 300},
    "ip_allowlist": [],
    "ip_denylist": [],
    "trust_x_forwarded_for": False,
    "disabled_rules": [],
    "security_headers": {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    },
    "log_file": "waf.log",
}

# Targets: "path" (decoded URL path), "query" (raw query string),
# "headers" (all header values), "body" (request body as text).
PATH_QUERY_BODY = ("path", "query", "body")
EVERYWHERE = ("path", "query", "headers", "body")

# (rule id, description, targets, regex). Regexes are matched case-insensitively.
RULES = [
    ("SQLI-001", "UNION-based SQL injection", EVERYWHERE,
     r"\bunion\b[\s/*()]*(all\s+)?select\b"),
    ("SQLI-002", "Boolean-based SQL injection", EVERYWHERE,
     r"['\"]\s*(or|and)\s+['\"\w]+\s*[=<>]"),
    ("SQLI-003", "Stacked SQL statement", EVERYWHERE,
     r";\s*(drop|alter|truncate|delete|insert|update|create|exec)\b"),
    ("SQLI-004", "Time-based SQL injection", EVERYWHERE,
     r"\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b"),
    ("XSS-001", "Script tag", EVERYWHERE,
     r"<\s*/?\s*script\b"),
    ("XSS-002", "Inline event handler attribute", EVERYWHERE,
     r"\bon(error|load|click|mouseover|focus|submit|toggle)\s*="),
    ("XSS-003", "javascript: URI", EVERYWHERE,
     r"\bjavascript\s*:"),
    ("XSS-004", "Script-capable HTML element", EVERYWHERE,
     r"<\s*(iframe|object|embed|svg|img)\b[^>]*\s(src|srcdoc|on\w+)\s*="),
    ("TRAV-001", "Path traversal sequence", PATH_QUERY_BODY,
     r"\.\.[/\\]"),
    ("TRAV-002", "Access to system files", PATH_QUERY_BODY,
     r"/etc/(passwd|shadow|hosts)\b|\bwin\.ini\b|\bboot\.ini\b"),
    ("CMD-001", "Shell command injection", PATH_QUERY_BODY,
     r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|rm|chmod|python3?|perl)\b"),
    ("RFI-001", "Stream wrapper inclusion", PATH_QUERY_BODY,
     r"\b(php|expect|data|zip|phar)://"),
    ("SCAN-001", "Known attack-tool user agent", ("headers",),
     r"\b(sqlmap|nikto|nmap|masscan|acunetix|wpscan|nuclei|gobuster|dirbuster)\b"),
]

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "trailers", "transfer-encoding", "upgrade",
}


def normalize(value: str) -> str:
    """Remove NULs and undo URL encoding (up to 3 layers) before matching."""
    current = value.replace("\x00", "")
    for _ in range(3):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


class Inspector:
    """Matches request parts against the signature rules."""

    def __init__(self, disabled=()):
        skip = set(disabled)
        self.rules = [
            (rid, desc, targets, re.compile(pattern, re.IGNORECASE | re.DOTALL))
            for rid, desc, targets, pattern in RULES
            if rid not in skip
        ]

    def inspect(self, parts):
        """parts maps a target name to a list of raw strings. Returns matched rule ids."""
        normalized = {t: [normalize(s) for s in vals] for t, vals in parts.items() if vals}
        hits = []
        for rid, _desc, targets, rx in self.rules:
            if any(rx.search(s) for t in targets for s in normalized.get(t, ())):
                hits.append(rid)
        return hits


class RateLimiter:
    """Sliding-window limiter per client IP. Exceeding the limit bans the IP temporarily."""

    def __init__(self, window, max_requests, ban_seconds):
        self.window = window
        self.max_requests = max_requests
        self.ban_seconds = ban_seconds
        self._hits = defaultdict(deque)
        self._banned_until = {}
        self._lock = threading.Lock()

    def check(self, ip, now=None):
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            until = self._banned_until.get(ip)
            if until is not None:
                if now < until:
                    return False, int(until - now) + 1
                del self._banned_until[ip]

            q = self._hits[ip]
            q.append(now)
            cutoff = now - self.window
            while q and q[0] < cutoff:
                q.popleft()

            if len(q) > self.max_requests:
                self._banned_until[ip] = now + self.ban_seconds
                q.clear()
                return False, self.ban_seconds

            if len(self._hits) > 50000:
                self._sweep(now)
            return True, 0

    def _sweep(self, now):
        stale = [ip for ip, q in self._hits.items() if not q or q[-1] < now - self.window]
        for ip in stale:
            del self._hits[ip]


class AuditLog:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, record):
        record = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), **record}
        line = json.dumps(record, ensure_ascii=True)
        with self._lock:
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            else:
                print(line, flush=True)


def _networks(cidrs):
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


def _in_any(ip_text, networks):
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return any(addr in net for net in networks)


class Context:
    """Everything the request handler needs, built once from the config."""

    def __init__(self, cfg):
        self.cfg = cfg
        upstream = urlsplit(cfg["upstream"])
        if upstream.scheme not in ("http", "https") or not upstream.hostname:
            raise ValueError(f"upstream must be an http:// or https:// URL, got {cfg['upstream']!r}")
        self.upstream = upstream
        self.allowlist = _networks(cfg["ip_allowlist"])
        self.denylist = _networks(cfg["ip_denylist"])
        rl = cfg["rate_limit"]
        self.limiter = RateLimiter(rl["window_seconds"], rl["max_requests"], rl["ban_seconds"])
        self.inspector = Inspector(cfg["disabled_rules"])
        self.audit = AuditLog(cfg["log_file"])

    def log(self, record):
        self.audit.write(record)


class WAFHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # one request per connection keeps the logic simple
    server_version = "webwaf"
    sys_version = ""
    timeout = 15  # drop clients that stall while sending

    def log_message(self, fmt, *args):
        pass  # the audit log replaces the default stderr access log

    def do_GET(self):
        self._process()

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_GET

    def _client_ip(self):
        if self.server.ctx.cfg["trust_x_forwarded_for"]:
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                # The rightmost entry is the one added by the closest trusted proxy.
                return xff.split(",")[-1].strip()
        return self.client_address[0]

    def _apply_security_headers(self, present):
        for name, value in self.server.ctx.cfg["security_headers"].items():
            if name.lower() not in present:
                self.send_header(name, value)

    def _reject(self, ctx, base, rid, status, action, message, headers=None, rules=None):
        record = dict(base, action=action, status=status)
        if rules:
            record["rules"] = rules
        ctx.log(record)

        body = f"{message}\nRequest ID: {rid}\n".encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self._apply_security_headers(set())
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _process(self):
        ctx = self.server.ctx
        cfg = ctx.cfg
        rid = uuid.uuid4().hex[:12]
        ip = self._client_ip()
        base = {"id": rid, "ip": ip, "method": self.command, "path": self.path[:300]}

        # 1. IP policy
        if _in_any(ip, ctx.denylist) or (ctx.allowlist and not _in_any(ip, ctx.allowlist)):
            return self._reject(ctx, base, rid, 403, "denied_ip", "Forbidden.")

        # 2. Rate limit
        allowed, retry = ctx.limiter.check(ip)
        if not allowed:
            return self._reject(ctx, base, rid, 429, "rate_limited", "Too many requests.",
                                headers={"Retry-After": str(retry)})

        # 3. Method allowlist
        if self.command not in cfg["allowed_methods"]:
            return self._reject(ctx, base, rid, 405, "method_not_allowed", "Method not allowed.",
                                headers={"Allow": ", ".join(cfg["allowed_methods"])})

        # 4. Body framing and size. Chunked uploads are refused to keep the body size check exact.
        if self.headers.get("Transfer-Encoding", "identity").strip().lower() != "identity":
            return self._reject(ctx, base, rid, 501, "unsupported_encoding",
                                "Chunked request bodies are not supported.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0:
            return self._reject(ctx, base, rid, 400, "bad_request", "Bad request.")
        if length > cfg["max_body_bytes"]:
            return self._reject(ctx, base, rid, 413, "body_too_large", "Request body too large.")
        body = self.rfile.read(length) if length else b""

        # 5. Signature inspection
        parsed = urlsplit(self.path)
        parts = {
            "path": [parsed.path],
            "query": [parsed.query],
            "headers": [value for _, value in self.headers.items()],
            "body": [body.decode("utf-8", "replace")] if (body and cfg["inspect_body"]) else [],
        }
        hits = ctx.inspector.inspect(parts)
        if hits and cfg["block_mode"]:
            return self._reject(ctx, base, rid, 403, "blocked",
                                "Request blocked by web application firewall.", rules=hits)

        # 6. Forward to upstream
        result = self._forward(ctx, body, ip, rid)
        if result is None:
            return self._reject(ctx, base, rid, 502, "upstream_error", "Bad gateway.")
        status, reason, resp_headers, data = result

        record = dict(base, action="detected" if hits else "allowed", status=status)
        if hits:
            record["rules"] = hits
        ctx.log(record)

        self._send_upstream_response(status, reason, resp_headers, data)

    def _forward(self, ctx, body, ip, rid):
        up = ctx.upstream
        conn_cls = HTTPSConnection if up.scheme == "https" else HTTPConnection
        conn = conn_cls(up.hostname, up.port, timeout=ctx.cfg["upstream_timeout"])
        try:
            conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            for key, value in self.headers.items():
                lk = key.lower()
                if lk in HOP_BY_HOP or lk in ("content-length", "x-forwarded-for", "x-request-id"):
                    continue
                conn.putheader(key, value)
            prior = self.headers.get("X-Forwarded-For")
            conn.putheader("X-Forwarded-For", f"{prior}, {ip}" if prior else ip)
            conn.putheader("X-Request-ID", rid)
            if body:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body or None)

            resp = conn.getresponse()
            data = resp.read()
            return resp.status, resp.reason, resp.getheaders(), data
        except (OSError, HTTPException):
            return None
        finally:
            conn.close()

    def _send_upstream_response(self, status, reason, resp_headers, data):
        self.send_response(status, reason)
        present = set()
        skip = HOP_BY_HOP | {"server", "date"}
        for key, value in resp_headers:
            lk = key.lower()
            if lk in skip or (lk == "content-length" and self.command != "HEAD"):
                continue
            self.send_header(key, value)
            present.add(lk)
        if self.command != "HEAD":
            self.send_header("Content-Length", str(len(data)))
        self._apply_security_headers(present)
        self.end_headers()
        if self.command != "HEAD" and data:
            self.wfile.write(data)


class WAFServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, ctx):
        self.ctx = ctx
        super().__init__(address, WAFHandler)


def load_config(path=None):
    cfg = deepcopy(DEFAULT_CONFIG)
    if path:
        with open(path, encoding="utf-8") as fh:
            user = json.load(fh)
        for key, value in user.items():
            if isinstance(value, dict) and isinstance(cfg.get(key), dict):
                cfg[key].update(value)
            else:
                cfg[key] = value
    return cfg


def main(argv=None):
    parser = argparse.ArgumentParser(description="webwaf: reverse-proxy web application firewall")
    parser.add_argument("--config", help="path to a JSON config file")
    parser.add_argument("--host", help="override listen_host")
    parser.add_argument("--port", type=int, help="override listen_port")
    parser.add_argument("--upstream", help="override upstream URL")
    parser.add_argument("--detect-only", action="store_true",
                        help="log matches but do not block them")
    parser.add_argument("--print-default-config", action="store_true",
                        help="print the default config as JSON and exit")
    args = parser.parse_args(argv)

    if args.print_default_config:
        print(json.dumps(DEFAULT_CONFIG, indent=2))
        return 0

    cfg = load_config(args.config)
    if args.host:
        cfg["listen_host"] = args.host
    if args.port:
        cfg["listen_port"] = args.port
    if args.upstream:
        cfg["upstream"] = args.upstream
    if args.detect_only:
        cfg["block_mode"] = False

    ctx = Context(cfg)
    server = WAFServer((cfg["listen_host"], cfg["listen_port"]), ctx)
    mode = "block" if cfg["block_mode"] else "detect-only"
    print(f"webwaf listening on {cfg['listen_host']}:{cfg['listen_port']} "
          f"-> {cfg['upstream']} (mode: {mode})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
