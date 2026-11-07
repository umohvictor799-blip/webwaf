"""Tests for webwaf. Run with: python3 -m unittest -v test_waf"""

import json
import os
import threading
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

from waf import Context, Inspector, RateLimiter, WAFServer, load_config, normalize


class EchoHandler(BaseHTTPRequestHandler):
    """Stands in for the protected application: echoes what it received."""
    protocol_version = "HTTP/1.0"

    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        out = json.dumps({
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "body": body.decode("utf-8", "replace"),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("X-Seen-XFF", self.headers.get("X-Forwarded-For", ""))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_PUT = _reply

    def log_message(self, fmt, *args):
        pass


def request(port, method, path, body=None, headers=None):
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
    finally:
        conn.close()


class WAFTestBase(unittest.TestCase):
    overrides = {}

    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()

        cfg = load_config(None)
        cfg["upstream"] = f"http://127.0.0.1:{cls.upstream.server_address[1]}"
        cfg["log_file"] = os.devnull
        cfg.update(cls.overrides)
        cls.ctx = Context(cfg)
        cls.waf = WAFServer(("127.0.0.1", 0), cls.ctx)
        threading.Thread(target=cls.waf.serve_forever, daemon=True).start()
        cls.port = cls.waf.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.waf.shutdown()
        cls.waf.server_close()
        cls.upstream.shutdown()
        cls.upstream.server_close()


class ForwardingTests(WAFTestBase):
    def test_get_is_forwarded(self):
        status, _, data = request(self.port, "GET", "/hello?x=1")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["path"], "/hello?x=1")

    def test_post_body_is_forwarded(self):
        status, _, data = request(self.port, "POST", "/form", body=b'{"name": "Ada"}',
                                  headers={"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["body"], '{"name": "Ada"}')

    def test_security_headers_added(self):
        _, headers, _ = request(self.port, "GET", "/")
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["x-frame-options"], "SAMEORIGIN")

    def test_host_header_rewritten_to_upstream(self):
        status, _, data = request(self.port, "GET", "/", headers={"Host": "public.example.com"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["host"], f"127.0.0.1:{self.upstream.server_address[1]}")

    def test_client_ip_appended_to_forwarded_for(self):
        _, headers, _ = request(self.port, "GET", "/",
                                headers={"X-Forwarded-For": "203.0.113.7"})
        self.assertEqual(headers["x-seen-xff"], "203.0.113.7, 127.0.0.1")


class BlockingTests(WAFTestBase):
    def assertBlocked(self, status):
        self.assertEqual(status, 403)

    def test_union_sqli_in_query_blocked(self):
        status, _, data = request(self.port, "GET",
                                  "/search?q=" + quote("1 UNION SELECT password FROM users"))
        self.assertBlocked(status)
        self.assertIn(b"Request ID", data)

    def test_script_tag_in_body_blocked(self):
        status, _, _ = request(self.port, "POST", "/comment",
                               body=b"text=<script>alert(1)</script>")
        self.assertBlocked(status)

    def test_path_traversal_blocked(self):
        status, _, _ = request(self.port, "GET", "/files?f=../../etc/passwd")
        self.assertBlocked(status)

    def test_double_encoded_xss_blocked(self):
        status, _, _ = request(self.port, "GET", "/?q=%253Cscript%253E")
        self.assertBlocked(status)

    def test_scanner_user_agent_blocked(self):
        status, _, _ = request(self.port, "GET", "/", headers={"User-Agent": "sqlmap/1.7"})
        self.assertBlocked(status)

    def test_command_injection_blocked(self):
        status, _, _ = request(self.port, "GET", "/ping?host=x;%20cat%20x")
        self.assertBlocked(status)


class DetectOnlyTests(WAFTestBase):
    overrides = {"block_mode": False}

    def test_malicious_request_is_forwarded_in_detect_mode(self):
        status, _, data = request(self.port, "GET",
                                  "/search?q=" + quote("1 UNION SELECT 1"))
        self.assertEqual(status, 200)
        self.assertIn("UNION", json.loads(data)["path"].upper())


class RateLimitTests(WAFTestBase):
    overrides = {"rate_limit": {"window_seconds": 60, "max_requests": 3, "ban_seconds": 60}}

    def test_fourth_request_is_rate_limited(self):
        for _ in range(3):
            self.assertEqual(request(self.port, "GET", "/")[0], 200)
        status, headers, _ = request(self.port, "GET", "/")
        self.assertEqual(status, 429)
        self.assertIn("retry-after", headers)


class IpPolicyTests(WAFTestBase):
    overrides = {"ip_denylist": ["127.0.0.0/8"]}

    def test_denylisted_ip_is_forbidden(self):
        self.assertEqual(request(self.port, "GET", "/")[0], 403)


class MethodAndSizeTests(WAFTestBase):
    overrides = {"allowed_methods": ["GET", "POST"], "max_body_bytes": 1000}

    def test_disallowed_method_rejected(self):
        status, headers, _ = request(self.port, "PUT", "/")
        self.assertEqual(status, 405)
        self.assertIn("allow", headers)

    def test_oversized_body_rejected(self):
        status, _, _ = request(self.port, "POST", "/", body=b"a" * 5000)
        self.assertEqual(status, 413)

    def test_allowed_request_still_works(self):
        self.assertEqual(request(self.port, "GET", "/")[0], 200)


class RateLimiterUnitTests(unittest.TestCase):
    def test_ban_after_limit_then_expires(self):
        rl = RateLimiter(window=10, max_requests=2, ban_seconds=30)
        self.assertEqual(rl.check("1.2.3.4", now=0), (True, 0))
        self.assertTrue(rl.check("1.2.3.4", now=1)[0])
        allowed, retry = rl.check("1.2.3.4", now=2)
        self.assertFalse(allowed)
        self.assertEqual(retry, 30)
        self.assertFalse(rl.check("1.2.3.4", now=10)[0])
        self.assertTrue(rl.check("1.2.3.4", now=33)[0])

    def test_window_slides(self):
        rl = RateLimiter(window=10, max_requests=2, ban_seconds=30)
        rl.check("a", now=0)
        rl.check("a", now=1)
        self.assertTrue(rl.check("a", now=20)[0])


class InspectorUnitTests(unittest.TestCase):
    def test_normalize_undoes_double_encoding(self):
        self.assertEqual(normalize("%253Cscript%253E"), "<script>")

    def test_normalize_strips_nul_bytes(self):
        self.assertEqual(normalize("uni\x00on"), "union")

    def test_union_select_detected(self):
        hits = Inspector().inspect({"query": ["id=1 union select 1"]})
        self.assertIn("SQLI-001", hits)

    def test_disabled_rule_not_applied(self):
        hits = Inspector(["SQLI-001"]).inspect({"query": ["id=1 union select 1"]})
        self.assertNotIn("SQLI-001", hits)

    def test_benign_text_not_flagged(self):
        hits = Inspector().inspect({
            "path": ["/products/blue-widget"],
            "query": ["page=2&sort=price"],
            "headers": ["Mozilla/5.0 (X11; Linux x86_64)"],
            "body": ['{"name": "Ada", "qty": 3}'],
        })
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
