# webwaf

A small web application firewall (WAF) written in Python using only the standard
library. It runs as a reverse proxy: visitors connect to webwaf, webwaf inspects
each request, blocks the suspicious ones, and forwards the rest to your real app.

## Quick start

```bash
# 1. Create a config (optional; defaults work for a local test)
python3 waf.py --print-default-config > waf.json

# 2. Edit "upstream" in waf.json to point at your app, e.g. http://127.0.0.1:8000
# 3. Start the WAF (listens on port 8080 by default)
python3 waf.py --config waf.json

# Try it out (should be blocked with 403)
curl -i "http://localhost:8080/?q=<script>alert(1)</script>"

# Run the tests
python3 -m unittest -v test_waf
```

Start in detect-only mode first (`--detect-only`, or `"block_mode": false`). It logs
what it would have blocked without blocking anything, so you can find false positives
before enforcing.

## What it protects against

| Rule ID   | Detects                                              |
|-----------|------------------------------------------------------|
| SQLI-001..004 | UNION, boolean, stacked and time-based SQL injection |
| XSS-001..004  | `<script>`, inline event handlers, `javascript:` URIs, script-capable tags |
| TRAV-001..002 | Path traversal and access to `/etc/passwd`-style files |
| CMD-001   | Shell command injection after `;`, `|`, `&&`, backticks, `$(` |
| RFI-001   | `php://`, `phar://` and similar stream wrappers       |
| SCAN-001  | sqlmap, nikto, nmap, nuclei and other scanner user agents |

Input is URL-decoded up to three times before matching, so double-encoded payloads
like `%253Cscript%253E` are caught.

Other protections: per-IP rate limiting with temporary bans, IP denylist and
allowlist (CIDR), HTTP method allowlist, request body size limit, security response
headers (`nosniff`, `X-Frame-Options`, `Referrer-Policy`), and a JSON-lines audit log.

## Configuration reference

| Key | Default | Meaning |
|-----|---------|---------|
| `listen_host` / `listen_port` | `0.0.0.0` / `8080` | Where the WAF listens |
| `upstream` | `http://127.0.0.1:8000` | The app being protected |
| `upstream_timeout` | `30` | Seconds to wait for the app |
| `block_mode` | `true` | `false` = detect only |
| `allowed_methods` | GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS | Others get 405 |
| `max_body_bytes` | `1048576` | Larger bodies get 413 |
| `inspect_body` | `true` | Scan request bodies too |
| `rate_limit` | 100 requests / 10 s, 300 s ban | Per client IP |
| `ip_denylist` | `[]` | CIDRs always refused (403) |
| `ip_allowlist` | `[]` | If non-empty, only these CIDRs may connect |
| `trust_x_forwarded_for` | `false` | Only enable behind your own trusted proxy |
| `disabled_rules` | `[]` | Rule IDs to switch off, e.g. `["SQLI-002"]` |
| `security_headers` | see file | Headers added to every response |
| `log_file` | `waf.log` | JSON-lines audit log; empty string logs to stdout |

## Audit log

Every request produces one line, for example:

```json
{"time": "2026-11-07T23:50:01+00:00", "id": "9f2c1a7e04bb", "ip": "203.0.113.7", "method": "GET", "path": "/search?q=...", "action": "blocked", "rules": ["SQLI-001"]}
```

`action` is one of `allowed`, `detected` (detect-only mode), `blocked`, `denied_ip`,
`rate_limited`, `method_not_allowed`, `body_too_large`, `unsupported_encoding`,
`bad_request`, or `upstream_error`. The `id` also appears in the response body
(`Request ID: ...`) and in the `X-Request-ID` header sent to your app, so you can
match a user's complaint to its log entry.

## Deploying it properly

- **Put TLS in front.** webwaf speaks plain HTTP. Terminate HTTPS with Caddy, nginx
  or a cloud load balancer, and forward to webwaf. Those tools can also set
  `X-Forwarded-For`. If you do, set `trust_x_forwarded_for: true`.
- **Run it as a service** (systemd, Docker, or similar) so it restarts on failure.
- **Keep the app itself private.** Bind your app to `127.0.0.1` so the only path in
  is through the WAF.
- **Tune before enforcing.** Run in detect-only mode for a few days, review the log,
  then disable rules that cause false positives.

## Limitations (please read)

- This is pattern-based filtering. It stops common, automated attacks and many
  basic exploit attempts. It does **not** stop every attack. A determined attacker
  can find encodings or logic flaws that signatures miss. Fixing the application
  (parameterized queries, output escaping, authentication checks) is still the real
  defense.
- It is not a DDoS shield. The rate limiter helps against a single abusive client,
  but large volumetric floods need a network-level service such as Cloudflare or your
  hosting provider's protection.
- Chunked request bodies are refused with 501. Responses are buffered in memory, so
  very large downloads are not a good fit.
- It runs as one process with a thread per connection. It suits small and medium
  sites. For high traffic, use nginx or Caddy with ModSecurity and the OWASP Core
  Rule Set.
- Rules can produce false positives (for example, text that contains `' and x=`).
  Use detect-only mode and `disabled_rules` to tune them.

## Files

- `waf.py` - the firewall (single file, standard library only)
- `test_waf.py` - automated tests (`python3 -m unittest -v test_waf`)
- `README.md` - this file
