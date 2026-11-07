# Deploying webwaf

This sets up HTTPS, the WAF and your application with Docker Compose. Caddy
handles certificates and is the only public entry point.

## Requirements
- A Linux server with a public IP (VPS) and Docker + Docker Compose installed
- A domain name whose DNS `A` record points to the server
- Ports 80 and 443 open in the firewall

## Steps

```bash
git clone https://github.com/umohvictor799-blip/webwaf.git
cd webwaf

# 1. Set your domain
echo "SITE_DOMAIN=example.com" > .env

# 2. Replace the placeholder "app" service in docker-compose.yml
#    with your real application (its internal port must match "upstream"
#    in config/waf.json).

# 3. Start everything
docker compose up -d --build

# 4. Check it
curl -I https://example.com        # expect 200 from your app
curl -i "https://example.com/?q=<script>alert(1)</script>"   # expect 403
docker compose logs -f waf          # audit log, one JSON line per request
```

## Operating notes
- Start with `"block_mode": false` in `config/waf.json` and check the logs for false
  positives before enforcing. Then set it back to `true` and run `docker compose restart waf`.
- Disable a noisy rule with `"disabled_rules": ["SQLI-002"]` in the same file.
- `trust_x_forwarded_for` is `true` because Caddy is the only route to the WAF. Do not
  expose the WAF port directly, or clients could spoof their IP.
- Update with `git pull && docker compose up -d --build`.
