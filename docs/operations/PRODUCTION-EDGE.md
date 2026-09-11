# Production Edge — TLS, Reverse Proxy & Trusted Headers (RC2 §19)

**Status: DESIGN (not deployed in this round).** The Demo stack is unchanged:
it binds every published port to `127.0.0.1` and terminates nothing. This
document is the required production-edge design + working example configs.
No part of this file was validated against a real public deployment; it is a
design deliverable, and the final report keeps it `PARTIAL / NOT CERTIFIED`.

---

## 1. The one rule

> **Never expose the FastAPI port (default `8000`) or PostgreSQL (`5432`)
> directly to an untrusted network.**

The backend ships with token-based RBAC and a fail-closed production gate —
it does **not** ship with TLS, rate limiting, or an account system. Those
belong at the edge. In `DEPLOYMENT_MODE=production` the application refuses to
boot unless it is behind a loopback bind (`BIND_HOST=127.0.0.1`) with auth
configured, and it *forbids* tokenless approval (see
[SECURITY.md](../../SECURITY.md) and the fail-closed startup gate in
`backend/app/core/runtime_mode.py`).

## 2. Reference topology

```
browser ──HTTPS──▶ edge (nginx / Caddy / cloud LB)
                    │  TLS termination, HSTS, security headers,
                    │  rate limits, request-size limits
                    ├──▶ static SPA          (frontend container, :80)
                    └──▶ /api, /health, /ready ──▶ backend :8000  (loopback only)
                                                        │
                                                        └▶ postgres :5432 (compose network only)
```

- Only the edge listens on a public address. Everything else stays on the
  Docker network / loopback.
- The SPA and the API stay on **one origin** (`https://sf.example.com`):
  the frontend nginx already proxies `/api/` to the backend
  (`frontend/nginx.conf`), so the browser never makes a cross-origin request.

## 3. TLS termination

- Terminate TLS at the edge; forward plain HTTP only over the compose
  network / loopback.
- Minimum **TLS 1.2**, prefer **TLS 1.3**; disable renegotiation and
  compression.
- Use a real certificate (Let's Encrypt / corporate PKI). Do not use
  self-signed certificates for anything beyond a lab.
- Enable **HSTS** only after the certificate is stable:
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
- Redirect HTTP → HTTPS at the edge (except an explicit ACME challenge path).

## 4. Trusted headers — where identity does and does NOT come from

Frozen RC2 boundary: **the approval/execution/reconcile identity comes ONLY
from the authenticated Bearer token** (`OPERATORS_JSON`), resolved
server-side. Request-body `operator` / `reviewer` fields are ignored by
design. Therefore:

- A forged `X-Forwarded-*` header can never elevate identity — there is no
  code path that trusts it for auth.
- The edge MUST still **overwrite** inbound hop-by-hop/forwarding headers
  (`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` etc.) so
  downstream logs and diagnostics see the real client, not a client-supplied
  lie.
- If you add an SSO / trusted-proxy *principal* integration in the future, it
  must be implemented as an explicit, documented trust boundary — request
  headers alone are not an auth mechanism.

## 5. Auth boundary at the edge

- The backend implements the RBAC (viewer / reviewer / executor / admin).
  The edge must **not** invent a second, weaker gate.
- Rate-limit the write paths hardest (`POST /api/v1/ai-response-approvals/...`,
  `POST /api/v1/executions`, reconcile endpoints) — they are the only paths
  that can eventually trigger a real external action.
- Issue one Bearer token per human, keep it out of URLs/logs, rotate it on
  personnel change (`OPERATORS_JSON` is static config in RC2; rotation = edit
  and restart).
- Full RBAC split (approval ≠ execution ≠ reconcile ≠ admin) is enforced in
  the application; the edge is just the delivery path.

## 6. Rate limiting

Rate-limit at the edge per source IP (adapt numbers to your environment):

| Path class | Suggested rate | Burst |
|---|---|---|
| `POST /api/v1/ai-response-approvals/*/approve|reject` | 5 r/min | 3 |
| `POST /api/v1/executions` | 10 r/min | 5 |
| `POST /api/v1/alerts` (ingestion) | 600 r/min | 200 |
| everything else (reads) | 120 r/min | 60 |

nginx: `limit_req_zone` + `limit_req`. Caddy: `rate_limit` plugin (or an
upstream LB). Cloud LB/WAF is acceptable too — the requirement is *some*
abuse ceiling on the write paths.

## 7. Request size limits

- Edge cap: `client_max_body_size 2m;` is generous for this API (alerts are
  small JSON documents). Tighten for your reality.
- Keep a per-endpoint sanity check in the application as defense in depth
  (FastAPI/Pydantic already rejects malformed bodies with 422).

## 8. CORS

- **Default: none, on purpose.** One origin (SPA + same-origin `/api`)
  means no CORS middleware is needed, and the application deliberately adds
  no permissive CORS.
- If you *must* split origins (e.g. `app.example.com` + `api.example.com`),
  add an explicit allow-list at the backend or edge — never `*`, and never
  `allow_credentials` with a wildcard. Treat it as a reviewed change with
  tests.

## 9. Security headers (set at the edge)

```
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: DENY                    # or CSP frame-ancestors 'none'
Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

(The SPA is a static React bundle served from the same origin; the CSP above
matches its actual needs — no CDNs, no inline scripts beyond styles.)

## 10. nginx example (complete server block)

```nginx
# ---- rate limit zones (http{} context) ----
limit_req_zone $binary_remote_addr zone=sf_writes:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=sf_reads:10m  rate=120r/m;
limit_req_zone $binary_remote_addr zone=sf_ingest:10m rate=600r/m;

server {
    listen 443 ssl;
    http2 on;
    server_name sf.example.com;

    ssl_certificate     /etc/letsencrypt/live/sf.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sf.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header X-Frame-Options DENY always;

    client_max_body_size 2m;

    # Static SPA + same-origin API proxy live INSIDE the compose network.
    location / {
        limit_req zone=sf_reads burst=60 nodelay;
        proxy_pass http://frontend:80;
        proxy_set_header Host $host;
    }

    # The hard write paths get their own stricter zones.
    location ~ ^/api/v1/ai-response-approvals/.+/(approve|reject)$ {
        limit_req zone=sf_writes burst=3 nodelay;
        proxy_pass http://frontend:80;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location = /api/v1/executions {
        limit_req zone=sf_writes burst=5 nodelay;
        proxy_pass http://frontend:80;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location = /api/v1/alerts {
        limit_req zone=sf_ingest burst=200 nodelay;
        proxy_pass http://frontend:80;
        proxy_set_header Host $host;
    }
    location /api/ {
        limit_req zone=sf_reads burst=60 nodelay;
        proxy_pass http://frontend:80;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location = /health { proxy_pass http://frontend:80; }
    location = /ready  { proxy_pass http://frontend:80; }
}
server {
    listen 80;
    server_name sf.example.com;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}
```

> `frontend` is the compose service name; it proxies `/api`, `/health` and
> `/ready` to `backend:8000` (see `frontend/nginx.conf`). Pointing the edge at
> the frontend keeps a single origin and the existing same-origin design.

## 11. Caddy example (short form)

```caddyfile
sf.example.com {
    encode gzip
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        Referrer-Policy strict-origin-when-cross-origin
        X-Frame-Options DENY
    }
    request_body { max_size 2MB }
    rate_limit { zone sf_global { key {remote_host} events 120 window 1m } }
    reverse_proxy frontend:80
}
```

(Requires the Caddy `rate_limit` plugin build; if it is unavailable, apply
rate limits at your load balancer / WAF instead. TLS and headers work with
stock Caddy.)

## 12. Production checklist (map to the app's own gate)

1. `DEPLOYMENT_MODE=production` and the app **boots** (it will refuse
   otherwise): `OPERATORS_JSON` auth configured, PostgreSQL (not SQLite),
   no tokenless approval, mock/reverse/unsafe settings rejected.
2. `BIND_HOST=127.0.0.1` — the edge is the only public listener.
3. TLS certificate valid; HSTS enabled after verification.
4. Security headers and request-size caps in place.
5. Rate limits on approval/execution/ingestion paths.
6. Secrets (`POSTGRES_PASSWORD`, tokens inside `OPERATORS_JSON`) live in
   runtime environment / secret manager — never in the repo, never in logs.
7. Backups scheduled (see [BACKUP-RESTORE.md](BACKUP-RESTORE.md)).
8. Logs aggregated with correlation ids; credentials never logged.

## 13. Explicit non-goals (unchanged by this document)

- No WAF, no SSO/OIDC integration, no mTLS, no HA topology — those are
  deployment-owner choices; this document only fixes the trust boundaries
  the application *requires*.
- Nothing here changes Demo Mode: `docker compose up` on a laptop still
  binds to `127.0.0.1` and stays HTTPS-free.
