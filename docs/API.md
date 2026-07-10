# HLSE HTTP API & Web Dashboard

`hlse-server` is a small, dependency-free HTTP/1.1 server (POSIX sockets +
libc + pthreads) that exposes the HLSE detection engine as a JSON API and
serves a local web dashboard. It links the same engine the CLI uses — no
separate detection logic, no third-party runtime.

## Running

```sh
make server                 # builds ./hlse-server
./hlse-server               # http://127.0.0.1:8080  (loopback only)
./hlse-server --host 127.0.0.1 --port 8080 --webroot ./web
```

Open `http://127.0.0.1:8080` for the dashboard, or call the API directly.

| Flag | Default | Meaning |
|------|---------|---------|
| `--host ADDR` | `127.0.0.1` | Bind address. Loopback by default; bind elsewhere only behind your own auth/TLS terminator. |
| `--port N` | `8080` | Listen port. |
| `--webroot DIR` | `./web` | Directory holding `index.html`, `app.js`, `style.css`. |

## Endpoints

All responses are `application/json; charset=utf-8` unless noted. Every
response carries hardening headers (`Content-Security-Policy`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`).

### `GET /api/v1/health`
```json
{ "status": "ok", "engine": "1.0.113", "server": "1.0.0" }
```

### `GET /api/v1/version`
```json
{ "version": "1.0.113" }
```

### `POST /api/v1/scan/url`
Body: `{ "url": "https://..." }`

```sh
curl -s localhost:8080/api/v1/scan/url \
  -d '{"url":"https://paypal.com@evil.xyz/login"}'
```
```json
{
  "kind": "url",
  "score": 100,
  "severity": 4,
  "action": "ISOLATE",
  "reasons": [
    "URL credential trick: @ in authority — displayed host is fake, real host follows @",
    "High-risk TLD: .xyz"
  ]
}
```

`severity` maps to `action`: `0 SAFE`, `1 LOG`, `2 ALERT`, `3 BLOCK`, `4 ISOLATE`.

### `POST /api/v1/scan/text`
Body: `{ "text": "..." }` — scans a message for scam/phishing language.
Same response shape as `/scan/url` with `"kind":"text"`.

### `POST /api/v1/scan/secrets`
Body: `{ "text": "..." }` — scans code/config for leaked credentials.
```json
{
  "kind": "secrets",
  "score": 100,
  "findings": [
    { "type": "AWS Access Key ID", "detail": "AWS Access Key ID found: AKIA2E3M..." }
  ]
}
```

### `POST /api/v1/scan/file`
Body: `{ "filename": "...", "content": "..." }` — combines name-based masquerade
detection (double extensions, RLO tricks) with a leaked-secret scan of the file
content. The client sends the claimed filename and the file text; nothing is
stored server-side.
```json
{
  "kind": "file",
  "filename": "invoice.pdf.exe",
  "score": 85,
  "severity": 4,
  "action": "ISOLATE",
  "reasons": ["F1: DOUBLE EXTENSION — '.pdf.exe' disguised as .pdf"],
  "secrets": [ { "type": "AWS Access Key ID", "detail": "..." } ]
}
```

## Errors

| Status | When |
|--------|------|
| `400 Bad Request` | Malformed request line, or missing/invalid JSON field. |
| `404 Not Found` | Unknown route or asset. |
| `405 Method Not Allowed` | Method other than GET/HEAD/POST. |
| `413 Payload Too Large` | Request body exceeds 64 KiB. |
| `429 Too Many Requests` | More than 300 requests from one source IP within 60s (`Retry-After: 60`). |
| `503 Service Unavailable` | More than 64 simultaneous connections; retry shortly (`Retry-After: 1`). |

Error bodies are `{ "error": "<message>" }`.

## Rate limiting

Each source IP is limited to `RATE_LIMIT_MAX` requests (default 300) per
`RATE_LIMIT_WINDOW_S` seconds (default 60) — a fixed-window counter in a small
mutex-guarded table, checked in the accept loop before a thread is spawned or
the detection engine runs. Exceeding it returns `429` with `Retry-After: 60`;
the source IP is logged as `RATE-LIMIT <ip> -> 429`. This is a defense-in-depth
limiter for a single runaway or abusive source, not a precise multi-tenant
quota system — see `hlse_server.c` for the exact eviction behavior when many
distinct IPs are active at once.

## Concurrency

Each accepted connection is handled on its own detached thread, capped at 64
simultaneous connections (`MAX_CONCURRENT` in `hlse_server.c`). A connection
beyond the cap gets an immediate `503` from the accept loop — no thread is
spawned, so a burst can't exhaust memory or file descriptors. This is safe
because every request handler only reads `static const` engine tables
(`hlse_scan()` / `hlse_scan_secrets()` / `hlse_check_filename()` are
documented thread-safe) and all per-request state lives in a stack-allocated
context — there is no shared mutable state in the request path to race on.

## Security notes

- **Loopback by default.** The server binds `127.0.0.1`; it performs no
  authentication and is intended as a local tool. To expose it, place it
  behind a reverse proxy that terminates TLS and handles auth.
- **No path traversal.** Static assets are served through a fixed three-route
  allowlist (`/`, `/app.js`, `/style.css`); the request path is never used to
  build a filesystem path.
- **Bounded input.** Request bodies are capped at 64 KiB.
- **Per-IP rate limiting.** 300 requests per 60s per source IP; see above.
- **Single detection engine.** Verdicts come from `hlse_scan()` /
  `hlse_scan_secrets()` — identical to the CLI. Nothing is sent off-host.
- The JSON request parser, output escaper, and rate limiter are unit-tested
  (`tests/hlse_server_tests.c`); the running server is smoke-tested end-to-end
  by `tests/server_integration.sh` (`make server-check`). The JSON parser is
  also fuzzed (`tests/hlse_server_fuzz.c`, part of `make fuzz`/`make
  fuzz-asan`) — it is the only parser in HLSE that consumes bytes directly
  from a network peer, so it gets the same fuzzing rigor as the URL/text/
  secrets/supply/file modules.
- **Observability.** Every request is logged to stdout as
  `<iso-8601> METHOD path -> status`.
