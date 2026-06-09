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
  Structured tests:             370 (8 suites + corpus + CLI integration)
  Fuzz iterations:              500,000 (5 harnesses × 100K, 0 crashes)
  ASan + UBSan:                 0 errors
  Compiler warnings:            0 (-Wall -Wextra -Wpedantic -Wshadow -Wconversion)

Binary size:   ~140 KB (dynamic, stripped), ~1.0 MB (static-pie, stripped)
Dependencies:  libc + libm only
Platform:      Linux, macOS (partial)
```

## Modules

| Module | File | What it detects |
|--------|------|-----------------|
| **URL phishing** | hlse_core.c | Homoglyph, typosquat, suspicious TLD/path, subdomain spoofing |
| **Text scam** | hlse_text.c | Urgency, financial bait, authority impersonation, ransom, BEC |
| **Ransomware** | hlse_protect.c | Entropy spike, ransom notes, extension mutation, shadow deletion |
| **MBR/GPT** | hlse_protect.c | Boot signature, bootkit strings, obfuscation detection |
| **Credential leak** | hlse_secrets.c | 39 token patterns — AWS (incl. STS), GitHub, GitLab, Google, npm, OpenAI/Anthropic, Stripe, Shopify, HuggingFace, PyPI, Postman, Square, Doppler, Grafana, Linear, New Relic, Databricks, PlanetScale, HashiCorp Vault, Slack/Discord webhooks, SSH keys, .env passwords (Twilio, SendGrid, Firebase, Cloudflare added; excludes doc/example/placeholder keys to cut false positives); clipboard crypto-swap for 11 chains (BTC/ETH/XMR/SOL/USDT-TRC20/LTC/DOGE/XRP/DASH/XLM/ADA) |
| **Email forensics** | hlse_secrets.c | SPF/DKIM fail, Reply-To mismatch, display-name spoofing |
| **Supply chain** | hlse_supply.c | Package typosquat (pip/npm/cargo/go — 229 packages), pastejacking (Unix curl\|sh + Windows ClickFix LOLBins), ARP/DNS safety |
| **File masquerade** | hlse_file.c | Double extensions, magic byte mismatch, suspicious filenames |
| **System audit** | hlse_audit.c | SSH hardening, file permissions, DNS, cron jobs, insecure $PATH, shell-rc backdoors |

## Quick start

```bash
make                                    # build CLI + shared library
make test                               # run all test suites
./hlse_core                             # interactive demo
./hlse_core "https://g00gle.com"        # scan a URL
./hlse_core text "URGENT: wire $5000"   # scan text
./hlse_core package reqeusts pip        # check for typosquat (229 packages)
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
make install    # install to ~/.local/{bin,lib,include/hlse,share/man}

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

HLSE normalizes input through a 5-stage pipeline before keyword
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

35 functions exported in `libhlse.so`. Analysis functions (URL, text,
secret, email, clipboard, file, package, paste) are pure, reentrant, and
zero-allocation. Filesystem/host functions (protect, audit, network) are
process-level.

## Score thresholds

| Score | Action | Meaning |
|-------|--------|---------|
| 0–14 | SAFE | No signals fired |
| 15–39 | LOG | Advisory, log only |
| 40–59 | ALERT | Warn user |
| 60–79 | BLOCK | Block action |
| 80+ | ISOLATE | Quarantine |

## JSON output

Every subcommand supports `--json`:

```bash
./hlse_core --json "https://g00gle.com"
./hlse_core --json package reqeusts pip
./hlse_core --json protect /path
./hlse_core --json audit
```

## Test architecture

| Suite | Count | What it verifies |
|-------|-------|------------------|
| Unit (URL) | 23 | Individual URL detector accuracy (incl. IDN/Punycode homograph) |
| Unit (text) | 15 | Individual text signal accuracy |
| Property invariants | 64 | Monotonicity, bounds, determinism, case, evasion (P1–P13) |
| Protection | 19 | Ransomware, network drive, SMB, MBR/GPT, ESP |
| Secrets | 46 | Credentials (40 token patterns + GCP SA JSON + Azure SAS), email headers (E1-E6 incl. E5 Received-chain anomaly), crypto addresses (BTC/ETH/SOL/XMR/LTC/DOGE/XRP/DASH/XLM/ADA) |
| Supply chain | 27 | Package typosquat, pastejacking (incl. Windows ClickFix + iwr/irm/appinstaller + wscript/wmic/rundll32), network |
| File/Audit | 27 | File masquerade (PE/ELF/Mach-O), system hardening (SSH/perms/DNS/cron/PATH/shell-rc) + hardening index |
| Util | 29 | Entropy, Damerau-Levenshtein, benign-magic (21 formats) + safe system-file open (FIFO/symlink) |
| OOD corpus | 29 | Out-of-distribution F1 (held-out phishing/scam) |
| CLI integration | 90 | All 12 subcommands, JSON action band, exit codes, scan, ESP, symlink-escape, evasion, embedded-URL JSON, SARIF relative URIs, no-arg exit=2 |
| Fuzz | 5 × 100K | text / secrets / supply-chain / file / URL harnesses (random bytes, truncated UTF-8, keyword stuffing, typosquat mutation, bidi/control, Unicode mutation, percent-encoding, dangerous-scheme) |

## Privacy

Zero network calls. Zero file I/O outside stdin/stdout. Zero telemetry.
CI enforces this with a privacy tripwire job.

## Identity anchor

```
bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5
```

Cryptographic identity hash for maintainer verification.

## License

MIT. See [LICENSE](LICENSE).
