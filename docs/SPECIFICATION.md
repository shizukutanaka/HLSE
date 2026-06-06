# HLSE Specification

Formal contract for the HLSE (Human-Layer Security Engine) C reference
implementation. This document is the source of truth for the CLI surface,
scoring model, module behaviour, output formats, and design invariants. A
**Gap Analysis** (§8) lists where the implementation diverged from this spec;
items marked **GAP** are resolved in the same change that introduced this file.

Target version: 0.9.x.

---

## 1. Design invariants

| Invariant | Requirement |
|-----------|-------------|
| Language | C99, portable (Linux + macOS). libc + libm only. |
| Network | **Zero network calls**, ever (CI privacy-tripwire enforced). |
| Allocation | Allocation-light; bounded stack/static buffers; no unbounded input. |
| Determinism | Same input → same verdict. No time/random dependence in scoring. |
| Memory safety | Clean under ASan + UBSan; strict `-Wall -Wextra -Wpedantic -Wshadow -Wconversion`; cppcheck error-gate clean. |
| File I/O | Read-only. Never follow symlinks (`O_NOFOLLOW`); only regular files (`S_ISREG`). |
| Thread-safety | Pure analysis functions (URL/text/secret/file/package) read only static const tables and are reentrant. Filesystem/host functions (protect/audit/network) are process-level. |

## 2. Scoring model

Every detector returns an integer `score` in `0..100`, mapped to an action:

| Score | Action | Meaning |
|-------|--------|---------|
| 0–14 | SAFE | no signal |
| 15–39 | LOG | weak signal, record only |
| 40–59 | ALERT | review |
| 60–79 | BLOCK | block the action |
| 80–100 | ISOLATE | block + isolate |

**Process exit code:** `0` = safe, `1` = threat (`score >= 60`), `2` = usage error.

## 3. CLI contract

`hlse_core [GLOBAL-FLAGS] <subcommand|input> [args]`

### 3.1 Subcommands

| Subcommand | Arguments | Purpose | Library fn | Status |
|------------|-----------|---------|-----------|--------|
| *(none)* | `<url\|text>` | auto-detect URL vs text, scan | `hlse_scan` | ✅ |
| `text` | `"<message>"` | scam/social-engineering text scan | `hlse_check_text` | ✅ |
| `scan` | `<directory>` | recursive secret + file masquerade scan (CI/CD) | `hlse_scan_secrets`, `hlse_check_file` | ✅ |
| `protect` | `<path> [--ransomware\|--smb\|--mbr\|--net]` | ransomware / SMB / MBR / netdrive | `hlse_protect_scan` | ✅ |
| `esp` | `[path]` | EFI System Partition bootkit-string scan (default `/boot/efi`) | `hlse_esp_verify` | ✅ (was undocumented — **GAP-D**) |
| `package` | `<name> [pip\|npm\|cargo\|go]` | package typosquat | `hlse_check_package` | ✅ |
| `paste` | `"<command>"` | pastejacking / ClickFix | `hlse_check_paste` | ✅ |
| `network` | — | ARP / DNS / hosts safety | `hlse_check_network` | ✅ |
| `file` | `<path>` | file masquerade | `hlse_check_file` | ✅ |
| `audit` | — | host hardening audit + hardening index | `hlse_audit_all` | ✅ |
| `secret` | `"<text>"` or `--stdin` | scan a text blob / stdin for leaked credentials | `hlse_scan_secrets` | **GAP-A** |
| `email` | `"<headers>"` or `--stdin` | email-header forensics (SPF/DKIM, spoofing, BEC) | `hlse_check_email_headers` | **GAP-B** |
| `clipboard` | `"<copied>" "<pasted>"` | clipboard crypto-swap (clipper) detection | `hlse_check_crypto_swap` | **GAP-C** |

### 3.2 Global flags

| Flag | Effect |
|------|--------|
| `--json` | machine-readable JSON (schema §5.2) |
| `--sarif` | SARIF 2.1.0 (with `scan <dir>`) for GitHub code scanning |
| `-q`, `--quiet` | exit code only, no stdout |
| `--stdin [--json]` | pipe mode: one input per line |
| `--self-test` | run built-in test cases |
| `--benchmark` | corpus F1 benchmark |
| `--version`, `-V` | version string |
| `-h`, `--help` | usage |

Every subcommand that produces a verdict MUST honour `--json` and MUST be listed
in `print_usage()` and the man page (`hlse.1`).

## 4. Modules

| Module | File | Inputs | Key signals | CLI |
|--------|------|--------|-------------|-----|
| URL phishing | `hlse_core.c` | URL | homoglyph, Punycode/IDN homograph, typosquat, TLD/path, DGA, subdomain spoof | *(none)* |
| Text scam / BEC | `hlse_text.c` | text | urgency, financial bait, authority, ransom, BEC amplifiers; evasion-normalised | `text` |
| Ransomware | `hlse_protect.c` | dir | entropy spike (+magic exclusion), ransom notes, ext mutation, shadow delete | `protect` |
| Boot integrity | `hlse_protect.c` | device / ESP | MBR signature/strings/entropy; ESP ransom/bootkit strings | `protect --mbr`, `esp` |
| Credential leak | `hlse_secrets.c` | text/dir | AWS/GitHub/Stripe/Slack/SSH/.env, placeholder exclusion | `scan`, `secret` |
| Email forensics | `hlse_secrets.c` | headers | SPF/DKIM fail, Reply-To mismatch, display-name spoof, BEC | `email` |
| Clipboard swap | `hlse_secrets.c` | copied,pasted | same-type address swap + vanity look-alike | `clipboard` |
| Supply chain | `hlse_supply.c` | pkg / paste / — | typosquat, pastejacking, ARP/DNS | `package`, `paste`, `network` |
| File masquerade | `hlse_file.c` | path/name | double-extension, magic mismatch, bidi, polyglot | `file` |
| System audit | `hlse_audit.c` | host | SSH/perm/DNS/cron + hardening index | `audit` |

## 5. Output formats

### 5.1 Human
`<ACTION> [<score>]  <subject>` followed by ` · <reason>` lines, or `OK    <subject>` when safe.

### 5.2 JSON (`--json`)
Object with a `"kind"` discriminator and `"score"`; reason/finding arrays vary by kind:
- `url`/`text`/`network`/`paste`/`protect`/`esp`: `{kind, score, reasons:[...]}` (+`action` where present)
- `package`: `{kind, name, score, matches:[{name,registry,distance}]}`
- `audit`: `{kind, score, hardening_index, hardening_band, findings:[{severity,description}]}`
- `secret`: `{kind, score, findings:[{type,description}]}`
- `email`: `{kind, score, reasons:[...]}`
- `clipboard`: `{kind, score, is_swap, original, swapped, reason}`

### 5.3 SARIF (`--sarif scan <dir>`)
SARIF 2.1.0 with rule definitions and `security-severity`.

## 6. Library API
All public functions are declared in the module headers (`hlse_core.h`,
`hlse_text.h`, `hlse_protect.h`, `hlse_secrets.h`, `hlse_supply.h`,
`hlse_file.h`, `hlse_audit.h`, `hlse_util.h`). Every CLI subcommand is a thin
wrapper over one of them; there MUST be no detection logic reachable only from
the CLI.

## 7. Build / test contract
`make all` (CLI + shared lib), `make static` (`-static-pie`), `make test`
(all suites + property + corpus + CLI integration), `make check-warnings`
(strict, zero), `make asan-test`, `make fuzz` (100K), `make coverage`.
Hardening flags: FORTIFY, stack-protector, PIE, RELRO/BIND_NOW, NX.

## 8. Gap analysis

Comparing §3 against the implementation revealed CLI-exposure gaps: several
documented modules (README "Modules" table) and shipped, tested library
functions had **no CLI subcommand**, so the capability was unreachable from the
binary. Resolved here:

- **GAP-A — `secret`**: `hlse_scan_secrets` was reachable only via a directory
  `scan`; no way to scan a pasted blob / stdin. → add `secret` subcommand.
- **GAP-B — `email`**: `hlse_check_email_headers` (README "Email forensics")
  had no CLI. → add `email` subcommand (arg or `--stdin`).
- **GAP-C — `clipboard`**: `hlse_check_crypto_swap` (incl. the 0.9.3 vanity
  look-alike signal) had no CLI. → add `clipboard <copied> <pasted>`.
- **GAP-D — `esp` documentation**: implemented in 0.9.4 but absent from
  `print_usage()` and `hlse.1`. → document it.

Each resolution is a thin CLI wrapper over the existing library function (per
§6), with `--json` support, usage/man entries, and CLI integration tests.
