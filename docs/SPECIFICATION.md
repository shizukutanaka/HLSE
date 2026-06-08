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
| `text` | `"<message>"` | scam/social-engineering text scan + embedded URL extraction | `hlse_scan` | ✅ |
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
Every object carries a `"kind"` discriminator, an integer `"score"`, and an
`"action"` string (the §2 band: `SAFE`/`LOG`/`ALERT`/`BLOCK`/`ISOLATE`), so a
consumer never has to re-derive the band. Additional fields vary by kind:
- `url`: `target` (the scanned URL), `reasons:[...]`
- `text`: `target` (the scanned string), `reasons:[...]`
- `protect`: `target` (the scanned path), `reasons:[...]`
- `network`/`esp`/`email`: `reasons:[...]`
- `paste`: `signals` (integer count of fired pastejacking signals), `reasons:[...]`
- `package`: `name`, `matches:[{name,registry,distance}]`
- `audit`: `hardening_index`, `hardening_band`, `findings:[{severity,description}]`
- `secret`: `findings:[{type,description}]`
- `clipboard`: `is_swap`, `original`, `swapped`, `reason`
- `file`: `path`, `reasons:[...]`
- streaming `scan` records add `path`/`line`/`url` as applicable (record
  kinds are `url`, `file`, and `secret`).
- `scan` emits a final `kind=scan_summary` terminator:
  `target` (scanned root path), `files_scanned` (integer), `threats` (integer).

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
(strict, zero), `make asan-test`, `make fuzz` (4 harnesses × 100K iterations:
text, secrets, supply-chain, file-masquerade), `make fuzz-asan` (same under
ASan/UBSan, 10K each), `make coverage`.
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

GAP-A..D resolved in 0.9.6. A second audit of §1 against the implementation
found a security-relevant invariant breach:

- **GAP-E — `scan` followed symlinks** (violates §1 "never follow symlinks"):
  the directory walker classified entries with `stat()` (which follows links)
  and read files with `fopen()` (no `O_NOFOLLOW`). A symlinked directory let the
  scan escape the target tree (and risk cycles); a symlinked file such as
  `x.env -> /etc/shadow` was read and scanned for secrets, leaking a file
  outside the tree. → classify with `lstat()` (symlinks become `S_ISLNK` and are
  skipped) and re-open the file with `O_NOFOLLOW` + `S_ISREG` (TOCTOU defence).
  Fixed in 0.9.7. Matches the hardened open pattern already used in
  `hlse_file.c`, `hlse_audit.c`, and the ESP scan.

A third audit, of documented capability vs. implementation, found:

- **GAP-F — Solana not detected**: `hlse_secrets.h` advertised crypto-swap
  support for "BTC, ETH, XMR, SOL, USDT", the `CRYPTO_SOL` enum and the
  `"SOL (Solana)"` name existed, but `detect_crypto_type()` had no Solana
  branch, so a Solana clipper swap was never flagged. → add a base58 32–44
  Solana branch, evaluated last so prefixed/fixed-length formats still win.
  Isolated to the clipboard-swap comparison and the validator (not the
  URL/text path), so F1 is unaffected. Fixed in 0.9.8.

A fourth audit, of §5.2, found:

- **GAP-G — inconsistent JSON `action`**: only 4 of 12 JSON kinds (`url`,
  `text`, `protect`, `esp`) emitted the `action` band; the other 8 plus the
  streaming `scan` records omitted it, forcing consumers to re-derive the band
  from `score`. → emit `"action"` (from `hlse_action_for_score`) on every
  score-bearing JSON object. Fixed in 0.9.9.

A fifth audit, of README numeric claims vs measured reality, found:

- **GAP-H — stale README numbers**: "Structured tests: 237" and "Binary size:
  53 KB (dynamic), 932 KB (static)" no longer matched reality (≈328 checks;
  ≈140 KB dynamic / ≈1.0 MB static-pie after the feature and hardening work).
  The detection/evasion example claims, F1, and 0% FP all verified accurate.
  → update the counts to a non-drifting `320+` and the sizes to measured
  approximate values; drop the brittle exact "237" from the `make test`
  comment. Docs-only; fixed in 0.9.10.

A sixth audit, of §7 (build/test contract) against the fuzz harness coverage, found:

- **GAP-I — fuzz coverage only for `hlse_text.c`**: `tests/hlse_fuzz.c`
  exercised only `hlse_check_text()`; the five other parser modules
  (`hlse_secrets.c`, `hlse_supply.c`, `hlse_file.c`) had zero fuzz coverage,
  leaving their string-parsing paths unverified under pathological input.
  → add three portable smoke-fuzz harnesses following the same pattern
  (deterministic PRNG, signal-handler crash detection, score-range assertion):
  - `tests/hlse_secrets_fuzz.c` — covers `hlse_scan_secrets`,
    `hlse_check_email_headers`, `hlse_check_crypto_swap`,
    `hlse_validate_crypto_address` (4 entry points, 4 input generators:
    random bytes, credential fragments, email headers, crypto addresses)
  - `tests/hlse_supply_fuzz.c` — covers `hlse_check_package`,
    `hlse_check_paste` (2 entry points, 3 generators: random bytes,
    typosquat-mutated package names, pastejacking commands)
  - `tests/hlse_file_fuzz.c` — covers `hlse_check_filename` (the
    disk-free entry point; 1 entry point, 4 generators: random bytes,
    double-extension, bidi/control characters, social-engineering lures)
  Each harness runs 100K iterations (10K under ASan). New Makefile targets:
  `make fuzz` now runs all four harnesses; `make fuzz-asan` runs all four
  under ASan/UBSan. Fixed in 0.9.11.

A twelfth audit, of cross-subcommand JSON schema consistency (§5.2), found:

- **GAP-P — `scan` `secret` records used wrong schema**: the `scan` walker's
  `--json` branch for secret findings emitted `"reasons":["description"...]`
  (a flat string array) while the standalone `secret` subcommand correctly
  emitted `"findings":[{"type":"...","description":"..."}]`. Spec §5.2
  defines `kind=secret` exclusively with `findings:[{type,description}]`.
  Both `kind=secret` contexts now emit the same structured schema. Confirmed
  all other JSON kinds (`audit`, `file`, `protect`, `esp`, `email`,
  `clipboard`, `package`, `paste`, `network`) match their spec §5.2
  definitions. Fixed in 0.9.18.

An eleventh audit, of the SARIF output (§5.3) and scan JSON records (§5.2), found:

- **GAP-O — SARIF rule definitions missing `security-severity`; scan `url`
  records missing `reasons`**: (a) the SARIF `tool.driver.rules` array had
  no `properties.security-severity` on rule definitions — GitHub code
  scanning requires this to classify severity; individual results had the
  field but rules did not. Fixed by adding `security-severity` per rule
  (`secret`=9.0, `file-masquerade`=8.0, `phishing-url`=7.5) and improving
  `shortDescription` text. (b) When the `scan` walker detected a phishing
  URL inside a source file, the `--json` `url` record omitted `"reasons"`
  even though the human output printed them and §5.2 mandates `reasons:[...]`
  on every `url` kind. Fixed in 0.9.17.

A tenth audit, of the JSON output path vs. the human-readable path, found:

- **GAP-N — `--json text` ignores embedded URL extraction**: when text input
  contained an embedded phishing URL (e.g. `"click https://paypa1.com/signin"`),
  the human-readable `text` subcommand path called `hlse_scan()` (which runs
  embedded URL extraction and returns score 60), but the `--json` path
  redundantly called `hlse_check_text()` alone (which returns score 0 for
  the same input). The same divergence existed in the auto-detect JSON path.
  Both were already computing `ScanResult sr = hlse_scan(...)` before the
  `json_out` branch — the fix reuses `sr` to build the `TextVerdict` rather
  than discarding it and re-calling `hlse_check_text`. A regression test was
  added to CLI integration. Fixed in 0.9.15.

A ninth audit, of the `print_usage()` output vs. spec §3.2 global flags, found:

- **GAP-L — `-h | --help` absent from its own help output**: spec §3.2 lists
  `-h`, `--help` as a global flag; all other 7 flags appeared in the "Options"
  block of `print_usage()` but `--help` itself did not. → added
  `%s -h | --help  Show this help` as the last option line. Code-only (no
  detection change), 1 `printf` arg added. Fixed in 0.9.14.

An eighth audit, of the README "C library API" section vs. `nm -D libhlse.so`, found:

- **GAP-K — stale library export count and incomplete API example**: the
  README claimed "29 functions exported in `libhlse.so`"; `nm -D libhlse.so`
  reports 35 (additions since the original count: `hlse_esp_verify`,
  `hlse_audit_hardening_index`, `hlse_validate_crypto_address`,
  `hlse_is_high_entropy_benign_magic`, `hlse_shannon_entropy_str`,
  `hlse_text_action_for_score`). The code snippet also omitted `hlse_util.h`,
  `hlse_scan_secrets`, `hlse_check_email_headers`, `hlse_check_crypto_swap`,
  `hlse_esp_verify`, and `hlse_audit_hardening_index`, so a reader of the README
  had no example of using six of the twelve CLI-visible entry points as library
  calls. The "All pure functions, thread-safe" line was also inaccurate —
  filesystem/host functions (`protect`, `audit`, `network`) are process-level,
  not reentrant. → update count to 35, add missing examples, correct
  thread-safety note. §7 `make fuzz (100K)` also updated to `4 × 100K`.
  Docs-only; fixed in 0.9.13.

A seventh audit, of the README "Test architecture" table vs. measured suite
counts, found:

- **GAP-J — stale test-architecture table**: the per-suite counts had drifted
  far from reality (table said Unit-URL 13 / Unit-text 14 / Property 60 /
  Secrets 20 / File-Audit 14 / CLI 45; actual is 23 / 15 / 64 / 25 / 17 / 86),
  and two whole suites — `util_tests` (14) and the out-of-distribution corpus
  (25) — were missing from the table; the Fuzz row predated GAP-I (one text
  harness, now four). The at-a-glance `320+` floor was re-verified and still
  holds (≈303 suite/corpus checks + 36 in-distribution benchmark cases ≈ 339).
  → refresh every row to the measured count, add the `Util` and `OOD corpus`
  rows, and update the Fuzz row to `4 × 100K`. Docs-only; fixed in 0.9.12.

An eleventh audit, of the exit-code contract vs. actual CLI behaviour, found:

- **GAP-Q — `secret` and `email` subcommands returned exit=0 instead of exit=2
  when invoked with no argument in CI/non-interactive environments**: both used
  `!isatty(0)` to fall through to stdin reading. In CI, stdin is not a tty even
  without a pipe, so they silently scanned empty input and returned exit=0.
  Spec §3 requires exit=2 for a usage error. Fixed to require explicit text
  argument or explicit `--stdin`; regression tests added. Fixed in 0.9.19.

A twelfth audit, of SARIF output compliance vs. the SARIF 2.1.0 standard, found:

- **GAP-R — `artifactLocation.uri` emitted absolute paths**: `scan --sarif`
  used the full `fullpath` (e.g. `/repo/src/file.py`) as the URI value.
  GitHub code scanning requires relative URIs relative to the checkout root
  so it can map findings back to source files. Fixed by stripping the scan
  root prefix before passing to `sarif_add()`. Regression test added.
  Fixed in 0.9.20.

A thirteenth audit, of CI infrastructure vs. README claims, found:

- **GAP-S — CI workflows missing despite README privacy-tripwire claim**:
  the README §Privacy section stated "CI enforces this with a privacy tripwire
  job" but no `.github/workflows/` directory existed. Created `ci.yml`
  (build/test + cppcheck error gate + strace-based privacy tripwire) and
  `codeql.yml` (CodeQL C/C++ with security-and-quality queries). The workflow
  files require a GitHub App token with `workflows` permission to push; they
  are version-controlled under `examples/workflows/` for manual install
  (the App token cannot write `.github/workflows/` directly). Fixed in 0.9.21.

A fourteenth audit, of each `--json` kind's actual field set vs. the §5.2
field inventory, found:

- **GAP-T — `paste` JSON emits an undocumented `signals` field**: the `paste`
  kind carries an integer `signals` (count of fired pastejacking signals)
  alongside `reasons`, but §5.2 listed only `reasons` for `paste`. Consistent
  with `audit` (which documents its extra `hardening_index` integer), the
  `signals` field is now documented in §5.2. All other eleven kinds
  (`url`, `text`, `network`, `protect`, `esp`, `email`, `package`, `audit`,
  `secret`, `clipboard`, `file`) were verified to match their §5.2 inventories
  exactly. Docs-only; fixed in 0.9.22.

A fifteenth audit, using a strict §5.2 baseline (no implicit fields), found:

- **GAP-U — `url`, `text`, and `protect` emit an undocumented `target` field**:
  all three kinds include a `target` string (the scanned URL, text string, or
  directory path respectively) in their JSON output. Spec §5.2 grouped these
  kinds with `network`/`esp`/`email` under a single `reasons:[...]` bullet,
  omitting `target`. Since `target` is the natural echo of the input and is
  consumed by tools and dashboards (it disambiguates which record corresponds
  to which scan), it is documented rather than removed. §5.2 is now split
  to list `url`, `text`, and `protect` separately with their `target` fields.
  `network`, `esp`, and `email` have no `target` equivalent and remain
  grouped. Docs-only; fixed in 0.9.23.

A sixteenth audit, of the §3.1 subcommand table's "Library fn" column vs.
the actual call in `hlse_core.c`, found:

- **GAP-V — `scan --json` missing `scan_summary` terminator from spec §5.2**:
  documented; fixed in 0.9.24.

- **GAP-W — `text` subcommand table lists wrong library function**: the §3.1
  table said `hlse_check_text` but the code was changed to `hlse_scan()` in
  GAP-N (0.9.15) to add embedded URL extraction. The purpose column was also
  updated to mention embedded URL extraction. Docs-only; fixed in 0.9.25.

A seventeenth audit, of CONTRIBUTING.md vs. the current test suite, found:

- **GAP-X — CONTRIBUTING.md had three stale test counts and an incomplete
  test-axis table**: "200+ tests" (actual: 320+), "7 suites" (actual: 8 —
  util_tests added in 0.9.12), "100K fuzz" (actual: 4 × 100K since GAP-I).
  The "Six-axis" section listed only 4 of 7 axes — Behavioral tests, CLI
  integration, and Fuzz harnesses were missing, leaving contributors with no
  guidance on when to add tests there. Updated counts, renamed to
  "Seven-axis", and extended the table to all 7 axes. Docs-only;
  fixed in 0.9.26.

Each resolution is a thin CLI wrapper over the existing library function (per
§6) or an invariant/coverage/consistency/accuracy fix, with tests where code
changed.
