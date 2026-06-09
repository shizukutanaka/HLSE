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
| File I/O | Read-only. **Untrusted paths** (directory-scan entries, ransomware-scan files): `O_NOFOLLOW` + `O_NONBLOCK` + `fstat`/`S_ISREG` — never follow attacker-controlled symlinks, never block on a planted FIFO, only read regular files. **Fixed trusted system paths** (`/etc/hosts`, `/etc/resolv.conf`, `/proc/net/arp`, `sshd_config`): `O_NONBLOCK` + `S_ISREG` via `hlse_open_system_file()`; symlinks ARE followed because these are root-owned and legitimately symlinked (e.g. `/etc/resolv.conf` on systemd). |
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
| Credential leak | `hlse_secrets.c` | text/dir | 36 token patterns: AWS(+STS)/GitHub/GitLab/Google/npm/OpenAI/Anthropic/Stripe/Shopify/HuggingFace/PyPI/Postman/Square/Doppler/Grafana/Linear/NewRelic/Databricks/Slack+Discord webhooks/SSH/.env, placeholder exclusion | `scan`, `secret` |
| Email forensics | `hlse_secrets.c` | headers | SPF/DKIM fail, Reply-To mismatch, display-name spoof, BEC | `email` |
| Clipboard swap | `hlse_secrets.c` | copied,pasted | same-type address swap + vanity look-alike | `clipboard` |
| Supply chain | `hlse_supply.c` | pkg / paste / — | typosquat, pastejacking, ARP/DNS | `package`, `paste`, `network` |
| File masquerade | `hlse_file.c` | path/name | double-extension, magic mismatch (PE/ELF/Mach-O), bidi, polyglot | `file` |
| System audit | `hlse_audit.c` | host | SSH/perm/DNS/cron + hardening index | `audit` |

### 4.1 Text-detection property invariants (P1–P13)

The `hlse_text.c` detection engine MUST satisfy all thirteen of the following
properties at every version. `make test` verifies these via
`tests/hlse_property_tests.c`.

| ID | Name | Requirement |
|----|------|-------------|
| P1 | Score monotonicity | Adding a recognised threat signal can only raise the score; removing one can only lower it. |
| P2 | Score bounds | Output is always an integer in `[0, 100]`. |
| P3 | Determinism | Same input → same score on every call, regardless of call order or count. |
| P4 | Case insensitivity | English-language signals are case-folded: `"URGENT"` and `"urgent"` score within 5 points of each other. |
| P5 | Whitespace evasion resistance | Replacing spaces with tabs, newlines, or repeated spaces does not lower a high-scoring input below the detection threshold. |
| P6 | Safe corpus FP ≤ 5% | The top-500 Alexa domains score below the LOG threshold (score < 15), capped at a 5% false-positive rate. |
| P7 | Multilingual parity | Japanese, Chinese, and other CJK scam phrases score ≥ 30 (LOG band), matching English equivalents. |
| P8 | HTML entity evasion | `U&#82;GENT`, `&#x55;RGENT`, and unterminated entities are normalised before scoring; they score the same as the plain text. |
| P9 | Zero-width Unicode evasion | U+200B (zero-width space), U+200D (zero-width joiner), and similar invisible code points are stripped before scoring. |
| P10 | L33tspeak evasion | Common letter-digit substitutions (`3→e`, `1→i`, `$→s`) are normalised. Long hex tokens and currency amounts are preserved. |
| P11 | Cyrillic/Greek homoglyph evasion | Cyrillic look-alikes (е, а, о, і, …) and Greek omicron are mapped to their Latin equivalents before scoring. |
| P12 | Combined evasion resistance | Two or three simultaneous evasion techniques (l33t + HTML entity, Cyrillic + zero-width, triple combo) do not produce a score lower than any single technique alone. |
| P13 | Full-width Unicode evasion | UTF-8 full-width variants of ASCII letters and digits are normalised to ASCII before scoring. |

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

An eighteenth audit, of §4 (Modules) vs. the test suite's property contract, found:

- **GAP-Y — property invariants P1–P13 undocumented in the spec**: spec §7
  stated `make test` runs "all suites + property + corpus + CLI integration"
  but the 13 formal properties the property suite verifies were documented only
  in `tests/hlse_property_tests.c`'s header comment — not in the spec. A reader
  of the spec could not determine what guarantees the text-detection engine must
  uphold (monotonicity, bounds, determinism, evasion-resistance categories,
  safe-corpus FP rate, multilingual parity) without reading the test source.
  Added §4.1 "Text-detection property invariants (P1–P13)" with a table
  enumerating all 13 properties. Docs-only; fixed in 0.9.27.

A nineteenth audit, of the property test file header vs. the actual tests, found:

- **GAP-Z — `tests/hlse_property_tests.c` header listed only P1–P7 while the
  implementation tests P1–P13**: when P8–P13 were added (HTML entity, zero-width
  Unicode, l33tspeak, Cyrillic/Greek homoglyph, combined evasion, full-width
  Unicode), the file header comment was not updated. A reader saw 7 properties
  listed even though 13 were enforced. Updated the header to enumerate all 13,
  consistent with the §4.1 table added in 0.9.27. Docs-only; fixed in 0.9.28.

A twentieth review — a competitive scan of peer open-source tools (gitleaks,
TruffleHog, detect-secrets) against HLSE's credential scanner — found:

- **GAP-AA — credential-pattern coverage lagged peer scanners**: gitleaks ships
  150+ token patterns; HLSE's `SECRET_PATTERNS` table carried 14. The missing
  formats were all high-confidence, distinctive-prefix tokens with negligible
  false-positive risk: Google API Key (`AIza`), GitLab PAT (`glpat-`), npm token
  (`npm_`), OpenAI (`sk-proj-`) and Anthropic (`sk-ant-`) keys, Shopify tokens
  (`shpat_`/`shpss_`/`shppa_`), Stripe restricted key (`rk_live_`), AWS temporary
  STS key (`ASIA`), and GitHub refresh token (`ghr_`). Added 11 entries
  (14 → 25). These live entirely in `hlse_secrets.c`, orthogonal to the
  URL/text F1 corpus, so F1=1.000 is unaffected (verified in- and
  out-of-distribution). 7 new behavioral tests including a prose
  false-positive guard; secrets suite 25 → 32. Fixed in 0.9.32.

- **GAP-AB — second peer-parity batch (9 more token patterns, 25 → 34)**:
  continuing the GAP-AA review, added Hugging Face (`hf_`, letters-only body to
  curb identifier collisions), PyPI (`pypi-AgEIcHlwaS5vcmc` fixed marker),
  Postman (`PMAK-`), Square (`sq0atp-`), Doppler (`dp.pt.`), Grafana (`glsa_`),
  Linear (`lin_api_`), New Relic (`NRAK-`), and Databricks (`dapi`). Same
  orthogonality argument holds — F1=1.000 re-verified in/out-of-distribution;
  scanning HLSE's own source tree confirmed zero false positives from the new
  prefixes. A table-driven detection test plus an extended prose FP guard;
  secrets suite 32 → 33. Fixed in 0.9.33.

- **GAP-AC — Discord webhook URLs undetected (34 → 36)**: the scanner already
  flagged Slack webhook URLs but not Discord, one of the most commonly leaked
  webhook formats. Added `discord.com/api/webhooks/<id>` and
  `discordapp.com/api/webhooks/<id>` (numeric-ID anchored, ~zero FP), completing
  the URL-anchored webhook category. F1=1.000 unaffected; secrets suite
  33 → 34. This concludes the credential-coverage vein — 36 patterns now span
  the major cloud/SaaS/LLM/registry/webhook providers that peer scanners ship.
  Fixed in 0.9.34.

A twenty-first review — a category-by-category robustness audit of every
module against spec §1 (driven by four parallel sub-audits) — found one
systematic gap plus several minor hardening items (most agent-reported
"overflows" were verified FALSE: `hlse_file.c:399` uses signed `ssize_t`
throughout under a `head_len > 100` guard; the email `reasons[]` array
(`HLSE_EMAIL_MAX_REASONS`=8) can hold at most 7 reasons; `extract_domain`'s
output is zero-initialised at declaration):

- **GAP-AD — fixed system-config reads lacked FIFO-block protection**:
  `hlse_audit.c` (sshd_config, /etc/hosts, /etc/resolv.conf, cron
  `file_contains`) and `hlse_supply.c` (/proc/net/arp, /etc/resolv.conf,
  /etc/hosts) opened config files with a bare `fopen()` — no `S_ISREG` guard,
  so a FIFO planted at one of these paths would block `fgets()` indefinitely
  (a local DoS), and non-regular targets were read blindly. Added a shared
  `hlse_open_system_file()` (`hlse_util.c`): `O_RDONLY|O_NONBLOCK` + `fstat` +
  `S_ISREG` + `fdopen`. It deliberately does **not** use `O_NOFOLLOW` — these
  are fixed, root-owned paths that may legitimately be symlinks (notably
  `/etc/resolv.conf` on systemd), where `O_NOFOLLOW` would break a correct
  read; `O_NOFOLLOW` stays reserved for untrusted directory-scan entries.
  Also hardened `read_file_head()` in `hlse_protect.c` (the ransomware-scan
  read path, an untrusted tree) with `O_NONBLOCK` + `S_ISREG` while keeping
  `O_NOFOLLOW`. 4 new `util_tests` cover the helper (regular file opens; FIFO,
  directory, and missing path all rejected without blocking). Spec §1 invariant
  refined to distinguish untrusted vs. fixed-trusted read paths. Minor
  companions: `read_file_head`/MBR scan use `unsigned char` to avoid an
  implementation-defined signed conversion of binary bytes; the
  Damerau-Levenshtein transposition uses the canonical `+1` (behaviour-
  identical). No detection logic changed; F1=1.000 and ASan/UBSan clean.
  Fixed in 0.9.35.

A twenty-second review — a coverage audit of the file-masquerade magic table
(`hlse_file.c`) for the macOS platform the tool targets — found:

- **GAP-AE — Mach-O executables were not detected**: the magic table covered
  PE/EXE and ELF but not Mach-O, so a macOS binary renamed `invoice.pdf` or
  `salary.docx` passed the F2 magic-mismatch check. Added the four unambiguous
  thin-binary Mach-O magics (`CE/CF FA ED FE` and the big-endian mirrors) plus
  an F2 branch mirroring the ELF one (score 70; `.dylib`/`.bundle`/`.o`
  whitelisted as legitimate Mach-O containers). The fat/universal magic
  `0xCAFEBABE` is deliberately omitted — it is indistinguishable from a Java
  `.class` file by header alone, so flagging it would risk false positives.
  Additive detection in a module outside the URL/text F1 corpus; 2 new file
  tests (masquerade flagged, legitimate `.dylib` spared); File/Audit suite
  17 → 19. F1=1.000 unaffected. Fixed in 0.9.36.

Each resolution is a thin CLI wrapper over the existing library function (per
§6) or an invariant/coverage/consistency/accuracy fix, with tests where code
changed.
