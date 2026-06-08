# Changelog

All notable changes to HLSE Core (C reference) follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.9.17] — 2026-06-08

### Fixed
- **SARIF rule definitions missing `security-severity`** (`hlse_core.c`
  `sarif_emit()`; SPECIFICATION.md §5.3, GAP-O). The SARIF output had
  `security-severity` on individual result objects but not on rule
  definitions, which GitHub code scanning requires to classify vulnerability
  severity. Added `"properties": { "security-severity": "X.X" }` to each
  rule (`secret`=9.0, `file-masquerade`=8.0, `phishing-url`=7.5). Also
  improved rule `shortDescription` text from the generic "HLSE X detector"
  to human-readable descriptions.

- **`scan --json` `url` records missing `reasons` field** (`hlse_core.c`
  scan walker; SPECIFICATION.md §5.2, GAP-O companion). When the `scan`
  directory walker found a phishing URL embedded in a source file, the
  human-readable output included the reason strings but the `--json` URL
  record did not emit `"reasons"`. Fixed to match the spec §5.2 requirement
  that `url` JSON objects carry `reasons:[...]`.

## [0.9.16] — 2026-06-08

### Fixed
- **`--stdin --json` dropped embedded URL scores** (`hlse_core.c`
  `stdin_mode()`; companion to GAP-N). The `--stdin --json` path had the
  identical bug as the `text`/auto-detect JSON paths fixed in 0.9.15:
  `hlse_check_text(line)` was called instead of reusing the `ScanResult`
  already computed by `hlse_scan(line)`, so text lines with embedded
  phishing URLs returned score=0 in JSON mode while human output showed
  the correct BLOCK.

### Changed
- **README docs**: property table corrected `P1–P12` → `P1–P13` (P13
  full-width Unicode evasion was already implemented and passing); CLI
  integration count updated 86 → 87.

## [0.9.15] — 2026-06-08

### Fixed
- **`--json text` dropped embedded URL scores** (`hlse_core.c`;
  SPECIFICATION.md §8, GAP-N). When a text message contained an embedded
  phishing URL (e.g. `"click https://paypa1.com/signin"`), the human-readable
  path called `hlse_scan()` (embedded URL extraction → score 60) but the
  `--json` path re-called `hlse_check_text()` alone, returning score 0 for
  the same input. Same flaw in the auto-detect JSON path. Both paths now
  reuse the `ScanResult` already computed by `hlse_scan()` to build the
  `TextVerdict` for JSON output. Regression guard added to CLI integration
  (now 87 tests). Man page `.TH` header version/date also updated.

- **Man page version frozen at 0.9.0** (`hlse.1`; SPECIFICATION.md §8,
  GAP-M). `.TH` header still read `"HLSE 0.9.0"` / `"2026-05-31"`, and the
  OPTIONS section omitted `-h | --help`. Updated header to `0.9.15` /
  `2026-06-08` and added the missing option entry.

## [0.9.14] — 2026-06-08

### Fixed
- **`-h | --help` absent from help output** (`hlse_core.c` `print_usage()`;
  SPECIFICATION.md §8, GAP-L). Spec §3.2 lists `-h`, `--help` as a global
  flag; all other 7 flags appeared in the "Options" block but `--help` did
  not self-reference. Added `%s -h | --help  Show this help` as the final
  option line (1 `printf` arg added; arg count in comment updated to 8).

## [0.9.13] — 2026-06-08

### Fixed
- **README C library API accuracy** (SPECIFICATION.md §8, GAP-K). The README
  claimed "29 functions exported in `libhlse.so`" but `nm -D libhlse.so`
  reports 35 (six additions since the original count: `hlse_esp_verify`,
  `hlse_audit_hardening_index`, `hlse_validate_crypto_address`,
  `hlse_is_high_entropy_benign_magic`, `hlse_shannon_entropy_str`,
  `hlse_text_action_for_score`). The code example also omitted `hlse_util.h`
  and six entry points (`scan_secrets`, `check_email_headers`,
  `check_crypto_swap`, `esp_verify`, `audit_hardening_index`, `validate_crypto`).
  The "All pure functions, thread-safe" note was inaccurate — filesystem/host
  functions (protect/audit/network) are process-level. Updated count to 35,
  added missing examples, corrected thread-safety note. Also updated spec §7
  fuzz description from `100K` to `4 × 100K`. Docs-only.

## [0.9.12] — 2026-06-08

### Fixed
- **README test-architecture accuracy** (SPECIFICATION.md §8, GAP-J). The
  per-suite counts in the "Test architecture" table had drifted from reality
  (Unit-URL 13→23, Unit-text 14→15, Property 60→64, Secrets 20→25,
  File/Audit 14→17, CLI integration 45→86), and the `util_tests` (14) and
  out-of-distribution corpus (25) suites were missing entirely. The Fuzz row
  predated GAP-I (one text harness → four). Refreshed all rows to measured
  counts, added the two missing suites, and updated the Fuzz row to `4 × 100K`.
  The at-a-glance `320+` floor was re-verified and still holds (≈339
  suite/corpus + in-distribution benchmark checks). Docs-only.

## [0.9.11] — 2026-06-08

### Added
- **Multi-module fuzz harnesses** (`tests/hlse_secrets_fuzz.c`,
  `tests/hlse_supply_fuzz.c`, `tests/hlse_file_fuzz.c`;
  SPECIFICATION.md §8, GAP-I). Previously `make fuzz` / `make fuzz-asan`
  covered only `hlse_text.c`; the five other parser modules had zero fuzz
  coverage. Three portable smoke-fuzz harnesses added — same pattern as the
  original: deterministic PRNG, signal-handler crash detection, score-range
  assertion, 100K iterations (10K under ASan):
  - `hlse_secrets_fuzz.c` — `hlse_scan_secrets`, `hlse_check_email_headers`,
    `hlse_check_crypto_swap`, `hlse_validate_crypto_address` (4 entry points;
    generators: random bytes, credential fragments, email headers, crypto addresses)
  - `hlse_supply_fuzz.c` — `hlse_check_package`, `hlse_check_paste`
    (generators: random bytes, typosquat-mutated names, pastejacking commands)
  - `hlse_file_fuzz.c` — `hlse_check_filename` (disk-free path; generators:
    random bytes, double-extension, bidi/control characters, social-engineering lures)
- `make fuzz` now runs all four harnesses sequentially; `make fuzz-asan` runs
  all four under ASan/UBSan. `make clean` removes all harness binaries.

## [0.9.10] — 2026-06-06

### Fixed
- **README accuracy** (SPECIFICATION.md §8, GAP-H). "Structured tests: 237" and
  "Binary size: 53 KB (dynamic), 932 KB (static)" had drifted — actual is ≈328
  checks across the suites + CLI integration, and ≈140 KB dynamic / ≈1.0 MB
  static-pie (stripped) after the feature and hardening work. Updated to a
  non-drifting `320+` and measured approximate sizes; dropped the brittle exact
  count from the `make test` comment. The detection/evasion examples, F1=1.000,
  and 0% FP claims were re-verified and are accurate.

## [0.9.9] — 2026-06-06

### Changed
- **Consistent JSON `action` band** (`hlse_core.c`; SPECIFICATION.md §5.2,
  GAP-G). Only 4 of 12 `--json` kinds (`url`, `text`, `protect`, `esp`) emitted
  the `action` band; the other 8 (`package`, `paste`, `network`, `secret`,
  `email`, `clipboard`, `audit`, `file`) plus the streaming `scan` records
  omitted it, forcing consumers to re-derive the band from `score`. Every
  score-bearing JSON object now carries `"action"` (from
  `hlse_action_for_score`). 10 CLI action-consistency tests added.

## [0.9.8] — 2026-06-06

### Fixed
- **Solana clipboard-swap detection** (`hlse_secrets.c`; SPECIFICATION.md §8,
  GAP-F). The header advertised crypto-swap support for "BTC, ETH, XMR, SOL,
  USDT" and the `CRYPTO_SOL` enum / `"SOL (Solana)"` name existed, but
  `detect_crypto_type()` had no Solana branch, so a Solana clipper swap was
  silently never flagged. Add a base58 32–44 Solana branch, evaluated last so
  the prefixed/fixed-length formats (BTC `1`/`3`, USDT `T`, ETH `0x`, …) keep
  precedence. Detection is confined to the clipboard-swap comparison and the
  (test-only) validator — it does not feed the URL/text path, so phishing/scam
  F1 is unaffected. Adds validate + swap regression tests.

## [0.9.7] — 2026-06-06

### Security
- **`scan` no longer follows symlinks** (`hlse_core.c`; SPECIFICATION.md §1,
  GAP-E). A second spec audit found the recursive directory walker classified
  entries with `stat()` (follows links) and read files with `fopen()` (no
  `O_NOFOLLOW`). A symlinked directory could make the scan escape the target
  tree (and risk symlink cycles); a symlinked file such as `x.env ->
  /etc/shadow` was opened and scanned for secrets, disclosing a file outside
  the scanned tree. Now classified with `lstat()` (symlinks become `S_ISLNK`
  and are skipped) and re-opened with `O_NOFOLLOW | O_NONBLOCK` + `S_ISREG`
  (TOCTOU defence), matching the hardened pattern already used in
  `hlse_file.c`, `hlse_audit.c`, and the ESP scan. Real in-tree files are still
  scanned; a regression test plus an ASan symlink-cycle test were added.

## [0.9.6] — 2026-06-06

### Added
- **Formal specification** (`docs/SPECIFICATION.md`): the CLI contract, scoring
  model, per-module behaviour, output schemas, design invariants, and a gap
  analysis. Writing it surfaced that several documented/library capabilities had
  no CLI access — resolved below.
- **`secret` subcommand**: scan a text argument or stdin for leaked credentials
  (`hlse_scan_secrets`), previously reachable only via a directory `scan`.
- **`email` subcommand**: email-header forensics (`hlse_check_email_headers`) —
  SPF/DKIM, Reply-To mismatch, display-name/BEC spoofing. Arg or `--stdin`.
- **`clipboard` subcommand**: crypto address-swap / clipper detection
  (`hlse_check_crypto_swap`, including the 0.9.3 vanity look-alike escalation),
  previously library-only.
- All three honour `--json`; `esp` (added in 0.9.4) plus the three new commands
  are now documented in `--help`/`print_usage`, the man page, and the README.

### Notes
- These are thin CLI wrappers over existing, tested library functions — no
  detection logic changed. 14 new CLI integration tests; ASan/UBSan clean
  (empty/large/binary stdin); strict warnings + cppcheck clean.

## [0.9.5] — 2026-06-05

### Added
- **Lynis-style hardening index** (`hlse_audit.c`): new
  `hlse_audit_hardening_index()` returns a 0..100 score where 100 = fully
  hardened (the complementary view of the finding-weighted risk score). The
  `audit` subcommand now prints `Hardening index: N/100 (hardened|good|fair|
  weak)` and exposes `hardening_index` / `hardening_band` in `--json audit`,
  giving the same at-a-glance posture signal Lynis provides. Stateless helper;
  no detection logic changed. (Research backlog #7.)

## [0.9.4] — 2026-06-05

### Added
- **EFI System Partition (ESP) integrity check** (`hlse_protect.c`, new `esp`
  subcommand): `hlse_esp_verify` walks the ESP (default `/boot/efi`) and flags
  `.efi` binaries containing high-specificity ransom/bootkit text. The legacy
  MBR check only covers BIOS boot; the live boot-level threat is UEFI bootkits
  (BlackLotus, Linux Bootkitty) that tamper with the ESP. Unlike the MBR scan,
  this uses only multi-word ransom-note phrases (`"all your files have been
  encrypted"`, `"pay bitcoin"`, …) — the MBR's generic single-word tokens
  (`decrypt`, `locked`) would false-positive inside legitimate multi-MB signed
  bootloaders. Read-only, never follows symlinks, depth- and count-bounded.
  `--json esp` supported. 6 CLI regression cases added.

### Notes
- ESP signature (Authenticode) validation is intentionally deferred: it cannot
  be done safely offline without a baseline, and a wrong implementation would
  risk false negatives. See `docs/RESEARCH_IMPROVEMENTS.md` #8.

## [0.9.3] — 2026-06-05

### Added
- **Clipboard clipper "vanity look-alike" signal** (`hlse_secrets.c`): when a
  same-type crypto address is swapped, `hlse_check_crypto_swap` now measures the
  shared leading/trailing characters between the original and the replacement.
  Real clipboard hijackers (per EthClipper, arXiv 2108.14004) grind a
  replacement that shares the victim address's ends so a glance misses the
  swap; a shared tail of 4+ chars between two *different* addresses is
  essentially impossible by chance. Such swaps now escalate from BLOCK (95) to
  ISOLATE (100) with an explanatory reason. Purely additive — detection is never
  weakened; addresses with no shared ends keep their existing score.

## [0.9.2] — 2026-06-05

### Added
- **IDN homograph detection via Punycode** (`hlse_core.c`): `xn--` labels are
  now decoded per RFC 3492 and analysed UTS-39 style. Cyrillic/Greek/Armenian
  homographs delivered as Punycode (which is pure ASCII and so invisible to the
  existing UTF-8 mixed-script check) are caught: a confusable-folded label that
  resembles a brand, or a label mixing Latin with another script, is flagged.
  `xn--pple-43d` (аpple), `xn--ggle-55da` (gооgle), `xn--pypl-53dc` (pаypаl) and
  `xn--mirosoft-gch` (miсrosoft) now score BLOCK. Legitimate single-script IDNs
  — `xn--mnchen-3ya` (münchen), `xn--wgv71a` (日本), `xn--e1afmkfd` (пример) —
  are deliberately **not** flagged, preserving the 0.0% false-positive posture.
  Closes the largest detection gap identified in `docs/RESEARCH_IMPROVEMENTS.md`
  (item #1). Pure C, no network, no new dependencies.

### Changed
- 7 IDN regression cases added to the in-binary `--self-test`; in- and
  out-of-distribution corpora remain F1 = 1.000; ASan/UBSan clean (including
  malformed Punycode); strict warnings and cppcheck clean.

## [0.9.1] — 2026-06-04

Security-hardening release. No detection-logic changes: in- and
out-of-distribution corpora remain F1 = 1.000 and all 237+ tests pass.

### Security
- **Exploit-mitigation build flags** (`Makefile`): the binaries are now
  compiled with `-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2`, and
  linked as PIE with Full RELRO, `BIND_NOW`, and a non-executable stack on
  Linux (`-static-pie` for the static target). Previously the security
  tool itself shipped with no hardening (`-O2 -Wall -Wextra`, empty
  `LDFLAGS`). macOS builds are unaffected (uname-guarded linker flags).
- **Symlink / special-file safety** (`hlse_file.c`, `hlse_audit.c`): file
  reads now use `O_NOFOLLOW | O_NONBLOCK` and require `S_ISREG` via
  `fstat()`. A symlink can no longer redirect a scan to an arbitrary file
  (e.g. `/etc/shadow`) and a FIFO/device node can no longer block the
  scanner. Brings both modules in line with `hlse_protect.c`.

### Changed
- **Bounded string construction** (`hlse_core.c`): replaced an unbounded
  `strcpy`/`strcat` pair in the homoglyph `ii→ll` path and the default
  path assignment with clamped `memcpy`/explicit writes. Behaviour is
  unchanged; removes latent overflow hazards.
- **DRY** (`hlse_util.c`): the benign high-entropy magic-byte table
  (ZIP/GZIP/JPEG/PNG/…) used by the ransomware entropy heuristic moved
  into a shared `hlse_is_high_entropy_benign_magic()`.
- **`hlse_scan` reason copy** (`hlse_core.c`): bound the copy loop by the
  source `Verdict.reasons` size instead of a mismatched literal.

### Added
- **Static analysis config** (`.clang-tidy`): a bugprone/cert/
  clang-analyzer check set for local runs
  (`clang-tidy hlse_*.c -- -I. -std=c99 ...`). Companion CI jobs — a
  cppcheck `error`-severity gate (with documented inline suppressions)
  and a CodeQL `security-and-quality` workflow for C — plus a
  `release.yml` version-gate fix are maintained alongside the
  repository's GitHub Actions workflows.
- **cppcheck-driven fixes** (`hlse_core.c`): bound the `hlse_scan`
  reason copy by the source `Verdict.reasons` size, and document a
  `legacyUninitvar` false positive with an inline suppression.

## [0.9.0] — 2026-05-31

### Added
- **DGA / high-entropy domain detection** (`hlse_core.c`): Shannon entropy
  + digit-ratio analysis flags algorithmically generated domains
  (`x7k2p9qzr4mw.com`). Grounded in published phishing-URL feature research;
  requires both high entropy and digit presence to avoid false positives on
  long brand names (stackoverflow, amazonwebservices).
- **Brand-hyphen phishing** — `paypal-verify.com`, `apple-support.net`
  flagged via brand + hyphen + security-word pattern.
- **Digraph homoglyph** — `arnazon.com` (rn→m), `vv→w` normalization.
- **New abused TLDs** — `.zip`, `.mov`, `.country`, and others added to the
  high-risk list.
- **BEC amplifiers** (`hlse_text.c`): authority+wire, secrecy+wire, and
  authority+secrecy+payment compound rules; expanded executive-title and
  secrecy phrasings. CEO-fraud messages now reach ISOLATE.
- **Full-width Unicode folding** — `ｕｒｇｅｎｔ` (U+FF01-FF5E) collapsed to
  ASCII before keyword matching.
- **Polyglot file detection** (`hlse_file.c`): image/archive magic bytes
  (GIF/JPEG/PNG/ZIP/GZIP) with an executable extension flagged as payload
  disguise.
- **Bidi-override filename detection** — U+202E (RLO), U+202D (LRO), and
  bidi isolates flagged independent of apparent extension; `file`
  subcommand now analyzes names even when the file is absent.
- **SARIF 2.1.0 output** — `--sarif scan <dir>` emits GitHub code-scanning
  compatible results with rule definitions and security-severity.
- **Shared utility module** (`hlse_util.c`): Shannon entropy and
  Damerau-Levenshtein consolidated from three duplicate copies (DRY).

### Changed
- **Secret scanner** now excludes placeholder/example/test keys
  (`AKIAIOSFODNN7EXAMPLE`, `your_api_key_here`, repetitive tokens),
  matching the false-positive reduction of gitleaks/TruffleHog without
  requiring network verification.
- **Ransomware entropy** check excludes known compressed/media formats by
  magic byte, eliminating false positives on directories of `.zip`/`.gz`/
  `.jpg` files (Shannon entropy cannot distinguish encrypted from
  compressed; magic-byte exclusion is the robust fix).
- `scan` now errors (exit 2) on a missing directory instead of reporting
  a clean result.

### Fixed
- Unterminated HTML entities (`U&#82GENT` without semicolon) now decoded
  like browsers do.
- CI workflow rebuilt to run the full test suite, strict warnings,
  sanitizers, fuzzing, coverage gate, and gitleaks (previously only ran a
  subset and referenced a nonexistent test file).

### Security
- Added `release.yml` that re-runs all gates before producing signed
  release artifacts; a release can no longer bypass CI.

## [0.8.0] — 2026-05-12

### Added
- **Protection module** (`hlse_protect.c`): 4 behavioral detection layers
  - Ransomware: Shannon entropy analysis, ransom note detection (14
    filenames), extension mutation (26 extensions), compound rules
  - Network drive: /proc/mounts CIFS/NFS detection, lateral movement amplifier
  - SMB server: canary honeypot files, Samba audit log analysis
  - MBR/GPT: boot signature check, first-instruction validation,
    bootkit string scan, boot code entropy analysis
- **Secrets module** (`hlse_secrets.c`): 3 detection layers
  - Credential scanner: AWS keys, GitHub PATs, Stripe keys, Slack tokens,
    SSH private keys, .env passwords, generic high-entropy secrets
  - Email header forensics: display-name vs From mismatch, Reply-To
    mismatch, SPF/DKIM/DMARC fail, free-email corporate impersonation
  - Clipboard crypto-swap: BTC/ETH/XMR/SOL/USDT address validation +
    swap detection
- Unified `hlse_scan` API — auto-detects URL vs text, runs both detectors
- `hlse_core.h` public header with ScanResult, Verdict types
- Apple-style zero-argument demo (`./hlse_core` with no args)
- `--version` / `-V` flag
- Empty input → meaningful error ("Nothing to scan")
- `protect` CLI subcommand with auto-detect (dir→ransomware, /dev/→MBR)
- JSON output for protect subcommand
- 14 protection tests + 20 secrets tests integrated into `make test`

### Changed
- `check_url` made static (internal only); `hlse_check_url` is the public API
- Library exports unified to `hlse_` prefix (19 symbols, no namespace pollution)
- `stdin_mode` rewritten to use `hlse_scan` (eliminated duplicate URL/text branching)
- Progressive disclosure: safe → 1 line, threat → detailed reasons

### Fixed
- Format-truncation warnings in hlse_secrets.c (display_name overflow)
- `memmem()` replaced with portable `memcmp` loop (macOS/musl compat)
- `system("rm -rf")` in tests replaced with `opendir/unlink/rmdir`
- Block comment terminated early by `/dev/*` glob in comment
- Stale build artifacts removed from outputs/

## [0.7.0] — 2026-04-29

First production release of the C reference implementation.

### Added
- 12 URL detectors (homoglyph, mixed-script, typosquat, suspicious TLD, etc.)
- 10 text signals + 4 amplifiers, multilingual EN/JP/ZH/KR
- JSON output, stdin pipe mode, text mode
- 45 property tests across 7 axes
- 18 + 18 corpus benchmark, F1=1.000
- libhlse.so shared library (~22 KB) for FFI
- Static binary build (~742 KB stripped)
- GitHub Actions CI: Linux+macOS × GCC+Clang
- Privacy tripwire CI job blocking network calls

### Bug fixes (TDD-driven discovery)

These bugs slipped through unit tests but were caught by property tests
or the corpus benchmark:

- **CONFUSABLES collision**: `paypa1.com` not detected because `('1','i')`
  came after `('1','l')`. Fixed: keep only `('1','l')`, expand digits.
- **Capital-I homoglyph**: `paypaII.com` undetected, str_tolower stripped
  the signal. Fixed: II→ll alternative form check.
- **Cyrillic homoglyph**: `mіcrosoft.com` undetected. Fixed: UTF-8 byte
  mapping for Cyrillic→ASCII collapse.
- **Wikipedia false positive**: `/wiki/Verify` flagged. Fixed: trusted-host
  allowlist requires ≥3 phishing-path matches.
- **Double counting**: `paypa1.com` scored 95 (homoglyph 45 + typosquat 50).
  Fixed: typosquat skips when homoglyph already fired.
- **str_to_lower mangled UTF-8**: applied tolower to high bytes. Fixed:
  ASCII bytes only (`< 0x80`).
- **normalize_whitespace mangled multibyte**: continuation bytes treated
  as whitespace. Fixed: detect UTF-8 sequence length, copy intact.
- **JP/ZH/KR keywords missed**: signal tables were EN-only. Fixed: full
  multilingual keyword tables + MATCH macro dispatching on first byte.
- **strtok_r segfault under -std=c11**: missing POSIX feature macro.
  Fixed: `-D_POSIX_C_SOURCE=200809L`.
- **Under-firing**: ransom/tech-support scored below ALERT threshold.
  Fixed: raised base_weight and per_hit_bonus on critical signals.

### Performance (in-process via libhlse.so)
- check_text short: 2.08 µs
- check_text long: 2.83 µs

### Privacy
- Zero network calls (CI-enforced)
- Zero environment reads
- Zero file I/O outside stdin/stdout

### Acceptance criteria (all PASS)
- recall ≥ 0.85 → 1.000
- FP rate ≤ 0.05 → 0.000
- F1 ≥ 0.85 → 1.000
- 72 tests green (27 unit + 45 property)

## Identity anchor

```
bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5
```
