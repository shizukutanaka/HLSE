# Changelog

All notable changes to HLSE Core (C reference) follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
