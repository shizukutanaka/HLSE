# AGENTS.md — HLSE contributor playbook (for AI coding agents)

Standing instructions for AI agents (Opus / Sonnet and peers) working on HLSE.
Read this before making changes. It captures the project's identity, its known
strengths/weaknesses, a prioritized improvement backlog, and the non-negotiable
verification protocol.

HLSE is a **dependency-free C** security-detection engine: modules for URL,
text/scam, secrets, supply-chain, file-masquerade, ransomware/boot (`protect`),
and system `audit`; a CLI (`hlse_core`), a shared library (`libhlse.so`), an
HTTP server + web dashboard (`hlse-server`), and a push-alert sink
(`hlse_alert.c`).

---

## Non-negotiable guardrails

1. **Never break a design invariant** (`docs/SPECIFICATION.md` §1):
   - **Zero network** — do not add a network syscall to any analysis module.
     (`hlse-server` is the only socket user, by design.)
   - **Dependency-free** — link only `-lm` (and `-lpthread` for the server).
     No third-party libraries.
   - **Deterministic** — no time/random dependence in scoring for
     pure-input analysis; host-integrity recency checks (R1/S4 in
     `hlse_protect.c`) compare fs metadata to wall-clock by design —
     see SPECIFICATION.md §1.
   - **Allocation-light** — bounded stack/static buffers; no unbounded input.
2. **Verify every commit, in this order — all must pass:**
   ```
   make && make check-warnings      # 0 warnings, CLI AND -DHLSE_CORE_AS_LIB library builds
   ./hlse_core --benchmark          # F1 = 1.000, FP = 0.0% MUST hold
   ./tests/<affected>_tests         # the suites you touched
   make asan-test                   # ASan/UBSan clean
   make fuzz                        # if you touched a parser/detector
   ```
   If anything regresses, **do not push.**
3. **`make test` baseline is all-green on a verified host** — measured on
   macOS (Apple clang): 10 unit suites 381/381, extended corpus 29/29, CLI
   integration 786 passed / 0 failed. A few checks print SKIP instead of
   PASS when the host genuinely lacks the precondition (no sudoers NOPASSWD
   on a hardened box, `jsonschema` module absent, /etc/hosts not writable) —
   SKIP is not a failure, but a FAIL line is. **Any FAIL you introduced is a
   regression — do not push.** Always read the counts.
4. **Add a test for every new behavior.** Detection changes need a *pair*: a
   positive case (fires) and a benign case (no false positive). Corpus F1 must
   stay 1.000.
5. **Match the surrounding code** — its style, comment density, naming, and
   idioms. Reuse existing helpers before writing new ones (e.g.
   `hlse_json_escape` in `hlse_util.c`, `read_file_head`/`read_file_segment` in
   `hlse_protect.c`, `hlse_open_system_file` in `hlse_util.c`).
6. **Git hygiene:** work on the active feature branch; `git fetch` before you
   start (this branch is sometimes force-pushed by parallel automation — rebase
   if it advanced). Push with `-u origin`, retry with exponential backoff on
   network errors. Do **not** open or merge a PR unless explicitly asked.
7. **Secret-scanning:** write test tokens as **split literals**
   (`"glpat-" + "abcd…"`), and before pushing, scan the staged diff for
   contiguous token patterns so GitHub push-protection doesn't block the push.
8. **CI note:** the GitHub App here lacks the `workflows` permission, so
   `.github/workflows/*.yml` cannot be committed from an agent. Deliver CI YAML
   under `examples/` and note in the PR that the maintainer must copy it in.

---

## Strengths (what to preserve)

- Invariants are **enforced by the build**, not aspirational: `check-warnings`
  runs the strict flag set (`-Wpedantic -Wshadow -Wconversion -Wformat-*`) over
  every module in *both* CLI and library modes; `asan-test` exercises the real
  paths (incl. `--baseline` and `esp`); binaries get
  `-fstack-protector-strong`/`_FORTIFY_SOURCE`/PIE/RELRO.
- **F1 = 1.000** on in- and out-of-distribution corpora, reproducible via
  `--benchmark`. 9 test suites + 6 fuzz harnesses (plain + ASan).
- Broad, layered detection with an **adversarial-review culture** (see
  `CHANGELOG.md`) and **honest `"blind_spot"` fields** in every JSON verdict.
- Full product surface: CLI + `libhlse.so` + HTTP server + dashboard + push
  sink + SARIF + custom-patterns-without-rebuild + man pages + rootless
  `make install`.

## Weaknesses / risks (what to improve — cite when you touch them)

- **`hlse_core.c` is ~2,759 lines**: the URL engine + thin public
  wrappers + `hlse_canonical_confirm` (closes over the static BRANDS[]
  table) + a thin `main()` (config load, flag parse into `HlseCli`,
  alert-sink init, one-line dispatch). Extracted modules:
  `hlse_selftest.c`, `hlse_registry.c`, `hlse_channel.c` (channel
  prior), `hlse_baseline.c` (fingerprint + suppress),
  `hlse_patterns.c` (SECRET/BRAND loader), `hlse_sarif.c` (collector +
  emitter), `hlse_manifest.c` (manifest parsers), `hlse_githistory.c`
  (fork/exec walker), `hlse_meta.c` (pattern ids + blast radius),
  `hlse_advisory.c` (public verdict-interpretation layer),
  `hlse_emit.c` (CLI output: advisory getters, JSON/human emitters,
  stdin mode), `hlse_cli.c` (all 12 subcommand handlers taking
  `const HlseCli *`). No file-scope flag statics remain.
  JSON escaping is consolidated on
  `hlse_util.c:hlse_json_escape` — `hlse_server.c` delegates to it.
- **No hosted CI:** `.github/workflows/` is absent (only `FUNDING.yml`). The
  "CI enforces" wording in README/CONTRIBUTING is true only of the Makefile
  targets. Shipped `examples/workflows/{ci,codeql,release}.yml` +
  `make install-workflows` close the gap once the maintainer installs them.
- **macOS builds and fully passes `make test`** (platform conditionals in
  the Makefile; `make static` is unsupported — no static libc on Darwin).
  Runtime coverage is still Linux-centric: FSEvents is a stub; `/proc`,
  `/dev/sd*`, and systemd checks are Linux-only. ~~**No continuous
  monitoring**~~ `hlsed` now covers incremental file monitoring
  (poll-based FIM — see P2 below); the SMB canary is a single
  `stat`+atime check.
- ~~**Contract tension for a daemon:**~~ resolved: `SECURITY.md` has a
  scoped carve-out for `hlsed`'s in-memory dedup state
  (intra-invocation only, dies with the process).
- Documentation numbers (test/fuzz counts, binary size, version stamps) drift;
  re-derive from reality when you touch them.

---

## Prioritized backlog

**P0 — consistency / reliability (low risk):**
- ~~Sync doc numbers to measured reality~~ done: README/CONTRIBUTING/AGENTS
  counts re-derived (1196 structured, 786 CLI, all-green baseline; now
  1211 with the daemon-lifecycle suite).
- ~~Triage the 14 known failures~~ done: root causes were macOS build
  breakage + host-dependent assertions; suite is green, env-dependent checks
  SKIP explicitly.
- ~~Ship `ci.yml`/`codeql.yml`/`release.yml` under `examples/`~~ shipped at
  `examples/workflows/` + `make install-workflows` (pointer in CONTRIBUTING).
  Remaining: a maintainer with `workflows` permission runs it once.

**P1 — maintainability / detection quality:**
- Split `hlse_core.c` (extract CLI dispatch to `hlse_cli.c`; table-drive the
  subcommand handlers) — behavior-preserving, incremental. Done: selftest +
  pattern registry extracted. Remaining clusters, in coupling order:
  output printers (`print_json_*`, advisories, `channel_*` + `g_from_channel`),
  scan-driver helpers (baseline/fingerprint/patterns-load/manifest/
  git-history), `stdin_mode`, then the subcommand handlers + `main`.
- ~~Consolidate JSON escaping onto `hlse_util.c:hlse_json_escape`~~ done:
  `hlse_server.c:json_escape_append` now delegates.
- ~~Escape attacker-controlled `.efi` filenames in `esp` output~~ done, and
  widened: `hlse_sanitize_display()`/`hlse_display_copy()` in `hlse_util.c`
  neutralise terminal-hostile bytes in every verdict-add helper and every
  human-facing operand echo, not just ESP.
- ~~2026 detection gaps~~ done: slopsquat dist-3 advisory in
  `hlse_check_package`, base62+CRC32 structural secret validation,
  chi-square uniformity for intermittent encryption.

**P2 — resident/daemon mode:**
- ~~`0.4` config-file loader~~ — DONE: `--config <file>` for the CLI
  (hlse_config.c/h), plus the daemon keys `watch`/`scan-interval`/
  `pid-file` (CLI parses + ignores them so one file serves both).
- ~~`hlsed` daemon~~ — DONE (first increment, deliberately divergent
  design): **poll-based FIM** instead of fanotify/FSEvents — same code
  on Linux+macOS, rootless, no new framework dep. Walks each `watch`
  dir on `scan-interval`, re-scans (hlse_check_file + bounded
  hlse_scan_secrets) files whose (path,mtime,size) tuple is new in the
  4096-entry in-memory dedup table → `hlse_alert` sinks. SIGHUP reload,
  SIGTERM/INT clean exit, PID-file flock, `hlsed --check` validator.
  systemd notify/watchdog/privilege-drop remain unbuilt — run foreground
  under `Type=simple`. Event backends (inotify/FSEvents) can slot under
  the same dedup contract later without changing the interface.

---

## Model role division

- **Opus** — design, architecture, and **adversarial security review *before*
  implementation**; large refactor planning. New C modules must go
  design → adversarial review → fold in fixes → implement. (This has already
  caught real defects pre-implementation — e.g. a `build_line` stack overflow
  and a `-Wpedantic` empty-translation-unit CI break.) Owns: `hlse_core.c`
  split design, the `0.4`/`hlsed` designs, and the contract-amendment text.
- **Sonnet** — well-specified implementation, mechanical changes, and fast
  verify loops. Owns: the P0 items, JSON-escape consolidation, the `esp`
  output-escape fix, coding up Opus-reviewed components, and running/reading
  fuzz + ASan. One logical unit per commit; verify and push each.

## Standard task loop

`git fetch` → read the target code (prefer reuse) → apply the change (match
style) → run the verification protocol above → add tests → update `CHANGELOG.md`
→ scan the staged diff for secrets → commit (`Co-Authored-By:` +
`Claude-Session:` footer; no model IDs in artifacts) → push.

Default order when unspecified: P0 items → P1 (escape consolidation, esp escape,
2026 gaps) → `hlse_core.c` split (Opus designs) → P2 (config loader, then daemon).
