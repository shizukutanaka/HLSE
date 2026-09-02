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
   - **Deterministic** — no time/random dependence in scoring.
   - **Allocation-light** — bounded stack/static buffers; no unbounded input.
2. **Never let a check that could not read its evidence report a pass.**
   "I read it and found nothing" and "I could not read it" are different
   claims and only the first clears anything. This was the single worst class
   of bug found in the product: `hlse_audit_sudoers()` asserted
   `AUDIT_PASS "No NOPASSWD entries found"` about `/etc/sudoers` (0440
   root:root) whenever it had not opened the file, so an unprivileged run
   awarded `100/100 (hardened)` to a host that root correctly rated
   `ALERT [40]` for passwordless sudo. `file`, `protect` and `network` had the
   same shape. When you add or touch a check that reads the filesystem:
   - Distinguish **absent** from **unreadable** via `errno == ENOENT`. Absence
     is a finding ("no SSH server"); denial is not.
   - Denial, not reach, is the predicate. `/etc/sudoers.d` being listable must
     not license a claim about the unreadable `/etc/sudoers`.
   - Report the gap in the score-0 path too — that is where a reader is most
     likely to stand down. Several clean branches printed only their headline
     and dropped the very findings that explained the gap.
   - Disclosure, never a score change, unless the user approves one.
   - **Check reachability end-to-end, not per function.** A merge step is a
     second place a diagnostic can die: `hlse_protect_scan()` copied a module's
     reasons only when its score was `> 0`, so ten score-0 diagnostics — every
     "could not read" message plus two positive confirmations — could not reach
     the CLI no matter how correct the module was. Fixing the modules one at a
     time missed it; running the command and reading the output found it.
   - Reproduce the before-state (`setpriv --reuid=65534 ... ./hlse_core audit`,
     `unshare -rm sh -c 'mount -t tmpfs none /proc; ...'`) and show the new
     tests failing against a binary built from `git show HEAD:<file>`.
   - **A test that branches on the tool's own output asserts nothing.** Decide
     the precondition independently (`dd` the device, `setpriv test -r` the
     file as the unprivileged user) — three checks in this suite passed
     vacuously before that was fixed.
   - **`tests/cli_integration.sh` runs under `set -eu`.** An unguarded
     `"$(./hlse_core ...)"` on input that scores a threat exits 1 and silently
     drops every check after it. Always append `|| true` to a capture. The
     `MIN_CHECKS` floor at the end of the file exists to catch this; do not
     lower it to make a run pass.
3. **Verify every commit, in this order — all must pass:**
   ```
   make && make check-warnings      # 0 warnings, CLI AND -DHLSE_CORE_AS_LIB library builds
   ./hlse_core --benchmark          # F1 = 1.000, FP = 0.0% MUST hold
   ./tests/<affected>_tests         # the suites you touched
   make asan-test                   # ASan/UBSan clean
   make privacy-check               # zero network syscalls (the core promise)
   make fuzz                        # if you touched a parser/detector
   ```
   If anything regresses, **do not push.**
4. **`make test` baseline is `851 passed / 0 failed`.** The 14 formerly
   permanent failures (JSON-schema-validation checks + a `release.yml`
   existence check) are fixed; the suite is fully green, so **any** failure is
   a regression you caused. Always read the number.
5. **Add a test for every new behavior.** Detection changes need a *pair*: a
   positive case (fires) and a benign case (no false positive). Corpus F1 must
   stay 1.000.
6. **Match the surrounding code** — its style, comment density, naming, and
   idioms. Reuse existing helpers before writing new ones (e.g.
   `hlse_json_escape` in `hlse_util.c`, `read_file_head`/`read_file_segment` in
   `hlse_protect.c`, `hlse_open_system_file` in `hlse_util.c`).
7. **Git hygiene:** work on the active feature branch; `git fetch` before you
   start (this branch is sometimes force-pushed by parallel automation — rebase
   if it advanced). Push with `-u origin`, retry with exponential backoff on
   network errors. Do **not** open or merge a PR unless explicitly asked.
8. **Secret-scanning:** write test tokens as **split literals**
   (`"glpat-" + "abcd…"`), and before pushing, scan the staged diff for
   contiguous token patterns so GitHub push-protection doesn't block the push.
9. **CI note:** the GitHub App here lacks the `workflows` permission, so
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

- **`hlse_core.c` is ~9,200 lines** with a giant `main()` dispatching 12+
  subcommands via flat `strcmp`. High regression surface. **JSON escaping is
  duplicated 3 ways** (`hlse_core.c` `json_escape`, `hlse_server.c`
  `json_escape_append`, `hlse_util.c` `hlse_json_escape`) — consolidation is
  only partial.
- **No hosted CI:** `.github/workflows/` is absent (only `FUNDING.yml`). The
  "CI enforces" wording in README/CONTRIBUTING is true only of the Makefile
  targets.
- **14 known `make test` failures** are environment/workflow-permission
  artifacts, not engine bugs — but "not green" is the steady state.
- **macOS is effectively unimplemented** (FSEvents is a stub; `/proc`,
  `/dev/sd*`, systemd checks are Linux-only). **No continuous monitoring**:
  `inotify`/`fanotify` are comments only; the SMB canary is a single
  `stat`+atime check; R5 shadow-delete is implemented but uncalled; R1
  (N-files-in-T-seconds) is documented but unimplemented.
- **Contract tension for a daemon:** `SECURITY.md:42` classes cross-invocation
  persistent state as a High-severity bug — which a resident FIM baseline/dedup
  store needs. Daemon mode requires an explicit, scoped contract amendment.
- Documentation numbers (test/fuzz counts, binary size, version stamps) drift;
  re-derive from reality when you touch them.

---

## Prioritized backlog

**P0 — consistency / reliability (low risk):**
- Sync doc numbers to measured reality (test/fuzz counts, stale "5×100K" line,
  binary size, version stamps).
- Triage the 14 known failures: separate the environment-dependent ones from
  `make test`, or mark them `SKIP`, and document that no engine bug is involved.
- Ship complete `ci.yml`/`codeql.yml`/`release.yml` under `examples/` with a
  README pointer (maintainer copies to `.github/workflows/`).

**P1 — maintainability / detection quality:**
- Split `hlse_core.c` (extract CLI dispatch to `hlse_cli.c`; table-drive the
  subcommand handlers) — behavior-preserving, incremental.
- Consolidate JSON escaping onto `hlse_util.c:hlse_json_escape`.
- Escape attacker-controlled `.efi` filenames in the plain-text `esp` CLI output
  (JSON output is already escaped).
- 2026 detection gaps: slopsquat heuristic, offline structural secret validation
  (base62+CRC32 etc.), chi-square uniformity test for intermittent encryption.

**P2 — resident/daemon mode (large; its own round, design-then-review-then-build):**
- `0.4` config-file loader (`--config`: `WATCH`/`PATTERNS`/`BASELINE`/`SYSLOG`/
  `LOGFILE`/`SCAN_INTERVAL`; reuse `hlse_patterns_load`/`hlse_baseline_load`;
  `lstat` + reject `S_ISLNK` on `WATCH`; check the config file's own perms;
  a CLI-only source list so the module isn't an empty translation unit under
  `-DHLSE_CORE_AS_LIB`).
- `hlsed` daemon: fanotify (Linux) / FSEvents (macOS) FIM → run existing
  detectors incrementally → dedup → push via `hlse_alert.c`; systemd
  `Type=notify` via a raw `$NOTIFY_SOCKET` write (no libsystemd), watchdog,
  SIGHUP reload, PID flock, privilege drop. Amend
  `SPECIFICATION.md`/`SECURITY.md` for scoped daemon state. Keep zero-network
  (all sinks local).

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
