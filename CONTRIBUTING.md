# Contributing to HLSE Core

Thank you for considering a contribution. HLSE protects real people from
real attacks, so we hold a high bar for changes.

## TL;DR

1. Run `make test` before opening a PR (1080+ checks; 14 CLI-integration
   checks are known-failing for environment reasons — schema validators and
   GitHub Actions workflow files absent in-tree — not engine bugs).
2. Run `make check-warnings` — every module must compile clean under
   `-Wpedantic -Wshadow -Wconversion`.
3. New detection logic must come with a test case in the matching axis
   (unit, property, behavioral, or corpus).
4. Never add a network call. HLSE is 100% local. Forever.
5. Match the existing C90/C99-compatible style: 4-space indent, ≤80 cols,
   `snake_case`, comments where intent isn't obvious.

## CI quality gates

Every PR must pass these gates (all run in CI, all runnable locally):

| Gate | Command | What it enforces |
|------|---------|------------------|
| Tests | `make test` | All 9 suites + property + corpus + CLI integration (1080+) |
| Warnings | `make check-warnings` | Zero strict warnings across all modules |
| Memory safety | `make asan-test` | No ASan/UBSan errors |
| Fuzzing | `make fuzz` | 6 harnesses × 100K iterations, zero crashes |
| Coverage | `make coverage` | Aggregate line coverage ≥ 65% |
| Privacy | (CI grep) | No network syscalls in source |
| Secrets | gitleaks | No leaked credentials in history |

## Seven-axis test architecture

When adding a feature, ask: **which axis catches it?**

| Axis | File | When to add a test here |
|------|------|--------------------------|
| Unit | `hlse_core.c` `self_test()` | Specific URL/text input → expected score range |
| Property | `tests/hlse_property_tests.c` | A universal invariant (P1–P13: monotonicity, bounds, evasion…) |
| Corpus | `hlse_core.c` `benchmark()` | Real-world phishing example or legitimate site |
| Edge | `tests/hlse_property_tests.c` `edge_cases()` | Boundary input (empty, huge, malformed, null) |
| Behavioral | `tests/hlse_*_tests.c` (protect, secrets, supply, file/audit, util, server) | Module-level contract (return type, field values, exit conditions) |
| CLI integration | `tests/cli_integration.sh` | End-to-end: subcommand exit codes, JSON schema, flag combos |
| Fuzz | `tests/hlse_*_fuzz.c` (text, secrets, supply, file, url, server) | Random/adversarial bytes → no crash, no UB |

Bugs that slipped through unit tests but were caught by property tests
are documented in CHANGELOG.md — read those entries before claiming
"unit tests are enough."

## How to add a new detection signal

Most detection improvements come from adding a keyword to an existing
signal table in `hlse_text.c`. Example: adding "wire your retirement"
to the BAIT_WORDS list:

```c
static const char *BAIT_WORDS[] = {
    /* ... existing ... */
    "wire your retirement",  /* ← new */
    NULL
};
```

Then add a corpus entry:
```c
/* in benchmark() in hlse_core.c, malicious[] */
"URGENT: wire your retirement to this account immediately",
```

Run `make test` — both your new keyword and the F1 score must hold.

## Code style

```c
/* Comment style: complete sentences when explaining intent.
 * Brief tags otherwise.                                     */

static int     /* return type on its own line for fn defs   */
function_name(const char *arg1, int arg2)
{
    /* 4-space indent, K&R brace style */
    if (condition) {
        do_something();
    }
}
```

- Functions returning bool-like values return `int` (`0`/`1`)
- Pointers can be `NULL`-checked or assumed valid; document which
- No dynamic allocation in hot paths
- `static` everything that doesn't need to be exported

## What we will NOT accept

- **Network calls.** Not even "anonymous telemetry." Not even an
  optional opt-in setting. The `privacy-tripwire` CI job rejects PRs
  that introduce socket APIs.
- **External dependencies.** Pure C standard library only. The whole
  point of this codebase is to be auditable in 30 minutes.
- **Convenience macros that hide control flow.** Code that's hard to
  audit is hard to trust.
- **Detection of single benign signals.** A new rule must improve F1
  on the corpus benchmark — recall AND precision both matter.

## Privacy bug bounty

If you find a way to make HLSE Core leak data to the network — even
under malicious config or weird input — that is a critical bug. Report
it via the SECURITY.md process below. We will fix it in a hotfix
release within 72 hours.

## Support the project

If HLSE is useful to you, see [.github/FUNDING.yml](.github/FUNDING.yml) for
donation options.
