# Security Policy

## Our promise

HLSE Core is a security tool. If it has a vulnerability, attackers might
weaponize it against the people we're trying to protect. We take this
seriously.

## Reporting a vulnerability

**Do not open a public issue for security bugs.**

Instead, contact the maintainer using one of the following private channels:

- GitHub: https://github.com/shizukutanaka (use "Report content"
  workflow, mark as security)
- Identity-anchored signed message: bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5

When reporting, please include:

1. **Reproduction steps** — exact input that triggers the bug
2. **Expected behaviour** — what should have happened
3. **Actual behaviour** — what does happen
4. **Impact** — what an attacker could do with this
5. **Suggested fix** (optional)

## What counts as a security bug?

Critical:
- Any way to make HLSE Core make a network connection (this violates
  the core privacy promise)
- Any way to make HLSE Core silently miss a known phishing pattern
  (false negative on adversarial input)
- Memory corruption (buffer overflow, use-after-free) — even on
  attacker-controlled input
- Crash on input that should be handled (DoS via crafted text)

High:
- A way to bypass detection by formatting tricks (e.g., HTML entities,
  base64, non-standard whitespace)
- Persistent state that survives across invocations when it shouldn't

Medium:
- False positive rate exceeds 5% on a documented corpus
- Performance regression > 3x on hot paths

Not a security bug (open an Issue normally):
- A specific phishing example we don't catch (these are detection
  improvements, not security holes)
- Cosmetic output differences

## Response timeline

| Severity | First response | Fix released |
|----------|---------------|--------------|
| Critical | within 24 hours | within 72 hours |
| High     | within 72 hours | within 14 days |
| Medium   | within 14 days  | next release   |

## Disclosure

We follow a coordinated disclosure model:

1. You report privately
2. We acknowledge within the timeline above
3. We investigate, fix, and prepare a release
4. We coordinate a public disclosure date with you (typically when the
   fix is widely deployed, 7-30 days after release)
5. CVE assignment if applicable
6. Credit to you in the CHANGELOG, unless you prefer to remain anonymous

## What HLSE Core does NOT protect against

This is a detection tool, not a sandbox. It cannot:

- Prevent execution of code the user explicitly runs
- Detect zero-day kernel exploits
- Detect threats outside its specified scope (URL/text — see README)
- Replace OS-level security (firewalls, MAC, signed binaries)

Use HLSE Core as one layer in defense-in-depth, not as the only line.

## Supported versions

| Version | Status |
|---------|--------|
| 0.7.x   | ✓ Receives security fixes |
| 0.6.x   | ✓ Critical fixes only, until 2026-12 |
| < 0.6   | ✗ Unsupported |

## Identity anchor (for verifying advisories)

Security advisories from the maintainer are signed against:

```
bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5
```

If you receive an advisory not signed against this identity, treat it
as suspicious and report it.
