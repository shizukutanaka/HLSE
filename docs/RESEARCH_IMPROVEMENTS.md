# Research-Grounded Improvement Backlog

Improvement opportunities for HLSE, derived from **comparable tools** and
**published research (arXiv et al.)**, June 2026.

Each item maps a current HLSE approach against what state-of-the-art tools and
papers do, then proposes a concrete change that stays **on-brand for HLSE**:
dependency-free portable C, **zero network calls** (enforced by the CI privacy
tripwire), allocation-light, deterministic. Network-dependent techniques (e.g.
TruffleHog-style live credential verification) are deliberately **out of scope**
— they violate HLSE's privacy guarantee — and are noted where relevant so the
trade-off is explicit.

Priorities: **P1** = high value / on-brand / bounded effort; **P2** = valuable,
larger effort or needs bundled data; **P3** = nice-to-have / research-track.

---

## 1. URL phishing — adopt the Unicode UTS-39 confusable model (P1)

**Current:** `hlse_core.c` carries a hand-rolled 9-entry single-char
`CONFUSABLES[]` table (`0→o`, `1→l`, `5→s`, …) plus a small Cyrillic/Greek
mixed-script pass and digraph rules (`rn→m`, `vv→w`). There is **no Punycode
(`xn--`) decoding** anywhere in the source.

**What others do:** Chrome and Firefox run every IDN label through the Unicode
**UTS-39 "Unicode Security Mechanisms"** gauntlet: UTS-46 conversion, identifier
status, **whole-script confusable** detection, and **skeleton** matching against
top domains; Firefox applies the **"Highly Restrictive"** profile. The companion
`confusables.txt` maps ~6,565 code points to visual equivalents — three orders
of magnitude more coverage than HLSE's 9 entries.

**Improvement:**
- **Decode Punycode `xn--` labels** before analysis. Today
  `xn--pple-43d.com` (аpple with a Cyrillic а) is invisible to HLSE because the
  host stays ASCII; decoding to the Unicode form lets the existing mixed-script
  and brand checks fire. This is the single biggest detection gap and is pure,
  network-free C (RFC 3492 is ~80 lines).
- **Bundle a generated subset of `confusables.txt`** (the skeleton map restricted
  to scripts that confuse Latin: Cyrillic, Greek, Armenian, fullwidth, math
  alphanumerics) as a static const table, and implement the **skeleton
  function** (map string → canonical form; two strings confusable iff equal
  skeletons). Keep it generated at build time from the Unicode data file so it
  stays dependency-free at runtime.
- Add a **"Highly Restrictive" mixed-script rejection** (a single label mixing
  Latin + another script is suspicious) — HLSE already has a partial version;
  formalize it to the UTS-39 profile.

Sources: [UTS #39](https://www.unicode.org/reports/tr39/),
[Confusable detection 101 (skeletons + mixed-script)](https://www.namesilo.com/blog/en/brand-protection/confusable-detection-101-unicode-skeletons-and-mixed-script-checks-for-your-brands),
[IDN homograph attack explained](https://www.punycoder.com/idn-homograph-attack/),
["Unicode ships one confusable map, you need two"](https://paultendo.github.io/posts/confusable-detection-without-nfkc/).

---

## 2. Supply-chain typosquat — go beyond edit distance (P1/P2)

**Current:** `hlse_supply.c` flags a package if Damerau-Levenshtein distance ≤ 2
to a **hard-coded** popular-package list. Pure lexical distance.

**What research shows:** "methods focusing on Levenshtein distance alone suffer
from false positives and negatives." The field has moved to **multi-signal**:
- **SpellBound / TypoSmart** add a **popularity signal** — flag only when an
  *unknown/scarcely-used* name closely resembles a *popular* one (attackers
  target high-download libraries; this slashes false positives). TypoSmart ran a
  month in production with a low-FP design.
- **Package-confusion taxonomy** (USENIX Security '23) — typos are only one
  class; also **combosquatting** (`requests-oauth`), **scope/separator
  confusion** (`-`↔`_`↔`.`), **homophones**, and **transposition**.
- **Slopsquatting** (2025) — LLMs hallucinate package names; 19.7% of generated
  samples referenced a non-existent package, and **43% of hallucinations recur
  across identical prompts**, making them predictable attacker targets.

**Improvement (on-brand):**
- **Bundle a popularity-ranked top-N list** (per ecosystem) instead of a flat
  list, and gate the alert on "candidate is *not* in the popular set AND is
  within distance k of one that is." This is a static-data change, no network.
- Add **separator-normalization confusion** (`-`/`_`/`.` collapse) and
  **combosquatting** (popular name as a token + extra affix) as distinct rules,
  matching GuardDog's "two characters swapped / short distance to top-5000."
- Add a **keyboard-adjacency distance** option (QWERTY neighbors) — fat-finger
  typos cluster on adjacent keys, raising precision over raw DL.
- Track **slopsquatting** explicitly: a short rule for names that are plausible
  but absent from the bundled registry snapshot is a useful future signal.

Sources: [TypoSmart (arXiv 2502.20528)](https://arxiv.org/html/2502.20528v1),
[SpellBound (arXiv 2003.03471)](https://arxiv.org/pdf/2003.03471),
[Package confusion, USENIX '23](https://ldklab.github.io/assets/papers/usenix23-confusion.pdf),
[GuardDog / Datadog](https://securitylabs.datadoghq.com/articles/guarddog-identify-malicious-pypi-packages/),
[Slopsquatting (Snyk)](https://snyk.io/articles/slopsquatting-mitigation-strategies/),
[AI package hallucination review](https://www.securityweek.com/ai-hallucinations-create-a-new-software-supply-chain-threat/).

---

## 3. Ransomware entropy — add chi-square + segment sampling (P1/P2)

**Current:** `hlse_protect.c` samples the **first 4 KB** of each file, computes
**Shannon entropy**, flags `> 7.5 bits/byte`, and excludes known compressed/media
formats by magic bytes (a robust, well-cited mitigation HLSE already ships).

**What research shows:**
- **Shannon entropy alone cannot separate encrypted from compressed data** —
  both approach 8 bits/byte (HLSE already cites this). The **chi-square test**
  distinguishes truly-random (encrypted) from merely-compressed streams **better
  than Shannon, KS, or Anderson-Darling** (arXiv 2210.13376, already in HLSE's
  references for the entropy claim but not used for the test itself).
- **Intermittent / partial encryption** (e.g. LockFile, BlackCat) encrypts only
  parts of each file specifically to **defeat first-N-bytes entropy sampling**
  (arXiv 2510.15133). Sampling only the first 4 KB misses this.

**Improvement (on-brand, pure math, no deps):**
- **Add a chi-square uniformity test** alongside Shannon (HLSE already has a
  byte-frequency table via `hlse_shannon_entropy`; chi-square reuses the same
  histogram — near-zero extra cost). Flag as "likely encrypted" only when *both*
  high Shannon *and* chi-square-uniform, which raises precision against
  compressed files that the magic-byte list doesn't catch (e.g. headerless
  archives).
- **Sample multiple segments** (head + middle + tail, or a few strided windows)
  instead of only the first 4 KB, so intermittent encryption is visible. Bounded,
  deterministic, still O(1) reads per file.

Sources: [Entropy calculation methods comparison (arXiv 2210.13376)](https://arxiv.org/pdf/2210.13376),
[Reliable detection of compressed vs encrypted (arXiv 2103.17059)](https://arxiv.org/pdf/2103.17059),
[Intermittent encryption (arXiv 2510.15133)](https://arxiv.org/html/2510.15133v1),
[High-entropy segment classification, Oxford 2025](https://academic.oup.com/cybersecurity/article/11/1/tyaf009/8109429).

---

## 4. Secret scanning — offline structural/checksum validation (P1)

**Current:** `hlse_secrets.c` matches by prefix + charset + min-length, then
excludes placeholders/examples (`AKIAIOSFODNN7EXAMPLE`, `your_api_key_here`) —
matching gitleaks/TruffleHog's FP reduction *without* network (HLSE's stated
design). No structural/checksum validation of the token body.

**What others do:** the 2024 trend is **verification** — TruffleHog authenticates
candidates against live services, cutting FPs dramatically; ML approaches cut FPs
~86%. Both require **network or models**, which HLSE forbids by design.

**Improvement that respects the zero-network constraint:**
- **Offline checksum validation** for providers whose key formats embed a
  self-check, so HLSE can reject malformed/random matches without any network:
  - **GitHub tokens** (`ghp_`, `gho_`, `ghs_`, …) carry a **base62 CRC32
    checksum** in the last characters — validate it locally.
  - **Stripe / Google `AIza` / Slack / Telegram** have fixed structural lengths
    and alphabets that can be tightened.
  This is exactly the "structural validity check" comparable tools do, minus the
  network call, and directly attacks the dominant FP class (high-entropy strings
  that merely share a prefix).
- **Combine entropy + context** for the *generic* high-entropy detector (assign
  weight by the surrounding key-name token, e.g. `secret`, `token`, `password`),
  which the benchmarks show is where entropy-only tools drown in FPs.
- Add a **labeled FP/TP benchmark** (realistic `.env` corpus) as a CI gate, since
  the literature stresses entropy-only scanners produced 50/50 false positives on
  real repos.

Sources: [Reducing FPs in secret scanning (HelpNetSecurity, 2024)](https://www.helpnetsecurity.com/2024/02/27/secrets-scanners-false-positives/),
[Secret scanning guide (Cycode)](https://cycode.com/blog/secret-scanning-guide/),
[LLMs for secret-breach detection (arXiv 2504.18784)](https://arxiv.org/pdf/2504.18784).
(Network-based verification — TruffleHog — intentionally excluded.)

---

## 5. Email / BEC forensics — lookalike-domain + alignment (P2)

**Current:** `hlse_secrets.c` checks SPF/DKIM fail, Reply-To≠From, and
display-name spoofing against a hard-coded brand list; 0.9.0 added BEC
amplifiers (authority + wire + secrecy).

**What others do:** mature BEC detection adds (a) **lookalike sender-domain**
detection via Levenshtein/homoglyph distance to known-good domains
(`paypa1.com`, `micros0ft.com`), (b) **DMARC alignment** (not just SPF/DKIM pass,
but alignment of the authenticated domain with the From domain), and (c)
display-name-to-address mismatch generalized beyond a fixed brand list.

**Improvement:** reuse `hlse_edit_distance` (already in `hlse_util`) to score the
**From/Reply-To domain against the brand/known-domain list** (homoglyph +
typo), and add a **DMARC-alignment** check on top of the existing SPF/DKIM
parsing. All header-only, no network.

Sources: [BEC attack identifiers (Abnormal)](https://abnormal.ai/blog/bec-attack-identifiers),
[BEC detection (Proofpoint)](https://www.proofpoint.com/us/threat-reference/business-email-compromise),
[Email fraud / BEC (Sublime Security)](https://sublime.security/attack-types/business-email-compromise-bec/).

---

## 6. Detection-quality methodology — guard against overfit features (P2)

**Current:** README claims F1 = 1.000 on in- and out-of-distribution corpora; the
OOD corpus (`hlse_corpus_extended.c`) is small and not gated in CI.

**What research warns:** "Can Features for Phishing URL Detection Be Trusted
Across Diverse Datasets?" (arXiv 2411.09813) shows lexical features that score
perfectly on one dataset **fail to generalize**, and phishing-page detectors are
**brittle under adversarial perturbation** (arXiv 2407.20361). A perfect in-corpus
F1 can indicate corpus overfit rather than real robustness.

**Improvement:** expand the OOD corpus toward a **public benign baseline**
(e.g. Tranco/top-domains sample for the 0% FP claim) and **gate OOD F1 in CI**
(the gate currently only checks in-distribution). Treat any single perfect score
as a prompt to widen the corpus, not as a finish line.

Sources: [Cross-dataset feature trust (arXiv 2411.09813)](https://arxiv.org/html/2411.09813),
[Robustness vs adversarial attacks (arXiv 2407.20361)](https://arxiv.org/html/2407.20361v2),
[Contextual URL features (arXiv 2404.09802)](https://arxiv.org/html/2404.09802v1).

---

## 7. File masquerade — extend polyglot / magic coverage (P3)

**Current:** 0.9.0 added polyglot detection (image/archive magic + executable
extension) plus double-extension and bidi-filename checks — already
state-of-aware.

**Improvement (incremental):** broaden the polyglot signature set (e.g.
PDF+ZIP, GIF+JS, MP4+JAR combinations seen in the wild) and reconcile the two
magic-byte tables (`hlse_file.c::detect_magic` vs the new
`hlse_util.c::hlse_is_high_entropy_benign_magic`) so format knowledge lives in
one place.

---

## 8. System audit — hardening index + CIS mapping (P2)

**Current:** `hlse_audit.c` checks a handful of items: SSH config, file
permissions, DNS/`/etc/hosts`/`resolv.conf`, and cron entries.

**What the comparable tool (Lynis) does:** Lynis runs **300+ controls**, emits a
single **"hardening index" score (0–100)**, and maps every finding to **CIS
Benchmark** controls (which PCI-DSS/HIPAA/ISO 27001 reference). It covers
authentication, kernel `sysctl` parameters, network config, logging/`auditd`,
package state, and integrity monitoring — "a server with no unpatched CVEs can
still score 50" because hardening ≠ patching.

**Improvement (on-brand — read-only local checks, no net):**
- Emit a **0–100 hardening score** (HLSE already produces per-check verdicts;
  aggregate them) so users get the same at-a-glance signal Lynis gives.
- Add high-value, well-defined checks HLSE lacks: **kernel `sysctl`**
  (`kernel.randomize_va_space`, `net.ipv4.*` rp_filter/redirects),
  **`auditd`/logging present**, **world-writable files / SUID inventory**,
  **umask**, **password policy** — all flat-file reads.
- **Tag each finding with its CIS Benchmark ID** so output is compliance-useful.
  This is a data/labelling change, not new machinery.

Sources: [Lynis (CISOfy)](https://cisofy.com/lynis/),
[Lynis on GitHub — 300+ controls, compliance mapping](https://github.com/CISOfy/lynis),
[CIS Benchmark audits on Ubuntu](https://oneuptime.com/blog/post/2026-03-02-how-to-run-cis-benchmark-audits-on-ubuntu/view).

---

## 9. Boot integrity — modernize from MBR to UEFI/ESP (P2)

**Current:** `hlse_protect.c` inspects the **legacy MBR** (boot signature,
bootkit strings, first-instruction byte, sector entropy). This only covers
BIOS/MBR-era threats.

**What the threat landscape shows:** the live boot-level threat is **UEFI
bootkits** — **BlackLotus** (2023, first to bypass Secure Boot on fully-patched
Windows 11, CVE-2022-21894 / CVE-2023-24932) and **Bootkitty** (first **Linux**
UEFI bootkit, 2024). These do **not** touch the MBR; they tamper with the **EFI
System Partition (ESP)**. Documented indicators: **unrecognized/unsigned `.efi`
files**, modified bootloaders, altered boot entries.

**Improvement:** add an **ESP integrity check** alongside the MBR check — scan
`/boot/efi/EFI/**` for unexpected/unsigned `.efi` binaries, flag modified
bootloader files, and (optionally) compare against a recorded baseline hash set.
Pure filesystem reads, no net. Keep the MBR check for legacy systems but
document that **MBR detection is historical** and ESP is where current attacks
live.

Sources: [BlackLotus analysis (WeLiveSecurity/ESET)](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/),
[NSA BlackLotus mitigation guide](https://thehackernews.com/2023/06/nsa-releases-guide-to-combat-powerful.html),
[Binarly: untold story of BlackLotus](https://www.binarly.io/blog/the-untold-story-of-the-blacklotus-uefi-bootkit).

---

## 10. Clipboard crypto-swap — exploit the visual-similarity signal (P2)

**Current:** `hlse_check_crypto_swap` flags when a copied address differs from a
pasted one (BTC/ETH), scoring any mismatch as a swap.

**What research adds (EthClipper, arXiv 2108.14004):** sophisticated clippers
(Laplas, Clipminer, the Linux **ClipXDaemon**, 2024) don't pick a *random*
replacement — they **select an address with maximum visual similarity** to the
original (same leading/trailing characters) so a glancing check passes. The
*degree of visual similarity* is itself the strongest evidence of a deliberate
clipper rather than a benign edit.

**Improvement:** score the swap **higher when the replacement shares the
original's prefix/suffix** (the deliberate-clipper signature) using a
prefix/suffix-match length on top of the existing equality check — reusing
`hlse_edit_distance`/simple char comparison, no net. This raises confidence and
explains *why* a swap is malicious.

Sources: [EthClipper (arXiv 2108.14004)](https://arxiv.org/abs/2108.14004),
[Clipboard hijacker replaces addresses with lookalikes (BleepingComputer)](https://www.bleepingcomputer.com/news/security/new-clipboard-hijacker-replaces-crypto-wallet-addresses-with-lookalikes/),
[ClipXDaemon Linux clipper (Cyble)](https://cyble.com/blog/clipxdaemon-autonomous-x11-clipboard-hijacker/).

---

## 11. Pastejacking — cover the ClickFix evolution (P1/P2)

**Current:** the `paste` subcommand flags `curl … | bash` style pastejacking.

**What's new:** the dominant 2024–2025 variant is **ClickFix** — a fake "Verify
you are human" / "Fix It" prompt that silently writes a command to the clipboard
for the user to paste into a terminal or Run dialog. Payloads hide behind
encoding (`base64 -d | sh`, `powershell -enc`), embedded newlines that
auto-execute on paste, and multi-stage downloaders.

**Improvement (string analysis, no net):** extend the `paste` detector to flag
**encoded-payload pipelines** (`base64`/`xxd`/`-enc` feeding a shell),
**embedded newline/carriage-return auto-run**, `mshta`/`powershell -w hidden`,
and the **ClickFix lure phrasing** ("verify you are human", "press Win+R") when
co-located with a command. Reuses HLSE's existing text-normalization
(de-obfuscation) machinery.

Sources: [ClickFix attack vector (Unit 42 / Palo Alto)](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/),
[Pastejacking detection (Palo Alto LIVEcommunity)](https://live.paloaltonetworks.com/t5/community-blogs/detection-of-pastejacking-social-engineering-tactics/ba-p/1247439),
[Clipboard hijacking (HackTricks)](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/phishing-methodology/clipboard-hijacking.html).

---

## Priority summary

| # | Area | Change | On-brand? | Priority |
|---|------|--------|-----------|----------|
| 1 | URL phishing | Punycode `xn--` decode + UTS-39 skeleton/confusables | ✅ pure C, no net | **P1** |
| 4 | Secrets | Offline checksum/structural validation (GitHub CRC32 …) | ✅ no net | **P1** |
| 11 | Pastejacking | ClickFix lures + encoded-payload pipelines | ✅ reuses normaliser | **P1/P2** |
| 3 | Ransomware | Chi-square test + multi-segment sampling | ✅ reuses histogram | **P1/P2** |
| 2 | Typosquat | Popularity gate + confusion taxonomy + slopsquatting | ✅ bundled data | **P1/P2** |
| 5 | Email/BEC | Lookalike-domain distance + DMARC alignment | ✅ header-only | **P2** |
| 8 | System audit | Hardening index score + CIS mapping + more checks | ✅ flat-file reads | **P2** |
| 9 | Boot integrity | Add UEFI/ESP check (MBR is legacy-only) | ✅ fs reads | **P2** |
| 10 | Clipboard swap | Visual-similarity (prefix/suffix) scoring | ✅ no net | **P2** |
| 6 | Methodology | Gate OOD F1, add benign baseline corpus | ✅ | **P2** |
| 7 | File masquerade | More polyglot combos, unify magic tables | ✅ | **P3** |

**Top recommendation:** start with **#1 (Punycode + UTS-39)** — it closes
HLSE's largest concrete detection gap (IDN homograph attacks are currently
undetectable) and is fully consistent with the dependency-free, zero-network
design — followed by **#4 (offline secret checksum validation)** and **#3
(chi-square entropy)**, both of which add precision by reusing machinery HLSE
already has.
