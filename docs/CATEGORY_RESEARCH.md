# HLSE Category Research — 10 Categories × ~10 Sources

Improvement scan for HLSE across **10 product categories**. For each category:
the comparable **tools (GitHub)** and **research (arXiv / venues)**, then concrete
**improvement points** for HLSE. All proposals respect HLSE's design contract:
portable dependency-free C, **zero network calls**, allocation-light,
deterministic. Network/ML-only techniques are flagged as out-of-scope where they
conflict with that contract.

> Companion to `docs/RESEARCH_IMPROVEMENTS.md` (prioritized backlog). This file
> is the broader source survey behind it.

---

## 1. URL phishing / IDN homoglyph / domain spoofing

**HLSE today:** `hlse_core.c` — confusables (9-entry ASCII table), digraph
(`rn→m`), typosquat (DL≤2 vs hard-coded brands), TLD/path heuristics, DGA
entropy. **No Punycode (`xn--`) decoding.**

Sources:
1. [elceef/dnstwist](https://github.com/elceef/dnstwist) — homograph/typo permutation engine; LSH fuzzy hashes + pHash for page similarity.
2. [atenreiro/opensquat](https://github.com/atenreiro/opensquat) — look-alike domain detection with IDN/unicode rendering of `xn--`.
3. [ics/libtyposquats](https://github.com/ics/libtyposquats) — C-friendly typosquat library.
4. [SunnyThakur25/Phishing-URL-Detector](https://github.com/SunnyThakur25/Phishing-URL-Detector) — blocklists + typosquat + homoglyph normalization.
5. [GitHub topic: homograph-attack](https://github.com/topics/homograph-attack) / [punycode-phishing](https://github.com/topics/punycode-phishing).
6. [Unicode UTS #39 — Security Mechanisms](https://www.unicode.org/reports/tr39/) — confusable skeleton + restriction profiles.
7. [Can Phishing-URL Features Be Trusted Across Datasets? (arXiv 2411.09813)](https://arxiv.org/html/2411.09813) — feature generalization caution.
8. [ML→LLM robustness of phishing detectors (arXiv 2407.20361)](https://arxiv.org/html/2407.20361v2) — adversarial brittleness.
9. [Sequential DL on contextual URL features (arXiv 2404.09802)](https://arxiv.org/html/2404.09802v1).
10. [IP-augmented multi-modal malicious-URL detection (arXiv 2510.12395)](https://arxiv.org/html/2510.12395) — IP/host features vs obfuscated URLs.

**改善点:**
- **Add Punycode `xn--` decoding** (RFC 3492, ~80 LOC) → run decoded labels
  through a UTS-39-aligned mixed-script / whole-script-confusable check. Closes
  the biggest concrete gap (IDN homograph blind spot).
- Adopt the **UTS-39 skeleton** with a bundled confusables subset instead of the
  9-entry table; add the **Highly Restrictive** mixed-script rule.
- Borrow dnstwist's idea of **registrable-domain extraction + brand distance**;
  optionally fold in IP-host signals (per 2510.12395).

---

## 2. Text scam / BEC / social-engineering NLP

**HLSE today:** `hlse_text.c` — keyword/urgency/authority/secrecy rules, BEC
amplifiers, multilingual normalization, de-obfuscation.

Sources:
1. [Labeled email dataset for phishing/spam (arXiv 2511.21448)](https://arxiv.org/html/2511.21448v1) — feature-rich benchmark; 99% of phish now use social engineering.
2. [Robust ML detection of conventional/LLM/adversarial phishing (arXiv 2510.11915)](https://arxiv.org/html/2510.11915v1) — preprocessing for evasive text.
3. [Enhancing phishing-email ID with LLMs (arXiv 2502.04759)](https://arxiv.org/pdf/2502.04759).
4. [SoK: LLM-generated textual phishing campaigns (arXiv 2508.21457)](https://arxiv.org/html/2508.21457v1) — LLM spear-phish CTR >30%.
5. [Context-aware phishing-email detection, ML+NLP (arXiv 2603.27326)](https://arxiv.org/pdf/2603.27326).
6. [Abnormal — 13 BEC red flags](https://abnormal.ai/blog/bec-attack-identifiers).
7. [Proofpoint — BEC defined](https://www.proofpoint.com/us/threat-reference/business-email-compromise).
8. [Sublime Security — BEC attack types](https://sublime.security/attack-types/business-email-compromise-bec/).
9. [Check Point — BEC types](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-email-security/business-email-compromise-bec/).
10. [Palo Alto — BEC tactics](https://www.paloaltonetworks.com/cyberpedia/what-is-business-email-compromise-bec-tactics-and-prevention).

**改善点:**
- LLM-written phishing is **grammatically clean** → don't lean on
  spelling/grammar; weight **structural/behavioral** signals (authority+wire,
  reply-to mismatch, new-domain) — HLSE's amplifier approach is on the right
  track; expand it.
- Add **lookalike sender-domain distance** (reuse `hlse_edit_distance`) and
  **DMARC alignment** on top of SPF/DKIM.
- Grow the **multilingual** scam-phrase tables (the datasets above show locale
  variance matters).

---

## 3. Ransomware behavioral detection (entropy / crypto)

**HLSE today:** `hlse_protect.c` — Shannon entropy (>7.5) on first 4 KB + magic
exclusion of benign high-entropy formats; ransom-note names; extension mutation.

Sources:
1. [Comparison of entropy calc methods (arXiv 2210.13376)](https://arxiv.org/pdf/2210.13376) — **chi-square beats Shannon** at encrypted-vs-compressed.
2. [Reliable detection of compressed vs encrypted (arXiv 2103.17059)](https://arxiv.org/pdf/2103.17059).
3. [Intermittent file encryption (arXiv 2510.15133)](https://arxiv.org/html/2510.15133v1) — evades first-N-bytes entropy.
4. [Cross-domain entropy signatures (arXiv 2502.10711)](https://arxiv.org/html/2502.10711v1).
5. [Decentralized entropy-based detection (arXiv 2502.09833)](https://arxiv.org/html/2502.09833v1).
6. [High-entropy segment classification, Oxford 2025](https://academic.oup.com/cybersecurity/article/11/1/tyaf009/8109429).
7. [R-Locker honeyfile approach, MDPI](https://www.mdpi.com/2227-7390/13/12/1933).
8. [Raz99/ransomware-detector](https://github.com/Raz99/ransomware-detector) — entropy + MIME-change + fuzzy similarity + decoys.
9. [rudra00434/Ransomware_Shield](https://github.com/rudra00434/Ransomware_Shield) — pre/post entropy jump >7.0 on honeyfiles.
10. [Aayushjn/RansomwareLocker](https://github.com/Aayushjn/RansomwareLocker) — inotify/auditd honeyfile detection (Linux).

**改善点:**
- **Add a chi-square uniformity test** (reuses the existing byte histogram, ~free)
  alongside Shannon; flag only when both agree → fewer FPs on headerless
  compressed files.
- **Sample head+middle+tail segments**, not just the first 4 KB, to catch
  **intermittent encryption**.
- Detect **extension-vs-MIME mismatch** (encrypted file keeps `.docx` but loses
  the magic). Honeyfile/decoy needs live monitoring → note as out-of-scope for
  the one-shot scanner, in-scope only if a daemon mode is ever added.

---

## 4. Secret / credential scanning

**HLSE today:** `hlse_secrets.c` — prefix + charset + min-length, placeholder/
example exclusion. **No checksum/structural validation; no network (by design).**

Sources:
1. [Comparative study of secret-detection tools (arXiv 2307.00714)](https://arxiv.org/pdf/2307.00714) — no single tool finds all; high FP from generic regex+entropy.
2. [LLMs for secret-breach detection (arXiv 2504.18784)](https://arxiv.org/pdf/2504.18784).
3. [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) — fast regex+entropy, pre-commit.
4. [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — **live credential verification** (network — out of scope for HLSE).
5. [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) — **baseline** workflow to suppress known.
6. [GitGuardian/ggshield](https://github.com/GitGuardian/ggshield) — 500+ secret types.
7. [TruffleHog vs GitGuardian comparison](https://www.gitguardian.com/comparisons/trufflehog-v3).
8. [Secrets-scanner comparison (detect-secrets/Gitleaks/TruffleHog)](https://devsecops.ae/secrets-scanners-comparison-2026/).
9. [Reducing FPs with AI (Help Net Security, 2024)](https://www.helpnetsecurity.com/2024/02/27/secrets-scanners-false-positives/) — ~86% FP cut.
10. [Cycode secret-scanning guide](https://cycode.com/blog/secret-scanning-guide/).

**改善点:**
- **Offline checksum/structural validation** (GitHub PAT base62 **CRC32**,
  Stripe/Google `AIza`/Slack length+alphabet) — the network-free equivalent of
  TruffleHog's "is it structurally real," attacking the dominant FP class.
- Add a **baseline/allowlist** workflow (detect-secrets-style) for CI adoption.
- **Entropy + key-name context** for the generic detector; add a labeled FP/TP
  `.env` corpus as a CI gate.
- Broaden secret **type coverage** toward the 500+ that ggshield handles.

---

## 5. Software supply-chain / malicious packages

**HLSE today:** `hlse_supply.c` — typosquat DL≤2 vs hard-coded list; pastejacking;
ARP/DNS checks.

Sources:
1. [TypoSmart (arXiv 2502.20528)](https://arxiv.org/html/2502.20528v1) — low-FP multi-signal typosquat.
2. [SpellBound (arXiv 2003.03471)](https://arxiv.org/pdf/2003.03471) — **popularity-weighted** similarity.
3. [Package confusion taxonomy, USENIX '23](https://ldklab.github.io/assets/papers/usenix23-confusion.pdf).
4. [OSS malicious packages in the wild (arXiv 2404.04991)](https://arxiv.org/html/2404.04991v1/).
5. [ML detection of malicious PyPI (arXiv 2412.05259)](https://arxiv.org/html/2412.05259v1).
6. [NPM malicious-package detection benchmark (arXiv 2603.27549)](https://arxiv.org/html/2603.27549v1).
7. [Knowledge-mining framework for malicious PyPI (arXiv 2601.16463)](https://arxiv.org/html/2601.16463).
8. [DataDog/guarddog](https://github.com/DataDog/guarddog) — Semgrep + heuristics; distance-to-top-5000.
9. [microsoft/OSSGadget](https://github.com/microsoft/OSSGadget) — OSS analysis toolset.
10. [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) — 26k+ vetted samples.
11. [Slopsquatting / AI-hallucinated packages (Snyk)](https://snyk.io/articles/slopsquatting-mitigation-strategies/) — 19.7% generated samples reference non-existent packages.

**改善点:**
- **Popularity gate**: bundle a top-N ranked snapshot; alert only when an
  *unknown* name is close to a *popular* one (kills FPs).
- Add **separator confusion** (`-`/`_`/`.`), **combosquatting**, **keyboard
  distance**; cover **slopsquatting** (plausible names absent from the snapshot).
- Optional **install-script static signals** (guarddog-style: net + exec +
  obfuscation co-occurrence) for fetched package metadata, still offline.

---

## 6. File masquerade / polyglot / magic-byte

**HLSE today:** `hlse_file.c` — magic table, double-extension, bidi filename,
polyglot (image/archive magic + exe ext) added in 0.9.0.

Sources:
1. [Polyglots & attack chains; detection & disarm (arXiv 2407.01529)](https://arxiv.org/html/2407.01529v1).
2. [Toward the Detection of Polyglot Files (CSET '22 / ACM)](https://dl.acm.org/doi/fullHtml/10.1145/3546096.3546106).
3. [trailofbits/polyfile](https://github.com/trailofbits/polyfile) — cleanroom libmagic + recursive embedded-file mapping.
4. [Polydet/polydet](https://github.com/Polydet/polydet) — best-in-class polyglot detector by F1.
5. [corkami/mitra](https://github.com/corkami/mitra) — polyglot generator (stacks/cavities/parasites/zippers) → test corpus.
6. [VirusTotal/yara](https://github.com/VirusTotal/yara) — magic-in-wrong-container rules (e.g. `MZ` inside PDF).
7. [Trail of Bits — libmagic critique](https://blog.trailofbits.com/2022/07/01/libmagic-the-blathering/).
8. [MITRE ATT&CK T1036.008 — masquerade file type](https://www.securityscientist.net/blog/12-questions-and-answers-about-masquerade-file-type-t1036-008/).

**改善点:**
- Broaden **polyglot combos** (PDF+ZIP, GIF+JS, MP4+JAR); add **MZ/PE-in-document**
  YARA-style rule.
- **Recursive embedded-file** scan (polyfile/binwalk idea) for archives/images.
- Use **corkami/mitra** outputs as a polyglot **test corpus**; unify the two
  in-repo magic tables (`detect_magic` vs `hlse_is_high_entropy_benign_magic`).

---

## 7. Host hardening audit

**HLSE today:** `hlse_audit.c` — SSH config, file perms, DNS/hosts/resolv.conf,
cron. Small surface, no score.

Sources:
1. [CISOfy/lynis](https://github.com/CISOfy/lynis) — 300+ controls, **hardening index**, CIS/PCI/HIPAA/ISO mapping.
2. [OpenSCAP](https://www.open-scap.org/) — SCAP-automated control testing.
3. [jtesta/ssh-audit](https://github.com/jtesta/ssh-audit) — deep SSH config/algorithm audit.
4. [dev-sec hardening (Ansible Galaxy)](https://github.com/dev-sec) — SSH/sysctl/auditd baselines.
5. [gensecaihq/Ubuntu-Security-Hardening-Script](https://github.com/gensecaihq/Ubuntu-Security-Hardening-Script) — OpenSCAP + DISA-STIG.
6. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — control catalog.
7. [Linux Audit — OSS auditing vs CIS](https://linux-audit.com/using-open-source-auditing-tools-as-alternative-for-cis-benchmarks/).
8. [Linux Audit — Tiger is history](https://linux-audit.com/tiger-is-history-long-live-modern-alternatives/) (don't repeat Tiger's mistakes).

**改善点:**
- Emit a **0–100 hardening index** (aggregate existing verdicts).
- Add high-value checks HLSE lacks: **kernel sysctl** (ASLR, rp_filter,
  redirects), **auditd/logging present**, **SUID inventory**, **world-writable**,
  **umask**, **password policy** — all flat-file reads.
- **Tag findings with CIS Benchmark IDs** for compliance use.

---

## 8. Boot / firmware integrity (MBR → UEFI)

**HLSE today:** `hlse_protect.c` — **legacy MBR only** (signature, bootkit
strings, entropy). No UEFI/ESP coverage.

Sources:
1. [chipsec/chipsec](https://github.com/chipsec/chipsec) — platform/firmware assessment; **reference-image diff** to detect modifications.
2. [LongSoft/UEFITool](https://github.com/LongSoft/UEFITool) — UEFI image parse/integrity.
3. [fwupd/fwupd + HSI](https://fwupd.github.io/libfwupdplugin/hsi.html) — Host Security ID scoring.
4. [river-li/awesome-uefi-security](https://github.com/river-li/awesome-uefi-security) — papers/tools/exploits.
5. [PreOS-Security/awesome-firmware-security](https://github.com/PreOS-Security/awesome-firmware-security).
6. [TheMalwareGuardian/UEFI-Firmware-Analysis](https://github.com/TheMalwareGuardian/UEFI-Firmware-Analysis).
7. [ESET — BlackLotus UEFI bootkit confirmed](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/).
8. [NSA — BlackLotus mitigation guide](https://thehackernews.com/2023/06/nsa-releases-guide-to-combat-powerful.html).
9. [Binarly — untold story of BlackLotus](https://www.binarly.io/blog/the-untold-story-of-the-blacklotus-uefi-bootkit).
10. [Huntress — CVE-2023-24932 Secure Boot bypass](https://www.huntress.com/threat-library/vulnerabilities/cve-2023-24932).

**改善点:**
- Add an **ESP integrity check**: scan `/boot/efi/EFI/**` for unexpected/unsigned
  `.efi` files and modified bootloaders (where BlackLotus/Bootkitty live).
- **Reference-baseline hashing** of boot components (CHIPSEC's diff idea), offline.
- Expose an **HSI-style host-security score**; mark MBR detection as *legacy*.

---

## 9. Clipboard / pastejacking / clipper

**HLSE today:** `hlse_supply.c` pastejacking (`curl|bash`); `hlse_check_crypto_swap`
flags any address mismatch.

Sources:
1. [EthClipper (arXiv 2108.14004)](https://arxiv.org/abs/2108.14004) — clippers pick **max visual-similarity** replacement addresses.
2. [Dan-Duran/clipboard-hijacking-POC](https://github.com/Dan-Duran/clipboard-hijacking-POC) — attack mechanics (test cases).
3. [3xploitGuy/pastehakk](https://github.com/3xploitGuy/pastehakk) — clipboard-poisoning PoC.
4. [Unit 42 — preventing the ClickFix vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/).
5. [Palo Alto LIVEcommunity — pastejacking detection](https://live.paloaltonetworks.com/t5/community-blogs/detection-of-pastejacking-social-engineering-tactics/ba-p/1247439).
6. [HackTricks — clipboard hijacking](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/phishing-methodology/clipboard-hijacking.html).
7. [BleepingComputer — lookalike-address clipboard hijacker](https://www.bleepingcomputer.com/news/security/new-clipboard-hijacker-replaces-crypto-wallet-addresses-with-lookalikes/).
8. [Cyble — ClipXDaemon (Linux X11 clipper, 2024)](https://cyble.com/blog/clipxdaemon-autonomous-x11-clipboard-hijacker/).
9. [hunt.io — Laplas Clipper](https://hunt.io/malware-families/laplas-clipper).
10. [Halborn — clipper malware overview](https://www.halborn.com/blog/post/clipper-malware-how-hackers-steal-crypto-with-clipboard-hijacking).

**改善点:**
- Score crypto-swap **higher when replacement shares the original's prefix/suffix**
  (the deliberate-clipper signature per EthClipper).
- Extend `paste` to the **ClickFix** evolution: encoded pipelines
  (`base64 -d|sh`, `powershell -enc`), embedded-newline auto-run, lure phrasing.
- Support more coin formats (legacy BTC `1`/`3`, ETH `0x`, Monero).

---

## 10. Engineering robustness (testing / evasion / integration)

**HLSE today:** 237+ tests, 100K fuzz (only `hlse_text.c`), ASan/UBSan, strict
warnings, SARIF output (0.9.0), property tests.

Sources:
1. [Robustness of malware detectors to adversarial samples (arXiv 2408.02310)](https://arxiv.org/abs/2408.02310).
2. [Evaluating adversarial defenses in malware detection (arXiv 2505.09342)](https://arxiv.org/abs/2505.09342).
3. [Fuzzers vs static analysis for C/C++ memory unsafety (arXiv 2505.22052)](https://arxiv.org/pdf/2505.22052) — **CodeQL + AFL++ together** finds most.
4. [LLM-powered vuln detection & patching (arXiv 2509.07225)](https://arxiv.org/html/2509.07225v1).
5. [Hyperfuzzing (arXiv 2308.09081)](https://arxiv.org/pdf/2308.09081).
6. [AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) — coverage-guided fuzzing.
7. [google/oss-fuzz](https://github.com/google/oss-fuzz) — continuous fuzzing for OSS.
8. [github/codeql](https://github.com/github/codeql) — semantic SAST (proposed in backlog).
9. [VirusTotal/yara](https://github.com/VirusTotal/yara) — rule engine for detection corpora.
10. [SARIF 2.1.0 (OASIS)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — already emitted by HLSE.

**改善点:**
- **Extend fuzzing to every module** (currently only `hlse_text.c`): add harnesses
  for secrets/protect/supply/file parsers.
- Pair **CodeQL (SAST) + AFL++ (coverage-guided)** — research shows low overlap,
  so both maximize bug yield (CodeQL workflow already drafted).
- Build an **adversarial/evasion corpus** (homoglyph, zero-width, polyglot via
  mitra, LLM-generated phish) as a regression gate against the brittleness the
  adversarial papers document.
- Consider **OSS-Fuzz** onboarding for continuous fuzzing.

---

## Cross-category priority (top picks)

| Category | Highest-leverage improvement | On-brand |
|----------|------------------------------|----------|
| 1 URL phishing | Punycode `xn--` decode + UTS-39 skeleton | ✅ |
| 4 Secrets | Offline checksum validation (GitHub CRC32 …) | ✅ |
| 3 Ransomware | Chi-square + multi-segment sampling | ✅ |
| 9 Clipboard | Visual-similarity scoring + ClickFix | ✅ |
| 5 Supply-chain | Popularity gate + slopsquatting | ✅ |
| 8 Boot | UEFI/ESP integrity (MBR is legacy) | ✅ |
| 7 Audit | Hardening index + CIS mapping | ✅ |
| 10 Engineering | Fuzz all modules + CodeQL/AFL++ | ✅ |

The recurring theme across every category: HLSE's heuristics are sound but
**single-signal**; the literature and tooling have moved to **multi-signal**
(popularity, chi-square, visual similarity, structural/checksum validation,
combined SAST+fuzzing). Most upgrades reuse machinery HLSE already has and keep
the dependency-free, zero-network contract intact.
