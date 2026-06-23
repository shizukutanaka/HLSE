/*
 * hlse_core.h — Public API for HLSE Core URL detection.
 *
 * Build the implementation with `-DHLSE_CORE_AS_LIB` to omit the CLI
 * entry point and expose this API:
 *
 *     gcc -DHLSE_CORE_AS_LIB -fPIC -shared \
 *         -o libhlse_core.so hlse_core.c hlse_text.c
 *
 * Usage from C:
 *
 *     #include "hlse_core.h"
 *     #include "hlse_text.h"
 *
 *     Verdict v = hlse_check_url("https://g00gle.com");
 *     if (v.score >= 60) { ... block ... }
 *
 * Usage from other languages: link against libhlse.so via the FFI
 * facility of your language (Python ctypes, Go cgo, etc).
 *
 * Identity anchor: bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5
 */

#ifndef HLSE_CORE_H
#define HLSE_CORE_H

#include <stddef.h>   /* size_t, for hlse_safe_destination() */
#include "hlse_text.h" /* TextVerdict, for hlse_classify_text_attack() */

/* Version — available to library users without access to the .c source. */
#define HLSE_VERSION "1.0.88"

#ifdef __cplusplus
extern "C" {
#endif

/* The result of analysing a URL.
 *
 *   score      — 0..100; threshold mapping:
 *                  0..14   SAFE
 *                 15..39   LOG
 *                 40..59   ALERT
 *                 60..79   BLOCK
 *                 80+      ISOLATE
 *   n_reasons  — number of populated entries in `reasons`
 *   reasons    — human-readable explanations of each detector that fired
 *
 * If parsing fails (unsupported scheme, malformed URL), `score` is 0 and
 * `n_reasons` is 0 unless the URI uses a dangerous scheme (javascript:,
 * data:) — in that case score is 90 with one reason.                  */
typedef struct {
    int  score;
    int  n_reasons;
    char reasons[12][128];
} Verdict;

/* Analyse a URL for phishing/spoofing patterns.
 *
 * Thread-safe: reads only static const tables. Multiple threads may
 * call concurrently with their own input strings.
 *
 * Time complexity: O(n × m) where n = URL length, m = brand list size.
 * Typical hot-path latency: 17 µs (clean), 170 µs (malicious).
 *
 * Returns a stack-allocated Verdict struct (no allocation).            */
Verdict hlse_check_url(const char *raw_url);

/* Map a numeric score to a human-readable action string ("SAFE",
 * "LOG", "ALERT", "BLOCK", "ISOLATE"). Returned string has static
 * lifetime; do not free.                                               */
const char *hlse_action_for_score(int score);

/* Map a score to a monotonic severity integer (0–4) for SIEM/SOAR rules.
 * Prefer this over string-matching `action`: `severity >= 3` correctly covers
 * BLOCK and ISOLATE (and any future tier inserted above BLOCK), whereas
 * hard-coded string comparisons break silently when tiers are added.
 *   0 = SAFE (0..14)   1 = LOG (15..39)   2 = ALERT (40..59)
 *   3 = BLOCK (60..79)  4 = ISOLATE (80+)
 * Thread-safe; no allocation.                                               */
int hlse_severity_for_score(int score);

/* Recommended next action for an actionable verdict (score >= 60); NULL if
 * there is no specific guidance for `kind`. */
const char *hlse_remediation_for(const char *kind, int score);

/* Blind-spot disclosure for a CLEAN verdict — what HLSE cannot see, so an OK
 * is not mistaken for proof of safety. NULL when there is no caveat. */
const char *hlse_blindspot_for(const char *kind);

/* Exoneration for a HEURISTIC threat (score 15..59) — the benign explanation
 * and falsifying test, so a low-confidence ALERT is neither panic nor noise.
 * NULL outside the LOG/ALERT band or when there is no caveat. */
const char *hlse_exoneration_for(const char *kind, int score);

/* Pattern-aware exoneration for a URL verdict — the benign explanation keyed
 * to the actual attack pattern that fired (shortener, subdomain, typosquat,
 * DGA, …) rather than a generic heuristic. Falls back to
 * hlse_exoneration_for("url", v->score) when no specific pattern is
 * recognisable. Returns NULL outside the LOG/ALERT band [15, 59]. */
const char *hlse_url_exoneration(const Verdict *v);

/* Pattern-aware exoneration for a text verdict — the benign explanation and
 * falsifying test keyed to the specific social-engineering pattern rather than
 * the generic "urgent wording appears in genuine messages" catch-all. Text
 * counterpart of hlse_url_exoneration(). Keyed to the pattern returned by
 * hlse_classify_text_attack(): QR → "scan with preview app first", callback →
 * "call the official number instead", investment → "verify FCA/SEC register",
 * lottery → "genuine prizes don't require upfront fees", etc. Falls back to
 * hlse_exoneration_for("text", score) when no pattern is recognisable.
 * Returns NULL outside the LOG/ALERT band [15, 59]. Thread-safe; no alloc. */
const char *hlse_text_exoneration(const TextVerdict *v);

/* Synthesise a named attack-pattern label from the signals in a URL Verdict
 * (e.g. "typosquat credential-harvest page", "free-hosting phishing
 * infrastructure"). Returns NULL when score is 0 or no recognisable pattern
 * is found. The label is always a short phrase — display it as a summary
 * line after the per-signal reasons. */
const char *hlse_classify_url_attack(const Verdict *v);

/* Return a stable machine-readable pattern identifier for a URL Verdict — the
 * URL counterpart of hlse_text_pattern_id(). The human label from
 * hlse_classify_url_attack() may be refined across versions, but these
 * HLSE-URL-* tokens are APPEND-ONLY: once issued they never change meaning, so
 * SIEM/SOAR rules can key on them without substring-matching fragile prose.
 *
 * Defined tokens (current):
 *   HLSE-URL-IDN-HOMOGRAPH, HLSE-URL-MULTI-BRAND, HLSE-URL-HOMOGLYPH,
 *   HLSE-URL-AT-CRED-TRICK, HLSE-URL-IP-BRAND, HLSE-URL-FREEHOST,
 *   HLSE-URL-SUBDOMAIN-HARVEST, HLSE-URL-SUBDOMAIN, HLSE-URL-TYPOSQUAT-HARVEST,
 *   HLSE-URL-TYPOSQUAT, HLSE-URL-HYPHEN-HARVEST, HLSE-URL-HYPHEN-BRAND,
 *   HLSE-URL-CRED-HARVEST, HLSE-URL-BRAND-RISKY-TLD, HLSE-URL-BRAND,
 *   HLSE-URL-SHORTENER, HLSE-URL-DGA, HLSE-URL-GENERIC.
 * Returns NULL when score is 0 or no pattern was found. Thread-safe; no alloc. */
const char *hlse_url_pattern_id(const Verdict *v);

/* Synthesise a named social-engineering attack-pattern label from the signals
 * in a text verdict (e.g. "BEC / CEO-fraud wire-transfer", "urgency
 * credential-harvest phishing", "ClickFix script-injection lure"). This is the
 * text counterpart of hlse_classify_url_attack. Returns NULL when score is 0
 * or no recognisable pattern was found. Thread-safe; no allocation. */
const char *hlse_classify_text_attack(const TextVerdict *v);

/* Return a stable machine-readable pattern identifier for a text verdict —
 * the SIEM/automation counterpart of hlse_classify_text_attack(). While the
 * human label may be refined across versions, these HLSE-* tokens are
 * APPEND-ONLY: once issued they never change meaning, so downstream rules can
 * key on them without substring-matching fragile prose.
 *
 * Defined tokens (current):
 *   HLSE-CLICKFIX, HLSE-OAUTH-DEVICECODE, HLSE-MFA-FATIGUE,
 *   HLSE-BEC-PAYMENT-DIVERSION, HLSE-BEC-CEO, HLSE-BEC-WIRE,
 *   HLSE-TECH-SUPPORT, HLSE-JOB-SCAM, HLSE-ADVANCE-FEE,
 *   HLSE-SEXTORTION, HLSE-RANSOM, HLSE-INVESTMENT, HLSE-EMERGENCY,
 *   HLSE-QUISHING, HLSE-REFUND-SCAM, HLSE-CALLBACK-TOAD,
 *   HLSE-AUTHORITY, HLSE-URGENCY-CRED, HLSE-FAKE-ALERT,
 *   HLSE-URGENCY, HLSE-CRED-LURE, HLSE-PRIZE, HLSE-GENERIC.
 * Returns NULL when score is 0 or no pattern was found. Thread-safe; no alloc. */
const char *hlse_text_pattern_id(const TextVerdict *v);

/* First-response triage for a text verdict — the 60-second action the post-
 * response user must take (score >= 60 only). Keyed to the same attack pattern
 * as hlse_classify_text_attack so the response matches the specific harm:
 * BEC → "call your bank to request SWIFT recall", ClickFix → "disconnect and
 * reinstall", grandparent scam → "call the family member directly", etc.
 * Returns a static string, or NULL when score < 60 or no recognisable pattern. */
const char *hlse_text_triage(const TextVerdict *v);

/* Pre-action verification for a text verdict — the single check to perform
 * BEFORE taking any requested action (score >= 60 only). The text counterpart
 * of hlse_verification_for() for URLs. Keyed to the attack pattern:
 *   BEC/CEO-fraud    → call the supposed sender on a separately-known number
 *   ClickFix         → never paste commands from unsolicited messages
 *   tech-support     → call the company's main switchboard independently
 *   ransomware       → do not pay; consult law enforcement
 *   investment       → verify FCA/SEC/ASIC registration first
 *   grandparent/emg. → call the family member on their known number
 *   callback/vishing → don't call the provided number
 *   lottery/advance-fee → don't pay any upfront fee
 *   QR phishing      → preview QR destination before scanning
 *   urgency/cred.    → navigate to the site directly via bookmark/search
 * Returns NULL when score < 60 or no recognisable pattern. Thread-safe;
 * no allocation. */
const char *hlse_text_verify(const TextVerdict *v);

/* Name the attacker's likely objective for a text verdict — the specific asset
 * the recipient must treat as at-risk (score >= 60 only). The text counterpart
 * of hlse_attacker_objective(), but keyed to the social-engineering attack
 * pattern rather than an impersonated brand:
 *   BEC/CEO-fraud    → wire-transfer funds (72-hour SWIFT recall window)
 *   ClickFix         → system access (runs with user privileges)
 *   tech-support     → credit card or remote device access
 *   ransomware       → cryptocurrency payment / file access
 *   investment       → long-term savings (unrecoverable)
 *   grandparent/emg. → cash withdrawal (unrecoverable)
 *   QR phishing      → credentials after camera-bypass redirect
 *   callback/vishing → financial account or device via voice
 *   urgency/cred.    → account credentials (cascade risk)
 * Returns NULL when score < 60 or no recognisable pattern. Thread-safe; no alloc. */
const char *hlse_text_objective(const TextVerdict *v);

/* Cascade risk for a text verdict — the other accounts and assets at risk
 * beyond the primary target, after a text BLOCK threat materialises (score >= 60).
 * Text counterpart of hlse_cascade_risk() for URL verdicts. Keyed to pattern:
 *   ClickFix         → all browser/OS stored credentials (exfiltrated by script)
 *   BEC/CEO-fraud    → corporate email (recovery address for every service)
 *   tech-support     → all credentials visible during remote-access session
 *   urgency/cred.    → email + every account sharing the harvested password
 *   QR phishing      → account entered after redirect + email + shared passwords
 *   investment       → other liquid assets and exchange/bank accounts funded
 * Returns NULL when score < 60 or no recognisable pattern. Thread-safe; no alloc. */
const char *hlse_text_cascade(const TextVerdict *v);

/* Count the number of INDEPENDENT signal categories that fired in a text
 * verdict — the text counterpart of hlse_confidence_for. Counts distinct base
 * signal families (urgency, financial, authority, secrecy, etc.); excludes
 * amplifier lines which are derived. Maps the count to the same qualitative
 * labels: 1 → "single signal", 2 → "corroborated", 3+ → "high confidence".
 * Caller supplies `out` buffer (160+ bytes); returns the signal count (0 when
 * no base signals fired). Thread-safe; no allocation. */
int hlse_text_confidence(const TextVerdict *v, char *out, size_t outsz);

/* Recover the safe destination a user actually wanted from a URL Verdict.
 * When a brand was impersonated, HLSE already knows the authentic domain (it
 * used it to detect the fake); this lifts that into a navigable URL so a BLOCK
 * also tells the user where to go instead of leaving them to re-search into
 * the same phishing net. Writes "https://<domain>" into `out` (caller-owned)
 * and returns 1 when a canonical brand domain is present, 0 otherwise. */
int hlse_safe_destination(const Verdict *v, char *out, size_t outsz);

/* Compound safe destination — extends hlse_safe_destination for multi-brand
 * co-spoof URLs where two legitimate sites were impersonated simultaneously.
 * For n_brands == 1: writes "https://<domain>" (same as hlse_safe_destination).
 * For n_brands >= 2: writes "https://<domain1> and https://<domain2>" so the
 * → Safe destination line is consistent with the ◉ and ⊕ compound framing.
 * Caller-owned buffer (256+ bytes recommended); returns 1 when found, 0 if no
 * canonical brand domain exists in the verdict. */
int hlse_safe_destinations(const Verdict *v, char *out, size_t outsz);

/* Disclose how many INDEPENDENT detector families corroborate a URL verdict —
 * the epistemic complement to the score. The score says how threatening; this
 * says how much independent evidence agrees, so a borderline score backed by
 * one fragile heuristic is distinguishable from the same score backed by four
 * concurring detectors. Counts distinct families (homoglyph, path, TLD, etc.),
 * collapsing reasons from the same technique and excluding the derived
 * "Legitimate '<brand>'" evidence lines. Writes a qualitative label into `out`;
 * returns the family count (0 when no signal fired). Caller owns the buffer. */
int hlse_confidence_for(const Verdict *v, char *out, size_t outsz);

/* Name the attacker's likely objective for a URL Verdict — the asset the
 * victim must now treat as compromised (e.g. "crypto theft — seed phrase or
 * wallet drain; transfers are irreversible"). Where hlse_classify_url_attack
 * describes the mechanism, this describes the motive and stake, derived from
 * the impersonated brand. Returns a static string, or NULL when no brand was
 * identified in the verdict. */
const char *hlse_attacker_objective(const Verdict *v);

/* Compound objective for multi-brand co-spoof URLs. For n_brands == 1
 * writes the same result as hlse_attacker_objective(). For n_brands >= 2
 * writes "compound theft — brand1 (class1) AND brand2 (class2) both targeted
 * simultaneously in a single click". Caller supplies `out` buffer; returns 1
 * when any brand was found, 0 otherwise. Prefer this over
 * hlse_attacker_objective() in display paths so compound attacks are not
 * silently reported as single-target. */
int hlse_compound_objective(const Verdict *v, char *out, size_t outsz);

/* Pinpoint the first disguised (non-ASCII) character in a URL's host — the
 * forensic proof behind a "homoglyph"/"mixed-script" label. Writes a one-line
 * summary ("position 1 is Cyrillic U+0440, not an ASCII letter") into `out`.
 * Returns 1 when a disguised character is found, 0 otherwise. Only raw IDN /
 * mixed-script hosts report; pure-ASCII homoglyphs and xn-- punycode do not. */
int hlse_confusable_report(const char *url, char *out, size_t outsz);

/* Pinpoint ASCII lookalike substitutions in a typosquat or ASCII homoglyph
 * verdict — the character-level proof that complements hlse_confusable_report
 * (which only fires for non-ASCII). Parses "Brand homoglyph: 'X' -> 'Y'" and
 * "Typosquat: 'X' is edit distance N from 'Y'" reasons; reports every
 * differing position with its character type (digit/letter/hyphen). Skips
 * reasons where the fake string contains non-ASCII bytes. Writes a one-line
 * summary into `out` (caller-owned); returns 1 when found, 0 otherwise. */
int hlse_ascii_diff(const Verdict *v, char *out, size_t outsz);

/* The single best independent check to confirm an actionable URL verdict
 * without trusting HLSE — the high-confidence (score >= 60) mirror of
 * hlse_exoneration_for. The check targets the signals that fired (e.g. "expand
 * the short link before opening it"). Returns a static string, or NULL when
 * score < 60. */
const char *hlse_verification_for(const Verdict *v);

/* First-response triage for the post-click user — what to do in the next
 * 60 seconds to minimise damage (score >= 60 only). Keyed to the same
 * brand-objective class as hlse_attacker_objective so the guidance matches
 * the specific asset at risk. Returns a static string, or NULL when score < 60. */
const char *hlse_triage_for(const Verdict *v);

/* Compound first-response triage for multi-brand co-spoof URLs — covers BOTH
 * compromised asset classes in a numbered two-step sequence. For n_brands == 1
 * writes the same result as hlse_triage_for(). For n_brands >= 2 writes
 * "(1) <triage for brand1>; (2) <triage for brand2>". Caller-owned buffer
 * (512+ bytes for compound case); returns 1 when guidance was written, 0 when
 * score < 60 or no brand found. Prefer over hlse_triage_for() in display paths
 * so compound attacks are not silently reported as single-target. */
int hlse_compound_triage(const Verdict *v, char *out, size_t outsz);

/* Positive authentication: tests whether the URL's host is a confirmed
 * canonical brand domain or an official subdomain of one in the HLSE brand
 * registry (e.g. paypal.com, login.paypal.com, accounts.google.com,
 * id.apple.com). Strips a leading "www." then checks: (1) exact match, (2)
 * host ends with ".<canonical>" (official subdomain). This fires only at score
 * 0 — a spoofed domain that triggered any brand detector has a non-zero score
 * and never reaches this path. Writes the matched brand name into `brand_out`
 * and returns 1 when confirmed; returns 0 otherwise. */
int hlse_canonical_confirm(const char *url, char *brand_out, size_t brand_outsz);

/* Password-reuse cascade risk after a credential-harvest click — which OTHER
 * accounts the victim should audit immediately, derived from the impersonated
 * brand's credential class. For multi-brand co-spoof URLs the guidance covers
 * both harvested credential classes. Returns a static string, or NULL when
 * score < 60 (pre-click context has no cascade to describe). */
const char *hlse_cascade_risk(const Verdict *v);

/* Library version string (compiled-in). */
const char *hlse_version(void);

/* ── Unified scan API (recommended entry point) ──────────────────────
 *
 * hlse_scan auto-detects whether the input is a URL or text:
 *   - Starts with http:// / https:// / javascript: / data:  → URL
 *   - Everything else → text
 *
 * For URLs, it also runs text detection on the URL string itself to
 * catch compound signals (e.g. a URL path containing "urgent").
 * Returns the higher-scoring result.
 *
 * Thread-safe. No allocation.                                         */

typedef struct {
    int  score;              /* 0..100 */
    int  is_url;             /* 1 if URL detection fired, 0 if text */
    int  n_reasons;
    char reasons[16][192];
} ScanResult;

ScanResult hlse_scan(const char *input);

#ifdef __cplusplus
}
#endif

#endif /* HLSE_CORE_H */
