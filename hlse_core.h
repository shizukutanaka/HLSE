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

/* Version — available to library users without access to the .c source. */
#define HLSE_VERSION "1.0.10"

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

/* Synthesise a named attack-pattern label from the signals in a URL Verdict
 * (e.g. "typosquat credential-harvest page", "free-hosting phishing
 * infrastructure"). Returns NULL when score is 0 or no recognisable pattern
 * is found. The label is always a short phrase — display it as a summary
 * line after the per-signal reasons. */
const char *hlse_classify_url_attack(const Verdict *v);

/* Recover the safe destination a user actually wanted from a URL Verdict.
 * When a brand was impersonated, HLSE already knows the authentic domain (it
 * used it to detect the fake); this lifts that into a navigable URL so a BLOCK
 * also tells the user where to go instead of leaving them to re-search into
 * the same phishing net. Writes "https://<domain>" into `out` (caller-owned)
 * and returns 1 when a canonical brand domain is present, 0 otherwise. */
int hlse_safe_destination(const Verdict *v, char *out, size_t outsz);

/* Name the attacker's likely objective for a URL Verdict — the asset the
 * victim must now treat as compromised (e.g. "crypto theft — seed phrase or
 * wallet drain; transfers are irreversible"). Where hlse_classify_url_attack
 * describes the mechanism, this describes the motive and stake, derived from
 * the impersonated brand. Returns a static string, or NULL when no brand was
 * identified in the verdict. */
const char *hlse_attacker_objective(const Verdict *v);

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
