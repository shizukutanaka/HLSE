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

/* Version — available to library users without access to the .c source. */
#define HLSE_VERSION "1.0.1"

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
