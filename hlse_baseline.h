/* hlse_baseline.h — finding fingerprints + baseline suppression.
 *
 * Extracted verbatim from hlse_core.c (split increment 4). Commercial
 * secret scanners (detect-secrets, gitleaks) need a way to accept known
 * findings so a brownfield repo's first scan does not fail the CI gate
 * forever. HLSE implements this as a pure post-detection output filter —
 * no detection logic touched, F1 unchanged:
 *   1. `hlse_core --fingerprints scan .` emits one stable fingerprint per
 *      finding; redirect to a file to create a baseline.
 *   2. `hlse_core --baseline <file> scan .` suppresses every finding whose
 *      fingerprint is listed; only NEW findings count toward the gate.
 *   3. an inline `hlse:allow` token on a scanned line suppresses findings
 *      on that line (gitleaks:allow-style). */
#ifndef HLSE_BASELINE_H
#define HLSE_BASELINE_H

/* Stable 16-hex-char fingerprint of (relpath, pattern_id, match) into
 * out[17]. 64-bit FNV-1a, NUL-separated fields; deliberately OMITS the
 * line number so a finding that moves lines stays suppressed. */
void hlse_fingerprint(const char *relpath, const char *pattern_id,
                      const char *match, char out[17]);

/* Load fingerprints from a baseline file (one per line; '#' comments and
 * blank lines ignored). 0 on success, -1 when the file cannot be opened. */
int  hlse_baseline_load(const char *path);

/* 1 when fp is in the loaded baseline set (linear scan — baselines are
 * modest and this runs once per finding). */
int  hlse_baseline_has(const char *fp);

/* Free the loaded set; idempotent and safe when nothing was loaded. */
void hlse_baseline_clear(void);

/* Central suppression gate for a scan finding. Computes the fingerprint;
 * when emit_fingerprints != 0 (--fingerprints) prints it and returns 2 —
 * the caller then skips all counting AND emission. Returns 1 to suppress
 * (baseline hit or inline `hlse:allow`), 0 to emit normally. `line` may
 * be NULL for whole-file findings with no inline-allow context. */
int  hlse_scan_suppress(const char *relpath, const char *pattern_id,
                        const char *match, const char *line,
                        int emit_fingerprints);

#endif /* HLSE_BASELINE_H */
