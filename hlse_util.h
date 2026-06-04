/*
 * hlse_util.h — Shared numeric/string utilities for HLSE
 *
 * Consolidates algorithms that were previously duplicated across modules:
 *   - Shannon entropy (was in hlse_core.c AND hlse_protect.c)
 *   - Damerau-Levenshtein edit distance (was in hlse_core.c AND hlse_supply.c)
 *
 * All functions are pure, thread-safe, and allocation-free.
 *
 * Identity: bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5
 */

#ifndef HLSE_UTIL_H
#define HLSE_UTIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Shannon entropy in bits/symbol over a byte buffer.
 * Returns 0.0 for empty input. Range: [0, 8] for byte data.        */
double hlse_shannon_entropy(const unsigned char *data, size_t len);

/* Convenience wrapper for NUL-terminated strings. */
double hlse_shannon_entropy_str(const char *s);

/* Damerau-Levenshtein edit distance (insertions, deletions,
 * substitutions, and adjacent transpositions).
 *
 * Returns the edit distance, or HLSE_DL_MAX if either string exceeds
 * the internal bound (treated as "very far apart"). The bound keeps the
 * DP matrix on the stack with no allocation.                        */
#define HLSE_DL_MAX 99
#define HLSE_DL_MAXLEN 64

int hlse_edit_distance(const char *a, const char *b);

/* True if `buf` (first `n` bytes of a file) begins with the magic
 * signature of a known compressed/encrypted-looking but BENIGN format
 * (ZIP, GZIP, RAR, 7z, XZ, BZIP2, Zstd, JPEG, PNG, MP4/MOV, PDF).
 *
 * Shannon entropy alone cannot distinguish such files from
 * ransomware-encrypted data — both approach 8 bits/byte — so callers
 * use this to exclude expected-high-entropy files from "encrypted"
 * heuristics and avoid false positives. Ransomware output does not
 * carry these signatures (the original header is encrypted away).    */
int hlse_is_high_entropy_benign_magic(const unsigned char *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* HLSE_UTIL_H */
