/*
 * hlse_util.h — Shared numeric/string utilities for HLSE
 *
 * Consolidates algorithms that were previously duplicated across modules:
 *   - Shannon entropy (was in hlse_core.c AND hlse_protect.c)
 *   - Damerau-Levenshtein edit distance (was in hlse_core.c AND hlse_supply.c)
 *
 * All functions are pure, thread-safe, and allocation-free.
 */

#ifndef HLSE_UTIL_H
#define HLSE_UTIL_H

#include <stddef.h>
#include <stdio.h>

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

/* Safely open a FIXED, trusted system file (e.g. /etc/hosts,
 * /etc/resolv.conf, /proc/net/arp, /etc/ssh/sshd_config) for reading.
 *
 * Uses O_NONBLOCK + fstat + S_ISREG so a FIFO planted at the path cannot
 * block the reader indefinitely (a local denial-of-service), and so that
 * non-regular targets (devices, sockets, directories) are rejected.
 *
 * Symlinks ARE followed deliberately: these are root-owned, fixed paths
 * that are legitimately symlinks on some systems (notably /etc/resolv.conf
 * on systemd hosts), so O_NOFOLLOW would break a correct read. O_NOFOLLOW
 * remains reserved for UNTRUSTED directory-scan entries, where an attacker
 * controls the filename.
 *
 * Returns a read-mode FILE* on success, or NULL (callers treat NULL as
 * "file absent / not readable"). The caller owns the FILE* and must
 * fclose() it.                                                          */
FILE *hlse_open_system_file(const char *path);

/* JSON-escape `s` into `out` (bounded by out_size), escaping ", \\, control
 * chars (<0x20 -> \uXXXX) and \n/\r/\t. Always NUL-terminates within out_size.
 * Shared helper so the CLI, server, and alert sink don't each carry a copy. */
void hlse_json_escape(const char *s, char *out, size_t out_size);

/* Standard CRC-32 (IEEE 802.3 / zlib, reflected poly 0xEDB88320). */
unsigned long hlse_crc32(const unsigned char *data, size_t len);

/* Encode a 32-bit value as exactly 6 base62 digits, '0'-padded on the left.
 * `out` needs room for 7 bytes. Used to check the checksum suffix that
 * GitHub-format tokens carry, so their integrity is verifiable offline. */
void hlse_base62_6(unsigned long v, char *out);

#ifdef __cplusplus
}
#endif

#endif /* HLSE_UTIL_H */
