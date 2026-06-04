/*
 * hlse_util.c — Shared numeric/string utilities for HLSE
 *
 * See hlse_util.h for the rationale. These implementations were
 * previously duplicated; this is the single source of truth.
 */

#include "hlse_util.h"

#include <string.h>
#include <math.h>

/* ── Shannon entropy ──────────────────────────────────────────────────── */

double
hlse_shannon_entropy(const unsigned char *data, size_t len) {
    unsigned long freq[256];
    size_t i;
    double entropy = 0.0;

    if (len == 0) return 0.0;

    memset(freq, 0, sizeof(freq));
    for (i = 0; i < len; i++) freq[data[i]]++;

    for (i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        {
            double p = (double)freq[i] / (double)len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

double
hlse_shannon_entropy_str(const char *s) {
    if (!s) return 0.0;
    return hlse_shannon_entropy((const unsigned char *)s, strlen(s));
}

/* ── Damerau-Levenshtein edit distance ────────────────────────────────── */

int
hlse_edit_distance(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    /* +1 for the zero row/column */
    int d[HLSE_DL_MAXLEN + 1][HLSE_DL_MAXLEN + 1];
    size_t i, j;

    if (la > HLSE_DL_MAXLEN || lb > HLSE_DL_MAXLEN) return HLSE_DL_MAX;

    for (i = 0; i <= la; i++) d[i][0] = (int)i;
    for (j = 0; j <= lb; j++) d[0][j] = (int)j;

    for (i = 1; i <= la; i++) {
        for (j = 1; j <= lb; j++) {
            int cost = (a[i-1] == b[j-1]) ? 0 : 1;
            int del = d[i-1][j] + 1;
            int ins = d[i][j-1] + 1;
            int sub = d[i-1][j-1] + cost;
            int best = del;

            if (ins < best) best = ins;
            if (sub < best) best = sub;

            /* Adjacent transposition (Damerau extension) */
            if (i > 1 && j > 1 &&
                a[i-1] == b[j-2] && a[i-2] == b[j-1]) {
                int tra = d[i-2][j-2] + cost;
                if (tra < best) best = tra;
            }
            d[i][j] = best;
        }
    }
    return d[la][lb];
}

/* ── Known benign high-entropy file signatures ────────────────────────── */

int
hlse_is_high_entropy_benign_magic(const unsigned char *buf, size_t n) {
    if (n < 4) return 0;

    /* ZIP/JAR/DOCX/XLSX: PK\x03\x04 */
    if (buf[0]==0x50 && buf[1]==0x4B && buf[2]==0x03 && buf[3]==0x04) return 1;
    /* GZIP: 1F 8B */
    if (buf[0]==0x1F && buf[1]==0x8B) return 1;
    /* RAR: Rar! */
    if (buf[0]==0x52 && buf[1]==0x61 && buf[2]==0x72 && buf[3]==0x21) return 1;
    /* 7z: 37 7A BC AF */
    if (buf[0]==0x37 && buf[1]==0x7A && buf[2]==0xBC && buf[3]==0xAF) return 1;
    /* JPEG: FF D8 FF */
    if (buf[0]==0xFF && buf[1]==0xD8 && buf[2]==0xFF) return 1;
    /* PNG: 89 50 4E 47 */
    if (buf[0]==0x89 && buf[1]==0x50 && buf[2]==0x4E && buf[3]==0x47) return 1;
    /* MP4/MOV ftyp box (offset 4): ....ftyp */
    if (n >= 8 && buf[4]==0x66 && buf[5]==0x74 && buf[6]==0x79 && buf[7]==0x70)
        return 1;
    /* PDF: %PDF (compressed streams inside) */
    if (buf[0]==0x25 && buf[1]==0x50 && buf[2]==0x44 && buf[3]==0x46) return 1;
    /* XZ: FD 37 7A 58 */
    if (buf[0]==0xFD && buf[1]==0x37 && buf[2]==0x7A && buf[3]==0x58) return 1;
    /* BZIP2: BZh */
    if (buf[0]==0x42 && buf[1]==0x5A && buf[2]==0x68) return 1;
    /* Zstandard: 28 B5 2F FD */
    if (buf[0]==0x28 && buf[1]==0xB5 && buf[2]==0x2F && buf[3]==0xFD) return 1;

    return 0;
}
