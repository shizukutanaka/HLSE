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
