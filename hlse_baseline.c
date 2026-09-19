/* hlse_baseline.c — finding fingerprints + baseline suppression.
 * Extracted verbatim from hlse_core.c (split increment 4); see
 * hlse_baseline.h for the contract. */
#include "hlse_baseline.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char      **g_baseline_fps = NULL;    /* loaded fingerprint set */
static size_t      g_baseline_n = 0;

void
hlse_fingerprint(const char *relpath, const char *pattern_id,
                 const char *match, char out[17]) {
    unsigned long long h = 1469598103934665603ULL; /* FNV-1a 64 offset basis */
    const char *parts[3];
    int p;
    parts[0] = relpath ? relpath : "";
    parts[1] = pattern_id ? pattern_id : "";
    parts[2] = match ? match : "";
    for (p = 0; p < 3; p++) {
        const unsigned char *s = (const unsigned char *)parts[p];
        while (*s) { h ^= (unsigned long long)*s++; h *= 1099511628211ULL; }
        h *= 1099511628211ULL; /* absorb the NUL field separator */
    }
    snprintf(out, 17, "%016llx", h);
}

int
hlse_baseline_has(const char *fp) {
    size_t i;
    for (i = 0; i < g_baseline_n; i++)
        if (strcmp(g_baseline_fps[i], fp) == 0) return 1;
    return 0;
}

int
hlse_baseline_load(const char *path) {
    FILE *fp = fopen(path, "r");
    char line[128];
    if (!fp) return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *s = line, *t;
        size_t n;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0') continue;
        /* Keep only the first whitespace-delimited token: the --fingerprints
         * output is "<fp>  <pattern_id>  <relpath>" for human readability, but
         * the lookup key is just the 16-hex fingerprint. Truncate at the first
         * space/tab so the readable columns are ignored on load. */
        for (t = s; *t && *t != ' ' && *t != '\t' && *t != '\n' && *t != '\r'; t++)
            ;
        *t = '\0';
        n = strlen(s);
        if (n == 0) continue;
        {
            char **grown = realloc(g_baseline_fps,
                                   (g_baseline_n + 1) * sizeof(char *));
            char *dup;
            if (!grown) break;
            g_baseline_fps = grown;
            dup = malloc(n + 1);
            if (!dup) break;
            memcpy(dup, s, n + 1);
            g_baseline_fps[g_baseline_n++] = dup;
        }
    }
    fclose(fp);
    return 0;
}

void
hlse_baseline_clear(void) {
    size_t i;
    for (i = 0; i < g_baseline_n; i++)
        free(g_baseline_fps[i]);
    free(g_baseline_fps);
    g_baseline_fps = NULL;
    g_baseline_n = 0;
}

/* 1 if a scanned line carries an inline `hlse:allow` suppression. */
static int
hlse_line_allowed(const char *line) {
    return line && strstr(line, "hlse:allow") != NULL;
}

int
hlse_scan_suppress(const char *relpath, const char *pattern_id,
                   const char *match, const char *line,
                   int emit_fingerprints) {
    char fp[17];
    hlse_fingerprint(relpath, pattern_id, match, fp);
    if (emit_fingerprints) {
        printf("%s  %s  %s\n", fp, pattern_id ? pattern_id : "-",
               relpath ? relpath : "-");
        return 2;
    }
    if (hlse_baseline_has(fp)) return 1;
    if (hlse_line_allowed(line)) return 1;
    return 0;
}
