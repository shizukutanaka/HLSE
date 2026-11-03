/*
 * hlse_suppress.c -- post-detection output filters for `hlse_core scan`.
 *
 * Split out of hlse_cli.c: the SARIF sink and the baseline/fingerprint/
 * inline-allow suppression state share one contract (hlse_scan_suppress)
 * and nothing else with the subcommand handlers. Linked into the
 * hlse_core executables only -- never into libhlse.so, the server, the
 * unit tests or the fuzzers.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>     /* malloc, realloc, free */

#include "hlse_util.h"   /* hlse_json_escape */
#include "hlse_cli.h"    /* sarif_add/emit, hlse_scan_suppress, baseline */

/* ── SARIF 2.1.0 output (GitHub code-scanning compatible) ─────────────────
 *
 * The scan subcommand streams findings as it walks the tree. SARIF needs a
 * single JSON document, so when --sarif is set we accumulate findings into
 * this fixed-capacity buffer and emit them all at the end. The cap is
 * generous; overflow simply truncates the report (a logged note is added).
 *
 * Each finding: file path, 1-based line, rule id, message, score.        */
#define SARIF_MAX_FINDINGS 4096

typedef struct {
    char  path[1024];
    int   line;
    char  rule[32];      /* e.g. "secret", "phishing-url", "file-masquerade" */
    char  pattern_id[40];/* stable HLSE-* token for SOAR routing (P91)        */
    char  message[512];
    int   score;
} SarifFinding;

static SarifFinding g_sarif[SARIF_MAX_FINDINGS];
static int          g_sarif_n = 0;
static int          g_sarif_overflow = 0;

void
sarif_add(const char *path, int line, const char *rule,
          const char *pattern_id, const char *message, int score) {
    SarifFinding *f;
    if (g_sarif_n >= SARIF_MAX_FINDINGS) { g_sarif_overflow = 1; return; }
    f = &g_sarif[g_sarif_n++];
    snprintf(f->path, sizeof(f->path), "%s", path);
    f->line = line < 1 ? 1 : line;
    snprintf(f->rule, sizeof(f->rule), "%s", rule);
    snprintf(f->pattern_id, sizeof(f->pattern_id), "%s",
             pattern_id ? pattern_id : "");
    snprintf(f->message, sizeof(f->message), "%s", message);
    f->score = score;
}

/* Map HLSE 0-100 score to SARIF level + security-severity (0.0-10.0). */
static const char *
sarif_level(int score) {
    if (score >= 60) return "error";
    if (score >= 40) return "warning";
    return "note";
}

void
sarif_emit(const char *tool_version) {
    int i;
    /* Rule metadata — id, display name, short description, and
     * security-severity (CVSS-like 0–10 for GitHub code scanning).    */
    static const struct {
        const char *id;
        const char *name;
        const char *description;
        const char *severity; /* string to avoid float formatting issues */
        const char *tags;     /* JSON array body for properties.tags        */
    } RULES[] = {
        { "secret",         "Credential Leak",
          "Exposed API key, token, or private key found in source file.",
          "9.0",
          "\"security\", \"external/cwe/cwe-798\"" },
        { "phishing-url",   "Phishing URL",
          "URL exhibits homoglyph, typosquat, or subdomain-spoof phishing indicators.",
          "7.5",
          "\"security\", \"external/cwe/cwe-1021\"" },
        { "file-masquerade","File Masquerade",
          "File extension or magic bytes indicate the file is disguised malware.",
          "8.0",
          "\"security\", \"external/cwe/cwe-646\"" },
        { "package-typosquat","Dependency Typosquat",
          "Declared dependency name is a likely typosquat of a popular package "
          "(dependency-confusion / supply-chain attack).",
          "7.0",
          "\"security\", \"external/cwe/cwe-1357\"" },
        { NULL, NULL, NULL, NULL, NULL }
    };
    char esc[1280];

    printf("{\n");
    printf("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
    printf("  \"version\": \"2.1.0\",\n");
    printf("  \"runs\": [\n    {\n");
    printf("      \"tool\": {\n        \"driver\": {\n");
    printf("          \"name\": \"HLSE\",\n");
    printf("          \"informationUri\": \"https://github.com/shizukutanaka/hlse\",\n");
    printf("          \"version\": \"%s\",\n", tool_version);
    printf("          \"rules\": [\n");
    for (i = 0; RULES[i].id; i++) {
        printf("            {\n"
               "              \"id\": \"%s\", \"name\": \"%s\",\n"
               "              \"shortDescription\": { \"text\": \"%s\" },\n"
               "              \"helpUri\": \"https://github.com/shizukutanaka/hlse/blob/main/docs/SIEM_INTEGRATION.md\",\n"
               "              \"properties\": { \"security-severity\": \"%s\", \"tags\": [%s] }\n"
               "            }%s\n",
               RULES[i].id, RULES[i].name, RULES[i].description,
               RULES[i].severity, RULES[i].tags, RULES[i+1].id ? "," : "");
    }
    printf("          ]\n        }\n      },\n");
    printf("      \"results\": [\n");
    for (i = 0; i < g_sarif_n; i++) {
        SarifFinding *f = &g_sarif[i];
        double sev = (double)f->score / 10.0;
        printf("        {\n");
        printf("          \"ruleId\": \"%s\",\n", f->rule);
        printf("          \"level\": \"%s\",\n", sarif_level(f->score));
        hlse_json_escape(f->message, esc, sizeof(esc));
        printf("          \"message\": { \"text\": \"%s\" },\n", esc);
        if (f->pattern_id[0]) {
            char epid[64];
            hlse_json_escape(f->pattern_id, epid, sizeof(epid));
            printf("          \"properties\": { \"security-severity\": \"%.1f\","
                   " \"hlse-score\": %d, \"pattern_id\": \"%s\" },\n",
                   sev, f->score, epid);
        } else {
            printf("          \"properties\": { \"security-severity\": \"%.1f\","
                   " \"hlse-score\": %d },\n", sev, f->score);
        }
        printf("          \"locations\": [\n            {\n");
        printf("              \"physicalLocation\": {\n");
        hlse_json_escape(f->path, esc, sizeof(esc));
        printf("                \"artifactLocation\": { \"uri\": \"%s\" },\n", esc);
        printf("                \"region\": { \"startLine\": %d }\n", f->line);
        printf("              }\n            }\n          ]\n");
        printf("        }%s\n", (i + 1 < g_sarif_n) ? "," : "");
    }
    printf("      ]\n");
    if (g_sarif_overflow) {
        printf("      ,\"properties\": { \"truncated\": true }\n");
    }
    printf("    }\n  ]\n}\n");
}

/* ── Baseline / allowlist (Perspective 107, roadmap P0-1) ──────────────────
 * Commercial secret scanners (detect-secrets, gitleaks) need a way to accept
 * known findings so a brownfield repo's first scan does not fail the CI gate
 * forever. HLSE implements this as a pure post-detection output filter — no
 * detection logic touched, F1 unchanged:
 *   1. `hlse_core --fingerprints scan .` emits one stable fingerprint per
 *      finding; redirect to a file to create a baseline.
 *   2. `hlse_core --baseline <file> scan .` suppresses every finding whose
 *      fingerprint is listed; only NEW findings count toward the gate.
 *   3. an inline `hlse:allow` token on a scanned line suppresses findings on
 *      that line (gitleaks:allow-style).
 * The fingerprint is a 64-bit FNV-1a hash of relpath\0pattern_id\0match,
 * rendered as 16 hex chars. It deliberately OMITS the line number so a
 * finding that moves lines stays suppressed. */
int                g_hlse_emit_fingerprints = 0;  /* --fingerprints */
static char      **g_baseline_fps = NULL;    /* loaded fingerprint set */
static size_t      g_baseline_n = 0;

/* Write a stable 16-hex-char fingerprint of (relpath, pattern_id, match) into
 * out[17]. NUL-separated so distinct field boundaries can't alias. */
static void
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

/* Return 1 if fp is in the loaded baseline set (linear scan; baselines are
 * modest and this runs once per finding). */
static int
hlse_baseline_has(const char *fp) {
    size_t i;
    for (i = 0; i < g_baseline_n; i++)
        if (strcmp(g_baseline_fps[i], fp) == 0) return 1;
    return 0;
}

/* Load fingerprints from the baseline file (one per line; '#' comments and
 * blank lines ignored; surrounding whitespace trimmed). Returns 0 on success,
 * -1 if the file cannot be opened. */
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

/* Free every fingerprint string owned by the loaded baseline set and the
 * backing array itself, then reset g_baseline_n/g_baseline_fps to their
 * pre-load state so a subsequent hlse_baseline_load() call starts clean.
 * Safe when no baseline was ever loaded, and idempotent. Named to match the
 * hlse_clear_custom_secret_patterns()/hlse_clear_custom_brands() convention. */
void
hlse_baseline_clear(void) {
    size_t i;
    for (i = 0; i < g_baseline_n; i++)
        free(g_baseline_fps[i]);
    free(g_baseline_fps);
    g_baseline_fps = NULL;
    g_baseline_n = 0;
}

/* Return 1 if a scanned line carries an inline `hlse:allow` suppression. */
static int
hlse_line_allowed(const char *line) {
    return line && strstr(line, "hlse:allow") != NULL;
}


/* Central suppression check for a scan finding, shared by all three checks
 * (file/secret/url). Computes the fingerprint; if --fingerprints is set,
 * prints it and returns 2 (caller skips all counting AND emission). Returns 1
 * to suppress (baseline hit or inline allow), 0 to emit normally. `line` may
 * be NULL for whole-file findings that have no inline-allow context. */
int
hlse_scan_suppress(const char *relpath, const char *pattern_id,
                   const char *match, const char *line) {
    char fp[17];
    hlse_fingerprint(relpath, pattern_id, match, fp);
    if (g_hlse_emit_fingerprints) {
        printf("%s  %s  %s\n", fp, pattern_id ? pattern_id : "-",
               relpath ? relpath : "-");
        return 2;
    }
    if (hlse_baseline_has(fp)) return 1;
    if (hlse_line_allowed(line)) return 1;
    return 0;
}
