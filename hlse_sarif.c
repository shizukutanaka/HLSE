/* hlse_sarif.c — SARIF 2.1.0 accumulation + emission (GitHub
 * code-scanning compatible). Extracted verbatim from hlse_core.c
 * (split increment 6).
 *
 * The scan subcommand streams findings as it walks the tree. SARIF
 * needs a single JSON document, so when --sarif is set findings are
 * accumulated into this fixed-capacity buffer and emitted all at
 * the end. The cap is generous; overflow truncates the report with
 * a logged note. */
#include "hlse_sarif.h"
#include "hlse_util.h"   /* hlse_json_escape */
#include <stdio.h>
#include <string.h>

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
hlse_sarif_add(const char *path, int line, const char *rule,
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
hlse_sarif_emit(const char *tool_version) {
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
