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
#define SARIF_MAX_IDS      8   /* per-result reason_ids cap (file verdicts
                                * bound reasons at 8) */

typedef struct {
    char  path[1024];
    int   line;
    char  rule[32];      /* e.g. "secret", "phishing-url", "file-masquerade" */
    char  pattern_id[40];/* stable HLSE-* token for SOAR routing (P91)        */
    char  reason_ids[SARIF_MAX_IDS][40]; /* per-reason dedup keys (optional)  */
    int   n_reason_ids;
    char  message[512];
    int   score;
} SarifFinding;

static SarifFinding g_sarif[SARIF_MAX_FINDINGS];
static int          g_sarif_n = 0;
static int          g_sarif_overflow = 0;

void
hlse_sarif_add_ids(const char *path, int line, const char *rule,
          const char *pattern_id, const char *const reason_ids[],
          int n_reason_ids, const char *message, int score) {
    SarifFinding *f;
    int i;
    if (g_sarif_n >= SARIF_MAX_FINDINGS) { g_sarif_overflow = 1; return; }
    f = &g_sarif[g_sarif_n++];
    snprintf(f->path, sizeof(f->path), "%s", path);
    f->line = line < 1 ? 1 : line;
    snprintf(f->rule, sizeof(f->rule), "%s", rule);
    snprintf(f->pattern_id, sizeof(f->pattern_id), "%s",
             pattern_id ? pattern_id : "");
    if (n_reason_ids > SARIF_MAX_IDS) n_reason_ids = SARIF_MAX_IDS;
    f->n_reason_ids = 0;
    for (i = 0; reason_ids && i < n_reason_ids; i++) {
        if (!reason_ids[i]) continue;
        snprintf(f->reason_ids[f->n_reason_ids],
                 sizeof(f->reason_ids[0]), "%s", reason_ids[i]);
        f->n_reason_ids++;
    }
    snprintf(f->message, sizeof(f->message), "%s", message);
    f->score = score;
}

void
hlse_sarif_add(const char *path, int line, const char *rule,
          const char *pattern_id, const char *message, int score) {
    hlse_sarif_add_ids(path, line, rule, pattern_id, NULL, 0, message,
                       score);
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
        { "package-lifecycle-hook","Install Lifecycle Hook",
          "Manifest declares an install/postinstall script that runs arbitrary "
          "code at install time (Shai-Hulud-style install worm surface).",
          "9.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-lockfile-poisoning","Lockfile Poisoning",
          "Lockfile resolved-URL host is outside the package registry — "
          "dependency substitution via a tampered lockfile.",
          "8.0",
          "\"security\", \"external/cwe/cwe-494\"" },
        { "package-registry-override","Registry Override",
          "A registry-override setting redirects every package lookup off the "
          "known registries (dependency confusion).",
          "8.5",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-index-redirect","Package Index Redirect",
          "Package index/lookup is redirected to a host outside the default "
          "index — verify it is the organization's own index.",
          "7.5",
          "\"security\", \"external/cwe/cwe-494\"" },
        { "package-mcp",       "MCP Server Risk",
          "MCP server configuration can spawn arbitrary commands inside "
          "agent tooling (tool-poisoning attack surface).",
          "7.5",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-devcontainer","Dev Container Risk",
          "Dev-container/CI config fetches and executes remote content at "
          "workspace or pipeline start.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-gha",       "Unpinned Action Reference",
          "GitHub Actions reference resolves a mutable ref (default branch "
          "tip) instead of a pinned commit SHA.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-npm-alias", "npm Alias Dependency",
          "npm: alias hides the real install source behind the declared "
          "name.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-cargo-patch","Cargo Patch Redirect",
          "Cargo [patch] section redirects crates.io dependencies to "
          "another source — verify every patched target is intended.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-cargo-toolchain","Rust Toolchain Override",
          "rust-toolchain configuration downloads a toolchain binary/script "
          "that runs on every build.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-go-replace","Go Replace Redirect",
          "go.mod replace directive redirects a module to another source — "
          "verify the replacement is intended.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-vcs-source","VCS Dependency Source",
          "Dependency pinned to a VCS/direct-URL host outside known forges — "
          "installs unvetted code (dependency substitution).",
          "6.5",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-swift-url", "Swift URL Source",
          "Swift package resolved from an off-forge git/URL host that can "
          "substitute package content (dependency confusion).",
          "6.5",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-pod-source","CocoaPods Source Override",
          "CocoaPods dependency resolves through an override source instead "
          "of trunk/CDN — every pod follows it.",
          "6.5",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-gem-source","Gem Source Override",
          "Gem dependency resolves through a source outside the known "
          "registries/forges.",
          "6.5",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-docker",    "Container Source Risk",
          "Container/compose configuration pulls from a mutable or "
          "unverified image source.",
          "6.5",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-go-replace-local","Go Local Replace",
          "go.mod replace directive points at a local path — bypasses module "
          "checksum verification.",
          "6.5",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-nuget-source","NuGet Source Override",
          "NuGet package source points off the official feed — every "
          "resolved package substitutes through it.",
          "7.5",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-vscode",    "VS Code Autoexec",
          "Workspace settings/extensions can auto-execute tasks or binaries "
          "on folder open.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-composer",  "Composer Autoexec",
          "Composer configuration or scripts run code at install/build "
          "time.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-pkgbuild",  "PKGBUILD Autoexec",
          "Arch PKGBUILD runs arbitrary shell during package build.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-platform",  "PlatformIO Autoexec",
          "PlatformIO configuration can inject build flags or scripts that "
          "run at build time.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-precommit", "Pre-commit Autoexec",
          "pre-commit hook configuration executes hook code on every "
          "commit.",
          "7.0",
          "\"security\", \"external/cwe/cwe-829\"" },
        { "package-gitlabcicd","GitLab CI Remote Exec",
          "GitLab CI script block fetches or pipes remote/encoded content — "
          "executes with CI variable scope.",
          "7.5",
          "\"security\", \"external/cwe/cwe-829\"" },
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
        if (f->pattern_id[0] || f->n_reason_ids > 0) {
            printf("          \"properties\": { \"security-severity\": \"%.1f\","
                   " \"hlse-score\": %d", sev, f->score);
            if (f->pattern_id[0]) {
                char epid[64];
                hlse_json_escape(f->pattern_id, epid, sizeof(epid));
                printf(", \"pattern_id\": \"%s\"", epid);
            }
            if (f->n_reason_ids > 0) {
                int j;
                printf(", \"reason_ids\": [");
                for (j = 0; j < f->n_reason_ids; j++) {
                    char rid[64];
                    hlse_json_escape(f->reason_ids[j], rid, sizeof(rid));
                    printf("%s\"%s\"", j ? ", " : "", rid);
                }
                printf("]");
            }
            printf(" },\n");
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
