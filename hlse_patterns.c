/*
 * hlse_patterns.c -- the --list-patterns pattern-ID registry.
 *
 * Split out of hlse_cli.c: the registry table and its emitter share no state
 * with the subcommand handlers, which is what made this a clean cut. Linked
 * into the hlse_core executables only -- never into libhlse.so, the server,
 * the unit tests or the fuzzers.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>      /* strstr */

#include "hlse_core.h"   /* HLSE_VERSION */
#include "hlse_file.h"   /* FileVerdict */
#include "hlse_cli.h"    /* cli_list_patterns + pattern-id helpers */

/* ── Pattern-ID registry (Perspective 88) ──────────────────────────────────
 * The stable HLSE-* pattern_id tokens introduced across P78–P87 exist so SIEM
 * and SOAR pipelines can route on an append-only identifier instead of prose
 * that we keep rewording. But a stable token is only useful to automation if
 * the FULL set is discoverable — and until now the universe of tokens could
 * only be learned by grepping this source. `--list-patterns` closes that gap:
 * it emits the authoritative registry (token, kind, prose description) so a
 * consumer can build a complete routing table without reading C.
 *
 * This table is the single source of truth; keep it append-only (never reword
 * or remove a token — that is the whole point) and in sync with the emitters
 * in hlse_cli.c and in hlse_text_pattern_id / hlse_url_pattern_id.           */
struct pattern_entry {
    const char *id;    /* stable HLSE-* token                                */
    const char *kind;  /* verdict kind that emits it                         */
    const char *desc;  /* one-line human description                         */
};

static const struct pattern_entry g_pattern_registry[] = {
    /* text / social-engineering attack patterns (hlse_text_pattern_id) */
    { "HLSE-CLICKFIX",            "text", "ClickFix paste-and-run script-injection lure" },
    { "HLSE-OAUTH-DEVICECODE",    "text", "OAuth device-code phishing" },
    { "HLSE-MFA-FATIGUE",         "text", "MFA fatigue / push-bombing" },
    { "HLSE-BEC-PAYMENT-DIVERSION","text","BEC payment / bank-detail diversion" },
    { "HLSE-BEC-CEO",             "text", "BEC CEO-fraud impersonation" },
    { "HLSE-BEC-WIRE",            "text", "BEC wire-transfer fraud" },
    { "HLSE-CALLBACK-TOAD",       "text", "Telephone-oriented attack delivery (callback phishing)" },
    { "HLSE-SEXTORTION",          "text", "Sextortion extortion scam" },
    { "HLSE-INVESTMENT",          "text", "Investment / pig-butchering scam" },
    { "HLSE-ADVANCE-FEE",         "text", "Advance-fee fraud" },
    { "HLSE-PRIZE",               "text", "Prize / lottery scam" },
    { "HLSE-REFUND-SCAM",         "text", "Refund / overpayment scam" },
    { "HLSE-JOB-SCAM",            "text", "Job-offer / task scam" },
    { "HLSE-TECH-SUPPORT",        "text", "Tech-support scam" },
    { "HLSE-QUISHING",            "text", "QR-code phishing (quishing)" },
    { "HLSE-RANSOM",              "text", "Ransom / extortion demand" },
    { "HLSE-FAKE-ALERT",          "text", "Fake security-alert lure" },
    { "HLSE-CRED-LURE",           "text", "Credential-harvest lure" },
    { "HLSE-URGENCY-CRED",        "text", "Urgency + credential request" },
    { "HLSE-AUTHORITY",           "text", "Authority-impersonation pressure" },
    { "HLSE-EMERGENCY",           "text", "Manufactured-emergency pressure" },
    { "HLSE-URGENCY",             "text", "Generic urgency pressure" },
    { "HLSE-GENERIC",             "text", "Recognised text attack, unclassified pattern" },
    /* url / phishing-link patterns (hlse_url_pattern_id) */
    { "HLSE-URL-HOMOGLYPH",       "url",  "Homoglyph / look-alike domain" },
    { "HLSE-URL-IDN-HOMOGRAPH",   "url",  "IDN homograph (mixed-script) domain" },
    { "HLSE-URL-TYPOSQUAT",       "url",  "Typosquat of a known brand domain" },
    { "HLSE-URL-TYPOSQUAT-HARVEST","url", "Typosquat with credential-harvest path" },
    { "HLSE-URL-BRAND",           "url",  "Brand impersonation in domain" },
    { "HLSE-URL-BRAND-RISKY-TLD", "url",  "Brand name on a high-risk TLD" },
    { "HLSE-URL-MULTI-BRAND",     "url",  "Multiple brands co-spoofed in one host" },
    { "HLSE-URL-SUBDOMAIN",       "url",  "Brand placed in subdomain of attacker domain" },
    { "HLSE-URL-SUBDOMAIN-HARVEST","url", "Subdomain brand spoof with harvest path" },
    { "HLSE-URL-HYPHEN-BRAND",    "url",  "Brand-hyphen-securityword phishing host" },
    { "HLSE-URL-HYPHEN-HARVEST",  "url",  "Hyphenated brand host with harvest path" },
    { "HLSE-URL-IP-BRAND",        "url",  "Raw-IP URL impersonating a brand" },
    { "HLSE-URL-CRED-HARVEST",    "url",  "Credential-harvest path pattern" },
    { "HLSE-URL-AT-CRED-TRICK",   "url",  "'@' userinfo credential trick in URL" },
    { "HLSE-URL-SHORTENER",       "url",  "URL shortener masking the destination" },
    { "HLSE-URL-FREEHOST",        "url",  "Free-hosting / abuse-prone provider" },
    { "HLSE-URL-DGA",             "url",  "Algorithmically-generated (DGA) domain" },
    { "HLSE-URL-GENERIC",         "url",  "Recognised URL attack, unclassified pattern" },
    /* file masquerade patterns (file_pattern_id) */
    { "HLSE-FILE-RTL-OVERRIDE",   "file", "Unicode RTL-override filename trick" },
    { "HLSE-FILE-DOUBLE-EXT",     "file", "Double-extension masquerade" },
    { "HLSE-FILE-MACRO",          "file", "Office macro delivery" },
    { "HLSE-FILE-PDF-JS",         "file", "PDF with embedded JavaScript" },
    { "HLSE-FILE-MASQUERADE",     "file", "Generic file masquerade / malicious delivery" },
    /* exposed-credential types (secret_pattern_id) */
    { "HLSE-SECRET-AWS",          "secret", "AWS access key" },
    { "HLSE-SECRET-GITHUB",       "secret", "GitHub token" },
    { "HLSE-SECRET-STRIPE",       "secret", "Stripe API key" },
    { "HLSE-SECRET-SLACK",        "secret", "Slack token" },
    { "HLSE-SECRET-GOOGLE",       "secret", "Google API key" },
    { "HLSE-SECRET-OPENAI",       "secret", "OpenAI API key" },
    { "HLSE-SECRET-ANTHROPIC",    "secret", "Anthropic API key" },
    { "HLSE-SECRET-AZURE",        "secret", "Azure credential" },
    { "HLSE-SECRET-PRIVATE-KEY",  "secret", "Private key (PEM/OpenSSH)" },
    { "HLSE-SECRET-JWT",          "secret", "JSON Web Token" },
    { "HLSE-SECRET-GENERIC",      "secret", "Generic / heuristic credential" },
    /* single-pattern kinds (emitted inline at the kind's BLOCK path) */
    { "HLSE-ESP-BOOTKIT",         "esp",       "UEFI bootkit indicator in EFI System Partition" },
    { "HLSE-PKG-TYPOSQUAT",       "package",   "Dependency-confusion / typosquat supply-chain attack" },
    { "HLSE-NET-C2",             "network",   "Suspicious network activity (C2 / exfiltration)" },
    { "HLSE-CLIP-HIJACK",         "clipboard", "Cryptocurrency clipboard hijack (clipper malware)" },
    { "HLSE-PROTECT-RANSOM",      "protect",   "Ransomware / destructive-malware indicator (file entropy, SMB canary, mass rename)" }
};

/* Emit the full pattern-ID registry. JSON mode → an array of
 * {id, kind, description} objects under a "patterns" key; text mode → an
 * aligned table. Returns 0 (a meta-command, never a failure gate).          */
int
cli_list_patterns(int json_out) {
    size_t n = sizeof(g_pattern_registry) / sizeof(g_pattern_registry[0]);
    size_t i;
    if (json_out) {
        /* The registry strings are author-controlled constants (ASCII, no
         * quotes/backslashes/control chars), so they need no JSON escaping —
         * keeping this file self-contained and free of a dependency on
         * hlse_json_escape in hlse_util.c. */
        printf("{\"kind\":\"pattern_registry\",\"hlse_version\":\"" HLSE_VERSION
               "\",\"count\":%zu,\"patterns\":[", n);
        for (i = 0; i < n; i++) {
            printf("%s{\"id\":\"%s\",\"kind\":\"%s\",\"description\":\"%s\"}",
                   i > 0 ? "," : "",
                   g_pattern_registry[i].id,
                   g_pattern_registry[i].kind,
                   g_pattern_registry[i].desc);
        }
        printf("]}\n");
    } else {
        printf("HLSE pattern_id registry (%zu stable tokens, append-only)\n", n);
        for (i = 0; i < n; i++)
            printf("  %-28s [%-9s] %s\n",
                   g_pattern_registry[i].id,
                   g_pattern_registry[i].kind,
                   g_pattern_registry[i].desc);
    }
    return 0;
}

/* ── Pattern-id ladders (moved from hlse_cli.c) ────────────────────────────
 * The HLSE-* token classification lives here, next to the registry that
 * documents every emitted token. FileVerdict-dependent helpers need
 * hlse_file.h; the rest are pure string matching.                            */
/* Stable machine-readable pattern id for a file-masquerade verdict — the file
 * counterpart of hlse_text_pattern_id (P86). Keyed to the prose label computed
 * inline at the file display sites so the same append-only HLSE-FILE-* tokens
 * are emitted everywhere a file `pattern` is shown. Returns "HLSE-FILE-MASQUERADE"
 * for the catch-all masquerade label; never NULL when called with a non-NULL
 * fpat. */
const char *
file_pattern_id(const char *fpat) {
    if (!fpat) return NULL;
    if (strstr(fpat, "RTL override"))    return "HLSE-FILE-RTL-OVERRIDE";
    if (strstr(fpat, "double-extension")) return "HLSE-FILE-DOUBLE-EXT";
    if (strstr(fpat, "macro"))            return "HLSE-FILE-MACRO";
    if (strstr(fpat, "embedded JavaScript")) return "HLSE-FILE-PDF-JS";
    return "HLSE-FILE-MASQUERADE";
}

/* Stable file pattern_id derived directly from a FileVerdict's first reason —
 * mirrors the prose-label ladder at the file display sites so the SARIF scan
 * path (P91) emits the same HLSE-FILE-* token as the standalone `file` JSON. */
const char *
file_verdict_pattern_id(const FileVerdict *fv) {
    if (fv->n_reasons > 0) {
        const char *r = fv->reasons[0];
        if (strstr(r, "RLO") || strstr(r, "Unicode"))
            return "HLSE-FILE-RTL-OVERRIDE";
        if (strstr(r, "DOUBLE EXTENSION") || strstr(r, "double"))
            return "HLSE-FILE-DOUBLE-EXT";
        if (strstr(r, "macro") || strstr(r, "Macro"))
            return "HLSE-FILE-MACRO";
        if (strstr(r, "PDF") || strstr(r, "JavaScript"))
            return "HLSE-FILE-PDF-JS";
    }
    return "HLSE-FILE-MASQUERADE";
}

/* Socratic question (Perspective 101): "The same RLO/DOUBLE-EXTENSION/macro/
 * PDF if-else classification ladder is copy-pasted at all four file display
 * sites (standalone `file` JSON, standalone plaintext, `scan`'s embedded-file
 * JSON, `scan`'s embedded-file plaintext) as an inline local `fpat` variable —
 * four independent copies of the same four conditions, right next to the
 * single shared file_verdict_pattern_id() a few lines above that already
 * performs the identical match for the pattern_id token. Four independently
 * maintained copies is exactly how the standalone-vs-scan field asymmetry
 * that Perspective 95 had to fix originally happened. Shouldn't the
 * human-readable label share one function the way the token already does?"
 *
 * Consolidates the four inline copies into one function so pattern label and
 * pattern_id can never again drift apart between the standalone and scan
 * code paths. Pure refactor — every branch and return value is unchanged. */
const char *
file_classify_pattern(const FileVerdict *fv) {
    if (fv->n_reasons > 0) {
        const char *r = fv->reasons[0];
        if (strstr(r, "RLO") || strstr(r, "Unicode"))
            return "Unicode RTL override trick (hidden file extension)";
        if (strstr(r, "DOUBLE EXTENSION") || strstr(r, "double"))
            return "double-extension file masquerade (disguised executable)";
        if (strstr(r, "macro") || strstr(r, "Macro"))
            return "Office macro delivery (document-based malware lure)";
        if (strstr(r, "PDF") || strstr(r, "JavaScript"))
            return "PDF with embedded JavaScript (drive-by execution lure)";
    }
    return "file masquerade / malicious file delivery";
}

/* Stable machine-readable pattern id for an exposed-credential verdict — the
 * secret counterpart of hlse_text_pattern_id (P86). Keyed to the credential
 * type label (sv.findings[0].type) so SIEM rules route on a stable HLSE-SECRET-*
 * token instead of the freeform provider string. Returns "HLSE-SECRET-GENERIC"
 * for unrecognised types; never NULL when called with a non-NULL ftype. */
const char *
secret_pattern_id(const char *ftype) {
    if (!ftype) return NULL;
    if (strstr(ftype, "AWS"))     return "HLSE-SECRET-AWS";
    if (strstr(ftype, "GitHub"))  return "HLSE-SECRET-GITHUB";
    if (strstr(ftype, "Stripe"))  return "HLSE-SECRET-STRIPE";
    if (strstr(ftype, "Slack"))   return "HLSE-SECRET-SLACK";
    if (strstr(ftype, "Google"))  return "HLSE-SECRET-GOOGLE";
    if (strstr(ftype, "OpenAI"))  return "HLSE-SECRET-OPENAI";
    if (strstr(ftype, "Anthropic")) return "HLSE-SECRET-ANTHROPIC";
    if (strstr(ftype, "Azure"))   return "HLSE-SECRET-AZURE";
    if (strstr(ftype, "Private key") || strstr(ftype, "private key"))
                                  return "HLSE-SECRET-PRIVATE-KEY";
    /* Checked before the generic JWT arm: an unsigned token is a distinct
     * finding class (forgeable credential / misconfiguration, not a leak) and
     * deserves its own routing token downstream. */
    if (strstr(ftype, "JWT_ALG_NONE")) return "HLSE-SECRET-JWT-ALG-NONE";
    if (strstr(ftype, "JWT"))     return "HLSE-SECRET-JWT";
    return "HLSE-SECRET-GENERIC";
}
