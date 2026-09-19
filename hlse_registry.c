/* hlse_registry.c — stable HLSE-* pattern_id registry + printer.
 *
 * Extracted from hlse_core.c (split increment 2): the table is pure data
 * plus list_patterns() which touches nothing but printf. Keeping the
 * registry append-only is the contract; see the header comment below.
 */
#include "hlse_registry.h"

#include <stdio.h>
#include <string.h>

#include "hlse_core.h"   /* HLSE_VERSION */

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
 * above and in hlse_text_pattern_id / hlse_url_pattern_id.                   */
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
hlse_list_patterns(int json_out) {
    size_t n = sizeof(g_pattern_registry) / sizeof(g_pattern_registry[0]);
    size_t i;
    if (json_out) {
        /* The registry strings are author-controlled constants (ASCII, no
         * quotes/backslashes/control chars), so they need no JSON escaping —
         * keeping this self-contained and free of a forward reference to
         * json_escape, which is defined later in the file. */
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

