/* hlse_meta.c — report-metadata helpers shared by the scan driver,
 * git-history scan, and the emitters: secret→pattern-id, file
 * verdict→classification/objective/verify, and the blast-radius
 * asset-class bucketing that turns a set of leaked credentials into
 * a pivot-risk statement. Extracted verbatim from hlse_core.c
 * (split increment 6). The dropped local `action_for_score` was a
 * byte-identical copy of public hlse_action_for_score — callers
 * now use the public name. */
#include "hlse_meta.h"
#include "hlse_file.h"
#include "hlse_secrets.h"
#include <string.h>
#include <stdio.h>

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
unsigned
hlse_asset_class_of(const char *type) {
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
const char *
hlse_scan_immediate_action(unsigned mask, int nclasses) {
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
int
hlse_asset_mask_describe(unsigned mask, char *out, size_t outsz) {
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


/* Stable machine-readable pattern id for a file-masquerade verdict — the file
 * counterpart of hlse_text_pattern_id (P86). Keyed to the prose label computed
 * inline at the file display sites so the same append-only HLSE-FILE-* tokens
 * are emitted everywhere a file `pattern` is shown. Returns "HLSE-FILE-MASQUERADE"
 * for the catch-all masquerade label; never NULL when called with a non-NULL
 * fpat. */
const char *
hlse_file_pattern_id(const char *fpat) {
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
hlse_file_verdict_pattern_id(const FileVerdict *fv) {
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
 * single shared hlse_file_verdict_pattern_id() a few lines above that already
 * performs the identical match for the pattern_id token. Four independently
 * maintained copies is exactly how the standalone-vs-scan field asymmetry
 * that Perspective 95 had to fix originally happened. Shouldn't the
 * human-readable label share one function the way the token already does?"
 *
 * Consolidates the four inline copies into one function so pattern label and
 * pattern_id can never again drift apart between the standalone and scan
 * code paths. Pure refactor — every branch and return value is unchanged. */
const char *
hlse_file_classify_pattern(const FileVerdict *fv) {
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
const char *
hlse_file_masquerade_objective(void) {
    return "code execution \xe2\x80\x94 opening a disguised executable "
           "or document with macros runs the payload with your "
           "user privileges; the visual disguise is designed to "
           "bypass 'I checked the extension' caution";
}

const char *
hlse_file_masquerade_verify(void) {
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
const char *
hlse_secret_pattern_id(const char *ftype) {
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
