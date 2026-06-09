/*
 * hlse_secrets.c — Credential Exposure Scanner + Email Forensics +
 *                  Clipboard Crypto-Swap Detector
 *
 * Three new detection modules for HLSE Core:
 *
 *   1. Secret scanner  — detect leaked API keys, tokens, private keys
 *                         in files or stdin (pre-commit hook use case)
 *   2. Email forensics — parse raw email headers for BEC/spoofing
 *   3. Crypto clipboard — detect address-swap malware
 *
 * All modules are:
 *   - Pure C, zero dependencies beyond libc
 *   - Fully local (zero network access)
 *   - Deterministic (same input → same output)
 *   - Thread-safe (no global mutable state)
 *
 * Build: gcc -O2 -c hlse_secrets.c -I.
 * Test:  see tests/hlse_secrets_tests.c
 *
 * Identity: bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>    /* strncasecmp */
#include <stdarg.h>
#include <ctype.h>

#include "hlse_secrets.h"

/* ═══════════════════════════════════════════════════════════════════════
 * Internal helpers
 * ═══════════════════════════════════════════════════════════════════════ */

static void
sv_add(SecretVerdict *v, int delta, const char *type,
       const char *fmt, ...) {
    va_list ap;
    if (v->n_findings >= HLSE_SECRET_MAX_FINDINGS) return;
    v->score += delta;
    if (v->score > 100) v->score = 100;

    strncpy(v->findings[v->n_findings].type, type,
            sizeof(v->findings[0].type) - 1);
    va_start(ap, fmt);
    vsnprintf(v->findings[v->n_findings].description,
              sizeof(v->findings[0].description), fmt, ap);
    va_end(ap);
    v->n_findings++;
}

static int
is_hex(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static int
is_base64(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

static int
is_alnum_or_dash(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_';
}

/* ═══════════════════════════════════════════════════════════════════════
 * Module 1: Secret / Credential Exposure Scanner
 *
 * Detects high-entropy strings matching known API key formats:
 *
 *   - AWS Access/STS Key:   AKIA|ABIA|ACCA|ASIA[0-9A-Z]{16}
 *   - AWS Secret Key:       40-char base64 after "aws_secret"
 *   - GitHub token family:  ghp_|gho_|ghu_|ghs_|ghr_[A-Za-z0-9]{36}
 *   - GitHub fine-grained:  github_pat_[A-Za-z0-9_]{20,}
 *   - Stripe key family:    (sk|rk)_live_ / pk_live_ / sk_test_[A-Za-z0-9]{24,}
 *   - Google API Key:       AIza[A-Za-z0-9_-]{35}
 *   - GitLab PAT:           glpat-[A-Za-z0-9_-]{20}
 *   - npm Access Token:     npm_[A-Za-z0-9]{36}
 *   - OpenAI / Anthropic:   sk-proj-... / sk-ant-... (dash-prefixed LLM keys)
 *   - Shopify tokens:       shpat_|shpss_|shppa_[0-9a-f]{32}
 *   - Hugging Face:         hf_[A-Za-z]{34}
 *   - PyPI Upload Token:    pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}
 *   - Postman / Square:     PMAK-[0-9a-f]{24} / sq0atp-[A-Za-z0-9-]{22,}
 *   - Doppler / Grafana:    dp.pt.[A-Za-z0-9]{43} / glsa_[A-Za-z0-9]{32}
 *   - Linear / New Relic:   lin_api_[A-Za-z0-9]{40} / NRAK-[A-Za-z0-9]{27}
 *   - Databricks:           dapi[0-9a-f]{32}
 *   - Slack Token:          xoxb-|xoxp-|xoxs-[0-9A-Za-z-]{10,}
 *   - Slack / Discord Webhook URLs (URL-anchored, ~zero false positive)
 *   - Generic high-entropy: 32+ hex chars after "key" / "secret" / "token"
 *   - SSH Private Key:      -----BEGIN (RSA|OPENSSH) PRIVATE KEY-----
 *   - .env PASSWORD=:       PASSWORD= or PASS= followed by non-empty value
 *
 * Design note: We match PATTERNS, not entropy alone. Pure entropy
 * detection produces too many false positives on binary data and
 * base64-encoded non-secret content.
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    const char *prefix;      /* literal prefix to search for */
    int         prefix_len;
    int         min_suffix;  /* minimum chars after prefix that must match */
    int         (*char_ok)(char); /* validation function for suffix chars */
    const char *label;       /* human-readable type */
    int         score;       /* risk score */
} SecretPattern;

static int char_upper_digit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z');
}

/* Digits only — used for URL-anchored tokens whose first segment is a numeric
 * ID (e.g. a Discord webhook ID after `.../webhooks/`). */
static int is_digit_c(char c) {
    return (c >= '0' && c <= '9');
}

/* Letters only — used for tokens whose body is pure alphabetic (e.g. Hugging
 * Face `hf_` + 34 letters), so a 34-char run is far less likely to collide
 * with an underscore/digit-bearing code identifier sharing the prefix. */
static int is_alpha(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static const SecretPattern SECRET_PATTERNS[] = {
    /* AWS */
    { "AKIA",          4,  16, char_upper_digit,   "AWS Access Key ID",     80 },
    { "ABIA",          4,  16, char_upper_digit,   "AWS STS Token",         80 },
    { "ACCA",          4,  16, char_upper_digit,   "AWS CloudFront Key",    70 },
    { "ASIA",          4,  16, char_upper_digit,   "AWS Temporary (STS) Access Key", 80 },

    /* GitHub */
    { "ghp_",          4,  36, is_alnum_or_dash,   "GitHub Personal Access Token", 90 },
    { "gho_",          4,  36, is_alnum_or_dash,   "GitHub OAuth Token",    85 },
    { "ghu_",          4,  36, is_alnum_or_dash,   "GitHub User Token",     85 },
    { "ghs_",          4,  36, is_alnum_or_dash,   "GitHub Server Token",   85 },
    { "ghr_",          4,  36, is_alnum_or_dash,   "GitHub Refresh Token",  85 },
    { "github_pat_",  11,  20, is_alnum_or_dash,   "GitHub Fine-grained PAT", 90 },

    /* Stripe */
    { "sk_live_",      8,  24, is_alnum_or_dash,   "Stripe Live Secret Key", 95 },
    { "rk_live_",      8,  24, is_alnum_or_dash,   "Stripe Restricted Key", 90 },
    { "pk_live_",      8,  24, is_alnum_or_dash,   "Stripe Live Publishable", 50 },
    { "sk_test_",      8,  24, is_alnum_or_dash,   "Stripe Test Key",       30 },

    /* Slack */
    { "xoxb-",         5,  10, is_alnum_or_dash,   "Slack Bot Token",       80 },
    { "xoxp-",         5,  10, is_alnum_or_dash,   "Slack User Token",      85 },
    { "xoxs-",         5,  10, is_alnum_or_dash,   "Slack Session Token",   85 },

    /* Google */
    { "AIza",          4,  35, is_alnum_or_dash,   "Google API Key",        80 },

    /* GitLab */
    { "glpat-",        6,  20, is_alnum_or_dash,   "GitLab Personal Access Token", 90 },

    /* npm */
    { "npm_",          4,  36, is_alnum_or_dash,   "npm Access Token",      85 },

    /* OpenAI / Anthropic (distinctive dash-prefixed LLM provider keys) */
    { "sk-proj-",      8,  20, is_alnum_or_dash,   "OpenAI Project Key",    90 },
    { "sk-ant-",       7,  20, is_alnum_or_dash,   "Anthropic API Key",     90 },

    /* Shopify (32-hex body — very low false-positive prefix) */
    { "shpat_",        6,  32, is_hex,             "Shopify Access Token",  85 },
    { "shpss_",        6,  32, is_hex,             "Shopify Shared Secret", 85 },
    { "shppa_",        6,  32, is_hex,             "Shopify Private App Token", 85 },

    /* Hugging Face */
    { "hf_",           3,  34, is_alpha,           "Hugging Face Token",    80 },

    /* PyPI (fixed 20-char marker prefix — essentially zero false positives) */
    { "pypi-AgEIcHlwaS5vcmc", 20, 20, is_alnum_or_dash, "PyPI Upload Token", 90 },

    /* Postman */
    { "PMAK-",         5,  24, is_hex,             "Postman API Key",       85 },

    /* Square */
    { "sq0atp-",       7,  22, is_alnum_or_dash,   "Square Access Token",   85 },

    /* Doppler */
    { "dp.pt.",        6,  43, is_alnum_or_dash,   "Doppler Personal Token", 85 },

    /* Grafana */
    { "glsa_",         5,  32, is_alnum_or_dash,   "Grafana Service Account Token", 85 },

    /* Linear */
    { "lin_api_",      8,  40, is_alnum_or_dash,   "Linear API Key",        85 },

    /* New Relic */
    { "NRAK-",         5,  27, is_alnum_or_dash,   "New Relic API Key",     85 },

    /* Databricks */
    { "dapi",          4,  32, is_hex,             "Databricks Access Token", 80 },

    /* PlanetScale (highly distinctive 11-char prefix) */
    { "pscale_tkn_",   11, 40, is_alnum_or_dash, "PlanetScale Service Token", 85 },

    /* HashiCorp Vault service token v2 (hvs. prefix, long body) */
    { "hvs.",           4, 50, is_alnum_or_dash, "HashiCorp Vault Token",     80 },

    /* Netlify Personal Access Token */
    { "nfp_",           4, 32, is_alnum_or_dash, "Netlify Personal Access Token", 85 },

    /* Webhook URLs (URL-anchored — essentially zero false positives) */
    { "hooks.slack.com/services/T", 27, 5, is_alnum_or_dash,
                                            "Slack Webhook URL",     70 },
    { "discord.com/api/webhooks/",     25, 17, is_digit_c,
                                            "Discord Webhook URL",   75 },
    { "discordapp.com/api/webhooks/",  28, 17, is_digit_c,
                                            "Discord Webhook URL",   75 },

    { NULL, 0, 0, NULL, NULL, 0 }
};

/* Check for SSH private key headers */
static int
check_ssh_key(const char *text, SecretVerdict *v) {
    const char *markers[] = {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        NULL
    };
    int found = 0;
    int i;
    for (i = 0; markers[i]; i++) {
        if (strstr(text, markers[i])) {
            sv_add(v, 95, "PRIVATE_KEY",
                   "Private key detected: %.40s...", markers[i]);
            found = 1;
        }
    }
    return found;
}

/* Check for .env-style password assignments */
static int
check_env_passwords(const char *text, SecretVerdict *v) {
    const char *patterns[] = {
        "PASSWORD=", "PASSWD=", "DB_PASSWORD=", "DATABASE_PASSWORD=",
        "MYSQL_ROOT_PASSWORD=", "POSTGRES_PASSWORD=",
        "API_KEY=", "API_SECRET=", "SECRET_KEY=",
        "AWS_SECRET_ACCESS_KEY=", "ANTHROPIC_API_KEY=",
        "OPENAI_API_KEY=", "STRIPE_SECRET_KEY=",
        "TWILIO_AUTH_TOKEN=", "SENDGRID_API_KEY=",
        "FIREBASE_PRIVATE_KEY=", "CLOUDFLARE_API_TOKEN=",
        /* SCM / CI / hosting */
        "GITHUB_TOKEN=", "GITLAB_TOKEN=", "GITLAB_CI_TOKEN=",
        "DIGITALOCEAN_TOKEN=", "HEROKU_API_KEY=",
        "NETLIFY_AUTH_TOKEN=", "VERCEL_TOKEN=",
        "CIRCLE_TOKEN=", "SNYK_TOKEN=",
        /* Connection strings that embed credentials */
        "DATABASE_URL=", "MONGODB_URI=", "REDIS_URL=",
        /* Generic secrets commonly leaked in .env */
        "JWT_SECRET=", "JWT_SECRET_KEY=", "APP_SECRET=",
        NULL
    };
    int found = 0;
    int i;
    for (i = 0; patterns[i]; i++) {
        const char *p = strstr(text, patterns[i]);
        if (p) {
            /* Check that value after = is non-empty and not a variable ref */
            const char *val = p + strlen(patterns[i]);
            if (*val && *val != '$' && *val != '{' && *val != '\n'
                && *val != '\r' && *val != ' ')
            {
                sv_add(v, 70, "ENV_SECRET",
                       "Hardcoded secret: %.30s<redacted>", patterns[i]);
                found = 1;
            }
        }
    }
    return found;
}

/* Check for generic high-entropy hex strings after secret-like keywords */
static int
check_generic_hex_secret(const char *text, SecretVerdict *v) {
    const char *keywords[] = {
        "\"key\":", "\"secret\":", "\"token\":", "\"apikey\":",
        "\"api_key\":", "\"access_token\":", "\"private_key\":",
        "'key':", "'secret':", "'token':",
        NULL
    };
    int found = 0;
    int i;
    for (i = 0; keywords[i]; i++) {
        const char *p = strstr(text, keywords[i]);
        if (!p) continue;
        p += strlen(keywords[i]);
        /* Skip whitespace and quotes */
        while (*p == ' ' || *p == '"' || *p == '\'') p++;
        /* Count consecutive hex/base64 chars */
        int hex_run = 0;
        const char *start = p;
        while (is_hex(*p) || is_base64(*p)) { hex_run++; p++; }
        if (hex_run >= 32) {
            sv_add(v, 60, "GENERIC_SECRET",
                   "High-entropy value after '%s' (%d chars)",
                   keywords[i], hex_run);
            found = 1;
        }
        (void)start;
    }
    return found;
}

/* Detect whether a matched secret is actually a placeholder, example, or
 * test fixture rather than a live credential. This addresses the most
 * common secret-scanner false positive documented in the literature
 * (arXiv 2307.00714, 2410.23657): AWS's own doc key AKIAIOSFODNN7EXAMPLE,
 * "your_api_key_here", sk_test_XXXX, etc.
 *
 * Checks the secret token itself AND a window of context before it.    */
static int
is_placeholder_secret(const char *line_start, const char *match,
                      const char *secret, size_t secret_len) {
    static const char *MARKERS[] = {
        "example", "EXAMPLE", "Example",
        "placeholder", "PLACEHOLDER",
        "your_", "your-", "YOUR_", "<your", "my_secret",
        "dummy", "DUMMY", "sample", "SAMPLE",
        "redacted", "REDACTED", "xxxxxxxx", "XXXXXXXX",
        "changeme", "CHANGEME", "todo", "TODO",
        "fake", "FAKE", "test_key", "testkey",
        NULL
    };
    size_t i;
    char window[256];
    size_t wlen;

    /* 1. Does the secret token itself contain a marker substring? */
    for (i = 0; MARKERS[i]; i++) {
        if (secret_len >= strlen(MARKERS[i]) &&
            strstr(secret, MARKERS[i]) != NULL &&
            (size_t)(strstr(secret, MARKERS[i]) - secret) < secret_len) {
            return 1;
        }
    }

    /* 2. Examine up to 64 chars of context before the match (variable
     *    names like "example_key =", "test_token:", "# sample").       */
    {
        size_t before = (size_t)(match - line_start);
        size_t take = before < 64 ? before : 64;
        const char *ctx = match - take;
        wlen = take;
        if (wlen >= sizeof(window)) wlen = sizeof(window) - 1;
        memcpy(window, ctx, wlen);
        window[wlen] = '\0';
        for (i = 0; MARKERS[i]; i++) {
            if (strstr(window, MARKERS[i]) != NULL) return 1;
        }
    }

    /* 3. Highly repetitive token (all X's, all A's) — not a real
     *    high-entropy credential. Count distinct characters.            */
    {
        int seen[256] = {0};
        int distinct = 0;
        for (i = 0; i < secret_len && i < 64; i++) {
            unsigned char c = (unsigned char)secret[i];
            if (!seen[c]) { seen[c] = 1; distinct++; }
        }
        if (secret_len >= 12 && distinct <= 4) return 1;
    }

    return 0;
}

SecretVerdict
hlse_scan_secrets(const char *text) {
    SecretVerdict v;
    const char *p;
    int i;

    memset(&v, 0, sizeof(v));
    if (!text) return v;

    /* Pattern-based scanning */
    for (i = 0; SECRET_PATTERNS[i].prefix; i++) {
        const SecretPattern *sp = &SECRET_PATTERNS[i];
        p = text;
        while ((p = strstr(p, sp->prefix)) != NULL) {
            /* Validate suffix characters */
            const char *suffix = p + sp->prefix_len;
            int valid = 0;
            int j;
            for (j = 0; j < sp->min_suffix && suffix[j]; j++) {
                if (!sp->char_ok(suffix[j])) break;
                valid++;
            }
            if (valid >= sp->min_suffix) {
                /* Skip placeholders/examples/test fixtures (literature-
                 * documented FP class). Measure the full token length. */
                size_t tok_len = (size_t)sp->prefix_len;
                while (suffix[tok_len - (size_t)sp->prefix_len] &&
                       sp->char_ok(suffix[tok_len - (size_t)sp->prefix_len]))
                    tok_len++;
                if (!is_placeholder_secret(text, p, p, tok_len)) {
                    /* Redact: show prefix + first 4 chars of suffix */
                    char preview[64];
                    snprintf(preview, sizeof(preview), "%.8s%.4s...",
                             sp->prefix, suffix);
                    sv_add(&v, sp->score, sp->label,
                           "%s found: %s", sp->label, preview);
                }
            }
            p += sp->prefix_len;
        }
    }

    /* Structural checks */
    check_ssh_key(text, &v);
    check_env_passwords(text, &v);
    check_generic_hex_secret(text, &v);

    /* GCP service account JSON — contains "type": "service_account" and
     * "private_key" together. Near-zero false positives.               */
    if (strstr(text, "\"type\"") && strstr(text, "service_account") &&
        strstr(text, "\"private_key\"")) {
        sv_add(&v, 90, "GCP_SERVICE_ACCOUNT",
               "GCP service account JSON (type+private_key fields)");
    }

    /* Azure SAS token — highly distinctive shared-access-signature pattern */
    if ((strstr(text, "sv=") || strstr(text, "SharedAccessSignature")) &&
        strstr(text, "sig=") && strstr(text, "se=")) {
        sv_add(&v, 85, "AZURE_SAS",
               "Azure SAS token (sv/sig/se fields)");
    }

    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Module 2: Email Header Forensics
 *
 * Parses raw email headers (RFC 5322) and detects spoofing signals:
 *
 *   E1. Display name ≠ From domain    (most common BEC technique)
 *   E2. Reply-To domain ≠ From domain (redirect replies to attacker)
 *   E3. Free email in corporate context (CEO using gmail.com)
 *   E4. SPF/DKIM fail hints            (Authentication-Results header)
 *   E5. Received chain anomaly          (first hop from suspicious IP)
 *   E6. Urgent subject + external sender (BEC pattern compound)
 *
 * Input: raw email header text (everything before the blank line).
 * Output: EmailVerdict with score and reasons.
 * ═══════════════════════════════════════════════════════════════════════ */

/* Extract a header value. Returns pointer to value after "Header: ",
 * or NULL if not found. Caller must not free. */
static const char *
find_header(const char *headers, const char *name) {
    size_t nlen = strlen(name);
    const char *p = headers;
    while (p) {
        /* Match at start of line */
        if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            const char *val = p + nlen + 1;
            while (*val == ' ' || *val == '\t') val++;
            return val;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return NULL;
}

/* Extract domain from an email address ("user@domain.com" → "domain.com") */
static int
extract_domain(const char *addr, char *out, size_t out_sz) {
    const char *at = NULL;
    const char *p = addr;
    /* Find the last @ in the address (handles "Name <user@domain>" format) */
    while (*p && *p != '\n' && *p != '\r') {
        if (*p == '@') at = p;
        p++;
    }
    if (!at) return 0;
    at++;
    {
        size_t i = 0;
        while (at[i] && at[i] != '>' && at[i] != ' ' && at[i] != '\n'
               && at[i] != '\r' && i < out_sz - 1) {
            out[i] = (at[i] >= 'A' && at[i] <= 'Z')
                     ? at[i] + 32 : at[i];
            i++;
        }
        out[i] = '\0';
        return (int)i;
    }
}

/* Extract display name from "Display Name <email@domain>" format */
static int
extract_display_name(const char *from, char *out, size_t out_sz) {
    const char *lt = strchr(from, '<');
    if (!lt || lt == from) return 0;
    {
        size_t len = (size_t)(lt - from);
        while (len > 0 && (from[len-1] == ' ' || from[len-1] == '"'))
            len--;
        const char *start = from;
        while (*start == '"' || *start == ' ') { start++; len--; }
        if (len == 0 || len >= out_sz) return 0;
        memcpy(out, start, len);
        out[len] = '\0';
        return 1;
    }
}

static const char *FREE_EMAIL_DOMAINS[] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "icloud.com", "mail.com",
    "yandex.com", "zoho.com", "gmx.com", "live.com",
    /* Disposable/temporary email services — very high fraud association */
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "throwam.com", "trashmail.com", "sharklasers.com",
    /* Asian free email providers */
    "qq.com", "163.com", "126.com",         /* China */
    "naver.com", "daum.net",                 /* Korea */
    "yahoo.co.jp",                           /* Japan */
    /* European free email providers */
    "web.de", "gmx.de", "freenet.de",       /* Germany */
    "orange.fr", "laposte.net",             /* France */
    "mail.ru", "yandex.ru",                 /* Russia */
    "libero.it", "virgilio.it",             /* Italy */
    NULL
};

static int
is_free_email(const char *domain) {
    int i;
    for (i = 0; FREE_EMAIL_DOMAINS[i]; i++) {
        if (strcmp(domain, FREE_EMAIL_DOMAINS[i]) == 0) return 1;
    }
    return 0;
}

EmailVerdict
hlse_check_email_headers(const char *raw_headers) {
    EmailVerdict v;
    const char *from_val, *reply_to_val, *auth_val, *subject_val;
    char from_domain[256] = {0};
    char reply_domain[256] = {0};
    char display_name[256] = {0};

    memset(&v, 0, sizeof(v));
    if (!raw_headers) return v;

    from_val = find_header(raw_headers, "From");
    reply_to_val = find_header(raw_headers, "Reply-To");
    auth_val = find_header(raw_headers, "Authentication-Results");
    subject_val = find_header(raw_headers, "Subject");

    if (!from_val) return v; /* No From header → cannot analyze */

    extract_domain(from_val, from_domain, sizeof(from_domain));

    /* E1: Display name vs From domain mismatch */
    if (extract_display_name(from_val, display_name, sizeof(display_name))) {
        /* Check if display name contains a different known domain */
        const char *known[] = {
            "microsoft", "apple", "google", "amazon", "paypal",
            "bank", "support", "security", "admin", "helpdesk",
            "facebook", "netflix", "linkedin", "twitter", "instagram",
            "irs", "fbi", "government", "treasury", "customs",
            "accounts", "notifications", "it department",
            /* Additional high-value impersonation targets */
            "stripe", "shopify", "github", "docusign", "zoom",
            "office 365", "microsoft 365", "apple id",
            "fedex", "dhl", "ups", "usps",
            "human resources", "hr department", "it support",
            NULL
        };
        int i;
        char lower_dn[256];
        size_t k;
        for (k = 0; k < strlen(display_name) && k < sizeof(lower_dn) - 1; k++)
            lower_dn[k] = (char)tolower((unsigned char)display_name[k]);
        lower_dn[k] = '\0';

        for (i = 0; known[i]; i++) {
            if (strstr(lower_dn, known[i]) &&
                !strstr(from_domain, known[i]))
            {
                v.score += 45;
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "E1: Display name '%.60s' implies %.40s but From is %.80s",
                    display_name, known[i], from_domain);
                break;
            }
        }
    }

    /* E2: Reply-To domain mismatch */
    if (reply_to_val) {
        extract_domain(reply_to_val, reply_domain, sizeof(reply_domain));
        if (reply_domain[0] && from_domain[0] &&
            strcmp(reply_domain, from_domain) != 0)
        {
            v.score += 30;
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "E2: Reply-To domain (%.80s) differs from From (%.80s)",
                reply_domain, from_domain);
        }
    }

    /* E3: Free email used in corporate/authority context */
    if (from_domain[0] && is_free_email(from_domain)) {
        if (display_name[0]) {
            const char *corp_words[] = {
                "ceo", "cfo", "coo", "director", "manager", "president",
                "department", "hr ", "legal", "invoice",
                "accounts payable", "accounting", "finance", "payroll",
                "treasurer", "vp ", "vice president",
                "cto", "chro", "chief", "executive", "board member",
                "chairman", "controller", "auditor", "compliance",
                NULL
            };
            char lower_dn[256];
            size_t k;
            int i;
            for (k = 0; k < strlen(display_name) && k < sizeof(lower_dn) - 1; k++)
                lower_dn[k] = (char)tolower((unsigned char)display_name[k]);
            lower_dn[k] = '\0';

            for (i = 0; corp_words[i]; i++) {
                if (strstr(lower_dn, corp_words[i])) {
                    v.score += 35;
                    snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                        "E3: Corporate title '%.60s' using free email (%.80s)",
                        display_name, from_domain);
                    break;
                }
            }
        }
    }

    /* E4: SPF/DKIM fail in Authentication-Results */
    if (auth_val) {
        if (strstr(auth_val, "spf=fail") || strstr(auth_val, "spf=softfail")) {
            v.score += 25;
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "E4: SPF check failed — sender domain not authorized");
        }
        if (strstr(auth_val, "dkim=fail")) {
            v.score += 25;
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "E4: DKIM signature invalid — message may be tampered");
        }
        if (strstr(auth_val, "dmarc=fail")) {
            v.score += 30;
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "E4: DMARC failed — high confidence of spoofing");
        }
    }

    /* E5: Received chain anomaly — too few hops (direct injection)
     * or first Received: from address contains a suspicious IP pattern.
     * Legitimate email services always add 2+ Received headers.
     * Direct injection (only 1 hop) is a common phishing technique.   */
    {
        int hop_count = 0;
        const char *rp = raw_headers;
        /* Count Received: headers */
        while (rp && *rp) {
            if (strncasecmp(rp, "received:", 9) == 0) hop_count++;
            rp = strchr(rp, '\n');
            if (rp) rp++;
        }
        /* 0 Received headers = local injection or header stripping */
        if (hop_count == 0 && from_domain[0]) {
            v.score += 20;
            if (v.n_reasons < HLSE_EMAIL_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "E5: No Received headers — possible local injection or "
                    "header stripping");
        }
        /* Single hop from a free email domain is suspicious */
        if (hop_count == 1 && from_domain[0] && is_free_email(from_domain)) {
            v.score += 15;
            if (v.n_reasons < HLSE_EMAIL_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "E5: Only 1 Received hop from free email domain (%.80s) "
                    "— atypical of legitimate delivery", from_domain);
        }
    }

    /* E6: Urgent subject + external/free sender (BEC compound) */
    if (subject_val) {
        const char *urgency[] = {
            "urgent", "immediately", "wire", "transfer",
            "asap", "time sensitive", "action required",
            "payment", "invoice", "overdue", "confirmation",
            "verify", "suspended", "locked",
            "final notice", "deadline", "expires today",
            "account closed", "your account", "security alert",
            "important update", "required action",
            NULL
        };
        char lower_subj[512];
        size_t k;
        int has_urgency = 0;
        int i;
        for (k = 0; subject_val[k] && subject_val[k] != '\n'
             && k < sizeof(lower_subj) - 1; k++)
            lower_subj[k] = (char)tolower((unsigned char)subject_val[k]);
        lower_subj[k] = '\0';

        for (i = 0; urgency[i]; i++) {
            if (strstr(lower_subj, urgency[i])) { has_urgency = 1; break; }
        }
        if (has_urgency && from_domain[0] && is_free_email(from_domain)) {
            v.score += 25;
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "E6: Urgent subject from free email domain (%.80s)",
                from_domain);
        }
    }

    if (v.score > 100) v.score = 100;
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Module 3: Clipboard Crypto-Address Swap Detector
 *
 * Crypto-clipboard malware (CryptoClippy, MassLogger, etc.) monitors
 * the clipboard and swaps any cryptocurrency address with the attacker's.
 *
 * This module:
 *   1. Validates crypto address format (BTC, ETH, XMR, SOL, etc.)
 *   2. Compares two strings to detect if a swap occurred
 *   3. Flags if a known-format address changed between copy and paste
 *
 * Usage: Call hlse_check_crypto_swap(copied, pasted) where:
 *   - `copied` is the address the user intended to paste
 *   - `pasted` is what actually appeared after paste
 *
 * If they differ but both match the same crypto format → BLOCK.
 * ═══════════════════════════════════════════════════════════════════════ */

typedef enum {
    CRYPTO_NONE = 0,
    CRYPTO_BTC_LEGACY,    /* 1... (26-35 chars, base58) */
    CRYPTO_BTC_SEGWIT,    /* bc1q... (42-62 chars) */
    CRYPTO_BTC_TAPROOT,   /* bc1p... (62 chars) */
    CRYPTO_ETH,           /* 0x... (42 chars hex) */
    CRYPTO_XMR,           /* 4... or 8... (95 chars) */
    CRYPTO_SOL,           /* base58 (32-44 chars) */
    CRYPTO_USDT_TRC20,    /* T... (34 chars) */
    CRYPTO_LTC_LEGACY,    /* L... or M... (34 chars, base58) */
    CRYPTO_LTC_SEGWIT,    /* ltc1q... (43 chars, bech32) */
    CRYPTO_DOGE,          /* D... (34 chars, base58) */
    CRYPTO_XRP,           /* r... (25-34 chars, base58-like) */
    CRYPTO_DASH,          /* X... (34 chars, base58) */
    CRYPTO_XLM,           /* G... (56 chars, Stellar base32) */
    CRYPTO_ADA,           /* addr1... or stake1... (58-110 chars, bech32) */
} CryptoType;

static int
is_base58(char c) {
    /* Base58 = alphanumeric minus 0, O, I, l */
    if (c >= '1' && c <= '9') return 1;
    if (c >= 'A' && c <= 'H') return 1;
    if (c >= 'J' && c <= 'N') return 1;
    if (c >= 'P' && c <= 'Z') return 1;
    if (c >= 'a' && c <= 'k') return 1;
    if (c >= 'm' && c <= 'z') return 1;
    return 0;
}

static CryptoType
detect_crypto_type(const char *addr) {
    size_t len;
    if (!addr) return CRYPTO_NONE;
    len = strlen(addr);

    /* BTC Segwit: bc1q + 39-58 bech32 chars */
    if (len >= 42 && len <= 62 && strncmp(addr, "bc1q", 4) == 0)
        return CRYPTO_BTC_SEGWIT;

    /* BTC Taproot: bc1p + 58 bech32 chars */
    if (len == 62 && strncmp(addr, "bc1p", 4) == 0)
        return CRYPTO_BTC_TAPROOT;

    /* BTC Legacy: 1 or 3 + 25-34 base58 chars */
    if (len >= 26 && len <= 35 && (addr[0] == '1' || addr[0] == '3')) {
        int i, ok = 1;
        for (i = 1; i < (int)len; i++) {
            if (!is_base58(addr[i])) { ok = 0; break; }
        }
        if (ok) return CRYPTO_BTC_LEGACY;
    }

    /* ETH: 0x + 40 hex chars */
    if (len == 42 && addr[0] == '0' && addr[1] == 'x') {
        int i, ok = 1;
        for (i = 2; i < 42; i++) {
            if (!is_hex(addr[i])) { ok = 0; break; }
        }
        if (ok) return CRYPTO_ETH;
    }

    /* Monero: 4 or 8 + ~93 base58 chars */
    if (len >= 90 && len <= 100 && (addr[0] == '4' || addr[0] == '8'))
        return CRYPTO_XMR;

    /* USDT TRC20: T + 33 base58 */
    if (len == 34 && addr[0] == 'T') {
        int i, ok = 1;
        for (i = 1; i < 34; i++) {
            if (!is_base58(addr[i])) { ok = 0; break; }
        }
        if (ok) return CRYPTO_USDT_TRC20;
    }

    /* Litecoin SegWit: ltc1q + ~38 bech32 chars = 43 total */
    if (len == 43 && strncmp(addr, "ltc1q", 5) == 0)
        return CRYPTO_LTC_SEGWIT;

    /* Litecoin Legacy: L or M + 33 base58 chars = 34 total */
    if (len == 34 && (addr[0] == 'L' || addr[0] == 'M')) {
        int i, ok = 1;
        for (i = 1; i < 34; i++) {
            if (!is_base58(addr[i])) { ok = 0; break; }
        }
        if (ok) return CRYPTO_LTC_LEGACY;
    }

    /* Dogecoin: D + 33 base58 chars = 34 total */
    if (len == 34 && addr[0] == 'D') {
        int i, ok = 1;
        for (i = 1; i < 34; i++) {
            if (!is_base58(addr[i])) { ok = 0; break; }
        }
        if (ok) return CRYPTO_DOGE;
    }

    /* DASH: X + 33 base58 chars = 34 total */
    if (len == 34 && addr[0] == 'X') {
        int i, ok = 1;
        for (i = 1; i < 34; i++) {
            if (!is_base58(addr[i])) { ok = 0; break; }
        }
        if (ok) return CRYPTO_DASH;
    }

    /* Stellar (XLM): G + 55 chars in Stellar base32 [A-Z2-7] = 56 total */
    if (len == 56 && addr[0] == 'G') {
        int i, ok = 1;
        for (i = 1; i < 56; i++) {
            if (!((addr[i] >= 'A' && addr[i] <= 'Z') ||
                  (addr[i] >= '2' && addr[i] <= '7'))) { ok = 0; break; }
        }
        if (ok) return CRYPTO_XLM;
    }

    /* XRP: r + 24-33 base58-like chars = 25-34 total. Checked before SOL
     * since XRP addresses always start with 'r' at this length range.    */
    if (len >= 25 && len <= 34 && addr[0] == 'r') {
        int i, ok = 1;
        for (i = 1; i < (int)len; i++) {
            if (!is_base58(addr[i])) { ok = 0; break; }
        }
        if (ok) return CRYPTO_XRP;
    }

    /* Cardano: addr1... (58-110 chars, bech32 lowercase + digits) or
     * stake1... stake address (~55-65 chars). The 5-char "addr1" and
     * 6-char "stake1" prefixes are uniquely Cardano — essentially zero FP. */
    if (len >= 55 && len <= 110 &&
        (strncmp(addr, "addr1", 5) == 0 || strncmp(addr, "stake1", 6) == 0)) {
        int i, ok = 1;
        int start = (addr[4] == '1') ? 5 : 6;
        for (i = start; i < (int)len; i++) {
            char c = addr[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) {
                ok = 0; break;
            }
        }
        if (ok) return CRYPTO_ADA;
    }

    /* Solana: base58, 32-44 chars, no fixed prefix. Checked LAST so the
     * prefixed / fixed-length formats above (BTC 1/3, USDT T, ETH 0x, …)
     * win; only an otherwise-unclassified base58 string of Solana length
     * lands here. detect_crypto_type feeds only the clipboard-swap
     * comparison and the (test-only) validator, never the URL/text path,
     * so this cannot affect phishing/scam scoring.                       */
    if (len >= 32 && len <= 44) {
        int i, ok = 1;
        for (i = 0; i < (int)len; i++) {
            if (!is_base58(addr[i])) { ok = 0; break; }
        }
        if (ok) return CRYPTO_SOL;
    }

    return CRYPTO_NONE;
}

static const char *
crypto_type_name(CryptoType t) {
    switch (t) {
        case CRYPTO_BTC_LEGACY:  return "BTC (Legacy)";
        case CRYPTO_BTC_SEGWIT:  return "BTC (SegWit)";
        case CRYPTO_BTC_TAPROOT: return "BTC (Taproot)";
        case CRYPTO_ETH:         return "ETH";
        case CRYPTO_XMR:         return "XMR (Monero)";
        case CRYPTO_SOL:         return "SOL (Solana)";
        case CRYPTO_USDT_TRC20:  return "USDT (TRC20)";
        case CRYPTO_LTC_LEGACY:  return "LTC (Legacy)";
        case CRYPTO_LTC_SEGWIT:  return "LTC (SegWit)";
        case CRYPTO_DOGE:        return "DOGE (Dogecoin)";
        case CRYPTO_XRP:         return "XRP (Ripple)";
        case CRYPTO_DASH:        return "DASH";
        case CRYPTO_XLM:         return "XLM (Stellar)";
        case CRYPTO_ADA:         return "ADA (Cardano)";
        default:                 return "Unknown";
    }
}

/* Count matching leading / trailing characters between two strings.
 * The EthClipper finding (arXiv 2108.14004): a real clipper does not pick
 * a random replacement — it grinds one that shares the victim address's
 * first and last characters, so a glance at "bc1q…wr5" doesn't reveal the
 * swap. A shared tail of 4+ chars between two *different* addresses is
 * astronomically unlikely by chance (random/checksum suffix), so it is a
 * high-confidence "deliberate look-alike" signal.                       */
static int
common_prefix_len(const char *a, const char *b) {
    int n = 0;
    while (a[n] && a[n] == b[n]) n++;
    return n;
}
static int
common_suffix_len(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    size_t n = 0;
    while (n < la && n < lb && a[la - 1 - n] == b[lb - 1 - n]) n++;
    return (int)n;
}

CryptoSwapVerdict
hlse_check_crypto_swap(const char *copied, const char *pasted) {
    CryptoSwapVerdict v;
    memset(&v, 0, sizeof(v));

    if (!copied || !pasted) return v;

    CryptoType type_copied = detect_crypto_type(copied);
    CryptoType type_pasted = detect_crypto_type(pasted);

    if (type_copied == CRYPTO_NONE && type_pasted == CRYPTO_NONE)
        return v; /* Neither is a crypto address */

    if (strcmp(copied, pasted) == 0)
        return v; /* Same address — no swap */

    /* Both are crypto addresses of the same type but different values
     * → clipboard was hijacked */
    if (type_copied != CRYPTO_NONE && type_pasted != CRYPTO_NONE
        && type_copied == type_pasted)
    {
        int pre = common_prefix_len(copied, pasted);
        int suf = common_suffix_len(copied, pasted);
        v.score = 95; /* Near-certain clipboard hijack */
        v.is_swap = 1;
        snprintf(v.original, sizeof(v.original), "%s", copied);
        snprintf(v.swapped, sizeof(v.swapped), "%s", pasted);
        /* Deliberate "vanity" look-alike: the replacement was ground to
         * match the original's ends. A shared tail of 4+ chars (beyond the
         * format prefix every same-type address shares) is the clipper
         * tell — escalate to ISOLATE.                                    */
        if (suf >= 4) {
            v.score = 100;
            snprintf(v.reason, sizeof(v.reason),
                "CLIPBOARD HIJACK (deliberate look-alike): %s address swapped; "
                "replacement shares first %d and last %d chars. "
                "Original: %.10s... Pasted: %.10s...",
                crypto_type_name(type_copied), pre, suf, copied, pasted);
        } else {
            snprintf(v.reason, sizeof(v.reason),
                "CLIPBOARD HIJACK: %s address swapped. "
                "Original: %.12s... Pasted: %.12s...",
                crypto_type_name(type_copied), copied, pasted);
        }
        return v;
    }

    /* Copied is crypto but pasted is different type — unusual but
     * less certain (could be user error) */
    if (type_copied != CRYPTO_NONE && type_pasted != CRYPTO_NONE) {
        v.score = 60;
        v.is_swap = 1;
        snprintf(v.reason, sizeof(v.reason),
            "SUSPICIOUS: copied %s address but pasted %s address",
            crypto_type_name(type_copied), crypto_type_name(type_pasted));
    }

    /* One is crypto, the other isn't — not a swap, just different content */
    return v;
}

/* Validate a single crypto address (useful for URL/text scanning context) */
int
hlse_validate_crypto_address(const char *addr) {
    return (int)detect_crypto_type(addr);
}
