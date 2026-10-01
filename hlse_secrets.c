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
 *   - Not thread-safe: hlse_register_custom_secret_pattern() and
 *     hlse_register_custom_brand() (P0-3/P1-6) populate module-level
 *     registries read by hlse_scan_secrets()/hlse_check_email_headers();
 *     register from one thread before scanning starts.
 *
 * Build: gcc -O2 -c hlse_secrets.c -I.
 * Test:  see tests/hlse_secrets_tests.c
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>    /* strncasecmp */
#include <stdarg.h>
#include <ctype.h>

#include "hlse_secrets.h"
#include "hlse_util.h"   /* hlse_crc32, hlse_base62_6 */

/* ═══════════════════════════════════════════════════════════════════════
 * Internal helpers
 * ═══════════════════════════════════════════════════════════════════════ */

/* GitHub's token formats carry a checksum, so their integrity is verifiable
 * WITHOUT contacting GitHub — which suits an offline-by-design scanner. The
 * layout is `prefix_` + 30 chars of entropy + 6 chars of checksum, where the
 * checksum is CRC-32 of the entropy encoded as 6 base62 digits (GitHub
 * Engineering, "Behind GitHub's new authentication token formats", 2021).
 *
 * Returns: 0 = not a fixed-length GitHub-family token (check not applicable),
 *          1 = checksum verifies, 2 = checksum mismatch.
 *
 * This is used ONLY to qualify confidence, never to drop a finding. The
 * encoding is reconstructed from public documentation rather than validated
 * against live credentials, so treating a mismatch as "not a secret" could
 * silently discard a real leaked token — the one failure a secret scanner
 * must not have. A mismatch therefore still reports, just with the caveat
 * that it may be a redacted, illustrative, or hand-typed value. */
static int
github_checksum_state(const char *prefix, const char *suffix, size_t suffix_len)
{
    char want[7];
    if (suffix_len != 36) return 0;
    if (strcmp(prefix, "ghp_") != 0 && strcmp(prefix, "gho_") != 0 &&
        strcmp(prefix, "ghu_") != 0 && strcmp(prefix, "ghs_") != 0 &&
        strcmp(prefix, "ghr_") != 0)
        return 0;
    hlse_base62_6(hlse_crc32((const unsigned char *)suffix, 30), want);
    return (memcmp(want, suffix + 30, 6) == 0) ? 1 : 2;
}

static int check_hex_private_key(const char *text, SecretVerdict *v);
static int check_mnemonic(const char *text, SecretVerdict *v);

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
    /* Descriptions quote bytes from the scanned input (token context,
     * header values); keep terminal-hostile characters out of every
     * downstream print/syslog sink. */
    hlse_sanitize_display(v->findings[v->n_findings].description);
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

/* base64url charset — token formats documented as url-safe base64
 * (RFC 4648 §5: '-'/'_' not '+'/'/'); is_base64 would drop them   */
static int
is_b64url(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '=';
}

/* base64url with the embedded separator dots several vendors use
 * (SendGrid SG.<22>.<43>, MailerSend, Dropbox sl.)               */
static int
is_b64url_dot(char c) {
    return is_b64url(c) || c == '.';
}

static int
is_alnum_plain(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9');
}

/* Case-insensitive substring search (returns pointer to first match in
 * `hay`, or NULL). Needed because real-world credential files use mixed
 * case for the same key (AWS_SECRET_ACCESS_KEY vs aws_secret_access_key). */
static const char *
ci_strstr(const char *hay, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0) return hay;
    for (; *hay; hay++) {
        if (strncasecmp(hay, needle, nlen) == 0) return hay;
    }
    return NULL;
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
static int is_hex_c(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}
static int is_digit_c(char c) {
    return (c >= '0' && c <= '9');
}

/* Bech32 charset (Nostr/lightning-style keys): lowercase alnum minus
 * 1, b, i, o — plus '1' separator already consumed by the prefix. */
static int is_bech32(char c) {
    return (c >= 'a' && c <= 'z' && c != 'b' && c != 'i' && c != 'o')
        || (c >= '0' && c <= '9');
}

/* Letters only — used for tokens whose body is pure alphabetic (e.g. Hugging
 * Face `hf_` + 34 letters), so a 34-char run is far less likely to collide
 * with an underscore/digit-bearing code identifier sharing the prefix. */
static int is_alpha(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* The alnum-dot charsets these helpers served were subsumed by
 * is_b64url_dot — dot-carrying tokens are base64url bodies, so the
 * narrower sets structurally missed '_'/'-' runs.               */

/* otpauth:// URIs carry the 2FA seed in a `secret=` query parameter —
 * the suffix is a URI tail, not a bare token charset.              */
static int is_uri_tail(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == ':' || c == '/' ||
           c == '?' || c == '=' || c == '&' || c == '%' ||
           c == '.' || c == '-' || c == '_' || c == '#' ||
           c == '~' || c == '@';
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
    { "rk_test_",      8,  24, is_alnum_or_dash,   "Stripe Restricted Test Key", 30 },
    { "whsec_",        6,  20, is_alnum_or_dash,   "Stripe Webhook Secret", 85 },
    /* Klaviyo private API key — pk_ + 32 hex. min_suffix=30 keeps
     * Stripe pk_live_/pk_test_ (suffix 'live_'/'test_' + 24 = 29)
     * below the bar, so each Stripe row still wins its own match */
    { "pk_",           3,  30, is_alnum_or_dash,   "Klaviyo Private API Key", 80 },
    /* Square application secret / personal token (sq0csp-/sq0atp-) */
    { "sq0csp-",       7,  40, is_alnum_or_dash,   "Square Application Secret", 85 },
    /* Remaining payment processors — Razorpay (IN's dominant gateway),
     * Mercado Pago (LATAM's dominant), Flutterwave (Africa's dominant),
     * Shippo (shipping API) — each fixed prefix hands over money-moving
     * capability to whoever holds the token                        */
    { "rzp_live_",     9,  14, is_alnum_or_dash,   "Razorpay Live Key",  85 },
    { "rzp_test_",     9,  14, is_alnum_or_dash,   "Razorpay Test Key",  40 },
    { "APP_USR-",      8,  30, is_alnum_or_dash,   "Mercado Pago Access Token", 80 },
    { "FLWSECK-",      8,  30, is_alnum_or_dash,   "Flutterwave Secret Key", 85 },
    { "FLWPUBK-",      9,  30, is_alnum_or_dash,   "Flutterwave Public Key", 40 },
    { "shippo_live_", 12,  40, is_alnum_or_dash,   "Shippo Live API Key", 80 },
    { "shippo_test_", 12,  40, is_alnum_or_dash,   "Shippo Test API Key", 40 },
    /* Heroku legacy API key — HRKU- + UUID-style body; modern keys are
     * UUIDs without the prefix but the HRKU- form is still in the wild */
    { "HRKU-",         5,  30, is_alnum_or_dash,   "Heroku API Key",    80 },
    /* NuGet — `oy2` + 43 base62 chars; short prefix but the long
     * suffix keeps the pattern specific                              */
    { "oy2",           3,  43, is_alnum_or_dash,   "NuGet API Key",     80 },

    /* Slack */
    { "xapp-",        5,  20, is_alnum_or_dash,   "Slack App-level Token", 85 },
    { "xoxe.",         5,  20, is_alnum_or_dash,   "Slack Config/Rotation Token", 85 },
    /* xoxe- single-segment rotation token and xoxa- app token —
     * remaining Slack credential variants                        */
    { "xoxe-",         5,  10, is_alnum_or_dash,   "Slack Rotation Token",  85 },
    { "xoxa-",         5,  10, is_alnum_or_dash,   "Slack App Token",       80 },
    { "xoxo-",         5,  10, is_alnum_or_dash,   "Slack OAuth Token",    85 },
    { "xoxr-",         5,  10, is_alnum_or_dash,   "Slack Refresh Token",  85 },
    { "xoxb-",        5,  10, is_alnum_or_dash,   "Slack Bot Token",       80 },
    { "xoxp-",         5,  10, is_alnum_or_dash,   "Slack User Token",      85 },
    { "xoxs-",         5,  10, is_alnum_or_dash,   "Slack Session Token",   85 },
    /* Slack desktop/client session theft — xoxc- is the client token
     * and xoxd- the 'd' cookie; exfiltrating the pair replays the
     * whole workspace session (browser-independent)             */
    { "xoxc-",         5,  10, is_alnum_or_dash,   "Slack Client Token",   85 },
    { "xoxd-",         5,  20, is_alnum_or_dash,   "Slack Session Cookie", 90 },

    /* Google */
    { "AIza",          4,  35, is_alnum_or_dash,   "Google API Key",        80 },
    /* Google OAuth2 client secret — fixed "GOCSPX-" prefix, ~28-char body.
     * The prefix is unique to Google, so false positives are essentially
     * zero.                                                                */
    { "GOCSPX-",       7,  28, is_alnum_or_dash,   "Google OAuth Client Secret", 90 },

    /* GitLab */
    { "glpat-",        6,  20, is_alnum_or_dash,   "GitLab Personal Access Token", 90 },
    { "gldt-",         5,  20, is_alnum_or_dash,   "GitLab Deploy Token",   80 },
    { "glrt-",         5,  20, is_alnum_or_dash,   "GitLab Runner Token",   80 },
    { "glcbt-",        6,  20, is_alnum_or_dash,   "GitLab CI Build Token", 80 },
    { "glptt-",        6,  20, is_alnum_or_dash,   "GitLab Pipeline Trigger Token", 80 },
    { "glagent-",      8,  20, is_alnum_or_dash,   "GitLab Agent Token",   80 },
    { "glft-",         5,  20, is_alnum_or_dash,   "GitLab Feed Token",    75 },
    { "glimt-",        6,  20, is_alnum_or_dash,   "GitLab Incoming Mail Token", 75 },
    { "gloas-",        6,  20, is_alnum_or_dash,   "GitLab OAuth App Secret", 85 },
    /* glffct- — GitLab feature-flag client token (the remaining
     * real gl* prefix; glit-/glt- are not documented forms)       */
    { "glffct-",       7,  16, is_alnum_or_dash,   "GitLab Feature Flag Client Token", 75 },
    /* SonarQube/SonarCloud token family — sqa_ analysis token,
     * sqp_ project token, squ_ user token (leak = scanner auth)   */
    { "sqa_",          4,  36, is_alnum_or_dash,   "SonarQube Analysis Token", 80 },
    { "sqp_",          4,  36, is_alnum_or_dash,   "SonarQube Project Token",  80 },
    { "squ_",          4,  36, is_alnum_or_dash,   "SonarQube User Token",     80 },
    /* LaunchDarkly client keys — sdk- (server-side SDK key) and
     * mob- (mobile key); public-facing but still auth material    */
    { "sdk-",          4,  40, is_alnum_or_dash,   "LaunchDarkly SDK Key",     70 },
    { "mob-",          4,  40, is_alnum_or_dash,   "LaunchDarkly Mobile Key",  70 },

    /* age encryption secret key — fixed "AGE-SECRET-KEY-1" prefix,
     * bech32-style lowercase body (~58 chars) */
    { "AGE-SECRET-KEY-1", 16, 40, is_alnum_plain,  "Age Secret Key",       90 },
    /* Doppler — dp.st. / dp.pt. (dop_v1_ is DigitalOcean's PAT,
     * kept with its own row later in this table) */
    /* Nostr secret key — bech32 `nsec1` + payload; nsec is the account
     * itself (posting + DM history + zap wallet) */
    { "nsec1",           5,  40, is_bech32,        "Nostr Secret Key",    80 },
    { "dp.st.",          6,  40, is_alnum_or_dash, "Doppler Service Token", 85 },
    { "dp.ct.",          6,  40, is_alnum_or_dash, "Doppler Config Token", 85 },
    /* Bitcoin HD-wallet extended keys — xprv hands over the entire
     * wallet (master private key); xpub exposes every address      */
    { "xprv",          4, 100, is_alnum_plain,     "Bitcoin HD Private Key", 95 },
    { "xpub",          4, 100, is_alnum_plain,     "Bitcoin HD Public Key",  50 },
    /* HD-wallet key variants — segwit (ypub/zpub) and testnet
     * (tpub/tprv/yprv/zprv) extended keys; same wallet exposure
     * as xprv/xpub                                                */
    { "ypub",          4, 100, is_alnum_plain,     "Bitcoin HD Public Key (segwit)", 50 },
    { "zpub",          4, 100, is_alnum_plain,     "Bitcoin HD Public Key (native segwit)", 50 },
    { "tpub",          4, 100, is_alnum_plain,     "Bitcoin HD Public Key (testnet)", 40 },
    { "yprv",          4, 100, is_alnum_plain,     "Bitcoin HD Private Key (segwit)", 95 },
    { "zprv",          4, 100, is_alnum_plain,     "Bitcoin HD Private Key (native segwit)", 95 },
    { "tprv",          4, 100, is_alnum_plain,     "Bitcoin HD Private Key (testnet)", 90 },
    /* Mailgun API key (key- + 32 hex) and Databricks PAT (dapi +
     * 32 hex) — both gate mail/API infrastructure               */
    { "key-",          4,  30, is_hex,             "Mailgun API Key",        80 },
    { "dapi",          4,  30, is_hex,             "Databricks Personal Access Token", 85 },
    /* Foursquare Places API key — 'fsq3' + base64-flavoured token;
     * controls the venue/location-data API surface                  */
    { "fsq3",          4,  24, is_b64url,          "Foursquare API Key",    80 },
    /* PostHog project API key ('phc_' + base64-flavoured) — product-
     * analytics ingest key                                         */
    { "phc_",          4,  30, is_b64url,          "PostHog Project API Key", 80 },
    /* Instagram Graph API token ('IGQWR' + base64-flavoured) and
     * Honeybadger project API key                                  */
    /* IGQVJ is the real Instagram Basic-Display/Graph prefix —
     * the 'IGQWR' row here matched nothing in the wild          */
    { "IGQVJ",         5,  40, is_b64url,          "Instagram Graph Token", 85 },
    { "hbp_",          4,  24, is_b64url,          "Honeybadger API Key",  75 },
    /* HashiCorp Vault tokens: 'hvs.' service token and 'hvb.' batch
     * token — full root/admin capability for the secrets engine    */
    /* HashiCorp tokens are base64url — '-'/'_' bodies, so
     * is_base64 ('+'/'/') structurally missed live keys         */
    { "hvs.",          4,  24, is_b64url,          "HashiCorp Vault Service Token", 95 },
    { "hvb.",          4,  24, is_b64url,          "HashiCorp Vault Batch Token",   90 },
    /* WooCommerce REST consumer key/secret: 'ck_'/'cs_' + 40 hex —
     * full read/write over the store's orders and customer data    */
    { "ck_",           3,  40, is_hex,             "WooCommerce Consumer Key",    80 },
    { "cs_",           3,  40, is_hex,             "WooCommerce Consumer Secret", 80 },
    /* Shopify token family — Admin API access token, custom-app
     * token, shared secret, and client credential (32-hex suffix)  */
    { "shpat_",        6,  30, is_hex,             "Shopify Admin Access Token",   90 },
    { "shppa_",        6,  30, is_hex,             "Shopify App Token",            85 },
    { "shpss_",        6,  30, is_hex,             "Shopify Shared Secret",        80 },
    { "shpca_",        6,  30, is_hex,             "Shopify Client Credential",    80 },
    /* Remaining New Relic key types — NRAI-/NRAK- already covered;
     * NRBR- (browser license), NRRA- (REST admin), NRDR- (legacy
     * insights insert)                                            */
    { "NRBR-",         5,  36, is_alnum_plain,     "New Relic Browser License",   80 },
    { "NRRA-",         5,  36, is_alnum_plain,     "New Relic REST Admin Key",    85 },
    { "NRDR-",         5,  36, is_alnum_plain,     "New Relic Insights Insert Key", 75 },
    /* age encryption secret material — 'AGE-SECRET-KEY-1' + bech32
     * (~59 chars) and 'AGE-PLUGIN-X25519-1' + plugin secrets       */
    { "AGE-SECRET-KEY-", 15, 50, is_bech32,        "age Secret Key",               95 },
    { "AGE-PLUGIN-X25519-1", 19, 30, is_bech32,    "age X25519 Plugin Secret",     85 },
    /* Brevo/Sendinblue SMTP+API key, Dropbox long-form token,
     * JFrog Artifactory identity key, Bitbucket app password —
     * each has a fixed vendor prefix that hands over an account */
    { "xkeysib-",        9,  40, is_alnum_or_dash, "Brevo (Sendinblue) API Key", 80 },
    /* Dropbox sl. lives below with the base64url-dot charset —
     * this copy used the plain alnum-dash set, which missed
     * '_'/'.' bodies and duplicated scoring with the 85 row     */
    { "AKCp",            4,  30, is_alnum_or_dash, "JFrog Artifactory API Key", 80 },
    { "ATCTT",           5,  20, is_alnum_or_dash, "Bitbucket App Password", 80 },
    { "ATBB",            4,  20, is_alnum_or_dash, "Bitbucket App Password", 80 },
    { "glsoat-",       7,  20, is_alnum_or_dash,   "GitLab Self-managed OAuth Token", 80 },

    /* Postman / Docker Hub / Dynatrace — collaboration + registry +
     * observability credentials the earlier table rows lacked */
    { "PMAK-",         5,  40, is_alnum_or_dash,   "Postman API Key",     80 },
    { "dckr_pat_",     9,  20, is_alnum_or_dash,   "Docker Hub Personal Access Token", 80 },
    /* Notion integration token — ntn_ + base62 secret (current
     * format; older `secret_` tokens already match the generic
     * key rules)                                                  */
    { "ntn_",          4,  30, is_alnum_or_dash,   "Notion Integration Token", 80 },
    /* Square application secret — sq0csp- sibling of the access
     * (sq0atp-) and ID-prefixed (sq0idp-) tokens already listed   */
    { "sq0csp-",       7,  30, is_alnum_or_dash,   "Square Application Secret", 80 },
    /* Dynatrace ingest token — dt0s01.; the dt0c01./dt0s16.
     * API-token rows below carry the b64url-dot charset          */
    { "dt0s01.",       7,  30, is_b64url_dot,     "Dynatrace Ingest Token", 80 },

    /* npm */
    { "npm_",          4,  36, is_alnum_or_dash,   "npm Access Token",      85 },

    /* Mapbox tokens are `pk.eyJ`/`sk.eyJ` + base64url JWT segments
     * (the `eyJ` is the base64 `{"` opener). Grafana service accounts
     * `glsa_`, Supabase service-role `sbp_` (bypasses all RLS — full
     * DB access), Render `rnd_`, Okta OAuth `xoa.` — each previously
     * scored OK on a live credential                            */
    { "sk.eyJ",        6,  30, is_b64url_dot,      "Mapbox Secret Token",   85 },
    { "pk.eyJ",        6,  30, is_b64url_dot,      "Mapbox Public Token",   45 },
    { "xoa.",          4,  30, is_alnum_or_dash,   "Okta OAuth Token",      80 },
    /* Okta legacy API token — 'SSWS <43>' is the auth-scheme
     * header form; a leaked one is full-tenant admin            */
    { "SSWS ",         5,  40, is_alnum_or_dash,   "Okta SSWS API Token",  90 },

    /* OpenAI / Anthropic (distinctive dash-prefixed LLM provider keys) */
    { "sk-proj-",      8,  20, is_alnum_or_dash,   "OpenAI Project Key",    90 },
    { "sk-svcacct-",  11,  20, is_alnum_or_dash,   "OpenAI Service Account Key", 90 },
    { "sk-admin-",     9,  20, is_alnum_or_dash,   "OpenAI Admin Key",      90 },
    { "sk-ant-",       7,  20, is_alnum_or_dash,   "Anthropic API Key",     90 },
    /* OpenRouter API key — 'sk-or-v1-' + 64-hex suffix              */
    { "sk-or-v1-",     9,  60, is_hex,             "OpenRouter API Key",    85 },
    /* MailerSend API token — 'mlsn.' + long alnum/dot suffix        */
    { "mlsn.",         5,  32, is_b64url_dot,      "MailerSend API Key",    80 },
    /* Dropbox OAuth access token — 'sl.' + ~140-char base64url tail */
    { "sl.",           3,  60, is_b64url_dot,      "Dropbox Access Token", 85 },
    /* Newer LLM providers with distinctive prefixes (~zero FP):
     * Groq gsk_<52>, Perplexity pplx-<48>, xAI/Grok xai-<80>, Replicate
     * r8_<36>, Hugging Face org api_org_<34>.                          */
    { "gsk_",          4,  20, is_alnum_or_dash,   "Groq API Key",          85 },
    { "pplx-",         5,  20, is_alnum_or_dash,   "Perplexity API Key",    85 },
    { "xai-",          4,  20, is_alnum_or_dash,   "xAI (Grok) API Key",    85 },
    { "r8_",           3,  30, is_alnum_or_dash,   "Replicate API Token",   85 },
    /* CI/CD + experiment-tracking keys */
    { "bkua_",         5,  40, is_alnum_or_dash,   "Buildkite User API Token", 85 },
    { "wandb_v1_",     9,  30, is_alnum_or_dash,   "Weights & Biases API Key", 80 },
    /* OpenShift OAuth access token — sha256~<43> */
    { "sha256~",       7,  40, is_alnum_or_dash,   "OpenShift OAuth Token", 80 },
    /* Vector DB / data-platform + payments keys */
    { "pcsk_",         5,  50, is_alnum_or_dash,   "Pinecone API Key",      85 },
    { "xau_",          4,  40, is_alnum_or_dash,   "Xata API Key",          80 },
    { "esecret_",      8,  30, is_alnum_or_dash,   "Anyscale Credential",   80 },
    { "xaat-",         5,  30, is_alnum_or_dash,   "Axiom API Token",       80 },
    { "AQVN",          4,  36, is_alnum_or_dash,   "Yandex OAuth Token",    80 },
    { "pdl_live_",     9,  30, is_alnum_or_dash,   "Paddle API Key (live)", 85 },
    { "pdl_sbox_",     9,  30, is_alnum_or_dash,   "Paddle API Key (sandbox)", 80 },
    /* Infisical service token — st.<uuid>.<key> (b64url-dot tail) */
    { "st.",           3,  60, is_b64url_dot,      "Infisical Service Token", 85 },
    /* Prismic permanent access token — MC5.<b64url> */
    { "MC5.",          4,  30, is_b64url_dot,      "Prismic Access Token",  80 },
    /* Fly.io token — literal 'FlyV1 fm2_' header form */
    { "FlyV1 fm2_",   10,  40, is_b64url,          "Fly.io Deploy Token",   80 },
    /* Checkly / Adafruit IO / MotherDuck / DeepSource */
    { "cu_",           3,  36, is_hex_c,           "Checkly API Key",       80 },
    { "aio_",          4,  30, is_alnum_or_dash,   "Adafruit IO Key",       80 },
    { "motherduck_",  11,  40, is_alnum_or_dash,   "MotherDuck Token",      80 },
    { "dsp_",          4,  36, is_alnum_or_dash,   "DeepSource API Token",  80 },
    { "api_org_",      8,  30, is_alnum_or_dash,   "Hugging Face Org Token", 80 },
    /* Dynatrace API tokens — 'dt0c01.' (v1 public token) and
     * 'dt0s16.' carry a '<id24|16>.<secret64>' dotted tail         */
    { "dt0c01.",       7,  80, is_b64url_dot,      "Dynatrace API Token",  85 },
    { "dt0s16.",       7,  80, is_b64url_dot,      "Dynatrace API Token",  85 },
    /* Samsara API token — 'sams_' + ~40-char tail                 */
    { "sams_",         5,  36, is_alnum_or_dash,   "Samsara API Token",    85 },
    /* Gitea access token — 'gitea_' + 40-hex                      */
    { "gitea_",        6,  36, is_hex,             "Gitea Access Token",   85 },

    /* Alibaba Cloud AccessKey ID (LTAI + ~20) and Tencent Cloud
     * SecretId (AKID + 32 alnum) — the two largest Chinese cloud
     * credential formats; pairs grant the same blast radius as AKIA */
    { "LTAI",          4,  20, is_alnum_or_dash,   "Alibaba Cloud AccessKey ID", 85 },
    { "AKID",          4,  30, is_alnum_or_dash,   "Tencent Cloud SecretId", 85 },

    /* Shopify 32-hex tokens live above at min_suffix 30 — the
     * first matching row wins, so a second shp* block here was
     * unreachable dead weight (removed).                        */
    { "ls__",          4,  30, is_alnum_or_dash,   "LangSmith Legacy API Key", 80 },

    /* Hugging Face — hf_ + 34 alphanumeric (real tokens carry digits;
     * is_alpha silently dropped any digit-bearing token)           */
    { "hf_",           3,  34, is_alnum_or_dash,   "Hugging Face Token",    80 },

    /* PyPI (fixed 20-char marker prefix — essentially zero false positives) */
    { "pypi-AgEIcHlwaS5vcmc", 20, 20, is_alnum_or_dash, "PyPI Upload Token", 90 },

    /* Square */
    { "sq0atp-",       7,  22, is_alnum_or_dash,   "Square Access Token",   85 },
    { "sq0idp-",       7,  22, is_alnum_or_dash,   "Square OAuth Token",    85 },

    /* Adyen API keys start AQEx/AQEy (EU payment processor) */
    { "AQEx",          4,  38, is_alnum_or_dash,   "Adyen API Key",        85 },
    { "AQEy",          4,  38, is_alnum_or_dash,   "Adyen API Key",        85 },
    /* Mollie live/test API keys — bare live_/test_ prefixes */
    { "live_",         5,  30, is_alnum_or_dash,   "Mollie Live Key",      75 },
    { "test_",         5,  30, is_alnum_or_dash,   "Mollie Test Key",      40 },

    /* Braintree / PayPal Checkout access tokens carry literal '$'
     * separators: access_token$production$<16>$<64>               */
    { "access_token$production$", 24, 16, is_alnum_or_dash,
                                        "Braintree Production Token", 85 },
    { "access_token$sandbox$", 21, 16, is_alnum_or_dash,
                                        "Braintree Sandbox Token",   40 },

    /* Doppler */
    { "dp.pt.",        6,  43, is_alnum_or_dash,   "Doppler Personal Token", 85 },

    /* Grafana */
    { "glsa_",         5,  32, is_alnum_or_dash,   "Grafana Service Account Token", 85 },

    /* Linear */
    { "lin_api_",      8,  40, is_alnum_or_dash,   "Linear API Key",        85 },
    { "lin_oauth_",   10,  30, is_alnum_or_dash,   "Linear OAuth Token",    85 },
    { "re_",           3,  32, is_alnum_or_dash,   "Resend API Key",        80 },
    { "xaai-",         5,  30, is_alnum_or_dash,   "Axiom API Token",       80 },
    { "waka_",         5,  32, is_alnum_or_dash,   "WakaTime API Key",      80 },
    { "pd_oauth_",     9,  20, is_alnum_or_dash,   "PagerDuty OAuth Token", 80 },
    { "tvly-",         5,  30, is_alnum_or_dash,   "Tavily API Key",        80 },

    /* New Relic — NRAK- admin key exists below at the 2026 batch;
     * NRAI- (Insights insert) and NRAL- (license, 40-hex) complete
     * the family                                                  */
    { "NRAI-",         5,  27, is_alnum_or_dash,   "New Relic Insights Key", 85 },
    { "NRAL-",         5,  38, is_hex_c,           "New Relic License Key",  85 },
    { "NRAK-",         5,  27, is_alnum_or_dash,   "New Relic API Key",     85 },

    /* Databricks */
    { "dapi",          4,  32, is_hex,             "Databricks Access Token", 80 },

    /* HashiCorp Vault service token v2 (hvs. prefix, long body) */
    { "hvs.",           4, 50, is_alnum_or_dash, "HashiCorp Vault Token",     80 },

    /* Netlify Personal Access Token */
    { "nfp_",           4, 32, is_alnum_or_dash, "Netlify Personal Access Token", 85 },

    /* Google OAuth access token (ya29. prefix — leaked in requests,
     * logs, and proto payloads; ~100-char bearer token) */
    { "ya29.",         5,  40, is_alnum_or_dash, "Google OAuth Access Token", 85 },

    /* Tailscale auth/client/api keys (tskey-auth-/tskey-client-/…) */
    { "tskey-",        6,  16, is_alnum_or_dash, "Tailscale Auth Key", 80 },

    /* Sentry org auth token (sntrys_ + base64url JSON payload);
     * sntryu_ is the user-auth-token sibling (64-hex body).     */
    { "sntrys_",       7,  30, is_alnum_or_dash, "Sentry Auth Token", 85 },
    { "sntryu_",       7,  60, is_hex,           "Sentry User Auth Token", 85 },

    /* Grafana Cloud access-policy token (glc_) — distinct from glsa_
     * service-account keys already covered */
    { "glc_",          4,  30, is_alnum_or_dash, "Grafana Cloud Token", 80 },

    /* Fly.io API token (fo1_) */
    { "fo1_",          4,  30, is_alnum_or_dash, "Fly.io API Token",  80 },
    /* Render (cloud PaaS) */
    { "rnd_",            4, 36, is_alnum_or_dash,   "Render API Key",        80 },

    /* Terraform Cloud / Atlas (atlasv1.) */
    { "atlasv1.",      8,  30, is_alnum_or_dash, "Terraform Cloud Token", 80 },

    /* IaC / CI/CD platform tokens */
    { "pul-",          4,  40, is_alnum_or_dash, "Pulumi Access Token",  85 },
    { "ccipat_",       7,  40, is_hex_c,         "CircleCI Personal API Token", 80 },
    { "pscale_tkn_",  11,  30, is_alnum_or_dash, "PlanetScale Token",    85 },
    { "pscale_pw_",   11,  30, is_alnum_or_dash, "PlanetScale Password", 85 },
    { "pscale_oauth_",13,  30, is_alnum_or_dash, "PlanetScale OAuth Token", 85 },
    /* Aiven access token (AVNS_ + base32-ish body) */
    { "AVNS_",         5,  24, is_alnum_or_dash, "Aiven Access Token",   85 },

    /* Webhook URLs (URL-anchored — essentially zero false positives) */
    { "hooks.slack.com/services/T", 27, 5, is_alnum_or_dash,
                                            "Slack Webhook URL",     70 },
    { "discord.com/api/webhooks/",     25, 17, is_digit_c,
                                            "Discord Webhook URL",   75 },
    { "discordapp.com/api/webhooks/",  28, 17, is_digit_c,
                                            "Discord Webhook URL",   75 },

    /* Fly.io — distinctive 5-char prefix before long base64 body */
    { "FlyV1",           5, 30, is_alnum_or_dash,   "Fly.io API Token",      85 },

    /* CircleCI personal API token */
    { "CCIPAT_",         7, 32, is_alnum_or_dash,   "CircleCI API Token",    85 },

    /* Contentful personal access token */
    { "CFPAT-",          6, 43, is_alnum_or_dash,   "Contentful PAT",        85 },

    /* SendGrid API Key — SG. + 22+ base64url chars (format: SG.<22>.<43>) */
    { "SG.",             3, 22, is_b64url_dot,     "SendGrid API Key",      85 },

    /* HashiCorp Vault batch and recovery tokens */
    { "hvb.",            4, 50, is_alnum_or_dash,   "HashiCorp Vault Batch Token",    80 },
    { "hvr.",            4, 50, is_alnum_or_dash,   "HashiCorp Vault Recovery Token", 80 },

    /* Vercel deploy hook / automation token */
    { "vercel_token_",  13, 20, is_alnum_or_dash,   "Vercel Token",          80 },

    /* DigitalOcean Personal Access Token (dop_v1_ — the earlier
     * 'Doppler Service Token' row was a mislabel of this format)  */
    { "dop_v1_",         7, 64, is_alnum_or_dash, "DigitalOcean PAT",        85 },

    /* Atlassian / Jira / Confluence API token (fixed prefix added in 2024) */
    { "ATATT",            5, 32, is_alnum_or_dash, "Atlassian API Token",     85 },

    /* 1Password service account token */
    { "ops_v",            5, 20, is_alnum_or_dash, "1Password Service Account Token", 85 },

    /* Discord MFA token (mfa. prefix + ~84-char session secret) */
    { "mfa.",            4, 30, is_alnum_or_dash, "Discord MFA Token",       85 },

    /* Twilio Account SID / API Key — AC/SK + exactly 32 lowercase hex.
     * Hex-only suffix keeps false positives low (short 2-char prefix). */
    { "AC",              2, 32, is_hex_c,          "Twilio Account SID",     70 },
    { "SK",              2, 32, is_hex_c,          "Twilio API Key",         70 },

    /* ── 2026 formats (GitHub secret-scanning Mar-2026 detector batch) ──
     * All have unique, vendor-reserved prefixes, so false positives are
     * essentially zero. */

    /* Supabase — personal access token (sbp_) and the newer secret API key
     * (sb_secret_). The publishable key (sb_publishable_) is client-side by
     * design and intentionally omitted to avoid flagging non-secrets. */
    { "sbp_",           4, 40, is_alnum_or_dash, "Supabase Personal Access Token", 85 },
    /* glsa_/rnd_ sibling rows exist earlier in this table         */
    { "sb_secret_",    10, 20, is_alnum_or_dash, "Supabase Secret Key",           90 },

    /* Figma personal access token (figd_) */
    { "figd_",          5, 40, is_alnum_or_dash, "Figma Personal Access Token",   85 },

    /* PostHog personal API key (phx_). The project key (phc_) is embedded in
     * client code on purpose, so it is intentionally omitted. */
    { "phx_",           4, 40, is_alnum_or_dash, "PostHog Personal API Key",      80 },

    /* LangSmith / LangChain — personal token (lsv2_pt_) and service key
     * (lsv2_sk_). Body carries an embedded '_', which is_alnum_or_dash
     * accepts, so the full token validates. */
    { "lsv2_pt_",       8, 30, is_alnum_or_dash, "LangSmith Personal Token",      85 },
    { "lsv2_sk_",       8, 30, is_alnum_or_dash, "LangSmith Service Key",         90 },

    /* Notion integration token (ntn_) — full workspace access. */
    { "ntn_",           4, 40, is_alnum_or_dash, "Notion Integration Token",      85 },

    /* Meta/Facebook long-lived tokens: EAA + variant letter + long
     * base62ish tail (EAAB/EAAI/EAAA/EAAC…). Grants account/page
     * posting and read access. */
    { "EAA",            3, 28, is_alnum_or_dash, "Meta/Facebook Access Token",    80 },

    /* TOTP/2FA seed URIs (otpauth://totp/...?secret=BASE32) — the URI
     * itself is the shared secret for every future OTP. */
    { "otpauth://",    10, 14, is_uri_tail,      "TOTP/2FA Seed URI",             85 },

    /* Dev-tooling / data-platform keys: RubyGems 'rubygems_' + 48 hex,
     * NVIDIA NGC 'nvapi-', Prefect 'pnu_', Apify 'apify_api_',
     * Pulumi 'pul-' + 40-hex */
    { "rubygems_",     9, 40, is_hex,            "RubyGems API Key",              85 },
    { "nvapi-",        6, 36, is_alnum_or_dash,  "NVIDIA NGC API Key",            80 },
    { "pnu_",          4, 30, is_alnum_or_dash,  "Prefect Cloud API Key",         80 },
    { "apify_api_",   10, 30, is_alnum_or_dash,  "Apify API Token",               80 },
    { "pul-",          4, 28, is_hex,            "Pulumi Access Token",           80 },

    /* HubSpot private-app PATs — 'pat-na1-'/'pat-eu1-' + UUID tail;
     * Covalent 'cqt_'/'ckey_' blockchain-data keys */
    { "pat-na",        6, 36, is_alnum_or_dash,  "HubSpot Private App Token",     80 },
    { "pat-eu",        6, 36, is_alnum_or_dash,  "HubSpot Private App Token (EU)", 80 },
    { "cqt_",          4, 30, is_alnum_or_dash,  "Covalent API Key",              80 },
    { "ckey_",         5, 30, is_alnum_or_dash,  "Covalent Legacy API Key",       80 },

    /* AWS STS session tokens carry fixed STS prefixes
     * (FQoG/FwoG/AQoD + 'YXdz'); Amazon LWA 'Atza|'; Webex bots use
     * the base64 'ciscospark://' header tag */
    { "FQoGZXIvYXdz", 12, 30, is_base64,         "AWS STS Session Token",         80 },
    { "FwoGZXIvYXdz", 12, 30, is_base64,         "AWS STS Session Token",         80 },
    { "AQoDYXdz",      8, 30, is_base64,         "AWS STS Session Token",         80 },
    { "Atza|",         5, 30, is_base64,         "Amazon LWA Access Token",       80 },
    { "Y2lzY29zcGFyazovL", 17, 24, is_base64,    "Webex/Cisco Spark Bot Token",   80 },

    /* Generic 'sk-' + 32 (DeepSeek / legacy OpenAI-class) — a
     * generic-looking prefix gated by a long tail; Braintree tokens
     * carry 'access_token$<env>$' — the '$' breaks the tail charset,
     * so the env-qualified prefixes gate instead. (Mailgun 'key-' is
     * covered above with a hex gate — documented keys are 32-hex.) */
    { "access_token$production$", 24, 12, is_alnum_or_dash, "Braintree Access Token", 80 },
    { "access_token$sandbox$", 21, 12, is_alnum_or_dash, "Braintree Sandbox Token", 70 },
    { "sk-",           3, 32, is_alnum_or_dash,  "Generic sk- Secret Key",        80 },

    /* More platform keys: Segment 'sgp_', Resend 're_', dbt Cloud
     * 'dbtc.', Trigger.dev env-scoped 'tr_dev_/tr_stg_/tr_prod_',
     * Hex.pm 'hex_', Akamai EdgeGrid 'akab-'                     */
    { "sgp_",          4, 30, is_alnum_or_dash,  "Segment API Key",               80 },
    { "re_",           3, 30, is_alnum_or_dash,  "Resend API Key",                80 },
    { "dbtc.",         5, 30, is_b64url,         "dbt Cloud Service Token",       80 },
    { "tr_dev_",       7, 20, is_alnum_or_dash,  "Trigger.dev API Key (dev)",     70 },
    { "tr_stg_",       7, 20, is_alnum_or_dash,  "Trigger.dev API Key (staging)", 70 },
    { "tr_prod_",      8, 20, is_alnum_or_dash,  "Trigger.dev API Key (prod)",    80 },
    { "hex_",          4, 24, is_alnum_or_dash,  "Hex.pm API Key",                80 },
    { "akab-",         5, 36, is_b64url,         "Akamai EdgeGrid Token",         80 },

    /* PubNub keyset — pub-c-/sub-c- publish+subscribe keys and the
     * sec-c- secret key (low scores for the client-embedded pair)  */
    { "pub-c-",        6, 30, is_alnum_or_dash,  "PubNub Publish Key",            50 },
    { "sub-c-",        6, 30, is_alnum_or_dash,  "PubNub Subscribe Key",          50 },
    { "sec-c-",        6, 30, is_alnum_or_dash,  "PubNub Secret Key",             85 },

    /* Vault 'hvl.' login token (hvs./hvb./hvr. already covered);
     * Honeycomb ingest 'hcaik_' and config 'hcxik_'/'hcxmk_' keys  */
    { "hvl.",          4, 24, is_b64url,         "HashiCorp Vault Login Token",   80 },
    { "hcaik_",        6, 28, is_alnum_or_dash,  "Honeycomb Ingest API Key",      80 },
    { "hcxik_",        6, 28, is_alnum_or_dash,  "Honeycomb Config API Key",      80 },
    { "hcxmk_",        6, 28, is_alnum_or_dash,  "Honeycomb Config API Key",      80 },

    { NULL, 0, 0, NULL, NULL, 0 }
};

/* ── Custom secret patterns (roadmap P0-3) ──────────────────────────────
 * Runtime-registered patterns, checked by hlse_scan_secrets() using the
 * same match + placeholder-suppression logic as the built-in table above.
 * Fixed-size, own storage (not `const char *`) since prefix/label come from
 * caller-owned or parsed-file buffers that may not outlive the call. */
typedef struct {
    char prefix[32];
    int  prefix_len;
    int  min_suffix;
    HlseCharset charset;
    char label[64];
    int  score;
} CustomSecretPattern;

static CustomSecretPattern g_custom_patterns[HLSE_CUSTOM_SECRET_MAX];
static int                 g_custom_pattern_n = 0;

static int
charset_char_ok(HlseCharset cs, char c) {
    switch (cs) {
        case HLSE_CHARSET_ALNUM:      return is_alnum_plain(c);
        case HLSE_CHARSET_ALNUM_DASH: return is_alnum_or_dash(c);
        case HLSE_CHARSET_HEX:        return is_hex(c);
        case HLSE_CHARSET_ALPHA:      return is_alpha(c);
        case HLSE_CHARSET_DIGIT:      return is_digit_c(c);
        default:                      return 0;
    }
}

int
hlse_register_custom_secret_pattern(const char *prefix, int min_suffix,
                                    HlseCharset charset,
                                    const char *label, int score) {
    CustomSecretPattern *cp;
    size_t plen;
    if (!prefix || !prefix[0] || min_suffix <= 0 || !label || !label[0])
        return 0;
    if (g_custom_pattern_n >= HLSE_CUSTOM_SECRET_MAX) return 0;
    plen = strlen(prefix);
    if (plen >= sizeof(cp->prefix)) return 0;
    cp = &g_custom_patterns[g_custom_pattern_n];
    snprintf(cp->prefix, sizeof(cp->prefix), "%s", prefix);
    cp->prefix_len = (int)plen;
    cp->min_suffix = min_suffix;
    cp->charset = charset;
    snprintf(cp->label, sizeof(cp->label), "%s", label);
    cp->score = (score < 0) ? 0 : (score > 100 ? 100 : score);
    g_custom_pattern_n++;
    return 1;
}

void
hlse_clear_custom_secret_patterns(void) {
    g_custom_pattern_n = 0;
}

int
hlse_custom_secret_pattern_count(void) {
    return g_custom_pattern_n;
}

/* ── Custom brands / organization impersonation targets (roadmap P1-6) ──── */
typedef struct {
    char name[64];
    char owned_domains[HLSE_CUSTOM_BRAND_DOMAINS][128];
    int  n_domains;
} CustomBrand;

static CustomBrand g_custom_brands[HLSE_CUSTOM_BRAND_MAX];
static int         g_custom_brand_n = 0;

static void
lowercase_copy(char *dst, size_t dstcap, const char *src) {
    size_t i;
    for (i = 0; src[i] && i + 1 < dstcap; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

int
hlse_register_custom_brand(const char *name, const char *owned_domains_csv) {
    CustomBrand *b;
    const char *p;
    if (!name || !name[0] || strlen(name) >= sizeof(b->name)) return 0;
    if (g_custom_brand_n >= HLSE_CUSTOM_BRAND_MAX) return 0;
    b = &g_custom_brands[g_custom_brand_n];
    lowercase_copy(b->name, sizeof(b->name), name);
    b->n_domains = 0;
    p = owned_domains_csv;
    while (p && *p && b->n_domains < HLSE_CUSTOM_BRAND_DOMAINS) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        while (len > 0 && (p[0] == ' ')) { p++; len--; } /* trim leading ws */
        while (len > 0 && p[len - 1] == ' ') len--;      /* trim trailing ws */
        if (len > 0 && len < sizeof(b->owned_domains[0])) {
            char tmp[128];
            memcpy(tmp, p, len);
            tmp[len] = '\0';
            lowercase_copy(b->owned_domains[b->n_domains], sizeof(b->owned_domains[0]), tmp);
            b->n_domains++;
        }
        p = comma ? comma + 1 : NULL;
    }
    if (b->n_domains == 0) return 0; /* need at least one owned domain */
    g_custom_brand_n++;
    return 1;
}

void
hlse_clear_custom_brands(void) {
    g_custom_brand_n = 0;
}

int
hlse_custom_brand_count(void) {
    return g_custom_brand_n;
}

static int
custom_brand_owns_domain(const CustomBrand *b, const char *domain) {
    int i;
    if (!domain) return 0;
    for (i = 0; i < b->n_domains; i++)
        if (strcmp(b->owned_domains[i], domain) == 0) return 1;
    return 0;
}

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
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN PKCS8 PRIVATE KEY-----",
        /* Tectia/SSH2 encrypted private key (legacy commercial
         * ssh.com format still produced by some tooling)          */
        "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----",
        /* PEM-wrapped PKCS#12 bundle — carries a private key +
         * certificate chain                                       */
        "-----BEGIN PKCS12-----",
        /* PuTTY .ppk private key files — the ppk header line is
         * the key material marker itself                          */
        "PuTTY-User-Key-File-2:",
        "PuTTY-User-Key-File-3:",
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
        "DIGITALOCEAN_TOKEN=", "DO_API_TOKEN=",
        "HEROKU_API_KEY=", "LINODE_TOKEN=",
        "VULTR_API_KEY=", "HETZNER_API_KEY=",
        "NETLIFY_AUTH_TOKEN=", "VERCEL_TOKEN=",
        "CIRCLE_TOKEN=", "SNYK_TOKEN=",
        /* CDN and edge computing */
        "FASTLY_API_KEY=", "CLOUDFRONT_KEY=",
        "BUNNYCDN_API_KEY=",
        /* Connection strings that embed credentials */
        "DATABASE_URL=", "MONGODB_URI=", "MONGO_URI=", "MONGO_URL=",
        "REDIS_URL=", "REDIS_URI=",
        "MYSQL_URL=", "MYSQL_URI=", "POSTGRES_URL=", "POSTGRES_URI=",
        "POSTGRESQL_URL=", "MARIADB_URL=", "COCKROACHDB_URL=",
        "ELASTICSEARCH_URL=", "CASSANDRA_URL=",
        /* Generic secrets commonly leaked in .env */
        "JWT_SECRET=", "JWT_SECRET_KEY=", "APP_SECRET=",
        "SECRET_KEY_BASE=", "APP_KEY=",
        "ENCRYPTION_KEY=", "MASTER_KEY=", "SIGNING_SECRET=",
        /* IaC / cloud provisioning */
        "TF_VAR_", "PULUMI_ACCESS_TOKEN=", "PULUMI_CONFIG_PASSPHRASE=",
        "ARM_CLIENT_SECRET=", "ARM_SUBSCRIPTION_ID=",
        "GOOGLE_CREDENTIALS=", "GOOGLE_APPLICATION_CREDENTIALS=",
        "TF_TOKEN_app_terraform_io=",
        /* HashiCorp secrets management / orchestration */
        "VAULT_TOKEN=", "CONSUL_HTTP_TOKEN=", "NOMAD_TOKEN=",
        "BOUNDARY_TOKEN=",
        /* GitHub Actions secrets in plaintext */
        "ACTIONS_RUNTIME_TOKEN=", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=",
        /* Supabase / PlanetScale / Neon */
        "SUPABASE_SERVICE_ROLE_KEY=", "SUPABASE_ANON_KEY=",
        "SUPABASE_JWT_SECRET=",
        "DATABASE_PASSWORD=", "NEON_DATABASE_URL=",
        /* AI / ML providers */
        "TOGETHER_API_KEY=", "COHERE_API_KEY=", "MISTRAL_API_KEY=",
        "REPLICATE_API_TOKEN=", "HUGGINGFACE_API_KEY=",
        "STABILITY_API_KEY=", "ELEVENLABS_API_KEY=",
        "GROQ_API_KEY=", "PERPLEXITY_API_KEY=",
        "DEEPSEEK_API_KEY=", "XAI_API_KEY=",
        "FIREWORKS_API_KEY=", "ANYSCALE_API_KEY=",
        "GEMINI_API_KEY=", "GOOGLE_GEMINI_API_KEY=",
        "OPENROUTER_API_KEY=", "VERTEX_AI_KEY=",
        /* Observability / APM */
        "DATADOG_API_KEY=", "DATADOG_APP_KEY=",
        "SENTRY_DSN=", "SENTRY_AUTH_TOKEN=",
        "HONEYCOMB_API_KEY=", "NEWRELIC_LICENSE_KEY=",
        "PAGERDUTY_API_KEY=", "PAGERDUTY_TOKEN=",
        "OPSGENIE_API_KEY=", "GRAFANA_API_KEY=",
        /* Payment processors */
        "PAYPAL_CLIENT_SECRET=", "PAYPAL_CLIENT_ID=",
        "SQUARE_ACCESS_TOKEN=", "SQUARE_APPLICATION_ID=",
        "BRAINTREE_PUBLIC_KEY=", "BRAINTREE_PRIVATE_KEY=",
        "ADYEN_API_KEY=", "ADYEN_CLIENT_KEY=",
        "RAZORPAY_KEY_SECRET=", "RAZORPAY_KEY_ID=",
        "KLARNA_API_KEY=", "MOLLIE_API_KEY=",
        /* Azure storage and cognitive services */
        "AZURE_STORAGE_CONNECTION_STRING=", "AZURE_STORAGE_ACCOUNT_KEY=",
        "AZURE_COGNITIVE_KEY=", "AZURE_OPENAI_API_KEY=",
        "AZURE_OPENAI_KEY=",
        /* Google / GCP keys not yet covered */
        "GOOGLE_API_KEY=", "GCP_API_KEY=", "FIREBASE_API_KEY=",
        "GOOGLE_MAPS_API_KEY=", "GOOGLE_CLOUD_API_KEY=",
        /* Cloud storage */
        "S3_ACCESS_KEY=", "S3_SECRET_KEY=", "S3_SECRET_ACCESS_KEY=",
        "STORAGE_ACCESS_KEY=", "STORAGE_SECRET_KEY=",
        /* Collaboration / productivity APIs */
        "NOTION_TOKEN=", "NOTION_SECRET=",
        "AIRTABLE_API_KEY=", "AIRTABLE_PAT=",
        "JIRA_API_TOKEN=", "JIRA_CLOUD_TOKEN=",
        "ZENDESK_API_TOKEN=",
        "INTERCOM_ACCESS_TOKEN=",
        "HUBSPOT_API_KEY=", "SALESFORCE_ACCESS_TOKEN=",
        /* Geo / mapping */
        "MAPBOX_ACCESS_TOKEN=", "MAPBOX_TOKEN=",
        "HERE_API_KEY=", "TOMTOM_API_KEY=",
        /* Communication */
        "DISCORD_BOT_TOKEN=", "DISCORD_TOKEN=", "TELEGRAM_BOT_TOKEN=",
        "MAILGUN_API_KEY=", "POSTMARK_API_TOKEN=",
        "TWILIO_API_KEY=", "VONAGE_API_SECRET=",
        /* Testing / CI / build tools */
        "CYPRESS_RECORD_KEY=", "TURBO_TOKEN=", "NX_CLOUD_AUTH_TOKEN=",
        "SONAR_TOKEN=", "SONARQUBE_TOKEN=", "EXPO_TOKEN=", "EAS_BUILD_PROFILE=",
        /* LLMOps / AI observability */
        "LANGCHAIN_API_KEY=", "LANGFUSE_SECRET_KEY=", "LANGFUSE_PUBLIC_KEY=",
        "LANGSMITH_API_KEY=", "TRACELOOP_API_KEY=",
        /* Fly.io and other PaaS via env var */
        "FLY_API_TOKEN=", "RAILWAY_TOKEN=",
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

    /* 2. Examine a SHORT window of context immediately before the match —
     *    only the assignment prefix / variable name (e.g. "example_key =",
     *    "test_token:", "# sample:"). The window is deliberately small (32
     *    chars): a marker word must abut the secret to suppress it. A larger
     *    window caused real keys to be silently dropped whenever unrelated
     *    prose nearby contained "example"/"sample" (e.g. "Example config for
     *    production: AKIA<real key>"). The repetitive-char markers
     *    (xxxxxxxx/XXXXXXXX) are intentionally excluded here — a run of x's in
     *    context is not an "example" signal; an x-filled *token* is already
     *    caught by checks 1 and 3.                                          */
    {
        size_t before = (size_t)(match - line_start);
        size_t take = before < 32 ? before : 32;
        const char *ctx = match - take;
        wlen = take;
        if (wlen >= sizeof(window)) wlen = sizeof(window) - 1;
        memcpy(window, ctx, wlen);
        window[wlen] = '\0';
        for (i = 0; MARKERS[i]; i++) {
            if (strcmp(MARKERS[i], "xxxxxxxx") == 0 ||
                strcmp(MARKERS[i], "XXXXXXXX") == 0)
                continue;  /* not a context indicator */
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

/* Generic key=value / key: value secret assignments.
 * check_env_passwords covers literal `KEY=` constants; this covers the
 * freeform forms real config files actually use — `password = "x"`,
 * `db_pass: hunter2`, `api-key: abc…` — lowercase keys, spaces around
 * the separator, quoted or bare values. Literature on secret leakage
 * (GitGuardian, trufflehog rulesets) treats these generic assignments
 * as the single largest missed class after prefixed tokens.          */
static int
check_kv_assignment(const char *text, SecretVerdict *v) {
    static const char *const KEYS[] = {
        "password", "passwd", "passphrase", "db_pass", "db_password",
        "api_key", "apikey", "api-key", "api_secret", "secret",
        "secret_key", "access_key", "secret_access_key",
        "auth_token", "access_token", "refresh_token", "id_token",
        "client_secret", "private_key", "encryption_key",
        "master_key", "signing_key", "smtp_pass", "smtp_password",
        "ftp_password", "ssh_pass", "ssh_password", "token",
        /* HTTP header forms */
        "authorization", "x-api-key", "x-auth-token",
        "x-access-token", "proxy-authorization",
        NULL
    };
    /* Schema/boolean words that appear as values in YAML/INI schemas —
     * `password: required` is a form spec, not a credential.          */
    static const char *const NONSECRET[] = {
        "required", "optional", "true", "false", "none", "null",
        "string", "integer", "boolean", "hidden", "yes", "no",
        "str", "int", "bool", "input", "password", "text",
        NULL
    };
    int found = 0;
    const char *p = text;

    while ((p = strpbrk(p, "=:")) != NULL) {
        const char *sep = p;
        const char *kstart;
        const char *val;
        char key[64];
        char sval[220];
        size_t kl = 0, vl = 0;
        size_t ki;
        int quoted = 0;

        /* Walk back over the key: letters, digits, '_', '-' — the key
         * token must abut the separator (spaces allowed before it).  */
        kstart = sep;
        while (kstart > text && (kstart[-1] == ' ' || kstart[-1] == '\t'))
            kstart--;
        {   const char *q = kstart;
            while (q > text &&
                   (isalnum((unsigned char)q[-1]) || q[-1] == '_' ||
                    q[-1] == '-'))
                q--;
            kstart = q;
        }
        kl = (size_t)(sep - kstart);
        /* Trim trailing whitespace already skipped above */
        {   const char *e = sep;
            while (e > kstart && (e[-1] == ' ' || e[-1] == '\t')) e--;
            kl = (size_t)(e - kstart);
        }
        if (kl == 0 || kl >= sizeof(key)) { p = sep + 1; continue; }
        /* Skip `==` / `=>` / `<=` / `>=` / `!=` comparison operators and
         * `:` that is part of `://` (URI scheme).                      */
        if (sep[1] == '=' || (sep[0] == '=' && sep > text &&
            (sep[-1] == '!' || sep[-1] == '<' || sep[-1] == '>' ||
             sep[-1] == '='))) { p = sep + 1; continue; }
        if (sep[0] == ':' && sep[1] == '/' && sep[2] == '/')
            { p = sep + 1; continue; }
        for (ki = 0; ki < kl; ki++)
            key[ki] = (char)tolower((unsigned char)kstart[ki]);
        key[kl] = '\0';

        for (ki = 0; KEYS[ki]; ki++)
            if (strcmp(key, KEYS[ki]) == 0) break;
        if (!KEYS[ki]) { p = sep + 1; continue; }

        /* Parse value: optional whitespace, optional quote, then the
         * value body up to the matching quote or a delimiter.        */
        val = sep + 1;
        while (*val == ' ' || *val == '\t') val++;
        if (*val == '"' || *val == '\'') {
            char qc = *val++;
            const char *e = strchr(val, qc);
            if (!e) { p = sep + 1; continue; }
            vl = (size_t)(e - val);
            quoted = 1;
        } else {
            const char *e;
            /* `Authorization: Bearer <token>` — the value leads with
             * an auth-scheme word; the credential follows the space. */
            if (strncasecmp(val, "bearer ", 7) == 0 ||
                strncasecmp(val, "basic ", 6) == 0 ||
                strncasecmp(val, "token ", 6) == 0)
                val = strchr(val, ' ') + 1;
            e = val;
            while (*e && *e != '\n' && *e != '\r' && *e != ',' &&
                   *e != ';' && *e != '}' && *e != ')' && *e != ' ' &&
                   *e != '\t' && *e != '#')
                e++;
            vl = (size_t)(e - val);
        }
        if (vl < 8 || vl >= sizeof(sval)) { p = sep + 1; continue; }
        memcpy(sval, val, vl);
        sval[vl] = '\0';

        /* Reject variable references / templates / function calls.    */
        if (sval[0] == '$' || sval[0] == '<' || sval[0] == '{' ||
            strchr(sval, '(') != NULL || strstr(sval, "${") != NULL) {
            p = sep + 1; continue;
        }
        /* Reject schema words and all-whitespace/uniform values.      */
        {   size_t n;
            int uniform = 1;
            for (n = 0; NONSECRET[n]; n++)
                if (strcmp(sval, NONSECRET[n]) == 0) break;
            if (NONSECRET[n]) { p = sep + 1; continue; }
            for (n = 1; n < vl; n++)
                if (sval[n] != sval[0]) { uniform = 0; break; }
            if (uniform) { p = sep + 1; continue; }
        }
        /* Placeholder suppression — reuse the shared marker logic.    */
        if (is_placeholder_secret(text, sep, sval, vl)) {
            p = sep + 1; continue;
        }
        (void)quoted;
        sv_add(v, 65, "KV_SECRET",
               "Hardcoded credential assignment: %s = <redacted> "
               "(%d chars)", key, (int)vl);
        found = 1;
        p = sep + 1;
    }
    return found;
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
            /* set by github_checksum_state() below: 0 n/a, 1 valid, 2 bad */
            int ck_state;
            /* " (AWS account NNNNNNNNNNNN — ...)" when the token is a
             * structurally valid AWS key ID, empty otherwise. */
            char aws_note[96];
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
                    ck_state = github_checksum_state(
                        sp->prefix, suffix,
                        tok_len - (size_t)sp->prefix_len);
                    /* For an AWS key ID the owning account number is encoded
                     * in the identifier itself. Surfacing it turns "a key
                     * leaked" into "THIS account is exposed", which is the
                     * fact whoever responds actually needs — and it costs no
                     * network call. */
                    aws_note[0] = '\0';
                    if (tok_len == 20) {
                        char keybuf[21], acct[13];
                        memcpy(keybuf, p, 20);
                        keybuf[20] = '\0';
                        if (hlse_aws_account_from_key(keybuf, acct, sizeof acct))
                            snprintf(aws_note, sizeof aws_note,
                                     " (AWS account %s — rotate this key and "
                                     "audit that account)", acct);
                    }
                    sv_add(&v, sp->score, sp->label,
                           "%s found: %s%s%s", sp->label, preview, aws_note,
                           ck_state == 1
                             ? " (checksum verifies — well-formed, "
                               "treat as live until rotated)"
                             : ck_state == 2
                               ? " (checksum does NOT verify — may be a "
                                 "redacted, illustrative, or mistyped value; "
                                 "still reported, verify manually)"
                               : "");
                }
            }
            p += sp->prefix_len;
        }
    }

    /* Custom (runtime-registered) patterns — roadmap P0-3. Identical
     * matching + placeholder-suppression logic as the built-in loop above,
     * over the caller-supplied table instead of SECRET_PATTERNS[]. */
    for (i = 0; i < g_custom_pattern_n; i++) {
        const CustomSecretPattern *cp = &g_custom_patterns[i];
        p = text;
        while ((p = strstr(p, cp->prefix)) != NULL) {
            const char *suffix = p + cp->prefix_len;
            int valid = 0;
            int j;
            for (j = 0; j < cp->min_suffix && suffix[j]; j++) {
                if (!charset_char_ok(cp->charset, suffix[j])) break;
                valid++;
            }
            if (valid >= cp->min_suffix) {
                size_t tok_len = (size_t)cp->prefix_len;
                while (suffix[tok_len - (size_t)cp->prefix_len] &&
                       charset_char_ok(cp->charset,
                           suffix[tok_len - (size_t)cp->prefix_len]))
                    tok_len++;
                if (!is_placeholder_secret(text, p, p, tok_len)) {
                    char preview[64];
                    snprintf(preview, sizeof(preview), "%.8s%.4s...",
                             cp->prefix, suffix);
                    sv_add(&v, cp->score, cp->label,
                           "%s found: %s", cp->label, preview);
                }
            }
            p += cp->prefix_len;
        }
    }

    /* Structural checks */
    check_ssh_key(text, &v);
    check_env_passwords(text, &v);
    check_generic_hex_secret(text, &v);
    check_kv_assignment(text, &v);
    check_hex_private_key(text, &v);
    check_mnemonic(text, &v);

    /* GCP service account JSON — contains "type": "service_account" and
     * "private_key" together. Near-zero false positives.               */
    if (strstr(text, "\"type\"") && strstr(text, "service_account") &&
        strstr(text, "\"private_key\"")) {
        sv_add(&v, 90, "GCP_SERVICE_ACCOUNT",
               "GCP service account JSON (type+private_key fields)");
    }

    /* AWS secret access key — the canonical `~/.aws/credentials` INI form
     * uses lowercase keys with spaces around '=' (`aws_secret_access_key =
     * wJal…`), which the case-sensitive, no-space env-pattern scan misses
     * entirely. The bare 40-char base64 secret is too generic to flag alone,
     * but anchored to its specific key name it is high-confidence. Match the
     * key case-insensitively, skip '='/quotes/space, then require ≥40 base64
     * chars (AWS secrets are exactly 40).                                  */
    {
        const char *k = ci_strstr(text, "aws_secret_access_key");
        if (k) {
            const char *val = k + strlen("aws_secret_access_key");
            while (*val == ' ' || *val == '=' || *val == ':' ||
                   *val == '"' || *val == '\'' || *val == '\t') val++;
            {
                const char *start = val;
                int b64_run = 0;
                while (is_base64(*val) && *val != '=') { b64_run++; val++; }
                if (b64_run >= 40 &&
                    !is_placeholder_secret(text, k, start, (size_t)b64_run)) {
                    sv_add(&v, 90, "AWS_SECRET_KEY",
                           "AWS secret access key (40-char base64 after "
                           "'aws_secret_access_key')");
                }
            }
        }
    }

    /* Azure storage connection string — AccountKey= followed by ≥40 base64
     * chars (actual keys are 88-char base64). The key is the credential
     * itself, not merely an env-variable reference.                      */
    {
        const char *ak = strstr(text, "AccountKey=");
        if (ak) {
            const char *val = ak + 11; /* strlen("AccountKey=") */
            int b64_run = 0;
            while (is_base64(*val) || *val == '=') { b64_run++; val++; }
            if (b64_run >= 40 && !is_placeholder_secret(text, ak, ak + 11,
                                                         (size_t)b64_run)) {
                sv_add(&v, 85, "AZURE_ACCOUNT_KEY",
                       "Azure storage AccountKey credential (%d chars)", b64_run);
            }
        }
    }

    /* Database / message-queue connection string with embedded credentials:
     * "<scheme>://<user>:<password>@<host>". A hardcoded password inside a
     * service URI is a high-volume real-world leak (.env, source, logs). We
     * match a fixed set of credential-bearing schemes so a plain "https://"
     * link (handled by the URL module) does not collide, and we suppress
     * variable references ($VAR) and placeholders.                         */
    {
        static const char *URI_SCHEMES[] = {
            "postgres://", "postgresql://", "mysql://", "mariadb://",
            "mongodb://", "mongodb+srv://", "redis://", "rediss://",
            "amqp://", "amqps://", "mssql://", "clickhouse://",
            "cockroachdb://", "sftp://", "ftp://", NULL
        };
        int si;
        for (si = 0; URI_SCHEMES[si]; si++) {
            const char *u = strstr(text, URI_SCHEMES[si]);
            if (!u) continue;
            {
                const char *userinfo = u + strlen(URI_SCHEMES[si]);
                const char *at = userinfo;
                const char *colon = NULL;
                /* Scan the authority up to '@' (userinfo end) or a path/end. */
                while (*at && *at != '@' && *at != '/' && *at != ' ' &&
                       *at != '\n' && *at != '\r') {
                    if (*at == ':' && !colon) colon = at;
                    at++;
                }
                if (*at == '@' && colon) {
                    const char *pw = colon + 1;
                    size_t pwlen = (size_t)(at - pw);
                    /* Non-trivial password, not a variable ref/placeholder. */
                    if (pwlen >= 4 && *pw != '$' && *pw != '{' &&
                        !is_placeholder_secret(text, pw, pw, pwlen)) {
                        sv_add(&v, 80, "URI_CREDENTIALS",
                               "Embedded credentials in %s connection string "
                               "(user:password@host)", URI_SCHEMES[si]);
                        break;
                    }
                }
            }
        }
    }

    /* Azure SAS token — highly distinctive shared-access-signature pattern */
    if ((strstr(text, "sv=") || strstr(text, "SharedAccessSignature")) &&
        strstr(text, "sig=") && strstr(text, "se=")) {
        sv_add(&v, 85, "AZURE_SAS",
               "Azure SAS token (sv/sig/se fields)");
    }

    /* Telegram bot token — "<8-10 digits>:<35 base64url chars>". The numeric
     * bot-id, the colon, and the 35-char secret are jointly distinctive
     * (near-zero false positives: a bare port/time has far fewer trailing
     * chars). Scan for a colon with a digit run before and a base64url run
     * after.                                                              */
    {
        const char *c = text;
        while ((c = strchr(c, ':')) != NULL) {
            /* Count the digit run immediately before the colon. */
            const char *d = c;
            int digits = 0;
            while (d > text && d[-1] >= '0' && d[-1] <= '9') { d--; digits++; }
            /* Count the base64url run immediately after the colon. */
            const char *a = c + 1;
            int after = 0;
            while ((*a >= 'A' && *a <= 'Z') || (*a >= 'a' && *a <= 'z') ||
                   (*a >= '0' && *a <= '9') || *a == '-' || *a == '_') {
                after++; a++;
            }
            /* The digit run must be the whole id (bounded by a non-digit or
             * start) to avoid matching the tail of a longer number.        */
            int bounded = (d == text || !(d[-1] >= '0' && d[-1] <= '9'));
            if (bounded && digits >= 8 && digits <= 10 && after >= 35) {
                sv_add(&v, 85, "TELEGRAM_BOT_TOKEN",
                       "Telegram bot token (<id>:<35-char secret>)");
                break;
            }
            c++;
        }
    }

    /* Discord bot token — "<b64 snowflake>.<6-7 b64url>.<27-38 b64url>".
     * Unlike a JWT there is no fixed prefix: segment 1 is the base64 of
     * the bot's numeric snowflake ID. Decode it and require an all-digit
     * run of plausible snowflake length (15+ digits) — that structure is
     * near-unique to Discord tokens, so false positives are rare.       */
    {
        const char *dc = text;
        while ((dc = strchr(dc, '.')) != NULL) {
            /* seg1 = the base64url run ending at this dot */
            const char *s1 = dc;
            int s1len = 0;
            while (s1 > text &&
                   ((s1[-1] >= 'A' && s1[-1] <= 'Z') ||
                    (s1[-1] >= 'a' && s1[-1] <= 'z') ||
                    (s1[-1] >= '0' && s1[-1] <= '9') ||
                    s1[-1] == '-' || s1[-1] == '_')) {
                s1--; s1len++;
            }
            if (s1len >= 20 && s1len <= 30 &&
                (s1 == text || !((s1[-1] >= 'A' && s1[-1] <= 'Z') ||
                                 (s1[-1] >= 'a' && s1[-1] <= 'z') ||
                                 (s1[-1] >= '0' && s1[-1] <= '9') ||
                                 s1[-1] == '-' || s1[-1] == '_'))) {
                /* seg2 after the dot */
                const char *q = dc + 1;
                int s2 = 0;
                while ((*q >= 'A' && *q <= 'Z') || (*q >= 'a' && *q <= 'z') ||
                       (*q >= '0' && *q <= '9') || *q == '-' || *q == '_') {
                    q++; s2++;
                }
                if (s2 >= 5 && s2 <= 8 && *q == '.') {
                    const char *s3 = q + 1;
                    int s3len = 0;
                    while ((s3[s3len] >= 'A' && s3[s3len] <= 'Z') ||
                           (s3[s3len] >= 'a' && s3[s3len] <= 'z') ||
                           (s3[s3len] >= '0' && s3[s3len] <= '9') ||
                           s3[s3len] == '-' || s3[s3len] == '_')
                        s3len++;
                    if (s3len >= 25 && s3len <= 45) {
                        /* decode seg1 — a real token's seg1 is the bot's
                         * numeric user id, so it decodes to digits    */
                        char dec[64];
                        size_t dn = hlse_base64url_decode(s1,
                            (size_t)s1len, dec, sizeof(dec));
                        int alldigit = (dn >= 15);
                        size_t di;
                        for (di = 0; di < dn; di++)
                            if (dec[di] < '0' || dec[di] > '9') {
                                alldigit = 0; break; }
                        if (alldigit) {
                            sv_add(&v, 85, "DISCORD_BOT_TOKEN",
                                   "Discord bot token (<b64 snowflake>"
                                   ".<short>.<hmac>) — full bot control");
                            break;
                        }
                    }
                }
            }
            dc++;
        }
    }

    /* JWT bearer token — header.payload.signature, all base64url. The "eyJ"
     * prefix is base64 of '{"', which every JWT header begins with. The
     * three-segment dotted structure with base64url segments is JWT-specific
     * (near-zero false positives), and a signed JWT is a live bearer
     * credential worth flagging.                                          */
    {
        const char *jp = text;
        while ((jp = strstr(jp, "eyJ")) != NULL) {
            const char *q = jp;
            int seg = 0, seglen = 0, ok;
            int seglens[3] = {0, 0, 0};
            /* Walk up to 3 base64url segments separated by single dots. */
            while (*q && seg < 3) {
                char c = *q;
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_') {
                    seglen++;
                    q++;
                } else if (c == '.') {
                    seglens[seg++] = seglen;
                    seglen = 0;
                    q++;
                } else {
                    break;
                }
            }
            if (seg == 2) { seglens[2] = seglen; seg = 3; } /* trailing sig */
            /* Require all three segments present and non-trivial: a real
             * signed JWT has header>=10, payload>=10, signature>=20.       */
            ok = (seg == 3 && seglens[0] >= 10 && seglens[1] >= 10 &&
                  seglens[2] >= 20);

            /* The header is base64url, not encrypted, so the algorithm is
             * readable offline. Two things are worth saying about it:
             *
             *  - alg "none" means the token is unsigned and anyone can forge
             *    one. This is the classic signature-bypass, still producing
             *    CVEs through 2026 (e.g. CVE-2026-28802 in Authlib), and
             *    libraries keep falling to CASE VARIANTS — nOnE, NONE — so the
             *    comparison here is case-insensitive.
             *  - Such a token has an EMPTY signature segment by construction,
             *    so the seglens[2] >= 20 rule above excludes exactly the most
             *    dangerous case. It is matched separately below.
             *
             * Naming the algorithm on an ordinary token is triage information
             * for free: it says what to check without opening the token. */
            if (seg == 3 && seglens[0] >= 10 && seglens[1] >= 10) {
                char hdr[256];
                size_t hn = hlse_base64url_decode(jp, (size_t)seglens[0],
                                                  hdr, sizeof hdr);
                if (hn > 0) {
                    const char *a = strstr(hdr, "\"alg\"");
                    if (a) {
                        const char *q1 = strchr(a + 5, '"');
                        const char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
                        if (q1 && q2 && q2 > q1 + 1 &&
                            (size_t)(q2 - q1 - 1) < 32) {
                            char alg[32];
                            size_t al = (size_t)(q2 - q1 - 1);
                            size_t ai;
                            memcpy(alg, q1 + 1, al);
                            alg[al] = '\0';
                            for (ai = 0; ai < al; ai++)
                                alg[ai] = (char)tolower((unsigned char)alg[ai]);
                            if (strcmp(alg, "none") == 0) {
                                sv_add(&v, 70, "JWT_ALG_NONE",
                                    "Unsigned JWT (alg \"none\"): the signature "
                                    "is absent, so this token can be forged by "
                                    "anyone — an attack artifact or a dangerous "
                                    "misconfiguration, not a normal credential");
                                break;
                            }
                            if (ok) {
                                sv_add(&v, 60, "JWT",
                                    "JWT bearer token (alg %s, "
                                    "header.payload.signature)", alg);
                                break;
                            }
                        }
                    }
                }
            }
            if (ok) {
                sv_add(&v, 60, "JWT",
                       "JWT bearer token (header.payload.signature)");
                break;
            }
            jp += 3;
        }
    }

    return v;
}

const char *
hlse_secret_confidence(const SecretVerdict *v) {
    int i;
    if (!v || v->n_findings == 0) return "none";
    /* Heuristic finding types: a match without a fixed, unforgeable anchor —
     * a generic VAR=value env line or a high-entropy string after a keyword.
     * Everything else (fixed-prefix tokens, private-key markers, structural
     * cloud-credential shapes) is high-specificity → certain. */
    for (i = 0; i < v->n_findings; i++) {
        const char *t = v->findings[i].type;
        if (strcmp(t, "ENV_SECRET") != 0 &&
            strcmp(t, "GENERIC_SECRET") != 0 &&
            strcmp(t, "KV_SECRET") != 0 &&
            strcmp(t, "HEX_PRIVATE_KEY") != 0 &&
            strcmp(t, "MNEMONIC_PHRASE") != 0)
            return "certain";
    }
    return "heuristic";
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

/* Whole-word substring match: returns 1 if `needle` appears in `hay`
 * bounded by non-alphanumeric characters (or string ends). This avoids
 * substring collisions where a short token like "irs" matches inside
 * "first" or "ups" matches inside "groups"/"backups". Both arguments
 * must already be lowercase. Multi-word needles (e.g. "office 365")
 * still match because only the outer boundaries are checked. */
static int
contains_word(const char *hay, const char *needle) {
    size_t nlen = strlen(needle);
    const char *p = hay;
    if (nlen == 0) return 0;
    while ((p = strstr(p, needle)) != NULL) {
        int pre_ok  = (p == hay) ||
                      !isalnum((unsigned char)p[-1]);
        int post_ok = (p[nlen] == '\0') ||
                      !isalnum((unsigned char)p[nlen]);
        if (pre_ok && post_ok) return 1;
        p++;
    }
    return 0;
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

/* Return 1 if `brand` legitimately owns `domain`.
 *
 * Uses suffix matching ("ends with base_domain") so subdomains like
 * accountprotection.microsoft.com are accepted but look-alike domains
 * like microsoft-verify.ru and apple-secure.net are NOT.                */
static int
brand_owns_domain(const char *brand, const char *domain) {
    static const struct { const char *brand; const char *base; } BD[] = {
        { "microsoft", "microsoft.com"    }, { "microsoft", "office.com"     },
        { "microsoft", "live.com"         }, { "microsoft", "hotmail.com"    },
        { "microsoft", "msn.com"          }, { "microsoft", "microsoft365.com"},
        { "apple",     "apple.com"        }, { "apple",     "icloud.com"     },
        { "apple",     "me.com"           }, { "apple",     "mac.com"        },
        { "google",    "google.com"       }, { "google",    "gmail.com"      },
        { "google",    "googlemail.com"   },
        { "amazon",    "amazon.com"       }, { "amazon",    "amazonses.com"  },
        { "amazon",    "amazon.co.uk"     }, { "amazon",    "amazon.de"      },
        { "amazon",    "amazon.co.jp"     },
        { "paypal",    "paypal.com"       }, { "paypal",    "paypal.co.uk"   },
        { "facebook",  "facebook.com"     }, { "facebook",  "facebookmail.com"},
        { "facebook",  "fb.com"           },
        { "instagram", "instagram.com"    }, { "instagram", "facebookmail.com"},
        { "netflix",   "netflix.com"      }, { "netflix",   "netflixmail.com"},
        { "linkedin",  "linkedin.com"     }, { "linkedin",  "linkedin.email" },
        { "twitter",   "twitter.com"      }, { "twitter",   "x.com"          },
        { "twitter",   "twitteremail.com" },
        { "stripe",    "stripe.com"       }, { "github",    "github.com"     },
        { "docusign",  "docusign.com"     }, { "docusign",  "docusign.net"   },
        { "zoom",      "zoom.us"          }, { "zoom",      "zoom.com"       },
        { "fedex",     "fedex.com"        }, { "dhl",       "dhl.com"        },
        { "ups",       "ups.com"          }, { "usps",      "usps.com"       },
        { "irs",       "irs.gov"          }, { "shopify",   "shopify.com"    },
        /* Financial institutions: "bank" keyword must not FP on their
         * own sending domains. Add canonical domains for major banks.  */
        { "bank", "chase.com"              }, { "bank", "bankofamerica.com"   },
        { "bank", "wellsfargo.com"         }, { "bank", "citibank.com"        },
        { "bank", "citi.com"               }, { "bank", "usbank.com"          },
        { "bank", "capitalone.com"         }, { "bank", "pnc.com"             },
        { "bank", "tdbank.com"             }, { "bank", "regions.com"         },
        { "bank", "suntrust.com"           }, { "bank", "truist.com"          },
        { "bank", "ally.com"               }, { "bank", "discoverbank.com"    },
        { "bank", "discover.com"           },
        /* JP banks */
        { "bank", "smbc.co.jp"             }, { "bank", "mufg.jp"             },
        { "bank", "mizuhobank.co.jp"       }, { "bank", "japanpost.jp"        },
        { "bank", "rakuten-bank.co.jp"     }, { "bank", "aeon.co.jp"          },
        /* EU banks */
        { "bank", "ing.com"                }, { "bank", "n26.com"             },
        { "bank", "bunq.com"               }, { "bank", "revolut.com"         },
        /* KR banks */
        { "bank", "kbstar.com"             }, { "bank", "ibk.co.kr"           },
        { "bank", "nonghyup.com"           }, { "bank", "shinhan.com"         },
        { NULL, NULL }
    };
    int i;
    size_t dl = strlen(domain);
    for (i = 0; BD[i].brand; i++) {
        size_t bl;
        if (strcmp(brand, BD[i].brand) != 0) continue;
        bl = strlen(BD[i].base);
        if (dl >= bl) {
            size_t off = dl - bl;
            /* Domain must end with base and have '.' or be identical */
            if (strcmp(domain + off, BD[i].base) == 0 &&
                (off == 0 || domain[off - 1] == '.'))
                return 1;
        }
    }
    return 0;
}

/* Generic display-name function words that should not trigger E1 when
 * the email's primary brand already owns the From domain. For example,
 * "Apple Support" from apple.com — "support" here is a department label,
 * not an impersonation. We only suppress if brand_owns = 1.             */
static int
is_generic_display_role(const char *word) {
    static const char *ROLES[] = {
        "support", "security", "admin", "helpdesk", "accounts",
        "notifications", "it department", "human resources",
        "hr department", "it support", NULL
    };
    int i;
    for (i = 0; ROLES[i]; i++)
        if (strcmp(word, ROLES[i]) == 0) return 1;
    return 0;
}

EmailVerdict
hlse_check_email_headers(const char *raw_headers) {
    EmailVerdict v;
    const char *from_val, *reply_to_val, *auth_val, *subject_val;
    char from_domain[256] = {0};
    char reply_domain[256] = {0};
    char display_name[256] = {0};
    char unfolded[8192];

    memset(&v, 0, sizeof(v));
    if (!raw_headers) return v;

    /* RFC 5322 §2.2.3 unfolding: a CRLF immediately followed by whitespace is
     * a single logical header split across lines. Join continuations back
     * onto one line before parsing, otherwise a spoofed
     *   From: PayPal Support
     *    <service@evil.ru>
     * leaves the domain on the folded line — extract_domain stops at the
     * newline (missing it) and the display name keeps an embedded newline.   */
    {
        size_t w = 0;
        const char *r = raw_headers;
        while (*r && w < sizeof(unfolded) - 1) {
            if (*r == '\r') { r++; continue; }      /* normalize CRLF → LF */
            if (*r == '\n' && (r[1] == ' ' || r[1] == '\t')) {
                r++;                                /* skip the fold LF */
                while (*r == ' ' || *r == '\t') r++;/* and leading WSP run */
                if (w > 0 && unfolded[w - 1] != ' ') unfolded[w++] = ' ';
                continue;
            }
            unfolded[w++] = *r++;
        }
        unfolded[w] = '\0';
        raw_headers = unfolded;
    }

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

        /* First pass: check if any brand in display name legitimately owns
         * the From domain (primary match OR trusted alternate domain).
         * This suppresses false positives like "Apple Support" from apple.com
         * — "support" is a department label, not an impersonation.          */
        int brand_owns = 0;
        for (i = 0; known[i]; i++) {
            if (contains_word(lower_dn, known[i]) &&
                brand_owns_domain(known[i], from_domain)) {
                brand_owns = 1; break;
            }
        }

        /* Second pass: fire E1 only when brand truly mismatches. Skip
         * generic role words ("support", "security", ...) if the primary
         * brand already matches the domain.                                  */
        int e1_fired = 0;
        for (i = 0; known[i]; i++) {
            /* Word-boundary match on the display name avoids substring
             * collisions ("irs" in "First", "ups" in "Backups Team");
             * brand_owns_domain() covers alternate sending domains so
             * "Apple" from icloud.com is not flagged as a mismatch.         */
            if (contains_word(lower_dn, known[i]) &&
                !brand_owns_domain(known[i], from_domain) &&
                !(brand_owns && is_generic_display_role(known[i])))
            {
                v.score += 45;
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "E1: Display name '%.60s' implies %.40s but From is %.80s",
                    display_name, known[i], from_domain);
                e1_fired = 1;
                break;
            }
        }

        /* Third pass: custom (runtime-registered) brands — roadmap P1-6.
         * Same word-boundary match and mismatch rule as the built-in table,
         * against each brand's own registered owned-domain list. Only
         * checked when the built-in pass above did not already flag this
         * email, so a message never double-counts E1 across two tables. */
        if (!e1_fired && v.n_reasons < HLSE_EMAIL_MAX_REASONS) {
            int j;
            for (j = 0; j < g_custom_brand_n; j++) {
                const CustomBrand *b = &g_custom_brands[j];
                if (contains_word(lower_dn, b->name) &&
                    !custom_brand_owns_domain(b, from_domain))
                {
                    v.score += 45;
                    snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                        "E1: Display name '%.60s' implies %.40s but From is %.80s",
                        display_name, b->name, from_domain);
                    break;
                }
            }
        }
    }

    /* E6: Brand typosquat inside the From domain itself — the classic
     * BEC sender "billing@amaz0n.example" / "mail.microsft.example".
     * E1 covers a brand claimed in the DISPLAY NAME; this covers a
     * brand mimicked inside the sender address. Two squats only:
     *   (a) leet/digit substitution — normalize 0→o 1→l 3→e 5→s
     *       7→t $→s @→a and the label equals a brand while the raw
     *       label differs ('amaz0n' → 'amazon')
     *   (b) Damerau distance 1 — 'microsft', 'paypai', 'arnazon'
     * Exact-match labels are skipped on purpose: 'support.x.com' is
     * ordinary wording, not a lookalike. The brand table stays to
     * high-value senders — generic role words are excluded so
     * 'accounts.example.com' stays clean.                              */
    if (from_domain[0] && v.n_reasons < HLSE_EMAIL_MAX_REASONS) {
        /* short/generic-brand exclusions: 'gmail' collides with 'mail',
         * 'binance' with 'finance'/'balance', 'chase' with 'phase',
         * 'usps' with 'ups' — all edit distance 1 from ordinary words */
        static const char *const SQUAT_BRANDS[] = {
            "amazon", "paypal", "microsoft", "apple", "google",
            "netflix", "facebook", "instagram", "linkedin", "twitter",
            "ebay", "wellsfargo", "citibank", "hmrc", "irs",
            "dhl", "fedex", "ups", "docusign", "stripe", "shopify",
            "github", "zoom", "coinbase", "outlook",
            "office365", "yahoo", "aol", "protonmail",
            NULL
        };
        char lab[96];
        size_t li, di, bi;
        const char *p;
        for (p = from_domain; *p; p++) {
            /* walk dot-separated labels */
            li = 0;
            while (p[li] && p[li] != '.' && li < sizeof(lab) - 1) {
                lab[li] = (char)tolower((unsigned char)p[li]);
                li++;
            }
            lab[li] = '\0';
            p += li;
            if (!*p) p--;
            if (li < 4 || li > 20) { if (!*p) break; continue; }
            /* leet-normalized copy */
            {
                char norm[96];
                memcpy(norm, lab, li + 1);
                for (di = 0; di < li; di++) {
                    if (norm[di] == '0') norm[di] = 'o';
                    else if (norm[di] == '1') norm[di] = 'l';
                    else if (norm[di] == '3') norm[di] = 'e';
                    else if (norm[di] == '5' || norm[di] == '$')
                        norm[di] = 's';
                    else if (norm[di] == '7') norm[di] = 't';
                    else if (norm[di] == '@') norm[di] = 'a';
                }
                for (bi = 0; SQUAT_BRANDS[bi]; bi++) {
                    const char *b = SQUAT_BRANDS[bi];
                    if ((strcmp(norm, b) == 0 && strcmp(lab, b) != 0) ||
                        (strcmp(lab, b) != 0 &&
                         hlse_edit_distance(lab, b) == 1)) {
                        if (brand_owns_domain(b, from_domain)) break;
                        v.score += 45;
                        snprintf(v.reasons[v.n_reasons++],
                            sizeof(v.reasons[0]),
                            "E6: From domain '%.80s' contains brand lookalike "
                            "'%.32s' resembling '%.40s' (typosquat sender)",
                            from_domain, lab, b);
                        goto e6_done;
                    }
                }
            }
            if (!*p) break;
        }
e6_done:;
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
        /* All three returning "none" means no authentication was performed
         * at all — a legitimate corporate mailer always publishes at least
         * SPF or DKIM records.                                             */
        if (strstr(auth_val, "spf=none") && strstr(auth_val, "dkim=none") &&
            strstr(auth_val, "dmarc=none")) {
            v.score += 20;
            if (v.n_reasons < HLSE_EMAIL_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "E4: No SPF/DKIM/DMARC records — sender domain has no "
                    "email authentication (uncommon for legitimate senders)");
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

    /* E7: duplicate From: headers — violates RFC 5322 §3.6 (mailbox
     * fields MUST NOT repeat) and is a delivery/parser-confusion
     * primitive: the gateway verifies one From while the client
     * displays the other (multiple-From spoofing).               */
    {
        int from_count = 0;
        const char *fp = raw_headers;
        while (fp && *fp) {
            if (strncasecmp(fp, "from:", 5) == 0) from_count++;
            fp = strchr(fp, '\n');
            if (fp) fp++;
        }
        if (from_count > 1) {
            v.score += 35;
            if (v.n_reasons < HLSE_EMAIL_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "E7: %d From: headers — RFC violation; parser "
                    "confusion lets one be verified and another "
                    "displayed", from_count);
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
    /* Reasons embed attacker-controlled header values (display names,
     * domains); sanitise display-hostile characters at the exit. */
    {
        int i;
        for (i = 0; i < v.n_reasons; i++)
            hlse_sanitize_display(v.reasons[i]);
    }
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
    CRYPTO_BCH,           /* bitcoincash:q/p... (CashAddr) */
    CRYPTO_COSMOS,        /* cosmos1... (bech32, 45 chars) */
    CRYPTO_XTZ,           /* tz1/tz2/tz3/KT1... (36 chars, base58) */
    CRYPTO_DOT,           /* 1... (47-48 chars, SS58 base58) */
    CRYPTO_ALGO,          /* 58 chars, base32 [A-Z2-7] */
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

    /* Bitcoin Cash CashAddr: "bitcoincash:" prefix + q/p + 41 base32 chars.
     * The explicit prefix makes this zero-FP. (Prefix-less CashAddr also
     * starts q/p but we require the prefix to avoid colliding with other
     * base32 formats.)                                                     */
    if (strncmp(addr, "bitcoincash:", 12) == 0) {
        const char *body = addr + 12;
        size_t blen = strlen(body);
        if (blen >= 42 && (body[0] == 'q' || body[0] == 'p')) {
            int i, ok = 1;
            /* CashAddr uses Bech32 charset (lowercase, no 1/b/i/o) */
            for (i = 1; i < (int)blen; i++) {
                char c = body[i];
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) {
                    ok = 0; break;
                }
            }
            if (ok) return CRYPTO_BCH;
        }
    }

    /* Cosmos Hub (ATOM): "cosmos1" + 38 bech32 chars = 45 total. The
     * "cosmos1" prefix is uniquely the Cosmos Hub — near-zero FP.          */
    if (len >= 44 && len <= 46 && strncmp(addr, "cosmos1", 7) == 0) {
        int i, ok = 1;
        for (i = 7; i < (int)len; i++) {
            char c = addr[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) {
                ok = 0; break;
            }
        }
        if (ok) return CRYPTO_COSMOS;
    }

    /* Tezos: tz1/tz2/tz3 (implicit) or KT1 (contract), 36 chars, base58.
     * Checked before the Solana catch-all so it is labeled correctly.     */
    if (len == 36 &&
        ((addr[0] == 't' && addr[1] == 'z' &&
          (addr[2] == '1' || addr[2] == '2' || addr[2] == '3')) ||
         (addr[0] == 'K' && addr[1] == 'T' && addr[2] == '1'))) {
        int i, ok = 1;
        for (i = 3; i < (int)len; i++) {
            if (!is_base58(addr[i])) { ok = 0; break; }
        }
        if (ok) return CRYPTO_XTZ;
    }

    /* Algorand: 58 chars, Algorand/RFC-4648 base32 [A-Z2-7], no prefix.
     * Length 58 distinguishes it from Stellar (56, 'G'-prefixed).         */
    if (len == 58) {
        int i, ok = 1;
        for (i = 0; i < 58; i++) {
            char c = addr[i];
            if (!((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'))) {
                ok = 0; break;
            }
        }
        if (ok) return CRYPTO_ALGO;
    }

    /* Polkadot (SS58): starts with '1', 47-48 base58 chars. Above the
     * Solana catch-all's 44-char ceiling, so it is otherwise unclassified.
     * (BTC legacy also starts with '1' but is 26-35 chars — length
     * disambiguates.)                                                      */
    if (len >= 46 && len <= 48 && addr[0] == '1') {
        int i, ok = 1;
        for (i = 1; i < (int)len; i++) {
            if (!is_base58(addr[i])) { ok = 0; break; }
        }
        if (ok) return CRYPTO_DOT;
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
        case CRYPTO_BCH:         return "BCH (Bitcoin Cash)";
        case CRYPTO_COSMOS:      return "ATOM (Cosmos)";
        case CRYPTO_XTZ:         return "XTZ (Tezos)";
        case CRYPTO_DOT:         return "DOT (Polkadot)";
        case CRYPTO_ALGO:        return "ALGO (Algorand)";
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

/* Copy `s` into `buf` with leading/trailing whitespace removed. A clipboard
 * selection routinely carries surrounding spaces/newlines (selecting an
 * address on a web page, a trailing line break); without trimming, a swapped
 * address with surrounding whitespace fails format detection and the hijack
 * is silently missed. */
static const char *
trim_ws_copy(const char *s, char *buf, size_t bufsz) {
    size_t len;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r' || *s == '\f'
           || *s == '\v')
        s++;
    len = strlen(s);
    while (len > 0 && (s[len-1] == ' ' || s[len-1] == '\t' ||
                       s[len-1] == '\n' || s[len-1] == '\r' ||
                       s[len-1] == '\f' || s[len-1] == '\v'))
        len--;
    if (len >= bufsz) len = bufsz - 1;
    memcpy(buf, s, len);
    buf[len] = '\0';
    return buf;
}

CryptoSwapVerdict
hlse_check_crypto_swap(const char *copied, const char *pasted) {
    CryptoSwapVerdict v;
    char cbuf[256], pbuf[256];
    memset(&v, 0, sizeof(v));

    if (!copied || !pasted) return v;

    /* Trim surrounding whitespace — a real copy/paste often includes it, and
     * an untrimmed address fails fixed-length/prefix format detection. */
    copied = trim_ws_copy(copied, cbuf, sizeof(cbuf));
    pasted = trim_ws_copy(pasted, pbuf, sizeof(pbuf));

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

/* `0x` + exactly 64 hex chars — Ethereum/hex private-key shape.
 * The 64-char bound keeps sha256-with-0x digests (also 64 hex) inside
 * the same class — both are high-entropy material worth flagging;
 * placeholder suppression removes doc fixtures. */
static int
check_hex_private_key(const char *text, SecretVerdict *v) {
    const char *p = text;
    int found = 0;
    while ((p = strstr(p, "0x")) != NULL) {
        const char *h = p + 2;
        int run = 0;
        if (p != text && isalnum((unsigned char)p[-1])) { p++; continue; }
        while (is_hex(h[run])) run++;
        if (run == 64 &&
            !is_placeholder_secret(text, p, p + 2, (size_t)run)) {
            sv_add(v, 55, "HEX_PRIVATE_KEY",
                   "0x-prefixed 64-hex value — private-key shape");
            found = 1;
        }
        p = h;
    }
    return found;
}

/* BIP39-shaped seed/recovery phrase: a run of >=12 lowercase alpha
 * words (1-9 chars each, space-separated) with >=10 distinct — plain
 * prose collides rarely because it repeats function words. A
 * seed/mnemonic/recovery/wallet/phrase keyword within 48 chars before
 * the run upgrades the score. */
static int
check_mnemonic(const char *text, SecretVerdict *v) {
    static const char *const CTX[] = {
        "seed", "mnemonic", "recovery", "wallet", "phrase", NULL
    };
    const char *p = text;
    int found = 0;
    while (*p) {
        const char *w = p;
        const char *skip_end = NULL;
        char seen[26][16];
        int nseen = 0, nwords = 0;
        if (!(*w >= 'a' && *w <= 'z')) { p++; continue; }
        for (;;) {
            int wl = 0;
            while (w[wl] >= 'a' && w[wl] <= 'z') wl++;
            if (wl < 3 || wl > 8) { skip_end = w + wl; break; }
            {
                int dup = 0, i, c = wl < 15 ? wl : 15;
                for (i = 0; i < nseen; i++)
                    if (strncmp(seen[i], w, (size_t)c) == 0 &&
                        (int)strlen(seen[i]) == c) { dup = 1; break; }
                if (!dup && nseen < 26) {
                    memcpy(seen[nseen], w, (size_t)c);
                    seen[nseen][c] = '\0';
                    nseen++;
                }
            }
            nwords++;
            if (w[wl] == ' ' && w[wl + 1] >= 'a' && w[wl + 1] <= 'z') {
                w += wl + 1;
                continue;
            }
            break;
        }
        /* only canonical BIP39 lengths (12/15/18/21/24 words) — a
         * run of 13 distinct prose words cannot be a mnemonic, and
         * restricting to these lengths keeps ordinary sentences out */
        if ((nwords == 12 || nwords == 15 || nwords == 18 ||
             nwords == 21 || nwords == 24) && nseen >= nwords - 2 &&
            !is_placeholder_secret(text, p, p, (size_t)(w - p))) {
            char ctx[49];
            const char *s = p - text > 48 ? p - 48 : text;
            size_t cn = (size_t)(p - s), i;
            int hot = 0;
            for (i = 0; i < cn; i++)
                ctx[i] = (char)tolower((unsigned char)s[i]);
            ctx[cn] = '\0';
            for (i = 0; CTX[i]; i++)
                if (strstr(ctx, CTX[i])) { hot = 1; break; }
            sv_add(v, hot ? 75 : 45, "MNEMONIC_PHRASE",
                   hot ? "BIP39-shaped seed/recovery phrase "
                         "(keyword context + %d distinct words)"
                       : "possible seed phrase — %d consecutive "
                         "distinct lowercase words",
                   nseen);
            found = 1;
        }
        /* advance past the whole run — rescanning inside it lets a
         * 17-word prose sentence expose a canonical-length sub-run;
         * skip_end covers the over-long word that aborted the run
         * (otherwise a megabyte of one letter rescans O(n^2)) */
        p = skip_end ? skip_end : ((w > p) ? w : p + 1);
    }
    return found;
}
