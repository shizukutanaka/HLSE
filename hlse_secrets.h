/*
 * hlse_secrets.h — Public API for credential scanning, email forensics,
 *                  and clipboard crypto-swap detection.
 */

#ifndef HLSE_SECRETS_H
#define HLSE_SECRETS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ── Module 1: Secret Scanner ─────────────────────────────────────────── */

#define HLSE_SECRET_MAX_FINDINGS 16

typedef struct {
    char type[32];          /* e.g. "AWS_KEY", "GITHUB_PAT", "PRIVATE_KEY" */
    char description[256];
} SecretFinding;

typedef struct {
    int           score;    /* 0..100 */
    int           n_findings;
    SecretFinding findings[HLSE_SECRET_MAX_FINDINGS];
} SecretVerdict;

/* Scan text for exposed credentials, API keys, private keys.
 * Input can be a file's content, a git diff, or any text.
 * Fully local — no network access.                                    */
SecretVerdict hlse_scan_secrets(const char *text);

/* Confidence is a separate axis from the score (severity). A fixed-prefix or
 * structural match (AKIA…, ghp_…, JWT, GCP service-account JSON) is
 * near-certain (~zero false positives); a generic env-var or high-entropy
 * match is a heuristic judgment call. Returns "certain" if any finding is a
 * high-specificity type, else "heuristic" (or "none" when there are no
 * findings). */
const char *hlse_secret_confidence(const SecretVerdict *v);

/* ── Custom secret patterns (roadmap P0-3) ────────────────────────────────
 * The built-in SECRET_PATTERNS table is compiled in and cannot name an
 * organization's internal token formats without a rebuild. These let a
 * caller register additional prefix+charset+length patterns at runtime,
 * checked by hlse_scan_secrets() using the exact same matching and
 * placeholder-suppression logic as the built-in table — purely additive, so
 * the corpus benchmark (which never registers custom patterns) and F1 are
 * unaffected. Not thread-safe; call before scanning, from one thread. */
#define HLSE_CUSTOM_SECRET_MAX 64

/* Named character-class selectors for a custom pattern's suffix, avoiding
 * the need to expose a function-pointer ABI to callers. */
typedef enum {
    HLSE_CHARSET_ALNUM = 0,      /* letters + digits */
    HLSE_CHARSET_ALNUM_DASH,     /* letters + digits + '-' '_' */
    HLSE_CHARSET_HEX,            /* 0-9 a-f A-F */
    HLSE_CHARSET_ALPHA,          /* letters only */
    HLSE_CHARSET_DIGIT           /* digits only */
} HlseCharset;

/* Register one custom secret pattern. `prefix` is the literal token prefix to
 * search for (e.g. "ACME_KEY_"); `min_suffix` is the minimum number of
 * `charset`-valid characters required after the prefix; `label` names the
 * credential type in findings; `score` (0-100) is its risk score. Returns 1
 * on success, 0 if the registry is full or an argument is invalid (prefix
 * empty/NULL, min_suffix <= 0, label empty/NULL). */
int hlse_register_custom_secret_pattern(const char *prefix, int min_suffix,
                                        HlseCharset charset,
                                        const char *label, int score);

/* Discard all registered custom patterns (built-in table is unaffected). */
void hlse_clear_custom_secret_patterns(void);

/* Number of currently registered custom patterns. */
int hlse_custom_secret_pattern_count(void);

/* ── Module 2: Email Header Forensics ─────────────────────────────────── */

#define HLSE_EMAIL_MAX_REASONS 8

typedef struct {
    int  score;             /* 0..100 */
    int  n_reasons;
    char reasons[HLSE_EMAIL_MAX_REASONS][256];
} EmailVerdict;

/* Parse raw email headers for spoofing/BEC signals.
 * Input: the header portion of the email (up to the first blank line).
 * Checks: display-name mismatch, Reply-To mismatch, SPF/DKIM fail,
 *         free-email corporate impersonation, urgent-subject pattern.  */
EmailVerdict hlse_check_email_headers(const char *raw_headers);

/* ── Custom brands / organization impersonation targets (roadmap P1-6) ────
 * The built-in display-name-vs-domain mismatch check (E1) only knows a
 * fixed set of major consumer brands — it has no way to protect an
 * organization's OWN name or executives without a rebuild. A registered
 * custom brand fires the exact same E1 check (score +45, same reason
 * format) when its name appears in a From display name but the sending
 * domain is not one of its registered owned domains. Purely additive: the
 * corpus benchmark never registers custom brands, so F1 is unaffected. Not
 * thread-safe; call before scanning, from one thread. */
#define HLSE_CUSTOM_BRAND_MAX     32
#define HLSE_CUSTOM_BRAND_DOMAINS 4

/* Register a custom brand. `name` is matched as a whole word (case-
 * insensitive) against the From display name (e.g. "Acme Corp" or a CEO's
 * name). `owned_domains_csv` is a comma-separated list of up to
 * HLSE_CUSTOM_BRAND_DOMAINS domains that legitimately send as this brand
 * (e.g. "acmecorp.com,acme-corp.com"); a From domain matching none of them
 * while the name appears in the display field triggers E1. Returns 1 on
 * success, 0 if the registry is full or an argument is invalid (name
 * empty/NULL, no valid domain parsed). */
int hlse_register_custom_brand(const char *name, const char *owned_domains_csv);

/* Discard all registered custom brands (built-in brand list is unaffected). */
void hlse_clear_custom_brands(void);

/* Number of currently registered custom brands. */
int hlse_custom_brand_count(void);

/* ── Module 3: Clipboard Crypto-Swap ──────────────────────────────────── */

typedef struct {
    int  score;             /* 0..100 (95 = confirmed swap) */
    int  is_swap;           /* 1 = address was swapped */
    char original[128];     /* what the user copied */
    char swapped[128];      /* what appeared after paste */
    char reason[256];
} CryptoSwapVerdict;

/* Compare a copied string with a pasted string. If both are crypto
 * addresses of the same type but different values, this is a clipboard
 * hijack (score 95). Supports BTC, ETH, XMR, SOL, USDT (TRC20),
 * LTC, DOGE, XRP, DASH, XLM, ADA (Cardano).                         */
CryptoSwapVerdict hlse_check_crypto_swap(const char *copied,
                                          const char *pasted);

/* Validate a crypto address format. Returns the detected type,
 * or CRYPTO_NONE (0) if not a recognized address.                     */
int hlse_validate_crypto_address(const char *addr);

#ifdef __cplusplus
}
#endif

#endif /* HLSE_SECRETS_H */
