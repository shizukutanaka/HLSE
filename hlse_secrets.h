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
