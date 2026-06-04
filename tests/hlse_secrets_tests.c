/*
 * tests/hlse_secrets_tests.c — Tests for secrets, email, clipboard modules
 *
 * Build: gcc -O2 -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *            -o tests/secrets_tests tests/hlse_secrets_tests.c \
 *            hlse_secrets.c -I.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include "../hlse_secrets.h"

static int total = 0, passed = 0, failed = 0;
#define TEST(n) do { total++; printf("  %-55s", n); fflush(stdout); } while(0)
#define PASS()  do { passed++; printf("PASS\n"); } while(0)
#define FAIL(m) do { failed++; printf("FAIL — %s\n", m); } while(0)

/* ─── Secret Scanner ──────────────────────────────────────────────────── */

static void test_aws_key(void) {
    TEST("Secret: AWS access key detected");
    /* Realistic-looking key (NOT the AWS doc example AKIAIOSFODNN7EXAMPLE,
     * which is intentionally excluded as a placeholder). */
    SecretVerdict v = hlse_scan_secrets(
        "aws_access_key_id = AKIA2E3MWORQXYZ4567PQ\n");
    if (v.score >= 70 && v.n_findings >= 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d n=%d",v.score,v.n_findings); FAIL(b); }
}

static void test_aws_example_key_excluded(void) {
    TEST("Secret: AWS doc example key (AKIAIOSFODNN7EXAMPLE) excluded");
    /* AWS's own documentation key must NOT be flagged — classic FP
     * documented in arXiv 2307.00714 / 2410.23657. */
    SecretVerdict v = hlse_scan_secrets(
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n");
    if (v.score == 0) PASS();
    else { char b[64]; snprintf(b,64,"false positive score=%d",v.score); FAIL(b); }
}

static void test_placeholder_excluded(void) {
    TEST("Secret: placeholder 'your_api_key_here' excluded");
    SecretVerdict v = hlse_scan_secrets("api_key = your_api_key_here\n");
    if (v.score == 0) PASS();
    else { char b[64]; snprintf(b,64,"false positive score=%d",v.score); FAIL(b); }
}

static void test_github_pat(void) {
    TEST("Secret: GitHub PAT detected");
    SecretVerdict v = hlse_scan_secrets(
        "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n");
    if (v.score >= 80 && v.n_findings >= 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_stripe_live(void) {
    TEST("Secret: Stripe live key detected");
    SecretVerdict v = hlse_scan_secrets(
        "STRIPE_KEY=sk_" "live_4eC39HqLyjWDarjtT1zdp7dc\n");
    if (v.score >= 90) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_ssh_private_key(void) {
    TEST("Secret: SSH private key detected");
    SecretVerdict v = hlse_scan_secrets(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF...\n"
        "-----END RSA PRIVATE KEY-----\n");
    if (v.score >= 90) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_env_password(void) {
    TEST("Secret: .env PASSWORD= detected");
    SecretVerdict v = hlse_scan_secrets(
        "DATABASE_URL=postgres://localhost:5432/mydb\n"
        "DB_PASSWORD=hunter2secretpassword\n"
        "DEBUG=true\n");
    if (v.score >= 60) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_clean_code(void) {
    TEST("Secret: clean code → no findings");
    SecretVerdict v = hlse_scan_secrets(
        "#include <stdio.h>\n"
        "int main(void) {\n"
        "    printf(\"Hello world\\n\");\n"
        "    return 0;\n"
        "}\n");
    if (v.n_findings == 0 && v.score == 0) PASS();
    else { char b[64]; snprintf(b,64,"score=%d n=%d",v.score,v.n_findings); FAIL(b); }
}

static void test_slack_token(void) {
    TEST("Secret: Slack bot token detected");
    SecretVerdict v = hlse_scan_secrets(
        "SLACK_TOKEN=xoxb-1234567890-abcdefghij\n");
    if (v.score >= 70) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_generic_hex(void) {
    TEST("Secret: generic high-entropy value after 'key':");
    SecretVerdict v = hlse_scan_secrets(
        "{\"api_key\": \"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0\"}");
    if (v.score >= 50) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

/* ─── Email Forensics ─────────────────────────────────────────────────── */

static void test_email_clean(void) {
    TEST("Email: legitimate headers → low score");
    EmailVerdict v = hlse_check_email_headers(
        "From: Alice Smith <alice@company.com>\n"
        "To: bob@company.com\n"
        "Subject: Q3 report\n"
        "Date: Mon, 5 May 2026 10:00:00 +0000\n");
    if (v.score < 40) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_email_display_name_spoof(void) {
    TEST("Email: display name spoofing (Microsoft + gmail)");
    EmailVerdict v = hlse_check_email_headers(
        "From: Microsoft Support <hacker123@gmail.com>\n"
        "To: victim@company.com\n"
        "Subject: Account verification needed\n");
    if (v.score >= 40) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_email_reply_to_mismatch(void) {
    TEST("Email: Reply-To domain ≠ From domain");
    EmailVerdict v = hlse_check_email_headers(
        "From: CEO <ceo@company.com>\n"
        "Reply-To: ceo-real@attacker.xyz\n"
        "Subject: Wire transfer needed\n");
    if (v.score >= 25) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_email_spf_fail(void) {
    TEST("Email: SPF + DKIM fail");
    EmailVerdict v = hlse_check_email_headers(
        "From: noreply@bigbank.com\n"
        "Authentication-Results: mx.google.com; spf=fail; dkim=fail\n"
        "Subject: Verify your account\n");
    if (v.score >= 40) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_email_ceo_gmail_urgent(void) {
    TEST("Email: CEO title + gmail + urgent subject (BEC)");
    EmailVerdict v = hlse_check_email_headers(
        "From: \"CEO John\" <john.ceo.real@gmail.com>\n"
        "Subject: URGENT: Wire transfer needed ASAP\n"
        "To: accounting@company.com\n");
    if (v.score >= 50) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

/* ─── Clipboard Crypto-Swap ───────────────────────────────────────────── */

static void test_crypto_no_swap(void) {
    TEST("Clipboard: same BTC address → no swap");
    CryptoSwapVerdict v = hlse_check_crypto_swap(
        "bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5",
        "bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5");
    if (v.score == 0 && v.is_swap == 0) PASS();
    else { char b[64]; snprintf(b,64,"score=%d swap=%d",v.score,v.is_swap); FAIL(b); }
}

static void test_crypto_btc_swap(void) {
    TEST("Clipboard: BTC address swapped → score 95");
    CryptoSwapVerdict v = hlse_check_crypto_swap(
        "bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5",
        "bc1q9h6tq358tcssvfjafy2dajfu7lk6f35c9cn3t2");
    if (v.score >= 90 && v.is_swap == 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d swap=%d",v.score,v.is_swap); FAIL(b); }
}

static void test_crypto_eth_swap(void) {
    TEST("Clipboard: ETH address swapped → score 95");
    CryptoSwapVerdict v = hlse_check_crypto_swap(
        "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD44",
        "0xDeaDBeef00000000000000000000000000001234");
    if (v.score >= 90 && v.is_swap == 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_crypto_non_crypto(void) {
    TEST("Clipboard: non-crypto text → score 0");
    CryptoSwapVerdict v = hlse_check_crypto_swap(
        "Hello world", "Hello world");
    if (v.score == 0) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_crypto_validate_btc(void) {
    TEST("Validate: bc1q... is BTC SegWit");
    int t = hlse_validate_crypto_address(
        "bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5");
    if (t != 0) PASS();  /* CRYPTO_BTC_SEGWIT */
    else FAIL("not recognized");
}

static void test_crypto_validate_eth(void) {
    TEST("Validate: 0x... is ETH");
    int t = hlse_validate_crypto_address(
        "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD44");
    if (t != 0) PASS();
    else FAIL("not recognized");
}

static void test_crypto_validate_garbage(void) {
    TEST("Validate: garbage → CRYPTO_NONE");
    int t = hlse_validate_crypto_address("not-a-crypto-address");
    if (t == 0) PASS();
    else { char b[32]; snprintf(b,32,"type=%d",t); FAIL(b); }
}

/* ─── Main ────────────────────────────────────────────────────────────── */

int main(void) {
    printf("HLSE Secrets / Email / Clipboard — Tests\n");
    printf("══════════════════════════════════════════\n\n");

    printf("Secret Scanner:\n");
    test_aws_key();
    test_aws_example_key_excluded();
    test_placeholder_excluded();
    test_github_pat();
    test_stripe_live();
    test_ssh_private_key();
    test_env_password();
    test_clean_code();
    test_slack_token();
    test_generic_hex();

    printf("\nEmail Forensics:\n");
    test_email_clean();
    test_email_display_name_spoof();
    test_email_reply_to_mismatch();
    test_email_spf_fail();
    test_email_ceo_gmail_urgent();

    printf("\nClipboard Crypto-Swap:\n");
    test_crypto_no_swap();
    test_crypto_btc_swap();
    test_crypto_eth_swap();
    test_crypto_non_crypto();
    test_crypto_validate_btc();
    test_crypto_validate_eth();
    test_crypto_validate_garbage();

    printf("\n══════════════════════════════════════════\n");
    printf("Secrets tests: %d/%d passed", passed, total);
    if (failed > 0) printf(", %d FAILED", failed);
    printf("\n══════════════════════════════════════════\n");

    return failed > 0 ? 1 : 0;
}
