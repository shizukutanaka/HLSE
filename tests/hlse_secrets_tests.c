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

/* These fixtures assemble each token at RUNTIME from a split prefix + body so
 * the contiguous credential string never appears literally in this source
 * file. That keeps push-protection / secret scanners (incl. GitHub's, which
 * shares the same vendor formats HLSE now detects) from flagging the test
 * data, while hlse_scan_secrets() still sees the fully-joined token. */

static void test_google_api_key(void) {
    TEST("Secret: Google API key (AIza) detected");
    char text[160];
    snprintf(text, sizeof(text), "GOOGLE_API_KEY=%s%s\n",
             "AIza", "SyB1cD3fGh4Jk5lMn6oPq7rStUv8wXyZ0aB");
    SecretVerdict v = hlse_scan_secrets(text);
    if (v.score >= 70 && v.n_findings >= 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d n=%d",v.score,v.n_findings); FAIL(b); }
}

static void test_gitlab_pat(void) {
    TEST("Secret: GitLab PAT (glpat-) detected");
    char text[160];
    snprintf(text, sizeof(text), "token = %s%s\n",
             "glpat-", "Ab3dEf6hIj9lMn2pQr5t");
    SecretVerdict v = hlse_scan_secrets(text);
    if (v.score >= 70 && v.n_findings >= 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d n=%d",v.score,v.n_findings); FAIL(b); }
}

static void test_npm_token(void) {
    TEST("Secret: npm access token (npm_) detected");
    char text[160];
    snprintf(text, sizeof(text), "_authToken=%s%s\n",
             "npm_", "0123456789abcdefghijklmnopqrstuvwxyz");
    SecretVerdict v = hlse_scan_secrets(text);
    if (v.score >= 70 && v.n_findings >= 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d n=%d",v.score,v.n_findings); FAIL(b); }
}

static void test_llm_provider_keys(void) {
    TEST("Secret: OpenAI + Anthropic keys detected");
    char text[256];
    snprintf(text, sizeof(text),
             "OPENAI_API_KEY=%s%s\nANTHROPIC_API_KEY=%s%s\n",
             "sk-proj-", "Ab3dEf6hIj9lMn2pQr5tUv8wXyZ0",
             "sk-ant-", "api03-Ab3dEf6hIj9lMn2pQr5tUv");
    SecretVerdict v = hlse_scan_secrets(text);
    if (v.score >= 80 && v.n_findings >= 2) PASS();
    else { char b[64]; snprintf(b,64,"score=%d n=%d",v.score,v.n_findings); FAIL(b); }
}

static void test_shopify_token(void) {
    TEST("Secret: Shopify access token (shpat_) detected");
    char text[160];
    snprintf(text, sizeof(text), "SHOPIFY_TOKEN=%s%s\n",
             "shpat_", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
    SecretVerdict v = hlse_scan_secrets(text);
    if (v.score >= 70 && v.n_findings >= 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d n=%d",v.score,v.n_findings); FAIL(b); }
}

static void test_aws_temp_key(void) {
    TEST("Secret: AWS temporary (ASIA) key detected");
    char text[160];
    snprintf(text, sizeof(text), "aws_session_token: %s%s\n",
             "ASIA", "2E3MWORQXYZ4567PQ");
    SecretVerdict v = hlse_scan_secrets(text);
    if (v.score >= 70 && v.n_findings >= 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d n=%d",v.score,v.n_findings); FAIL(b); }
}

static void test_extended_provider_tokens(void) {
    /* Second peer-parity batch (HuggingFace/PyPI/Postman/Square/Doppler/
     * Grafana/Linear/NewRelic/Databricks). Tokens assembled at runtime from
     * split prefix+body so the literal never appears in source. */
    struct { const char *pfx; const char *body; } cases[] = {
        { "hf_",                  "abcdefghijklmnopqrstuvwxyzabcdefgh" },
        { "pypi-AgEIcHlwaS5vcmc", "Ab3dEf6hIj9lMn2pQr5tUv8w" },
        { "PMAK-",                "0123456789abcdef01234567" },
        { "sq0atp-",              "0123456789abcdefghijkl" },
        { "dp.pt.",               "0123456789abcdefghijklmnopqrstuvwxyz0123456" },
        { "glsa_",                "0123456789abcdefghijklmnopqrstuv" },
        { "lin_api_",             "0123456789abcdefghijklmnopqrstuvwxyz0123" },
        { "NRAK-",                "0123456789abcdefghijklmnopq" },
        { "dapi",                 "0123456789abcdef0123456789abcdef" },
    };
    size_t i, n = sizeof(cases) / sizeof(cases[0]);
    int fail_idx = -1;

    TEST("Secret: 9 extended provider tokens all detected");
    for (i = 0; i < n; i++) {
        char text[256];
        SecretVerdict v;
        snprintf(text, sizeof(text), "API_TOKEN=%s%s\n",
                 cases[i].pfx, cases[i].body);
        v = hlse_scan_secrets(text);
        if (v.score < 70 || v.n_findings < 1) { fail_idx = (int)i; break; }
    }
    if (fail_idx < 0) PASS();
    else { char b[80]; snprintf(b,80,"undetected: prefix '%s'",
           cases[fail_idx].pfx); FAIL(b); }
}

static void test_discord_webhook(void) {
    TEST("Secret: Discord webhook URL detected");
    char text[200];
    /* Split so the contiguous webhook URL never appears literally in source. */
    snprintf(text, sizeof(text), "WEBHOOK=https://%s%s/%s\n",
             "discord.com/api/webhooks/", "012345678901234567",
             "Ab3dEf6hIj9lMn2pQr5tUv8wXyZ0aB1c2D3e4F5g6H7i8J9k");
    SecretVerdict v = hlse_scan_secrets(text);
    if (v.score >= 70 && v.n_findings >= 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d n=%d",v.score,v.n_findings); FAIL(b); }
}

static void test_new_patterns_no_fp(void) {
    TEST("Secret: new-pattern prefixes in prose → no false positive");
    /* Words/identifiers that share a prefix but are not credentials. */
    SecretVerdict v = hlse_scan_secrets(
        "The npm_config setting and the Asian market and a glpat "
        "report. shppa means nothing here. The dapi endpoint and "
        "glsa group and hf_ tag are all harmless words.\n");
    if (v.score == 0 && v.n_findings == 0) PASS();
    else { char b[80]; snprintf(b,80,"false positive score=%d n=%d",
           v.score,v.n_findings); FAIL(b); }
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

static void test_crypto_vanity_swap(void) {
    TEST("Clipboard: vanity look-alike swap (shared ends) → score 100");
    /* Two distinct ETH addresses sharing first 6 and last 6 hex digits —
     * the deliberate-clipper (EthClipper) signature. */
    CryptoSwapVerdict v = hlse_check_crypto_swap(
        "0xabcdef0000000000000000000000000000c0ffee",
        "0xabcdef1111111111111111111111111111c0ffee");
    if (v.score == 100 && v.is_swap == 1) PASS();
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

static void test_crypto_validate_sol(void) {
    TEST("Validate: Solana base58 (44) is recognized");
    int t = hlse_validate_crypto_address(
        "So11111111111111111111111111111111111111112");
    if (t != 0) PASS();  /* CRYPTO_SOL */
    else FAIL("SOL not recognized");
}

static void test_crypto_sol_swap(void) {
    TEST("Clipboard: SOL address swapped → score 95");
    CryptoSwapVerdict v = hlse_check_crypto_swap(
        "So11111111111111111111111111111111111111112",
        "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
    if (v.score >= 90 && v.is_swap == 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_crypto_validate_garbage(void) {
    TEST("Validate: garbage → CRYPTO_NONE");
    int t = hlse_validate_crypto_address("not-a-crypto-address");
    if (t == 0) PASS();
    else { char b[32]; snprintf(b,32,"type=%d",t); FAIL(b); }
}

static void test_crypto_ltc_swap(void) {
    TEST("Clipboard: LTC address swapped → score 95");
    /* Two structurally valid LTC Legacy addresses (L + 33 base58 chars) */
    CryptoSwapVerdict v = hlse_check_crypto_swap(
        "LaBcDeFgHiJkMnPqRsTuVwXyZ12345678",
        "LzYxWvUtSrQpNmKjHgFeDcBa98765432");
    if (v.score >= 90 && v.is_swap == 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d swap=%d",v.score,v.is_swap); FAIL(b); }
}

static void test_crypto_doge_swap(void) {
    TEST("Clipboard: DOGE address swapped → score 95");
    /* Two structurally valid DOGE addresses (D + 33 base58 chars) */
    CryptoSwapVerdict v = hlse_check_crypto_swap(
        "DaBcDeFgHiJkMnPqRsTuVwXyZ12345678",
        "DzYxWvUtSrQpNmKjHgFeDcBa98765432");
    if (v.score >= 90 && v.is_swap == 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d swap=%d",v.score,v.is_swap); FAIL(b); }
}

static void test_crypto_xrp_swap(void) {
    TEST("Clipboard: XRP address swapped → score 95");
    /* Two structurally valid XRP addresses (r + base58-like, 25-34 chars) */
    CryptoSwapVerdict v = hlse_check_crypto_swap(
        "raBcDeFgHiJkMnPqRsTuVwXyZ12345",
        "rzYxWvUtSrQpNmKjHgFeDcBa98765");
    if (v.score >= 90 && v.is_swap == 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d swap=%d",v.score,v.is_swap); FAIL(b); }
}

static void test_crypto_validate_ltc(void) {
    TEST("Validate: LTC Legacy address recognized");
    int t = hlse_validate_crypto_address("LaBcDeFgHiJkMnPqRsTuVwXyZ12345678");
    if (t != 0) PASS();
    else FAIL("LTC not recognized");
}

static void test_crypto_validate_doge(void) {
    TEST("Validate: DOGE address recognized");
    int t = hlse_validate_crypto_address("DaBcDeFgHiJkMnPqRsTuVwXyZ12345678");
    if (t != 0) PASS();
    else FAIL("DOGE not recognized");
}

static void test_crypto_validate_xrp(void) {
    TEST("Validate: XRP address recognized");
    int t = hlse_validate_crypto_address("raBcDeFgHiJkMnPqRsTuVwXyZ12345");
    if (t != 0) PASS();
    else FAIL("XRP not recognized");
}

static void test_crypto_ada_swap(void) {
    TEST("Clipboard: ADA (addr1) address swapped → score 95");
    /* Two structurally valid Cardano payment addresses (addr1 + 54 bech32 chars) */
    CryptoSwapVerdict v = hlse_check_crypto_swap(
        "addr1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqq0xvwyz3rp8s9x2yy7p",
        "addr1vqpzry9x8gf2tvdw0s3jn54khce6mua7lmqqq0xvwyz3rp8s9x2yy");
    if (v.score >= 90 && v.is_swap == 1) PASS();
    else { char b[64]; snprintf(b,64,"score=%d swap=%d",v.score,v.is_swap); FAIL(b); }
}

static void test_crypto_validate_ada(void) {
    TEST("Validate: Cardano addr1 address recognized");
    int t = hlse_validate_crypto_address(
        "addr1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqq0xvwyz3rp8s9x2yy7p");
    if (t != 0) PASS();
    else FAIL("ADA not recognized");
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
    test_google_api_key();
    test_gitlab_pat();
    test_npm_token();
    test_llm_provider_keys();
    test_shopify_token();
    test_aws_temp_key();
    test_extended_provider_tokens();
    test_discord_webhook();
    test_new_patterns_no_fp();

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
    test_crypto_vanity_swap();
    test_crypto_non_crypto();
    test_crypto_validate_btc();
    test_crypto_validate_eth();
    test_crypto_validate_sol();
    test_crypto_sol_swap();
    test_crypto_ltc_swap();
    test_crypto_doge_swap();
    test_crypto_xrp_swap();
    test_crypto_validate_ltc();
    test_crypto_validate_doge();
    test_crypto_validate_xrp();
    test_crypto_ada_swap();
    test_crypto_validate_ada();
    test_crypto_validate_garbage();

    printf("\n══════════════════════════════════════════\n");
    printf("Secrets tests: %d/%d passed", passed, total);
    if (failed > 0) printf(", %d FAILED", failed);
    printf("\n══════════════════════════════════════════\n");

    return failed > 0 ? 1 : 0;
}
