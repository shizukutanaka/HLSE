/*
 * tests/hlse_server_tests.c — Unit tests for the HLSE HTTP server's
 * untrusted-input surfaces: the JSON string extractor and the JSON output
 * escaper. The server's main() is compiled out (HLSE_SERVER_NO_MAIN) so we
 * can exercise its static helpers directly.
 *
 * Build (see Makefile `$(SERVER_TEST)`):
 *   cc -DHLSE_CORE_AS_LIB -DHLSE_SERVER_NO_MAIN -o tests/server_tests \
 *      tests/hlse_server_tests.c <core srcs> -I. -lm
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "../hlse_server.c"

static int total = 0, passed = 0, failed = 0;
#define TEST(n) do { total++; printf("  %-56s", n); fflush(stdout); } while(0)
#define PASS()  do { passed++; printf("PASS\n"); } while(0)
#define FAIL(m) do { failed++; printf("FAIL — %s\n", m); } while(0)

static void t_json_basic(void) {
    char out[256];
    TEST("json: extract simple string field");
    if (json_get_string("{\"url\":\"https://x.com\"}", "url", out, sizeof(out))
        && strcmp(out, "https://x.com") == 0) PASS();
    else FAIL(out);
}

static void t_json_whitespace(void) {
    char out[256];
    TEST("json: tolerate whitespace around colon");
    if (json_get_string("{ \"text\" :   \"hi\" }", "text", out, sizeof(out))
        && strcmp(out, "hi") == 0) PASS();
    else FAIL(out);
}

static void t_json_escapes(void) {
    char out[256];
    TEST("json: decode \\n \\t \\\" \\\\ escapes");
    if (json_get_string("{\"text\":\"a\\nb\\tc\\\"d\\\\e\"}", "text", out, sizeof(out))
        && strcmp(out, "a\nb\tc\"d\\e") == 0) PASS();
    else FAIL(out);
}

static void t_json_unicode(void) {
    char out[256];
    TEST("json: decode \\u0041 -> 'A' and BMP UTF-8");
    if (json_get_string("{\"text\":\"\\u0041\\u00e9\"}", "text", out, sizeof(out))
        && (unsigned char)out[0] == 'A'
        && (unsigned char)out[1] == 0xC3 && (unsigned char)out[2] == 0xA9) PASS();
    else FAIL("bad decode");
}

static void t_json_missing(void) {
    char out[256];
    TEST("json: missing field -> failure");
    if (!json_get_string("{\"other\":\"x\"}", "url", out, sizeof(out))) PASS();
    else FAIL("should have failed");
}

static void t_json_unterminated(void) {
    char out[256];
    TEST("json: unterminated string -> failure");
    if (!json_get_string("{\"url\":\"abc", "url", out, sizeof(out))) PASS();
    else FAIL("should have failed");
}

static void t_json_bad_escape(void) {
    char out[256];
    TEST("json: invalid escape -> failure");
    if (!json_get_string("{\"url\":\"a\\qb\"}", "url", out, sizeof(out))) PASS();
    else FAIL("should have failed");
}

static void t_json_key_substring(void) {
    char out[256];
    /* "surl" must not match a search for "url" (needle includes quotes). */
    TEST("json: key match is quote-anchored");
    if (json_get_string("{\"surl\":\"no\",\"url\":\"yes\"}", "url", out, sizeof(out))
        && strcmp(out, "yes") == 0) PASS();
    else FAIL(out);
}

static void t_json_truncation_safe(void) {
    char out[8];
    TEST("json: output truncation stays in bounds");
    /* A long value into a tiny buffer must not overflow. */
    json_get_string("{\"url\":\"AAAAAAAAAAAAAAAAAAAA\"}", "url", out, sizeof(out));
    if (strlen(out) < sizeof(out)) PASS();
    else FAIL("overflow");
}

static void t_escape_output(void) {
    char buf[128]; size_t len = 0;
    buf[0] = '\0';
    TEST("json escape: quotes/newline/control escaped");
    json_escape_append(buf, sizeof(buf), &len, "a\"b\nc\x01");
    if (strcmp(buf, "a\\\"b\\nc\\u0001") == 0) PASS();
    else FAIL(buf);
}

static void t_escape_bound(void) {
    char buf[8]; size_t len = 0;
    buf[0] = '\0';
    TEST("json escape: respects buffer cap");
    json_escape_append(buf, sizeof(buf), &len, "aaaaaaaaaaaaaaaaaa");
    if (len < sizeof(buf)) PASS();
    else FAIL("overflow");
}

/* rate_limit_check() tests. Each test uses a distinct fake IP so the shared
 * g_rate_buckets table (module-global, since we #include hlse_server.c
 * directly) doesn't cross-contaminate between tests. */

static void t_rate_fresh_ip_allowed(void) {
    TEST("rate limit: fresh IP allowed");
    if (rate_limit_check("10.0.0.1")) PASS();
    else FAIL("first request from a new IP was rejected");
}

static void t_rate_burst_within_limit(void) {
    int i, ok = 1;
    TEST("rate limit: RATE_LIMIT_MAX requests all allowed");
    for (i = 0; i < RATE_LIMIT_MAX; i++) {
        if (!rate_limit_check("10.0.0.2")) { ok = 0; break; }
    }
    if (ok) PASS();
    else FAIL("a request within the limit was rejected");
}

static void t_rate_exceeds_limit(void) {
    int i;
    TEST("rate limit: request beyond RATE_LIMIT_MAX is rejected");
    for (i = 0; i < RATE_LIMIT_MAX; i++) rate_limit_check("10.0.0.3");
    if (!rate_limit_check("10.0.0.3")) PASS();
    else FAIL("the over-limit request was allowed");
}

static void t_rate_per_ip_isolation(void) {
    int i;
    TEST("rate limit: exhausting one IP doesn't affect another");
    for (i = 0; i < RATE_LIMIT_MAX; i++) rate_limit_check("10.0.0.4");
    (void)rate_limit_check("10.0.0.4"); /* exhaust it */
    if (rate_limit_check("10.0.0.5")) PASS();
    else FAIL("a different IP was incorrectly rate-limited");
}

int main(void) {
    printf("HLSE Server — JSON parser / escaper / rate-limit tests\n");
    printf("══════════════════════════════════════════\n\n");
    t_json_basic();
    t_json_whitespace();
    t_json_escapes();
    t_json_unicode();
    t_json_missing();
    t_json_unterminated();
    t_json_bad_escape();
    t_json_key_substring();
    t_json_truncation_safe();
    t_escape_output();
    t_escape_bound();
    t_rate_fresh_ip_allowed();
    t_rate_burst_within_limit();
    t_rate_exceeds_limit();
    t_rate_per_ip_isolation();
    printf("\n══════════════════════════════════════════\n");
    printf("Server tests: %d/%d passed", passed, total);
    if (failed) printf(", %d FAILED", failed);
    printf("\n══════════════════════════════════════════\n");
    return failed ? 1 : 0;
}
