/*
 * tests/hlse_util_tests.c — Tests for shared utility functions
 *
 * Verifies hlse_shannon_entropy and hlse_edit_distance, which are now
 * the single source of truth for entropy and edit-distance across all
 * HLSE modules.
 *
 * Build: gcc -O2 -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *            -o tests/util_tests tests/hlse_util_tests.c hlse_util.c -I. -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "../hlse_util.h"

static int total = 0, passed = 0, failed = 0;

#define TEST(name) do { total++; printf("  %-52s", name); } while(0)
#define PASS()     do { passed++; printf("PASS\n"); } while(0)
#define FAIL(m)    do { failed++; printf("FAIL — %s\n", m); } while(0)
#define CHECK(c, m) do { if (c) PASS(); else FAIL(m); } while(0)

/* ─── Shannon entropy ─────────────────────────────────────────────────── */

static void test_entropy_empty(void) {
    TEST("entropy: empty string → 0");
    CHECK(hlse_shannon_entropy_str("") == 0.0, "empty must be 0");
}

static void test_entropy_uniform_char(void) {
    TEST("entropy: 'aaaa' (single symbol) → 0");
    CHECK(hlse_shannon_entropy_str("aaaa") == 0.0,
          "single repeated char has 0 entropy");
}

static void test_entropy_two_symbols(void) {
    TEST("entropy: 'abab' (2 symbols equal) → 1.0 bit");
    double e = hlse_shannon_entropy_str("abab");
    CHECK(e > 0.99 && e < 1.01, "two equiprobable symbols = 1 bit");
}

static void test_entropy_random_higher(void) {
    TEST("entropy: random string > brand name");
    double rnd = hlse_shannon_entropy_str("x7k2p9qzr4mw");
    double brand = hlse_shannon_entropy_str("google");
    CHECK(rnd > brand, "random domain must have higher entropy");
}

static void test_entropy_byte_buffer(void) {
    TEST("entropy: byte-buffer API matches string API");
    const char *s = "hello world";
    double a = hlse_shannon_entropy((const unsigned char *)s, strlen(s));
    double b = hlse_shannon_entropy_str(s);
    CHECK(a == b, "byte and string APIs must agree");
}

static void test_entropy_null(void) {
    TEST("entropy: NULL string → 0 (no crash)");
    CHECK(hlse_shannon_entropy_str(NULL) == 0.0, "NULL safe");
}

/* ─── Edit distance ───────────────────────────────────────────────────── */

static void test_edit_identical(void) {
    TEST("edit: identical strings → 0");
    CHECK(hlse_edit_distance("requests", "requests") == 0, "identical = 0");
}

static void test_edit_substitution(void) {
    TEST("edit: 'paypal' vs 'paypa1' → 1 (substitution)");
    CHECK(hlse_edit_distance("paypal", "paypa1") == 1, "one sub = 1");
}

static void test_edit_insertion(void) {
    TEST("edit: 'express' vs 'expresss' → 1 (insertion)");
    CHECK(hlse_edit_distance("express", "expresss") == 1, "one ins = 1");
}

static void test_edit_deletion(void) {
    TEST("edit: 'requests' vs 'requets' → 1 (deletion)");
    CHECK(hlse_edit_distance("requests", "requets") == 1, "one del = 1");
}

static void test_edit_transposition(void) {
    TEST("edit: 'requests' vs 'reqeusts' → 1 (transposition)");
    /* Damerau extension: adjacent swap counts as 1, not 2 */
    CHECK(hlse_edit_distance("requests", "reqeusts") == 1,
          "adjacent transposition = 1 (Damerau)");
}

static void test_edit_empty(void) {
    TEST("edit: '' vs 'abc' → 3");
    CHECK(hlse_edit_distance("", "abc") == 3, "empty to 3-char = 3");
}

static void test_edit_overlong(void) {
    TEST("edit: strings over bound → HLSE_DL_MAX");
    char big[100];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    CHECK(hlse_edit_distance(big, "x") == HLSE_DL_MAX,
          "overlong input returns sentinel");
}

static void test_edit_symmetry(void) {
    TEST("edit: distance is symmetric");
    int ab = hlse_edit_distance("kitten", "sitting");
    int ba = hlse_edit_distance("sitting", "kitten");
    CHECK(ab == ba && ab == 3, "kitten<->sitting = 3 both ways");
}

/* ─── Safe system-file open ───────────────────────────────────────────── */

static void test_sysopen_regular(void) {
    TEST("sysopen: regular file → opens");
    char tmpl[] = "/tmp/hlse_util_reg_XXXXXX";
    int fd = mkstemp(tmpl);
    FILE *fp;
    ssize_t wn;
    if (fd < 0) { FAIL("mkstemp failed"); return; }
    wn = write(fd, "hello\n", 6);
    close(fd);
    if (wn != 6) { unlink(tmpl); FAIL("write failed"); return; }
    fp = hlse_open_system_file(tmpl);
    if (fp) { fclose(fp); unlink(tmpl); PASS(); }
    else { unlink(tmpl); FAIL("regular file should open"); }
}

static void test_sysopen_fifo(void) {
    TEST("sysopen: FIFO → NULL (no block)");
    char path[] = "/tmp/hlse_util_fifo_XXXXXX";
    /* mkstemp then unlink+mkfifo to get a unique FIFO path. */
    int fd = mkstemp(path);
    if (fd < 0) { FAIL("mkstemp failed"); return; }
    close(fd); unlink(path);
    if (mkfifo(path, 0600) != 0) { FAIL("mkfifo failed"); return; }
    /* If the helper blocked, this test would hang; reaching the assert
     * proves O_NONBLOCK + S_ISREG rejected the FIFO without blocking. */
    {
        FILE *fp = hlse_open_system_file(path);
        unlink(path);
        if (!fp) PASS();
        else { fclose(fp); FAIL("FIFO must be rejected"); }
    }
}

static void test_sysopen_directory(void) {
    TEST("sysopen: directory → NULL");
    FILE *fp = hlse_open_system_file("/tmp");
    if (!fp) PASS();
    else { fclose(fp); FAIL("directory must be rejected"); }
}

static void test_sysopen_missing(void) {
    TEST("sysopen: missing path / NULL → NULL (no crash)");
    FILE *fp = hlse_open_system_file("/no/such/hlse/path/xyz");
    int ok = (fp == NULL);
    if (fp) fclose(fp);
    ok = ok && (hlse_open_system_file(NULL) == NULL);
    CHECK(ok, "missing and NULL must return NULL");
}

int main(void) {
    printf("HLSE Util — Shared Utility Tests\n");
    printf("══════════════════════════════════════\n\n");

    printf("Shannon entropy:\n");
    test_entropy_empty();
    test_entropy_uniform_char();
    test_entropy_two_symbols();
    test_entropy_random_higher();
    test_entropy_byte_buffer();
    test_entropy_null();

    printf("\nEdit distance (Damerau-Levenshtein):\n");
    test_edit_identical();
    test_edit_substitution();
    test_edit_insertion();
    test_edit_deletion();
    test_edit_transposition();
    test_edit_empty();
    test_edit_overlong();
    test_edit_symmetry();

    printf("\nSafe system-file open:\n");
    test_sysopen_regular();
    test_sysopen_fifo();
    test_sysopen_directory();
    test_sysopen_missing();

    printf("\n══════════════════════════════════════\n");
    printf("Util tests: %d/%d passed", passed, total);
    if (failed > 0) printf(", %d FAILED", failed);
    printf("\n══════════════════════════════════════\n");
    return failed > 0 ? 1 : 0;
}
