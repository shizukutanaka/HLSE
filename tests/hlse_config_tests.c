/*
 * tests/hlse_config_tests.c — Tests for the --config file loader
 *
 * Covers hlse_config_load: valid directives, comment/blank handling,
 * every bool spelling, fail-on tiers, from-channel validation, quoted
 * paths, and every hard-error path (unknown key, bad bool, missing
 * value, unterminated quote, unreadable file).
 *
 * Build: gcc -O2 -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *            -o tests/config_tests tests/hlse_config_tests.c hlse_config.c -I.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../hlse_config.h"

static int total = 0, passed = 0, failed = 0;

#define TEST(name) do { total++; printf("  %-52s", name); } while(0)
#define PASS()     do { passed++; printf("PASS\n"); } while(0)
#define FAIL(m)    do { failed++; printf("FAIL — %s\n", m); } while(0)
#define CHECK(c, m) do { if (c) PASS(); else FAIL(m); } while(0)

static char cfgpath[256];
static char err[256];

static void
write_cfg(const char *body) {
    FILE *fp;
    snprintf(cfgpath, sizeof(cfgpath), "/tmp/hlse_cfg_%d.conf", getpid());
    fp = fopen(cfgpath, "w");
    if (fp) { fputs(body, fp); fclose(fp); }
}

static void
cleanup_cfg(void) { unlink(cfgpath); }

/* ─── happy paths ─────────────────────────────────────────────────────── */

static void test_full_config(void) {
    HlseConfig c;
    TEST("config: all keys parse");
    write_cfg("# comment\n\njson = true\nquiet = yes\nfail-on = alert\n"
              "from = sms\nbaseline = /tmp/base.txt\n"
              "log-file = /tmp/log.jsonl\npatterns = /tmp/pats.txt\n"
              "syslog = off\ngit-history = 1\nsarif = no\n"
              "fingerprints = on\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) != 0) { FAIL(err); return; }
    CHECK(c.json == 1 && c.quiet == 1 && c.syslog == 0 &&
          c.git_history == 1 && c.sarif == 0 && c.fingerprints == 1 &&
          c.fail_on == 40 && strcmp(c.from, "sms") == 0 &&
          strcmp(c.baseline, "/tmp/base.txt") == 0 &&
          strcmp(c.log_file, "/tmp/log.jsonl") == 0 &&
          strcmp(c.patterns, "/tmp/pats.txt") == 0, "field mismatch");
    cleanup_cfg();
}

static void test_missing_file(void) {
    HlseConfig c;
    TEST("config: unreadable file -> -1 with message");
    if (hlse_config_load("/nonexistent/hlse.conf", &c, err, sizeof(err)) == -1
        && strstr(err, "cannot read config") != NULL) PASS();
    else FAIL("expected -1 and a 'cannot read' message");
}

static void test_key_value_no_equals(void) {
    HlseConfig c;
    TEST("config: 'key value' without '=' accepted");
    write_cfg("quiet true\nfrom email\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) != 0) { FAIL(err); return; }
    CHECK(c.quiet == 1 && strcmp(c.from, "email") == 0, "parse failed");
    cleanup_cfg();
}

static void test_fail_on_numeric(void) {
    HlseConfig c;
    TEST("config: fail-on numeric 0..100");
    write_cfg("fail-on = 42\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) != 0) { FAIL(err); return; }
    CHECK(c.has_fail_on && c.fail_on == 42, "numeric threshold failed");
    cleanup_cfg();
}

static void test_fail_on_tiers(void) {
    HlseConfig c;
    const char *tiers[] = { "log", "alert", "block", "isolate" };
    int expect[] = { 15, 40, 60, 80 };
    int i, ok = 1;
    TEST("config: fail-on tier names resolve");
    for (i = 0; i < 4; i++) {
        char body[64];
        snprintf(body, sizeof(body), "fail-on = %s\n", tiers[i]);
        write_cfg(body);
        if (hlse_config_load(cfgpath, &c, err, sizeof(err)) != 0 ||
            c.fail_on != expect[i]) ok = 0;
    }
    CHECK(ok, "tier resolution mismatch");
    cleanup_cfg();
}

static void test_bool_spellings(void) {
    HlseConfig c;
    const char *on[]  = { "true", "yes", "on", "1" };
    const char *off[] = { "false", "no", "off", "0" };
    int i, ok = 1;
    TEST("config: every bool spelling");
    for (i = 0; i < 4; i++) {
        char body[64];
        snprintf(body, sizeof(body), "quiet = %s\n", on[i]);
        write_cfg(body);
        if (hlse_config_load(cfgpath, &c, err, sizeof(err)) != 0 || c.quiet != 1)
            ok = 0;
        snprintf(body, sizeof(body), "quiet = %s\n", off[i]);
        write_cfg(body);
        if (hlse_config_load(cfgpath, &c, err, sizeof(err)) != 0 || c.quiet != 0)
            ok = 0;
    }
    CHECK(ok, "bool spelling failed");
    cleanup_cfg();
}

static void test_quoted_path(void) {
    HlseConfig c;
    TEST("config: quoted path with spaces");
    write_cfg("baseline = \"/tmp/dir with space/base.txt\"\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) != 0) { FAIL(err); return; }
    CHECK(strcmp(c.baseline, "/tmp/dir with space/base.txt") == 0,
          "quotes not stripped");
    cleanup_cfg();
}

/* ─── hard errors ─────────────────────────────────────────────────────── */

static void test_unknown_key(void) {
    HlseConfig c;
    TEST("config: unknown key -> hard error");
    write_cfg("frobnicator = true\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) == -1 &&
        strstr(err, "unknown config key") != NULL) PASS();
    else FAIL("unknown key must be an error, not a warning");
    cleanup_cfg();
}

static void test_bad_bool(void) {
    HlseConfig c;
    TEST("config: bad bool -> hard error");
    write_cfg("quiet = maybe\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) == -1) PASS();
    else FAIL("invalid bool accepted");
    cleanup_cfg();
}

static void test_bad_fail_on(void) {
    HlseConfig c;
    TEST("config: fail-on out of range -> hard error");
    write_cfg("fail-on = 101\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) == -1) PASS();
    else FAIL("out-of-range threshold accepted");
    cleanup_cfg();
}

static void test_bad_from(void) {
    HlseConfig c;
    TEST("config: bad from channel -> hard error");
    write_cfg("from = pigeon\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) == -1) PASS();
    else FAIL("invalid channel accepted");
    cleanup_cfg();
}

static void test_missing_value(void) {
    HlseConfig c;
    TEST("config: key with no value -> hard error");
    write_cfg("baseline =\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) == -1) PASS();
    else FAIL("missing value accepted");
    cleanup_cfg();
}

static void test_unterminated_quote(void) {
    HlseConfig c;
    TEST("config: unterminated quote -> hard error");
    write_cfg("baseline = \"/tmp/noclose\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) == -1) PASS();
    else FAIL("unterminated quote accepted");
    cleanup_cfg();
}

static void test_error_has_line_number(void) {
    HlseConfig c;
    TEST("config: errors carry path:line");
    write_cfg("quiet = true\nbogus = 1\n");
    if (hlse_config_load(cfgpath, &c, err, sizeof(err)) == -1 &&
        strstr(err, ":2:") != NULL) PASS();
    else FAIL("no line number in error");
    cleanup_cfg();
}

int
main(void) {
    printf("HLSE config loader tests\n\n");

    test_full_config();
    test_missing_file();
    test_key_value_no_equals();
    test_fail_on_numeric();
    test_fail_on_tiers();
    test_bool_spellings();
    test_quoted_path();
    test_unknown_key();
    test_bad_bool();
    test_bad_fail_on();
    test_bad_from();
    test_missing_value();
    test_unterminated_quote();
    test_error_has_line_number();

    printf("\n══════════════════════════════════════\n");
    printf("Config tests: %d/%d passed", passed, total);
    if (failed > 0) printf(", %d FAILED", failed);
    printf("\n══════════════════════════════════════\n");
    return failed > 0 ? 1 : 0;
}
