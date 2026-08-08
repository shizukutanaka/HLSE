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

/* ─── Benign high-entropy magic bytes ────────────────────────────────── */

static void test_benign_zip(void) {
    TEST("benign-magic: ZIP PK\\x03\\x04 → 1 (regression)");
    unsigned char b[] = {0x50, 0x4B, 0x03, 0x04};
    CHECK(hlse_is_high_entropy_benign_magic(b, 4) == 1, "ZIP must be benign");
}

static void test_benign_lz4(void) {
    TEST("benign-magic: LZ4 frame 04 22 4D 18 → 1");
    unsigned char b[] = {0x04, 0x22, 0x4D, 0x18, 0x60, 0x70};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1, "LZ4 must be benign");
}

static void test_benign_webp(void) {
    TEST("benign-magic: WebP RIFF....WEBP → 1");
    unsigned char b[12] = {
        0x52,0x49,0x46,0x46,  /* RIFF */
        0x00,0x00,0x00,0x00,  /* size (dummy) */
        0x57,0x45,0x42,0x50   /* WEBP */
    };
    CHECK(hlse_is_high_entropy_benign_magic(b, 12) == 1, "WebP must be benign");
}

static void test_benign_flac(void) {
    TEST("benign-magic: FLAC fLaC → 1");
    unsigned char b[] = {0x66, 0x4C, 0x61, 0x43, 0x00, 0x00};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1, "FLAC must be benign");
}

static void test_benign_gif(void) {
    TEST("benign-magic: GIF89a → 1");
    unsigned char b[] = {0x47, 0x49, 0x46, 0x38, 0x39, 0x61};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1, "GIF must be benign");
}

static void test_benign_ogg(void) {
    TEST("benign-magic: OGG OggS → 1");
    unsigned char b[] = {0x4F, 0x67, 0x67, 0x53, 0x00, 0x02};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1, "OGG must be benign");
}

static void test_benign_sqlite(void) {
    TEST("benign-magic: SQLite 'SQLite format 3' → 1");
    unsigned char b[] = {0x53, 0x51, 0x4C, 0x69, 0x74, 0x65};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1, "SQLite must be benign");
}

static void test_benign_mp3_id3(void) {
    TEST("benign-magic: MP3 ID3 tag header → 1");
    unsigned char b[] = {0x49, 0x44, 0x33, 0x03, 0x00, 0x00};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1, "MP3/ID3 must be benign");
}

static void test_benign_tiff_le(void) {
    TEST("benign-magic: TIFF little-endian → 1");
    unsigned char b[] = {0x49, 0x49, 0x2A, 0x00, 0x08, 0x00};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1, "TIFF-LE must be benign");
}

static void test_benign_avi(void) {
    TEST("benign-magic: AVI (RIFF....AVI ) → 1");
    unsigned char b[] = {0x52,0x49,0x46,0x46, 0x00,0x00,0x00,0x00,
                         0x41,0x56,0x49,0x20};
    CHECK(hlse_is_high_entropy_benign_magic(b, 12) == 1, "AVI must be benign");
}

static void test_benign_wav(void) {
    TEST("benign-magic: WAV (RIFF....WAVE) → 1");
    unsigned char b[] = {0x52,0x49,0x46,0x46, 0x00,0x00,0x00,0x00,
                         0x57,0x41,0x56,0x45};
    CHECK(hlse_is_high_entropy_benign_magic(b, 12) == 1, "WAV must be benign");
}

static void test_benign_ebml(void) {
    TEST("benign-magic: EBML/WebM (1A 45 DF A3) → 1");
    unsigned char b[] = {0x1A, 0x45, 0xDF, 0xA3, 0x00, 0x00};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1, "EBML must be benign");
}

static void test_benign_hdf5(void) {
    TEST("benign-magic: HDF5 (89 48 44 46...) → 1");
    unsigned char b[] = {0x89,0x48,0x44,0x46, 0x0D,0x0A,0x1A,0x0A};
    CHECK(hlse_is_high_entropy_benign_magic(b, 8) == 1, "HDF5 must be benign");
}

static void test_benign_parquet(void) {
    TEST("benign-magic: Parquet (PAR1) → 1");
    unsigned char b[] = {0x50, 0x41, 0x52, 0x31, 0x00};
    CHECK(hlse_is_high_entropy_benign_magic(b, 5) == 1, "Parquet must be benign");
}

static void test_benign_otf_font(void) {
    TEST("benign-magic: OpenType font (OTTO) → 1");
    unsigned char b[] = {0x4F, 0x54, 0x54, 0x4F, 0x00, 0x10};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1,
          "OTF font must be benign");
}

static void test_benign_woff(void) {
    TEST("benign-magic: WOFF web font (wOFF) → 1");
    unsigned char b[] = {0x77, 0x4F, 0x46, 0x46, 0x00, 0x01};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1,
          "WOFF must be benign");
}

static void test_benign_der_cert(void) {
    TEST("benign-magic: DER X.509 certificate (30 82) → 1");
    unsigned char b[] = {0x30, 0x82, 0x04, 0xC0, 0x30, 0x82};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 1,
          "DER certificate must be benign");
}

static void test_benign_random(void) {
    TEST("benign-magic: random-looking bytes → 0");
    unsigned char b[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    CHECK(hlse_is_high_entropy_benign_magic(b, 6) == 0,
          "unknown bytes must not be whitelisted");
}

static void test_sysopen_missing(void) {
    TEST("sysopen: missing path / NULL → NULL (no crash)");
    FILE *fp = hlse_open_system_file("/no/such/hlse/path/xyz");
    int ok = (fp == NULL);
    if (fp) fclose(fp);
    ok = ok && (hlse_open_system_file(NULL) == NULL);
    CHECK(ok, "missing and NULL must return NULL");
}

static void test_json_escape_basic(void) {
    char out[64];
    TEST("json_escape: quote/backslash escaped");
    hlse_json_escape("a\"b\\c", out, sizeof out);
    CHECK(strcmp(out, "a\\\"b\\\\c") == 0, out);
}

static void test_json_escape_control(void) {
    char out[64];
    TEST("json_escape: newline/tab/control -> \\n\\t\\u00XX");
    hlse_json_escape("x\ny\tz\x01", out, sizeof out);
    CHECK(strcmp(out, "x\\ny\\tz\\u0001") == 0, out);
}

static void test_json_escape_bounded(void) {
    char out[8];
    TEST("json_escape: truncates within bounds, always NUL-terminated");
    hlse_json_escape("AAAAAAAAAAAAAAAAAAAA", out, sizeof out);
    CHECK(strlen(out) < sizeof out, "overflow");
}

static void test_crc32_known_vector(void) {
    TEST("crc32: \"123456789\" -> 0xCBF43926 (standard vector)");
    CHECK(hlse_crc32((const unsigned char *)"123456789", 9) == 0xCBF43926UL,
          "crc mismatch");
}

static void test_crc32_empty(void) {
    TEST("crc32: empty input -> 0");
    CHECK(hlse_crc32((const unsigned char *)"", 0) == 0UL, "nonzero");
}

static void test_base62_6_padding(void) {
    char out[7];
    TEST("base62_6: pads to exactly 6 digits");
    hlse_base62_6(0, out);
    CHECK(strcmp(out, "000000") == 0 && strlen(out) == 6, out);
}

static void test_base62_6_radix(void) {
    char out[7];
    TEST("base62_6: 62 -> '000010' (radix boundary)");
    hlse_base62_6(62, out);
    CHECK(strcmp(out, "000010") == 0, out);
}

static void test_chi_square_perfect_uniform(void) {
    unsigned char buf[2560];
    int i;
    TEST("chi_square: perfectly flat histogram -> 0");
    for (i = 0; i < 2560; i++) buf[i] = (unsigned char)(i % 256);
    CHECK(hlse_chi_square_uniform(buf, sizeof buf) < 0.0001, "not ~0");
}

static void test_chi_square_degenerate(void) {
    unsigned char buf[2560];
    TEST("chi_square: single-symbol buffer -> very large");
    memset(buf, 'A', sizeof buf);
    CHECK(hlse_chi_square_uniform(buf, sizeof buf) > 100000.0, "too small");
}

static void test_chi_square_small_sample(void) {
    unsigned char buf[256];
    TEST("chi_square: sample under 1280 bytes -> -1 (not meaningful)");
    memset(buf, 0, sizeof buf);
    CHECK(hlse_chi_square_uniform(buf, sizeof buf) < 0.0, "should be -1");
}

static void test_chi_square_null(void) {
    TEST("chi_square: NULL input -> -1 (no crash)");
    CHECK(hlse_chi_square_uniform(NULL, 4096) < 0.0, "should be -1");
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

    printf("\nBenign high-entropy magic bytes:\n");
    test_benign_zip();
    test_benign_lz4();
    test_benign_webp();
    test_benign_flac();
    test_benign_gif();
    test_benign_ogg();
    test_benign_sqlite();
    test_benign_mp3_id3();
    test_benign_tiff_le();
    test_benign_avi();
    test_benign_wav();
    test_benign_ebml();
    test_benign_hdf5();
    test_benign_parquet();
    test_benign_otf_font();
    test_benign_woff();
    test_benign_der_cert();
    test_benign_random();

    printf("\nSafe system-file open:\n");
    test_sysopen_regular();
    test_sysopen_fifo();
    test_sysopen_directory();
    test_sysopen_missing();
    test_json_escape_basic();
    test_json_escape_control();
    test_json_escape_bounded();
    test_crc32_known_vector();
    test_crc32_empty();
    test_base62_6_padding();
    test_base62_6_radix();
    test_chi_square_perfect_uniform();
    test_chi_square_degenerate();
    test_chi_square_small_sample();
    test_chi_square_null();

    printf("\n══════════════════════════════════════\n");
    printf("Util tests: %d/%d passed", passed, total);
    if (failed > 0) printf(", %d FAILED", failed);
    printf("\n══════════════════════════════════════\n");
    return failed > 0 ? 1 : 0;
}
