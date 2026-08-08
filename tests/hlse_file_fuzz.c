/*
 * tests/hlse_file_fuzz.c
 *
 * Fuzz harness for the file-masquerade module's filename-only path,
 * which requires no disk access and is therefore safe to fuzz with
 * arbitrary byte sequences.
 *
 * Function exercised:
 *   hlse_check_filename(filename)  — double-extension, bidi, lure
 *
 * The disk-reading hlse_check_file() is deliberately excluded: it
 * opens real paths, so random-byte inputs would just return early on
 * ENOENT and cover nothing interesting.
 *
 * Build (plain):
 *   gcc -O0 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *       -o tests/fuzz_file tests/hlse_file_fuzz.c hlse_file.c -I.
 * Build (ASan):
 *   gcc -O1 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *       -fsanitize=address,undefined \
 *       -o tests/fuzz_file_asan tests/hlse_file_fuzz.c hlse_file.c -I.
 *
 * Usage: ./tests/fuzz_file [iterations] [seed]
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include "../hlse_file.h"

static jmp_buf crash_jmp;
static char    last_input[4096];
static size_t  last_input_len;

static void crash_handler(int sig) { (void)sig; longjmp(crash_jmp, 1); }

static unsigned long xorshift(unsigned long *s) {
    unsigned long x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x; return x;
}

/* ── Input generators ─────────────────────────────────────────────────── */

static size_t gen_random(char *buf, size_t cap, unsigned long *rng) {
    /* keep short: filenames are rarely more than 255 bytes */
    size_t len = xorshift(rng) % 256;
    if (len >= cap) len = cap - 1;
    size_t i;
    for (i = 0; i < len; i++) buf[i] = (char)(xorshift(rng) & 0xFF);
    buf[len] = '\0';
    return len;
}

static size_t gen_double_extension(char *buf, size_t cap, unsigned long *rng) {
    static const char *pairs[][2] = {
        {"invoice",     ".pdf.exe"},
        {"report",      ".doc.scr"},
        {"photo",       ".jpg.exe"},
        {"readme",      ".txt.bat"},
        {"setup",       ".zip.exe"},
        {"update",      ".pdf.com"},
        {"document",    ".docx.js"},
        {"attachment",  ".xlsx.vbs"},
        {"contract",    ".pdf.lnk"},
        {"payslip",     ".pdf.ps1"},
    };
    int n = (int)(sizeof(pairs) / sizeof(pairs[0]));
    int idx = (int)(xorshift(rng) % (unsigned long)n);
    int ret = snprintf(buf, cap, "%s%s", pairs[idx][0], pairs[idx][1]);
    if (ret < 0 || (size_t)ret >= cap) { buf[cap - 1] = '\0'; return cap - 1; }
    return (size_t)ret;
}

static size_t gen_bidi(char *buf, size_t cap, unsigned long *rng) {
    /* Right-to-left override U+202E to hide extension */
    static const char *templates[] = {
        "invoice\xe2\x80\xaegnp.exe",   /* U+202E RLO */
        "photo\xe2\x80\xaegpj.exe",
        "document\xe2\x81\xab.exe",      /* U+202B RLE */
        "readme\xef\xbb\xbf.exe",        /* BOM */
        "file\xe2\x80\x8b.exe",          /* ZWSP */
    };
    int n = (int)(sizeof(templates) / sizeof(templates[0]));
    const char *t = templates[xorshift(rng) % (unsigned long)n];
    size_t len = strlen(t);
    if (len >= cap) len = cap - 1;
    memcpy(buf, t, len);
    buf[len] = '\0';
    return len;
}

static size_t gen_lure_name(char *buf, size_t cap, unsigned long *rng) {
    static const char *lures[] = {
        "invoice_final.exe",
        "Bank_Statement_2024.exe",
        "Resume_John_Smith.exe",
        "nude_photos.exe",
        "free_software_crack.exe",
        "PayPal_Receipt.scr",
        "Tax_Return_2023.bat",
        "Your_Package_Tracking.js",
        "NDA_Agreement.vbs",
        "Password_Reset.exe",
        /* safe names */
        "readme.txt",
        "Makefile",
        "main.c",
        "photo.jpg",
        "document.pdf",
        /* edge cases */
        "",
        ".",
        ".exe",
        "a",
        "a.b.c.d.e.f.exe",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.exe",
        NULL
    };
    int n = 0; while (lures[n]) n++;
    const char *l = lures[xorshift(rng) % (unsigned long)n];
    size_t len = strlen(l);
    if (len >= cap) len = cap - 1;
    memcpy(buf, l, len);
    buf[len] = '\0';
    return len;
}

/* ── Main ─────────────────────────────────────────────────────────────── */

typedef size_t (*gen_fn)(char *, size_t, unsigned long *);

int main(int argc, char **argv) {
    long iterations = (argc > 1) ? atol(argv[1]) : 100000;
    unsigned long seed = (argc > 2) ? (unsigned long)atol(argv[2]) : 0xBADC0DEUL;
    if (seed == 0) seed = (unsigned long)time(NULL);

    printf("HLSE File-Masquerade Fuzz Harness\n");
    printf("  iterations: %ld\n  seed:       0x%lx\n\n", iterations, seed);

    struct sigaction sa;
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    gen_fn generators[] = {
        gen_random,
        gen_double_extension,
        gen_bidi,
        gen_lure_name,
    };
    const int n_gen = (int)(sizeof(generators) / sizeof(generators[0]));
    const char *gen_names[] = {
        "random bytes", "double extension", "bidi / control", "lure name"
    };

    long crashes = 0, out_of_range = 0, ok = 0;
    long stats[4] = {0, 0, 0, 0};
    char buf[4096];
    unsigned long rng = seed;

    long i;
    for (i = 0; i < iterations; i++) {
        int g = (int)(xorshift(&rng) % (unsigned long)n_gen);
        size_t len = generators[g](buf, sizeof(buf), &rng);
        (void)len;
        stats[g]++;

        last_input_len = strlen(buf);
        if (last_input_len < sizeof(last_input))
            memcpy(last_input, buf, last_input_len + 1);

        if (setjmp(crash_jmp) == 0) {
            FileVerdict fv = hlse_check_filename(buf);
            if (fv.score < 0 || fv.score > 100) {
                out_of_range++;
                printf("  OUT OF RANGE [%d] gen=%s\n", fv.score, gen_names[g]);
                if (out_of_range >= 5) {
                    printf("  Too many out-of-range scores, aborting.\n");
                    return 1;
                }
            } else {
                ok++;
            }
        } else {
            crashes++;
            printf("  CRASH on iter %ld, generator=%s, input_len=%zu\n",
                   i, gen_names[g], last_input_len);
            printf("  First 64 bytes: ");
            size_t k;
            for (k = 0; k < 64 && k < last_input_len; k++)
                printf("%02x", (unsigned char)last_input[k]);
            printf("\n");
            if (crashes >= 5) { printf("  Too many crashes, aborting.\n"); return 1; }
        }

        if (i > 0 && i % 10000 == 0)
            printf("  ... %ld iters, ok=%ld crashes=%ld oor=%ld\n",
                   i, ok, crashes, out_of_range);
    }

    printf("\n=== Fuzz results ===\n");
    printf("  total iterations:   %ld\n", iterations);
    printf("  ok (in range):      %ld (%.1f%%)\n", ok, 100.0 * ok / iterations);
    printf("  out-of-range score: %ld\n", out_of_range);
    printf("  crashes:            %ld\n", crashes);
    printf("\n  Generator distribution:\n");
    int gi;
    for (gi = 0; gi < n_gen; gi++)
        printf("    %-24s  %ld\n", gen_names[gi], stats[gi]);
    printf("\n");

    if (crashes > 0 || out_of_range > 0) { printf("FUZZ FAILED\n"); return 1; }
    printf("FUZZ PASSED\n");
    return 0;
}
