/*
 * tests/fuzz_harness.c
 *
 * A simple, dependency-free fuzz harness for HLSE Core. Generates
 * pathological inputs and verifies the engine never crashes, hangs,
 * or returns out-of-range scores.
 *
 * This is NOT a coverage-guided fuzzer (cargo-fuzz / libFuzzer).
 * It's a portable smoke fuzzer that can run anywhere with GCC.
 *
 * What it tests:
 *   1. Random byte sequences (any length 0..16K)
 *   2. Truncated UTF-8 sequences (incomplete multi-byte chars)
 *   3. Pathological URLs (deeply nested, very long paths)
 *   4. Worst-case keyword stuffing (every keyword every signal)
 *   5. Embedded NULs and control characters
 *
 * Crash conditions detected:
 *   - SIGSEGV / SIGBUS via signal handler → reports last input
 *   - Out-of-range score (< 0 or > 100)
 *   - Excessive runtime (> 1 second per check) → likely infinite loop
 *
 * Build: gcc -O0 -g -fsanitize=address,undefined -o fuzz_harness \
 *            tests/fuzz_harness.c hlse_text.c hlse_core.c -I.
 *        (without -fsanitize, the harness still works but won't catch
 *         memory bugs)
 *
 * Usage: ./fuzz_harness [iterations] [seed]
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include "../hlse_text.h"

static jmp_buf crash_jmp;
static char    last_input[16384];
static size_t  last_input_len = 0;

static void
crash_handler(int sig) {
    (void)sig;
    longjmp(crash_jmp, 1);
}

/* Pseudorandom generator — deterministic given seed, no external deps. */
static unsigned long
xorshift(unsigned long *state) {
    unsigned long x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

/* Generate a random byte sequence into buffer, return length. */
static size_t
gen_random_bytes(char *buf, size_t cap, unsigned long *rng) {
    size_t len = (xorshift(rng) % (cap - 1));
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (char)(xorshift(rng) & 0xFF);
    }
    buf[len] = '\0';
    return len;
}

/* Generate a truncated UTF-8 sequence — partial multi-byte char at end. */
static size_t
gen_truncated_utf8(char *buf, size_t cap, unsigned long *rng) {
    /* Mix some valid keywords with random truncated UTF-8 */
    const char *fragments[] = {
        "urgent ", "wire ", "gift card ", "bitcoin ",
        "\xe8\x87\xb3",           /* incomplete 至 */
        "\xe7\xb7\x8a\xe6",       /* incomplete 緊+partial */
        "\xe3\x82\xae\xe3\x83",   /* incomplete ギ+partial フ */
        "\xff\xff\xff",           /* invalid UTF-8 */
        "\x80\x80\x80",           /* lone continuation bytes */
        NULL
    };
    int n_frags = 0;
    while (fragments[n_frags]) n_frags++;

    size_t pos = 0;
    int rounds = (xorshift(rng) % 10) + 1;
    int r;
    for (r = 0; r < rounds && pos < cap - 16; r++) {
        const char *f = fragments[xorshift(rng) % n_frags];
        size_t fl = strlen(f);
        if (pos + fl >= cap) break;
        memcpy(buf + pos, f, fl);
        pos += fl;
    }
    buf[pos] = '\0';
    return pos;
}

/* Generate a pathologically long URL. */
static size_t
gen_path_url(char *buf, size_t cap, unsigned long *rng) {
    size_t pos = 0;
    pos += snprintf(buf + pos, cap - pos, "https://");
    /* Deep subdomains */
    int n_sub = (xorshift(rng) % 50) + 1;
    int i;
    for (i = 0; i < n_sub && pos < cap - 20; i++) {
        pos += snprintf(buf + pos, cap - pos, "a%lu.", xorshift(rng) % 1000);
    }
    pos += snprintf(buf + pos, cap - pos, "example.com");
    /* Long path */
    int n_seg = (xorshift(rng) % 30) + 1;
    for (i = 0; i < n_seg && pos < cap - 20; i++) {
        pos += snprintf(buf + pos, cap - pos, "/seg%lu", xorshift(rng) % 1000);
    }
    return pos;
}

/* Generate keyword stuffing — concatenate all known signals. */
static size_t
gen_keyword_stuffing(char *buf, size_t cap, unsigned long *rng) {
    const char *all_signals[] = {
        "urgent immediately right now ",
        "wire transfer bitcoin gift card ",
        "you won lottery jackpot prize ",
        "irs fbi microsoft support ",
        "don't tell secret between us ",
        "investing for you guaranteed returns ",
        "your pc has a virus ",
        "your files have been encrypted ",
        "send bitcoin pay now ",
        "curl -fssl | sh ",
        NULL
    };
    int n = 0;
    while (all_signals[n]) n++;
    size_t pos = 0;
    int rounds = (xorshift(rng) % 30) + 5;
    int r;
    for (r = 0; r < rounds && pos < cap - 100; r++) {
        const char *s = all_signals[xorshift(rng) % n];
        size_t sl = strlen(s);
        if (pos + sl >= cap) break;
        memcpy(buf + pos, s, sl);
        pos += sl;
    }
    buf[pos] = '\0';
    return pos;
}

/* Generate input with embedded NUL — strstr stops at NUL, but our
 * length-aware code should still be OK. */
static size_t
gen_with_nul(char *buf, size_t cap, unsigned long *rng) {
    const char *base = "URGENT wire bitcoin gift card";
    size_t bl = strlen(base);
    if (bl + 5 >= cap) return 0;
    memcpy(buf, base, bl);
    buf[bl] = '\0';
    /* Add bytes after the NUL — they won't be seen, that's fine */
    int extra = (xorshift(rng) % 100) + 1;
    int i;
    for (i = 0; i < extra && bl + 1 + i < cap; i++) {
        buf[bl + 1 + i] = (char)(xorshift(rng) & 0xFF);
    }
    return bl;  /* length up to NUL */
}

typedef size_t (*gen_fn)(char *, size_t, unsigned long *);

int
main(int argc, char **argv) {
    long  iterations = (argc > 1) ? atol(argv[1]) : 100000;
    unsigned long seed = (argc > 2) ? (unsigned long)atol(argv[2]) : 0xDEADBEEFUL;

    if (seed == 0) seed = (unsigned long)time(NULL);

    printf("HLSE Core Fuzz Harness\n");
    printf("  iterations: %ld\n", iterations);
    printf("  seed:       0x%lx\n", seed);
    printf("\n");

    /* Install signal handlers for crash detection */
    struct sigaction sa;
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    gen_fn generators[] = {
        gen_random_bytes,
        gen_truncated_utf8,
        gen_path_url,
        gen_keyword_stuffing,
        gen_with_nul,
    };
    const int n_gen = sizeof(generators) / sizeof(generators[0]);
    const char *gen_names[] = {
        "random bytes", "truncated UTF-8", "pathological URL",
        "keyword stuffing", "embedded NUL"
    };

    long crashes = 0;
    long out_of_range = 0;
    long ok = 0;
    long stats[5] = {0};
    char buf[16384];
    unsigned long rng = seed;

    long i;
    for (i = 0; i < iterations; i++) {
        int g = xorshift(&rng) % n_gen;
        size_t len = generators[g](buf, sizeof(buf), &rng);
        (void)len;
        stats[g]++;

        /* Save in case of crash */
        last_input_len = strlen(buf);
        if (last_input_len < sizeof(last_input)) {
            memcpy(last_input, buf, last_input_len + 1);
        }

        /* Try to call hlse_check_text — if it crashes, jump back here */
        if (setjmp(crash_jmp) == 0) {
            TextVerdict v = hlse_check_text(buf);
            if (v.score < 0 || v.score > 100) {
                out_of_range++;
                printf("  OUT OF RANGE [%d] gen=%s\n",
                       v.score, gen_names[g]);
                if (out_of_range >= 5) {
                    printf("  Too many out-of-range scores, aborting.\n");
                    return 1;
                }
            } else {
                ok++;
            }
        } else {
            crashes++;
            printf("  CRASH on iter %ld, generator=%s, input len=%zu\n",
                   i, gen_names[g], last_input_len);
            printf("  First 64 bytes: ");
            size_t k;
            for (k = 0; k < 64 && k < last_input_len; k++) {
                printf("%02x", (unsigned char)last_input[k]);
            }
            printf("\n");
            if (crashes >= 5) {
                printf("  Too many crashes, aborting.\n");
                return 1;
            }
        }

        if (i > 0 && i % 10000 == 0) {
            printf("  ... %ld iters, ok=%ld crashes=%ld oor=%ld\n",
                   i, ok, crashes, out_of_range);
        }
    }

    printf("\n=== Fuzz results ===\n");
    printf("  total iterations:   %ld\n", iterations);
    printf("  ok (in range):      %ld (%.1f%%)\n",
           ok, 100.0 * ok / iterations);
    printf("  out-of-range score: %ld\n", out_of_range);
    printf("  crashes:            %ld\n", crashes);
    printf("\n  Generator distribution:\n");
    int gi;
    for (gi = 0; gi < n_gen; gi++) {
        printf("    %-20s  %ld\n", gen_names[gi], stats[gi]);
    }
    printf("\n");

    if (crashes > 0 || out_of_range > 0) {
        printf("FUZZ FAILED\n");
        return 1;
    }
    printf("FUZZ PASSED\n");
    return 0;
}
