/*
 * tests/hlse_server_fuzz.c
 *
 * Fuzz harness for hlse-server's untrusted-input surface: the JSON request
 * parser (json_get_string) and JSON output escaper (json_escape_append).
 * These are the only parsers in HLSE that consume bytes from a network
 * peer (an HTTP request body), so they get the same fuzzing rigor as the
 * URL/text/secrets/supply/file modules.
 *
 * Uses the same portable smoke-fuzzer approach as hlse_secrets_fuzz.c:
 * deterministic PRNG, signal-handler crash detection, invariant checks
 * (output always NUL-terminated within the caller's buffer).
 *
 * Functions exercised:
 *   json_get_string(json, key, out, outsz)
 *   json_escape_append(dst, cap, len, src)
 *
 * Build (plain):
 *   gcc -O0 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L -DHLSE_CORE_AS_LIB \
 *       -DHLSE_SERVER_NO_MAIN -o tests/fuzz_server tests/hlse_server_fuzz.c \
 *       hlse_core.c hlse_text.c hlse_protect.c hlse_secrets.c hlse_supply.c \
 *       hlse_file.c hlse_audit.c hlse_util.c -I. -lm -lpthread
 * Build (ASan):
 *   (same, +-fsanitize=address,undefined, -o tests/fuzz_server_asan)
 *
 * Usage: ./tests/fuzz_server [iterations] [seed]
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>

#include "../hlse_server.c"

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
    size_t len = xorshift(rng) % (cap - 1);
    size_t i;
    for (i = 0; i < len; i++) buf[i] = (char)(xorshift(rng) & 0xFF);
    buf[len] = '\0';
    return len;
}

/* Syntactically-plausible JSON: balanced/unbalanced braces, valid and
 * invalid escapes, truncated strings — the shapes the parser must survive
 * without crashing even when it correctly rejects them. */
static size_t gen_json_like(char *buf, size_t cap, unsigned long *rng) {
    static const char *frags[] = {
        "{\"url\":\"", "{\"text\":\"", "{\"filename\":\"", "{\"content\":\"",
        "\"}", "\",\"other\":\"x\"}", "\\\"", "\\\\", "\\n", "\\t", "\\u",
        "\\u00", "\\uZZZZ", "\\q", "{", "}", "[", "]", ":", ",",
        "https://paypal.com@evil.xyz", "AKIA2E3MWORQXYZ4567PQ",
        "\xC3\xA9\xE2\x80\x94", /* multi-byte UTF-8 */
        NULL
    };
    int n = 0; while (frags[n]) n++;
    size_t pos = 0;
    int rounds = (int)(xorshift(rng) % 12) + 1, r;
    for (r = 0; r < rounds && pos < cap - 32; r++) {
        const char *f = frags[xorshift(rng) % (unsigned long)n];
        size_t fl = strlen(f);
        if (pos + fl >= cap) break;
        memcpy(buf + pos, f, fl); pos += fl;
    }
    buf[pos] = '\0';
    return pos;
}

/* Well-formed {"<key>":"<random text>"} so the happy path is exercised too,
 * not just malformed/adversarial input. */
static size_t gen_valid_json(char *buf, size_t cap, unsigned long *rng) {
    static const char *keys[] = { "url", "text", "filename", "content" };
    const char *key = keys[xorshift(rng) % 4];
    char value[256];
    size_t vlen = xorshift(rng) % 200;
    size_t i;
    static const char printable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ./@-_";
    for (i = 0; i < vlen; i++)
        value[i] = printable[xorshift(rng) % (sizeof(printable) - 1)];
    value[vlen] = '\0';
    return (size_t)snprintf(buf, cap, "{\"%s\":\"%s\"}", key, value);
}

/* ── Main ─────────────────────────────────────────────────────────────── */

typedef size_t (*gen_fn)(char *, size_t, unsigned long *);

int main(int argc, char **argv) {
    long iterations = (argc > 1) ? atol(argv[1]) : 100000;
    unsigned long seed = (argc > 2) ? (unsigned long)atol(argv[2]) : 0xFEEDFACEUL;
    if (seed == 0) seed = (unsigned long)time(NULL);

    printf("HLSE Server Fuzz Harness (JSON parser + escaper)\n");
    printf("  iterations: %ld\n  seed:       0x%lx\n\n", iterations, seed);

    struct sigaction sa;
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    gen_fn generators[] = { gen_random, gen_json_like, gen_valid_json };
    const int n_gen = (int)(sizeof(generators) / sizeof(generators[0]));
    const char *gen_names[] = { "random bytes", "json-like adversarial", "valid json" };
    static const char *keys[] = { "url", "text", "filename", "content" };

    long crashes = 0, invariant_fail = 0, ok = 0;
    long stats[3] = {0, 0, 0};
    char buf[4096];
    char out[4096];
    char esc[4096];
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
            const char *key = keys[xorshift(&rng) % 4];
            int found;
            size_t esc_len = 0;

            out[0] = '\0';
            found = json_get_string(buf, key, out, sizeof(out));

            /* Invariant: on success, `out` must be a proper C string that
             * fits within the buffer we gave it — the parser must never
             * report success while leaving out[] unterminated. */
            if (found && strnlen(out, sizeof(out)) >= sizeof(out)) {
                invariant_fail++;
                printf("  INVARIANT FAIL (unterminated) gen=%s\n", gen_names[g]);
            } else {
                ok++;
            }

            /* Also fuzz the escaper directly on the same random bytes. */
            esc[0] = '\0';
            json_escape_append(esc, sizeof(esc), &esc_len, buf);
            if (esc_len >= sizeof(esc) || strnlen(esc, sizeof(esc)) >= sizeof(esc)) {
                invariant_fail++;
                printf("  INVARIANT FAIL (escaper overflow) gen=%s\n", gen_names[g]);
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
            printf("  ... %ld iters, ok=%ld crashes=%ld inv_fail=%ld\n",
                   i, ok, crashes, invariant_fail);
    }

    printf("\n=== Fuzz results ===\n");
    printf("  total iterations:   %ld\n", iterations);
    printf("  ok:                 %ld (%.1f%%)\n", ok, 100.0 * ok / iterations);
    printf("  invariant failures: %ld\n", invariant_fail);
    printf("  crashes:            %ld\n", crashes);
    printf("\n  Generator distribution:\n");
    int gi;
    for (gi = 0; gi < n_gen; gi++)
        printf("    %-24s  %ld\n", gen_names[gi], stats[gi]);
    printf("\n");

    if (crashes > 0 || invariant_fail > 0) { printf("FUZZ FAILED\n"); return 1; }
    printf("FUZZ PASSED\n");
    return 0;
}
