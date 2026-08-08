/*
 * tests/hlse_secrets_fuzz.c
 *
 * Fuzz harness for the secrets module: credential scanning,
 * email header forensics, and clipboard crypto-swap detection.
 *
 * Uses the same portable smoke-fuzzer approach as hlse_fuzz.c:
 * deterministic PRNG, signal-handler crash detection, score range checks.
 *
 * Functions exercised:
 *   hlse_scan_secrets(text)
 *   hlse_check_email_headers(raw_headers)
 *   hlse_check_crypto_swap(copied, pasted)
 *   hlse_validate_crypto_address(addr)
 *
 * Build (plain):
 *   gcc -O0 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *       -o tests/fuzz_secrets tests/hlse_secrets_fuzz.c hlse_secrets.c -I.
 * Build (ASan):
 *   gcc -O1 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *       -fsanitize=address,undefined \
 *       -o tests/fuzz_secrets_asan tests/hlse_secrets_fuzz.c hlse_secrets.c -I.
 *
 * Usage: ./tests/fuzz_secrets [iterations] [seed]
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include "../hlse_secrets.h"

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

static size_t gen_credential_fragments(char *buf, size_t cap, unsigned long *rng) {
    static const char *frags[] = {
        "AKIA", "AKID", "AKIT", "ASIA",
        "ghp_", "github_pat_", "ghs_", "ghr_",
        "sk_live_", "sk_test_", "rk_live_",
        "xoxb-", "xoxp-", "xoxa-",
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "-----BEGIN EC PRIVATE KEY-----\n",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "password=", "passwd=", "secret=", "token=", "api_key=",
        "EXAMPLE", "REDACTED", "your_key_here", "changeme",
        "AAAAB3NzaC1yc2E",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        NULL
    };
    int n = 0; while (frags[n]) n++;
    size_t pos = 0;
    int rounds = (int)(xorshift(rng) % 8) + 1, r;
    for (r = 0; r < rounds && pos < cap - 128; r++) {
        const char *f = frags[xorshift(rng) % (unsigned long)n];
        size_t fl = strlen(f);
        if (pos + fl >= cap) break;
        memcpy(buf + pos, f, fl); pos += fl;
        /* append random alphanum suffix */
        int slen = (int)(xorshift(rng) % 40), j;
        static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        for (j = 0; j < slen && pos < cap - 2; j++)
            buf[pos++] = alpha[xorshift(rng) % (sizeof(alpha) - 1)];
        buf[pos++] = '\n';
    }
    buf[pos] = '\0';
    return pos;
}

static size_t gen_email_headers(char *buf, size_t cap, unsigned long *rng) {
    static const char *lines[] = {
        "From: CEO <ceo@evil.com>\r\n",
        "From: \"CEO\" <boss@evil.net>\r\n",
        "Reply-To: attacker@gmail.com\r\n",
        "To: victim@corp.com\r\n",
        "Subject: URGENT wire transfer needed\r\n",
        "Subject: Invoice payment required immediately\r\n",
        "Received-SPF: fail (domain does not designate)\r\n",
        "Authentication-Results: dkim=fail header.d=corp.com\r\n",
        "Authentication-Results: spf=pass smtp.mailfrom=corp.com\r\n",
        "DKIM-Signature: v=1; a=rsa-sha256; d=evil.com;\r\n",
        "X-Mailer: PHP/7.4\r\n",
        "X-Originating-IP: 198.51.100.1\r\n",
        "\r\n",
        NULL
    };
    int n = 0; while (lines[n]) n++;
    size_t pos = 0;
    int rounds = (int)(xorshift(rng) % 10) + 2, r;
    for (r = 0; r < rounds && pos < cap - 128; r++) {
        const char *l = lines[xorshift(rng) % (unsigned long)n];
        size_t ll = strlen(l);
        if (pos + ll >= cap) break;
        memcpy(buf + pos, l, ll); pos += ll;
    }
    buf[pos] = '\0';
    return pos;
}

static const char *CRYPTO_ADDRS[] = {
    /* BTC bech32 */
    "bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5",
    "bc1q42lja79elem0anu8q8s3h2n687re9jax556pnm",
    /* BTC legacy */
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    /* ETH */
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BA",
    /* XMR */
    "46BeWrHpwXmHDpDEUmZBWZfoQpdc6HaERCNmx1pEYL2rAcuwufPN9rXHHtyUA4QVy31jdHfchdTYEa3fKE2Y8hPFHL75Hy",
    /* SOL */
    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    /* USDT */
    "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    /* Random junk */
    "notanaddress",
    "0x",
    "",
    "bc1",
    NULL
};

static size_t gen_crypto_addr(char *buf, size_t cap, unsigned long *rng) {
    int n = 0; while (CRYPTO_ADDRS[n]) n++;
    const char *addr = CRYPTO_ADDRS[xorshift(rng) % (unsigned long)n];
    size_t len = strlen(addr);
    if (len >= cap) len = cap - 1;
    memcpy(buf, addr, len);
    /* optionally corrupt one byte */
    if (len > 4 && xorshift(rng) % 3 == 0) {
        size_t pos = xorshift(rng) % len;
        buf[pos] = (char)(xorshift(rng) & 0xFF);
    }
    buf[len] = '\0';
    return len;
}

/* ── Main ─────────────────────────────────────────────────────────────── */

typedef size_t (*gen_fn)(char *, size_t, unsigned long *);

int main(int argc, char **argv) {
    long iterations = (argc > 1) ? atol(argv[1]) : 100000;
    unsigned long seed = (argc > 2) ? (unsigned long)atol(argv[2]) : 0xFEEDFACEUL;
    if (seed == 0) seed = (unsigned long)time(NULL);

    printf("HLSE Secrets Fuzz Harness\n");
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
        gen_credential_fragments,
        gen_email_headers,
        gen_crypto_addr,
    };
    const int n_gen = (int)(sizeof(generators) / sizeof(generators[0]));
    const char *gen_names[] = {
        "random bytes", "credential fragments",
        "email headers", "crypto address"
    };

    long crashes = 0, out_of_range = 0, ok = 0;
    long stats[4] = {0, 0, 0, 0};
    char buf[16384];
    char buf2[16384];
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

            if (g == 0 || g == 1) {
                /* scan text for secrets */
                SecretVerdict sv = hlse_scan_secrets(buf);
                score = sv.score;
            } else if (g == 2) {
                /* email header forensics */
                EmailVerdict ev = hlse_check_email_headers(buf);
                score = ev.score;
            } else {
                /* crypto swap: same addr vs slightly modified */
                gen_crypto_addr(buf2, sizeof(buf2), &rng);
                CryptoSwapVerdict cv = hlse_check_crypto_swap(buf, buf2);
                score = cv.score;
                /* also exercise standalone validator */
                (void)hlse_validate_crypto_address(buf);
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
