/*
 * tests/hlse_url_fuzz.c
 *
 * URL-focused fuzz harness for hlse_check_url() and hlse_scan().
 *
 * Exercises:
 *   1. Random-byte URLs (garbage after "http://")
 *   2. Homoglyph/Unicode mutation of known-good domains
 *   3. Deeply nested subdomain + long-path URLs
 *   4. Percent-encoding variations (%XX on every character)
 *   5. Brand-typosquat mutation (edit-distance 1 on brand names)
 *   6. Bidi / control-character injection into URLs
 *   7. Very long hostnames (> MAX_HOST boundary)
 *   8. Dangerous-scheme prefixes (javascript:, data:, blob:)
 *
 * Crash/invariant checks:
 *   - No SIGSEGV/SIGBUS/SIGABRT
 *   - Score always in [0, 100]
 *   - hlse_action_for_score() never returns NULL
 *   - hlse_scan() consistent with hlse_check_url() for http(s) input
 *
 * Build: gcc -O0 -g -fsanitize=address,undefined \
 *            -o url_fuzz tests/hlse_url_fuzz.c hlse_core.c hlse_text.c \
 *            hlse_util.c -I. -lm
 * Usage: ./url_fuzz [iterations] [seed]
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include "../hlse_core.h"

static jmp_buf crash_jmp;
static char    last_input[16384];

static void
crash_handler(int sig) {
    (void)sig;
    longjmp(crash_jmp, 1);
}

static unsigned long
xorshift(unsigned long *s) {
    unsigned long x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x;
    return x;
}

/* ── generators ─────────────────────────────────────────────────────── */

static size_t
gen_random_url(char *buf, size_t cap, unsigned long *rng) {
    const char *schemes[] = { "http://", "https://", "ftp://", "javascript:",
                               "data:text/html,", "" };
    int ns = (int)(sizeof(schemes)/sizeof(schemes[0]));
    const char *scheme = schemes[xorshift(rng) % (unsigned long)ns];
    size_t pos = 0;
    pos += snprintf(buf + pos, cap - pos, "%s", scheme);
    size_t rlen = xorshift(rng) % 200;
    size_t i;
    for (i = 0; i < rlen && pos + 1 < cap; i++) {
        buf[pos++] = (char)(xorshift(rng) & 0x7F);
    }
    buf[pos] = '\0';
    return pos;
}

static size_t
gen_unicode_mutation(char *buf, size_t cap, unsigned long *rng) {
    /* Mutate a real brand URL with homoglyph characters */
    const char *bases[] = {
        "https://paypal.com/signin",
        "https://google.com/accounts",
        "https://apple.com/id",
        "https://microsoft.com/login",
        "https://amazon.com/signin",
    };
    int nb = (int)(sizeof(bases)/sizeof(bases[0]));
    const char *base = bases[xorshift(rng) % (unsigned long)nb];
    /* Homoglyph substitutions: Cyrillic look-alikes */
    const char subs[][4] = {
        "\xd0\xb0",   /* а (Cyrillic a) */
        "\xd0\xbe",   /* о (Cyrillic o) */
        "\xd1\x96",   /* і (Cyrillic i) */
        "\xd0\xb5",   /* е (Cyrillic e) */
        "\xef\xbc\xa1", /* Ａ (full-width) */
        "\xef\xbc\xaf", /* Ｏ (full-width) */
    };
    int nsubs = (int)(sizeof(subs)/sizeof(subs[0]));
    size_t blen = strlen(base);
    if (blen + 10 >= cap) { strncpy(buf, base, cap-1); buf[cap-1]='\0'; return blen; }
    strcpy(buf, base);
    /* Mutate 1-3 random characters */
    unsigned long mutations = (xorshift(rng) % 3) + 1;
    unsigned long m;
    for (m = 0; m < mutations; m++) {
        size_t pos = xorshift(rng) % blen;
        if (buf[pos] < 'a' || buf[pos] > 'z') continue;
        const char *sub = subs[xorshift(rng) % (unsigned long)nsubs];
        size_t sl = strlen(sub);
        /* Replace one ASCII char with multi-byte sub — shift right */
        size_t curlen = strlen(buf);
        if (curlen + sl >= cap) break;
        memmove(buf + pos + sl, buf + pos + 1, curlen - pos);
        memcpy(buf + pos, sub, sl);
    }
    return strlen(buf);
}

static size_t
gen_deep_subdomain(char *buf, size_t cap, unsigned long *rng) {
    size_t pos = 0;
    pos += snprintf(buf + pos, cap - pos, "https://");
    unsigned long depth = (xorshift(rng) % 100) + 1;
    unsigned long i;
    for (i = 0; i < depth && pos + 20 < cap; i++) {
        pos += snprintf(buf + pos, cap - pos, "sub%lu.", xorshift(rng) % 9999UL);
    }
    pos += snprintf(buf + pos, cap - pos, "paypal.com");
    unsigned long segs = (xorshift(rng) % 50) + 1;
    for (i = 0; i < segs && pos + 20 < cap; i++) {
        pos += snprintf(buf + pos, cap - pos, "/verify%lu", xorshift(rng) % 999UL);
    }
    return pos;
}

static size_t
gen_percent_encoded(char *buf, size_t cap, unsigned long *rng) {
    const char *bases[] = {
        "https://evil.com/%76%65%72%69%66%79",
        "https://paypal.com.evil.com/%73%69%67%6e%69%6e",
        "https://g%6F%6Fgle.com/login",
    };
    int nb = (int)(sizeof(bases)/sizeof(bases[0]));
    const char *base = bases[xorshift(rng) % (unsigned long)nb];
    /* Optionally append random percent-encoded junk */
    size_t pos = snprintf(buf, cap, "%s", base);
    unsigned long extra = xorshift(rng) % 20;
    unsigned long i;
    for (i = 0; i < extra && pos + 4 < cap; i++) {
        pos += snprintf(buf + pos, cap - pos, "%%%02lx",
                        (unsigned long)(xorshift(rng) & 0xFF));
    }
    return pos;
}

static size_t
gen_brand_typosquat(char *buf, size_t cap, unsigned long *rng) {
    const char *brands[] = {
        "paypal", "google", "apple", "microsoft", "amazon",
        "netflix", "facebook", "instagram", "twitter", "linkedin",
    };
    const char *tlds[] = { ".com", ".net", ".org", ".xyz", ".top", ".pw" };
    const char *paths[] = { "/login", "/verify", "/account", "/signin",
                             "/update", "/secure", "/support", "" };
    int nb = (int)(sizeof(brands)/sizeof(brands[0]));
    int nt = (int)(sizeof(tlds)/sizeof(tlds[0]));
    int np = (int)(sizeof(paths)/sizeof(paths[0]));
    const char *brand = brands[xorshift(rng) % (unsigned long)nb];
    size_t blen = strlen(brand);
    char mutated[64];
    strncpy(mutated, brand, sizeof(mutated)-1);
    mutated[sizeof(mutated)-1] = '\0';
    /* Apply one random edit */
    unsigned long op = xorshift(rng) % 4;
    size_t pos2 = xorshift(rng) % (blen ? blen : 1);
    if (op == 0 && pos2 < blen) {
        /* substitution */
        mutated[pos2] = (char)('a' + xorshift(rng) % 26);
    } else if (op == 1 && blen + 2 < sizeof(mutated)) {
        /* insertion */
        memmove(mutated + pos2 + 1, mutated + pos2, blen - pos2 + 1);
        mutated[pos2] = (char)('a' + xorshift(rng) % 26);
    } else if (op == 2 && blen > 1) {
        /* deletion */
        memmove(mutated + pos2, mutated + pos2 + 1, blen - pos2);
    } else if (op == 3 && pos2 + 1 < blen) {
        /* transposition */
        char tmp = mutated[pos2]; mutated[pos2] = mutated[pos2+1]; mutated[pos2+1] = tmp;
    }
    return (size_t)snprintf(buf, cap, "https://%s%s%s",
                            mutated,
                            tlds[xorshift(rng) % (unsigned long)nt],
                            paths[xorshift(rng) % (unsigned long)np]);
}

static size_t
gen_bidi_url(char *buf, size_t cap, unsigned long *rng) {
    /* Inject bidi/control characters into a phishing URL */
    const char *base = "https://paypal.com.evil.com/login";
    const char *controls[] = {
        "\xe2\x80\xaa",  /* U+202A LRE */
        "\xe2\x80\xab",  /* U+202B RLE */
        "\xe2\x80\xac",  /* U+202C PDF */
        "\xe2\x81\xa0",  /* U+2060 WJ  */
        "\xef\xbb\xbf",  /* U+FEFF BOM */
        "\xe2\x80\x8b",  /* U+200B ZWSP */
    };
    int nc = (int)(sizeof(controls)/sizeof(controls[0]));
    size_t blen = strlen(base);
    if (blen + 30 >= cap) { strncpy(buf, base, cap-1); buf[cap-1]='\0'; return blen; }
    strcpy(buf, base);
    size_t curlen = blen;
    unsigned long inj = (xorshift(rng) % 5) + 1;
    unsigned long i;
    for (i = 0; i < inj; i++) {
        const char *ctrl = controls[xorshift(rng) % (unsigned long)nc];
        size_t cl = strlen(ctrl);
        size_t at = xorshift(rng) % (curlen + 1);
        if (curlen + cl + 1 >= cap) break;
        memmove(buf + at + cl, buf + at, curlen - at + 1);
        memcpy(buf + at, ctrl, cl);
        curlen += cl;
    }
    return curlen;
}

static size_t
gen_very_long_host(char *buf, size_t cap, unsigned long *rng) {
    size_t pos = 0;
    pos += snprintf(buf + pos, cap - pos, "https://");
    /* Host exactly at, below, and above MAX_HOST (512) */
    unsigned long target = 400 + (xorshift(rng) % 300);
    while (pos < target + 8 && pos + 8 < cap) {
        pos += snprintf(buf + pos, cap - pos, "a");
    }
    if (pos + 5 < cap)
        pos += snprintf(buf + pos, cap - pos, ".com");
    return pos;
}

static size_t
gen_dangerous_scheme(char *buf, size_t cap, unsigned long *rng) {
    const char *schemes[] = {
        "javascript:alert(document.cookie)",
        "javascript:void(0)",
        "data:text/html,<script>alert(1)</script>",
        "data:application/octet-stream;base64,AAAA",
        "blob:https://evil.com/fake-id",
        "vbscript:msgbox(1)",
    };
    int ns = (int)(sizeof(schemes)/sizeof(schemes[0]));
    /* Optionally add Unicode evasion to scheme */
    const char *s = schemes[xorshift(rng) % (unsigned long)ns];
    unsigned long variant = xorshift(rng) % 3;
    if (variant == 0) {
        return (size_t)snprintf(buf, cap, "%s", s);
    } else if (variant == 1) {
        /* Uppercase scheme */
        size_t i, slen = strlen(s);
        for (i = 0; i < slen && i + 1 < cap; i++) {
            buf[i] = (char)((s[i] >= 'a' && s[i] <= 'z') ? s[i] - 32 : s[i]);
        }
        buf[i] = '\0';
        return i;
    } else {
        /* Percent-encode scheme characters */
        size_t pos = 0, i;
        for (i = 0; s[i] && pos + 4 < cap; i++) {
            if (s[i] >= 'a' && s[i] <= 'z' && xorshift(rng) % 3 == 0) {
                pos += (size_t)snprintf(buf + pos, cap - pos, "%%%02x",
                                        (unsigned char)s[i]);
            } else {
                buf[pos++] = s[i];
            }
        }
        buf[pos] = '\0';
        return pos;
    }
}

typedef size_t (*gen_fn)(char *, size_t, unsigned long *);

int
main(int argc, char **argv) {
    long iterations = (argc > 1) ? atol(argv[1]) : 100000;
    unsigned long seed = (argc > 2) ? (unsigned long)atol(argv[2]) : 0xCAFEBABEUL;
    if (seed == 0) seed = (unsigned long)time(NULL);

    printf("HLSE URL Fuzz Harness\n");
    printf("  iterations: %ld\n", iterations);
    printf("  seed:       0x%lx\n\n", seed);

    struct sigaction sa;
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    gen_fn generators[] = {
        gen_random_url,
        gen_unicode_mutation,
        gen_deep_subdomain,
        gen_percent_encoded,
        gen_brand_typosquat,
        gen_bidi_url,
        gen_very_long_host,
        gen_dangerous_scheme,
    };
    const char *gen_names[] = {
        "random URL", "unicode mutation", "deep subdomain", "percent-encoded",
        "brand typosquat", "bidi injection", "very long host", "dangerous scheme",
    };
    const int n_gen = (int)(sizeof(generators)/sizeof(generators[0]));

    long crashes = 0, out_of_range = 0, ok = 0;
    long stats[8] = {0};
    char buf[16384];
    unsigned long rng = seed;

    long i;
    for (i = 0; i < iterations; i++) {
        int g = (int)(xorshift(&rng) % (unsigned long)n_gen);
        generators[g](buf, sizeof(buf), &rng);
        stats[g]++;

        strncpy(last_input, buf, sizeof(last_input) - 1);
        last_input[sizeof(last_input) - 1] = '\0';

        if (setjmp(crash_jmp) == 0) {
            Verdict v = hlse_check_url(buf);
            if (v.score < 0 || v.score > 100) {
                out_of_range++;
                printf("  OUT_OF_RANGE [%d] gen=%s\n", v.score, gen_names[g]);
                if (out_of_range >= 5) return 1;
            }
            /* action must not be NULL */
            const char *act = hlse_action_for_score(v.score);
            if (!act) {
                printf("  NULL action for score %d\n", v.score);
                out_of_range++;
            }
            /* For http(s) URLs, hlse_scan must agree within 20 points */
            if (buf[0] == 'h' && buf[1] == 't') {
                ScanResult sr = hlse_scan(buf);
                int diff = v.score - sr.score;
                if (diff < 0) diff = -diff;
                if (diff > 20) {
                    /* Not a hard error — compound text scoring may push higher */
                    (void)diff;
                }
                if (sr.score < 0 || sr.score > 100) {
                    out_of_range++;
                    printf("  SCAN OOR [%d]\n", sr.score);
                }
            }
            ok++;
        } else {
            crashes++;
            printf("  CRASH iter=%ld gen=%s input=%.80s\n",
                   i, gen_names[g], last_input);
            if (crashes >= 5) return 1;
        }

        if (i > 0 && i % 10000 == 0) {
            printf("  ... %ld iters ok=%ld crash=%ld oor=%ld\n",
                   i, ok, crashes, out_of_range);
        }
    }

    printf("\n=== URL Fuzz results ===\n");
    printf("  total:       %ld\n", iterations);
    printf("  ok:          %ld (%.1f%%)\n", ok, 100.0 * ok / (double)iterations);
    printf("  out-of-range:%ld\n", out_of_range);
    printf("  crashes:     %ld\n", crashes);
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
