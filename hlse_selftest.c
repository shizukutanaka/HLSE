/*
 * hlse_selftest.c -- the CLI's built-in --self-test and --benchmark.
 *
 * Split out of hlse_cli.c: this block shares no state with the subcommand
 * handlers (no SARIF, baseline or --fail-on globals), which is what made it a
 * clean first cut. Linked into the hlse_core executables only.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <math.h>

#include "hlse_core.h"
#include "hlse_text.h"
#include "hlse_protect.h"
#include "hlse_util.h"
#include "hlse_supply.h"
#include "hlse_file.h"
#include "hlse_audit.h"
#include "hlse_secrets.h"
#include "hlse_core_internal.h"
#include "hlse_cli.h"

int
cli_self_test(void) {
    int pass = 0, fail = 0;

    struct test_case {
        const char *url;
        int min_score;
        int max_score;
        const char *desc;
    };

    /* These cases are derived directly from the Rust v0.7 corpus. */
    struct test_case cases[] = {
        /* Homoglyph attacks */
        { "https://g00gle.com",                         40, 80,
          "Digit-substitution homoglyph" },
        { "https://paypa1.com",                         40, 80,
          "1-for-l homoglyph" },
        { "https://paypaII.com",                        40, 80,
          "Capital-I-for-l homoglyph" },
        /* Suspicious TLD */
        { "https://secure-net-fix.top/update",          25, 80,
          "Suspicious TLD + hyphenation" },
        /* Subdomain spoofing */
        { "https://paypal.com.attacker.xyz/verify",     50, 100,
          "Subdomain brand spoof" },
        { "https://apple.com.id-locked.top/unlock",     45, 100,
          "Subdomain spoof + suspicious TLD" },
        /* Phishing path */
        { "https://random.xyz/verify/account/signin",   30, 100,
          "Multiple phishing path patterns + sus TLD" },
        /* Dangerous URI */
        { "javascript:alert(1)",                        80, 100,
          "javascript: URI" },
        /* False positives — must NOT fire */
        { "https://github.com/anthropics/sdk",           0, 14,
          "Legit GitHub URL" },
        { "https://docs.google.com/document/d/1/edit",   0, 14,
          "Legit Google Docs" },
        { "https://en.wikipedia.org/wiki/Verify",        0, 14,
          "Wikipedia article happens to mention 'verify'" },
        { "https://mail.google.com/mail/u/0",            0, 14,
          "Legit Gmail subdomain" },
        { "https://www.paypal.com/signin",               0, 39,
          "Real PayPal — has 'signin' in path but legit" },
        { "https://paypal-verify.com/account",            40, 100,
          "Brand-hyphen phishing: paypal-verify" },
        { "https://apple-support.net/signin",             40, 100,
          "Brand-hyphen phishing: apple-support" },
        { "https://x7k2p9qzr4mw.com/login",               40, 100,
          "DGA: high-entropy random domain with digits" },
        /* IDN homograph via Punycode (xn--) — decode then confusable-fold */
        { "https://xn--pple-43d.com",                     60, 100,
          "IDN homograph: xn--pple-43d = аpple (Cyrillic a)" },
        { "https://xn--ggle-55da.com",                    60, 100,
          "IDN homograph: xn--ggle-55da = gооgle (Cyrillic o)" },
        { "https://xn--pypl-53dc.com",                    60, 100,
          "IDN homograph: xn--pypl-53dc = pаypаl (Cyrillic a)" },
        { "https://xn--mirosoft-gch.com",                 60, 100,
          "IDN homograph: xn--mirosoft-gch = miсrosoft (Cyrillic c)" },
        /* Brand-token FP guard — short brand "line" must not match "airline" */
        { "https://airline-update.com/flights",            0, 39,
          "FP guard: 'airline' must not match brand 'line'" },
        /* @ credential trick */
        { "https://google.com@evil.com/verify",           45, 100,
          "@ credential trick detected" },
        /* URL shorteners */
        { "https://bit.ly/3xYzAbc",                        15, 39,
          "URL shortener: bit.ly scores LOG (destination hidden)" },
        /* Free-hosting phishing */
        { "https://paypal-verify.netlify.app/login",       50, 100,
          "Free-hosting phishing: brand in netlify.app subdomain" },
        { "https://myapp.netlify.app/home",                 0, 25,
          "FP guard: legitimate app on netlify.app without brand" },
        /* Legitimate IDNs — must NOT be flagged as homographs (UTS-39) */
        { "https://xn--mnchen-3ya.com",                    0, 14,
          "Legit IDN: xn--mnchen-3ya = münchen (German, single-script)" },
        { "https://xn--wgv71a.com",                        0, 14,
          "Legit IDN: xn--wgv71a = 日本 (Japanese, single-script)" },
        { "https://xn--e1afmkfd.com",                      0, 14,
          "Legit IDN: xn--e1afmkfd = пример (pure Cyrillic, not a brand)" },
        /* New brands: security software, tax software */
        { "https://norton-verify.click/account",           60, 100,
          "New brand 'norton' + suspicious TLD + phishing path" },
        { "https://turbotax-update.xyz/signin",            60, 100,
          "New brand 'turbotax' + suspicious TLD + phishing path" },
        /* New path patterns: CMS admin */
        { "https://paypal.pages.dev/wp-admin",             80, 100,
          "Free-hosting + brand + /wp-admin path" },
        /* Raw (non-Punycode) UTF-8 homoglyphs — folded via cp_fold().
         * Greek omicron (U+03BF) was previously collapsed to '?' and
         * missed; now folds to 'o' and matches the brand.              */
        { "https://g\xce\xbf\xce\xbfgle.com",             40, 100,
          "Raw UTF-8 Greek-omicron homoglyph: gοοgle → google" },
        { "https://paypa\xd3\x8f.com/login",              40, 100,
          "Raw UTF-8 Cyrillic-palochka homoglyph: paypaӏ → paypal" },
        /* Armenian homoglyphs — cp_fold now covers U+0561/0565/0578/0570 */
        { "https://\xd5\xa1pple.com",                     60, 100,
          "Raw UTF-8 Armenian-Ayb homoglyph: \xd5\xa1pple → apple" },
        { "https://g\xd5\xb8\xd5\xb8gle.com",            60, 100,
          "Raw UTF-8 Armenian-Vo homoglyph: g\xd5\xb8\xd5\xb8gle → google" },
        /* Cyrillic Komi De (U+0501) → 'd' */
        { "https://\xd4\x81iscord.com",                   60, 100,
          "Raw UTF-8 Cyrillic-Komi-De homoglyph: \xd4\x81iscord → discord" },
        /* Greek chi/omega (U+03C7/03C9) — newly mapped */
        { "https://\xcf\x89hatsapp.com",                  60, 100,
          "Raw UTF-8 Greek-omega homoglyph: \xcf\x89hatsapp → whatsapp" },
        /* Subdomain spoofing + phishing-typical SLD (security word + hyphen) */
        { "https://apple.com.id-login.net/appleid",        60, 100,
          "Subdomain spoof + phishing SLD (login) = BLOCK" },
        /* brand-hyphen alone on .net (no suspicious TLD, no path) — still ALERT */
        { "https://paypal-verify.net",                     20, 59,
          "FP calibration: brand-hyphen alone without sus TLD/path stays below BLOCK" },
    };
    int n = sizeof(cases) / sizeof(cases[0]);
    int i;

    printf("Running %d test cases...\n\n", n);

    for (i = 0; i < n; i++) {
        Verdict v = check_url(cases[i].url);
        int ok = (v.score >= cases[i].min_score
                  && v.score <= cases[i].max_score);
        printf("%s [%3d in %d..%d]  %-50s  %s\n",
               ok ? "PASS" : "FAIL",
               v.score, cases[i].min_score, cases[i].max_score,
               cases[i].url, cases[i].desc);
        if (!ok) {
            int j;
            for (j = 0; j < v.n_reasons; j++) {
                printf("       reason: %s\n", v.reasons[j]);
            }
            fail++;
        } else {
            pass++;
        }
    }

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

/* ──────────────────────── corpus benchmark ──────────────────────────── */

int
cli_benchmark(void) {
    static const char *malicious[] = {
        "https://g00gle.com/accounts/signin",
        "https://g00gle-security.top/verify",
        "https://paypa1.com/signin",
        "https://paypaII.com/signin",
        "https://gogle.com/signin",
        "https://amzaon.com/account",
        "https://mіcrosoft.com/signin",        /* Cyrillic */
        "https://paypal.com.secure-update-verify.xyz/signin",
        "https://netflix.com.billing-update.online/login",
        "https://apple.com.id-locked-verify.top/unlock",
        "https://amazon.com.account-security-alert.xyz/verify",
        "https://random-domain-98127.xyz/account/verify/urgent",
        "https://secureaccount.top/paypal/signin/verify-identity",
        "https://webmail-reset.click/office365/login",
        "https://document-secure-view.xyz/docusign/verify",
        /* Japanese phishing */
        "https://rakuten.co.jp.security-alert.xyz/login",
        "https://amazon.co.jp.account-verify.top/signin",
        "https://my.softbank.jp.account-suspended.online/reactivate",
        NULL
    };
    static const char *legit[] = {
        "https://github.com",
        "https://github.com/anthropics/sdk",
        "https://google.com",
        "https://mail.google.com/mail/u/0",
        "https://docs.google.com/document/d/1/edit",
        "https://microsoft.com",
        "https://learn.microsoft.com/en-us/azure",
        "https://apple.com",
        "https://docs.rs/tokio",
        "https://crates.io/crates/serde",
        "https://stackoverflow.com/questions/49937",
        "https://en.wikipedia.org/wiki/Rust_(programming_language)",
        "https://en.wikipedia.org/wiki/Verify",
        "https://www.paypal.com/signin",
        "https://www.chase.com/personal/credit-cards",
        /* Japanese legitimate */
        "https://www.rakuten.co.jp",
        "https://www.amazon.co.jp",
        "https://www.nhk.or.jp/news",
        NULL
    };

    int n_mal = 0, n_legit = 0;
    int detected = 0, fp = 0;
    int i;

    for (i = 0; malicious[i]; i++) {
        Verdict v = check_url(malicious[i]);
        n_mal++;
        if (v.score >= 40) detected++;
        else printf("MISSED %s [%d]\n", malicious[i], v.score);
    }
    for (i = 0; legit[i]; i++) {
        Verdict v = check_url(legit[i]);
        n_legit++;
        if (v.score >= 40) {
            fp++;
            printf("FALSE POSITIVE %s [%d]\n", legit[i], v.score);
        }
    }

    {
        double tp_rate = (double)detected / n_mal;
        double fp_rate = (double)fp / n_legit;
        double precision = (detected + fp) > 0
            ? (double)detected / (detected + fp) : 1.0;
        double recall = tp_rate;
        double f1 = (precision + recall) > 0
            ? 2 * precision * recall / (precision + recall) : 0;

        printf("\n=== Corpus Benchmark ===\n");
        printf("Malicious: %d/%d detected  (%.1f%% recall)\n",
               detected, n_mal, tp_rate * 100);
        printf("Legitimate: %d/%d false positives (%.1f%% FP rate)\n",
               fp, n_legit, fp_rate * 100);
        printf("Precision: %.3f\n", precision);
        printf("Recall:    %.3f\n", recall);
        printf("F1:        %.3f\n", f1);
        printf("\nAcceptance criteria:\n");
        printf("  recall >= 0.85    %s\n", recall >= 0.85 ? "PASS" : "FAIL");
        printf("  fp_rate <= 0.05   %s\n", fp_rate <= 0.05 ? "PASS" : "FAIL");
        printf("  F1 >= 0.85        %s\n", f1 >= 0.85 ? "PASS" : "FAIL");

        return (recall >= 0.85 && fp_rate <= 0.05 && f1 >= 0.85) ? 0 : 1;
    }
}
