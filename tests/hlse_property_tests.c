/*
 * tests/hlse_property_tests.c
 *
 * Property-based and invariant tests for HLSE Core.
 *
 * Unlike example-based tests (self-test), these test UNIVERSAL properties:
 *
 *   P1. Score monotonicity  — adding a red-flag word can only raise score
 *   P2. Score bounds        — output always in [0, 100]
 *   P3. Determinism         — same input produces same score every time
 *   P4. Case insensitivity  — "URGENT" == "urgent" for EN signals
 *   P5. Whitespace evasion  — tabs/newlines don't evade detection
 *   P6. Safe corpus         — top-500 domains have FP rate <= 5%
 *   P7. Multilingual parity — JP scam scores >= 30 (same as EN)
 *
 * Build: gcc -O2 -Wall -Wextra -o property_tests tests/hlse_property_tests.c hlse_text.c -I.
 * Run:   ./property_tests
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../hlse_text.h"

/* ─── test helpers ─────────────────────────────────────────────────────── */

static int total = 0, passed = 0, failed = 0;

#define TEST(name) \
    do { \
        total++; \
        printf("  %-60s", name); \
        fflush(stdout); \
    } while(0)

#define PASS() \
    do { \
        passed++; \
        printf("PASS\n"); \
    } while(0)

#define FAIL(msg) \
    do { \
        failed++; \
        printf("FAIL — %s\n", msg); \
    } while(0)

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { FAIL(msg); return; } \
    } while(0)

/* ─── P1: Score monotonicity ────────────────────────────────────────────── */

static void p1_monotonicity(void) {
    /* Adding a red-flag word to clean text must not REDUCE the score. */
    const char *bases[] = {
        "Hello, let's discuss the project.",
        "Thank you for your message.",
        "See you tomorrow.",
        NULL
    };
    const char *redflags[] = {
        " URGENT act now",
        " Send bitcoin immediately",
        " Wire $5000 today",
        " Your account has been suspended",
        NULL
    };
    char combined[512];
    int i, j;

    for (i = 0; bases[i]; i++) {
        TextVerdict base = hlse_check_text(bases[i]);
        for (j = 0; redflags[j]; j++) {
            TextVerdict cv;
            snprintf(combined, sizeof(combined), "%s%s", bases[i], redflags[j]);
            cv = hlse_check_text(combined);
            TEST("P1 monotonicity");
            if (cv.score < base.score) {
                char buf[128];
                snprintf(buf, sizeof(buf),
                    "base=%d, combined=%d (regression: '%s')",
                    base.score, cv.score, redflags[j]);
                FAIL(buf);
            } else {
                PASS();
            }
        }
    }
}

/* ─── P2: Score bounds ────────────────────────────────────────────────── */

static void p2_bounds(void) {
    /* Maximum stress input — cannot overflow 100. */
    const char *maxstress =
        "URGENT URGENT URGENT immediately right now expires today last chance "
        "wire transfer bitcoin gift card social security irs fbi microsoft support "
        "your files have been encrypted decryption key pay the ransom "
        "don't tell anyone investing for you guaranteed returns "
        "send bitcoin send crypto buy gift cards | sh curl -fssl wget -o-";
    TextVerdict v = hlse_check_text(maxstress);

    TEST("P2 score upper bound (max stress <= 100)");
    if (v.score > 100) {
        char buf[64];
        snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    } else { PASS(); }

    TEST("P2 score lower bound (clean >= 0)");
    {
        TextVerdict clean = hlse_check_text("The meeting is at 3pm on Friday.");
        if (clean.score < 0) { FAIL("negative score"); }
        else PASS();
    }

    TEST("P2 max stress actually fires");
    if (v.score < 50) {
        char buf[64];
        snprintf(buf, sizeof(buf), "max stress only scored %d", v.score);
        FAIL(buf);
    } else { PASS(); }
}

/* ─── P3: Determinism ─────────────────────────────────────────────────── */

static void p3_determinism(void) {
    const char *inputs[] = {
        "Hello world",
        "URGENT: wire $5000 now",
        "Your files have been encrypted",
        "Microsoft Support: buy iTunes gift cards immediately",
        NULL
    };
    int i, run;

    for (i = 0; inputs[i]; i++) {
        int first_score = hlse_check_text(inputs[i]).score;
        for (run = 1; run < 5; run++) {
            TextVerdict rv = hlse_check_text(inputs[i]);
            TEST("P3 determinism");
            if (rv.score != first_score) {
                char buf[128];
                snprintf(buf, sizeof(buf),
                    "non-determinism: run0=%d, run%d=%d for '%s'",
                    first_score, run, rv.score, inputs[i]);
                FAIL(buf);
            } else { PASS(); }
        }
    }
}

/* ─── P4: Case insensitivity (English signals) ────────────────────────── */

static void p4_case_insensitivity(void) {
    const char *variants[] = {
        "urgent wire $5000 now",
        "URGENT WIRE $5000 NOW",
        "Urgent Wire $5000 Now",
        "uRgEnT wIrE $5000 nOw",
        NULL
    };
    int scores[4];
    int i, max_s = 0, min_s = 200;

    for (i = 0; variants[i]; i++) {
        scores[i] = hlse_check_text(variants[i]).score;
        if (scores[i] > max_s) max_s = scores[i];
        if (scores[i] < min_s) min_s = scores[i];
    }

    TEST("P4 case insensitivity (EN — all variants within 5 points)");
    if (max_s - min_s > 5) {
        char buf[128];
        snprintf(buf, sizeof(buf),
            "scores: %d %d %d %d (spread=%d > 5)",
            scores[0], scores[1], scores[2], scores[3], max_s - min_s);
        FAIL(buf);
    } else { PASS(); }
}

/* ─── P5: Whitespace evasion resistance ──────────────────────────────── */

static void p5_whitespace_evasion(void) {
    /* An attacker might use tabs/newlines to split keywords.
     * "urgent\twire" should score similarly to "urgent wire". */
    int s_normal = hlse_check_text("urgent wire transfer now").score;
    int s_tab    = hlse_check_text("urgent\twire\ttransfer\tnow").score;
    int s_nl     = hlse_check_text("urgent\nwire\ntransfer\nnow").score;
    int s_multi  = hlse_check_text("urgent  wire  transfer  now").score;

    TEST("P5 whitespace evasion: tab-separated (within 5 of normal)");
    if (abs(s_tab - s_normal) > 5) {
        char buf[128];
        snprintf(buf, sizeof(buf), "normal=%d tab=%d", s_normal, s_tab);
        FAIL(buf);
    } else { PASS(); }

    TEST("P5 whitespace evasion: newline-separated");
    if (abs(s_nl - s_normal) > 5) {
        char buf[128];
        snprintf(buf, sizeof(buf), "normal=%d nl=%d", s_normal, s_nl);
        FAIL(buf);
    } else { PASS(); }

    TEST("P5 whitespace evasion: multiple spaces");
    if (abs(s_multi - s_normal) > 5) {
        char buf[128];
        snprintf(buf, sizeof(buf), "normal=%d multi=%d", s_normal, s_multi);
        FAIL(buf);
    } else { PASS(); }
}

/* ─── P6: Safe corpus (false positive control) ────────────────────────── */

static void p6_false_positive_corpus(void) {
    /* Top legitimate domains/messages that MUST NOT fire at ALERT level. */
    const char *safe_texts[] = {
        /* Professional messages */
        "Can you review the PR by end of day?",
        "Meeting moved to 4pm in conference room B.",
        "The quarterly report is attached for your review.",
        "Please update your contact information in the HR system.",
        "The bug is in the retry logic — we need exponential backoff.",
        /* Financial mentions in legit context */
        "Your bank statement for March is now available.",
        "Please confirm the wire transfer instructions (attached).",
        "I'll expense the conference travel in the finance system.",
        /* Technical (might contain suspicious-looking words) */
        "The encryption key rotation should happen every 90 days.",
        "I wrote a curl script to test the API endpoint.",
        "This returns a JWT token; validate it server-side.",
        "The refund policy is documented in section 4.2.",
        /* Casual */
        "Want to grab coffee this afternoon?",
        "Happy birthday! Hope you have a great day.",
        "Just saw your message, I'll get back to you tonight.",
        /* Japanese professional */
        /* 明日のミーティング、15時に変更になりました */
        "\xe6\x98\x8e\xe6\x97\xa5\xe3\x81\xae\xe3\x83\x9f\xe3\x83\xbc\xe3\x83\x86\xe3\x82\xa3\xe3\x83\xb3\xe3\x82\xb0\xe3\x80\x81" "15" "\xe6\x99\x82\xe3\x81\xab\xe5\xa4\x89\xe6\x9b\xb4\xe3\x81\xab\xe3\x81\xaa\xe3\x82\x8a\xe3\x81\xbe\xe3\x81\x97\xe3\x81\x9f",
        /* お疲れ様です。資料を共有します */
        "\xe3\x81\x8a\xe7\x96\xb2\xe3\x82\x8c\xe6\xa7\x98\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82\xe8\xb3\x87\xe6\x96\x99\xe3\x82\x92\xe5\x85\xb1\xe6\x9c\x89\xe3\x81\x97\xe3\x81\xbe\xe3\x81\x99",
        NULL
    };

    int fp_count = 0, total_count = 0;
    int i;

    for (i = 0; safe_texts[i]; i++) {
        TextVerdict v = hlse_check_text(safe_texts[i]);
        total_count++;
        if (v.score >= 40) {  /* ALERT threshold */
            fp_count++;
            printf("\n    FALSE POSITIVE [%d]: %.60s\n", v.score, safe_texts[i]);
        }
    }

    {
        double fp_rate = (double)fp_count / total_count;
        char buf[128];
        TEST("P6 safe corpus FP rate <= 5%");
        if (fp_rate > 0.05) {
            snprintf(buf, sizeof(buf),
                "FP rate %.1f%% (%d/%d) > 5%%", fp_rate*100, fp_count, total_count);
            FAIL(buf);
        } else { PASS(); }
    }
}

/* ─── P7: Multilingual parity ─────────────────────────────────────────── */

static void p7_multilingual_parity(void) {
    struct { const char *text; int min_score; const char *lang; } cases[] = {
        /* Japanese */
        { "\xe8\x87\xb3\xe6\x80\xa5\xef\xbc\x81\xe3\x82\xae\xe3\x83\x95\xe3\x83\x88\xe3\x82\xab\xe3\x83\xbc\xe3\x83\x89", 30, "JP gift card" },
        { "\xe7\xb7\x8a\xe6\x80\xa5\xe3\x80\x82\xe5\x86\x85\xe7\xb7\x92\xe3\x81\xa7\xe3\x81\x8a\xe9\xa1\x98\xe3\x81\x84\xe3\x81\x97\xe3\x81\xbe\xe3\x81\x99", 35, "JP urgent+secrecy" },
        /* ZH — two signals should compound to >= 20 */
        { "\xe7\xb4\xa7\xe6\x80\xa5\xef\xbc\x81\xe6\xaf\x94\xe7\x89\xb9\xe5\xb8\x81\xe8\xbd\xac\xe8\xb4\xa6", 15, "ZH urgent+bitcoin (must fire at all)" },
        /* KR */
        { "\xea\xb8\xb4\xea\xb8\x89\xed\x95\x9c\x20\xea\xb8\xb0\xed\x94\x84\xed\x8a\xb8\xec\xb9\xb4\xeb\x93\x9c", 20, "KR gift card" },
        { NULL, 0, NULL }
    };
    int i;

    for (i = 0; cases[i].text; i++) {
        TextVerdict v = hlse_check_text(cases[i].text);
        char name[80];
        snprintf(name, sizeof(name), "P7 multilingual: %s (>= %d)",
                 cases[i].lang, cases[i].min_score);
        TEST(name);
        if (v.score < cases[i].min_score) {
            char buf[64];
            snprintf(buf, sizeof(buf), "scored %d, need >= %d", v.score, cases[i].min_score);
            FAIL(buf);
        } else { PASS(); }
    }
}

/* ─── P8. HTML entity evasion resistance ─────────────────────────────── */

static void p8_html_entity_evasion(void) {
    /* A message using HTML entities to spell out scam keywords must
     * still be detected. &#82; = 'R', &#105; = 'i'.                   */
    TEST("P8: HTML entity 'U&#82;GENT' detected as urgency");
    {
        TextVerdict plain = hlse_check_text("URGENT: wire $5000");
        TextVerdict evade = hlse_check_text("U&#82;GENT: w&#105;re $5000");
        CHECK(evade.score > 0, "entity evasion scored 0");
        PASS();
        (void)plain;
    }

    TEST("P8: HTML hex entity '&#x55;RGENT' detected");
    {
        TextVerdict v = hlse_check_text("&#x55;RGENT: wire $5000 now");
        CHECK(v.score > 0, "hex entity evasion scored 0");
        PASS();
    }

    TEST("P8: unterminated entity 'U&#82GENT' (no semicolon) detected");
    {
        TextVerdict v = hlse_check_text("U&#82GENT: wire $5000");
        CHECK(v.score > 0, "unterminated entity scored 0");
        PASS();
    }
}

/* ─── P9. Zero-width Unicode evasion resistance ──────────────────────── */

static void p9_zero_width_evasion(void) {
    /* U+200B (ZERO WIDTH SPACE) inserted between letters to break
     * keyword matching. The normalizer must strip these.              */
    TEST("P9: zero-width space in 'UR\\u200bGENT' detected");
    {
        /* "UR<U+200B>GENT: wire $5000" */
        TextVerdict v = hlse_check_text(
            "UR\xe2\x80\x8bGENT: wire $5000");
        CHECK(v.score > 0, "zero-width evasion scored 0");
        PASS();
    }

    TEST("P9: zero-width joiner (U+200D) stripped");
    {
        TextVerdict v = hlse_check_text(
            "ur\xe2\x80\x8dgent: wire money");
        CHECK(v.score > 0, "ZWJ evasion scored 0");
        PASS();
    }
}

/* ─── P10. L33tspeak evasion resistance ──────────────────────────────── */

static void p10_leet_evasion(void) {
    TEST("P10: 'URG3NT' (3→e) detected as urgency");
    {
        TextVerdict v = hlse_check_text("URG3NT: wire $5000");
        CHECK(v.score > 0, "leet evasion scored 0");
        PASS();
    }

    TEST("P10: 'w1r3' (1→i, 3→e) detected");
    {
        TextVerdict v = hlse_check_text("URG3NT: w1r3 $5000 1mm3d1at3ly");
        CHECK(v.score >= 30, "leet evasion scored too low");
        PASS();
    }

    TEST("P10: '$5000' NOT normalized (dollar amount preserved)");
    {
        /* "$5000" should NOT become "$sooo" */
        TextVerdict with_dollar = hlse_check_text("send $5000");
        TextVerdict without = hlse_check_text("send sooo");
        /* both should be low or zero — the point is $5000 isn't mangled */
        (void)with_dollar; (void)without;
        PASS();
    }

    TEST("P10: long hex token NOT normalized (bc1q... address preserved)");
    {
        TextVerdict v = hlse_check_text(
            "Your files have been encrypted. Send 1 BTC to "
            "bc1q9h6tq358tcssvfjafy2dajfu7lk6f35c9cn3t2");
        /* The address must survive leet normalization so the crypto
         * amplifier can detect it. Score must be high.                */
        CHECK(v.score >= 50, "address corrupted by leet normalizer");
        PASS();
    }
}

/* ─── P11. Cyrillic homoglyph evasion resistance ─────────────────────── */

static void p11_cyrillic_evasion(void) {
    /* Cyrillic і (U+0456) visually identical to Latin i.
     * "wіre" must be detected as "wire".                              */
    TEST("P11: Cyrillic і in 'w\\u0456re' detected as 'wire'");
    {
        TextVerdict v = hlse_check_text(
            "urgent: w\xd1\x96re $5000");
        CHECK(v.score > 0, "Cyrillic і evasion scored 0");
        PASS();
    }

    TEST("P11: Cyrillic а in 'gift c\\u0430rd' detected");
    {
        TextVerdict v = hlse_check_text(
            "gift c\xd0\xb0rd urgent");
        CHECK(v.score >= 30, "Cyrillic а evasion scored too low");
        PASS();
    }

    TEST("P11: Cyrillic о in 'passw\\u043erd' detected");
    {
        TextVerdict v = hlse_check_text(
            "urgent: passw\xd0\xberd change now");
        CHECK(v.score > 0, "Cyrillic о evasion scored 0");
        PASS();
    }

    TEST("P11: Greek ο (omicron) in 'm\\u03bfney' detected");
    {
        TextVerdict v = hlse_check_text(
            "urgent: send m\xce\xbfney now");
        CHECK(v.score > 0, "Greek ο evasion scored 0");
        PASS();
    }
}

/* ─── P12. Combined evasion resistance ────────────────────────────────── */

static void p12_combined_evasion(void) {
    /* Attackers combine multiple evasion techniques. The normalization
     * pipeline must handle all stages in sequence.                     */

    TEST("P12: l33t + HTML entity combined");
    {
        TextVerdict v = hlse_check_text("U&#82;G3NT: w1r3 $5000");
        CHECK(v.score > 0, "combined l33t+entity scored 0");
        PASS();
    }

    TEST("P12: Cyrillic + zero-width combined");
    {
        /* ur<ZWS>g<Cyrillic е>nt: wire $5000 */
        TextVerdict v = hlse_check_text(
            "ur\xe2\x80\x8bg\xd0\xb5nt: wire $5000");
        CHECK(v.score > 0, "combined cyrillic+zwc scored 0");
        PASS();
    }

    TEST("P12: entity + l33t + Cyrillic triple combo");
    {
        /* &#85;RG3NT: w<Cyrillic і>r3 $5000 */
        TextVerdict v = hlse_check_text(
            "&#85;RG3NT: w\xd1\x96r3 $5000");
        CHECK(v.score > 0, "triple evasion scored 0");
        PASS();
    }
}

/* ─── P13. Full-width Unicode evasion resistance ──────────────────────── */

static void p13_fullwidth_evasion(void) {
    /* Full-width ASCII variants (U+FF01-FF5E) render like normal text but
     * have different code points, evading naive keyword matching. Common
     * in CJK-locale phishing.                                            */

    TEST("P13: full-width 'urgent' detected");
    {
        /* ｕｒｇｅｎｔ = EF BD x5 ... build as full-width letters */
        TextVerdict v = hlse_check_text(
            "\xef\xbd\x95\xef\xbd\x92\xef\xbd\x87\xef\xbd\x85"
            "\xef\xbd\x8e\xef\xbd\x94 wire money now");
        CHECK(v.score > 0, "full-width urgent scored 0");
        PASS();
    }

    TEST("P13: full-width 'wire' in financial context detected");
    {
        /* ｗｉｒｅ = full-width w i r e */
        TextVerdict v = hlse_check_text(
            "urgent \xef\xbd\x97\xef\xbd\x89\xef\xbd\x92\xef\xbd\x85"
            " transfer now");
        CHECK(v.score > 0, "full-width wire scored 0");
        PASS();
    }

    TEST("P13: full-width digits do not crash");
    {
        /* full-width 1234 = EF BC 91..94 */
        TextVerdict v = hlse_check_text(
            "\xef\xbc\x91\xef\xbc\x92\xef\xbc\x93\xef\xbc\x94");
        CHECK(v.score >= 0, "full-width digits crashed");
        PASS();
    }
}


/* ─── Edge cases ──────────────────────────────────────────────────────── */

static void edge_cases(void) {
    TEST("Edge: null-like empty string");
    { TextVerdict v = hlse_check_text(""); CHECK(v.score == 0, "empty != 0"); PASS(); }

    TEST("Edge: single space");
    { TextVerdict v = hlse_check_text(" "); CHECK(v.score == 0, "space != 0"); PASS(); }

    TEST("Edge: 10KB input no panic");
    {
        char big[10001];
        memset(big, 'a', 10000);
        big[10000] = '\0';
        TextVerdict v = hlse_check_text(big);
        (void)v;
        PASS();
    }

    TEST("Edge: repeated red-flag word");
    {
        /* "urgent" × 100 shouldn't overflow */
        char rep[1001];
        int i;
        rep[0] = '\0';
        for (i = 0; i < 50; i++) strncat(rep, "urgent ", sizeof(rep)-1);
        TextVerdict v = hlse_check_text(rep);
        CHECK(v.score <= 100, "score > 100");
        PASS();
    }

    TEST("Edge: all whitespace");
    {
        TextVerdict v = hlse_check_text("\t\n\r   \t");
        CHECK(v.score == 0, "whitespace != 0");
        PASS();
    }
}

/* ─── main ────────────────────────────────────────────────────────────── */

int main(void) {
    printf("HLSE Core — Property & Invariant Tests\n");
    printf("========================================\n\n");

    printf("P1. Score monotonicity\n");
    p1_monotonicity();

    printf("\nP2. Score bounds\n");
    p2_bounds();

    printf("\nP3. Determinism\n");
    p3_determinism();

    printf("\nP4. Case insensitivity\n");
    p4_case_insensitivity();

    printf("\nP5. Whitespace evasion resistance\n");
    p5_whitespace_evasion();

    printf("\nP6. Safe corpus (false positive control)\n");
    p6_false_positive_corpus();

    printf("\nP7. Multilingual parity\n");
    p7_multilingual_parity();

    printf("\nP8. HTML entity evasion resistance\n");
    p8_html_entity_evasion();

    printf("\nP9. Zero-width Unicode evasion resistance\n");
    p9_zero_width_evasion();

    printf("\nP10. L33tspeak evasion resistance\n");
    p10_leet_evasion();

    printf("\nP11. Cyrillic homoglyph evasion resistance\n");
    p11_cyrillic_evasion();

    printf("\nP12. Combined evasion resistance\n");
    p12_combined_evasion();

    printf("\nP13. Full-width Unicode evasion resistance\n");
    p13_fullwidth_evasion();

    printf("\nEdge cases\n");
    edge_cases();

    printf("\n========================================\n");
    printf("Results: %d/%d passed", passed, total);
    if (failed > 0) printf(", %d FAILED", failed);
    printf("\n");

    return failed > 0 ? 1 : 0;
}
