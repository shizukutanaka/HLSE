/*
 * tests/hlse_corpus_extended.c
 *
 * Extended detection-rate corpus, sourced from external phishing
 * patterns and ordinary corporate/personal communications.
 *
 * The corpus in benchmark() inside hlse_core.c was written by the
 * same person who wrote the detection logic. This creates SELECTION
 * BIAS — cases match the heuristics by construction.
 *
 * This file contains test cases derived from FTC consumer alerts,
 * 国民生活センター reports, and ordinary professional communications.
 *
 * Build: gcc -O2 -o tests/corpus_ext tests/hlse_corpus_extended.c \
 *            hlse_core.c hlse_text.c -I. -D_POSIX_C_SOURCE=200809L
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include "../hlse_text.h"

typedef struct {
    int  score;
    int  n_reasons;
    char reasons[12][128];
} Verdict;

extern Verdict hlse_check_url(const char *raw_url);

struct ext_url_case {
    const char *url;
    int         min_score;
    const char *desc;
};

static struct ext_url_case ext_url_corpus[] = {
    /* FTC consumer-alert-derived patterns */
    { "https://your-package-tracking-update.click/usps", 40,
      "FTC: USPS package phishing" },
    { "https://account-billing-suspended-now.xyz/netflix/login", 40,
      "FTC: Netflix billing scam" },
    { "https://refund-claim-irs.online/2025/file", 40,
      "FTC: IRS refund phishing" },
    { "https://covid-relief-payment-portal.top/claim", 40,
      "FTC: COVID relief scam" },

    /* JP NCAC patterns */
    { "https://amazon.co.jp.security-account-verify.xyz/login", 40,
      "JP NCAC: Amazon spoof" },

    /* Wikipedia/research-cited examples */
    { "https://gооgle.com", 30,
      "Wikipedia: Cyrillic о×2 in google" },
    { "https://раypal.com/signin", 40,
      "Wikipedia: Cyrillic р in paypal" },
    { "https://a8s3kd92mfqx.tk/account", 40,
      "DGA: high-entropy random domain with digits" },

    /* Edge cases that should NOT fire (legitimate) */
    { "https://www.google.com.au", 0,
      "Google Australia ccTLD subdomain" },
    { "https://accounts.google.com/signin", 0,
      "Google account signin (legit)" },
    { "https://docs.microsoft.com/en-us/azure/security/", 0,
      "Microsoft docs about security" },
    { "https://github.com/anthropics/anthropic-sdk/issues/123/verify-build", 0,
      "GitHub issue with /verify-build path" },
    { "https://stackoverflow.com/questions/login-form-validation", 0,
      "SO question about login forms" },

    { NULL, 0, NULL }
};

struct ext_text_case {
    const char *text;
    int         min_score;
    const char *desc;
};

static struct ext_text_case ext_text_corpus[] = {
    /* FTC complaint excerpts */
    { "I'm calling from Microsoft. We detected suspicious activity on your "
      "computer. To prevent identity theft, you need to act immediately. "
      "Please buy iTunes gift cards and read the codes to me.", 50,
      "FTC: tech-support call transcript" },

    { "This is the IRS. You owe back taxes of $4,200. If you do not pay "
      "today, a warrant will be issued for your arrest. Pay via Google Play "
      "gift cards.", 50,
      "FTC: IRS impersonation call" },

    { "Hi, I saw your profile and you seem nice. I'm a successful trader. "
      "I can teach you to invest in cryptocurrency and triple your money. "
      "Please don't tell your family yet.", 40,
      "FTC: pig butchering opener" },

    /* JP scam scripts */
    /* 至急です。本日中に暗証番号をご入力ください */
    { "\xe8\x87\xb3\xe6\x80\xa5\xe3\x81\xa7\xe3\x81\x99"
      "\xe3\x80\x82\xe6\x9c\xac\xe6\x97\xa5\xe4\xb8\xad"
      "\xe3\x81\xab\xe6\x9a\x97\xe8\xa8\xbc\xe7\x95\xaa"
      "\xe5\x8f\xb7\xe3\x82\x92\xe3\x81\x94\xe5\x85\xa5"
      "\xe5\x8a\x9b\xe3\x81\x8f\xe3\x81\xa0\xe3\x81\x95"
      "\xe3\x81\x84", 30,
      "JP: bank credential phishing" },

    /* 緊急のお知らせ。連絡が取れないので振り込んでください */
    { "\xe7\xb7\x8a\xe6\x80\xa5\xe3\x81\xae\xe3\x81\x8a"
      "\xe7\x9f\xa5\xe3\x82\x89\xe3\x81\x9b\xe3\x80\x82"
      "\xe9\x80\xa3\xe7\xb5\xa1\xe3\x81\x8c\xe5\x8f\x96"
      "\xe3\x82\x8c\xe3\x81\xaa\xe3\x81\x84\xe3\x81\xae"
      "\xe3\x81\xa7\xe6\x8c\xaf\xe3\x82\x8a\xe8\xbe\xbc"
      "\xe3\x82\x93\xe3\x81\xa7\xe3\x81\x8f\xe3\x81\xa0"
      "\xe3\x81\x95\xe3\x81\x84", 30,
      "JP: emergency wire fraud" },

    /* Things that LOOK like scams but are legitimate */
    { "Reminder: your password expires next week. Please change it via the "
      "company SSO portal.", 0,
      "Legit: IT password reminder" },

    { "Quick question — can you wire the $50 reimbursement for last week's "
      "lunch when you have a sec?", 0,
      "Legit: casual reimbursement (no urgency/authority)" },

    { "Reminder: file your tax return by April 15. The IRS provides free "
      "filing tools.", 0,
      "Legit: tax season reminder (mentions IRS but no scam signals)" },

    { "The encryption key rotation policy was updated. New keys must be "
      "rotated every 90 days.", 0,
      "Legit: security policy update" },

    /* BEC CEO-fraud: authority + wire + secrecy (literature-grounded) */
    { "This is the CEO. I need an urgent wire transfer of $48,000 to a new "
      "supplier. Please keep this confidential between us.", 60,
      "BEC: CEO-fraud with secrecy isolation" },

    /* Legit executive email — has authority but no scam combination */
    { "This is the CEO. Great work this quarter, everyone. Enjoy the "
      "long weekend and see you Monday.", 0,
      "Legit: genuine executive message (authority, no payment/secrecy)" },

    /* Double extortion ransomware demand */
    { "Your data has been exfiltrated and all your files have been encrypted. "
      "Contact us to decrypt before we publish your data will be published. "
      "Pay 10 BTC to recover your files.", 60,
      "Double extortion: exfil + encrypt + publish threat" },

    /* Crypto wallet phishing */
    { "URGENT: Your wallet has been compromised. Enter your seed phrase "
      "immediately to verify ownership and prevent loss.", 25,
      "Phishing: seed phrase + urgency" },

    /* INTERPOL impersonation scam */
    { "This is INTERPOL. You are under investigation for cybercrime. "
      "Pay $5,000 via Western Union within 24 hours to avoid arrest.", 50,
      "Authority: INTERPOL impersonation + wire demand" },

    /* Legit crypto documentation — mentions seed phrase, no threat context */
    { "Best practices for wallet security: always store your seed phrase "
      "offline in a secure location. Never share it with anyone.", 0,
      "Legit: crypto security guide (seed phrase in neutral context)" },

    /* JP legitimate */
    /* 明日の社内研修についてお知らせします */
    { "\xe6\x98\x8e\xe6\x97\xa5\xe3\x81\xae\xe7\xa4\xbe"
      "\xe5\x86\x85\xe7\xa0\x94\xe4\xbf\xae\xe3\x81\xab"
      "\xe3\x81\xa4\xe3\x81\x84\xe3\x81\xa6\xe3\x81\x8a"
      "\xe7\x9f\xa5\xe3\x82\x89\xe3\x81\x9b\xe3\x81\x97"
      "\xe3\x81\xbe\xe3\x81\x99", 0,
      "JP legit: training notice" },

    { NULL, 0, NULL }
};

int
main(void) {
    int n_url = 0, url_pass = 0;
    int n_text = 0, text_pass = 0;
    int detected_url = 0, expected_url = 0;
    int detected_text = 0, expected_text = 0;
    int fp_url = 0, fp_text = 0;
    int legit_url_count = 0, legit_text_count = 0;
    int i;

    printf("HLSE Core — Extended (Bias-Reduced) Corpus\n");
    printf("══════════════════════════════════════════\n\n");

    printf("── URL phishing patterns ────────────────\n");
    for (i = 0; ext_url_corpus[i].url; i++) {
        Verdict v = hlse_check_url(ext_url_corpus[i].url);
        int expect_threat = ext_url_corpus[i].min_score > 0;
        int got_threat = v.score >= 40;
        int ok = expect_threat ? (v.score >= ext_url_corpus[i].min_score)
                                : (v.score < 40);
        n_url++;
        printf("%s [%3d] %.55s\n",
               ok ? "PASS" : "FAIL", v.score, ext_url_corpus[i].desc);
        if (ok) url_pass++;
        if (expect_threat) {
            expected_url++;
            if (got_threat) detected_url++;
        } else {
            legit_url_count++;
            if (got_threat) fp_url++;
        }
    }

    printf("\n── Text scam patterns ───────────────────\n");
    for (i = 0; ext_text_corpus[i].text; i++) {
        TextVerdict v = hlse_check_text(ext_text_corpus[i].text);
        int expect_threat = ext_text_corpus[i].min_score > 0;
        int got_threat = v.score >= 40;
        int ok = expect_threat ? (v.score >= ext_text_corpus[i].min_score)
                                : (v.score < 40);
        n_text++;
        printf("%s [%3d] %.55s\n",
               ok ? "PASS" : "FAIL", v.score, ext_text_corpus[i].desc);
        if (ok) text_pass++;
        if (expect_threat) {
            expected_text++;
            if (got_threat) detected_text++;
        } else {
            legit_text_count++;
            if (got_threat) fp_text++;
        }
    }

    int total_tp = detected_url + detected_text;
    int total_fp = fp_url + fp_text;
    int total_fn = (expected_url - detected_url) + (expected_text - detected_text);
    double precision = (total_tp + total_fp) > 0
        ? (double)total_tp / (total_tp + total_fp) : 1.0;
    double recall = (total_tp + total_fn) > 0
        ? (double)total_tp / (total_tp + total_fn) : 1.0;
    double f1 = (precision + recall) > 0
        ? 2.0 * precision * recall / (precision + recall) : 0.0;

    printf("\n══════════════════════════════════════════\n");
    printf("URL:  %d/%d cases pass, recall %d/%d, FP %d/%d\n",
           url_pass, n_url, detected_url, expected_url, fp_url, legit_url_count);
    printf("Text: %d/%d cases pass, recall %d/%d, FP %d/%d\n",
           text_pass, n_text, detected_text, expected_text, fp_text, legit_text_count);
    printf("Combined precision=%.3f recall=%.3f F1=%.3f (out-of-distribution)\n",
           precision, recall, f1);
    printf("Acceptance threshold: 0.75 (out-of-distribution data)\n\n");

    int total_pass = url_pass + text_pass;
    int total = n_url + n_text;
    if (f1 >= 0.75 && total_pass >= (total * 80 / 100)) {
        printf("EXTENDED CORPUS PASSED (F1=%.3f, %d/%d cases)\n",
               f1, total_pass, total);
        return 0;
    }
    printf("EXTENDED CORPUS FAILED (F1=%.3f, %d/%d cases)\n",
           f1, total_pass, total);
    return 1;
}
