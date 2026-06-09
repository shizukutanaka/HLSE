/*
 * hlse_text.c — Text scam detection for HLSE Core
 *
 * Implements signal-based phishing/scam detection on text input.
 * This complements hlse_core.c's URL detection.
 *
 * Architecture mirrors the Rust v0.7 signal-based scoring engine:
 *   - Each Signal is a named keyword group with weights
 *   - Compound amplifiers detect combinations (e.g. urgency + wire = BEC)
 *   - One pass over the signal table; adding new categories = 1 row
 *
 * Build:  gcc -O2 -Wall -Wextra -c hlse_text.c
 * Test:   linked into main hlse_core binary as `hlse_core text "..."`
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>

#include "hlse_text.h"

/* ─────────────── signal definitions ─────────────── */

/*
 * Signal scoring rationale:
 *
 *   base_weight       — score added when at least one keyword matches.
 *                       Reflects "how strong is a single hit on its own?"
 *   per_hit_bonus     — additional score for each extra keyword hit in
 *                       the same category. Reflects "does repetition
 *                       strengthen the case?" (e.g., 2× urgency words is
 *                       more concerning than 1×). 0 = no boost.
 *   max_contribution  — caps the category's contribution to prevent
 *                       any single signal from dominating the score.
 *
 * Threshold mapping (for reference):
 *     0..14   = SAFE   (no signal fired)
 *    15..39   = LOG    (advisory, log only)
 *    40..59   = ALERT  (warn user)
 *    60..79   = BLOCK  (block action)
 *    80+      = ISOLATE (quarantine)
 *
 * Weight calibration philosophy:
 *
 *   Most attacks combine 2-3 signal categories. We want:
 *     1 weak signal alone        → SAFE/LOG     (avoid false positives)
 *     1 strong signal alone      → ALERT        (e.g., "encrypted files")
 *     2+ signals combined        → BLOCK or higher
 *     Strong signal + amplifier  → BLOCK
 *
 *   This explains why:
 *     - URGENCY base=8: alone, just "urgent" shouldn't trigger
 *     - BAIT base=12: financial requests slightly stronger than urgency
 *     - AUTHORITY base=25: impersonating IRS/FBI is on its own a clear flag
 *     - SECRECY base=30: "don't tell anyone" is rarely innocent
 *     - RANSOM base=35: file-encryption language is almost always malicious
 *     - SHELL_PIPE base=40: "curl | sh" with suspicious URL is BLOCK-level
 *
 *   Amplifiers (Pass 2) add cross-category bonuses to catch known
 *   playbooks (BEC = wire+urgency, tech-support = giftcard+urgency, etc.)
 *
 *   These weights were calibrated against the in-distribution corpus
 *   (`benchmark()` in hlse_core.c). Changes to weights should be
 *   verified against BOTH corpora — the in-distribution and the
 *   out-of-distribution one in tests/hlse_corpus_extended.c.
 */
typedef struct {
    const char  *name;
    const char **words;        /* NULL-terminated */
    int          base_weight;  /* score added when any word matches */
    int          per_hit_bonus;
    int          max_contribution;
} Signal;

/* Each list is NULL-terminated for portability; iteration stops at NULL. */
static const char *URGENCY_WORDS[] = {
    /* English */
    "urgent", "immediately", "right now", "expires today", "last chance",
    "limited time", "act now", "within 24 hours", "within 48 hours",
    "suspend", "suspended", "locked", "unauthorized access", "verify now",
    "account will be closed", "deadline", "time-sensitive",
    "pay today", "act today", "respond today", "don't delay",
    "final warning", "last warning",
    "action required", "your account has been flagged", "must respond",
    "confirm within", "failure to respond",
    /* Japanese (UTF-8) */
    "至急", "緊急", "即座", "本日中", "24時間以内", "48時間以内",
    "停止", "凍結", "ロック", "不正アクセス", "確認してください",
    "期限切れ", "アカウント停止",
    /* Chinese */
    "紧急", "立即", "马上", "账户暂停",
    /* Korean */
    "긴급", "즉시", "계정 정지",
    NULL
};

static const char *BAIT_WORDS[] = {
    /* English */
    "password", "passcode", "pin number", "credit card", "debit card",
    "card number", "cvv", "social security", "ssn", "date of birth",
    "bank account", "routing number", "wire transfer", "bank wire",
    "please wire", "wire the funds", "transfer funds to", "transfer money to",
    "bitcoin", "btc", "crypto", "cryptocurrency", "ethereum", "eth", "usdt",
    "gift card", "itunes", "google play card", "google play cards",
    "amazon gift", "walmart gift", "target gift", "best buy gift", "steam card",
    "purchase gift", "purchase google", "purchase itunes",
    "refund", "reimbursement", "claim your",
    /* Crypto wallet theft */
    "seed phrase", "recovery phrase", "mnemonic", "private key",
    "connect wallet", "wallet passphrase",
    /* Money transfer platforms common in elder/tech-support fraud */
    "zelle", "western union", "moneygram",
    /* Japanese */
    "パスワード", "暗証番号", "暗証番号をご入力", "クレジットカード", "銀行口座", "振込",
    "ビットコイン", "仮想通貨", "ギフトカード", "アマゾンギフト", "還付金", "返金",
    "本日中に", "本人確認",
    /* Chinese */
    "密码", "银行卡", "礼品卡", "比特币",
    /* Korean */
    "비밀번호", "계좌번호", "기프트카드",
    NULL
};

static const char *PRIZE_WORDS[] = {
    /* English */
    "you won", "you have won", "congratulations", "winner", "selected",
    "chosen", "claim your prize", "claim your reward", "prize money",
    "lottery", "jackpot", "sweepstakes", "free gift", "unclaimed funds",
    /* Japanese */
    "おめでとう", "当選", "賞品",
    /* Korean */
    "당첨", "축하", "경품",
    /* Chinese */
    "中奖", "奖品", "恭喜",
    NULL
};

static const char *AUTHORITY_WORDS[] = {
    /* English */
    "irs", "fbi", "cia", "dhs", "treasury", "social security administration",
    "medicare", "medicaid", "department of justice",
    "microsoft support", "apple support", "google security",
    "amazon security", "paypal security",
    "under investigation", "criminal charges", "warrant for your arrest",
    "warrant will be issued", "back taxes", "owe back taxes",
    "ceo here", "from the ceo", "this is the ceo",
    "this is your ceo", "this is the cfo", "this is your cfo",
    "from the cfo", "your manager", "from the director",
    "the chairman", "head of finance", "from legal", "legal department",
    "from accounts payable", "executive office",
    /* International law enforcement impersonation */
    "interpol", "secret service", "homeland security", "federal reserve",
    "customs and border", "immigration enforcement",
    "attorney general",
    /* Japanese */
    "警察", "税務署", "国税庁", "総務省", "裁判所", "検察", "警視庁",
    /* Korean */
    "국세청", "경찰",
    NULL
};

static const char *SECRECY_WORDS[] = {
    /* English */
    "don't tell", "do not tell", "keep this secret", "between us",
    "don't mention", "no one else", "just between you and me",
    "keep this confidential", "do not discuss", "don't discuss",
    "keep it confidential", "do not share", "handle this discreetly",
    "do not loop in", "without involving", "off the record",
    /* Japanese */
    "内緒", "秘密にして", "誰にも言わないで", "他言無用", "内密に",
    NULL
};

static const char *GROOMING_WORDS[] = {
    /* English */
    "investing for you", "i'll 3x", "i'll triple", "double your money",
    "guaranteed returns", "guaranteed profit", "risk-free investment",
    "crypto opportunity", "investment opportunity",
    "hi sweetie", "hi dear", "hi honey",
    /* Japanese */
    "投資してあげる", "必ず儲かる", "絶対に儲かる",
    NULL
};

static const char *FAKE_ALERT_WORDS[] = {
    /* English */
    "security alert", "security warning", "virus detected",
    "your computer is infected", "your pc is infected",
    "your pc has a virus", "your computer has a virus",
    "unusual activity detected", "suspicious activity detected",
    "account compromised", "your account has been compromised",
    "call us immediately", "call this number immediately",
    "call now to", "call +1-888", "call +1-800",
    /* Japanese */
    "セキュリティ警告", "ウイルス検出", "不審なアクティビティ",
    NULL
};

static const char *RANSOM_WORDS[] = {
    /* English */
    "your files have been encrypted", "your data has been encrypted",
    "files are locked", "files have been locked", "all your files",
    "pay the ransom", "recover your files",
    "decryption key", "decrypt your files",
    /* Double-extortion phrases (2020+ threat landscape) */
    "data has been exfiltrated", "your data will be published",
    "contact us to decrypt",
    /* Japanese */
    "ファイルが暗号化", "復号キー", "身代金",
    NULL
};

static const char *FIN_ACTION_WORDS[] = {
    /* English */
    "send money", "send funds", "transfer money", "transfer funds",
    "wire money", "pay now", "pay immediately",
    "buy gift cards", "purchase gift cards", "get gift cards",
    "send bitcoin", "send crypto", "send eth",
    "cash app", "cashapp", "venmo", "apple pay",
    /* Japanese */
    "送金", "振り込んで", "ギフトカードを買って",
    NULL
};

static const char *SHELL_PIPE_WORDS[] = {
    "curl -fssl", "curl -ssl", "curl -fsl", "curl -fsssl",
    "| sh", "| bash", "| zsh",
    "wget -o- ", "wget -qo- ",
    NULL
};

static const Signal SIGNALS[] = {
    { "Urgency pressure",           URGENCY_WORDS,    8,  8, 25 },
    { "Financial/credential req",   BAIT_WORDS,      12, 12, 36 },
    { "Prize/reward lure",          PRIZE_WORDS,     15, 15, 30 },
    { "Authority impersonation",    AUTHORITY_WORDS, 25,  8, 35 },
    { "Secrecy/grooming",           SECRECY_WORDS,   30,  0, 30 },
    { "Investment scam pattern",    GROOMING_WORDS,  20, 20, 40 },
    { "Fake security alert",        FAKE_ALERT_WORDS,30, 12, 45 },
    { "Ransom/extortion language",  RANSOM_WORDS,    35, 20, 55 },
    { "Direct financial action",    FIN_ACTION_WORDS,15, 15, 30 },
    { "Shell-pipe-to-interpreter",  SHELL_PIPE_WORDS,40,  0, 40 },
    { NULL, NULL, 0, 0, 0 }
};

#define N_SIGNALS ((int)(sizeof(SIGNALS) / sizeof(SIGNALS[0]) - 1))

/* ─────────────── helpers ─────────────── */

static int
str_contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != NULL;
}

/* Case-fold ASCII characters only. Multi-byte UTF-8 sequences (any byte
 * >= 0x80) are passed through unchanged. Applying tolower() to high bytes
 * causes undefined behaviour in C and corrupts UTF-8 characters.         */
static void
str_to_lower(char *s) {
    while (*s) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x80) {
            *s = (char)tolower(c);
        }
        /* Skip complete multi-byte sequence: 2-byte (0xC0..0xDF),
         * 3-byte (0xE0..0xEF), 4-byte (0xF0..0xF7).                 */
        s++;
    }
}

/* Collapse ASCII whitespace runs to single space. Multi-byte UTF-8
 * sequences are copied byte-by-byte without touching them.             */
static void
normalize_whitespace(const char *in, char *out, size_t out_size) {
    size_t k = 0;
    int last_was_space = 1;  /* skip leading whitespace */

    while (*in && k < out_size - 1) {
        unsigned char c = (unsigned char)*in;
        if (c < 0x80) {
            /* ASCII: treat control chars and space as whitespace */
            if (c <= ' ') {
                if (!last_was_space) {
                    out[k++] = ' ';
                    last_was_space = 1;
                }
                in++;
            } else {
                out[k++] = (char)c;
                last_was_space = 0;
                in++;
            }
        } else {
            /* Multi-byte UTF-8 sequence: copy it intact.
             * Byte count from leading byte:
             *   110xxxxx = 2 bytes   (0xC0-0xDF)
             *   1110xxxx = 3 bytes   (0xE0-0xEF)
             *   11110xxx = 4 bytes   (0xF0-0xF7)
             *   Continuation 10xxxxxx: copy single byte as fallback   */
            int seq = (c < 0xE0) ? 2 : (c < 0xF0) ? 3 : 4;
            int j;
            last_was_space = 0;
            for (j = 0; j < seq && *in && k < out_size - 1; j++) {
                out[k++] = *in++;
            }
        }
    }
    /* Trim trailing space */
    if (k > 0 && out[k-1] == ' ') k--;
    out[k] = '\0';
}

static void
add_text_reason(TextVerdict *v, int delta, const char *fmt, ...) {
    va_list ap;
    if (v->n_reasons >= 16) return;
    if (delta > 0) {
        v->score += delta;
        if (v->score > 100) v->score = 100;
    }
    va_start(ap, fmt);
    vsnprintf(v->reasons[v->n_reasons], sizeof(v->reasons[0]), fmt, ap);
    va_end(ap);
    v->n_reasons++;
}

/* ─── evasion-resistant normalization ──────────────────────────────────
 *
 * Attackers bypass keyword detection via:
 *   1. Zero-width Unicode chars: U​RGENT (U+200B between U and R)
 *   2. HTML entities: U&#82;GENT (&#82; = 'R')
 *   3. L33tspeak: URG3NT, w1r3, 1mm3d1at3ly
 *
 * This stage runs AFTER whitespace normalization and lowering,
 * producing a canonical form for keyword matching.
 *
 * Design: only applied to the ASCII-lowered `lower` buffer used for
 * English keyword matching. Japanese/Chinese/Korean matching uses the
 * original `normalized` buffer (these evasions are ASCII-only).       */

/* Strip known zero-width UTF-8 sequences from buffer in-place.
 * Returns new length.                                                  */
/* Normalize full-width ASCII variants (U+FF01–FF5E) to their ASCII
 * equivalents (0x21–0x7E). Attackers use full-width characters
 * (ｕｒｇｅｎｔ, ｗｉｒｅ) to evade keyword matching while remaining visually
 * readable. UTF-8 encoding of U+FF01..FF5E:
 *   U+FF01..FF3F = EF BC 81 .. EF BC BF
 *   U+FF40..FF5E = EF BD 80 .. EF BD 9E
 * Maps each back to (codepoint - 0xFEE0) = ASCII. Also normalizes the
 * full-width space U+3000 (E3 80 80) to a regular space. In-place;
 * output is never longer than input. Returns new length.            */
static size_t
normalize_fullwidth(char *buf, size_t len) {
    size_t r = 0, w = 0;
    while (r < len) {
        unsigned char b0 = (unsigned char)buf[r];
        if (r + 2 < len && b0 == 0xEF) {
            unsigned char b1 = (unsigned char)buf[r+1];
            unsigned char b2 = (unsigned char)buf[r+2];
            /* U+FF01..FF3F: EF BC 81..BF → ASCII 0x21..0x5F */
            if (b1 == 0xBC && b2 >= 0x81 && b2 <= 0xBF) {
                buf[w++] = (char)(b2 - 0x81 + 0x21);
                r += 3;
                continue;
            }
            /* U+FF40..FF5E: EF BD 80..9E → ASCII 0x60..0x7E */
            if (b1 == 0xBD && b2 >= 0x80 && b2 <= 0x9E) {
                buf[w++] = (char)(b2 - 0x80 + 0x60);
                r += 3;
                continue;
            }
        }
        /* U+3000 ideographic space: E3 80 80 → ASCII space */
        if (r + 2 < len && b0 == 0xE3 &&
            (unsigned char)buf[r+1] == 0x80 &&
            (unsigned char)buf[r+2] == 0x80) {
            buf[w++] = ' ';
            r += 3;
            continue;
        }
        buf[w++] = buf[r++];
    }
    buf[w] = '\0';
    return w;
}

static size_t
strip_zero_width(char *buf, size_t len) {
    /* Zero-width bytes (3-byte UTF-8 sequences):
     *   U+200B ZERO WIDTH SPACE     = E2 80 8B
     *   U+200C ZERO WIDTH NON-JOIN  = E2 80 8C
     *   U+200D ZERO WIDTH JOINER    = E2 80 8D
     *   U+2060 WORD JOINER          = E2 81 A0
     *   U+FEFF BOM (when not at pos 0) = EF BB BF                    */
    size_t r = 0, w = 0;
    while (r < len) {
        unsigned char b0 = (unsigned char)buf[r];
        if (r + 2 < len && b0 == 0xE2) {
            unsigned char b1 = (unsigned char)buf[r+1];
            unsigned char b2 = (unsigned char)buf[r+2];
            if ((b1 == 0x80 && (b2 == 0x8B || b2 == 0x8C || b2 == 0x8D))
                || (b1 == 0x80 && b2 == 0xAE)  /* RTL override */
                || (b1 == 0x81 && b2 == 0xA0))  /* word joiner */
            {
                r += 3;
                continue;
            }
        }
        if (r + 2 < len && b0 == 0xEF) {
            unsigned char b1 = (unsigned char)buf[r+1];
            unsigned char b2 = (unsigned char)buf[r+2];
            if (b1 == 0xBB && b2 == 0xBF && r > 0) { /* BOM not at start */
                r += 3;
                continue;
            }
        }
        buf[w++] = buf[r++];
    }
    buf[w] = '\0';
    return w;
}

/* Decode HTML numeric entities in-place: &#82; → R, &#x52; → R.
 * Only handles numeric entities (not named like &amp;).
 * Operates on an already-lowered ASCII buffer.                         */
static void
decode_html_entities(char *buf) {
    char *r = buf, *w = buf;
    while (*r) {
        if (*r == '&' && *(r+1) == '#') {
            char *end = NULL;
            long codepoint = 0;
            if (*(r+2) == 'x' || *(r+2) == 'X') {
                codepoint = strtol(r + 3, &end, 16);
            } else {
                codepoint = strtol(r + 2, &end, 10);
            }
            /* Accept both &#82; (with semicolon) and &#82G (without).
             * Browsers parse unterminated numeric entities the same way.
             * Attackers use sloppy HTML to evade strict parsers.       */
            if (end && end != r + 2 && codepoint >= 0x20 && codepoint < 0x7F) {
                char c = (char)codepoint;
                if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                *w++ = c;
                r = end;
                if (*r == ';') r++;  /* consume semicolon if present */
                continue;
            }
        }
        *w++ = *r++;
    }
    *w = '\0';
}

/* Normalize common l33tspeak substitutions in-place.
 * Only affects ASCII digits → letters. Conservative mapping:
 *   0→o  1→i  3→e  4→a  5→s  7→t  @→a
 * NOT applied to numbers that look like amounts ($5000).              */
static void
normalize_leet(char *buf) {
    static const char leet_map[128] = {
        ['0'] = 'o', ['1'] = 'i', ['3'] = 'e',
        ['4'] = 'a', ['5'] = 's', ['7'] = 't',
        ['@'] = 'a',
    };

    /* First pass: identify long alphanumeric tokens (>12 chars) and
     * mark them as skip zones. These are hashes, addresses, API keys
     * — NOT l33tspeak.                                                */
    unsigned char skip[8192];
    size_t len = strlen(buf);
    memset(skip, 0, len < sizeof(skip) ? len : sizeof(skip));

    {
        size_t i = 0;
        while (i < len && i < sizeof(skip)) {
            /* Find start of alphanumeric token */
            if ((buf[i] >= 'a' && buf[i] <= 'z') ||
                (buf[i] >= '0' && buf[i] <= '9')) {
                size_t start = i;
                while (i < len && ((buf[i] >= 'a' && buf[i] <= 'z') ||
                                   (buf[i] >= '0' && buf[i] <= '9')))
                    i++;
                if (i - start > 12) {
                    /* Long token — skip all digits in this range */
                    size_t k;
                    for (k = start; k < i && k < sizeof(skip); k++)
                        skip[k] = 1;
                }
            } else {
                i++;
            }
        }
    }

    /* Second pass: apply leet normalization only to non-skipped positions */
    {
        char *p = buf;
        while (*p) {
            size_t pos = (size_t)(p - buf);
            unsigned char c = (unsigned char)*p;
            if (c < 128 && leet_map[c] && pos < sizeof(skip) && !skip[pos]) {
                int left_ok = (p > buf) &&
                    (( *(p-1) >= 'a' && *(p-1) <= 'z') ||
                     ( *(p-1) >= 'A' && *(p-1) <= 'Z'));
                int right_ok = (*(p+1) >= 'a' && *(p+1) <= 'z') ||
                               (*(p+1) >= 'A' && *(p+1) <= 'Z');
                int is_dollar = (p > buf && *(p-1) == '$');
                if ((left_ok || right_ok) && !is_dollar) {
                    *p = leet_map[c];
                }
            }
            p++;
        }
    }
}

/* Normalize homoglyph characters to ASCII in-place.
 * Covers Cyrillic AND Greek confusables used in phishing.
 *
 * Only collapses visually-identical characters → ASCII.              */
static size_t
normalize_homoglyphs(char *buf, size_t len) {
    /* Map: 2-byte UTF-8 → 1-byte ASCII replacement.
     * Format: { byte0, byte1, ascii_replacement }                    */
    static const struct { unsigned char b0, b1; char repl; } MAP[] = {
        /* Cyrillic (D0/D1/D2 prefix) */
        { 0xD0, 0xB0, 'a' },  /* а → a */
        { 0xD0, 0xB5, 'e' },  /* е → e */
        { 0xD0, 0xBE, 'o' },  /* о → o */
        { 0xD1, 0x80, 'p' },  /* р → p */
        { 0xD1, 0x81, 'c' },  /* с → c */
        { 0xD1, 0x83, 'y' },  /* у → y */
        { 0xD1, 0x96, 'i' },  /* і → i (Ukrainian) */
        { 0xD2, 0xBB, 'h' },  /* һ → h */
        { 0xD1, 0x85, 'x' },  /* х → x */
        { 0xD1, 0x95, 'j' },  /* ј → j */
        /* Greek (CE/CF prefix) — most commonly used in phishing      */
        { 0xCE, 0xBF, 'o' },  /* ο (omicron) → o */
        { 0xCE, 0xB1, 'a' },  /* α (alpha) → a — some fonts match */
        { 0xCE, 0xBD, 'v' },  /* ν (nu) → v */
        { 0xCF, 0x81, 'p' },  /* ρ (rho) → p */
        { 0xCE, 0xBA, 'k' },  /* κ (kappa) → k */
        { 0xCE, 0xB9, 'i' },  /* ι (iota) → i */
        { 0, 0, 0 }
    };
    size_t r = 0, w = 0;
    while (r < len) {
        if (r + 1 < len) {
            unsigned char b0 = (unsigned char)buf[r];
            unsigned char b1 = (unsigned char)buf[r + 1];
            int matched = 0;
            int i;
            for (i = 0; MAP[i].b0; i++) {
                if (b0 == MAP[i].b0 && b1 == MAP[i].b1) {
                    buf[w++] = MAP[i].repl;
                    r += 2;
                    matched = 1;
                    break;
                }
            }
            if (matched) continue;
        }
        buf[w++] = buf[r++];
    }
    buf[w] = '\0';
    return w;
}

/* ─────────────── analysis ─────────────── */

TextVerdict
hlse_check_text(const char *raw_text) {
    TextVerdict v;
    char normalized[8192];    /* whitespace-normalized, original case */
    char lower[8192];         /* ASCII-lowercased copy for EN matching */
    int  i, j;
    int  fired_urgency = 0, fired_bait = 0, fired_prize = 0;
    int  fired_ransom = 0, fired_authority = 0, fired_secrecy = 0;

    memset(&v, 0, sizeof(v));
    if (!raw_text) return v;

    normalize_whitespace(raw_text, normalized, sizeof(normalized));

    /* Make a separate ASCII-lowercased copy.
     * We match EN keywords against `lower` (case-insensitive),
     * and JP/ZH/KR keywords against `normalized` (exact bytes).
     * This approach is correct because:
     *   - EN keywords are ASCII — tolower() is safe
     *   - JP/ZH/KR keywords are already lowercase in our tables
     *     (languages don't have lowercase variants), so we match
     *     them directly against the normalized original             */
    {
        size_t n = strlen(normalized);
        if (n >= sizeof(lower)) n = sizeof(lower) - 1;
        memcpy(lower, normalized, n);
        lower[n] = '\0';
        /* Full-width → ASCII before lowering, so ｕｒｇｅｎｔ becomes urgent. */
        n = normalize_fullwidth(lower, strlen(lower));
        str_to_lower(lower);  /* safe: only touches ASCII bytes < 0x80 */

        /* Evasion-resistant normalization (applied to EN matching only):
         * 1. Strip zero-width Unicode chars that split keywords
         * 2. Decode HTML entities (&#82; → r)
         * 3. Normalize l33tspeak digits (3→e, 1→i, etc.)              */
        n = strip_zero_width(lower, strlen(lower));
        n = normalize_homoglyphs(lower, n);
        decode_html_entities(lower);
        normalize_leet(lower);
    }

    /* Match a keyword against either lower (ASCII) or normalized (multibyte).
     * If keyword starts with a byte >= 0x80, it's a multibyte keyword
     * and we match it against the original (normalized) text.          */
    #define MATCH(keyword) \
        (((unsigned char)(keyword)[0] < 0x80) \
            ? str_contains(lower, (keyword)) \
            : str_contains(normalized, (keyword)))

    /* Pass 1 — scan signal table */
    for (i = 0; SIGNALS[i].name != NULL; i++) {
        const Signal *sig = &SIGNALS[i];
        const char  *first_hit = NULL;
        int          n_hits = 0;

        for (j = 0; sig->words[j] != NULL; j++) {
            if (MATCH(sig->words[j])) {
                n_hits++;
                if (!first_hit) first_hit = sig->words[j];
            }
        }
        if (n_hits == 0) continue;

        {
            int contrib = sig->base_weight
                        + (n_hits - 1) * sig->per_hit_bonus;
            if (contrib > sig->max_contribution)
                contrib = sig->max_contribution;
            add_text_reason(&v, contrib,
                "%s (%d hit%s, e.g. '%s')",
                sig->name, n_hits, n_hits == 1 ? "" : "s",
                first_hit ? first_hit : "");
        }

        if (strcmp(sig->name, "Urgency pressure") == 0) fired_urgency = 1;
        else if (strcmp(sig->name, "Financial/credential req") == 0) fired_bait = 1;
        else if (strcmp(sig->name, "Prize/reward lure") == 0) fired_prize = 1;
        else if (strcmp(sig->name, "Ransom/extortion language") == 0) fired_ransom = 1;
        else if (strcmp(sig->name, "Authority impersonation") == 0) fired_authority = 1;
        else if (strcmp(sig->name, "Secrecy/grooming") == 0) fired_secrecy = 1;
    }

    #undef MATCH

    /* Pass 2 — compound amplifiers */
    {
        int has_gift = str_contains(lower, "gift card")
                    || str_contains(lower, "itunes")
                    || str_contains(lower, "google play")
                    || str_contains(lower, "amazon gift")
                    /* JP */ || str_contains(normalized, "\xe3\x82\xae\xe3\x83\x95\xe3\x83\x88\xe3\x82\xab\xe3\x83\xbc\xe3\x83\x89")
                    /* JP */ || str_contains(normalized, "\xe3\x82\xa2\xe3\x83\x9e\xe3\x82\xbe\xe3\x83\xb3\xe3\x82\xae\xe3\x83\x95\xe3\x83\x88");
        if (fired_urgency && has_gift) {
            add_text_reason(&v, 25,
                "Amplifier: gift card + urgency = tech-support scam pattern");
        }
        if (fired_prize && fired_bait) {
            add_text_reason(&v, 20,
                "Amplifier: prize + financial request = lottery/advance-fee fraud");
        }
        {
            int has_wire = str_contains(lower, " wire ")
                        || str_contains(lower, "wire transfer")
                        || str_contains(lower, "please wire")
                        /* JP */ || str_contains(normalized, "\xe6\x8c\xaf\xe8\xbe\xbc")
                        /* JP */ || str_contains(normalized, "\xe6\x8c\xaf\xe3\x82\x8a\xe8\xbe\xbc");
            if (fired_urgency && has_wire) {
                add_text_reason(&v, 30,
                    "Amplifier: wire transfer + urgency = BEC pattern");
            }
            /* Literature-grounded BEC signature (arxiv 2308.10776, BEC
             * 58-feature studies): the strongest BEC pattern combines
             * AUTHORITY (CEO/CFO/Legal) + financial action + SECRECY
             * (isolate the victim from verification). Each pair raises
             * confidence; all three is the canonical CEO-fraud script. */
            if (fired_authority && has_wire) {
                add_text_reason(&v, 25,
                    "Amplifier: authority figure + wire transfer = "
                    "CEO-fraud pattern");
            }
            if (fired_secrecy && has_wire) {
                add_text_reason(&v, 20,
                    "Amplifier: secrecy pressure + financial request = "
                    "victim isolation tactic");
            }
            if (fired_authority && fired_secrecy && (has_wire || fired_bait)) {
                add_text_reason(&v, 20,
                    "Amplifier: authority + secrecy + payment = "
                    "classic BEC isolation script");
            }
        }
        {
            const char *p = strstr(lower, "bc1");
            if (p && fired_ransom) {
                int word_len = 0;
                while (p[word_len] && p[word_len] != ' ' && p[word_len] != '\n')
                    word_len++;
                if (word_len >= 42 && word_len <= 62) {
                    add_text_reason(&v, 20,
                        "Amplifier: crypto address + extortion context");
                }
            }
        }
    }

    /* Suspicious URL in flagged context */
    {
        int has_url = str_contains(lower, "http")
                   || str_contains(lower, "bit.ly")
                   || str_contains(lower, ".xyz")
                   || str_contains(lower, ".top")
                   || str_contains(lower, ".click");
        if (has_url && v.score > 0) {
            add_text_reason(&v, 10, "URL in suspicious context");
        }
    }

    if (v.score < 15) {
        memset(&v, 0, sizeof(v));
    }

    return v;
}

const char *
hlse_text_action_for_score(int score) {
    if (score >= 80) return "ISOLATE";
    if (score >= 60) return "BLOCK";
    if (score >= 40) return "ALERT";
    if (score >= 15) return "LOG";
    return "SAFE";
}
