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
#include "hlse_alert.h"    /* hlse_alert_init/emit/shutdown */

#include <sys/stat.h>
#include <sys/wait.h>     /* waitpid — reap the `git log` child (P0-2) */
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* ───────────────────────────── version ──────────────────────────────── */
/* HLSE_VERSION is defined in hlse_core.h so library users can read it
 * without access to this translation unit.                             */
#define HLSE_BUILD_DATE    __DATE__

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
    /* Microsoft collaboration — teams-enterprise.com / teams-signin.com phishing */
    "teams",
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

/* Return the canonical domain for a known brand, so detectors can surface
 * "where to actually go" alongside each impersonation warning.
 * Returns NULL for any brand not in the table (safe callers must handle).  */
static const char *brand_canonical(const char *brand) {
    if (!brand) return NULL;
    if (strcmp(brand, "1password")       == 0) return "1password.com";
    if (strcmp(brand, "adobe")           == 0) return "adobe.com";
    if (strcmp(brand, "amazon")          == 0) return "amazon.com";
    if (strcmp(brand, "anthropic")       == 0) return "anthropic.com";
    if (strcmp(brand, "apple")           == 0) return "apple.com";
    if (strcmp(brand, "avast")           == 0) return "avast.com";
    if (strcmp(brand, "bankofamerica")   == 0) return "bankofamerica.com";
    if (strcmp(brand, "barclays")        == 0) return "barclays.com";
    if (strcmp(brand, "bestbuy")         == 0) return "bestbuy.com";
    if (strcmp(brand, "binance")         == 0) return "binance.com";
    if (strcmp(brand, "bitdefender")     == 0) return "bitdefender.com";
    if (strcmp(brand, "bitwarden")       == 0) return "bitwarden.com";
    if (strcmp(brand, "blockchain")      == 0) return "blockchain.com";
    if (strcmp(brand, "capitalone")      == 0) return "capitalone.com";
    if (strcmp(brand, "cashapp")         == 0) return "cash.app";
    if (strcmp(brand, "chatgpt")         == 0) return "chatgpt.com";
    if (strcmp(brand, "chase")           == 0) return "chase.com";
    if (strcmp(brand, "citibank")        == 0) return "citi.com";
    if (strcmp(brand, "cloudflare")      == 0) return "cloudflare.com";
    if (strcmp(brand, "coinbase")        == 0) return "coinbase.com";
    if (strcmp(brand, "coincheck")       == 0) return "coincheck.com";
    if (strcmp(brand, "crypto")          == 0) return "crypto.com";
    if (strcmp(brand, "dhl")             == 0) return "dhl.com";
    if (strcmp(brand, "dhlexpress")      == 0) return "dhlexpress.com";
    if (strcmp(brand, "discord")         == 0) return "discord.com";
    if (strcmp(brand, "disney")          == 0) return "disneyplus.com";
    if (strcmp(brand, "docomo")          == 0) return "docomo.ne.jp";
    if (strcmp(brand, "docusign")        == 0) return "docusign.com";
    if (strcmp(brand, "dropbox")         == 0) return "dropbox.com";
    if (strcmp(brand, "ebay")            == 0) return "ebay.com";
    if (strcmp(brand, "epicgames")       == 0) return "epicgames.com";
    if (strcmp(brand, "etrade")          == 0) return "etrade.com";
    if (strcmp(brand, "facebook")        == 0) return "facebook.com";
    if (strcmp(brand, "fedex")           == 0) return "fedex.com";
    if (strcmp(brand, "fidelity")        == 0) return "fidelity.com";
    if (strcmp(brand, "figma")           == 0) return "figma.com";
    if (strcmp(brand, "gemini")          == 0) return "gemini.google.com";
    if (strcmp(brand, "github")          == 0) return "github.com";
    if (strcmp(brand, "gitlab")          == 0) return "gitlab.com";
    if (strcmp(brand, "google")          == 0) return "google.com";
    if (strcmp(brand, "hbo")             == 0) return "max.com";
    if (strcmp(brand, "homedepot")       == 0) return "homedepot.com";
    if (strcmp(brand, "hsbc")            == 0) return "hsbc.com";
    if (strcmp(brand, "hulu")            == 0) return "hulu.com";
    if (strcmp(brand, "instagram")       == 0) return "instagram.com";
    if (strcmp(brand, "intuit")          == 0) return "intuit.com";
    if (strcmp(brand, "kaspersky")       == 0) return "kaspersky.com";
    if (strcmp(brand, "kraken")          == 0) return "kraken.com";
    if (strcmp(brand, "lastpass")        == 0) return "lastpass.com";
    if (strcmp(brand, "ledger")          == 0) return "ledger.com";
    if (strcmp(brand, "line")            == 0) return "line.me";
    if (strcmp(brand, "linkedin")        == 0) return "linkedin.com";
    if (strcmp(brand, "malwarebytes")    == 0) return "malwarebytes.com";
    if (strcmp(brand, "mcafee")          == 0) return "mcafee.com";
    if (strcmp(brand, "meta")            == 0) return "meta.com";
    if (strcmp(brand, "metamask")        == 0) return "metamask.io";
    if (strcmp(brand, "microsoft")       == 0) return "microsoft.com";
    if (strcmp(brand, "microsoft365")    == 0) return "microsoft365.com";
    if (strcmp(brand, "microsoftonline") == 0) return "login.microsoftonline.com";
    if (strcmp(brand, "microsoftteams")  == 0) return "teams.microsoft.com";
    if (strcmp(brand, "mizuho")          == 0) return "mizuho-fg.co.jp";
    if (strcmp(brand, "mufg")            == 0) return "mufg.jp";
    if (strcmp(brand, "netflix")         == 0) return "netflix.com";
    if (strcmp(brand, "norton")          == 0) return "norton.com";
    if (strcmp(brand, "notion")          == 0) return "notion.so";
    if (strcmp(brand, "office365")       == 0) return "microsoft365.com";
    if (strcmp(brand, "okta")            == 0) return "okta.com";
    if (strcmp(brand, "openai")          == 0) return "openai.com";
    if (strcmp(brand, "opensea")         == 0) return "opensea.io";
    if (strcmp(brand, "oracle")          == 0) return "oracle.com";
    if (strcmp(brand, "outlook")         == 0) return "outlook.com";
    if (strcmp(brand, "pancakeswap")     == 0) return "pancakeswap.finance";
    if (strcmp(brand, "payoneer")        == 0) return "payoneer.com";
    if (strcmp(brand, "paypal")          == 0) return "paypal.com";
    if (strcmp(brand, "paypay")          == 0) return "paypay.ne.jp";
    if (strcmp(brand, "peacock")         == 0) return "peacocktv.com";
    if (strcmp(brand, "quickbooks")      == 0) return "quickbooks.intuit.com";
    if (strcmp(brand, "rakuten")         == 0) return "rakuten.co.jp";
    if (strcmp(brand, "reddit")          == 0) return "reddit.com";
    if (strcmp(brand, "revolut")         == 0) return "revolut.com";
    if (strcmp(brand, "robinhood")       == 0) return "robinhood.com";
    if (strcmp(brand, "roblox")          == 0) return "roblox.com";
    if (strcmp(brand, "salesforce")      == 0) return "salesforce.com";
    if (strcmp(brand, "schwab")          == 0) return "schwab.com";
    if (strcmp(brand, "shopify")         == 0) return "shopify.com";
    if (strcmp(brand, "slack")           == 0) return "slack.com";
    if (strcmp(brand, "smbc")            == 0) return "smbc.co.jp";
    if (strcmp(brand, "snapchat")        == 0) return "snapchat.com";
    if (strcmp(brand, "softbank")        == 0) return "softbank.jp";
    if (strcmp(brand, "spotify")         == 0) return "spotify.com";
    if (strcmp(brand, "steam")           == 0) return "steampowered.com";
    if (strcmp(brand, "stripe")          == 0) return "stripe.com";
    if (strcmp(brand, "teams")           == 0) return "teams.microsoft.com";
    if (strcmp(brand, "telegram")        == 0) return "telegram.org";
    if (strcmp(brand, "tiktok")          == 0) return "tiktok.com";
    if (strcmp(brand, "tmobile")         == 0) return "t-mobile.com";
    if (strcmp(brand, "trezor")          == 0) return "trezor.io";
    if (strcmp(brand, "truist")          == 0) return "truist.com";
    if (strcmp(brand, "trustwallet")     == 0) return "trustwallet.com";
    if (strcmp(brand, "turbotax")        == 0) return "turbotax.intuit.com";
    if (strcmp(brand, "twilio")          == 0) return "twilio.com";
    if (strcmp(brand, "twitch")          == 0) return "twitch.tv";
    if (strcmp(brand, "twitter")         == 0) return "x.com";
    if (strcmp(brand, "uniswap")         == 0) return "uniswap.org";
    if (strcmp(brand, "ups")             == 0) return "ups.com";
    if (strcmp(brand, "usbank")          == 0) return "usbank.com";
    if (strcmp(brand, "usps")            == 0) return "usps.com";
    if (strcmp(brand, "venmo")           == 0) return "venmo.com";
    if (strcmp(brand, "verizon")         == 0) return "verizon.com";
    if (strcmp(brand, "walmart")         == 0) return "walmart.com";
    if (strcmp(brand, "wellsfargo")      == 0) return "wellsfargo.com";
    if (strcmp(brand, "whatsapp")        == 0) return "whatsapp.com";
    if (strcmp(brand, "wise")            == 0) return "wise.com";
    if (strcmp(brand, "wordpress")       == 0) return "wordpress.com";
    if (strcmp(brand, "yahoo")           == 0) return "yahoo.com";
    if (strcmp(brand, "youtube")         == 0) return "youtube.com";
    if (strcmp(brand, "zelle")           == 0) return "zellepay.com";
    if (strcmp(brand, "zoom")            == 0) return "zoom.us";
    return NULL;
}

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
    "/verify", "/signin", "/sign-in", "/login", "/log-in",
    "/account", "/update",
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
    /* Wallet-connect / wallet-drain phishing paths */
    "/connect-wallet", "/import-wallet", "/restore-wallet",
    "/sync-wallet", "/link-wallet", "/migrate-wallet",
    /* Meeting / collaboration platform phishing (fake Teams, Zoom invite) */
    "/join-meeting", "/secure-meeting", "/verify-meeting",
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
    /* Callback-phishing / order-cancellation fraud: amazon-order-cancel.com,
     * paypal-cancel-order.com — the brand never hyphenates these in its SLD. */
    "cancel", "order",
    /* Brand-service impersonation: microsoft-service.com, apple-service-desk.com */
    "service",
    /* Fake notification/alert portals: apple-notification-center.com */
    "notification",
    /* Delivery fee / customs-scam domain lures: fedex-duty.com, ups-fee.com,
     * dhl-customs.com. Real carriers never put "fee" or "duty" in their SLD. */
    "duty", "fee",
    /* Tracking / delivery phishing lures: track-package.com, delivery-track.net */
    "track", "tracking", "delivery",
    /* Crypto wallet-connect phishing lures: metamask-connect.com,
     * ledger-connect.io, trustwallet-connect-wallet.com               */
    "connect",
    NULL
};

/* Brand-impersonation suffix words — product names / editions / generic
 * business terms that are TOO COMMON in legitimate registrable domains to
 * be treated as generic "security words" (enterprise-blog.com, drive-thru.com
 * and hard-drive-recovery.com are all benign).  They are suspicious ONLY when
 * fused to a known brand: slack-enterprise.com, microsoftexcel.com,
 * googledrive.net.  Used exclusively by the brand-impersonation checks below;
 * they never contribute to the generic hyphenation counter.            */
static const char *BRAND_SUFFIX_WORDS[] = {
    "enterprise", "excel", "outlook", "drive", "onedrive",
    "sharepoint", "office", "workspace", "meet", "calendar",
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

/* Append the canonical-domain "Legitimate '<brand>': <domain>" reason for a
 * detected brand impersonation — but only once per verdict. Multiple brand
 * detectors can fire on the same URL (subdomain-spoof AND free-hosting, say);
 * without this dedup the same canonical line is emitted twice, wasting one of
 * the 12 reason slots and reading as a duplicate. Zero score delta. */
static void
add_brand_canonical(Verdict *v, const char *brand) {
    const char *canon = brand_canonical(brand);
    char want[128];
    int i;
    if (!canon) return;
    snprintf(want, sizeof(want), "Legitimate '%s': %s", brand, canon);
    for (i = 0; i < v->n_reasons; i++)
        if (strcmp(v->reasons[i], want) == 0) return;  /* already present */
    add_reason(v, 0, "%s", want);
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
                    add_brand_canonical(v, BRANDS[i]);
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
                add_brand_canonical(v, b);
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
    /* Crypto wallets — legitimate wallet sites use /connect-wallet,
     * /seed, /mnemonic in their real UIs; don't flag those.            */
    "metamask.io", "ledger.com", "trezor.io",
    "trustwallet.com", "phantom.app",
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

/* Returns 1 if the registrable domain is exactly "<brand>.com" — i.e. the
 * brand's own canonical domain, which the trademark holder owns. A brand is
 * never impersonated on its *own* "<brand>.com"; the danger is always a
 * different registrable domain (paypal.xyz, paypal-verify.com) or a
 * confusable (g00gle.com). sld_label() returns the true registrable SLD, so
 * a nested decoy like "paypal.com.evil.com" yields SLD "evil" (not a brand)
 * and is correctly excluded. Scales to every brand without a per-brand map. */
static int
is_own_brand_dotcom(const char *host) {
    char sld_buf[MAX_HOST];
    const char *sld;
    int i;
    if (!ends_with(host, ".com")) return 0;
    sld = sld_label(host, sld_buf, sizeof(sld_buf));
    if (!sld) return 0;
    for (i = 0; BRANDS[i] != NULL; i++) {
        if (strcmp(sld, BRANDS[i]) == 0) return 1;
    }
    return 0;
}

/* 3. Phishing path patterns. */
static void
detect_phishing_path(const ParsedUrl *u, Verdict *v) {
    int i;
    int matches = 0;
    char first[64];
    int trusted = is_trusted_host(u->host) || is_own_brand_dotcom(u->host);
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
                        /* Brand as direct subdomain of a trusted parent
                         * (e.g. outlook.live.com, outlook.microsoft.com).
                         * Only exempt when no additional nesting exists —
                         * paypal.com.google.com has registrable_start > 1. */
                        if (registrable_start == 1 &&
                            is_trusted_host(registrable)) return;
                        (void)blen;  /* used via brand_is_token_in_sld */

                        add_reason(v, token_match ? 35 : 45,
                                   "Subdomain spoofing: '%s' appears before "
                                   "registrable domain", BRANDS[j]);
                        add_brand_canonical(v, BRANDS[j]);
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

    /* ── Brand-impersonation cascade (mutually exclusive) ──────────────
     * Evaluated most-specific first; `brand_matched` ensures a single
     * registrable domain contributes at most one brand-impersonation
     * reason, so paypal-verify.net is not scored twice.                 */
    {
        int brand_matched = 0;

        /* (1) Brand + hyphen + security word — classic phishing pattern:
         * paypal-verify, apple-support, microsoft-account. brand_is_token_in_sld
         * requires a complete hyphen-delimited token, so short brands (e.g.
         * "line") don't fire on "airline-update". Brand and security word may
         * appear in any order ("secure-paypal" as well as "paypal-verify"). */
        if (hyphens >= 1 && sec_count >= 1) {
            for (i = 0; BRANDS[i] != NULL; i++) {
                if (brand_is_token_in_sld(sld, BRANDS[i])) {
                    add_reason(v, 35,
                        "Brand impersonation: '%s' hyphenated with security "
                        "term — real brand uses its own domain", BRANDS[i]);
                    add_brand_canonical(v, BRANDS[i]);
                    brand_matched = 1;
                    break;
                }
            }
        }

        /* (2) Brand fused (concat or hyphen) to a security word or a
         * brand-suffix word and LEADING the SLD: "googleverify.net",
         * "microsoftexcel.com", "slack-enterprise.com". The BRAND_SUFFIX_WORDS
         * arm catches product/edition terms (enterprise, excel, drive) that
         * are too common to be generic security words but are damning when
         * fused to a brand. Only the leading-brand form is checked here; the
         * in-order hyphen form is already handled by (1).                   */
        if (!brand_matched) {
            for (i = 0; BRANDS[i] != NULL; i++) {
                size_t blen = strlen(BRANDS[i]);
                const char *after;
                int j;
                if (blen < 4) continue;
                if (strncmp(sld, BRANDS[i], blen) != 0) continue;
                after = sld + blen;
                if (*after == '-') after++;        /* hyphenated: skip sep    */
                else if (*after == '\0') continue; /* bare brand: see (4)     */
                for (j = 0; SECURITY_WORDS[j] != NULL && !brand_matched; j++) {
                    size_t wl = strlen(SECURITY_WORDS[j]);
                    if (strncmp(after, SECURITY_WORDS[j], wl) == 0 &&
                        (after[wl] == '\0' || after[wl] == '-')) {
                        add_reason(v, 30,
                            "Brand+security-word fusion: '%s' prefixes SLD "
                            "with its own name — real brand uses its own "
                            "domain", BRANDS[i]);
                        add_brand_canonical(v, BRANDS[i]);
                        brand_matched = 1;
                    }
                }
                for (j = 0; BRAND_SUFFIX_WORDS[j] != NULL && !brand_matched; j++) {
                    size_t wl = strlen(BRAND_SUFFIX_WORDS[j]);
                    if (strncmp(after, BRAND_SUFFIX_WORDS[j], wl) == 0 &&
                        (after[wl] == '\0' || after[wl] == '-')) {
                        add_reason(v, 30,
                            "Brand+product-term fusion: '%s' fused to '%s' — "
                            "real brand serves this from its own domain",
                            BRANDS[i], BRAND_SUFFIX_WORDS[j]);
                        add_brand_canonical(v, BRANDS[i]);
                        brand_matched = 1;
                    }
                }
                if (brand_matched) break;
            }
        }

        /* (3) Brand as a complete token in a hyphenated SLD without any
         * security word — covers mobile-app / wallet-connect framing like
         * "metamask-io-app.com". Minimum length 6 avoids common short words. */
        if (!brand_matched && hyphens >= 1 && sec_count == 0) {
            for (i = 0; BRANDS[i] != NULL; i++) {
                if (strlen(BRANDS[i]) >= 6 &&
                    brand_is_token_in_sld(sld, BRANDS[i])) {
                    add_reason(v, 25,
                        "Brand present in hyphenated domain — "
                        "real '%s' does not use a hyphenated SLD", BRANDS[i]);
                    add_brand_canonical(v, BRANDS[i]);
                    brand_matched = 1;
                    break;
                }
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
            add_brand_canonical(v, BRANDS[i]);
            return;
        }
        if (d == 2 && bl >= 7) {
            add_reason(v, 30,
                       "Possible typosquat: '%s' is edit distance 2 from '%s'",
                       sld, BRANDS[i]);
            add_brand_canonical(v, BRANDS[i]);
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
                    add_brand_canonical(v, BRANDS[i]);
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
                    add_brand_canonical(v, BRANDS[i]);
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
                add_brand_canonical(v, BRANDS[i]);
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
     * RFC 3986 §3.2.1 allows userinfo@host but browsers use host only.
     * The '@' must be inside the AUTHORITY (between "://" and the first
     * '/', '?', or '#') — an '@' in the path/query (e.g. an email address
     * in "?email=user@gmail.com") is not a credential trick.              */
    {
        size_t scheme_len = u.is_https ? 8 : 7;  /* https:// or http:// */
        const char *auth = raw_url + scheme_len;
        const char *at = strchr(auth, '@');
        if (at) {
            /* Find the authority terminator. */
            const char *end = auth;
            while (*end && *end != '/' && *end != '?' && *end != '#') end++;
            if (at < end) {
                add_reason(&v, 45, "URL credential trick: @ in authority — "
                           "displayed host is fake, real host follows @");
            }
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
            /* Popular free website builders heavily abused for phishing lures */
            "000webhostapp.com",  /* 000webhost — top free host for phishing */
            "wixsite.com",        /* Wix website builder */
            "weebly.com",         /* Weebly */
            "godaddysites.com",   /* GoDaddy website builder */
            "mystrikingly.com",   /* Strikingly */
            "sites.google.com",   /* Google Sites (for subdomain checks) */
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
                            add_brand_canonical(&v, BRANDS[bi]);
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
                    add_brand_canonical(&v, BRANDS[i]);
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

    /* Obfuscated / dotless IP host — hex (0x7f000001), dword-decimal
     * (2130706433), or octal forms decode to a real IP but evade naive
     * blocklists and hide the destination from the user. A host with no dot
     * that is all-digits or 0x-hex is never a registrable domain (no
     * all-numeric TLD exists), so this is a high-confidence evasion signal
     * with effectively zero false positives.                              */
    {
        const char *h = u.host;
        size_t hlen = strlen(h);
        if (hlen > 0 && h[0] != '[' && !strchr(h, '.') && !strchr(h, ':')) {
            int all_digits = 1, is_hex = 0;
            size_t k;
            if (hlen > 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) {
                is_hex = 1;
                for (k = 2; k < hlen; k++) {
                    char c = h[k];
                    if (!((c >= '0' && c <= '9') ||
                          (c >= 'a' && c <= 'f') ||
                          (c >= 'A' && c <= 'F'))) { is_hex = 0; break; }
                }
            }
            for (k = 0; k < hlen; k++) {
                if (h[k] < '0' || h[k] > '9') { all_digits = 0; break; }
            }
            /* Dword-decimal IPs are large; require >=7 digits to avoid
             * flagging a stray numeric token, while 0x-hex is unambiguous. */
            if (is_hex || (all_digits && hlen >= 7)) {
                add_reason(&v, 40,
                    "Obfuscated IP host '%s' — %s-encoded address hides the "
                    "real destination (evasion technique)", h,
                    is_hex ? "hex" : "decimal");
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

        /* Open-redirect scan: if the URL contains a query parameter that
         * itself holds an http/https URL (e.g. ?continue=, ?redirect=,
         * ?url=, ?next=), scan that embedded URL too.  Attackers abuse
         * legitimate redirect endpoints on trusted domains to bypass URL
         * filters.  We do NOT suppress on trusted outer host — the outer
         * host being legitimate is exactly what makes open-redirect abuse
         * dangerous.                                                      */
        {
            const char *qs = strchr(input, '?');
            if (qs) {
                const char *ep = qs;
                while ((ep = strstr(ep, "http")) != NULL) {
                    if (ep == input) { ep += 4; continue; }
                    if (strncmp(ep, "http://",  7) == 0 ||
                        strncmp(ep, "https://", 8) == 0)
                    {
                        char redir[2048];
                        int k = 0;
                        while (ep[k] && ep[k] != ' ' && ep[k] != '\t' &&
                               ep[k] != '&' && ep[k] != '#' &&
                               ep[k] != '"' && ep[k] != '\'' &&
                               k < (int)sizeof(redir) - 1) {
                            redir[k] = ep[k]; k++;
                        }
                        redir[k] = '\0';
                        if (k > 10 && strcmp(redir, input) != 0) {
                            Verdict uv_r = check_url(redir);
                            if (uv_r.score > 0) {
                                int j2;
                                for (j2 = 0; j2 < uv_r.n_reasons &&
                                             r.n_reasons < 16; j2++) {
                                    size_t csz =
                                        sizeof(uv_r.reasons[0]) <
                                        sizeof(r.reasons[0])
                                        ? sizeof(uv_r.reasons[0])
                                        : sizeof(r.reasons[0]);
                                    memcpy(r.reasons[r.n_reasons],
                                           uv_r.reasons[j2], csz);
                                    r.n_reasons++;
                                }
                                if (r.n_reasons < 16) {
                                    snprintf(r.reasons[r.n_reasons],
                                             sizeof(r.reasons[0]),
                                             "Open redirect to suspicious URL"
                                             " — trusted domain abused as"
                                             " redirect proxy");
                                    r.n_reasons++;
                                }
                                r.score += uv_r.score;
                                if (r.score > 100) r.score = 100;
                            }
                        }
                        ep += k;
                    } else {
                        ep += 4;
                    }
                }
            }
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

        /* Bare-domain scan: find "domain.tld[/path]" without a scheme
         * prefix, synthesise "https://...", run URL detection.
         * Group A (inherently suspicious TLDs): scan always (≥3-char prefix).
         * Group B (common TLDs): only when domain contains a hyphen —
         * hallmark of lookalike / typosquat phishing.                   */
        {
#define BD_ALWAYS_N 8
            static const char *const BD_TLDS[] = {
                /* Group A — always scan (suspicious TLD) */
                ".xyz", ".top", ".click", ".tk", ".pw", ".su", ".vip", ".icu",
                /* Group B — require hyphen in domain */
                ".com", ".net", ".org", ".io", ".cc", ".info", ".biz",
                ".online", ".site", ".ru",
                NULL
            };
            int wt;
            for (wt = 0; BD_TLDS[wt]; wt++) {
                const char *tld2    = BD_TLDS[wt];
                size_t      tlen2   = strlen(tld2);
                int         need_hy = (wt >= BD_ALWAYS_N);
                const char *bp2     = input;
                while ((bp2 = strstr(bp2, tld2)) != NULL) {
                    unsigned char aft2 = (unsigned char)bp2[tlen2];
                    /* TLD must end at path-sep, whitespace, or string end */
                    if (aft2 && aft2 != '/' && aft2 != ' ' && aft2 != '\t' &&
                        aft2 != '\n' && aft2 != '\r' && aft2 != ',' &&
                        aft2 != '.' && aft2 != ')' && aft2 != '"' &&
                        aft2 != '\'' && aft2 != '>' && aft2 != ']') {
                        bp2 += tlen2;
                        continue;
                    }
                    /* Walk backwards to domain start (domain chars only) */
                    {
                        const char *dom_s = bp2;
                        while (dom_s > input) {
                            unsigned char c2 = (unsigned char)*(dom_s - 1);
                            if ((c2 >= 'a' && c2 <= 'z') ||
                                (c2 >= 'A' && c2 <= 'Z') ||
                                (c2 >= '0' && c2 <= '9') ||
                                c2 == '-' || c2 == '.') {
                                dom_s--;
                            } else {
                                break;
                            }
                        }
                        /* Must start at a word boundary */
                        if (dom_s > input) {
                            unsigned char bef2 = (unsigned char)*(dom_s - 1);
                            if ((bef2 >= 'a' && bef2 <= 'z') ||
                                (bef2 >= 'A' && bef2 <= 'Z') ||
                                (bef2 >= '0' && bef2 <= '9')) {
                                bp2 += tlen2;
                                continue;
                            }
                        }
                        /* Skip already-schemed URLs handled above */
                        if (dom_s >= input + 3 &&
                            dom_s[-3] == ':' && dom_s[-2] == '/' && dom_s[-1] == '/') {
                            bp2 += tlen2;
                            continue;
                        }
                        /* Qualify: prefix length and hyphen requirement */
                        {
                            size_t prefix_len = (size_t)(bp2 - dom_s);
                            int    has_hyph   = 0;
                            size_t ki2;
                            for (ki2 = 0; ki2 < prefix_len; ki2++) {
                                if (dom_s[ki2] == '-') { has_hyph = 1; break; }
                            }
                            if (need_hy && !has_hyph) { bp2 += tlen2; continue; }
                            if (!need_hy && prefix_len < 3U) { bp2 += tlen2; continue; }
                        }
                        /* Extend to include path */
                        {
                            const char *dom_e = bp2 + tlen2;
                            while (*dom_e &&
                                   *dom_e != ' '  && *dom_e != '\t' &&
                                   *dom_e != '\n' && *dom_e != '\r' &&
                                   *dom_e != ','  && *dom_e != ')'  &&
                                   *dom_e != '"'  && *dom_e != '\'' &&
                                   *dom_e != '>'  && *dom_e != ']'  &&
                                   (size_t)(dom_e - dom_s) < 500U) {
                                dom_e++;
                            }
                            /* Synthesise https:// URL and run check_url */
                            {
                                size_t dlen2 = (size_t)(dom_e - dom_s);
                                if (dlen2 >= 4U && dlen2 + 9U < 2048U) {
                                    char syn2[2048];
                                    Verdict uv3;
                                    memcpy(syn2, "https://", 8);
                                    memcpy(syn2 + 8, dom_s, dlen2);
                                    syn2[8 + dlen2] = '\0';
                                    uv3 = check_url(syn2);
                                    if (uv3.score > 0) {
                                        int j3;
                                        for (j3 = 0; j3 < uv3.n_reasons &&
                                                      r.n_reasons < 16; j3++) {
                                            size_t csz =
                                                sizeof(uv3.reasons[0]) <
                                                sizeof(r.reasons[0])
                                                ? sizeof(uv3.reasons[0])
                                                : sizeof(r.reasons[0]);
                                            memcpy(r.reasons[r.n_reasons],
                                                   uv3.reasons[j3], csz);
                                            r.n_reasons++;
                                        }
                                        r.score += uv3.score;
                                        if (r.score > 100) r.score = 100;
                                    }
                                }
                            }
                            bp2 = dom_e;
                        }
                    }
                }
            }
#undef BD_ALWAYS_N
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

/* Map a score to a monotonic severity integer (0–4) aligned with CVSS-style
 * numeric severity levels.  Consumers can write `severity >= 3` instead of
 * `action == "BLOCK" || action == "ISOLATE"`, making rules stable against any
 * future insertion of a new named tier:
 *   0 = SAFE    (0..14)
 *   1 = LOG    (15..39)
 *   2 = ALERT  (40..59)
 *   3 = BLOCK  (60..79)
 *   4 = ISOLATE(80+)    */
int
hlse_severity_for_score(int score) {
    if (score >= 80) return 4;
    if (score >= 60) return 3;
    if (score >= 40) return 2;
    if (score >= 15) return 1;
    return 0;
}

/* Recommended next action for an actionable verdict (score >= 60).
 *
 * A detector answers "is this dangerous?"; the user's real question is "what
 * do I do now?". For the highest-stakes, time-critical checks we return a
 * concrete remediation directive, turning a verdict into a response. `kind`
 * is the subcommand label ("clipboard", "secret", "email", "url", "file").
 * Returns NULL when there is no specific guidance (caller prints nothing).  */
const char *
hlse_remediation_for(const char *kind, int score) {
    if (score < 60 || !kind) return NULL;
    if (strcmp(kind, "clipboard") == 0)
        return "Do NOT send funds. Clipboard-hijacker malware may be active: "
               "re-copy the address, verify every character against the source, "
               "and run a malware scan before transacting.";
    if (strcmp(kind, "secret") == 0)
        return "Treat this credential as compromised: revoke/rotate it now and "
               "purge it from git history (git filter-repo / BFG) — commits are "
               "already cloned.";
    if (strcmp(kind, "email") == 0)
        return "Do not click links, open attachments, or reply. Verify the "
               "sender through a separately-known channel before acting.";
    if (strcmp(kind, "url") == 0)
        return "Do not enter credentials or payment details. Navigate to the "
               "brand's site by typing its known address, not via this link.";
    if (strcmp(kind, "file") == 0)
        return "Do not open or execute this file. Inspect it in a sandbox or "
               "delete it; the real type does not match its name.";
    return NULL;
}

/* Blind-spot disclosure for a CLEAN verdict (score 0). A clean result means
 * "no syntactic deception markers found" — NOT "safe". Stating what HLSE
 * cannot see prevents the most dangerous outcome: a false OK the user trusts
 * and acts on. Returned for the phishing-judgment checks where structural
 * cleanliness is weakest evidence of safety; NULL otherwise.              */
const char *
hlse_blindspot_for(const char *kind) {
    if (!kind) return NULL;
    if (strcmp(kind, "url") == 0)
        return "structural check only — a pixel-perfect clone on a clean or "
               "newly-compromised domain still phishes; confirm the brand "
               "independently before entering credentials or payment.";
    if (strcmp(kind, "text") == 0)
        return "keyword/structure based — a novel or carefully-worded scam "
               "with no known phrasing can read clean; trust your judgment on "
               "unexpected requests for money or credentials.";
    if (strcmp(kind, "email") == 0)
        return "header forensics only — authentication PASS (SPF/DKIM/DMARC) is "
               "not a safety guarantee: a brand name in the display field, an "
               "attacker-owned look-alike/cousin domain, or a breached but "
               "legitimate account all pass authentication by design. Read the "
               "actual From-address domain character-by-character and verify "
               "unexpected requests out-of-band.";
    if (strcmp(kind, "clipboard") == 0)
        return "swap check only — this compares the two addresses you provided; "
               "it cannot confirm the address belongs to the intended recipient. "
               "Crypto transfers are irreversible: verify the full address "
               "against the recipient's own published source before sending.";
    if (strcmp(kind, "paste") == 0)
        return "injection-pattern check only — this flags hidden or obfuscated "
               "command injection, not whether a command is safe to run. Never "
               "run a command you did not seek out or do not understand, even "
               "when it looks clean.";
    if (strcmp(kind, "url_canonical") == 0)
        return "positive authentication covers the domain name — it cannot "
               "verify the page's content, a same-site redirect, or that the "
               "service actually sent you here; close unexpected pop-ups and "
               "confirm the specific page's request is what you expect from "
               "this service before entering credentials or authorising payment.";
    if (strcmp(kind, "secret") == 0)
        return "pattern-based detection — novel credential formats, encoded "
               "secrets, or credentials split across lines that don't match "
               "known patterns will be missed; manually review high-entropy "
               "strings and any line containing 'password', 'key', or 'token'.";
    if (strcmp(kind, "network") == 0)
        return "local-view only — DNS-over-HTTPS, process-level routing, "
               "encrypted tunnels, and outbound traffic over allowed ports are "
               "invisible to this check; a compromised process may appear clean.";
    if (strcmp(kind, "package") == 0)
        return "typosquat detection only — a compromised legitimate package, "
               "a dependency confusion attack, or malicious post-install scripts "
               "inside a correctly-named package are not detected; review the "
               "package's repository, recent commits, and published checksums "
               "before installing in a production or privileged environment.";
    if (strcmp(kind, "file") == 0)
        return "magic-byte and filename analysis only — obfuscated payloads, "
               "encrypted content, or malicious macros inside office formats "
               "are not detected; run untrusted files through a multi-engine "
               "scanner before opening.";
    if (strcmp(kind, "audit") == 0)
        return "point-in-time configuration snapshot — kernel-level exploits, "
               "container escapes, LD_PRELOAD injection, and custom LSM bypasses "
               "are outside the scope of this check; re-run after any system or "
               "configuration change.";
    if (strcmp(kind, "protect") == 0)
        return "indicator-based scan only — memory-only ransomware, staged "
               "pre-encryption activity, encrypted C2 traffic, and ransomware "
               "that operates before writing ransom notes will not be detected; "
               "an OK here does not rule out active compromise.";
    if (strcmp(kind, "esp") == 0)
        return "string-pattern scan of the EFI System Partition only — a "
               "bootkit that uses fileless persistence, firmware-level implants, "
               "or Secure-Boot bypass techniques not matching known patterns will "
               "not be detected; an OK here does not guarantee bootloader "
               "integrity.";
    if (strcmp(kind, "scan") == 0)
        return "pattern-based secret detection only — obfuscated credentials, "
               "secrets in binary or compiled artefacts, environment variables "
               "passed at runtime, and vault-managed secrets retrieved at startup "
               "are invisible to this scan; treat as complementary to a secrets "
               "manager, not a replacement.";
    return NULL;
}

/* Exoneration: the benign explanation that would clear a HEURISTIC threat.
 * Mirror of hlse_blindspot_for — that hedges a clean OK, this hedges a
 * low-confidence threat. Scoped to the LOG/ALERT band (15..59) where false
 * positives live; at BLOCK/ISOLATE (>=60) the signals (homoglyph, @-trick,
 * clipboard swap) are high-confidence and a benign read would mislead. Gives
 * the user the *falsifying test* so they neither panic nor blindly comply. */
const char *
hlse_exoneration_for(const char *kind, int score) {
    if (!kind || score < 15 || score >= 60) return NULL;
    if (strcmp(kind, "url") == 0)
        return "heuristic — legitimate small businesses and security vendors "
               "also use hyphens and words like 'secure'/'login'. Decisive "
               "test: were you expecting this link, and does the registrable "
               "domain (just before the first single '/') belong to the real "
               "brand?";
    if (strcmp(kind, "text") == 0)
        return "heuristic — urgent or financial wording appears in genuine "
               "messages too. Decisive test: were you expecting this, and does "
               "it push you to act through an unusual channel or in a hurry?";
    if (strcmp(kind, "email") == 0)
        return "heuristic — forwarders, mailing lists, and some legitimate "
               "senders trip these checks. Decisive test: confirm the request "
               "with the sender through a separately-known channel.";
    if (strcmp(kind, "protect") == 0)
        return "heuristic \xe2\x80\x94 legitimate software (compression tools, "
               "encrypted containers, software installers) can produce "
               "high-entropy content and file patterns that resemble ransomware. "
               "Decisive test: verify the file has a publisher signature whose "
               "hash matches the vendor's published release notes.";
    if (strcmp(kind, "esp") == 0)
        return "heuristic \xe2\x80\x94 hardware-vendor firmware updates and "
               "OS-managed bootloaders also modify the EFI System Partition. "
               "Decisive test: cross-check the modified file against your last "
               "known-good ESP snapshot and the vendor's firmware changelog "
               "before taking any disruptive action.";
    if (strcmp(kind, "package") == 0)
        return "heuristic \xe2\x80\x94 a name this close to a popular library can be "
               "a legitimate fork, organisation-scoped package, or namespace "
               "variant. Decisive test: search the official registry for the "
               "exact name, verify the maintainer's username matches the "
               "original project, and check the publish date and download count.";
    if (strcmp(kind, "network") == 0)
        return "heuristic \xe2\x80\x94 update servers, telemetry daemons, and "
               "monitoring agents routinely make external connections on unusual "
               "ports. Decisive test: identify the owning process "
               "('lsof -i' or 'ss -tp') and verify it against the software's "
               "documented network requirements.";
    if (strcmp(kind, "paste") == 0)
        return "heuristic \xe2\x80\x94 legitimate install scripts and CI snippets "
               "also use curl, sudo, and base64. Decisive test: paste into a "
               "plain text editor first and read every line \xe2\x80\x94 a hidden "
               "newline or trailing command that only appears there is the "
               "decisive sign of a paste-and-run trap.";
    if (strcmp(kind, "file") == 0)
        return "heuristic \xe2\x80\x94 some legitimate tools intentionally bundle "
               "content in unconventional containers (self-extracting installers, "
               "polyglot test fixtures, archive-based package formats). Decisive "
               "test: check the file's actual origin (was it downloaded from an "
               "official site, or did it arrive unsolicited?) and scan it with a "
               "multi-engine tool (e.g. VirusTotal) before opening.";
    if (strcmp(kind, "secret") == 0)
        return "heuristic \xe2\x80\x94 test-mode keys (sk_test_/pk_test_), "
               "placeholder examples in documentation, and low-entropy sample "
               "values can match a credential pattern without being a real, "
               "live secret. Decisive test: does the value work against the "
               "provider's live API right now, and does it appear in version "
               "control history rather than a docs/example file?";
    return NULL;
}

const char *
hlse_version(void) {
    return HLSE_VERSION;
}

/* Pattern-aware exoneration: the benign explanation and falsifying test keyed
 * to the specific attack pattern that fired, not a generic URL heuristic.
 *
 * Socratic question (Perspective 24): "hlse_exoneration_for('url', score)
 * returns 'heuristic — legitimate small businesses also use hyphens and words
 * like secure/login' for EVERY LOG/ALERT URL — including URL shorteners
 * (bit.ly), DGA-style domains, free-hosting pages, and typosquats. A shortener
 * LOG user reads 'hyphens and login words' and is completely confused — their
 * URL has no hyphens. The falsifying test ('does the registrable domain belong
 * to the brand?') is unanswerable for a shortener because the registrable
 * domain IS the shortener (bit.ly). The exoneration isn't just generic; for
 * shorteners it's actively wrong. Shouldn't the benign explanation match the
 * actual signal?"
 *
 * Returns a static string matched to the pattern in the verdict, or falls
 * back to the generic hlse_exoneration_for("url", score) when no specific
 * pattern is recognisable. Returns NULL when score is outside [15, 59].
 * Thread-safe: no allocation.                                               */
const char *
hlse_url_exoneration(const Verdict *v) {
    const char *pat;
    if (!v || v->score < 15 || v->score >= 60) return NULL;
    pat = hlse_classify_url_attack(v);
    if (!pat) return hlse_exoneration_for("url", v->score);

    if (strstr(pat, "obfuscated") || strstr(pat, "shortener"))
        return "URL shorteners are standard tools for social-media links, print "
               "materials, and marketing campaigns. Decisive test: expand the link "
               "first (append '+' for bit.ly/tinyurl previews) to see the real "
               "destination before you open it";
    if (strstr(pat, "free-hosting"))
        return "developers and small teams legitimately host projects on GitHub "
               "Pages, Netlify, and similar platforms. Decisive test: search the "
               "exact domain — if it's a real project the owner is easy to find; "
               "if it's impersonating a brand, ownership will be anonymous";
    if (strstr(pat, "subdomain spoofing"))
        return "legitimate small businesses and security vendors also use hyphens "
               "and words like 'secure'/'verify' in subdomains. Decisive test: "
               "read the domain right-to-left — the registrable part just before "
               "the first '/' must belong to the real brand, not appear before it";
    if (strstr(pat, "typosquat") || strstr(pat, "lookalike"))
        return "human typing errors that coincidentally resemble brand names are "
               "common. Decisive test: was this URL typed manually or sent by "
               "someone? If sent, did the sender independently confirm it through "
               "a channel you trust?";
    if (strstr(pat, "DGA") || strstr(pat, "high-entropy"))
        return "newly-registered or randomly-named domains are also used by "
               "legitimate services, CDNs, and internal tools. Decisive test: "
               "search the domain in a search engine — a legitimate service will "
               "have a traceable history; a phishing domain will not";
    if (strstr(pat, "high-risk TLD"))
        return "high-risk TLDs (.xyz, .tk, .top) are also used by legitimate "
               "start-ups and projects. Decisive test: find the brand via a "
               "bookmark or search engine and confirm you reach the same domain";
    if (strstr(pat, "credential trick") || strstr(pat, "@-trick"))
        return "the '@' in a URL is a standard HTTP Basic Auth separator; some "
               "internal tools use it legitimately. Decisive test: paste the URL "
               "into a URL decoder — what comes after '@' is where you actually land";
    /* Fallback for any unrecognised pattern */
    return hlse_exoneration_for("url", v->score);
}

/* Pattern-aware exoneration for a text verdict — the benign explanation and
 * falsifying test keyed to the specific social-engineering pattern, not the
 * generic "urgent wording appears in genuine messages" catch-all.
 *
 * Socratic question (Perspective 30): "hlse_exoneration_for('text', score)
 * returns 'heuristic — urgent or financial wording appears in genuine messages
 * too' for every LOG/ALERT text verdict — including QR-code phishing (which
 * has nothing to do with urgent wording), callback scams (which target phone
 * numbers, not urgency language), and investment lures (which look like
 * financial advice). The falsifying test ('were you expecting this, does it
 * push you to act in a hurry?') is unanswerable for a QR code — QR codes are
 * legitimately used everywhere. Shouldn't the benign explanation and decisive
 * test match the actual signal pattern, exactly as hlse_url_exoneration does
 * for URLs?"
 *
 * Returns a static string matched to the pattern in the verdict, or falls
 * back to hlse_exoneration_for("text", score) when no specific pattern is
 * recognisable. Returns NULL when score is outside [15, 59]. Thread-safe;
 * no allocation.                                                              */
const char *
hlse_text_exoneration(const TextVerdict *v) {
    const char *pat;
    if (!v || v->score < 15 || v->score >= 60) return NULL;
    pat = hlse_classify_text_attack(v);
    if (!pat) return hlse_exoneration_for("text", v->score);

    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
        return "Microsoft and other services do send genuine verification codes "
               "you requested yourself. Decisive test: did YOU initiate a sign-in "
               "or device-pairing flow in the last 60 seconds? If not, the code "
               "is the attacker's session and entering it grants them your tokens";
    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
        return "legitimate recruiters do reach out with real openings. Decisive "
               "test: does the 'job' require you to pay anything, deposit your "
               "own funds, or buy equipment to start? A real job pays you "
               "\xe2\x80\x94 money only ever flows TO you, never from you";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
        return "legitimate sign-ins do trigger MFA prompts. Decisive test: did "
               "YOU just try to log in? If an 'approve' request or push arrives "
               "that you did not start, deny it \xe2\x80\x94 it means someone else "
               "already has your password";
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
        return "these threats feel personal but are almost always mass-mailed "
               "bluffs. Decisive test: can they show actual footage, or only "
               "claim it? A breached password quoted from a data leak is not "
               "proof of webcam access \xe2\x80\x94 do not pay, do not reply";
    if (strstr(pat, "payment-diversion"))
        return "employees and vendors do legitimately change banks. Decisive "
               "test: call the person or company on a number you ALREADY have on "
               "file (never the contact in this message) and confirm the change "
               "before updating any payee or direct-deposit record";
    if (strstr(pat, "QR") || strstr(pat, "quishing"))
        return "QR codes appear legitimately in event tickets, restaurant menus, "
               "and physical adverts. Decisive test: scan with a QR decoder that "
               "shows the URL before opening it, then verify the domain belongs "
               "to the expected organisation; on a physical QR, check it is not a "
               "sticker placed over the original";
    if (strstr(pat, "grandparent") || strstr(pat, "emergency impersonation"))
        return "family members do have genuine emergencies. Decisive test: a "
               "familiar voice is no longer proof \xe2\x80\x94 AI clones a voice "
               "from a few seconds of audio; hang up and call them back on their "
               "own known number, and ask a pre-agreed safe word that an AI "
               "clone cannot know";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
        return "real subscriptions do auto-renew and send receipts. Decisive "
               "test: open your bank/card statement or the provider's official "
               "app directly (never the number or link here) and check whether "
               "the charge is real \xe2\x80\x94 a 'call to cancel' invoice for a "
               "service you don't use is the tell";
    if (strstr(pat, "callback") || strstr(pat, "TOAD") || strstr(pat, "vishing"))
        return "organisations do send callback numbers for account verification. "
               "Decisive test: find the number independently on the organisation's "
               "official website and call that — not the number provided here";
    if (strstr(pat, "ClickFix") || strstr(pat, "script-injection"))
        return "developers and sysadmins do share commands in messages. Decisive "
               "test: legitimate software updates and fixes are delivered through "
               "official package managers or websites — a message that asks you to "
               "paste or run a command you were not expecting is the defining sign "
               "of a script-injection lure";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
        return "investment outreach from regulated firms is legitimate. Decisive "
               "test: verify the firm's authorisation on the FCA/SEC/ASIC register "
               "before sending any funds or personal information";
    if (strstr(pat, "lottery") || strstr(pat, "advance-fee"))
        return "prize notifications appear in genuine marketing campaigns. Decisive "
               "test: search the organisation's official website — genuine prizes "
               "do not require winners to pay upfront fees";
    if (strstr(pat, "prize"))
        return "prize and reward messages appear in legitimate loyalty programmes. "
               "Decisive test: log in to your account at the organisation's official "
               "domain (not via any link here) and check whether the reward appears";
    if (strstr(pat, "urgency credential") || strstr(pat, "credential / payment"))
        return "account security alerts are sent legitimately by services you use. "
               "Decisive test: navigate to the site directly (not via any link in "
               "this message) and check whether the alert appears in your account "
               "dashboard";
    if (strstr(pat, "authority impersonation"))
        return "authority figures send urgent communications legitimately. Decisive "
               "test: verify by calling the supposed sender on a number you already "
               "have — not any contact provided in this message";
    if (strstr(pat, "urgency"))
        return "time-sensitive messages are common in legitimate business. Decisive "
               "test: verify the request through a separately-known channel — "
               "urgency combined with a request to act through an unusual channel "
               "is the strongest warning sign";
    if (strstr(pat, "BEC") || strstr(pat, "CEO") ||
        strstr(pat, "wire-transfer") || strstr(pat, "wire transfer"))
        return "internal payment requests do arrive by email. Decisive test: call "
               "the supposed sender on a number you already have — wire-transfer "
               "requests without a prior phone call are a strong warning sign";
    if (strstr(pat, "tech-support"))
        return "tech-support teams do send proactive alerts about account issues. "
               "Decisive test: call the company's main switchboard (on their "
               "official website), not any number provided in this message";
    if (strstr(pat, "fake security alert") || strstr(pat, "account suspension"))
        return "account suspension and security notices are sent legitimately by "
               "service providers. Decisive test: log in to the service directly "
               "(via bookmark or search engine, not any link here) and check "
               "whether your account actually shows a problem";
    /* Fallback for any unrecognised text pattern */
    return hlse_exoneration_for("text", v->score);
}

/* Synthesize a named attack pattern from the set of signals that fired.
 *
 * Socratic question (Perspective 17): "Single-brand detection assumes one
 * attacker wearing one mask. But what if the URL simultaneously contains two
 * known brand names — 'paypal.apple-secure.com', 'netflix-amazon-billing.net'?
 * Presenting as two brands at once exploits both user bases and is harder to
 * dismiss, because each fragment looks 'almost right' in isolation. Shouldn't
 * a fundamentally different attack label surface this compound deception?"
 *
 * Returns a short human-readable attack-class label (e.g. "typosquat
 * credential-harvest page"), or NULL when the signals don't map to a
 * recognisable pattern. The label is intentionally terse — it belongs on
 * a single summary line, not a paragraph.
 *
 * Precondition: called only when score > 0 (no signals → no pattern).   */
const char *
hlse_classify_url_attack(const Verdict *v) {
    /* Scan reason strings for the signal classes we care about. */
    int has_homoglyph     = 0;  /* confusable-char, II→ll, rn/vv, Cyrillic */
    int has_idn           = 0;  /* Punycode / IDN homograph                */
    int has_typosquat     = 0;  /* edit-distance 1 or 2 from a brand       */
    int has_brand         = 0;  /* any brand-impersonation reason           */
    int has_path          = 0;  /* phishing-typical path pattern            */
    int has_tld           = 0;  /* high-risk TLD                            */
    int has_subdomain     = 0;  /* subdomain spoofing                       */
    int has_free_host     = 0;  /* brand in netlify/github.io/etc.          */
    int has_shortener     = 0;  /* URL shortener                            */
    int has_at_trick      = 0;  /* @ in authority                           */
    int has_ip            = 0;  /* IP-address host with brand in path       */
    int has_hyphen_brand  = 0;  /* brand-hyphen-securityword pattern        */
    int has_dga           = 0;  /* DGA / high-entropy random domain         */
    int n_brands          = 0;  /* count of distinct impersonated brands    */
    int i;

    if (!v || v->n_reasons == 0) return NULL;

    for (i = 0; i < v->n_reasons; i++) {
        const char *r = v->reasons[i];
        if (strstr(r, "homoglyph") || strstr(r, "Homoglyph") ||
            strstr(r, "Mixed-script"))               has_homoglyph = 1;
        if (strstr(r, "IDN") || strstr(r, "Punycode")) has_idn     = 1;
        if (strstr(r, "Typosquat") || strstr(r, "typosquat") ||
            strstr(r, "Digraph homoglyph"))           has_typosquat = 1;
        if (strstr(r, "Brand") || strstr(r, "brand") ||
            strstr(r, "Legitimate '"))                 has_brand   = 1;
        if (strstr(r, "path pattern") || strstr(r, "Phishing path"))
                                                       has_path     = 1;
        if (strstr(r, "TLD"))                          has_tld      = 1;
        if (strstr(r, "Subdomain spoofing") ||
            strstr(r, "subdomain"))                  { has_subdomain= 1; has_brand = 1; }
        if (strstr(r, "Free-hosting") ||
            strstr(r, "free page builder"))          { has_free_host= 1; has_brand = 1; }
        if (strstr(r, "shortener") || strstr(r, "Shortened"))
                                                       has_shortener= 1;
        if (strstr(r, "credential trick") ||
            strstr(r, "@ in authority"))               has_at_trick = 1;
        if (strstr(r, "IP-based URL") || strstr(r, "IP-address host"))
                                                       has_ip       = 1;
        if (strstr(r, "hyphenated with security") ||
            strstr(r, "Brand impersonation"))          has_hyphen_brand = 1;
        if (strstr(r, "DGA") || strstr(r, "high-entropy") ||
            strstr(r, "random-looking"))               has_dga      = 1;
        if (strstr(r, "Legitimate '"))                 n_brands++;
    }

    /* Priority-ordered classification: most specific / highest-confidence
     * patterns first so the label describes the dominant attack vector.  */
    if (has_idn)
        return "Unicode/IDN homograph impersonation";
    /* Perspective 17: two or more distinct brand canonical reasons means the
     * attacker is simultaneously impersonating multiple brands — a compound
     * co-spoof that is more sophisticated than any single-brand pattern. */
    if (n_brands >= 2)
        return "multi-brand co-spoof (compound impersonation)";
    if (has_homoglyph && has_brand)
        return "visual impersonation via lookalike characters";
    if (has_at_trick)
        return "authority-trick credential phishing";
    if (has_ip && has_brand)
        return "IP-hosted brand impersonation";
    if (has_free_host)
        return "free-hosting phishing infrastructure";
    if (has_subdomain && has_brand && has_path)
        return "subdomain-spoof credential-harvest page";
    if (has_subdomain && has_brand)
        return "subdomain spoofing";
    if (has_typosquat && has_path)
        return "typosquat credential-harvest page";
    if (has_typosquat)
        return "typosquat domain";
    if (has_hyphen_brand && has_path)
        return "brand-hyphen credential-harvest page";
    if (has_hyphen_brand)
        return "brand hyphenation phishing";
    if (has_brand && has_path && has_tld)
        return "classic credential-harvest phishing";
    if (has_brand && has_tld)
        return "brand phishing on high-risk TLD";
    if (has_brand)
        return "brand impersonation";
    if (has_shortener)
        return "obfuscated link (shortener conceals destination)";
    if (has_dga)
        return "DGA / random-domain phishing";
    return NULL;
}

/* Stable machine-readable pattern identifier for a URL Verdict — the URL
 * counterpart of hlse_text_pattern_id (Perspective 78). The prose label from
 * hlse_classify_url_attack may be reworded across versions; these HLSE-URL-*
 * tokens are APPEND-ONLY so SIEM/SOAR rules can route on a stable id instead
 * of substring-matching prose. Returns NULL when score is 0 or no pattern was
 * recognised. Order mirrors the classifier's priority so the most specific
 * id wins. Thread-safe; no allocation. */
const char *
hlse_url_pattern_id(const Verdict *v) {
    const char *pat = hlse_classify_url_attack(v);
    if (!pat) return NULL;
    if (strstr(pat, "IDN homograph"))            return "HLSE-URL-IDN-HOMOGRAPH";
    if (strstr(pat, "multi-brand co-spoof"))     return "HLSE-URL-MULTI-BRAND";
    if (strstr(pat, "lookalike characters"))     return "HLSE-URL-HOMOGLYPH";
    if (strstr(pat, "authority-trick"))          return "HLSE-URL-AT-CRED-TRICK";
    if (strstr(pat, "IP-hosted"))                return "HLSE-URL-IP-BRAND";
    if (strstr(pat, "free-hosting"))             return "HLSE-URL-FREEHOST";
    if (strstr(pat, "subdomain-spoof credential-harvest"))
                                                 return "HLSE-URL-SUBDOMAIN-HARVEST";
    if (strstr(pat, "subdomain spoofing"))       return "HLSE-URL-SUBDOMAIN";
    if (strstr(pat, "typosquat credential-harvest"))
                                                 return "HLSE-URL-TYPOSQUAT-HARVEST";
    if (strstr(pat, "typosquat domain"))         return "HLSE-URL-TYPOSQUAT";
    if (strstr(pat, "brand-hyphen credential-harvest"))
                                                 return "HLSE-URL-HYPHEN-HARVEST";
    if (strstr(pat, "brand hyphenation"))        return "HLSE-URL-HYPHEN-BRAND";
    if (strstr(pat, "classic credential-harvest"))
                                                 return "HLSE-URL-CRED-HARVEST";
    if (strstr(pat, "high-risk TLD"))            return "HLSE-URL-BRAND-RISKY-TLD";
    if (strstr(pat, "brand impersonation"))      return "HLSE-URL-BRAND";
    if (strstr(pat, "shortener"))                return "HLSE-URL-SHORTENER";
    if (strstr(pat, "DGA"))                       return "HLSE-URL-DGA";
    return "HLSE-URL-GENERIC";
}

/* Synthesise a named social-engineering attack pattern from the signals in a
 * text verdict — the text counterpart of hlse_classify_url_attack.
 *
 * Socratic question (Perspective 25): "hlse_classify_url_attack gives URL
 * verdicts a ▸ Pattern: label ('typosquat credential-harvest', 'authority-trick
 * credential phishing', etc.). Text verdicts above score 0 show only raw reason
 * strings and a generic exoneration. A BEC wire-transfer fraud and a grandparent
 * emergency scam both say 'Urgency pressure (N hits)' — but they need entirely
 * different responses: one requires immediate CFO verification, the other
 * requires calling the family member directly. Shouldn't text verdicts also name
 * the attack pattern so the response is directed to the right playbook?"
 *
 * Scans the reasons[] for amplifier labels and individual signal names to
 * identify the dominant tactic. Priority order mirrors threat severity.
 * Returns a short label or NULL when no signals fired. Thread-safe; no alloc. */
const char *
hlse_classify_text_attack(const TextVerdict *v) {
    int i;
    int urgency = 0, bait = 0, prize = 0, ransom = 0, authority = 0;
    int secrecy = 0, investment = 0, qr = 0, callback = 0;
    int emergency = 0, clickfix = 0;
    int fake_alert = 0, direct_fin = 0;
    int amp_bec = 0, amp_tss = 0, amp_ceo = 0, amp_laf = 0;
    int devicecode = 0, bankchange = 0, mfapush = 0, jobscam = 0, sextortion = 0;
    int refundscam = 0;

    if (!v || v->n_reasons == 0) return NULL;

    for (i = 0; i < v->n_reasons; i++) {
        const char *r = v->reasons[i];
        if (strstr(r, "Urgency pressure"))           urgency    = 1;
        if (strstr(r, "Financial/credential"))        bait       = 1;
        if (strstr(r, "Prize/reward"))                prize      = 1;
        if (strstr(r, "Ransom") || strstr(r, "ransom")) ransom   = 1;
        if (strstr(r, "Authority impersonation"))     authority  = 1;
        if (strstr(r, "Secrecy/grooming"))            secrecy    = 1;
        if (strstr(r, "Investment scam"))             investment = 1;
        if (strstr(r, "QR code phishing"))            qr         = 1;
        if (strstr(r, "Callback") || strstr(r, "TOAD") ||
            strstr(r, "smishing"))                    callback   = 1;
        if (strstr(r, "Emergency") || strstr(r, "grandparent")) emergency = 1;
        if (strstr(r, "ClickFix") || strstr(r, "Shell-pipe")) clickfix  = 1;
        if (strstr(r, "Fake security alert"))         fake_alert = 1;
        if (strstr(r, "Direct financial action"))     direct_fin = 1;
        /* Amplifier pattern labels */
        if (strstr(r, "BEC") || strstr(r, "wire transfer"))  amp_bec = 1;
        if (strstr(r, "tech-support") || strstr(r, "gift card")) amp_tss = 1;
        if (strstr(r, "CEO-fraud"))                           amp_ceo = 1;
        if (strstr(r, "lottery") || strstr(r, "advance-fee")) amp_laf = 1;
        /* OAuth device-code phishing (P64): the 2026 attack class where the
         * victim is sent to a LEGITIMATE Microsoft URL (microsoft.com/
         * devicelogin) and asked to enter an attacker-supplied code. The raw
         * reason text includes the literal phrase that fired, so we can match
         * "verification code" / "device code" / "two-factor code" surfacing
         * from the auth-bait list. Detection is unchanged; this only refines
         * the pattern label so the user knows the unique mechanism. */
        if (strstr(r, "verification code") ||
            strstr(r, "device code") ||
            strstr(r, "two-factor code") ||
            strstr(r, "one-time code") ||
            strstr(r, "otp code"))                    devicecode = 1;
        /* Payment/payroll-diversion BEC (P73): the attacker impersonates an
         * employee (to HR/payroll) or a vendor (to AP/finance) and requests a
         * BANK-ACCOUNT / direct-deposit CHANGE, diverting future payments to
         * their account. This is the fastest-growing BEC variant (FBI), but it
         * is NOT a wire-transfer and NOT credential harvest — so it needs its
         * own label and advisory. The banking-change phrases surface in the
         * matched-phrase "e.g. '...'" of the reason text, same as gift-card. */
        if (strstr(r, "bank account has changed") ||
            strstr(r, "banking details") ||
            strstr(r, "payment details have changed") ||
            strstr(r, "update our bank") ||
            strstr(r, "update our payment") ||
            strstr(r, "direct deposit") ||
            strstr(r, "new bank account") ||
            strstr(r, "new payment account"))         bankchange = 1;
        /* MFA-fatigue / push-bombing (P74): the attacker already has the
         * password and spams authenticator push prompts (or phones the victim)
         * asking them to "just approve" one. The defining tell is an
         * unsolicited request to approve an auth push. Distinct remedy: deny
         * the prompt and rotate the already-compromised password. Phrases
         * surface in the matched-phrase text of the reasons. */
        if (strstr(r, "approve the notification") ||
            strstr(r, "approve the push") ||
            strstr(r, "approve the sign-in") ||
            strstr(r, "approve the login") ||
            strstr(r, "approve the authentication") ||
            strstr(r, "approve the mfa") ||
            strstr(r, "approve the two-factor") ||
            strstr(r, "approve on your phone") ||
            strstr(r, "just approve") ||
            strstr(r, "approve in") ||
            strstr(r, "approve on your authenticator") ||
            strstr(r, "until you approve"))            mfapush = 1;
        /* Fake-job / task scam (P75): 2026's fastest-growing consumer fraud
         * (FTC: $521M, +1000% spike). The defining tell is a "job" that
         * requires the victim to PAY to start — buy equipment, deposit funds
         * to "unlock" tasks, or install a "work-from-home app" (often a RAT).
         * Distinct remedy: a real job only ever pays money TO you. Phrases
         * surface in the matched-phrase text of the reasons. */
        if (strstr(r, "work from home opportunity") ||
            strstr(r, "no experience required") ||
            strstr(r, "starter kit") ||
            strstr(r, "buy your equipment") ||
            strstr(r, "purchase the equipment") ||
            strstr(r, "equipment will be reimbursed") ||
            strstr(r, "reimbursed on first paycheck") ||
            strstr(r, "mystery shopper") ||
            strstr(r, "brand ambassador") ||
            strstr(r, "money transfer agent") ||
            strstr(r, "reshipping agent") ||
            strstr(r, "shipping agent position") ||
            strstr(r, "per day from home") ||
            strstr(r, "per week from home") ||
            strstr(r, "weekly income from home"))      jobscam = 1;
        /* Sextortion / webcam-extortion (P76): the attacker claims to hold
         * intimate footage (real, bluffed, or AI-deepfaked) and threatens to
         * send it to the victim's contacts unless paid. Distinct from
         * ransomware extortion — there is nothing to "recover"; the threat is
         * usually an empty mass-mailed bluff. Distinct remedy: do not pay, do
         * not reply, preserve and report. Phrases surface in the matched-phrase
         * text of the Ransom/extortion reason. */
        if (strstr(r, "footage of you") ||
            strstr(r, "video of you") ||
            strstr(r, "photos of you") ||
            strstr(r, "recorded you") ||
            strstr(r, "your webcam") ||
            strstr(r, "your camera") ||
            strstr(r, "camera was hacked") ||
            strstr(r, "adult content") ||
            strstr(r, "watching explicit") ||
            strstr(r, "compromising footage") ||
            strstr(r, "compromising material") ||
            strstr(r, "send this to your contacts") ||
            strstr(r, "send this video to your contacts"))  sextortion = 1;
        /* Refund / subscription-renewal scam (P77): a fake auto-renewal invoice
         * (Geek Squad, Norton, McAfee, PayPal) that exists to make the victim
         * CALL to "cancel and get a refund" — then the agent demands remote
         * access or tricks the victim into "returning an over-refund" via gift
         * cards/wire. Distinct from a plain callback scam by the refund pretext.
         * Phrases surface in the matched-phrase text of the reasons. */
        if (strstr(r, "auto-renew") ||
            strstr(r, "membership has renewed") ||
            strstr(r, "subscription has renewed") ||
            strstr(r, "subscription has been renewed") ||
            strstr(r, "annual membership") ||
            strstr(r, "receive a full refund") ||
            strstr(r, "cancel and refund") ||
            strstr(r, "cancel and receive a refund") ||
            strstr(r, "to cancel and receive") ||
            strstr(r, "did not authorize this") ||
            strstr(r, "did not authorize this charge") ||
            strstr(r, "to cancel this charge"))         refundscam = 1;
    }

    /* Fake security alerts and direct financial-action signals are credential/
     * financial bait by nature; fold them into the bait category so they
     * participate in BEC, urgency-credential, and related pattern rules. */
    if (fake_alert || direct_fin) bait = 1;

    /* Specific amplifier patterns take priority over individual signals */
    if (clickfix)
        return "ClickFix script-injection lure (paste-and-run attack)";
    /* Device-code phishing: when auth-code language fires with authority
     * impersonation OR fake security alert, the attack class is OAuth
     * device-code abuse (M365/Azure 2026 #1 vector) rather than a generic
     * fake-alert. The unique mechanism — legitimate URL, attacker-supplied
     * code — needs its own label so the advisory can warn about it. */
    if (devicecode && (authority || fake_alert))
        return "OAuth device-code phishing "
               "(legitimate URL, attacker-supplied verification code)";
    /* MFA-fatigue / push-bombing: an unsolicited 'approve the prompt' request
     * is a distinct attack — the attacker already holds the password — with a
     * distinct remedy (deny and rotate the password), not a credential
     * re-harvest. Priority above the generic fake-alert/credential labels. */
    if (mfapush)
        return "MFA-fatigue / push-bombing (approve-the-prompt attack)";
    /* Payment/payroll-diversion BEC takes priority over the generic
     * wire-transfer and credential-harvest labels: a bank-account-change
     * request is a distinct attack with a distinct remedy (verify the change
     * out-of-band, do not update the payee), not a password reset. */
    if (bankchange)
        return "payment-diversion BEC (bank-account-change / payroll fraud)";
    if (amp_ceo || (authority && secrecy && bait))
        return "BEC / CEO-fraud wire-transfer";
    if (amp_bec || (urgency && bait && authority))
        return "business email compromise (BEC) wire-transfer fraud";
    if (amp_tss || (urgency && bait && strstr(v->reasons[0], "gift")))
        return "tech-support gift-card scam";
    /* Fake-job / task scam takes priority over the generic lottery/advance-fee
     * and investment/pig-butchering labels: a "job" that asks you to pay,
     * deposit, or buy equipment to start is a distinct fraud with a distinct
     * tell — a real job only ever pays money TO you. */
    if (jobscam)
        return "fake-job / task scam (pay-to-start employment fraud)";
    if (amp_laf || (prize && bait))
        return "lottery / advance-fee fraud";
    /* Sextortion takes priority over the generic ransom/extortion label: the
     * threat is to release intimate footage (often a bluff or AI deepfake),
     * not to withhold encrypted files — a distinct attack with a distinct
     * remedy (do not pay, do not reply, preserve and report). */
    if (sextortion)
        return "sextortion / webcam blackmail";
    if (ransom)
        return "ransom / extortion message";
    if (investment)
        return "investment scam / pig-butchering";
    if (emergency)
        return "emergency impersonation scam (grandparent / fake-kidnapping)";
    if (qr)
        return "QR-code phishing (quishing)";
    /* Refund / subscription-renewal scam takes priority over the generic
     * callback/TOAD label: the fake auto-renewal invoice and the "call to get
     * a refund" hook have a distinct remedy (a real refund needs nothing from
     * you; never grant remote access or return an "over-refund"). */
    if (refundscam)
        return "refund / subscription-renewal scam (fake auto-renewal invoice)";
    if (callback)
        return "callback phone scam (TOAD / vishing)";
    if (authority && urgency)
        return "authority impersonation phishing";
    if (urgency && bait)
        return "urgency credential-harvest phishing";
    /* Fake security alert without urgency amplifier — account suspension hook */
    if (fake_alert)
        return "fake security alert / account suspension phishing";
    if (urgency)
        return "urgency social engineering";
    if (bait)
        return "credential / payment lure";
    if (prize)
        return "prize lure / fraud bait";
    return NULL;
}

/* Stable machine-readable identifier for a text attack pattern.
 *
 * Socratic question (Perspective 78): "Every text verdict now carries a human
 * `pattern` label, but that label is prose we keep refining — when P57 changed
 * 'Verify first' to 'Verify independently' a downstream test broke. A SIEM or
 * SOAR rule that wants to route 'OAuth device-code phishing' alerts has no
 * choice but to substring-match the prose, so every wording polish risks
 * silently breaking automation. Shouldn't each pattern also expose a STABLE id
 * (e.g. HLSE-OAUTH-DEVICECODE) that survives wording changes, so machines key
 * on the id and humans read the label?"
 *
 * Maps the label from hlse_classify_text_attack() to a stable token. The ids
 * are an append-only contract: an id, once shipped, never changes meaning even
 * if the human label is reworded. Returns NULL when no pattern fired (so JSON
 * consumers can treat absence as 'no recognised pattern'). Thread-safe; no
 * allocation. */
const char *
hlse_text_pattern_id(const TextVerdict *v) {
    const char *pat = hlse_classify_text_attack(v);
    if (!pat) return NULL;
    /* Order mirrors the classifier's priority so the most specific id wins. */
    if (strstr(pat, "ClickFix"))              return "HLSE-CLICKFIX";
    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
                                              return "HLSE-OAUTH-DEVICECODE";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
                                              return "HLSE-MFA-FATIGUE";
    if (strstr(pat, "payment-diversion"))     return "HLSE-BEC-PAYMENT-DIVERSION";
    if (strstr(pat, "CEO-fraud"))             return "HLSE-BEC-CEO";
    if (strstr(pat, "business email compromise") ||
        strstr(pat, "BEC"))                   return "HLSE-BEC-WIRE";
    if (strstr(pat, "tech-support"))          return "HLSE-TECH-SUPPORT";
    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
                                              return "HLSE-JOB-SCAM";
    if (strstr(pat, "lottery") || strstr(pat, "advance-fee"))
                                              return "HLSE-ADVANCE-FEE";
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
                                              return "HLSE-SEXTORTION";
    if (strstr(pat, "ransom") || strstr(pat, "extortion"))
                                              return "HLSE-RANSOM";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
                                              return "HLSE-INVESTMENT";
    if (strstr(pat, "emergency"))             return "HLSE-EMERGENCY";
    if (strstr(pat, "quishing") || strstr(pat, "QR"))
                                              return "HLSE-QUISHING";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
                                              return "HLSE-REFUND-SCAM";
    if (strstr(pat, "callback") || strstr(pat, "TOAD") || strstr(pat, "vishing"))
                                              return "HLSE-CALLBACK-TOAD";
    if (strstr(pat, "authority impersonation"))
                                              return "HLSE-AUTHORITY";
    if (strstr(pat, "urgency credential"))    return "HLSE-URGENCY-CRED";
    if (strstr(pat, "fake security alert") || strstr(pat, "account suspension"))
                                              return "HLSE-FAKE-ALERT";
    if (strstr(pat, "urgency"))               return "HLSE-URGENCY";
    if (strstr(pat, "credential / payment"))  return "HLSE-CRED-LURE";
    if (strstr(pat, "prize"))                 return "HLSE-PRIZE";
    return "HLSE-GENERIC";
}

/*
 * Socratic question (Perspective 21): "Your score says HOW threatening, but two
 * verdicts both scoring 60 can be epistemically worlds apart: one from a single
 * homoglyph detector barely crossing threshold, another from homoglyph + path +
 * TLD + structure all agreeing. The first might be a fragile-heuristic false
 * positive; the second is corroborated by four independent detectors. A SOC
 * analyst triaging a borderline score has no way to tell which they're looking
 * at. Shouldn't the output disclose how many independent signals concur, so a
 * reviewer knows whether to trust a thin score or act on a corroborated one?"
 *
 * Counts DISTINCT detector families — not raw reasons — so that two reasons from
 * the same family (e.g. "Brand homoglyph" + "Multiple confusable chars") count
 * once. The "Legitimate '<brand>'" canonical lines are evidence the engine
 * derived, not independent detections, so they are excluded. Writes a label
 * ("single signal — corroborate before acting", "corroborated by N independent
 * signals", etc.) into `out`; returns the family count (0 when no signal fired).
 * Thread-safe; caller owns the buffer. */
int
hlse_confidence_for(const Verdict *v, char *out, size_t outsz) {
    int fam_homoglyph = 0, fam_typosquat = 0, fam_idn = 0, fam_brand = 0;
    int fam_subdomain = 0, fam_freehost = 0, fam_path = 0, fam_tld = 0;
    int fam_shortener = 0, fam_attrick = 0, fam_ip = 0, fam_dga = 0;
    int fam_structure = 0, fam_depth = 0;
    int n_families;
    int i;

    /* 160-byte minimum: longest label ("high confidence — N independent
     * detector families agree; this is a deliberate, multi-faceted spoof")
     * is ~115 bytes incl. the multi-byte em dash. */
    if (!v || !out || outsz < 160) return 0;
    out[0] = '\0';
    if (v->n_reasons == 0) return 0;

    for (i = 0; i < v->n_reasons; i++) {
        const char *r = v->reasons[i];
        if (strstr(r, "homoglyph") || strstr(r, "Homoglyph") ||
            strstr(r, "Mixed-script") || strstr(r, "confusable") ||
            strstr(r, "Confusable"))                      fam_homoglyph = 1;
        if (strstr(r, "Typosquat") || strstr(r, "typosquat")) fam_typosquat = 1;
        if (strstr(r, "IDN") || strstr(r, "Punycode"))    fam_idn       = 1;
        if (strstr(r, "Brand impersonation") ||
            strstr(r, "Brand+") || strstr(r, "Brand present") ||
            strstr(r, "Brand homoglyph"))                 fam_brand     = 1;
        if (strstr(r, "Subdomain spoofing"))              fam_subdomain = 1;
        if (strstr(r, "Free-hosting") ||
            strstr(r, "free page builder"))               fam_freehost  = 1;
        if (strstr(r, "path pattern") || strstr(r, "Phishing path"))
                                                          fam_path      = 1;
        if (strstr(r, "TLD"))                             fam_tld       = 1;
        if (strstr(r, "shortener") || strstr(r, "Shortened"))
                                                          fam_shortener = 1;
        if (strstr(r, "credential trick") ||
            strstr(r, "@ in authority"))                  fam_attrick   = 1;
        if (strstr(r, "IP-based URL") || strstr(r, "IP-address host"))
                                                          fam_ip        = 1;
        if (strstr(r, "DGA") || strstr(r, "high-entropy") ||
            strstr(r, "random-looking"))                  fam_dga       = 1;
        if (strstr(r, "Phishing-typical domain structure")) fam_structure = 1;
        if (strstr(r, "Deep subdomain nesting"))          fam_depth     = 1;
    }

    /* Homoglyph and typosquat are the same underlying family (lookalike SLD);
     * collapse so we don't double-count a single visual-spoofing technique. */
    if (fam_homoglyph && fam_typosquat) fam_typosquat = 0;
    /* Brand-homoglyph sets both fam_homoglyph and fam_brand; the homoglyph is
     * the detection, the brand match is its consequence — collapse to one when
     * homoglyph is the only brand signal (no independent hyphenation/subdomain). */
    if (fam_homoglyph && fam_brand &&
        !fam_subdomain && !fam_freehost && !fam_structure) fam_brand = 0;

    n_families = fam_homoglyph + fam_typosquat + fam_idn + fam_brand +
                 fam_subdomain + fam_freehost + fam_path + fam_tld +
                 fam_shortener + fam_attrick + fam_ip + fam_dga +
                 fam_structure + fam_depth;

    if (n_families <= 0) return 0;
    if (n_families == 1) {
        snprintf(out, outsz,
                 "single signal \xe2\x80\x94 one detector fired; corroborate "
                 "independently before acting on a borderline score");
        return 1;
    }
    if (n_families == 2) {
        snprintf(out, outsz,
                 "corroborated by %d independent signals \xe2\x80\x94 unlikely "
                 "to be a single-heuristic false positive", n_families);
        return n_families;
    }
    snprintf(out, outsz,
             "high confidence \xe2\x80\x94 %d independent detector families "
             "agree; this is a deliberate, multi-faceted spoof", n_families);
    return n_families;
}

/* Count how many INDEPENDENT signal categories corroborate a text verdict.
 *
 * Socratic question (Perspective 28): "hlse_confidence_for gives URL verdicts
 * an ⚖ Confidence label. Text verdicts have the same epistemic spectrum: a
 * BEC with urgency + financial + authority + secrecy all firing concurrently
 * is as corroborated as a URL with four independent detectors agreeing. A
 * single-urgency LOG text is as fragile as a single-heuristic URL LOG. Without
 * a confidence line, text verdicts look uniformly certain. Why should URL get
 * epistemic disclosure and text be silent?"
 *
 * Counts base signal families (urgency, financial, authority, secrecy, etc.)
 * separately from amplifier reason strings — amplifiers are derived, not
 * independent. Applies the same qualitative labels as hlse_confidence_for:
 * 1 → "single signal", 2 → "corroborated by N independent signals",
 * 3+ → "high confidence — N independent signal categories agree".
 * Caller supplies `out` buffer (160+ bytes); returns the family count.
 * Thread-safe; no allocation.                                              */
int
hlse_text_confidence(const TextVerdict *v, char *out, size_t outsz) {
    int i;
    int sig_urgency = 0, sig_financial = 0, sig_prize = 0, sig_ransom = 0;
    int sig_authority = 0, sig_secrecy = 0, sig_investment = 0;
    int sig_qr = 0, sig_callback = 0, sig_emergency = 0, sig_clickfix = 0;
    int sig_fake_alert = 0, sig_direct_fin = 0;
    int n_sigs;

    if (!v || !out || outsz < 160) return 0;
    out[0] = '\0';
    if (v->n_reasons == 0) return 0;

    for (i = 0; i < v->n_reasons; i++) {
        const char *r = v->reasons[i];
        /* Skip amplifier lines — they are derived, not independent */
        if (strncmp(r, "Amplifier:", 10) == 0) continue;
        if (strstr(r, "Urgency pressure"))           sig_urgency    = 1;
        if (strstr(r, "Financial/credential"))        sig_financial  = 1;
        if (strstr(r, "Prize/reward"))                sig_prize      = 1;
        if (strstr(r, "Ransom") || strstr(r, "ransom")) sig_ransom   = 1;
        if (strstr(r, "Authority impersonation"))     sig_authority  = 1;
        if (strstr(r, "Secrecy/grooming"))            sig_secrecy    = 1;
        if (strstr(r, "Investment scam"))             sig_investment = 1;
        if (strstr(r, "QR code phishing"))            sig_qr         = 1;
        if (strstr(r, "Callback") || strstr(r, "TOAD") ||
            strstr(r, "smishing"))                    sig_callback   = 1;
        if (strstr(r, "Emergency") || strstr(r, "grandparent")) sig_emergency = 1;
        if (strstr(r, "ClickFix") || strstr(r, "Shell-pipe")) sig_clickfix  = 1;
        if (strstr(r, "Fake security alert"))         sig_fake_alert = 1;
        if (strstr(r, "Direct financial action"))     sig_direct_fin = 1;
    }

    n_sigs = sig_urgency + sig_financial + sig_prize + sig_ransom +
             sig_authority + sig_secrecy + sig_investment + sig_qr +
             sig_callback + sig_emergency + sig_clickfix +
             sig_fake_alert + sig_direct_fin;

    if (n_sigs <= 0) return 0;
    if (n_sigs == 1) {
        snprintf(out, outsz,
                 "single signal \xe2\x80\x94 one category fired; corroborate "
                 "independently before acting on a borderline score");
        return 1;
    }
    if (n_sigs == 2) {
        snprintf(out, outsz,
                 "corroborated by %d independent signals \xe2\x80\x94 unlikely "
                 "to be a single-heuristic false positive", n_sigs);
        return n_sigs;
    }
    snprintf(out, outsz,
             "high confidence \xe2\x80\x94 %d independent signal categories "
             "agree; this is a multi-tactic social engineering attempt", n_sigs);
    return n_sigs;
}

/* Extract the safe destination a user actually wanted, from a URL verdict.
 *
 * Socratic question: "You blocked the counterfeit — but the user still has
 * the legitimate need that made them click. Saying only 'no' leaves them to
 * re-search straight back into the same phishing net. You already know the
 * real domain (you used it to detect the fake). Shouldn't you hand it over?"
 *
 * Perspective 8 derives the canonical brand domain and records it as the
 * evidence reason "Legitimate '<brand>': <domain>". This lifts that buried
 * fact into an actionable, navigable destination so detection completes the
 * loop into guidance. Writes "https://<domain>" into `out`; returns 1 when a
 * canonical brand domain is present in the verdict, 0 otherwise. Thread-safe
 * (caller owns the buffer); no allocation. */
int
hlse_safe_destination(const Verdict *v, char *out, size_t outsz) {
    int i;
    /* Need room for at least "https://" + one host char + NUL. */
    if (!v || !out || outsz < 10) return 0;
    for (i = 0; i < v->n_reasons; i++) {
        const char *r     = v->reasons[i];
        const char *brand = strstr(r, "Legitimate '");
        const char *colon;
        if (!brand) continue;
        colon = strstr(brand, "': ");
        if (!colon) continue;
        /* colon+3 points at the canonical domain, which runs to end-of-reason
         * (the reason is built as "Legitimate '<brand>': <domain>"). */
        snprintf(out, outsz, "https://%s", colon + 3);
        return 1;
    }
    return 0;
}

/* Compound safe destination — the logical counterpart to hlse_compound_objective:
 * for multi-brand co-spoof URLs, a single canonical URL leaves the second
 * brand's legitimate site unnamed while the ◉ and ⊕ lines name both.
 *
 * Socratic question (Perspective 22): "hlse_compound_objective already says
 * 'compound theft — paypal (financial) AND apple (identity) both targeted
 * simultaneously'. hlse_cascade_risk says 'two credential classes targeted at
 * once — audit BOTH'. But → Safe destination: https://paypal.com names only
 * PayPal. The user who just escaped a PayPal+Apple co-spoof phishing page reads
 * 'go to paypal.com' and has no navigable address for their Apple account.
 * The compound framing is now logically inconsistent — should both legitimate
 * destinations appear on that line?"
 *
 * For n_brands == 1 writes "https://<domain>" exactly as hlse_safe_destination().
 * For n_brands >= 2 writes "https://<domain1> and https://<domain2>".
 * Caller supplies `out` buffer (256+ bytes recommended for compound case);
 * returns 1 when any canonical domain was found, 0 otherwise. Thread-safe. */
int
hlse_safe_destinations(const Verdict *v, char *out, size_t outsz) {
    int i;
    char url1[128] = "";
    char url2[128] = "";
    int n_found = 0;

    /* Minimum for "https://<longest domain>" (8 + 64 + NUL = 73) */
    if (!v || !out || outsz < 10) return 0;
    out[0] = '\0';

    for (i = 0; i < v->n_reasons && n_found < 2; i++) {
        const char *r     = v->reasons[i];
        const char *brand = strstr(r, "Legitimate '");
        const char *colon;
        if (!brand) continue;
        colon = strstr(brand, "': ");
        if (!colon) continue;
        /* colon+3 is the canonical domain (to end of reason string) */
        if (n_found == 0)
            snprintf(url1, sizeof(url1), "https://%s", colon + 3);
        else
            snprintf(url2, sizeof(url2), "https://%s", colon + 3);
        n_found++;
    }

    if (n_found == 0) return 0;
    if (n_found == 1 || url2[0] == '\0') {
        snprintf(out, outsz, "%s", url1);
        return 1;
    }
    /* n_found >= 2: name both destinations */
    snprintf(out, outsz, "%s and %s", url1, url2);
    return 1;
}

/* True if `brand` is one of the NULL-terminated names in `set`. */
static int
brand_in_set(const char *brand, const char *const *set) {
    int i;
    for (i = 0; set[i]; i++)
        if (strcmp(brand, set[i]) == 0) return 1;
    return 0;
}

/* Map an impersonated brand to the attacker's likely objective and the asset
 * the victim must now treat as compromised. A known brand that matches no
 * category still returns the generic credential-harvest objective, so any
 * identified brand yields guidance. */
static const char *
brand_objective(const char *brand) {
    static const char *const crypto[] = {
        "coinbase","binance","kraken","coincheck","crypto","metamask","ledger",
        "trezor","trustwallet","opensea","uniswap","pancakeswap","blockchain", NULL };
    static const char *const payment[] = {
        "paypal","paypay","venmo","zelle","cashapp","payoneer","stripe","wise",
        "revolut","chase","wellsfargo","bankofamerica","citibank","barclays",
        "hsbc","usbank","capitalone","mufg","smbc","mizuho","truist","robinhood",
        "etrade","fidelity","schwab","intuit","turbotax","quickbooks", NULL };
    static const char *const identity[] = {
        "google","microsoft","apple","outlook","yahoo","office365",
        "microsoft365","microsoftonline", NULL };
    static const char *const work[] = {
        "okta","microsoftteams","teams","salesforce","docusign","slack","zoom", NULL };
    static const char *const vault[] = {
        "1password","lastpass","bitwarden", NULL };
    static const char *const social[] = {
        "facebook","meta","instagram","twitter","tiktok","snapchat","telegram",
        "whatsapp","reddit","discord","line","linkedin","youtube", NULL };
    static const char *const shopping[] = {
        "netflix","hulu","spotify","disney","hbo","twitch","peacock","amazon",
        "ebay","walmart","bestbuy","homedepot","shopify","rakuten", NULL };
    static const char *const gaming[] = {
        "steam","epicgames","roblox", NULL };
    static const char *const logistics[] = {
        "fedex","dhl","dhlexpress","ups","usps", NULL };
    static const char *const avsoft[] = {
        "norton","mcafee","kaspersky","bitdefender","avast","malwarebytes", NULL };
    static const char *const ai[] = {
        "openai","anthropic","chatgpt","gemini", NULL };
    static const char *const telecom[] = {
        "verizon","tmobile","docomo","softbank", NULL };

    if (brand_in_set(brand, crypto))
        return "crypto theft \xe2\x80\x94 seed phrase or wallet drain; transfers are irreversible";
    if (brand_in_set(brand, payment))
        return "financial-account takeover \xe2\x80\x94 your funds and linked bank accounts";
    if (brand_in_set(brand, vault))
        return "password-vault compromise \xe2\x80\x94 the master key to every stored credential";
    if (brand_in_set(brand, identity))
        return "email/identity takeover \xe2\x80\x94 the keystone that can reset every other account";
    if (brand_in_set(brand, work))
        return "corporate credential theft \xe2\x80\x94 lateral movement into your employer's systems";
    if (brand_in_set(brand, social))
        return "social-account hijack \xe2\x80\x94 impersonation and contact-list scams";
    if (brand_in_set(brand, shopping))
        return "subscription/payment-card theft \xe2\x80\x94 stored payment methods on file";
    if (brand_in_set(brand, gaming))
        return "gaming-account theft \xe2\x80\x94 resale of the account and in-game items";
    if (brand_in_set(brand, logistics))
        return "delivery-fee scam \xe2\x80\x94 a small fraudulent payment and card capture";
    if (brand_in_set(brand, avsoft))
        return "fake-AV / tech-support scam \xe2\x80\x94 remote access and bogus 'support' fees";
    if (brand_in_set(brand, ai))
        return "AI-account / API-key theft \xe2\x80\x94 billed usage and access to your data";
    if (brand_in_set(brand, telecom))
        return "telecom-account takeover \xe2\x80\x94 SIM-swap to intercept your 2FA codes";
    return "credential harvesting \xe2\x80\x94 account takeover";
}

/* One-word credential class label, used to build compound-objective summaries.
 * Derived from the same category sets as brand_objective(). */
static const char *
brand_objective_class(const char *brand) {
    const char *obj = brand_objective(brand);
    if (!obj) return "account";
    if (strstr(obj, "financial") || strstr(obj, "banking") || strstr(obj, "funds"))
        return "financial";
    if (strstr(obj, "crypto") || strstr(obj, "seed phrase") || strstr(obj, "wallet"))
        return "crypto";
    if (strstr(obj, "password-vault"))
        return "vault";
    if (strstr(obj, "identity") || strstr(obj, "keystone"))
        return "identity";
    if (strstr(obj, "corporate") || strstr(obj, "employer") || strstr(obj, "enterprise"))
        return "corporate";
    if (strstr(obj, "social") || strstr(obj, "contact-list"))
        return "social";
    if (strstr(obj, "gaming"))
        return "gaming";
    if (strstr(obj, "subscription") || strstr(obj, "streaming") ||
        strstr(obj, "stored payment"))
        return "subscription";
    if (strstr(obj, "SIM-swap") || strstr(obj, "telecom"))
        return "telecom";
    if (strstr(obj, "AI") || strstr(obj, "API-key"))
        return "AI/API";
    if (strstr(obj, "delivery-fee"))
        return "payment";
    if (strstr(obj, "shopping") || strstr(obj, "logistics"))
        return "shopping";
    return "account";
}

/* Name the attacker's likely objective for a URL verdict.
 *
 * Socratic question: "You named HOW the attack works and WHERE the user should
 * go instead — but never WHAT the attacker is after. 'A phishing page' is
 * abstract and easy to shrug off; 'they want your crypto seed phrase, and that
 * theft is irreversible' names the exact asset to treat as compromised right
 * now. Doesn't the stake decide how hard the user should care?"
 *
 * The attack-pattern lens (hlse_classify_url_attack) describes the mechanism;
 * this describes the *motive and the asset at risk*, derived from which brand
 * was impersonated. Returns a static string, or NULL when no brand was
 * identified in the verdict (no brand → no specific objective to name). */
const char *
hlse_attacker_objective(const Verdict *v) {
    int i;
    if (!v) return NULL;
    for (i = 0; i < v->n_reasons; i++) {
        const char *r     = v->reasons[i];
        const char *start = strstr(r, "Legitimate '");
        const char *end;
        char brand[64];
        size_t len;
        if (!start) continue;
        start += 12;                 /* skip past "Legitimate '" */
        end = strchr(start, '\'');
        if (!end) continue;
        len = (size_t)(end - start);
        if (len == 0 || len >= sizeof(brand)) continue;
        memcpy(brand, start, len);
        brand[len] = '\0';
        return brand_objective(brand);
    }
    return NULL;
}

/* Compound objective for multi-brand co-spoof URLs.
 *
 * Socratic question (Perspective 19): "hlse_attacker_objective() names the
 * primary target precisely — but for multi-brand co-spoof URLs (Perspective 17)
 * it returns only the FIRST brand's objective. A user phished for PayPal AND
 * Apple ID simultaneously faces two compromised credential classes, not one.
 * The ◉ Attacker's goal line says 'financial-account takeover', leaving Apple
 * ID's identity-credential risk completely unnamed. The second objective isn't
 * redundant noise — it determines what the user must protect next. Shouldn't
 * the output name BOTH?"
 *
 * For n_brands == 1 writes the same result as hlse_attacker_objective().
 * For n_brands >= 2 writes a compound summary: "compound theft — paypal
 * (financial) AND apple (identity) both targeted simultaneously". Caller
 * supplies the buffer; no allocation. Returns 1 when any brand was found,
 * 0 when no "Legitimate '...'" reason exists in the verdict. Thread-safe. */
int
hlse_compound_objective(const Verdict *v, char *out, size_t outsz) {
    int i;
    char brand1[64] = "";
    char brand2[64] = "";
    const char *obj1   = NULL;
    const char *class1 = NULL, *class2 = NULL;
    int n_found = 0;

    /* 256 bytes minimum: worst-case compound format is ~228 bytes
     * (19-byte prefix + 63-byte brand1 + 12-byte class + separators
     * + 63-byte brand2 + 12-byte class + 48-byte suffix + NUL). */
    if (!v || !out || outsz < 256) return 0;
    out[0] = '\0';

    for (i = 0; i < v->n_reasons && n_found < 2; i++) {
        const char *r     = v->reasons[i];
        const char *start = strstr(r, "Legitimate '");
        const char *end;
        char brand[64];
        size_t len;
        if (!start) continue;
        start += 12;
        end = strchr(start, '\'');
        if (!end) continue;
        len = (size_t)(end - start);
        if (len == 0 || len >= sizeof(brand)) continue;
        memcpy(brand, start, len);
        brand[len] = '\0';
        if (n_found == 0) {
            memcpy(brand1, brand, len + 1);
            obj1   = brand_objective(brand1);
            class1 = brand_objective_class(brand1);
        } else {
            memcpy(brand2, brand, len + 1);
            class2 = brand_objective_class(brand2);
        }
        n_found++;
    }

    if (n_found == 0) return 0;
    if (n_found == 1) {
        /* Single brand: write the full descriptive objective */
        snprintf(out, outsz, "%s",
                 (obj1 && obj1[0]) ? obj1 : "credential harvesting");
        return 1;
    }
    /* Multi-brand: name both credential classes explicitly */
    snprintf(out, outsz,
             "compound theft \xe2\x80\x94 %s (%s) AND %s (%s) both targeted "
             "simultaneously in a single click",
             brand1, class1 ? class1 : "account",
             brand2, class2 ? class2 : "account");
    return 1;
}

/* Characterise an ASCII character for the diff label. */
static const char *
ascii_char_type(char c) {
    if (c >= '0' && c <= '9') return "digit";
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) return "letter";
    if (c == '-') return "hyphen";
    if (c == '_') return "underscore";
    return "char";
}

/* Pinpoint the ASCII lookalike substitution(s) in a typosquat or ASCII
 * homoglyph verdict — the character-level proof that complements
 * hlse_confusable_report() (which only fires for non-ASCII codepoints).
 *
 * Socratic question (Perspective 20): "You report 'paypa1' vs 'paypal' as a
 * homoglyph. But in a proportional-font browser address bar, digit '1' and
 * lowercase 'l' are visually indistinguishable — the user has to mentally
 * align two strings to spot the difference. Your own verify guidance says
 * 'compare the address bar character by character' without saying WHICH
 * character. What if you pointed to position 6: 'digit 1 masking letter l'?
 * That transforms 'edit distance 1' from an abstract metric into proof the
 * user can physically verify in their address bar right now."
 *
 * Parses "Brand homoglyph: 'X' -> 'Y' (brand)" and
 * "Typosquat: 'X' is edit distance N from 'Y'" reason strings to extract the
 * fake string X and genuine string Y, then reports every differing position
 * with its character type (digit/letter/hyphen). Deliberately skips reasons
 * where X contains non-ASCII bytes — those are already covered by
 * hlse_confusable_report() with richer Unicode context.
 *
 * Writes a one-line summary into `out` (caller-owned); returns 1 when an
 * ASCII-level difference was found, 0 otherwise. Thread-safe; no allocation. */
int
hlse_ascii_diff(const Verdict *v, char *out, size_t outsz) {
    int ri;
    /* 192-byte minimum: worst-case format is "'<63-char-host>': chars N,N are
     * <type> '<c>' masking '<c>'" ≈ 2+63+30+30+30 = ~155 bytes + NUL */
    if (!v || !out || outsz < 192) return 0;
    out[0] = '\0';

    for (ri = 0; ri < v->n_reasons; ri++) {
        const char *r = v->reasons[ri];
        const char *fake_s = NULL, *fake_e = NULL;
        const char *real_s = NULL, *real_e = NULL;
        char fake[64], real_str[64];
        size_t fl, rl;
        int k;

        /* "Brand homoglyph: 'X' -> 'Y' (brand)" */
        if (strncmp(r, "Brand homoglyph:", 16) == 0 &&
            strstr(r, " -> '")) {
            fake_s = strchr(r, '\'');
            if (!fake_s) continue;
            fake_s++;
            fake_e = strchr(fake_s, '\'');
            if (!fake_e) continue;
            real_s = strstr(fake_e, "-> '");
            if (!real_s) continue;
            real_s += 4;
            real_e = strchr(real_s, '\'');
            if (!real_e) continue;
        }
        /* "Typosquat: 'X' is edit distance N from 'Y'"
         * "Possible typosquat: 'X' is edit distance N from 'Y'" */
        else if ((strncmp(r, "Typosquat:", 10) == 0 ||
                  strncmp(r, "Possible typosquat:", 19) == 0) &&
                 strstr(r, "from '")) {
            fake_s = strchr(r, '\'');
            if (!fake_s) continue;
            fake_s++;
            fake_e = strchr(fake_s, '\'');
            if (!fake_e) continue;
            real_s = strstr(fake_e, "from '");
            if (!real_s) continue;
            real_s += 6;
            real_e = strchr(real_s, '\'');
            if (!real_e) continue;
        } else {
            continue;
        }

        fl = (size_t)(fake_e - fake_s);
        rl = (size_t)(real_e - real_s);
        if (fl == 0 || fl >= sizeof(fake)) continue;
        if (rl == 0 || rl >= sizeof(real_str)) continue;
        memcpy(fake,     fake_s, fl); fake[fl]    = '\0';
        memcpy(real_str, real_s, rl); real_str[rl] = '\0';

        /* Skip if fake contains non-ASCII — hlse_confusable_report() covers it */
        {
            int has_non_ascii = 0;
            for (k = 0; k < (int)fl; k++)
                if ((unsigned char)fake[k] > 127) { has_non_ascii = 1; break; }
            if (has_non_ascii) continue;
        }

        /* Find all differing positions (substitution case: fl == rl) */
        if (fl == rl) {
            int diff_positions[8];
            int n_diffs = 0;
            for (k = 0; k < (int)fl && n_diffs < 8; k++) {
                if (fake[k] != real_str[k]) diff_positions[n_diffs++] = k;
            }
            if (n_diffs == 0) continue;
            if (n_diffs == 1) {
                int p = diff_positions[0];
                snprintf(out, outsz,
                         "'%s': char %d is %s '%c', masking %s '%c'",
                         fake, p + 1,
                         ascii_char_type(fake[p]), fake[p],
                         ascii_char_type(real_str[p]), real_str[p]);
            } else {
                /* Multiple substitutions: report first two, note count */
                int p0 = diff_positions[0];
                int p1 = diff_positions[1];
                snprintf(out, outsz,
                         "'%s': char %d %s '%c'→'%c', char %d %s '%c'→'%c'%s",
                         fake,
                         p0 + 1, ascii_char_type(fake[p0]), fake[p0], real_str[p0],
                         p1 + 1, ascii_char_type(fake[p1]), fake[p1], real_str[p1],
                         n_diffs > 2 ? " (more)" : "");
            }
            return 1;
        }

        /* Insertion: fake has one extra character */
        if (fl == rl + 1) {
            int j = 0;
            for (k = 0; k < (int)fl; k++) {
                if (j >= (int)rl || fake[k] != real_str[j]) {
                    snprintf(out, outsz,
                             "'%s': extra %s '%c' at char %d",
                             fake, ascii_char_type(fake[k]), fake[k], k + 1);
                    return 1;
                }
                j++;
            }
            continue;
        }

        /* Deletion: real has one extra character */
        if (rl == fl + 1) {
            int j = 0;
            for (k = 0; k < (int)rl; k++) {
                if (j >= (int)fl || real_str[k] != fake[j]) {
                    snprintf(out, outsz,
                             "'%s': missing %s '%c' at char %d",
                             fake, ascii_char_type(real_str[k]), real_str[k], k + 1);
                    return 1;
                }
                j++;
            }
            continue;
        }
    }
    return 0;
}

/* Name the Unicode script block a confusable codepoint belongs to, for the
 * human-readable forensic report. */
static const char *
confusable_script(unsigned long cp) {
    if (cp >= 0x0400 && cp <= 0x04FF) return "Cyrillic";
    if (cp >= 0x0500 && cp <= 0x052F) return "Cyrillic-supplement";
    if (cp >= 0x0370 && cp <= 0x03FF) return "Greek";
    if (cp >= 0x0530 && cp <= 0x058F) return "Armenian";
    if (cp >= 0x2000 && cp <= 0x206F) return "Unicode-punctuation";
    if (cp >= 0xFF00 && cp <= 0xFFEF) return "fullwidth/halfwidth";
    return "non-Latin";
}

/* Pinpoint the first disguised (non-ASCII) character in a URL's host, with its
 * 1-based position, Unicode codepoint, and script — the forensic proof behind
 * a "homoglyph" label.
 *
 * Socratic question: "You said 'mixed-script homoglyph' and then showed the
 * user the very string their eyes already glossed over — 'раypal.com' looks
 * identical to 'paypal.com'. Which exact character is the impostor? Naming it
 * ('position 1 is Cyrillic U+0440, not an ASCII letter') turns an abstract
 * label into undeniable, teachable proof a browser's address bar hides."
 *
 * Only non-ASCII (raw IDN / mixed-script) hosts produce a report — pure-ASCII
 * homoglyphs (0/1/l) are already spelled out in the brand-homoglyph reason, and
 * xn-- punycode hosts are ASCII and covered by the IDN reason. Operates on the
 * host (between "://" and the first "/?#"). Writes a one-line summary into out;
 * returns 1 when a disguised character is found, 0 otherwise. Thread-safe; no
 * allocation. */
int
hlse_confusable_report(const char *url, char *out, size_t outsz) {
    const char *h, *p, *host_end;
    int cp_pos = 0;
    if (!url || !out || outsz == 0) return 0;
    h = strstr(url, "://");
    h = h ? h + 3 : url;
    host_end = h;
    while (*host_end && *host_end != '/' && *host_end != '?' && *host_end != '#')
        host_end++;
    for (p = h; p < host_end; ) {
        unsigned char c = (unsigned char)*p;
        unsigned long cp;
        int n, k, ok = 1;
        if      (c < 0x80)          { n = 1; cp = c; }
        else if ((c & 0xE0) == 0xC0){ n = 2; cp = (unsigned long)(c & 0x1F); }
        else if ((c & 0xF0) == 0xE0){ n = 3; cp = (unsigned long)(c & 0x0F); }
        else if ((c & 0xF8) == 0xF0){ n = 4; cp = (unsigned long)(c & 0x07); }
        else                        { n = 1; cp = c; }
        for (k = 1; k < n; k++) {
            if (p + k >= host_end || ((unsigned char)p[k] & 0xC0) != 0x80) {
                ok = 0;
                break;
            }
            cp = (cp << 6) | (unsigned long)((unsigned char)p[k] & 0x3F);
        }
        cp_pos++;
        if (ok && cp >= 0x80) {
            /* Format into a bounded local buffer first: in the library build
             * GCC cannot see callers to bound `outsz`, so a direct snprintf of
             * the literal trips -Wformat-truncation=2. Stage into a fixed-size
             * buffer (provable bound), then copy with an explicit clamp to
             * outsz — memcpy is outside the format-truncation analysis. */
            char tmp[96];
            size_t L;
            snprintf(tmp, sizeof(tmp),
                     "position %d is %s U+%04lX, not an ASCII letter",
                     cp_pos, confusable_script(cp), cp);
            if (outsz > 0) {
                L = strlen(tmp);
                if (L >= outsz) L = outsz - 1;
                memcpy(out, tmp, L);
                out[L] = '\0';
            }
            return 1;
        }
        p += ok ? n : 1;
    }
    return 0;
}

/* The single best independent check a user can run to confirm an actionable
 * URL verdict — without trusting HLSE.
 *
 * Socratic question (Perspective 95): "You're a heuristic engine with no
 * network, no certificate inspection, no ground truth. A user about to type
 * their password is betting on your word alone. What ONE check can they run
 * right now — one that doesn't require trusting you — to confirm the verdict
 * before they act? And why does ALERT [40-59] leave verify/triage/cascade_risk
 * NULL while BLOCK [60+] fills them in — is the user at 40-59 not ALSO about
 * to make a decision that benefits from an independent check?"
 *
 * This used to gate at score >= 60 only, leaving the ALERT band a
 * pattern+objective with no actionable next step. But ALERT is precisely the
 * band where the verdict is least certain and an independent check is most
 * valuable — a BLOCK verdict is confident enough that "verify" is a courtesy,
 * while an ALERT verdict genuinely needs it to resolve the ambiguity. Gates
 * at score >= 40 (ALERT+) so it now co-occurs with hlse_exoneration_for's
 * 15..59 band in the 40..59 overlap: exoneration gives the benign read,
 * verify gives the independent test — together they let the user decide
 * rather than just watching a score. The check is chosen from the signals
 * that fired so it targets the actual deception. Returns a static string, or
 * NULL when score < 40. */
const char *
hlse_verification_for(const Verdict *v) {
    int i;
    int shortener = 0, at_trick = 0, ip = 0, homoglyph = 0, idn = 0;
    int subdomain = 0, free_host = 0, typo = 0, brand = 0;

    if (!v || v->score < 40) return NULL;

    for (i = 0; i < v->n_reasons; i++) {
        const char *r = v->reasons[i];
        if (strstr(r, "shortener") || strstr(r, "Shortened"))       shortener = 1;
        if (strstr(r, "credential trick") || strstr(r, "@ in authority")) at_trick = 1;
        if (strstr(r, "IP-based URL") || strstr(r, "IP-address host")) ip = 1;
        if (strstr(r, "homoglyph") || strstr(r, "Homoglyph") ||
            strstr(r, "Mixed-script"))                              homoglyph = 1;
        if (strstr(r, "IDN") || strstr(r, "Punycode"))              idn = 1;
        if (strstr(r, "Subdomain spoofing") || strstr(r, "subdomain")) subdomain = 1;
        if (strstr(r, "Free-hosting") || strstr(r, "free page builder")) free_host = 1;
        if (strstr(r, "Typosquat") || strstr(r, "typosquat"))       typo = 1;
        if (strstr(r, "Brand") || strstr(r, "brand") ||
            strstr(r, "Legitimate '"))                              brand = 1;
    }

    if (shortener)
        return "expand the short link before opening it (many shorteners show a "
               "preview if you append '+' to the URL) \xe2\x80\x94 never click one blind";
    if (at_trick)
        return "read the authority right before the first '/': everything after "
               "an '@' is where you actually land, not the brand shown before it";
    if (ip)
        return "legitimate brands do not serve login pages from a bare IP "
               "address \xe2\x80\x94 that alone marks it fake";
    if (idn || homoglyph)
        return "don't read the link \xe2\x80\x94 reach the brand from your own "
               "bookmark or a search engine and compare the address bar "
               "character by character";
    if (subdomain || free_host)
        return "read the domain right-to-left: the registrable name just before "
               "the first single '/' is the real owner, not the brand spelled "
               "earlier in the host";
    if (typo || brand)
        return "ignore the link text; open the brand via a saved bookmark or by "
               "typing its name into a search engine, then compare the domain";
    return "confirm through a channel you already trust (the official app, or a "
           "number printed on your card/statement) \xe2\x80\x94 never one supplied "
           "by this message";
}

/* First-response triage for the post-click user — what to do in the next
 * 60 seconds to minimise damage.
 *
 * Socratic question: "The verdict assumes the user saw HLSE's output BEFORE
 * clicking. But people typically notice something's wrong AFTER submitting
 * credentials. At that moment 'BLOCK' and a list of structural reasons is
 * useless — they need triage: what to do right now. Does HLSE serve the
 * post-click user at all?"
 *
 * This is the temporal complement: verify (before) → triage (after). Derived
 * from the same brand-objective class as hlse_attacker_objective so the
 * action directly matches the asset at risk. Only fires at score >= 60 where
 * the verdict is confident enough to warrant incident-response guidance.
 * Returns a static string, or NULL when score < 60.                         */
const char *
hlse_triage_for(const Verdict *v) {
    const char *obj;
    if (!v || v->score < 60) return NULL;
    obj = hlse_attacker_objective(v);
    if (!obj)
        return "revoke all active sessions NOW (Security settings \xe2\x86\x92 "
               "'sign out everywhere'), THEN change the password \xe2\x80\x94 "
               "modern phishing proxies your real login and steals the session "
               "cookie, so 2FA does not stop it and a password change alone "
               "leaves the attacker's stolen session live; check login history "
               "for sessions you do not recognise";
    if (strstr(obj, "crypto") || strstr(obj, "seed phrase") || strstr(obj, "wallet"))
        return "if you entered a seed phrase or private key, move remaining assets "
               "to a new wallet immediately \xe2\x80\x94 crypto transfers cannot be "
               "reversed or frozen; if instead you APPROVED a transaction or "
               "connected your wallet to the site, revoke the token approval NOW "
               "at revoke.cash or your chain's explorer (Token Approvals) \xe2\x80\x94 "
               "a wallet drainer steals through a live approval, not your seed, "
               "and keeps draining until the approval is revoked";
    if (strstr(obj, "password-vault"))
        return "change your master password now and rotate every credential stored "
               "in the vault \xe2\x80\x94 a compromised vault is a skeleton key to "
               "every account you manage";
    if (strstr(obj, "financial") || strstr(obj, "funds"))
        return "call the number on the back of your card or the banking app "
               "immediately to block it and dispute any pending transactions";
    if (strstr(obj, "identity") || strstr(obj, "keystone"))
        return "change your email password, revoke all active sessions (usually "
               "in Security settings), and audit account-recovery options now "
               "\xe2\x80\x94 this account can reset every other";
    if (strstr(obj, "corporate") || strstr(obj, "employer"))
        return "notify your IT/security team immediately \xe2\x80\x94 enterprise "
               "SSO compromise enables lateral movement into your organisation's "
               "systems and must be contained within minutes";
    if (strstr(obj, "social") || strstr(obj, "contact-list"))
        return "revoke active sessions, change your password, and warn your "
               "contacts right now \xe2\x80\x94 attackers use hijacked accounts to "
               "target your network next";
    if (strstr(obj, "SIM-swap") || strstr(obj, "telecom"))
        return "call your carrier immediately to add a SIM-lock PIN \xe2\x80\x94 "
               "a SIM-swap defeats every SMS-based 2FA code across all accounts";
    if (strstr(obj, "API-key") || strstr(obj, "AI"))
        return "revoke the affected API key in the provider console now "
               "\xe2\x80\x94 a live key incurs billed usage every second until "
               "revoked and may expose your data";
    if (strstr(obj, "gaming"))
        return "change your account password and enable 2FA now \xe2\x80\x94 "
               "gaming accounts are listed for sale within minutes of compromise";
    if (strstr(obj, "subscription") || strstr(obj, "stored payment"))
        return "remove saved payment methods from the account and change your "
               "password; check for unauthorised subscription charges";
    if (strstr(obj, "delivery-fee"))
        return "if you entered card details on the fake delivery page, call the "
               "number on the back of the card immediately to block it";
    return "revoke all active sessions NOW (Security settings \xe2\x86\x92 "
           "'sign out everywhere'), THEN change the password \xe2\x80\x94 "
           "modern phishing proxies your real login and steals the session "
           "cookie, so 2FA does not stop it and a password change alone "
           "leaves the attacker's stolen session live; check login history "
           "for sessions you do not recognise";
}

/* Map an objective-class label to its concise triage imperative for use
 * in compound (multi-brand) triage sentences.
 * Returns a short phrase (<= 140 chars) or the generic fallback. */
static const char *
triage_imperative(const char *cls) {
    if (!cls) return "change the password and check recent login activity";
    if (strcmp(cls, "financial") == 0)
        return "call the number on the back of your card to freeze it and dispute "
               "pending transactions";
    if (strcmp(cls, "crypto") == 0)
        return "move remaining assets to a new wallet immediately \xe2\x80\x94 "
               "crypto transfers are irreversible";
    if (strcmp(cls, "vault") == 0)
        return "change your master password and rotate every stored credential "
               "now \xe2\x80\x94 a compromised vault is a skeleton key to every account";
    if (strcmp(cls, "identity") == 0)
        return "change that email/identity password, revoke all sessions, and "
               "audit recovery options \xe2\x80\x94 it can reset every other account";
    if (strcmp(cls, "corporate") == 0)
        return "notify your IT/security team immediately \xe2\x80\x94 enterprise "
               "SSO compromise enables lateral movement within minutes";
    if (strcmp(cls, "social") == 0)
        return "revoke active sessions, change your password, and warn your "
               "contacts \xe2\x80\x94 attackers target your network next";
    if (strcmp(cls, "telecom") == 0)
        return "call your carrier to add a SIM-lock PIN \xe2\x80\x94 a SIM-swap "
               "defeats every SMS-based 2FA code";
    if (strcmp(cls, "AI/API") == 0)
        return "revoke the affected API key in the provider console now";
    if (strcmp(cls, "gaming") == 0)
        return "change your account password and enable 2FA \xe2\x80\x94 gaming "
               "accounts are listed for sale within minutes";
    if (strcmp(cls, "subscription") == 0 || strcmp(cls, "payment") == 0)
        return "remove saved payment methods and change your password";
    return "change the password and check recent login activity";
}

/* Compound first-response triage for the post-click user — the temporal
 * complement to hlse_cascade_risk, narrowed to the next 60 seconds.
 *
 * Socratic question (Perspective 23): "hlse_triage_for() calls
 * hlse_attacker_objective() which returns the FIRST brand's objective.
 * For a PayPal+Apple co-spoof (financial AND identity), the triage line says
 * 'call the number on the back of your card' — correct for PayPal but silent
 * on Apple ID. That account can reset every other account the victim owns.
 * In a compound attack the victim has TWO concurrent incident-response
 * obligations, not one. If they prioritise the bank call and miss the Apple
 * ID reset window, the attacker still controls the recovery gateway for their
 * entire account ecosystem. Shouldn't the ⚑ line cover both?
 *
 * For n_brands == 1: writes the same result as hlse_triage_for().
 * For n_brands >= 2: writes a numbered two-step sequence:
 *   '(1) <financial triage>; (2) <identity triage>'
 * so both response obligations are visible in one line without truncation.
 * Caller supplies `out` buffer (512+ bytes for compound case);
 * returns 1 when guidance was written, 0 when score < 60 or buffer too small. */
int
hlse_compound_triage(const Verdict *v, char *out, size_t outsz) {
    int i;
    char brand1[64] = "";
    char brand2[64] = "";
    const char *class1 = NULL, *class2 = NULL;
    int n_found = 0;
    const char *single;

    /* 512-byte minimum for compound two-step triage sentence */
    if (!v || !out || outsz < 512 || v->score < 60) return 0;
    out[0] = '\0';

    for (i = 0; i < v->n_reasons && n_found < 2; i++) {
        const char *r     = v->reasons[i];
        const char *start = strstr(r, "Legitimate '");
        const char *end;
        char brand[64];
        size_t len;
        if (!start) continue;
        start += 12;
        end = strchr(start, '\'');
        if (!end) continue;
        len = (size_t)(end - start);
        if (len == 0 || len >= sizeof(brand)) continue;
        memcpy(brand, start, len);
        brand[len] = '\0';
        if (n_found == 0) {
            memcpy(brand1, brand, len + 1);
            class1 = brand_objective_class(brand1);
        } else {
            memcpy(brand2, brand, len + 1);
            class2 = brand_objective_class(brand2);
        }
        n_found++;
    }

    if (n_found == 0) {
        /* No brand found — fall back to hlse_triage_for() */
        single = hlse_triage_for(v);
        if (!single) return 0;
        snprintf(out, outsz, "%s", single);
        return 1;
    }
    if (n_found == 1) {
        single = hlse_triage_for(v);
        if (!single) return 0;
        snprintf(out, outsz, "%s", single);
        return 1;
    }
    /* n_found >= 2: compound two-step triage */
    snprintf(out, outsz,
             "(1) %s; (2) %s",
             triage_imperative(class1), triage_imperative(class2));
    return 1;
}

/* First-response triage for a text verdict — the 60-second action the post-
 * response user must take immediately.
 *
 * Socratic question (Perspective 27): "URL verdicts have ⚑ If already clicked:
 * triage. But BEC, tech-support scam, and grandparent-emergency victims don't
 * click a URL — they REPLY to an email, call a phone number, or act on a voice
 * instruction. By the time they reach HLSE, the harmful action is already done.
 * A BEC victim who just sent a wire needs to know: call the sending bank's
 * fraud line within 72 hours and request SWIFT recall — not read 'BLOCK [100]'.
 * A tech-support victim who gave remote access needs: disconnect from the
 * internet immediately, not a structural verdict. Shouldn't text threats >= 60
 * have the same temporal triage as URL threats?"
 *
 * Keyed to the same attack pattern as hlse_classify_text_attack() so the
 * response matches the specific harm that fired. Returns a static string, or
 * NULL when score < 60 or no recognisable pattern was found. Thread-safe;
 * no allocation.                                                              */
const char *
hlse_text_triage(const TextVerdict *v) {
    const char *pat;
    if (!v || v->score < 60) return NULL;
    pat = hlse_classify_text_attack(v);
    if (!pat) return NULL;

    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
        return "stop all payments and deposits now; if you already paid or "
               "deposited crypto, contact your bank or exchange immediately; if "
               "you installed any 'work-from-home' or 'security' app they sent, "
               "disconnect from the internet and remove it \xe2\x80\x94 it may be a "
               "remote-access trojan; report to the FTC (reportfraud.ftc.gov) "
               "or your national fraud line";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
        return "deny/dismiss the prompt; do NOT approve it \xe2\x80\x94 then "
               "change your password immediately from a device you trust, "
               "because an unsolicited MFA prompt means your password is already "
               "compromised; if you did approve one, sign out all sessions, "
               "rotate the password, and report it to your IT/security team";
    if (strstr(pat, "payment-diversion"))
        return "do NOT update the bank/payee details; if you already changed "
               "them, revert immediately and alert your payroll/accounts-payable "
               "team and your bank \xe2\x80\x94 check whether a payment run already "
               "went out so it can be recalled while it is still pending; verify "
               "the real employee or vendor on a phone number you already have";
    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
        return "if you entered the code OR clicked 'Accept' on a consent "
               "screen: FIRST revoke the app's access at "
               "myapplications.microsoft.com (or have an admin remove the "
               "enterprise app), then sign out of all Microsoft 365 sessions "
               "and revoke active tokens in entra.microsoft.com (Security "
               "\xe2\x86\x92 Sign-ins \xe2\x86\x92 revoke), then rotate the "
               "password \xe2\x80\x94 a consented app and a stolen refresh "
               "token both outlive a password reset, so removing the app's "
               "consent is the step most victims miss";
    if (strstr(pat, "ClickFix"))
        return "if you already pasted and ran the command: disconnect from the "
               "network immediately, scan with antivirus, and consider a full "
               "reinstall \xe2\x80\x94 a pasted command runs with your privileges";
    if (strstr(pat, "BEC") || strstr(pat, "CEO") ||
        strstr(pat, "wire-transfer") || strstr(pat, "wire transfer"))
        return "DO NOT send or authorise the transfer \xe2\x80\x94 if already "
               "sent, call your bank's fraud line within 72 hours to attempt a "
               "SWIFT recall; verify the request by calling the supposed sender "
               "on a separately-known number, not the one in this message";
    if (strstr(pat, "tech-support"))
        return "if you called the number: hang up now; if you gave remote "
               "access: disconnect from the internet immediately and UNINSTALL "
               "the remote-access tool they had you install (AnyDesk, "
               "TeamViewer, UltraViewer, etc.) \xe2\x80\x94 it keeps their access "
               "until removed; then change your banking credentials from a "
               "different device and call your IT team or bank directly";
    if (strstr(pat, "grandparent") || strstr(pat, "emergency impersonation"))
        return "call the family member directly on a number you already know "
               "\xe2\x80\x94 if they are genuinely in trouble, they can confirm "
               "it themselves; a voice that sounds exactly like them is NOT "
               "proof \xe2\x80\x94 AI clones a voice from 3 seconds of audio, so "
               "ask a pre-agreed safe word and do not send money or gift cards "
               "until you reach them on your own number";
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
        return "do NOT pay and do NOT reply \xe2\x80\x94 replying confirms a live "
               "target and invites more demands; screenshot the message as "
               "evidence, block the sender, and report to IC3 / your national "
               "cybercrime line (and, if a minor is involved, NCMEC at "
               "CyberTipline.org); if real intimate images of you do exist, "
               "report them to the platform for takedown";
    if (strstr(pat, "ransom") || strstr(pat, "extortion"))
        return "do not pay \xe2\x80\x94 screenshot the message and report to "
               "your local cybercrime unit (FBI IC3, Action Fraud, etc.), then "
               "block the sender; most extortion threats are empty";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
        return "stop all transfers immediately \xe2\x80\x94 if funds were sent, "
               "contact your bank to attempt a recall; report to your financial "
               "regulator; 'withdrawal fees' to recover losses are always a "
               "second theft";
    if (strstr(pat, "quishing") || strstr(pat, "QR"))
        return "if you already scanned the QR code: check your browser's address "
               "bar for an untrusted domain before entering any credentials; if "
               "you entered credentials, change that account's password now; if "
               "you approved a payment to an unexpected payee, contact your bank "
               "or payment provider immediately to stop or dispute it";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
        return "do not call the number; if you already called, never grant "
               "remote access or send back an 'over-refund' \xe2\x80\x94 a genuine "
               "refund needs nothing from you; if you gave remote access, "
               "disconnect and uninstall the tool (it may be a trojan) and "
               "dispute any real charge through your card issuer, not the caller";
    if (strstr(pat, "callback") || strstr(pat, "vishing") || strstr(pat, "TOAD"))
        return "do not call the number in this message \xe2\x80\x94 if you "
               "already called and gave personal information, contact your bank "
               "and change the relevant account credentials immediately";
    if (strstr(pat, "lottery") || strstr(pat, "advance-fee"))
        return "stop sending money \xe2\x80\x94 every 'fee' request is another "
               "theft; report to Action Fraud / FTC and block the contact";
    if (strstr(pat, "urgency credential") || strstr(pat, "urgency social") ||
        strstr(pat, "authority impersonation"))
        return "if you entered credentials: change that account's password "
               "immediately and enable 2FA; if you shared personal information: "
               "monitor credit and banking for unusual activity";
    /* Generic fallback for any other high-confidence text threat */
    return "stop the action if ongoing; change credentials for any account "
           "involved and enable 2FA; report the contact to your IT team or "
           "the relevant platform's abuse reporting";
}

/* Pre-action verification for a text verdict — the single check to perform
 * BEFORE taking any requested action (score >= 40, the ALERT floor).
 *
 * Socratic question (Perspective 31): "URL BLOCK verdicts show BOTH
 * ✓ Verify independently: (what to check before clicking) AND ⚑ If already
 * clicked: (post-click triage). Text BLOCK verdicts show only ⚑ If you acted:
 * whose label implies post-action, even when the most important advice is
 * pre-action — 'DO NOT send the wire transfer'. A BEC victim reading BLOCK [100]
 * needs to know the single decisive check they should do BEFORE authorising
 * anything: call the supposed sender on a separately-known number. A ClickFix
 * victim needs to know: never paste commands from unsolicited messages. Burying
 * this pre-action guidance inside a post-action triage label obscures it. Should
 * text BLOCK verdicts have the same ✓ Verify first: / ⚑ If you acted: split
 * that URL verdicts already have?"
 *
 * Socratic question (Perspective 95): "An ALERT [40-59] text verdict — e.g.
 * a single urgency/callback signal — shows a pattern label but no verify
 * guidance, same gap as the URL side. Widened the floor from 60 to 40 in
 * lockstep with hlse_verification_for so a user reading ALERT text gets the
 * same pre-action check a BLOCK reader gets, before the situation escalates."
 *
 * Keyed to the pattern from hlse_classify_text_attack(). Returns a static
 * string, or NULL when score < 40 or no recognisable pattern. Thread-safe;
 * no allocation.                                                               */
const char *
hlse_text_verify(const TextVerdict *v) {
    const char *pat;
    if (!v || v->score < 40) return NULL;
    pat = hlse_classify_text_attack(v);
    if (!pat) return NULL;
    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
        return "a real job only ever pays money TO you \xe2\x80\x94 no legitimate "
               "employer asks you to pay to start, deposit your own funds to "
               "'unlock' tasks or earnings, or buy equipment upfront; that "
               "request alone proves the job is fake, so stop before paying "
               "anything";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
        return "never approve an MFA or authenticator prompt you did not start "
               "yourself \xe2\x80\x94 a prompt or 'approve' request that arrives "
               "when you were not logging in means someone ALREADY has your "
               "password; deny it, and never approve to 'make the prompts stop'";
    if (strstr(pat, "payment-diversion"))
        return "confirm any bank-account or direct-deposit change by calling the "
               "employee or vendor on a number you ALREADY have on file \xe2\x80\x94 "
               "never the number, email, or reply-to in the request; a banking-"
               "detail change is the single highest-risk request, so treat it as "
               "fraud until verified through a separate channel";
    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
        return "never enter a verification code you did not initiate yourself, "
               "and never click 'Accept' on an app-permission/consent screen "
               "you did not start \xe2\x80\x94 even at a legitimate microsoft.com "
               "or google.com URL; the page is real but the code or consent "
               "hands the attacker's app your tokens";
    if (strstr(pat, "ClickFix"))
        return "never paste or run commands from unsolicited messages \xe2\x80\x94 "
               "legitimate software installations never require manual command-line "
               "execution";
    if (strstr(pat, "BEC") || strstr(pat, "CEO") ||
        strstr(pat, "wire-transfer") || strstr(pat, "wire transfer"))
        return "verify by calling the supposed sender on a number you already have "
               "\xe2\x80\x94 not any number or channel in this message; wire-transfer "
               "requests without a prior phone call are a red flag";
    if (strstr(pat, "tech-support"))
        return "a virus-warning popup that shows a phone number is ALWAYS fake "
               "\xe2\x80\x94 real security software never tells you to call; close "
               "the browser (or force-quit it) and never call the number on the "
               "screen; if you need help, call the company's main switchboard "
               "independently before allowing any remote access or payment";
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
        return "the 'I hacked your webcam' claim is almost always a bluff blasted "
               "to millions \xe2\x80\x94 any password they quote was bought from a "
               "data breach, not proof of access; they cannot show you real "
               "footage because none exists, so do not pay and do not reply";
    if (strstr(pat, "ransom") || strstr(pat, "extortion"))
        return "do not pay \xe2\x80\x94 consult a law enforcement or cybersecurity "
               "professional before responding; paying funds further attacks";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
        return "verify the firm's FCA/SEC/ASIC registration before engaging \xe2\x80\x94 "
               "registration numbers must match the official regulator's public register";
    if (strstr(pat, "grandparent") || strstr(pat, "emergency impersonation"))
        return "do not trust the voice \xe2\x80\x94 AI voice-cloning reproduces a "
               "loved one from a few seconds of audio; hang up and call the "
               "family member back on their own known number, and ask a "
               "pre-agreed safe word before sending any money or meeting any "
               "courier \xe2\x80\x94 take at least 10 minutes to verify independently";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
        return "check the charge in your real bank or card statement, or the "
               "provider's official app \xe2\x80\x94 never the number or link in "
               "this message; no genuine company phones you to give money back, "
               "so an unexpected 'refund' offer is itself the scam";
    if (strstr(pat, "callback") || strstr(pat, "TOAD") || strstr(pat, "vishing"))
        return "do not call the number in this message \xe2\x80\x94 find the "
               "organisation's number independently on their official website";
    if (strstr(pat, "lottery") || strstr(pat, "advance-fee"))
        return "do not pay any fee \xe2\x80\x94 legitimate prize schemes never charge "
               "winners upfront; search the organisation's official website to verify";
    if (strstr(pat, "QR") || strstr(pat, "quishing"))
        return "preview the QR destination before scanning \xe2\x80\x94 do not enter "
               "any credentials until you have confirmed the domain belongs to the "
               "expected organisation; on a PHYSICAL QR (parking meter, restaurant "
               "table, payment poster) feel for a sticker placed over the original, "
               "and on any payment QR confirm the payee name shown matches the real "
               "merchant before approving";
    if (strstr(pat, "urgency credential") || strstr(pat, "credential / payment") ||
        strstr(pat, "authority impersonation"))
        return "navigate directly to the service's official website (bookmark or "
               "search engine) \xe2\x80\x94 do not use any link in this message; "
               "verify the alert appears in your actual account dashboard";
    if (strstr(pat, "urgency"))
        return "verify the request through a separately-known channel before acting "
               "\xe2\x80\x94 do not use any contact details provided in this message";
    return NULL;
}

/* Name the attacker's likely objective for a text verdict — the specific asset
 * the recipient must treat as at-risk.
 *
 * Socratic question (Perspective 29): "URL verdicts show ◉ Attacker's goal:
 * keyed to the impersonated brand — 'crypto theft — seed phrase or wallet
 * drain; transfers are irreversible'. Text verdicts name the attack pattern
 * (▸ Pattern:) but not what the attacker is specifically trying to take. A BEC
 * victim reads 'BEC / CEO-fraud wire-transfer' and knows the mechanism, but
 * not that the asset at risk is wire-transfer funds with a 72-hour recall
 * window. A grandparent-scam victim reads 'emergency impersonation scam' but
 * not that the asset is cash — unrecoverable once handed to a courier. Without
 * naming the specific asset, the advisory gives no triage priority signal.
 * Shouldn't text threats >= 60 name the specific asset at risk, parallel to
 * the URL ◉ Attacker's goal: line?"
 *
 * Keyed to the same pattern as hlse_classify_text_attack(). Returns a static
 * string, or NULL when score < 60 or no recognisable pattern. Thread-safe;
 * no allocation.                                                               */
const char *
hlse_text_objective(const TextVerdict *v) {
    const char *pat;
    if (!v || v->score < 60) return NULL;
    pat = hlse_classify_text_attack(v);
    if (!pat) return NULL;
    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
        return "upfront fees and deposits you will never recover \xe2\x80\x94 the "
               "'job' exists to take your equipment payment or 'task' deposit; "
               "any 'work-from-home app' they tell you to install may be a "
               "remote-access trojan that drains your bank and files";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
        return "account takeover via MFA approval \xe2\x80\x94 the attacker "
               "already has your password and is spamming push prompts; "
               "approving one hands them an authenticated session";
    if (strstr(pat, "payment-diversion"))
        return "redirected payments \xe2\x80\x94 your next payroll deposit or "
               "vendor invoice is rerouted to the attacker's bank account; the "
               "money is gone once the payment run clears";
    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
        return "Microsoft 365 / Azure OAuth tokens \xe2\x80\x94 grants persistent "
               "access that bypasses MFA and survives password reset; attacker "
               "can read mail, exfiltrate files, and pivot to connected SaaS";
    if (strstr(pat, "ClickFix"))
        return "system access \xe2\x80\x94 pasted command runs with your user "
               "privileges; treat the machine as compromised until proven clean";
    if (strstr(pat, "BEC") || strstr(pat, "CEO") ||
        strstr(pat, "wire-transfer") || strstr(pat, "wire transfer"))
        return "wire-transfer funds \xe2\x80\x94 irreversible once processed; "
               "72-hour SWIFT recall window";
    if (strstr(pat, "tech-support"))
        return "credit card or remote device access \xe2\x80\x94 reversible "
               "within hours if caught immediately";
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
        return "an extortion payment for a threat that is almost always an empty "
               "bluff \xe2\x80\x94 these emails are mass-mailed and the attacker "
               "usually has no footage at all; even AI-deepfaked images do not "
               "make paying work, because payment only marks you as a target";
    if (strstr(pat, "ransom") || strstr(pat, "extortion"))
        return "cryptocurrency payment \xe2\x80\x94 paying does not guarantee "
               "recovery and invites further extortion demands";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
        return "long-term savings \xe2\x80\x94 typically unrecoverable once "
               "withdrawn to attacker-controlled wallet";
    if (strstr(pat, "grandparent") || strstr(pat, "emergency impersonation"))
        return "cash withdrawal \xe2\x80\x94 typically unrecoverable once handed "
               "to courier";
    if (strstr(pat, "QR") || strstr(pat, "quishing"))
        return "credentials entered after redirect \xe2\x80\x94 QR codes bypass "
               "link-preview safety checks";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
        return "money and device access via a fake refund \xe2\x80\x94 the "
               "invoice is bait to make you call; the 'refund' then requires "
               "remote access to your device or tricks you into wiring back an "
               "'over-refund' the scammer never actually sent";
    if (strstr(pat, "callback") || strstr(pat, "TOAD") || strstr(pat, "vishing"))
        return "financial account or device access obtained via voice social "
               "engineering";
    if (strstr(pat, "lottery") || strstr(pat, "advance-fee"))
        return "upfront payment or personal information for a non-existent prize";
    if (strstr(pat, "urgency credential") || strstr(pat, "credential / payment") ||
        strstr(pat, "authority impersonation"))
        return "account credentials \xe2\x80\x94 all sites sharing this password "
               "are at cascade risk";
    if (strstr(pat, "urgency"))
        return "account credentials or an action taken under false time pressure";
    if (strstr(pat, "prize"))
        return "personal information or upfront payment for a fraudulent prize";
    return NULL;
}

/* Cascade risk for a text verdict — the other accounts or assets at risk
 * beyond the primary target.
 *
 * Socratic question (Perspective 32): "URL verdicts have ⊕ Also change:
 * naming every account class in the password-reuse blast radius (email,
 * banking, every service sharing the harvested password). Text BLOCK verdicts
 * identify the primary attack and tell users what to do about it — but say
 * nothing about the downstream accounts that fall if the primary is compromised.
 * A ClickFix victim who disconnects their machine has fixed the primary but may
 * still have all their saved browser passwords exfiltrated. A BEC victim who
 * recalls the wire has stopped the funds but may have the corporate email
 * account compromised, giving the attacker the recovery address for everything
 * else. Shouldn't text BLOCK verdicts also name what else is at risk, parallel
 * to the URL ⊕ Also change: line?"
 *
 * Keyed to the attack pattern from hlse_classify_text_attack(). Returns a
 * static string, or NULL when score < 60 or no recognisable pattern.
 * Thread-safe; no allocation.                                                 */
const char *
hlse_text_cascade(const TextVerdict *v) {
    const char *pat;
    if (!v || v->score < 60) return NULL;
    pat = hlse_classify_text_attack(v);
    if (!pat) return NULL;
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
        return "nothing of yours is technically compromised by the threat itself "
               "\xe2\x80\x94 but if you reused the breached password they quoted, "
               "change it everywhere it appears, and tighten privacy on your "
               "social accounts so the attacker cannot reach your contact list";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
        return "if you granted remote access or moved any money, treat the whole "
               "device and every account you opened during the call as "
               "compromised \xe2\x80\x94 scan from a clean device, change those "
               "passwords, and watch your card and bank for unauthorised charges";
    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
        return "any card or account you used to pay, and any credentials you "
               "entered on the fake 'employer portal' \xe2\x80\x94 plus, if you ran "
               "their software, treat the whole device as compromised: scan it, "
               "change passwords from a clean device, and watch for unauthorised "
               "bank activity";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
        return "every account sharing this now-compromised password, and your "
               "email (the recovery gateway) \xe2\x80\x94 the attacker already "
               "knows the password, so rotate it everywhere it is reused and "
               "switch this account to phishing-resistant MFA (a passkey or "
               "hardware key) that cannot be approved by mistake";
    if (strstr(pat, "payment-diversion"))
        return "every other payee record an attacker with this mailbox could "
               "alter \xe2\x80\x94 audit all recent bank-detail changes for staff "
               "and vendors, and check whether the email account that sent this "
               "is itself compromised (it is the likely entry point)";
    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
        return "every SaaS app connected to your Microsoft 365 tenant (SharePoint, "
               "Teams, Exchange, OneDrive) and any third-party app with consent "
               "from your account \xe2\x80\x94 revoke app consents in entra.microsoft."
               "com and audit recent OAuth grants from a clean device";
    if (strstr(pat, "ClickFix"))
        return "all credentials stored in browsers, password managers, and the OS "
               "credential store \xe2\x80\x94 assume the script exfiltrated them; "
               "change all saved passwords from a clean device";
    if (strstr(pat, "BEC") || strstr(pat, "CEO") ||
        strstr(pat, "wire-transfer") || strstr(pat, "wire transfer"))
        return "corporate email (likely the channel used to authorise the transfer "
               "and the recovery address for every downstream service) \xe2\x80\x94 "
               "treat it as compromised and change it from a different device";
    if (strstr(pat, "tech-support"))
        return "all credentials visible during the remote-access session "
               "\xe2\x80\x94 the operator could see your screen, saved logins, and "
               "password manager; change them all from a different device";
    if (strstr(pat, "urgency credential") || strstr(pat, "credential / payment") ||
        strstr(pat, "authority impersonation"))
        return "email (the recovery gateway for all other accounts), banking and "
               "payment apps, and every account sharing this password "
               "\xe2\x80\x94 credential-stuffing bots test stolen logins within "
               "minutes of harvest";
    if (strstr(pat, "QR") || strstr(pat, "quishing"))
        return "the account entered after redirect, email (recovery gateway), and "
               "every service sharing that password";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
        return "other liquid assets and any exchange accounts or bank accounts used "
               "to fund the investment \xe2\x80\x94 review all recent transfers";
    if (strstr(pat, "urgency"))
        return "email (the recovery gateway) and every account sharing the password "
               "or personal information disclosed under urgency pressure";
    return NULL;
}

/* Cascade risk: the blast radius if the victim reused this password elsewhere.
 *
 * Socratic question (Perspective 18): "You've named the primary target and
 * given triage guidance for that account. But credential-stuffing bots test
 * stolen logins against hundreds of services within minutes — and 65 % of
 * people reuse passwords. If the victim's PayPal password is also their Gmail
 * password, the attacker now controls the recovery address for every other
 * account. Shouldn't post-click guidance name the accounts most likely to fall
 * in a cascade, not just the one they were phished for?
 *
 * For multi-brand co-spoof URLs (Perspective 17) the cascade is compound —
 * two credential classes harvested at once compounds the blast radius further."
 *
 * Returns a static string, or NULL when score < 60 (pre-click context has no
 * cascade to describe). Thread-safe: no allocation, reads static tables only. */
const char *
hlse_cascade_risk(const Verdict *v) {
    const char *obj;
    const char *pat;
    if (!v || v->score < 60) return NULL;

    /* Multi-brand co-spoof: compound harvest across two credential classes. */
    pat = hlse_classify_url_attack(v);
    if (pat && strstr(pat, "multi-brand co-spoof"))
        return "two credential classes were targeted at once — audit BOTH: "
               "the financial/payment account AND the identity/email account, "
               "then change any other account sharing either password; "
               "stuffing bots test stolen pairs across hundreds of services "
               "within minutes";

    obj = hlse_attacker_objective(v);
    if (!obj)
        return "change any other account sharing this password \xe2\x80\x94 "
               "credential-stuffing bots test stolen logins across "
               "hundreds of services within minutes";
    if (strstr(obj, "financial") || strstr(obj, "banking") || strstr(obj, "funds"))
        return "email (the recovery gateway for all other accounts), other "
               "banking and payment apps, and every account sharing this "
               "password \xe2\x80\x94 stuffing attacks start within minutes "
               "of a credential harvest";
    if (strstr(obj, "crypto") || strstr(obj, "seed phrase") || strstr(obj, "wallet"))
        return "other exchanges and any account using the same email or "
               "password \xe2\x80\x94 on-chain transfers are irreversible so "
               "act before funds move; a compromised seed drains ALL wallets "
               "derived from it, not just one; and if you approved any contract, "
               "audit and revoke EVERY active token approval (revoke.cash) \xe2\x80\x94 "
               "a drainer often holds approvals across several tokens at once";
    if (strstr(obj, "identity") || strstr(obj, "keystone"))
        return "every account that lists this email as its password-reset "
               "address \xe2\x80\x94 whoever controls your inbox controls "
               "account recovery for everything else; start with banking, "
               "then work through any account you care about";
    if (strstr(obj, "corporate") || strstr(obj, "employer") || strstr(obj, "enterprise"))
        return "other work apps (email, Slack, Jira, VPN, SSO), and alert your "
               "IT security team immediately \xe2\x80\x94 a single corporate "
               "credential often pivots to the entire network within hours";
    if (strstr(obj, "SIM-swap") || strstr(obj, "telecom"))
        return "every account protected only by SMS-based 2FA \xe2\x80\x94 a "
               "SIM-swap defeats those codes across all services at once; "
               "switch to an authenticator app on accounts you cannot afford "
               "to lose";
    if (strstr(obj, "password-vault"))
        return "all credentials stored in the vault, and the email address "
               "used to recover the vault itself \xe2\x80\x94 a compromised "
               "vault exposes every account you manage in one breach";
    if (strstr(obj, "gaming"))
        return "linked payment methods, the associated email, and any account "
               "sharing this password \xe2\x80\x94 compromised game accounts "
               "are listed for sale within hours, often before the owner "
               "notices";
    if (strstr(obj, "social") || strstr(obj, "contact-list"))
        return "accounts accessed via 'Sign in with [brand]', linked payment "
               "methods, and the associated email \xe2\x80\x94 attackers use "
               "a hijacked social account to target your contact list next";
    if (strstr(obj, "subscription") || strstr(obj, "stored payment"))
        return "saved payment cards on other shopping sites and any account "
               "sharing this password \xe2\x80\x94 attackers drain gift cards "
               "and place orders on saved methods immediately after compromise";
    return "any other account sharing this password \xe2\x80\x94 change them "
           "starting with email (the master reset key for everything else)";
}

/* Positive authentication check for a clean URL verdict.
 *
 * Socratic question: "When you output 'OK' for https://paypal.com you're
 * saying 'I found nothing wrong' — absence of evidence. But you KNOW
 * paypal.com is the exact canonical PayPal domain — you used that fact to
 * detect paypa1.com. For this URL you have POSITIVE evidence of legitimacy,
 * not just absence of threat signals. 'This is the authenticated PayPal
 * domain confirmed by the HLSE brand registry' is a stronger statement than
 * 'I found nothing suspicious.' Why not say that?"
 *
 * Iterates BRANDS[] and brand_canonical() to test whether the URL's
 * effective host is a confirmed canonical or official subdomain.
 * Strips a leading "www." before comparing, then checks:
 *   1. Exact match: paypal.com → paypal (same as before).
 *   2. Official subdomain: login.paypal.com ends with ".paypal.com" → paypal.
 * The subdomain check only fires at score == 0 (a fake domain that triggered
 * any brand detector will have a non-zero score and never reaches this path).
 * This closes the gap where official brand authentication subdomains such as
 * login.paypal.com, accounts.google.com, and id.apple.com were indistinguishable
 * from unknown domains in HLSE output.
 *
 * Writes the matched brand name into `brand_out` (caller-owned). Returns 1
 * when the URL is confirmed canonical or an official brand subdomain, 0 otherwise.
 * Thread-safe; no allocation.                                                */
int
hlse_canonical_confirm(const char *url, char *brand_out, size_t brand_outsz) {
    const char *h, *host_end;
    char host[256];
    size_t hlen;
    int i;
    const char *check;

    if (!url || !brand_out || brand_outsz == 0) return 0;

    /* Extract host between "://" and first "/?#" */
    h = strstr(url, "://");
    h = h ? h + 3 : url;
    host_end = h;
    while (*host_end && *host_end != '/' && *host_end != '?' && *host_end != '#')
        host_end++;
    hlen = (size_t)(host_end - h);
    if (hlen == 0 || hlen >= sizeof(host)) return 0;
    memcpy(host, h, hlen);
    host[hlen] = '\0';

    /* Strip optional "www." prefix */
    check = (strncmp(host, "www.", 4) == 0) ? host + 4 : host;

    for (i = 0; BRANDS[i]; i++) {
        const char *canon = brand_canonical(BRANDS[i]);
        size_t clen;
        size_t chklen;
        if (!canon) continue;
        clen   = strlen(canon);
        chklen = strlen(check);
        /* Exact match (e.g. paypal.com) */
        if (strcmp(check, canon) == 0) {
            if (brand_outsz > 1) {
                strncpy(brand_out, BRANDS[i], brand_outsz - 1);
                brand_out[brand_outsz - 1] = '\0';
            }
            return 1;
        }
        /* Official subdomain (e.g. login.paypal.com, accounts.google.com).
         * Requires chklen > clen + 1 (at least one label before the dot),
         * a literal dot separator, and the suffix equal to the canonical. */
        if (chklen > clen + 1 &&
            check[chklen - clen - 1] == '.' &&
            strcmp(check + chklen - clen, canon) == 0) {
            if (brand_outsz > 1) {
                strncpy(brand_out, BRANDS[i], brand_outsz - 1);
                brand_out[brand_outsz - 1] = '\0';
            }
            return 1;
        }
    }
    return 0;
}

/* ───────────────── blast-radius / asset-class correlation ─────────────────
 * A leaked credential's danger is not its count but what the *set* of leaked
 * credentials collectively unlocks. We bucket each secret-finding type into a
 * coarse asset class; when a scan turns up credentials spanning two or more
 * classes, an attacker can pivot across systems (code → cloud → data), which
 * is materially worse than many tokens of a single class. */
enum {
    ASSET_CLOUD    = 1 << 0,   /* AWS/GCP/Azure/DO infrastructure          */
    ASSET_SCM      = 1 << 1,   /* GitHub/GitLab source control             */
    ASSET_DATABASE = 1 << 2,   /* DB / service connection-string creds     */
    ASSET_PAYMENT  = 1 << 3,   /* Stripe/PayPal/Square                     */
    ASSET_COMMS    = 1 << 4,   /* Slack/Discord/Telegram/SendGrid/Twilio   */
    ASSET_AI       = 1 << 5,   /* OpenAI/Anthropic/Groq/… provider keys    */
    ASSET_CRYPTO   = 1 << 6    /* SSH/PGP private keys                      */
};

/* CLI-only (scan/secret blast-radius reporting); marked unused so the
 * library build, which excludes the CLI, does not warn. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused))
#endif
static unsigned
asset_class_of(const char *type) {
    if (!type) return 0;
    if (strstr(type, "AWS") || strstr(type, "GCP") || strstr(type, "Google") ||
        strstr(type, "AZURE") || strstr(type, "Azure") ||
        strstr(type, "DigitalOcean") || strstr(type, "Databricks") ||
        strstr(type, "Render") || strstr(type, "Fly.io") ||
        strstr(type, "Vercel") || strstr(type, "Netlify"))
        return ASSET_CLOUD;
    if (strstr(type, "GitHub") || strstr(type, "GitLab"))
        return ASSET_SCM;
    if (strstr(type, "URI_CREDENTIALS") || strstr(type, "Database") ||
        strstr(type, "PlanetScale"))
        return ASSET_DATABASE;
    if (strstr(type, "Stripe") || strstr(type, "PayPal") ||
        strstr(type, "Square"))
        return ASSET_PAYMENT;
    if (strstr(type, "Slack") || strstr(type, "Discord") ||
        strstr(type, "Telegram") || strstr(type, "SendGrid") ||
        strstr(type, "Twilio") || strstr(type, "Postman"))
        return ASSET_COMMS;
    if (strstr(type, "OpenAI") || strstr(type, "Anthropic") ||
        strstr(type, "Groq") || strstr(type, "Perplexity") ||
        strstr(type, "xAI") || strstr(type, "Hugging"))
        return ASSET_AI;
    if (strstr(type, "PRIVATE_KEY") || strstr(type, "Private key"))
        return ASSET_CRYPTO;
    return 0;  /* generic env/JWT/entropy — not pivot-defining */
}

/* Priority action for the threat mix found by a scan pass.
 * Returns a one-sentence triage hint keyed to the highest-severity
 * asset class (or file/URL threats when no credentials were found). */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused))
#endif
static const char *
scan_immediate_action(unsigned mask, int nclasses) {
    if (nclasses >= 2)
        return "MULTI-CLASS: rotate ALL leaked credentials immediately \xe2\x80\x94 "
               "an attacker with multiple asset classes can pivot across systems";
    if (mask & ASSET_CLOUD)
        return "rotate all cloud API keys immediately \xe2\x80\x94 cloud access "
               "enables server control, data exfiltration, and billing fraud";
    if (mask & ASSET_PAYMENT)
        return "contact your payment processor to invalidate the leaked key \xe2\x80\x94 "
               "payment keys can be used for fraud within minutes";
    if (mask & ASSET_SCM)
        return "revoke the leaked source control token from repository settings "
               "\xe2\x80\x94 then audit CI/CD pipeline secret access";
    if (mask & ASSET_DATABASE)
        return "rotate database credentials and audit the query log for "
               "unauthorized reads \xe2\x80\x94 database access exposes all records";
    if (mask & ASSET_CRYPTO)
        return "replace the private key and remove it from authorized_keys "
               "on every host that trusts it";
    if (mask & ASSET_AI)
        return "regenerate the API key in the provider dashboard \xe2\x80\x94 "
               "AI provider keys can incur large charges when abused";
    if (mask & ASSET_COMMS)
        return "regenerate the webhook or bot token from the service dashboard";
    return "review per-finding output \xe2\x80\x94 quarantine or delete flagged "
           "files before deploying or sharing";
}

/* CLI-only (scan/secret blast-radius reporting); see asset_class_of above. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused))
#endif
static int
asset_mask_describe(unsigned mask, char *out, size_t outsz) {
    static const struct { unsigned bit; const char *name; } A[] = {
        { ASSET_CLOUD,    "cloud-infrastructure" },
        { ASSET_SCM,      "source-control" },
        { ASSET_DATABASE, "database" },
        { ASSET_PAYMENT,  "payment" },
        { ASSET_COMMS,    "communications" },
        { ASSET_AI,       "AI-provider" },
        { ASSET_CRYPTO,   "private-key" },
        { 0, NULL }
    };
    int i, n = 0;
    size_t w = 0;
    out[0] = '\0';
    for (i = 0; A[i].name; i++) {
        if (mask & A[i].bit) {
            int k = snprintf(out + w, outsz - w, "%s%s",
                             n ? ", " : "", A[i].name);
            if (k > 0 && (size_t)k < outsz - w) w += (size_t)k;
            n++;
        }
    }
    return n;  /* number of distinct asset classes */
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

/* Stable machine-readable pattern id for a file-masquerade verdict — the file
 * counterpart of hlse_text_pattern_id (P86). Keyed to the prose label computed
 * inline at the file display sites so the same append-only HLSE-FILE-* tokens
 * are emitted everywhere a file `pattern` is shown. Returns "HLSE-FILE-MASQUERADE"
 * for the catch-all masquerade label; never NULL when called with a non-NULL
 * fpat. */
static const char *
file_pattern_id(const char *fpat) {
    if (!fpat) return NULL;
    if (strstr(fpat, "RTL override"))    return "HLSE-FILE-RTL-OVERRIDE";
    if (strstr(fpat, "double-extension")) return "HLSE-FILE-DOUBLE-EXT";
    if (strstr(fpat, "macro"))            return "HLSE-FILE-MACRO";
    if (strstr(fpat, "embedded JavaScript")) return "HLSE-FILE-PDF-JS";
    return "HLSE-FILE-MASQUERADE";
}

/* Stable file pattern_id derived directly from a FileVerdict's first reason —
 * mirrors the prose-label ladder at the file display sites so the SARIF scan
 * path (P91) emits the same HLSE-FILE-* token as the standalone `file` JSON. */
static const char *
file_verdict_pattern_id(const FileVerdict *fv) {
    if (fv->n_reasons > 0) {
        const char *r = fv->reasons[0];
        if (strstr(r, "RLO") || strstr(r, "Unicode"))
            return "HLSE-FILE-RTL-OVERRIDE";
        if (strstr(r, "DOUBLE EXTENSION") || strstr(r, "double"))
            return "HLSE-FILE-DOUBLE-EXT";
        if (strstr(r, "macro") || strstr(r, "Macro"))
            return "HLSE-FILE-MACRO";
        if (strstr(r, "PDF") || strstr(r, "JavaScript"))
            return "HLSE-FILE-PDF-JS";
    }
    return "HLSE-FILE-MASQUERADE";
}

/* Socratic question (Perspective 101): "The same RLO/DOUBLE-EXTENSION/macro/
 * PDF if-else classification ladder is copy-pasted at all four file display
 * sites (standalone `file` JSON, standalone plaintext, `scan`'s embedded-file
 * JSON, `scan`'s embedded-file plaintext) as an inline local `fpat` variable —
 * four independent copies of the same four conditions, right next to the
 * single shared file_verdict_pattern_id() a few lines above that already
 * performs the identical match for the pattern_id token. Four independently
 * maintained copies is exactly how the standalone-vs-scan field asymmetry
 * that Perspective 95 had to fix originally happened. Shouldn't the
 * human-readable label share one function the way the token already does?"
 *
 * Consolidates the four inline copies into one function so pattern label and
 * pattern_id can never again drift apart between the standalone and scan
 * code paths. Pure refactor — every branch and return value is unchanged. */
static const char *
file_classify_pattern(const FileVerdict *fv) {
    if (fv->n_reasons > 0) {
        const char *r = fv->reasons[0];
        if (strstr(r, "RLO") || strstr(r, "Unicode"))
            return "Unicode RTL override trick (hidden file extension)";
        if (strstr(r, "DOUBLE EXTENSION") || strstr(r, "double"))
            return "double-extension file masquerade (disguised executable)";
        if (strstr(r, "macro") || strstr(r, "Macro"))
            return "Office macro delivery (document-based malware lure)";
        if (strstr(r, "PDF") || strstr(r, "JavaScript"))
            return "PDF with embedded JavaScript (drive-by execution lure)";
    }
    return "file masquerade / malicious file delivery";
}

/* The two ALERT-floor (score >= 40) advisory lines for any file-masquerade
 * verdict — identical regardless of which specific pattern fired, so a
 * single pair of accessors (mirroring file_classify_pattern above) replaces
 * the four independently duplicated string literals this used to be. */
static const char *
file_masquerade_objective(void) {
    return "code execution \xe2\x80\x94 opening a disguised executable "
           "or document with macros runs the payload with your "
           "user privileges; the visual disguise is designed to "
           "bypass 'I checked the extension' caution";
}

static const char *
file_masquerade_verify(void) {
    return "do NOT open the file; scan it with a multi-engine "
           "sandbox (e.g. VirusTotal) first \xe2\x80\x94 right-click "
           "to upload; confirm the file came from a trusted source "
           "through a separately-known channel";
}

/* Stable machine-readable pattern id for an exposed-credential verdict — the
 * secret counterpart of hlse_text_pattern_id (P86). Keyed to the credential
 * type label (sv.findings[0].type) so SIEM rules route on a stable HLSE-SECRET-*
 * token instead of the freeform provider string. Returns "HLSE-SECRET-GENERIC"
 * for unrecognised types; never NULL when called with a non-NULL ftype. */
static const char *
secret_pattern_id(const char *ftype) {
    if (!ftype) return NULL;
    if (strstr(ftype, "AWS"))     return "HLSE-SECRET-AWS";
    if (strstr(ftype, "GitHub"))  return "HLSE-SECRET-GITHUB";
    if (strstr(ftype, "Stripe"))  return "HLSE-SECRET-STRIPE";
    if (strstr(ftype, "Slack"))   return "HLSE-SECRET-SLACK";
    if (strstr(ftype, "Google"))  return "HLSE-SECRET-GOOGLE";
    if (strstr(ftype, "OpenAI"))  return "HLSE-SECRET-OPENAI";
    if (strstr(ftype, "Anthropic")) return "HLSE-SECRET-ANTHROPIC";
    if (strstr(ftype, "Azure"))   return "HLSE-SECRET-AZURE";
    if (strstr(ftype, "Private key") || strstr(ftype, "private key"))
                                  return "HLSE-SECRET-PRIVATE-KEY";
    if (strstr(ftype, "JWT"))     return "HLSE-SECRET-JWT";
    return "HLSE-SECRET-GENERIC";
}

/* ── Pattern-ID registry (Perspective 88) ──────────────────────────────────
 * The stable HLSE-* pattern_id tokens introduced across P78–P87 exist so SIEM
 * and SOAR pipelines can route on an append-only identifier instead of prose
 * that we keep rewording. But a stable token is only useful to automation if
 * the FULL set is discoverable — and until now the universe of tokens could
 * only be learned by grepping this source. `--list-patterns` closes that gap:
 * it emits the authoritative registry (token, kind, prose description) so a
 * consumer can build a complete routing table without reading C.
 *
 * This table is the single source of truth; keep it append-only (never reword
 * or remove a token — that is the whole point) and in sync with the emitters
 * above and in hlse_text_pattern_id / hlse_url_pattern_id.                   */
struct pattern_entry {
    const char *id;    /* stable HLSE-* token                                */
    const char *kind;  /* verdict kind that emits it                         */
    const char *desc;  /* one-line human description                         */
};

static const struct pattern_entry g_pattern_registry[] = {
    /* text / social-engineering attack patterns (hlse_text_pattern_id) */
    { "HLSE-CLICKFIX",            "text", "ClickFix paste-and-run script-injection lure" },
    { "HLSE-OAUTH-DEVICECODE",    "text", "OAuth device-code phishing" },
    { "HLSE-MFA-FATIGUE",         "text", "MFA fatigue / push-bombing" },
    { "HLSE-BEC-PAYMENT-DIVERSION","text","BEC payment / bank-detail diversion" },
    { "HLSE-BEC-CEO",             "text", "BEC CEO-fraud impersonation" },
    { "HLSE-BEC-WIRE",            "text", "BEC wire-transfer fraud" },
    { "HLSE-CALLBACK-TOAD",       "text", "Telephone-oriented attack delivery (callback phishing)" },
    { "HLSE-SEXTORTION",          "text", "Sextortion extortion scam" },
    { "HLSE-INVESTMENT",          "text", "Investment / pig-butchering scam" },
    { "HLSE-ADVANCE-FEE",         "text", "Advance-fee fraud" },
    { "HLSE-PRIZE",               "text", "Prize / lottery scam" },
    { "HLSE-REFUND-SCAM",         "text", "Refund / overpayment scam" },
    { "HLSE-JOB-SCAM",            "text", "Job-offer / task scam" },
    { "HLSE-TECH-SUPPORT",        "text", "Tech-support scam" },
    { "HLSE-QUISHING",            "text", "QR-code phishing (quishing)" },
    { "HLSE-RANSOM",              "text", "Ransom / extortion demand" },
    { "HLSE-FAKE-ALERT",          "text", "Fake security-alert lure" },
    { "HLSE-CRED-LURE",           "text", "Credential-harvest lure" },
    { "HLSE-URGENCY-CRED",        "text", "Urgency + credential request" },
    { "HLSE-AUTHORITY",           "text", "Authority-impersonation pressure" },
    { "HLSE-EMERGENCY",           "text", "Manufactured-emergency pressure" },
    { "HLSE-URGENCY",             "text", "Generic urgency pressure" },
    { "HLSE-GENERIC",             "text", "Recognised text attack, unclassified pattern" },
    /* url / phishing-link patterns (hlse_url_pattern_id) */
    { "HLSE-URL-HOMOGLYPH",       "url",  "Homoglyph / look-alike domain" },
    { "HLSE-URL-IDN-HOMOGRAPH",   "url",  "IDN homograph (mixed-script) domain" },
    { "HLSE-URL-TYPOSQUAT",       "url",  "Typosquat of a known brand domain" },
    { "HLSE-URL-TYPOSQUAT-HARVEST","url", "Typosquat with credential-harvest path" },
    { "HLSE-URL-BRAND",           "url",  "Brand impersonation in domain" },
    { "HLSE-URL-BRAND-RISKY-TLD", "url",  "Brand name on a high-risk TLD" },
    { "HLSE-URL-MULTI-BRAND",     "url",  "Multiple brands co-spoofed in one host" },
    { "HLSE-URL-SUBDOMAIN",       "url",  "Brand placed in subdomain of attacker domain" },
    { "HLSE-URL-SUBDOMAIN-HARVEST","url", "Subdomain brand spoof with harvest path" },
    { "HLSE-URL-HYPHEN-BRAND",    "url",  "Brand-hyphen-securityword phishing host" },
    { "HLSE-URL-HYPHEN-HARVEST",  "url",  "Hyphenated brand host with harvest path" },
    { "HLSE-URL-IP-BRAND",        "url",  "Raw-IP URL impersonating a brand" },
    { "HLSE-URL-CRED-HARVEST",    "url",  "Credential-harvest path pattern" },
    { "HLSE-URL-AT-CRED-TRICK",   "url",  "'@' userinfo credential trick in URL" },
    { "HLSE-URL-SHORTENER",       "url",  "URL shortener masking the destination" },
    { "HLSE-URL-FREEHOST",        "url",  "Free-hosting / abuse-prone provider" },
    { "HLSE-URL-DGA",             "url",  "Algorithmically-generated (DGA) domain" },
    { "HLSE-URL-GENERIC",         "url",  "Recognised URL attack, unclassified pattern" },
    /* file masquerade patterns (file_pattern_id) */
    { "HLSE-FILE-RTL-OVERRIDE",   "file", "Unicode RTL-override filename trick" },
    { "HLSE-FILE-DOUBLE-EXT",     "file", "Double-extension masquerade" },
    { "HLSE-FILE-MACRO",          "file", "Office macro delivery" },
    { "HLSE-FILE-PDF-JS",         "file", "PDF with embedded JavaScript" },
    { "HLSE-FILE-MASQUERADE",     "file", "Generic file masquerade / malicious delivery" },
    /* exposed-credential types (secret_pattern_id) */
    { "HLSE-SECRET-AWS",          "secret", "AWS access key" },
    { "HLSE-SECRET-GITHUB",       "secret", "GitHub token" },
    { "HLSE-SECRET-STRIPE",       "secret", "Stripe API key" },
    { "HLSE-SECRET-SLACK",        "secret", "Slack token" },
    { "HLSE-SECRET-GOOGLE",       "secret", "Google API key" },
    { "HLSE-SECRET-OPENAI",       "secret", "OpenAI API key" },
    { "HLSE-SECRET-ANTHROPIC",    "secret", "Anthropic API key" },
    { "HLSE-SECRET-AZURE",        "secret", "Azure credential" },
    { "HLSE-SECRET-PRIVATE-KEY",  "secret", "Private key (PEM/OpenSSH)" },
    { "HLSE-SECRET-JWT",          "secret", "JSON Web Token" },
    { "HLSE-SECRET-GENERIC",      "secret", "Generic / heuristic credential" },
    /* single-pattern kinds (emitted inline at the kind's BLOCK path) */
    { "HLSE-ESP-BOOTKIT",         "esp",       "UEFI bootkit indicator in EFI System Partition" },
    { "HLSE-PKG-TYPOSQUAT",       "package",   "Dependency-confusion / typosquat supply-chain attack" },
    { "HLSE-NET-C2",             "network",   "Suspicious network activity (C2 / exfiltration)" },
    { "HLSE-CLIP-HIJACK",         "clipboard", "Cryptocurrency clipboard hijack (clipper malware)" },
    { "HLSE-PROTECT-RANSOM",      "protect",   "Ransomware / destructive-malware indicator (file entropy, SMB canary, mass rename)" }
};

/* Emit the full pattern-ID registry. JSON mode → an array of
 * {id, kind, description} objects under a "patterns" key; text mode → an
 * aligned table. Returns 0 (a meta-command, never a failure gate).          */
static int
list_patterns(int json_out) {
    size_t n = sizeof(g_pattern_registry) / sizeof(g_pattern_registry[0]);
    size_t i;
    if (json_out) {
        /* The registry strings are author-controlled constants (ASCII, no
         * quotes/backslashes/control chars), so they need no JSON escaping —
         * keeping this self-contained and free of a forward reference to
         * json_escape, which is defined later in the file. */
        printf("{\"kind\":\"pattern_registry\",\"hlse_version\":\"" HLSE_VERSION
               "\",\"count\":%zu,\"patterns\":[", n);
        for (i = 0; i < n; i++) {
            printf("%s{\"id\":\"%s\",\"kind\":\"%s\",\"description\":\"%s\"}",
                   i > 0 ? "," : "",
                   g_pattern_registry[i].id,
                   g_pattern_registry[i].kind,
                   g_pattern_registry[i].desc);
        }
        printf("]}\n");
    } else {
        printf("HLSE pattern_id registry (%zu stable tokens, append-only)\n", n);
        for (i = 0; i < n; i++)
            printf("  %-28s [%-9s] %s\n",
                   g_pattern_registry[i].id,
                   g_pattern_registry[i].kind,
                   g_pattern_registry[i].desc);
    }
    return 0;
}


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
    char  pattern_id[40];/* stable HLSE-* token for SOAR routing (P91)        */
    char  message[512];
    int   score;
} SarifFinding;

static SarifFinding g_sarif[SARIF_MAX_FINDINGS];
static int          g_sarif_n = 0;
static int          g_sarif_overflow = 0;

static void
sarif_add(const char *path, int line, const char *rule,
          const char *pattern_id, const char *message, int score) {
    SarifFinding *f;
    if (g_sarif_n >= SARIF_MAX_FINDINGS) { g_sarif_overflow = 1; return; }
    f = &g_sarif[g_sarif_n++];
    snprintf(f->path, sizeof(f->path), "%s", path);
    f->line = line < 1 ? 1 : line;
    snprintf(f->rule, sizeof(f->rule), "%s", rule);
    snprintf(f->pattern_id, sizeof(f->pattern_id), "%s",
             pattern_id ? pattern_id : "");
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
        const char *tags;     /* JSON array body for properties.tags        */
    } RULES[] = {
        { "secret",         "Credential Leak",
          "Exposed API key, token, or private key found in source file.",
          "9.0",
          "\"security\", \"external/cwe/cwe-798\"" },
        { "phishing-url",   "Phishing URL",
          "URL exhibits homoglyph, typosquat, or subdomain-spoof phishing indicators.",
          "7.5",
          "\"security\", \"external/cwe/cwe-1021\"" },
        { "file-masquerade","File Masquerade",
          "File extension or magic bytes indicate the file is disguised malware.",
          "8.0",
          "\"security\", \"external/cwe/cwe-646\"" },
        { "package-typosquat","Dependency Typosquat",
          "Declared dependency name is a likely typosquat of a popular package "
          "(dependency-confusion / supply-chain attack).",
          "7.0",
          "\"security\", \"external/cwe/cwe-1357\"" },
        { NULL, NULL, NULL, NULL, NULL }
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
               "              \"helpUri\": \"https://github.com/shizukutanaka/hlse/blob/main/docs/SIEM_INTEGRATION.md\",\n"
               "              \"properties\": { \"security-severity\": \"%s\", \"tags\": [%s] }\n"
               "            }%s\n",
               RULES[i].id, RULES[i].name, RULES[i].description,
               RULES[i].severity, RULES[i].tags, RULES[i+1].id ? "," : "");
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
        if (f->pattern_id[0]) {
            char epid[64];
            json_escape(f->pattern_id, epid, sizeof(epid));
            printf("          \"properties\": { \"security-severity\": \"%.1f\","
                   " \"hlse-score\": %d, \"pattern_id\": \"%s\" },\n",
                   sev, f->score, epid);
        } else {
            printf("          \"properties\": { \"security-severity\": \"%.1f\","
                   " \"hlse-score\": %d },\n", sev, f->score);
        }
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

/* Delivery channel supplied via --from.  NULL when the flag is absent.
 * Socratic Q: "You analysed the URL — but HLSE has no idea how it reached
 * you.  A QR code in a parking meter and a link you typed yourself share
 * the same bytes, yet carry very different priors.  Should the channel
 * change the verdict?"  Answer: yes — the channel is a threat-prior.      */
static const char *g_from_channel = NULL;

/* Score boost applied to URLs when a high-risk delivery channel is set.
 * Only meaningful for URLs (not text); capped at 100 at output sites.    */
static int
channel_delta(const char *ch)
{
    if (!ch) return 0;
    if (strcmp(ch, "qr")     == 0) return 20; /* quishing — QR masks destination */
    if (strcmp(ch, "sms")    == 0) return 15; /* smishing — primary mobile vector  */
    if (strcmp(ch, "email")  == 0) return 10; /* phishing — classic email vector   */
    if (strcmp(ch, "dm")     == 0) return 10; /* social-engineering via DM         */
    if (strcmp(ch, "manual") == 0) return  0; /* user typed it — lowest prior      */
    return 0;
}

/* Human-readable reason string for the channel boost (NULL when delta==0). */
static const char *
channel_reason(const char *ch)
{
    if (!ch) return NULL;
    if (strcmp(ch, "qr")    == 0)
        return "Channel (qr): +20 \xe2\x80\x94 QR codes mask destinations (quishing)";
    if (strcmp(ch, "sms")   == 0)
        return "Channel (sms): +15 \xe2\x80\x94 SMS is the primary smishing "
               "vector; on RCS the displayed sender name is set by the sender, "
               "so a familiar brand or carrier label is NOT proof of identity";
    if (strcmp(ch, "email") == 0)
        return "Channel (email): +10 \xe2\x80\x94 email is the primary phishing vector";
    if (strcmp(ch, "dm")    == 0)
        return "Channel (dm): +10 \xe2\x80\x94 direct messages are used for social-engineering";
    return NULL; /* manual → no delta, no noise */
}

/* ── Baseline / allowlist (Perspective 107, roadmap P0-1) ──────────────────
 * Commercial secret scanners (detect-secrets, gitleaks) need a way to accept
 * known findings so a brownfield repo's first scan does not fail the CI gate
 * forever. HLSE implements this as a pure post-detection output filter — no
 * detection logic touched, F1 unchanged:
 *   1. `hlse_core --fingerprints scan .` emits one stable fingerprint per
 *      finding; redirect to a file to create a baseline.
 *   2. `hlse_core --baseline <file> scan .` suppresses every finding whose
 *      fingerprint is listed; only NEW findings count toward the gate.
 *   3. an inline `hlse:allow` token on a scanned line suppresses findings on
 *      that line (gitleaks:allow-style).
 * The fingerprint is a 64-bit FNV-1a hash of relpath\0pattern_id\0match,
 * rendered as 16 hex chars. It deliberately OMITS the line number so a
 * finding that moves lines stays suppressed. */
static const char *g_baseline_file = NULL;   /* --baseline <file> */
static int         g_emit_fingerprints = 0;  /* --fingerprints */
static char      **g_baseline_fps = NULL;    /* loaded fingerprint set */
static size_t      g_baseline_n = 0;
static int         g_git_history = 0;        /* --git-history (P0-2) */

/* Write a stable 16-hex-char fingerprint of (relpath, pattern_id, match) into
 * out[17]. NUL-separated so distinct field boundaries can't alias. */
static void
hlse_fingerprint(const char *relpath, const char *pattern_id,
                 const char *match, char out[17]) {
    unsigned long long h = 1469598103934665603ULL; /* FNV-1a 64 offset basis */
    const char *parts[3];
    int p;
    parts[0] = relpath ? relpath : "";
    parts[1] = pattern_id ? pattern_id : "";
    parts[2] = match ? match : "";
    for (p = 0; p < 3; p++) {
        const unsigned char *s = (const unsigned char *)parts[p];
        while (*s) { h ^= (unsigned long long)*s++; h *= 1099511628211ULL; }
        h *= 1099511628211ULL; /* absorb the NUL field separator */
    }
    snprintf(out, 17, "%016llx", h);
}

/* Return 1 if fp is in the loaded baseline set (linear scan; baselines are
 * modest and this runs once per finding). */
static int
hlse_baseline_has(const char *fp) {
    size_t i;
    for (i = 0; i < g_baseline_n; i++)
        if (strcmp(g_baseline_fps[i], fp) == 0) return 1;
    return 0;
}

/* Load fingerprints from the baseline file (one per line; '#' comments and
 * blank lines ignored; surrounding whitespace trimmed). Returns 0 on success,
 * -1 if the file cannot be opened. */
static int
hlse_baseline_load(const char *path) {
    FILE *fp = fopen(path, "r");
    char line[128];
    if (!fp) return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *s = line, *t;
        size_t n;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0') continue;
        /* Keep only the first whitespace-delimited token: the --fingerprints
         * output is "<fp>  <pattern_id>  <relpath>" for human readability, but
         * the lookup key is just the 16-hex fingerprint. Truncate at the first
         * space/tab so the readable columns are ignored on load. */
        for (t = s; *t && *t != ' ' && *t != '\t' && *t != '\n' && *t != '\r'; t++)
            ;
        *t = '\0';
        n = strlen(s);
        if (n == 0) continue;
        {
            char **grown = realloc(g_baseline_fps,
                                   (g_baseline_n + 1) * sizeof(char *));
            char *dup;
            if (!grown) break;
            g_baseline_fps = grown;
            dup = malloc(n + 1);
            if (!dup) break;
            memcpy(dup, s, n + 1);
            g_baseline_fps[g_baseline_n++] = dup;
        }
    }
    fclose(fp);
    return 0;
}

/* Free every fingerprint string owned by the loaded baseline set and the
 * backing array itself, then reset g_baseline_n/g_baseline_fps to their
 * pre-load state so a subsequent hlse_baseline_load() call starts clean.
 * Safe when no baseline was ever loaded, and idempotent. Named to match the
 * hlse_clear_custom_secret_patterns()/hlse_clear_custom_brands() convention. */
static void
hlse_baseline_clear(void) {
    size_t i;
    for (i = 0; i < g_baseline_n; i++)
        free(g_baseline_fps[i]);
    free(g_baseline_fps);
    g_baseline_fps = NULL;
    g_baseline_n = 0;
}

/* Return 1 if a scanned line carries an inline `hlse:allow` suppression. */
static int
hlse_line_allowed(const char *line) {
    return line && strstr(line, "hlse:allow") != NULL;
}

/* ── Custom pattern config file (Perspective 110/112, roadmap P0-3/P1-6) ───
 * The built-in credential patterns and brand list are compiled in and
 * cannot name an organization's internal token formats or protect its own
 * name/executives without a rebuild — a real commercial-adoption blocker.
 * `--patterns <file>` loads a small, non-regex config format and registers
 * each entry via hlse_register_custom_secret_pattern() /
 * hlse_register_custom_brand() (hlse_secrets.c), which hlse_scan_secrets()
 * and hlse_check_email_headers() then check using the exact same logic as
 * their built-in tables. Purely additive — the benchmark corpus never
 * passes --patterns, so F1 is unaffected.
 *
 * File format (one directive per line; '#' comments and blank lines ignored):
 *   SECRET <prefix> <min_suffix> <charset> <score> <label...>
 *   BRAND  <name> <owned_domain1>[,<owned_domain2>...]
 * charset is one of: alnum | alnum_dash | hex | alpha | digit
 * SECRET's label is free text (may contain spaces) to end of line.
 * BRAND's owned-domains list has no spaces (comma-separated, up to 4).
 *
 * Example:
 *   # ACME Corp internal API keys and impersonation targets
 *   SECRET ACME_KEY_ 20 alnum 85 ACME Internal API Key
 *   BRAND acmecorp acmecorp.com,acme-corp.com
 */
static int
patterns_charset_from_name(const char *name, HlseCharset *out) {
    if (strcmp(name, "alnum")      == 0) { *out = HLSE_CHARSET_ALNUM;      return 1; }
    if (strcmp(name, "alnum_dash") == 0) { *out = HLSE_CHARSET_ALNUM_DASH; return 1; }
    if (strcmp(name, "hex")        == 0) { *out = HLSE_CHARSET_HEX;        return 1; }
    if (strcmp(name, "alpha")      == 0) { *out = HLSE_CHARSET_ALPHA;      return 1; }
    if (strcmp(name, "digit")      == 0) { *out = HLSE_CHARSET_DIGIT;      return 1; }
    return 0;
}

static int
patterns_load_secret_line(const char *path, int lineno, const char *rest) {
    char prefix[32], charset_name[16], label[256];
    int min_suffix = 0, score = 0, consumed = 0;
    HlseCharset cs;
    if (sscanf(rest, "%31s %d %15s %d %n", prefix, &min_suffix,
               charset_name, &score, &consumed) != 4) {
        fprintf(stderr, "hlse: warning: %s:%d: malformed SECRET line, "
                "skipped\n", path, lineno);
        return 0;
    }
    if (!patterns_charset_from_name(charset_name, &cs)) {
        fprintf(stderr, "hlse: warning: %s:%d: unknown charset '%s' "
                "(expected alnum|alnum_dash|hex|alpha|digit), skipped\n",
                path, lineno, charset_name);
        return 0;
    }
    {
        const char *lp = rest + consumed;
        size_t n;
        while (*lp == ' ' || *lp == '\t') lp++;
        snprintf(label, sizeof(label), "%s", lp);
        n = strlen(label);
        while (n > 0 && (label[n-1] == '\n' || label[n-1] == '\r'))
            label[--n] = '\0';
        if (n == 0) {
            fprintf(stderr, "hlse: warning: %s:%d: missing label, skipped\n",
                    path, lineno);
            return 0;
        }
    }
    if (!hlse_register_custom_secret_pattern(prefix, min_suffix, cs,
                                              label, score)) {
        fprintf(stderr, "hlse: warning: %s:%d: pattern rejected (bad field "
                "or registry full), skipped\n", path, lineno);
        return 0;
    }
    return 1;
}

/* Parse a BRAND line's remainder as "<name> <domains>", where <domains> is
 * the LAST whitespace-delimited token (comma-separated, no internal
 * spaces by construction) and <name> is everything before it. Splitting
 * from the end (not sscanf's %s, which stops at the first space) lets
 * <name> itself contain spaces — real organization names commonly do
 * ("Acme Corp", not "AcmeCorp"), matching how the built-in brand table
 * already handles multi-word entries like "office 365" / "human resources"
 * via contains_word()'s literal substring match. */
static int
patterns_load_brand_line(const char *path, int lineno, const char *rest) {
    char name[64], domains[512];
    char buf[600];
    size_t len;
    const char *end, *split, *name_end, *name_start;
    size_t domlen, namelen;

    snprintf(buf, sizeof(buf), "%s", rest);
    len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' ||
                       buf[len-1] == ' '  || buf[len-1] == '\t'))
        buf[--len] = '\0';
    end = buf + len;

    split = end;
    while (split > buf && split[-1] != ' ' && split[-1] != '\t') split--;
    if (split == buf || split == end) {
        fprintf(stderr, "hlse: warning: %s:%d: malformed BRAND line "
                "(expected: BRAND <name> <domain1>[,<domain2>...]), "
                "skipped\n", path, lineno);
        return 0;
    }
    domlen = (size_t)(end - split);
    if (domlen >= sizeof(domains)) domlen = sizeof(domains) - 1;
    memcpy(domains, split, domlen);
    domains[domlen] = '\0';

    name_end = split;
    while (name_end > buf && (name_end[-1] == ' ' || name_end[-1] == '\t'))
        name_end--;
    name_start = buf;
    while (name_start < name_end && (*name_start == ' ' || *name_start == '\t'))
        name_start++;
    namelen = (size_t)(name_end - name_start);
    if (namelen == 0 || namelen >= sizeof(name)) {
        fprintf(stderr, "hlse: warning: %s:%d: malformed BRAND line "
                "(expected: BRAND <name> <domain1>[,<domain2>...]), "
                "skipped\n", path, lineno);
        return 0;
    }
    memcpy(name, name_start, namelen);
    name[namelen] = '\0';

    if (!hlse_register_custom_brand(name, domains)) {
        fprintf(stderr, "hlse: warning: %s:%d: brand rejected (bad field "
                "or registry full), skipped\n", path, lineno);
        return 0;
    }
    return 1;
}

/* Load and register custom patterns/brands from `path`. Returns 0 on
 * success (even if individual malformed lines were skipped with a warning),
 * -1 if the file cannot be opened. */
static int
hlse_patterns_load(const char *path) {
    FILE *fp = fopen(path, "r");
    char line[512];
    int lineno = 0, loaded = 0;
    if (!fp) return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *s = line;
        char directive[16];
        int consumed = 0;
        lineno++;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0') continue;
        if (sscanf(s, "%15s %n", directive, &consumed) != 1) {
            fprintf(stderr, "hlse: warning: %s:%d: malformed line, skipped\n",
                    path, lineno);
            continue;
        }
        if (strcmp(directive, "SECRET") == 0) {
            loaded += patterns_load_secret_line(path, lineno, s + consumed);
        } else if (strcmp(directive, "BRAND") == 0) {
            loaded += patterns_load_brand_line(path, lineno, s + consumed);
        } else {
            fprintf(stderr, "hlse: warning: %s:%d: unknown directive '%s' "
                    "(expected SECRET or BRAND), skipped\n",
                    path, lineno, directive);
        }
    }
    fclose(fp);
    if (loaded == 0) {
        fprintf(stderr, "hlse: warning: %s: no valid SECRET/BRAND entries "
                "loaded\n", path);
    }
    return 0;
}

/* Central suppression check for a scan finding, shared by all three checks
 * (file/secret/url). Computes the fingerprint; if --fingerprints is set,
 * prints it and returns 2 (caller skips all counting AND emission). Returns 1
 * to suppress (baseline hit or inline allow), 0 to emit normally. `line` may
 * be NULL for whole-file findings that have no inline-allow context. */
static int
hlse_scan_suppress(const char *relpath, const char *pattern_id,
                   const char *match, const char *line) {
    char fp[17];
    hlse_fingerprint(relpath, pattern_id, match, fp);
    if (g_emit_fingerprints) {
        printf("%s  %s  %s\n", fp, pattern_id ? pattern_id : "-",
               relpath ? relpath : "-");
        return 2;
    }
    if (hlse_baseline_has(fp)) return 1;
    if (hlse_line_allowed(line)) return 1;
    return 0;
}

/* ── Manifest scanning (Perspective 108, roadmap P1-8) ─────────────────────
 * The single-name `package <name>` check is impractical for real dependency
 * files. `package --manifest <file>` parses a manifest and runs the existing
 * hlse_check_package() over every declared dependency. Ecosystem is inferred
 * from the filename or given explicitly. Pure orchestration of the existing
 * detector — no scoring change, F1 unchanged. */

/* Infer package ecosystem from a manifest filename (basename match). Returns
 * a canonical eco string or NULL if unrecognised. */
static const char *
manifest_ecosystem(const char *path) {
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    if (strncmp(b, "requirements", 12) == 0 || strcmp(b, "Pipfile") == 0)
        return "pip";
    if (strcmp(b, "package.json") == 0 ||
        strcmp(b, "package-lock.json") == 0) return "npm";
    if (strcmp(b, "Cargo.toml") == 0 || strcmp(b, "Cargo.lock") == 0)
        return "cargo";
    if (strcmp(b, "go.mod") == 0) return "go";
    if (strcmp(b, "Gemfile") == 0 || strcmp(b, "Gemfile.lock") == 0)
        return "gem";
    return NULL;
}

/* Extract the leading pip/requirements-style package name from a line into
 * out (name = leading run of [A-Za-z0-9._-], stopping at a version operator
 * or extras bracket). Returns 1 if a name was found, else 0. Skips blank
 * lines, comments, and pip options (-r/-e/--). */
static int
manifest_name_pip(const char *line, char *out, size_t outcap) {
    const char *s = line;
    size_t n = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '\0' || *s == '\n' || *s == '#' || *s == '-') return 0;
    while (*s && n + 1 < outcap &&
           ((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') ||
            (*s >= '0' && *s <= '9') || *s == '.' || *s == '_' || *s == '-'))
        out[n++] = *s++;
    out[n] = '\0';
    return n > 0;
}

/* Extract the next npm dependency name at/after *cursor, tracking whether we
 * are inside a *dependencies object via *in_deps. Handles both the canonical
 * one-dep-per-line layout and the compact single-line object form, and can be
 * called repeatedly on the same line: it advances *cursor past what it
 * consumed. A dependency entry is  "name" : "version"  inside a dependencies
 * object. Returns 1 and fills out when a name is extracted, 0 when the current
 * text is exhausted. */
static int
manifest_name_npm(const char **cursor, int *in_deps, char *out, size_t outcap) {
    const char *p = *cursor;
    for (;;) {
        if (!*in_deps) {
            /* Look for a dependencies-section keyword on this text. */
            const char *k = NULL, *cands[4]; int ci, best = -1;
            cands[0] = strstr(p, "\"dependencies\"");
            cands[1] = strstr(p, "\"devDependencies\"");
            cands[2] = strstr(p, "\"peerDependencies\"");
            cands[3] = strstr(p, "\"optionalDependencies\"");
            for (ci = 0; ci < 4; ci++)
                if (cands[ci] && (best < 0 || cands[ci] < cands[best])) best = ci;
            if (best < 0) { *cursor = p + strlen(p); return 0; }
            k = strchr(cands[best], '{');
            if (!k) { *cursor = p + strlen(p); return 0; }
            *in_deps = 1;
            p = k + 1;
            continue;
        }
        /* In a deps object: the next '}' closes it; the next '"' before it
         * starts a "name": "ver" entry. */
        {
            const char *close = strchr(p, '}');
            const char *q = strchr(p, '"');
            size_t n = 0;
            const char *r;
            if (!q || (close && close < q)) {
                if (close) { *in_deps = 0; p = close + 1; continue; }
                *cursor = p + strlen(p); return 0;
            }
            r = q + 1;
            while (*r && *r != '"' && n + 1 < outcap) out[n++] = *r++;
            out[n] = '\0';
            if (*r != '"') { *cursor = p + strlen(p); return 0; }
            r++;                                  /* past closing quote */
            while (*r == ' ' || *r == '\t') r++;
            if (*r != ':') { p = r; continue; }   /* not a key — keep scanning */
            *cursor = r + 1;
            if (n > 0) return 1;
        }
    }
}

/* Per-finding remediation hint for HIGH/CRIT audit findings.
 * Returns a short command or action string, or NULL if no specific fix
 * is available for this finding. Keyed to the A-code prefix + keywords. */
static const char *
audit_remediation_for(const char *desc)
{
    if (!desc) return NULL;
    /* A1: SSH configuration */
    if (strncmp(desc, "A1:", 3) == 0) {
        if (strstr(desc, "PermitRootLogin yes"))
            return "sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "PasswordAuthentication yes"))
            return "sudo sed -i 's/PasswordAuthentication yes/"
                   "PasswordAuthentication no/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "Protocol 1"))
            return "sudo sed -i 's/^Protocol 1/Protocol 2/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "PermitEmptyPasswords"))
            return "sudo sed -i 's/PermitEmptyPasswords yes/"
                   "PermitEmptyPasswords no/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "authorized_keys"))
            return "chmod 600 ~/.ssh/authorized_keys";
        return "sudo nano /etc/ssh/sshd_config  # correct the flagged setting,"
               " then: sudo systemctl reload ssh";
    }
    /* A2: File permission issues */
    if (strncmp(desc, "A2:", 3) == 0) {
        if (strstr(desc, "id_rsa") || strstr(desc, "id_ed25519")
            || strstr(desc, "id_ecdsa"))
            return "chmod 600 ~/.ssh/id_rsa  # (or id_ed25519 / id_ecdsa)";
        if (strstr(desc, ".aws/credentials"))
            return "chmod 600 ~/.aws/credentials";
        if (strstr(desc, ".env"))
            return "chmod 600 ~/.env";
        if (strstr(desc, ".netrc"))
            return "chmod 600 ~/.netrc";
        if (strstr(desc, ".pgpass"))
            return "chmod 600 ~/.pgpass";
        if (strstr(desc, ".docker/config.json"))
            return "chmod 600 ~/.docker/config.json";
        if (strstr(desc, ".kube/config"))
            return "chmod 600 ~/.kube/config";
        if (strstr(desc, "gnupg") || strstr(desc, "GPG"))
            return "chmod 700 ~/.gnupg && chmod 600 ~/.gnupg/secring.gpg";
        return "chmod go-rwx <file>  # remove group/other read permission"
               " from the flagged file";
    }
    /* A3: DNS / hosts file poisoning */
    if (strncmp(desc, "A3:", 3) == 0) {
        if (strstr(desc, "/etc/hosts"))
            return "sudo diff /etc/hosts /etc/hosts.bak 2>/dev/null ||"
                   " sudo cp /etc/hosts /etc/hosts.bak;"
                   " review /etc/hosts for unexpected entries";
        return "review the flagged DNS resolver or hosts file entry";
    }
    /* A4: Cron persistence */
    if (strncmp(desc, "A4:", 3) == 0)
        return "crontab -l  # review; then: crontab -e to remove"
               " the suspicious entry";
    /* A5: Insecure PATH */
    if (strncmp(desc, "A5:", 3) == 0)
        return "remove '.' and any world-writable directories from PATH"
               " in ~/.bashrc or ~/.profile; then: source ~/.bashrc";
    /* A6: Shell startup backdoor */
    if (strncmp(desc, "A6:", 3) == 0)
        return "nano ~/.bashrc  # (or ~/.profile / ~/.bash_profile)"
               " — remove the flagged line, then: source ~/.bashrc";
    /* A7: Sudoers NOPASSWD */
    if (strncmp(desc, "A7:", 3) == 0)
        return "sudo visudo  # change 'NOPASSWD: ALL' to 'ALL'"
               " to require a password for sudo";
    /* A8: Systemd user unit persistence */
    if (strncmp(desc, "A8:", 3) == 0)
        return "systemctl --user disable <unit> &&"
               " systemctl --user stop <unit>;"
               " then: rm ~/.config/systemd/user/<unit>.service";
    return NULL;
}

/* Map a credential type label to what access it grants the attacker.
 *
 * Socratic question (Perspective 99): "'Stripe Live Publishable' matches the
 * strstr(type, \"Stripe\") branch below and is told it grants 'ability to
 * issue charges, view customer payment data, and issue refunds' — but a
 * publishable key (pk_live_) cannot do any of that by Stripe's own design;
 * only a SECRET key (sk_live_/rk_live_) can. Reachable whenever this finding
 * combines with another to cross the >=60 objective/remediation/triage
 * threshold (e.g. alongside a JWT), telling the user their exposed
 * publishable key just handed an attacker refund access — false, and exactly
 * the kind of over-claim that erodes trust in every other correct verdict."
 *
 * Exact-match this label BEFORE the generic Stripe substring check so a
 * publishable key gets the accurate (and much calmer) objective instead of
 * inheriting the secret-key narrative.                                     */
static const char *
secret_objective_for(const char *type)
{
    if (!type || !type[0]) return NULL;
    if (strcmp(type, "Stripe Live Publishable") == 0)
        return "none directly \xe2\x80\x94 publishable keys are designed to be "
               "embedded in public client-side code and cannot create charges, "
               "issue refunds, or read customer payment data; only a paired "
               "SECRET key (sk_live_/rk_live_) grants that access";
    if (strstr(type, "AWS"))
        return "cloud API access \xe2\x80\x94 S3 read/write, EC2 control, and IAM "
               "privilege escalation; all resources visible to this key are at risk";
    if (strstr(type, "GitHub") || strstr(type, "GitLab"))
        return "source code and CI/CD pipeline access \xe2\x80\x94 read/write "
               "repositories, access CI secrets, trigger workflows";
    if (strstr(type, "Stripe"))
        return "payment processing \xe2\x80\x94 ability to issue charges, view "
               "customer payment data, and issue refunds";
    if (strstr(type, "Google") || strstr(type, "GCP"))
        return "Google Cloud API access \xe2\x80\x94 Maps, Analytics, or Cloud "
               "resources depending on key scope";
    if (strstr(type, "Slack"))
        return "workspace access \xe2\x80\x94 read messages and files across "
               "channels, post as the bot user or the token owner";
    if (strstr(type, "SSH") || strstr(type, "Private Key")
        || strstr(type, "RSA") || strstr(type, "OPENSSH"))
        return "server authentication \xe2\x80\x94 SSH access to every host that "
               "trusts this key (check authorized_keys)";
    if (strstr(type, "Database") || strstr(type, "Postgres")
        || strstr(type, "MySQL") || strstr(type, "Mongo"))
        return "database read/write access \xe2\x80\x94 plaintext query access "
               "to all records in the connected database";
    if (strstr(type, "Twilio") || strstr(type, "SendGrid")
        || strstr(type, "Mailgun"))
        return "messaging API access \xe2\x80\x94 send SMS/email as your account, "
               "read inbound messages, and incur billing charges";
    return "authenticated access to the associated service and any resource "
           "this credential controls";
}

/* Perspective 99: a factual correction for credential TYPES that are
 * public-by-design and therefore not "compromised" in the sense the rest of
 * the secret advisory assumes. Unlike hlse_exoneration_for() (a probabilistic
 * "might be a false positive" hedge for a score band), this is an
 * unconditional, type-specific fact: Stripe publishable keys are ALWAYS
 * meant to be public, at any score. Returns NULL for every other type. */
static const char *
secret_finding_caveat(const char *type) {
    if (!type) return NULL;
    if (strcmp(type, "Stripe Live Publishable") == 0)
        return "Stripe publishable keys (pk_live_/pk_test_) are designed to "
               "be public \xe2\x80\x94 embedded in checkout pages, mobile "
               "apps, and browser JavaScript by every Stripe integration. "
               "Stripe's own documentation confirms they cannot create "
               "charges, issue refunds, or read customer payment data. "
               "Rotation is not required for this key; if a paired SECRET "
               "key (sk_live_/rk_live_) was also exposed, that one needs "
               "immediate rotation instead.";
    return NULL;
}

/* Socratic question (Perspective 102): "The P101 audit found the file kind's
 * pattern/objective/verify text duplicated four ways and consolidated it —
 * does 'secret' have the exact same problem?" Answer: yes. The pattern label
 * ("exposed credential — %s"), verify, triage, and cascade_risk text were
 * each independently copy-pasted at the standalone `secret` JSON site and
 * the scan-embedded JSON site (identical strings, two names: sec_vrf/ss_vrf,
 * sec_tri/ss_tri, sec_cas/ss_cas), and ALSO reduced to shorter, differently-
 * worded printf literals at the two plaintext sites — so a `secret` verdict
 * read as JSON and the same verdict read as plaintext described the
 * independent verification step differently. Consolidated into shared
 * accessors, mirroring file_masquerade_objective()/file_masquerade_verify();
 * every one of the four sites and both output formats now say the same
 * thing. Pure refactor — no detection logic, score, or field value changed. */
static void
secret_pattern_label(const char *ftype, char *buf, size_t buflen) {
    snprintf(buf, buflen, "exposed credential \xe2\x80\x94 %s", ftype);
}

static const char *
secret_verify_text(void) {
    /* Deliberately avoids the phrase "blast radius" — `scan` has a distinct,
     * unrelated BLAST RADIUS warning for credentials found across multiple
     * asset classes (P102 caught the two colliding in scan's plaintext
     * output once JSON/plaintext text was unified). */
    return "check access logs for this credential BEFORE revoking "
           "\xe2\x80\x94 audit trails (AWS CloudTrail, GitHub audit "
           "log) reveal whether it was already used and exactly what "
           "was accessed";
}

static const char *
secret_triage_text(void) {
    return "revoke or rotate the credential immediately (do not "
           "delete \xe2\x80\x94 rotate to cut off access before the key is "
           "gone); purge from git history with git filter-repo or "
           "BFG Repo Cleaner \xe2\x80\x94 assume every clone already has it";
}

static const char *
secret_cascade_text(void) {
    return "every other credential in the same file, repository, "
           "or environment \xe2\x80\x94 treat everything co-located as "
           "potentially leaked; also rotate any secret that shared "
           "the same passphrase or was stored alongside this one";
}

/* Socratic question (Perspective 103): "P101/P102 found and fixed the same
 * JSON/plaintext duplication-and-drift for file and secret — do protect,
 * network, and package have it too?" Yes: each kind's JSON path built its
 * advisory lines from `static const char[]` literals, while the matching
 * plaintext path re-typed shorter, differently-worded printf literals for
 * the exact same verdict. Consolidated into shared accessors, one group per
 * kind, following the same naming convention as the file/secret ones above.
 * Pure refactor — every JSON value is unchanged; only the plaintext wording
 * is upgraded to match (previously-shortened) JSON text word-for-word. */
static const char *
protect_pattern_text(void) {
    return "ransomware / destructive malware indicators detected";
}

static const char *
protect_objective_text(void) {
    return "data destruction and extortion \xe2\x80\x94 ransomware encrypts "
           "accessible files and demands payment; credentials are "
           "often harvested before encryption begins";
}

static const char *
protect_verify_text(void) {
    return "photograph or copy the ransom note before any other "
           "action \xe2\x80\x94 it contains the attacker's ID, contact, "
           "and decryption instructions; consult NCSC/CISA or law "
           "enforcement BEFORE paying \xe2\x80\x94 free decryptors may exist";
}

static const char *
protect_triage_text(void) {
    return "IMMEDIATELY disconnect from the network (unplug Ethernet, "
           "disable WiFi and Bluetooth) \xe2\x80\x94 this stops lateral "
           "movement and stops encryption spreading to network shares; "
           "do NOT reboot \xe2\x80\x94 volatile memory may contain keys; "
           "preserve all logs and report to law enforcement";
}

static const char *
protect_cascade_text(void) {
    return "all credentials on this machine and any network shares "
           "it accessed \xe2\x80\x94 ransomware groups commonly harvest "
           "credentials before encrypting; rotate domain admin, file "
           "server, VPN, and cloud credentials from a clean device";
}

static const char *
net_pattern_text(void) {
    return "suspicious network activity (C2 / exfiltration indicator)";
}

static const char *
network_objective_text(void) {
    return "data exfiltration or persistent access \xe2\x80\x94 an active "
           "process may be beaconing to a command-and-control server, "
           "exfiltrating credentials, or establishing lateral movement";
}

static const char *
network_verify_text(void) {
    return "identify the process owning the suspicious connection: "
           "'lsof -i' or 'ss -tp' on Linux, 'netstat -b' on Windows; "
           "verify it against your known installed software before "
           "taking any disruptive action";
}

static const char *
network_triage_text(void) {
    return "if the process is unrecognised: kill it and isolate the "
           "host from the network; preserve network capture (tcpdump) "
           "and process memory before rebooting \xe2\x80\x94 evidence is lost "
           "on reboot; report to your security team or law enforcement";
}

static const char *
network_cascade_text(void) {
    return "credentials stored on this machine (browser, credential "
           "manager, SSH keys, cloud CLI tokens) \xe2\x80\x94 an active "
           "C2 connection may already be exfiltrating them; rotate all "
           "from a clean device before the machine is brought back online";
}

static const char *
package_pattern_text(void) {
    return "dependency confusion / typosquat supply-chain attack";
}

static const char *
package_objective_text(void) {
    return "arbitrary code execution \xe2\x80\x94 package install scripts "
           "run with your user privileges; any secret readable from "
           "your shell (API keys, tokens, SSH keys) is at risk";
}

static const char *
package_verify_text(void) {
    return "verify the exact package name on the official registry "
           "page before installing; if you must proceed, install "
           "with --ignore-scripts (npm/pnpm) or --no-build (uv/pip) "
           "so a malicious preinstall/postinstall/prepare hook "
           "cannot run \xe2\x80\x94 lifecycle scripts execute with your "
           "privileges before install even completes; most "
           "ecosystems also support --dry-run to preview first";
}

static const char *
package_triage_text(void) {
    return "if already installed, remove the package immediately "
           "(pip uninstall / npm uninstall / cargo remove) and "
           "inspect the lifecycle scripts (preinstall/postinstall/"
           "prepare); self-propagating worms (Shai-Hulud) run a "
           "disk-wide secret scan (TruffleHog), so rotate EVERY "
           "credential on the machine, not just shell-environment "
           "ones \xe2\x80\x94 if you publish packages, revoke your "
           "npm/PyPI token FIRST, before the worm can republish "
           "from your account";
}

static const char *
package_cascade_text(void) {
    return "if you maintain packages, your registry publish token is "
           "the worm's self-propagation vector \xe2\x80\x94 it "
           "republishes the payload into YOUR packages, infecting "
           "every downstream user; revoke the token and audit your "
           "published versions for unexpected releases, plus all "
           "disk-resident API keys, SSH keys, and cloud credentials "
           "a TruffleHog-style scan would harvest";
}

/* Perspective 104: esp and clipboard are BLOCK+-only (score is always 0 or
 * >=60/70 — no ALERT-band split needed, unlike file/secret/protect/network/
 * package), but they had the same JSON/plaintext duplication-and-drift the
 * P101-103 accessors fixed elsewhere. Consolidated here. */
static const char *
esp_pattern_text(void) {
    return "UEFI bootkit indicator in EFI System Partition";
}

static const char *
esp_objective_text(void) {
    return "persistent firmware-level access \xe2\x80\x94 a bootkit "
           "survives OS reinstall; it executes before the OS boots "
           "and can disable security software, log keystrokes, and "
           "intercept disk encryption before the OS sees it";
}

static const char *
esp_verify_text(void) {
    return "run a second scan with a different tool (CHIPSEC, "
           "vendor UEFI integrity check) before taking disruptive "
           "action \xe2\x80\x94 bootkit false positives exist and the "
           "remediation is destructive; check Secure Boot status "
           "first (mokutil --sb-state)";
}

static const char *
esp_triage_text(void) {
    return "do NOT reinstall the OS first \xe2\x80\x94 it will not "
           "remove a bootkit; consult an incident-response specialist; "
           "if confirmed, flash the UEFI firmware from a vendor-signed "
           "image and replace Secure Boot enrollment keys "
           "(mokutil --reset)";
}

static const char *
esp_cascade_text(void) {
    return "all credentials and disk encryption keys on this machine "
           "\xe2\x80\x94 a bootkit has pre-OS access to encrypted volumes "
           "and can log all keystrokes before encryption; rotate from "
           "a clean device and consider the machine untrusted until "
           "the firmware is re-flashed";
}

static const char *
clipboard_pattern_text(void) {
    return "cryptocurrency clipboard hijack (clipper malware)";
}

static const char *
clipboard_objective_text(void) {
    return "cryptocurrency theft \xe2\x80\x94 your copied address was "
           "silently replaced; funds sent reach the attacker's wallet "
           "and cannot be recovered";
}

static const char *
clipboard_verify_text(void) {
    return "re-copy the address from the recipient's own verified "
           "source and compare every character in your wallet app "
           "before confirming the transaction";
}

static const char *
clipboard_triage_text(void) {
    return "if you already sent funds: contact your exchange or "
           "wallet provider immediately \xe2\x80\x94 crypto transfers "
           "are irreversible; file a report with law enforcement "
           "and the exchange's fraud team";
}

static const char *
clipboard_cascade_text(void) {
    return "every crypto address you have copied since the last "
           "clean boot \xe2\x80\x94 clipper malware intercepts all "
           "clipboard activity; assume all recent copies were "
           "redirected and run a full malware scan before "
           "transacting again";
}

static void
print_json_url(const char *url, const Verdict *v) {
    char escaped_url[MAX_URL * 2];
    const char *pat  = hlse_classify_url_attack(v);
    const char *pid  = hlse_url_pattern_id(v);  /* stable HLSE-URL-* token */
    const char *vrf  = hlse_verification_for(v);
    const char *cas  = hlse_cascade_risk(v);
    const char *exon = hlse_url_exoneration(v); /* NULL outside [15,59] */
    char obj_buf[320] = "";
    char tri_buf[512] = "";
    char asc_diff_buf[256] = "";
    char cf_buf[160] = "";
    char esc_pat[256] = "";
    char esc_obj[320] = "";
    char esc_vrf[512] = "";
    char esc_tri[1024] = "";
    char esc_cas[512] = "";
    char esc_asc[384] = "";
    char esc_cf[320] = "";
    char esc_exon[512] = "";
    char safe[384]; /* compound "https://A and https://B" */
    char esc_safe[768] = "";
    char conf[160];
    char esc_conf[320] = "";
    char canon_brand[64];
    int  has_obj    = hlse_compound_objective(v, obj_buf, sizeof(obj_buf));
    int  has_safe   = hlse_safe_destinations(v, safe, sizeof(safe));
    int  has_conf   = hlse_confusable_report(url, conf, sizeof(conf));
    int  has_asc    = hlse_ascii_diff(v, asc_diff_buf, sizeof(asc_diff_buf));
    int  signal_cnt = hlse_confidence_for(v, cf_buf, sizeof(cf_buf));
    int  has_tri    = hlse_compound_triage(v, tri_buf, sizeof(tri_buf));
    int  has_canon  = (v->score == 0) &&
                      hlse_canonical_confirm(url, canon_brand, sizeof(canon_brand));
    json_escape(url, escaped_url, sizeof(escaped_url));
    if (pat)     json_escape(pat,          esc_pat,  sizeof(esc_pat));
    if (has_obj) json_escape(obj_buf,      esc_obj,  sizeof(esc_obj));
    if (vrf)     json_escape(vrf,          esc_vrf,  sizeof(esc_vrf));
    if (has_tri) json_escape(tri_buf,      esc_tri,  sizeof(esc_tri));
    if (cas)     json_escape(cas,          esc_cas,  sizeof(esc_cas));
    if (has_asc) json_escape(asc_diff_buf, esc_asc,  sizeof(esc_asc));
    if (signal_cnt > 0) json_escape(cf_buf, esc_cf,  sizeof(esc_cf));
    if (has_safe) json_escape(safe, esc_safe, sizeof(esc_safe));
    if (has_conf) json_escape(conf, esc_conf, sizeof(esc_conf));
    if (exon)    json_escape(exon, esc_exon, sizeof(esc_exon));
    printf("{\"kind\":\"url\",\"hlse_version\":\"" HLSE_VERSION "\","
           "\"target\":\"%s\",\"score\":%d,\"action\":\"%s\","
           "\"severity\":%d",
           escaped_url, v->score, action_for_score(v->score),
           hlse_severity_for_score(v->score));
    if (signal_cnt > 0) printf(",\"signal_count\":%d,\"confidence\":\"%s\"",
                               signal_cnt, esc_cf);
    if (has_canon)  printf(",\"canonical_brand\":\"%s\"", canon_brand);
    if (v->score == 0) {
        /* Use the narrower post-authentication caveat when the domain was
         * positively confirmed against the brand registry — the generic
         * "pixel-perfect clone" blind spot contradicts a canonical confirm. */
        const char *bs = hlse_blindspot_for(has_canon ? "url_canonical" : "url");
        if (bs) {
            char esc_bs[512];
            json_escape(bs, esc_bs, sizeof(esc_bs));
            printf(",\"blind_spot\":\"%s\"", esc_bs);
        }
    }
    if (pat)        printf(",\"pattern\":\"%s\"", esc_pat);
    if (pid)        printf(",\"pattern_id\":\"%s\"", pid); /* stable SIEM token */
    if (has_obj)    printf(",\"objective\":\"%s\"", esc_obj);
    if (has_conf)   printf(",\"confusable\":\"%s\"", esc_conf);
    if (has_asc)    printf(",\"ascii_diff\":\"%s\"", esc_asc);
    if (has_safe)   printf(",\"safe_url\":\"%s\"", esc_safe);
    if (vrf)        printf(",\"verify\":\"%s\"", esc_vrf);
    if (has_tri)    printf(",\"triage\":\"%s\"", esc_tri);
    if (cas)        printf(",\"cascade_risk\":\"%s\"", esc_cas);
    if (exon)       printf(",\"exoneration\":\"%s\"", esc_exon);
    if (g_from_channel) {
        int d   = channel_delta(g_from_channel);
        int eff = v->score + d; if (eff > 100) eff = 100;
        printf(",\"channel\":\"%s\",\"channel_delta\":%d,\"effective_score\":%d,"
               "\"effective_action\":\"%s\",\"effective_severity\":%d",
               g_from_channel, d, eff, action_for_score(eff),
               hlse_severity_for_score(eff));
        {
            const char *ch_rsn = channel_reason(g_from_channel);
            if (ch_rsn) {
                char esc_ch[512];
                json_escape(ch_rsn, esc_ch, sizeof(esc_ch));
                printf(",\"channel_reason\":\"%s\"", esc_ch);
            }
        }
    }
    printf(",\"reasons\":[");
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
    const char *pat  = hlse_classify_text_attack(v);
    const char *pid  = hlse_text_pattern_id(v);   /* stable HLSE-* token */
    const char *tobj = hlse_text_objective(v);    /* NULL outside score >= 60 */
    const char *tvrf = hlse_text_verify(v);       /* NULL outside score >= 40 (P95) */
    const char *ttri = hlse_text_triage(v);       /* NULL outside score >= 60 */
    const char *tcas = hlse_text_cascade(v);      /* NULL outside score >= 60 */
    const char *exon = hlse_text_exoneration(v);  /* NULL outside [15,59] */
    char cf_buf[160] = "";
    char esc_pat[256] = "";
    char esc_tobj[512] = "";
    char esc_tvrf[512] = "";
    char esc_ttri[640] = "";
    char esc_tcas[512] = "";
    char esc_exon[512] = "";
    char esc_cf[320] = "";
    int  sig_cnt = hlse_text_confidence(v, cf_buf, sizeof(cf_buf));
    /* Truncate long text for the JSON preview */
    {
        size_t n = strlen(text);
        if (n > 120) n = 120;
        memcpy(preview, text, n);
        preview[n] = '\0';
    }
    json_escape(preview, esc, sizeof(esc));
    if (pat)        json_escape(pat,    esc_pat,  sizeof(esc_pat));
    if (tobj)       json_escape(tobj,   esc_tobj, sizeof(esc_tobj));
    if (tvrf)       json_escape(tvrf,   esc_tvrf, sizeof(esc_tvrf));
    if (ttri)       json_escape(ttri,   esc_ttri, sizeof(esc_ttri));
    if (tcas)       json_escape(tcas,   esc_tcas, sizeof(esc_tcas));
    if (exon)       json_escape(exon,   esc_exon, sizeof(esc_exon));
    if (sig_cnt > 0) json_escape(cf_buf, esc_cf,  sizeof(esc_cf));
    printf("{\"kind\":\"text\",\"hlse_version\":\"" HLSE_VERSION "\","
           "\"target\":\"%s\",\"score\":%d,\"action\":\"%s\","
           "\"severity\":%d",
           esc, v->score, hlse_text_action_for_score(v->score),
           hlse_severity_for_score(v->score));
    if (sig_cnt > 0) printf(",\"signal_count\":%d,\"confidence\":\"%s\"",
                            sig_cnt, esc_cf);
    if (v->score == 0) {
        const char *bs = hlse_blindspot_for("text");
        if (bs) {
            char esc_bs[512];
            json_escape(bs, esc_bs, sizeof(esc_bs));
            printf(",\"blind_spot\":\"%s\"", esc_bs);
        }
    }
    if (pat)  printf(",\"pattern\":\"%s\"",     esc_pat);
    if (pid)  printf(",\"pattern_id\":\"%s\"", pid);   /* stable SIEM token */
    if (tobj) printf(",\"objective\":\"%s\"",   esc_tobj);
    if (tvrf) printf(",\"verify\":\"%s\"",      esc_tvrf);
    if (ttri) printf(",\"triage\":\"%s\"",      esc_ttri);
    if (tcas) printf(",\"cascade_risk\":\"%s\"",esc_tcas);
    if (exon) printf(",\"exoneration\":\"%s\"", esc_exon);
    if (g_from_channel) {
        int d   = channel_delta(g_from_channel);
        int eff = v->score + d; if (eff > 100) eff = 100;
        printf(",\"channel\":\"%s\",\"channel_delta\":%d,\"effective_score\":%d,"
               "\"effective_action\":\"%s\",\"effective_severity\":%d",
               g_from_channel, d, eff, hlse_text_action_for_score(eff),
               hlse_severity_for_score(eff));
        {
            const char *ch_rsn = channel_reason(g_from_channel);
            if (ch_rsn) {
                char esc_ch[512];
                json_escape(ch_rsn, esc_ch, sizeof(esc_ch));
                printf(",\"channel_reason\":\"%s\"", esc_ch);
            }
        }
    }
    printf(",\"reasons\":[");
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

/* Print the per-URL human-readable advisory lines for an actionable verdict —
 * the synthesis lenses layered on top of the raw per-signal reasons:
 *   ▸ Pattern             attack-class label
 *   ⌖ Disguised char      first non-ASCII confusable codepoint
 *   ◉ Attacker's goal     objective / asset at risk
 *   → Safe destination    canonical brand domain to use instead
 *   ✓ Verify independently  high-confidence (>=60) confirmation test
 *   ⚑ If already clicked  post-click incident triage
 *   ⊕ Also change         password-reuse cascade risk (other accounts)
 *
 * Centralised so the three text output sites (stdin / `text` subcommand /
 * default auto-detect) cannot drift out of sync — every lens fires from one
 * place. `url` is the raw input (needed for confusable/host inspection); `uv`
 * is its URL verdict. Each line is conditional, so a low-score verdict prints
 * only the lenses that apply.                                                */
static void
print_url_advisories(const char *url, const Verdict *uv) {
    const char *pat = hlse_classify_url_attack(uv);
    const char *vrf = hlse_verification_for(uv);
    const char *cas = hlse_cascade_risk(uv);
    char obj_buf[320];
    char safe[384]; /* 384: compound "https://A and https://B" fits in 2*128+8 */
    char conf[160];
    char asc_diff[256];
    char cf_buf[160];
    char tri_buf[512]; /* 512: compound two-step triage */
    if (pat) printf("  \xe2\x96\xb8 Pattern: %s\n", pat);
    if (hlse_confidence_for(uv, cf_buf, sizeof(cf_buf)))
        printf("  \xe2\x9a\x96 Confidence: %s\n", cf_buf);  /* ⚖ */
    if (hlse_confusable_report(url, conf, sizeof(conf)))
        printf("  \xe2\x8c\x96 Disguised char: %s\n", conf);
    if (hlse_ascii_diff(uv, asc_diff, sizeof(asc_diff)))
        printf("  \xe2\x8c\x96 ASCII lookalike: %s\n", asc_diff);
    if (hlse_compound_objective(uv, obj_buf, sizeof(obj_buf)))
        printf("  \xe2\x97\x89 Attacker's goal: %s\n", obj_buf);
    if (hlse_safe_destinations(uv, safe, sizeof(safe)))
        printf("  \xe2\x86\x92 Safe destination: %s\n", safe);
    if (vrf) printf("  \xe2\x9c\x93 Verify independently: %s\n", vrf);
    if (hlse_compound_triage(uv, tri_buf, sizeof(tri_buf)))
        printf("  \xe2\x9a\x91 If already clicked: %s\n", tri_buf);
    if (cas) printf("  \xe2\x8a\x95 Also change: %s\n", cas);  /* ⊕ */
}

/* Print the per-text human-readable advisory lines for an actionable text
 * verdict — the text counterpart of print_url_advisories(). Layers the same
 * synthesis lenses on top of the raw per-signal reasons:
 *   ▸ Pattern           social-engineering attack-class label
 *   ◉ Attacker's goal   asset at risk (score >= 60)
 *   ✓ Verify first      pre-action verification check (score >= 60)
 *   ⚖ Confidence        how many independent signal families concur
 *   ⚑ If you acted      post-response triage (score >= 60)
 *   ⊕ Also change       cascade risk — other accounts at stake (score >= 60)
 *
 * Centralised so the three text output sites (stdin / `text` subcommand /
 * default auto-detect) cannot drift out of sync — exactly the guarantee
 * print_url_advisories() gives the URL path. Like its URL sibling, this does
 * NOT print the "↺ Could be benign" exoneration or the "· <channel>" line:
 * those depend on caller-local state (channel reason) and are emitted by each
 * caller after this returns. Each line is conditional, so a low-score verdict
 * prints only the lenses that apply.                                         */
static void
print_text_advisories(const TextVerdict *tv) {
    const char *tpat = hlse_classify_text_attack(tv);
    const char *tobj = hlse_text_objective(tv);
    const char *tvrf = hlse_text_verify(tv);
    const char *ttri = hlse_text_triage(tv);
    const char *tcas = hlse_text_cascade(tv);
    char tcf[160];
    if (tpat) printf("  \xe2\x96\xb8 Pattern: %s\n", tpat);
    if (tobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", tobj);
    if (tvrf) printf("  \xe2\x9c\x93 Verify first: %s\n", tvrf);
    if (hlse_text_confidence(tv, tcf, sizeof(tcf)))
        printf("  \xe2\x9a\x96 Confidence: %s\n", tcf);
    if (ttri) printf("  \xe2\x9a\x91 If you acted: %s\n", ttri);
    if (tcas) printf("  \xe2\x8a\x95 Also change: %s\n", tcas);
}

/* Score at/above which the process exits 1 (threat). Configurable via
 * --fail-on so a pipeline picks its own risk gate. Default = BLOCK(60). */
static int g_fail_threshold = 60;

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
            /* Channel-only risk: content scored 0 but delivery channel adds prior */
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                if (d > 0) {
                    const char *ch_rsn = channel_reason(g_from_channel);
                    printf("%-7s [%d]  %s\n", hlse_action_for_score(d), d, line);
                    if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                    continue;
                }
            }
            {
                char canon_brand[64];
                printf("OK    %s\n", line);
                if (sr.is_url && hlse_canonical_confirm(line, canon_brand, sizeof(canon_brand)))
                    printf("  \xe2\x9c\x94 Canonical: confirmed authentic %s domain "
                           "(HLSE brand registry)\n", canon_brand);
            }
        } else {
            int i;
            int eff = sr.score;
            const char *ch_rsn = NULL;
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                eff += d; if (eff > 100) eff = 100;
                ch_rsn = channel_reason(g_from_channel);
            }
            printf("%-7s [%d]  %s\n",
                   hlse_action_for_score(eff), eff, line);
            for (i = 0; i < sr.n_reasons; i++) {
                /* Amplifier lines are derived meta-labels, not independently
                 * detected facts; the ▸ Pattern line already expresses them
                 * in user-facing language. Keep them in JSON; filter here. */
                if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                printf("  \xc2\xb7 %s\n", sr.reasons[i]);  /* · */
            }
            if (sr.is_url) {
                Verdict uv = check_url(line);
                const char *url_ex = hlse_url_exoneration(&uv);
                print_url_advisories(line, &uv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (url_ex) printf("  \xe2\x86\xba Could be benign: %s\n", url_ex);
            } else {
                TextVerdict tv;
                const char *tex;
                int ti;
                memset(&tv, 0, sizeof(tv));
                tv.score = sr.score;
                tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                               ? sr.n_reasons
                               : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                for (ti = 0; ti < tv.n_reasons; ti++)
                    snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                             "%s", sr.reasons[ti]);
                tex  = hlse_text_exoneration(&tv);
                print_text_advisories(&tv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (tex) printf("  \xe2\x86\xba Could be benign: %s\n", tex);
            }
        }
        /* Gate uses effective score (raw + channel boost) so that e.g.
         * --from sms raises exit 0 → exit 1 when boost crosses the threshold. */
        {
            int eff_gate = sr.score;
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                eff_gate += d; if (eff_gate > 100) eff_gate = 100;
            }
            if (eff_gate >= g_fail_threshold) any_threat = 1;
        }
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
        "  %s scan <dir> --git-history  Scan every commit ever made, not just the working tree\n"
        "  %s secret \"<text>\"          Scan text/stdin for leaked credentials\n"
        "  %s email \"<headers>\"        Email-header forensics (SPF/DKIM, BEC)\n"
        "  %s clipboard <copied> <pasted>  Crypto address-swap (clipper) check\n"
        "  %s package <name> [eco]     Package typosquat check\n"
        "  %s package --manifest <f>   Scan every dep in requirements.txt / package.json\n"
        "  %s paste \"<command>\"        Pastejacking detection\n"
        "  %s network                  ARP / DNS / hosts safety check\n"
        "  %s file <path>              File masquerade detection\n"
        "  %s audit                    System hardening audit\n"
        "\n"
        "Options:\n"
        "  %s --json <subcommand>      JSON output\n"
        "  %s --sarif scan <dir>       SARIF 2.1.0 output (GitHub code scanning)\n"
        "  %s -q | --quiet             Exit code only (CI/CD mode)\n"
        "  %s --fail-on <tier>         Exit-1 gate: log|alert|block|isolate|0-100 (default block)\n"
        "  %s --from <channel>         Delivery channel: email|sms|dm|qr|manual (boosts URL & text score)\n"
        "  %s --baseline <file>        scan: suppress findings whose fingerprint is listed (CI adoption)\n"
        "  %s --fingerprints scan <d>  scan: emit one fingerprint per finding (generate a baseline)\n"
        "  %s --patterns <file>        Load custom org-specific secret patterns (no rebuild needed)\n"
        "  %s --syslog                 Push findings to syslog (LOG_AUTHPRIV)\n"
        "  %s --log-file <file>        Append one JSONL record per finding (0600)\n"
        "  %s --stdin [--json]         Pipe mode (one input per line)\n"
        "  %s --self-test              Built-in tests\n"
        "  %s --benchmark              Corpus benchmark\n"
        "  %s --list-patterns [--json] List stable pattern_id tokens (SIEM/SOAR registry)\n"
        "  %s --version | -V           Version\n"
        "  %s -h | --help              Show this help\n"
        "\n"
        "Baseline workflow (brownfield CI adoption):\n"
        "  %s --fingerprints scan . > .hlse-baseline   # accept today's findings\n"
        "  %s --baseline .hlse-baseline scan .          # only NEW findings fail\n"
        "  Inline suppression: put `hlse:allow` on a line to skip its findings.\n"
        "\n"
        "Custom patterns (%s --patterns <file>), one directive per line:\n"
        "  SECRET <prefix> <min_suffix> <charset> <score> <label...>\n"
        "    charset is alnum|alnum_dash|hex|alpha|digit.\n"
        "    Example: SECRET ACME_KEY_ 20 alnum 85 ACME Internal API Key\n"
        "  BRAND <name> <owned_domain1>[,<owned_domain2>...]\n"
        "    Protects your org's name/executives in email BEC display-name checks.\n"
        "    Example: BRAND acmecorp acmecorp.com,acme-corp.com\n"
        "\n"
        "Exit code: 0 = safe, 1 = threat (>= --fail-on, default block/60), 2 = usage error\n",
        HLSE_VERSION,
        prog, prog, prog,                                /* scanning: 3 */
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, /* protection: 14 */
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, /* options: 16 */
        prog, prog, prog); /* baseline workflow: 2 + custom patterns: 1 */
}

/* Read all of stdin into buf (NUL-terminated, truncated to cap-1 bytes).
 *
 * Perspective 105 (P1-2): the previous version truncated silently at cap-1,
 * so a secret past the buffer end read as "clean" (exit 0) — a false
 * negative demonstrated through the shipped pre-commit hook. Now: if input
 * exceeds the buffer, drain the rest of stdin so a pipe writer does not
 * block on a full pipe, and print a clear warning to stderr naming how many
 * bytes were dropped so the caller knows the result is not authoritative.
 * The buffers were also enlarged to 1 MiB (see the --stdin call sites),
 * matching the shipped hook's own 1 MB file-size guard, so the demonstrated
 * gap is closed outright and the warning is a backstop for larger inputs. */
static size_t
read_stdin_all(char *buf, size_t cap) {
    size_t total = 0, r;
    if (cap == 0) return 0;
    while (total < cap - 1 &&
           (r = fread(buf + total, 1, cap - 1 - total, stdin)) > 0)
        total += r;
    buf[total] = '\0';
    if (total == cap - 1) {
        /* Buffer filled exactly — there may be more input we cannot hold.
         * Drain and count the overflow so the warning is precise, and so a
         * writer piping into us does not block on a full pipe. */
        size_t dropped = 0;
        char sink[8192];
        while ((r = fread(sink, 1, sizeof(sink), stdin)) > 0) dropped += r;
        if (dropped > 0) {
            fprintf(stderr,
                    "hlse: warning: stdin exceeded %zu-byte buffer; %zu byte(s) "
                    "dropped \xe2\x80\x94 scan of the truncated tail was skipped, "
                    "so a clean result is NOT authoritative for the full input\n",
                    cap - 1, dropped);
        }
    }
    return total;
}

/* ── Git history scanning (Perspective 111, roadmap P0-2) ──────────────────
 * `scan <dir> --git-history` finds secrets ANYWHERE in the repo's commit
 * history, not just the current working tree — the primary use case for
 * commercial secret scanners (gitleaks/trufflehog): a credential that was
 * committed and later deleted is still readable by anyone who clones the
 * repo, and a working-tree-only scan never sees it.
 *
 * Implementation: stream `git log --all -p` (every commit, unified diff,
 * every ref) and scan only ADDED lines ('+' lines, excluding the '+++'
 * file-header marker) — the lines that introduced a secret at the moment it
 * entered history. This needs one git subprocess for the whole history
 * (not one per blob), keeping it fast even on repos with thousands of
 * commits.
 *
 * Spawned via fork()+execlp(), never popen()/system(): the directory path
 * is passed as a discrete argv element to git, so it is never interpreted
 * by a shell and no combination of characters in `dir` can inject a command.
 * `git log` performs no network I/O (only fetch/pull/clone do), so this
 * preserves HLSE's zero-network-calls guarantee — verified by the existing
 * CI privacy tripwire, which traces socket-family syscalls, not process
 * spawns. */
static FILE *
git_history_open(const char *dir, pid_t *out_pid) {
    int pipefd[2];
    pid_t pid;
    if (pipe(pipefd) != 0) return NULL;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }
    if (pid == 0) {
        /* Child: redirect stdout to the pipe, stderr to /dev/null (git
         * prints progress/warnings we don't want mixed into our stream). */
        int devnull;
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execlp("git", "git", "-C", dir, "log", "--all", "-p", "--no-color",
               "--full-history", (char *)NULL);
        _exit(127); /* execlp failed — git not installed / not found in PATH */
    }
    close(pipefd[1]);
    *out_pid = pid;
    return fdopen(pipefd[0], "r");
}

/* Scan every commit in `root`'s history for secrets. Returns the process
 * exit code (0 = clean, 1 = threat, 2 = usage/environment error). */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
static int
scan_git_history(const char *root, int json_out, int sarif_out) {
    FILE *gp;
    pid_t pid;
    char line[8192];
    char commit[41] = "";
    char curpath[4096] = "";
    int commits_seen = 0, threats = 0, gate_hits = 0, max_score = 0;
    unsigned asset_mask = 0;
    int child_status;

    gp = git_history_open(root, &pid);
    if (!gp) {
        fprintf(stderr, "Error: cannot start 'git log' for '%s': %s\n",
                root, strerror(errno));
        return 2;
    }

    while (fgets(line, sizeof(line), gp)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';

        if (strncmp(line, "commit ", 7) == 0) {
            snprintf(commit, sizeof(commit), "%.40s", line + 7);
            commits_seen++;
            continue;
        }
        if (strncmp(line, "+++ ", 4) == 0) {
            const char *p = line + 4;
            if (strncmp(p, "b/", 2) == 0) p += 2;
            if (strcmp(p, "/dev/null") != 0) {
                /* Explicit bounded copy (not snprintf(dst, sizeof(dst), "%s",
                 * p)) — `p` derives from `line` (larger than `curpath`), and
                 * -Wformat-truncation cannot see that silent truncation here
                 * is harmless (curpath is a display label, not a real path
                 * used for I/O), so make the bound explicit instead of
                 * suppressing the warning. */
                size_t plen = strlen(p);
                if (plen >= sizeof(curpath)) plen = sizeof(curpath) - 1;
                memcpy(curpath, p, plen);
                curpath[plen] = '\0';
            } else {
                curpath[0] = '\0'; /* file was deleted in this commit */
            }
            continue;
        }
        /* An added line: starts with '+' but is not the "+++ " file header
         * and is not the empty "+" (context-only artifact). */
        if (line[0] == '+' && strncmp(line, "+++", 3) != 0 && n > 1) {
            const char *content = line + 1;
            SecretVerdict sv = hlse_scan_secrets(content);
            if (sv.score >= 40) {
                const char *spid = sv.n_findings > 0
                    ? secret_pattern_id(sv.findings[0].type)
                    : "HLSE-SECRET-GENERIC";
                const char *sdesc = sv.n_findings > 0
                    ? sv.findings[0].description : "";
                char loc[4200];
                snprintf(loc, sizeof(loc), "%s@%.7s",
                         curpath[0] ? curpath : "(unknown path)", commit);
                /* Baseline/allowlist suppression reuses the same fingerprint
                 * mechanism as the working-tree scan (P0-1); the "line" for
                 * inline hlse:allow purposes is this diff line itself. */
                if (hlse_scan_suppress(loc, spid, sdesc, content))
                    continue;
                threats++;
                if (sv.score > max_score) max_score = sv.score;
                if (sv.score >= g_fail_threshold) gate_hits++;
                {
                    int ai;
                    for (ai = 0; ai < sv.n_findings; ai++)
                        asset_mask |= asset_class_of(sv.findings[ai].type);
                }
                if (sarif_out) {
                    char msg[512] = {0};
                    int i;
                    for (i = 0; i < sv.n_findings; i++) {
                        size_t l = strlen(msg);
                        snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                 i ? "; " : "", sv.findings[i].description);
                    }
                    snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg),
                             " (commit %.7s)", commit);
                    sarif_add(curpath[0] ? curpath : "(unknown path)", 1,
                              "secret", spid, msg[0] ? msg : "secret", sv.score);
                } else if (json_out) {
                    int i;
                    char ep[4096], ed[512];
                    json_escape(curpath, ep, sizeof(ep));
                    printf("{\"kind\":\"secret\",\"hlse_version\":\"" HLSE_VERSION
                           "\",\"path\":\"%s\",\"commit\":\"%s\",\"score\":%d,"
                           "\"action\":\"%s\",\"severity\":%d,\"findings\":[",
                           ep, commit, sv.score, hlse_action_for_score(sv.score),
                           hlse_severity_for_score(sv.score));
                    for (i = 0; i < sv.n_findings; i++) {
                        json_escape(sv.findings[i].description, ed, sizeof(ed));
                        printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                               i ? "," : "", sv.findings[i].type, ed);
                    }
                    printf("],\"pattern_id\":\"%s\"}\n", spid);
                } else {
                    int i;
                    printf("%-7s [%d]  %s@%.7s\n",
                           hlse_action_for_score(sv.score), sv.score,
                           curpath[0] ? curpath : "(unknown path)", commit);
                    for (i = 0; i < sv.n_findings; i++)
                        printf("  \xc2\xb7 %s\n", sv.findings[i].description);
                }
            }
        }
    }
    fclose(gp);
    /* Reap the child and distinguish real failure from a clean scan. A
     * non-zero exit with zero commits seen means `git log` itself failed
     * (not a repo, corrupt repo, etc.) — report it as a usage error rather
     * than silently printing "OK, 0 commits scanned", which would read as
     * "scanned and clean" instead of "did not scan anything at all". */
    if (waitpid(pid, &child_status, 0) == pid &&
        WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0) {
        int code = WEXITSTATUS(child_status);
        if (code == 127) {
            fprintf(stderr, "Error: 'git' not found in PATH \xe2\x80\x94 "
                    "--git-history requires the git binary\n");
        } else if (commits_seen == 0) {
            fprintf(stderr, "Error: '%s' is not a git repository (git log "
                    "exited %d) \xe2\x80\x94 --git-history requires a git "
                    "repository\n", root, code);
        } else {
            /* git produced partial output before failing; still report what
             * was found, but note the scan may be incomplete. */
            fprintf(stderr, "hlse: warning: 'git log' exited %d after %d "
                    "commit(s) \xe2\x80\x94 history scan may be incomplete\n",
                    code, commits_seen);
        }
        if (commits_seen == 0) return 2;
    }

    if (sarif_out) {
        sarif_emit(HLSE_VERSION);
    } else if (json_out) {
        char ep[4096], classes[256];
        int nclasses = asset_mask_describe(asset_mask, classes, sizeof(classes));
        json_escape(root, ep, sizeof(ep));
        printf("{\"kind\":\"scan_summary\",\"hlse_version\":\"" HLSE_VERSION "\","
               "\"target\":\"%s\",\"mode\":\"git-history\","
               "\"commits_scanned\":%d,\"threats\":%d,"
               "\"max_severity\":%d,\"gate_hits\":%d,\"fail_threshold\":%d,"
               "\"asset_classes\":%d,\"blast_radius\":\"%s\"}\n",
               ep, commits_seen, threats, hlse_severity_for_score(max_score),
               gate_hits, g_fail_threshold, nclasses, classes);
    } else if (threats == 0) {
        printf("OK    %s (%d commits scanned, 0 secrets found in history)\n",
               root, commits_seen);
    } else {
        printf("\n%d secret(s) found across %d commits in %s history\n",
               threats, commits_seen, root);
        printf("\xe2\x86\x92 Immediate action: rotate every credential found above "
               "\xe2\x80\x94 they are readable in every existing clone regardless "
               "of the current working tree, and deleting the file does not "
               "remove them from history (use git filter-repo or BFG)\n");
    }
    return gate_hits > 0 ? 1 : 0;
}
#pragma GCC diagnostic pop

int
main(int argc, char **argv) {
    int json_out = 0;
    int quiet = 0;
    int sarif_out = 0;
    int opt_syslog = 0;
    const char *opt_log_file = NULL;
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
     * supported by the `scan` and `package --manifest` subcommands. */
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

    /* Parse --fail-on <tier> (anywhere) — the machine consumer's risk gate.
     * The exit code (1 = threat) collapses five severity tiers into pass/fail;
     * hardcoding the boundary at BLOCK(60) imposes one risk posture on every
     * pipeline. A payments repo may want to fail at ALERT(40); a noisy docs
     * repo only at ISOLATE(80). This sets the score at/above which the process
     * exits 1. Default stays 60 (block) for backward compatibility.        */
    {
        int i;
        for (i = 1; i < argc - 1; i++) {
            if (strcmp(argv[i], "--fail-on") == 0) {
                const char *t = argv[i + 1];
                if      (strcmp(t, "log")     == 0) g_fail_threshold = 15;
                else if (strcmp(t, "alert")   == 0) g_fail_threshold = 40;
                else if (strcmp(t, "block")   == 0) g_fail_threshold = 60;
                else if (strcmp(t, "isolate") == 0) g_fail_threshold = 80;
                else {
                    /* Accept a bare numeric threshold (0..100) too. */
                    char *end;
                    long n = strtol(t, &end, 10);
                    if (*end == '\0' && n >= 0 && n <= 100)
                        g_fail_threshold = (int)n;
                    else {
                        fprintf(stderr, "Error: --fail-on expects "
                                "log|alert|block|isolate or 0..100\n");
                        return 2;
                    }
                }
                { int j; for (j = i; j < argc - 2; j++) argv[j] = argv[j+2];
                  argc -= 2; }
                break;
            }
        }
    }

    /* Parse --from <channel> — delivery-channel prior for URL risk boost.
     * Socratic: the same URL in an unsolicited SMS is riskier than one typed
     * by hand.  The flag lets callers supply that context so the verdict
     * reflects real-world threat priors, not just URL structure alone.     */
    {
        int i;
        for (i = 1; i < argc - 1; i++) {
            if (strcmp(argv[i], "--from") == 0) {
                const char *ch = argv[i + 1];
                if (strcmp(ch, "email")  == 0 || strcmp(ch, "sms") == 0 ||
                    strcmp(ch, "dm")     == 0 || strcmp(ch, "qr")  == 0 ||
                    strcmp(ch, "manual") == 0) {
                    g_from_channel = ch;
                } else {
                    fprintf(stderr,
                            "Error: --from expects email|sms|dm|qr|manual\n");
                    return 2;
                }
                { int j; for (j = i; j < argc - 2; j++) argv[j] = argv[j+2];
                  argc -= 2; }
                break;
            }
        }
    }

    /* Parse --baseline <file> (Perspective 107 / P0-1) — suppress findings
     * whose fingerprint is listed, so a brownfield repo's accepted findings
     * do not fail the CI gate forever. */
    {
        int i;
        for (i = 1; i < argc - 1; i++) {
            if (strcmp(argv[i], "--baseline") == 0) {
                g_baseline_file = argv[i + 1];
                { int j; for (j = i; j < argc - 2; j++) argv[j] = argv[j+2];
                  argc -= 2; }
                break;
            }
        }
    }

    /* Parse --syslog (boolean) — push findings to syslog(LOG_AUTHPRIV). */
    {
        int i;
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--syslog") == 0) {
                opt_syslog = 1;
                { int j; for (j = i; j < argc - 1; j++) argv[j] = argv[j+1];
                  argc--; }
                break;
            }
        }
    }

    /* Parse --log-file <path> (value) — append one JSONL record per finding. */
    {
        int i;
        for (i = 1; i < argc - 1; i++) {
            if (strcmp(argv[i], "--log-file") == 0) {
                opt_log_file = argv[i + 1];
                { int j; for (j = i; j < argc - 2; j++) argv[j] = argv[j+2];
                  argc -= 2; }
                break;
            }
        }
    }

    /* Parse --fingerprints (Perspective 107 / P0-1) — emit one stable
     * fingerprint per finding instead of the verdict; redirect to a file to
     * generate a baseline. */
    {
        int i;
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--fingerprints") == 0) {
                g_emit_fingerprints = 1;
                { int j; for (j = i; j < argc - 1; j++) argv[j] = argv[j+1];
                  argc--; }
                break;
            }
        }
    }

    /* Parse --git-history (Perspective 111, roadmap P0-2) — `scan <dir>
     * --git-history` scans every commit ever made to the repo for secrets,
     * not just the current working tree. */
    {
        int i;
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--git-history") == 0) {
                g_git_history = 1;
                { int j; for (j = i; j < argc - 1; j++) argv[j] = argv[j+1];
                  argc--; }
                break;
            }
        }
    }

    /* Parse --patterns <file> (Perspective 110 / P0-3) — register custom
     * organization-specific secret patterns without a rebuild. */
    {
        int i;
        for (i = 1; i < argc - 1; i++) {
            if (strcmp(argv[i], "--patterns") == 0) {
                const char *ppath = argv[i + 1];
                if (hlse_patterns_load(ppath) != 0) {
                    fprintf(stderr, "Error: cannot read --patterns file '%s': %s\n",
                            ppath, strerror(errno));
                    return 2;
                }
                { int j; for (j = i; j < argc - 2; j++) argv[j] = argv[j+2];
                  argc -= 2; }
                break;
            }
        }
    }

    /* Load the baseline file now that flags are parsed. A missing/unreadable
     * baseline is a usage error — silently ignoring it would let the gate
     * pass on a typo'd path, defeating the purpose. */
    if (g_baseline_file && hlse_baseline_load(g_baseline_file) != 0) {
        fprintf(stderr, "Error: cannot read --baseline file '%s': %s\n",
                g_baseline_file, strerror(errno));
        return 2;
    }
    /* Register cleanup once — covers every one of main()'s many return paths
     * uniformly (atexit failure just reverts to pre-fix behavior: a no-op). */
    if (g_baseline_file) atexit(hlse_baseline_clear);

    /* Open alert sinks now that flags are parsed. A requested but unopenable
     * --log-file is a usage error (same convention as --baseline/--patterns). */
    if ((opt_syslog || opt_log_file) &&
        hlse_alert_init(opt_syslog, opt_log_file) != 0) {
        fprintf(stderr, "Error: cannot open --log-file '%s': %s\n",
                opt_log_file ? opt_log_file : "(syslog only)", strerror(errno));
        return 2;
    }
    if (opt_syslog || opt_log_file) atexit(hlse_alert_shutdown);

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
        return 0;
    }
    if (strcmp(argv[idx], "--self-test") == 0) {
        int rc1 = self_test();
        int rc2 = text_self_test();
        return rc1 || rc2 ? 1 : 0;
    }
    if (strcmp(argv[idx], "--list-patterns") == 0) {
        return list_patterns(json_out);
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
            fprintf(stderr, "Usage: %s scan <directory> [--git-history]\n",
                    argv[0]);
            return 2;
        }
        /* --git-history (Perspective 111 / P0-2): scan every commit in the
         * repo's history for secrets, not just the working tree. Entirely
         * different algorithm (git subprocess stream vs. directory walk),
         * so it branches out before the normal walker below. */
        if (g_git_history) {
            return scan_git_history(argv[idx + 1], json_out, sarif_out);
        }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        {
            const char *root = argv[idx + 1];
            int threats = 0, files_scanned = 0, max_depth = 20;
            int gate_hits = 0;  /* findings at/above g_fail_threshold (exit gate) */
            int max_score = 0;  /* highest score seen — for max_severity in summary */
            unsigned asset_mask = 0;  /* blast-radius: classes seen across scan */
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
                    /* Skip only the '.' and '..' entries — NOT all dotfiles.
                     * A blanket dot-skip would silently ignore .env, .npmrc,
                     * .pypirc, .git-credentials, .aws/credentials … which are
                     * the single highest-value secret-bearing files. Dot-named
                     * directories (.git, .svn) are filtered by SKIP_DIRS below. */
                    if (ent->d_name[0] == '.' &&
                        (ent->d_name[1] == '\0' ||
                         (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
                        continue;

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
                            /* VCS metadata dirs — large, binary, no secrets to
                             * surface; previously skipped by the blanket dot
                             * filter, now skipped explicitly.                  */
                            ".git", ".svn", ".hg",
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
                        /* P0-1: baseline/allowlist suppression. Whole-file
                         * finding — no inline-allow line context. */
                        int sup = hlse_scan_suppress(sarif_path,
                                      file_verdict_pattern_id(&fv), NULL, NULL);
                        if (sup) goto after_file_check;
                        threats++;
                        if (fv.score > max_score) max_score = fv.score;
                        if (fv.score >= g_fail_threshold) gate_hits++;
                        if (sarif_out) {
                            char msg[512] = {0};
                            int i;
                            for (i = 0; i < fv.n_reasons; i++) {
                                size_t l = strlen(msg);
                                snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                         i ? "; " : "", fv.reasons[i]);
                            }
                            sarif_add(sarif_path, 1, "file-masquerade",
                                      file_verdict_pattern_id(&fv),
                                      msg[0] ? msg : "file masquerade", fv.score);
                        } else if (json_out) {
                            int i;
                            char esc[512];
                            json_escape(fullpath, esc, sizeof(esc));
                            printf("{\"kind\":\"file\",\"hlse_version\":\"" HLSE_VERSION "\","
                                   "\"path\":\"%s\","
                                   "\"score\":%d,\"action\":\"%s\","
                                   "\"severity\":%d,\"reasons\":[",
                                   esc, fv.score, hlse_action_for_score(fv.score),
                                   hlse_severity_for_score(fv.score));
                            for (i = 0; i < fv.n_reasons; i++) {
                                json_escape(fv.reasons[i], esc, sizeof(esc));
                                printf("%s\"%s\"", i ? "," : "", esc);
                            }
                            printf("]");
                            if (fv.score >= 40) {
                                /* Perspective 98: matches the standalone
                                 * `file` JSON path — pattern/objective/verify
                                 * fire from the ALERT floor (40); triage/
                                 * cascade_risk stay BLOCK+-only (60).
                                 * Perspective 101: classification and the two
                                 * advisory lines now come from the shared
                                 * file_classify_pattern()/file_masquerade_*()
                                 * accessors instead of an inline copy. */
                                const char *fpat = file_classify_pattern(&fv);
                                json_escape(fpat, esc, sizeof(esc)); printf(",\"pattern\":\"%s\"",      esc);
                                printf(",\"pattern_id\":\"%s\"", file_pattern_id(fpat));
                                json_escape(file_masquerade_objective(), esc, sizeof(esc)); printf(",\"objective\":\"%s\"", esc);
                                json_escape(file_masquerade_verify(),    esc, sizeof(esc)); printf(",\"verify\":\"%s\"",    esc);
                            }
                            if (fv.score >= 60) {
                                static const char sf_tri[] =
                                    "if already opened: disconnect from the network "
                                    "immediately; run a full antivirus scan; change "
                                    "credentials for any service you were logged into at "
                                    "the time; consider a full OS reinstall for high-score "
                                    "detections";
                                static const char sf_cas[] =
                                    "all credentials and session tokens active when the file "
                                    "was opened \xe2\x80\x94 malware runs with your session "
                                    "context; also check for persistence (startup items, "
                                    "scheduled tasks, browser extensions added)";
                                json_escape(sf_tri, esc, sizeof(esc)); printf(",\"triage\":\"%s\"",       esc);
                                json_escape(sf_cas, esc, sizeof(esc)); printf(",\"cascade_risk\":\"%s\"", esc);
                            }
                            if (fv.score > 0 && fv.score < 60) {
                                const char *ex = hlse_exoneration_for("file", fv.score);
                                if (ex) {
                                    json_escape(ex, esc, sizeof(esc));
                                    printf(",\"exoneration\":\"%s\"", esc);
                                }
                            }
                            printf("}\n");
                        } else {
                            int i;
                            printf("%-7s [%d]  %s\n",
                                   hlse_action_for_score(fv.score),
                                   fv.score, fullpath);
                            for (i = 0; i < fv.n_reasons; i++)
                                printf("  \xc2\xb7 %s\n", fv.reasons[i]);
                            if (fv.score >= 40) {
                                /* Perspective 101: shared with the JSON path
                                 * above (and both standalone `file` sites)
                                 * so plaintext and JSON never again describe
                                 * the same verdict with different wording. */
                                printf("  \xe2\x96\xb8 Pattern: %s\n", file_classify_pattern(&fv));
                                printf("  \xe2\x97\x89 Attacker's goal: %s\n", file_masquerade_objective());
                                printf("  \xe2\x9c\x93 Verify first: %s\n", file_masquerade_verify());
                            }
                            if (fv.score >= 60) {
                                printf("  \xe2\x9a\x91 If you acted: if already opened, disconnect "
                                       "from the network; run antivirus; change credentials for "
                                       "any active session\n");
                                printf("  \xe2\x8a\x95 Also change: all credentials and session "
                                       "tokens active when the file was opened \xe2\x80\x94 check "
                                       "for persistence (startup items, scheduled tasks, new "
                                       "browser extensions)\n");
                            }
                            if (fv.score > 0 && fv.score < 60) {
                                const char *ex = hlse_exoneration_for("file", fv.score);
                                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                            }
                        }
                    }
                    after_file_check: ;  /* P0-1 suppression jump target */

                    /* Check 2: secrets in text files. Large files are NOT
                     * skipped outright (a 2 MB log or DB dump routinely
                     * contains leaked credentials) — instead we scan up to a
                     * byte budget so work stays bounded on huge files.       */
                    if (st.st_size > 0) {
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
                            /* Bound the bytes inspected per file (8 MB) so a
                             * giant file cannot stall the scan, while still
                             * covering far more than the old 1 MB hard skip. */
                            size_t scanned_bytes = 0;
                            const size_t SCAN_BUDGET = 8u * 1024u * 1024u;
                            while (scanned_bytes < SCAN_BUDGET &&
                                   fgets(line, sizeof(line), fp)) {
                                lineno++;
                                scanned_bytes += strlen(line);
                                SecretVerdict sv = hlse_scan_secrets(line);
                                if (sv.score >= 40) {
                                    int ai;
                                    /* P0-1: baseline/allowlist + inline
                                     * hlse:allow suppression. Distinguisher =
                                     * the redacted finding description (stable
                                     * per distinct secret, line-independent). */
                                    const char *spid = sv.n_findings > 0
                                        ? secret_pattern_id(sv.findings[0].type)
                                        : "HLSE-SECRET-GENERIC";
                                    const char *sdesc = sv.n_findings > 0
                                        ? sv.findings[0].description : "";
                                    if (hlse_scan_suppress(sarif_path, spid, sdesc, line))
                                        continue;
                                    threats++;
                                    if (sv.score > max_score) max_score = sv.score;
                                    if (sv.score >= g_fail_threshold) gate_hits++;
                                    for (ai = 0; ai < sv.n_findings; ai++)
                                        asset_mask |=
                                            asset_class_of(sv.findings[ai].type);
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
                                                  sv.n_findings > 0
                                                    ? secret_pattern_id(sv.findings[0].type)
                                                    : "HLSE-SECRET-GENERIC",
                                                  msg[0] ? msg : "secret", sv.score);
                                    } else if (json_out) {
                                        int i;
                                        char esc_p[512], et[64], ed[512];
                                        json_escape(fullpath, esc_p, sizeof(esc_p));
                                        /* Emit findings:[{type,description}] per spec §5.2
                                         * (same schema as the standalone secret subcommand). */
                                        printf("{\"kind\":\"secret\","
                                               "\"hlse_version\":\"" HLSE_VERSION "\","
                                               "\"path\":\"%s\","
                                               "\"line\":%d,\"score\":%d,"
                                               "\"action\":\"%s\",\"severity\":%d,"
                                               "\"findings\":[",
                                               esc_p, lineno, sv.score,
                                               hlse_action_for_score(sv.score),
                                               hlse_severity_for_score(sv.score));
                                        for (i = 0; i < sv.n_findings; i++) {
                                            json_escape(sv.findings[i].type, et, sizeof(et));
                                            json_escape(sv.findings[i].description, ed, sizeof(ed));
                                            printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                                                   i ? "," : "", et, ed);
                                        }
                                        printf("]");
                                        {
                                            const char *conf = hlse_secret_confidence(&sv);
                                            if (conf) {
                                                json_escape(conf, ed, sizeof(ed));
                                                printf(",\"confidence\":\"%s\"", ed);
                                            }
                                        }
                                        {
                                            const char *rem = hlse_remediation_for("secret", sv.score);
                                            if (rem) {
                                                json_escape(rem, ed, sizeof(ed));
                                                printf(",\"remediation\":\"%s\"", ed);
                                            }
                                        }
                                        if (sv.n_findings > 0) {
                                            const char *cav = secret_finding_caveat(sv.findings[0].type);
                                            if (cav) {
                                                json_escape(cav, ed, sizeof(ed));
                                                printf(",\"caveat\":\"%s\"", ed);
                                            }
                                        }
                                        if (sv.score >= 60 && sv.n_findings > 0) {
                                            const char *ftype = sv.findings[0].type;
                                            const char *sobj  = secret_objective_for(ftype);
                                            secret_pattern_label(ftype, esc_p, sizeof(esc_p));
                                            json_escape(esc_p, ed, sizeof(ed));
                                            printf(",\"pattern\":\"%s\"", ed);
                                            printf(",\"pattern_id\":\"%s\"", secret_pattern_id(ftype));
                                            if (sobj) {
                                                json_escape(sobj, ed, sizeof(ed));
                                                printf(",\"objective\":\"%s\"", ed);
                                            }
                                            json_escape(secret_verify_text(),  ed, sizeof(ed)); printf(",\"verify\":\"%s\"",       ed);
                                            json_escape(secret_triage_text(),  ed, sizeof(ed)); printf(",\"triage\":\"%s\"",       ed);
                                            json_escape(secret_cascade_text(), ed, sizeof(ed)); printf(",\"cascade_risk\":\"%s\"", ed);
                                        }
                                        if (sv.score > 0 && sv.score < 60) {
                                            const char *ex = hlse_exoneration_for("secret", sv.score);
                                            if (ex) {
                                                json_escape(ex, ed, sizeof(ed));
                                                printf(",\"exoneration\":\"%s\"", ed);
                                            }
                                        }
                                        printf("}\n");
                                    } else {
                                        int i;
                                        printf("%-7s [%d]  %s:%d\n",
                                               hlse_action_for_score(sv.score),
                                               sv.score, fullpath, lineno);
                                        for (i = 0; i < sv.n_findings; i++)
                                            printf("  \xc2\xb7 %s\n",
                                                   sv.findings[i].description);
                                        if (sv.n_findings > 0) {
                                            const char *cav = secret_finding_caveat(sv.findings[0].type);
                                            if (cav) printf("  \xe2\x9a\xa0 Caveat: %s\n", cav);
                                        }
                                        if (sv.score >= 60 && sv.n_findings > 0) {
                                            const char *ftype = sv.findings[0].type;
                                            const char *sobj  = secret_objective_for(ftype);
                                            char epat[128];
                                            secret_pattern_label(ftype, epat, sizeof(epat));
                                            printf("  \xe2\x96\xb8 Pattern: %s\n", epat);
                                            if (sobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", sobj);
                                            printf("  \xe2\x9c\x93 Verify first: %s\n", secret_verify_text());
                                            printf("  \xe2\x9a\x91 Immediate action: %s\n", secret_triage_text());
                                            printf("  \xe2\x8a\x95 Also change: %s\n", secret_cascade_text());
                                        }
                                        if (sv.score > 0 && sv.score < 60) {
                                            const char *ex = hlse_exoneration_for("secret", sv.score);
                                            if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                                        }
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
                                                /* P0-1: baseline/allowlist +
                                                 * inline hlse:allow. Use the
                                                 * relative path + url as the
                                                 * distinguisher; on suppression
                                                 * fall through to p += ui. */
                                                if (hlse_scan_suppress(sarif_path,
                                                        hlse_url_pattern_id(&uv),
                                                        url_buf, line))
                                                    goto url_advance;
                                                threats++;
                                                if (uv.score > max_score) max_score = uv.score;
                                                if (uv.score >= g_fail_threshold)
                                                    gate_hits++;
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
                                                              "phishing-url",
                                                              hlse_url_pattern_id(&uv),
                                                              msg, uv.score);
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
                                                    printf("]");
                                                    {
                                                        char ucf_buf[160];
                                                        int u_sig = hlse_confidence_for(&uv, ucf_buf, sizeof(ucf_buf));
                                                        if (u_sig > 0) {
                                                            json_escape(ucf_buf, eu, sizeof(eu));
                                                            printf(",\"signal_count\":%d,\"confidence\":\"%s\"", u_sig, eu);
                                                        }
                                                    }
                                                    if (uv.score >= 40) {
                                                        /* Perspective 95: pattern/pattern_id/objective/safe_url/verify
                                                         * now fire from the ALERT floor (40), matching the standalone
                                                         * URL JSON path — an embedded URL scored ALERT used to emit
                                                         * only raw reasons + exoneration while the same URL scanned
                                                         * standalone got the full advisory. triage/cascade_risk stay
                                                         * BLOCK+-only (60): post-incident guidance presumes the user
                                                         * already acted, which only high confidence warrants. */
                                                        const char *upat = hlse_classify_url_attack(&uv);
                                                        const char *uvrf = hlse_verification_for(&uv);
                                                        char uobj_buf[320], usafe[384];
                                                        int has_obj  = hlse_compound_objective(&uv, uobj_buf, sizeof(uobj_buf));
                                                        int has_safe = hlse_safe_destinations(&uv, usafe, sizeof(usafe));
                                                        if (upat)     { json_escape(upat,     eu, sizeof(eu)); printf(",\"pattern\":\"%s\"",      eu); }
                                                        if (upat)     { const char *upid = hlse_url_pattern_id(&uv); if (upid) printf(",\"pattern_id\":\"%s\"", upid); }
                                                        if (has_obj)  { json_escape(uobj_buf, eu, sizeof(eu)); printf(",\"objective\":\"%s\"",    eu); }
                                                        if (has_safe) { json_escape(usafe,    eu, sizeof(eu)); printf(",\"safe_url\":\"%s\"",     eu); }
                                                        if (uvrf)     { json_escape(uvrf,     eu, sizeof(eu)); printf(",\"verify\":\"%s\"",       eu); }
                                                    }
                                                    if (uv.score >= 60) {
                                                        const char *ucas = hlse_cascade_risk(&uv);
                                                        char utri_buf[512];
                                                        int has_tri  = hlse_compound_triage(&uv, utri_buf, sizeof(utri_buf));
                                                        if (has_tri)  { json_escape(utri_buf, eu, sizeof(eu)); printf(",\"triage\":\"%s\"",       eu); }
                                                        if (ucas)     { json_escape(ucas,     eu, sizeof(eu)); printf(",\"cascade_risk\":\"%s\"", eu); }
                                                    }
                                                    if (uv.score >= 40 && uv.score < 60) {
                                                        const char *uexon = hlse_url_exoneration(&uv);
                                                        if (uexon) {
                                                            json_escape(uexon, eu, sizeof(eu));
                                                            printf(",\"exoneration\":\"%s\"", eu);
                                                        }
                                                    }
                                                    printf("}\n");
                                                } else {
                                                    int k;
                                                    printf("%-7s [%d]  %s:%d  %s\n",
                                                           hlse_action_for_score(uv.score),
                                                           uv.score, fullpath, lineno, url_buf);
                                                    for (k = 0; k < uv.n_reasons; k++)
                                                        printf("  \xc2\xb7 %s\n", uv.reasons[k]);
                                                    print_url_advisories(url_buf, &uv);
                                                    if (uv.score >= 40 && uv.score < 60) {
                                                        const char *uexon = hlse_url_exoneration(&uv);
                                                        if (uexon)
                                                            printf("  \xe2\x86\xba Could be benign: %s\n", uexon);
                                                    }
                                                }
                                            }
                                        }
                                        url_advance:            /* P0-1 target */
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

            /* --fingerprints mode emits only the per-finding fingerprint lines
             * (for baseline generation); skip the summary and never fail the
             * gate — generating a baseline must exit 0. */
            if (g_emit_fingerprints) {
                return 0;
            }
            if (sarif_out) {
                sarif_emit(HLSE_VERSION);
            } else if (!json_out) {
                if (threats == 0) {
                    const char *bs = hlse_blindspot_for("scan");
                    printf("OK    %s (%d files scanned, 0 threats)\n",
                           root, files_scanned);
                    if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
                } else {
                    char classes[256];
                    int nclasses = asset_mask_describe(asset_mask, classes,
                                                       sizeof(classes));
                    printf("\n%d threat(s) in %d files under %s\n",
                           threats, files_scanned, root);
                    if (gate_hits > 0 && g_fail_threshold != 60)
                        printf("  %d finding(s) exceeded the --fail-on threshold (%d)\n",
                               gate_hits, g_fail_threshold);
                    /* Immediate action: one-sentence triage keyed to the
                     * most severe asset class (or file/URL threats). */
                    printf("\xe2\x86\x92 Immediate action: %s\n",
                           scan_immediate_action((unsigned)asset_mask, nclasses));
                    /* Blast radius: credentials spanning 2+ asset classes let
                     * an attacker pivot across systems — worse than the count
                     * alone suggests. */
                    if (nclasses >= 2)
                        printf("\xe2\x9a\xa0  BLAST RADIUS: leaked credentials "
                               "span %d asset classes (%s) — an attacker can "
                               "pivot across these systems. Rotate ALL of them "
                               "and assume lateral movement.\n",
                               nclasses, classes);
                }
            } else {
                /* NDJSON: final summary line for CI tooling */
                char esc_root[4096], classes[256];
                int nclasses = asset_mask_describe(asset_mask, classes,
                                                   sizeof(classes));
                json_escape(root, esc_root, sizeof(esc_root));
                printf("{\"kind\":\"scan_summary\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"target\":\"%s\","
                       "\"files_scanned\":%d,\"threats\":%d,"
                       "\"max_severity\":%d,"
                       "\"gate_hits\":%d,\"fail_threshold\":%d,"
                       "\"asset_classes\":%d,\"blast_radius\":\"%s\"",
                       esc_root, files_scanned, threats,
                       hlse_severity_for_score(max_score),
                       gate_hits, g_fail_threshold,
                       nclasses, classes);
                if (threats == 0) {
                    const char *bs = hlse_blindspot_for("scan");
                    if (bs) {
                        char esc_bs[512];
                        json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                } else {
                    const char *ia = scan_immediate_action((unsigned)asset_mask, nclasses);
                    char esc_ia[512];
                    json_escape(ia, esc_ia, sizeof(esc_ia));
                    printf(",\"immediate_action\":\"%s\"", esc_ia);
                }
                printf("}\n");
            }
            return gate_hits > 0 ? 1 : 0;
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
            {
                const char *aar[16]; int aq, aqn = pv.n_reasons;
                if (aqn > 16) aqn = 16;
                for (aq = 0; aq < aqn; aq++) aar[aq] = pv.reasons[aq];
                hlse_alert_emit("protect", pv.score,
                    hlse_severity_for_score(pv.score), path, aar, aqn);
            }

            if (json_out) {
                /* JSON output for protect.
                 * Perspective 100: this was the only verdict kind still
                 * missing hlse_version and severity — every other kind
                 * (url/text/file/secret/email/network/esp/package/paste/
                 * clipboard) has carried both since P84/P85; protect was
                 * never brought in line. */
                char esc_path[4096];
                json_escape(path, esc_path, sizeof(esc_path));
                printf("{\"kind\":\"protect\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"target\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"severity\":%d,\"reasons\":[",
                       esc_path, pv.score,
                       hlse_action_for_score(pv.score),
                       hlse_severity_for_score(pv.score));
                {
                    int i;
                    for (i = 0; i < pv.n_reasons; i++) {
                        char esc[512];
                        json_escape(pv.reasons[i], esc, sizeof(esc));
                        printf("%s\"%s\"", i > 0 ? "," : "", esc);
                    }
                }
                printf("]");
                if (pv.score == 0) {
                    const char *bs = hlse_blindspot_for("protect");
                    if (bs) {
                        char esc_bs[512];
                        json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (pv.score > 0) {
                    int ns = pv.n_reasons;
                    const char *conf = ns >= 3 ? "high confidence" :
                                       ns >= 2 ? "corroborated" : "single signal";
                    printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
                }
                if (pv.score >= 40) {
                    /* Perspective 100: a single SMB canary-file access (+40)
                     * or mass-rename detection (+40) lands the protect
                     * verdict in ALERT (40-59) alone — the same gap P95-98
                     * closed for other kinds. pattern/objective/verify now
                     * fire from the ALERT floor; triage/cascade_risk
                     * (disconnect-network incident response) stay
                     * BLOCK+-only (>= 60).
                     * Perspective 103: text now shared with the plaintext
                     * path below via protect_*_text() accessors. */
                    char e[512];
                    json_escape(protect_pattern_text(), e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"HLSE-PROTECT-RANSOM\"");
                    json_escape(protect_objective_text(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                    json_escape(protect_verify_text(),    e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                }
                if (pv.score >= 60) {
                    char e[512];
                    json_escape(protect_triage_text(),  e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                    json_escape(protect_cascade_text(), e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("protect", pv.score);
                    if (ex) {
                        char e[512];
                        json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (pv.score == 0) {
                const char *bs = hlse_blindspot_for("protect");
                printf("OK    %s\n", path);
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(pv.score), pv.score, path);
                for (i = 0; i < pv.n_reasons; i++) {
                    printf("  \xc2\xb7 %s\n", pv.reasons[i]);
                }
                if (pv.score >= 40) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", protect_pattern_text());
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", protect_objective_text());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", protect_verify_text());
                }
                if (pv.score >= 60) {
                    printf("  \xe2\x9a\x91 Immediate action: %s\n", protect_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", protect_cascade_text());
                }
                if (pv.score < 60) {
                    const char *ex = hlse_exoneration_for("protect", pv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return pv.score >= g_fail_threshold ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "esp") == 0) {
        /* EFI System Partition integrity (UEFI bootkit indicators). */
        const char *path = (argc > idx + 1) ? argv[idx + 1] : NULL;
        ProtectionVerdict pv = hlse_esp_verify(path);
        if (json_out) {
            int i;
            printf("{\"kind\":\"esp\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"reasons\":[",
                   pv.score, hlse_action_for_score(pv.score),
                   hlse_severity_for_score(pv.score));
            for (i = 0; i < pv.n_reasons; i++) {
                char esc[512];
                json_escape(pv.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]");
            {
                const char *bs = hlse_blindspot_for("esp");
                if (pv.score == 0 && bs) {
                    char esc_bs[512];
                    json_escape(bs, esc_bs, sizeof(esc_bs));
                    printf(",\"blind_spot\":\"%s\"", esc_bs);
                }
            }
            if (pv.score > 0) {
                int ns = pv.n_reasons;
                const char *conf = ns >= 3 ? "high confidence" :
                                   ns >= 2 ? "corroborated" : "single signal";
                printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
            }
            if (pv.score >= 60) {
                char e[512];
                json_escape(esp_pattern_text(),   e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                printf(",\"pattern_id\":\"HLSE-ESP-BOOTKIT\"");
                json_escape(esp_objective_text(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                json_escape(esp_verify_text(),     e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                json_escape(esp_triage_text(),     e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                json_escape(esp_cascade_text(),    e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
            }
            if (pv.score > 0 && pv.score < 60) {
                const char *ex = hlse_exoneration_for("esp", pv.score);
                if (ex) {
                    char e[512];
                    json_escape(ex, e, sizeof(e));
                    printf(",\"exoneration\":\"%s\"", e);
                }
            }
            printf("}\n");
        } else if (pv.score == 0) {
            const char *bs = hlse_blindspot_for("esp");
            printf("OK    (esp)%s%s\n",
                   pv.n_reasons ? " \xe2\x80\x94 " : "",
                   pv.n_reasons ? pv.reasons[0] : "");
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            int i;
            printf("%-7s [%d]  (esp)\n",
                   hlse_action_for_score(pv.score), pv.score);
            for (i = 0; i < pv.n_reasons; i++)
                printf("  \xc2\xb7 %s\n", pv.reasons[i]);
            if (pv.score >= 60) {
                printf("  \xe2\x96\xb8 Pattern: %s\n", esp_pattern_text());
                printf("  \xe2\x97\x89 Attacker's goal: %s\n", esp_objective_text());
                printf("  \xe2\x9c\x93 Verify first: %s\n", esp_verify_text());
                printf("  \xe2\x9a\x91 Immediate action: %s\n", esp_triage_text());
                printf("  \xe2\x8a\x95 Also change: %s\n", esp_cascade_text());
            } else {
                const char *ex = hlse_exoneration_for("esp", pv.score);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        return pv.score >= g_fail_threshold ? 1 : 0;
    }

    /* ── Supply Chain Defense subcommands ───────────────────────────── */

    if (strcmp(argv[idx], "package") == 0) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s package <name> [pip|npm|cargo|go]\n"
                    "       %s package --manifest <file> [pip|npm|cargo|go|gem]\n",
                    argv[0], argv[0]);
            return 2;
        }
        /* --manifest <file>: scan every dependency in a manifest (P1-8). */
        if (strcmp(argv[idx + 1], "--manifest") == 0) {
            const char *mpath, *eco;
            FILE *mf;
            char line[4096];
            int in_deps = 0, checked = 0, threats = 0, gate_hits = 0;
            int max_score = 0, lineno = 0;
            if (argc < idx + 3) {
                fprintf(stderr, "Usage: %s package --manifest <file> [eco]\n",
                        argv[0]);
                return 2;
            }
            mpath = argv[idx + 2];
            eco = (argc > idx + 3) ? argv[idx + 3] : manifest_ecosystem(mpath);
            if (!eco) {
                fprintf(stderr, "Error: cannot infer ecosystem from '%s' \xe2\x80\x94 "
                        "pass one explicitly (pip|npm|cargo|go|gem)\n", mpath);
                return 2;
            }
            mf = fopen(mpath, "r");
            if (!mf) {
                fprintf(stderr, "Error: cannot read manifest '%s': %s\n",
                        mpath, strerror(errno));
                return 2;
            }
            while (fgets(line, sizeof(line), mf)) {
                char name[128];
                const char *cursor = line;
                int is_npm = (strcmp(eco, "npm") == 0);
                lineno++;
                /* npm: a line may hold several "name":"ver" pairs (compact
                 * object form), so drain the cursor. pip: one name per line. */
                for (;;) {
                    int got;
                    if (is_npm)
                        got = manifest_name_npm(&cursor, &in_deps, name, sizeof(name));
                    else
                        got = manifest_name_pip(line, name, sizeof(name));
                    if (!got || name[0] == '\0') break;
                {
                    PackageVerdict pv = hlse_check_package(name, eco);
                    checked++;
                    if (pv.score >= 40) {
                        threats++;
                        if (pv.score > max_score) max_score = pv.score;
                        if (pv.score >= g_fail_threshold) gate_hits++;
                        if (sarif_out) {
                            char msg[512];
                            snprintf(msg, sizeof(msg), "%s",
                                     pv.reason[0] ? pv.reason
                                     : "dependency typosquat");
                            sarif_add(mpath, lineno, "package-typosquat",
                                      "HLSE-PKG-TYPOSQUAT", msg, pv.score);
                        } else if (json_out) {
                            char en[128];
                            int i;
                            json_escape(name, en, sizeof(en));
                            printf("{\"kind\":\"package\",\"hlse_version\":\""
                                   HLSE_VERSION "\",\"name\":\"%s\","
                                   "\"ecosystem\":\"%s\",\"score\":%d,"
                                   "\"action\":\"%s\",\"severity\":%d,"
                                   "\"pattern_id\":\"HLSE-PKG-TYPOSQUAT\","
                                   "\"matches\":[",
                                   en, eco, pv.score,
                                   hlse_action_for_score(pv.score),
                                   hlse_severity_for_score(pv.score));
                            for (i = 0; i < pv.n_matches; i++)
                                printf("%s{\"name\":\"%s\",\"registry\":\"%s\","
                                       "\"distance\":%d}", i ? "," : "",
                                       pv.matches[i].legit_name,
                                       pv.matches[i].registry,
                                       pv.matches[i].distance);
                            printf("]}\n");
                        } else {
                            printf("%-7s [%d]  %s (%s)\n",
                                   hlse_action_for_score(pv.score), pv.score,
                                   name, eco);
                            if (pv.reason[0])
                                printf("  \xc2\xb7 %s\n", pv.reason);
                        }
                    }
                }
                    if (!is_npm) break;   /* pip: one name per line */
                }  /* for(;;) drain-line */
            }
            fclose(mf);
            if (sarif_out) {
                sarif_emit(HLSE_VERSION);
            } else if (json_out) {
                char ep[4096];
                json_escape(mpath, ep, sizeof(ep));
                printf("{\"kind\":\"manifest_summary\",\"hlse_version\":\""
                       HLSE_VERSION "\",\"manifest\":\"%s\",\"ecosystem\":\"%s\","
                       "\"packages_checked\":%d,\"threats\":%d,"
                       "\"max_severity\":%d,\"gate_hits\":%d}\n",
                       ep, eco, checked, threats,
                       hlse_severity_for_score(max_score), gate_hits);
            } else if (threats == 0) {
                printf("OK    %s (%d packages checked, 0 typosquat risks)\n",
                       mpath, checked);
            } else {
                printf("\n%d suspicious package(s) of %d checked in %s\n",
                       threats, checked, mpath);
            }
            return gate_hits > 0 ? 1 : 0;
        }
        {
            const char *eco = (argc > idx + 2) ? argv[idx + 2] : NULL;
            PackageVerdict pv = hlse_check_package(argv[idx + 1], eco);
            if (json_out) {
                printf("{\"kind\":\"package\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"name\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"severity\":%d",
                       argv[idx + 1], pv.score, hlse_action_for_score(pv.score),
                       hlse_severity_for_score(pv.score));
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
                if (pv.score == 0) {
                    const char *bs = hlse_blindspot_for("package");
                    if (bs) {
                        char esc_bs[512];
                        json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (pv.score > 0) {
                    int ns = pv.n_matches > 0 ? pv.n_matches : 1;
                    const char *conf = ns >= 3 ? "high confidence" :
                                       ns >= 2 ? "corroborated" : "single signal";
                    printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
                }
                if (pv.score >= 40) {
                    /* Perspective 97: a name matching 2+ registries at once
                     * (e.g. "reqests" ~ pip "requests" dist-1 AND cargo
                     * "reqwest" dist-2, when no ecosystem is given) lands at
                     * score 50 alone — the n_matches==1 amplifier to 70 never
                     * fires — but pattern/objective/verify used to require
                     * >= 60, the same gap P95/P96 closed elsewhere.
                     * Perspective 103: text now shared with the plaintext
                     * path below via package_*_text() accessors. */
                    char e[512];
                    json_escape(package_pattern_text(), e, sizeof(e));
                    printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"HLSE-PKG-TYPOSQUAT\"");
                    json_escape(package_objective_text(), e, sizeof(e));
                    printf(",\"objective\":\"%s\"", e);
                    json_escape(package_verify_text(), e, sizeof(e));
                    printf(",\"verify\":\"%s\"", e);
                }
                if (pv.score >= 60) {
                    char e[512];
                    json_escape(package_triage_text(), e, sizeof(e));
                    printf(",\"triage\":\"%s\"", e);
                    json_escape(package_cascade_text(), e, sizeof(e));
                    printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("package", pv.score);
                    if (ex) {
                        char e[512];
                        json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (pv.score == 0) {
                const char *bs = hlse_blindspot_for("package");
                printf("OK    %s\n", argv[idx + 1]);
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(pv.score), pv.score,
                       argv[idx + 1]);
                if (pv.reason[0])
                    printf("  \xc2\xb7 %s\n", pv.reason);
                if (pv.score >= 40) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", package_pattern_text());
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", package_objective_text());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", package_verify_text());
                }
                if (pv.score >= 60) {
                    printf("  \xe2\x9a\x91 If you acted: %s\n", package_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", package_cascade_text());
                }
                if (pv.score < 60) {
                    const char *ex = hlse_exoneration_for("package", pv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return pv.score >= g_fail_threshold ? 1 : 0;
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
                printf("{\"kind\":\"paste\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,\"signals\":%d",
                       pv.score, hlse_action_for_score(pv.score),
                       hlse_severity_for_score(pv.score), pv.signals);
                if (pv.score == 0) {
                    const char *bs = hlse_blindspot_for("paste");
                    if (bs) {
                        char esc_bs[512];
                        json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (pv.score > 0) {
                    /* Count distinct PASTE_* signal families from the bitmask —
                     * the epistemic complement to the score: how many independent
                     * detectors corroborate this paste threat. */
                    int ns = 0, bits = pv.signals;
                    while (bits) { ns += bits & 1; bits >>= 1; }
                    if (ns == 0) ns = pv.n_reasons;  /* fallback if bitmask empty */
                    {
                        const char *conf = ns >= 3 ? "high confidence" :
                                           ns >= 2 ? "corroborated" : "single signal";
                        printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
                    }
                }
                if (pv.score >= 40) {
                    /* Build a minimal TextVerdict so the existing advisory
                     * machinery fires: "Shell-pipe" triggers ClickFix
                     * classification in hlse_classify_text_attack().
                     * Perspective 95: pattern/objective/verify now fire from
                     * the ALERT floor (40); triage/cascade_risk stay
                     * BLOCK+-only (60) since post-incident guidance presumes
                     * the user already acted. */
                    TextVerdict ptv;
                    const char *ppat, *pobj, *pvrf;
                    memset(&ptv, 0, sizeof(ptv));
                    ptv.score = pv.score;
                    ptv.n_reasons = 1;
                    snprintf(ptv.reasons[0], sizeof(ptv.reasons[0]),
                             "Shell-pipe: paste-and-run pastejacking");
                    ppat = hlse_classify_text_attack(&ptv);
                    pobj = hlse_text_objective(&ptv);
                    pvrf = hlse_text_verify(&ptv);
                    if (ppat) { char e[512]; json_escape(ppat,e,sizeof(e)); printf(",\"pattern\":\"%s\"",e); }
                    if (ppat) { const char *pid = hlse_text_pattern_id(&ptv); if (pid) printf(",\"pattern_id\":\"%s\"",pid); }
                    if (pobj) { char e[512]; json_escape(pobj,e,sizeof(e)); printf(",\"objective\":\"%s\"",e); }
                    if (pvrf) { char e[512]; json_escape(pvrf,e,sizeof(e)); printf(",\"verify\":\"%s\"",e); }
                    if (pv.score >= 60) {
                        const char *ptri, *pcas;
                        ptri = hlse_text_triage(&ptv);
                        pcas = hlse_text_cascade(&ptv);
                        if (ptri) { char e[512]; json_escape(ptri,e,sizeof(e)); printf(",\"triage\":\"%s\"",e); }
                        if (pcas) { char e[512]; json_escape(pcas,e,sizeof(e)); printf(",\"cascade_risk\":\"%s\"",e); }
                    }
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("paste", pv.score);
                    if (ex) {
                        char e[512];
                        json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf(",\"reasons\":[");
                for (i = 0; i < pv.n_reasons; i++) {
                    char esc[512];
                    json_escape(pv.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]}\n");
            } else if (pv.score == 0) {
                const char *bs = hlse_blindspot_for("paste");
                printf("OK    (paste)\n");
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                printf("%-7s [%d]  (paste)\n",
                       hlse_action_for_score(pv.score), pv.score);
                for (i = 0; i < pv.n_reasons; i++)
                    printf("  \xc2\xb7 %s\n", pv.reasons[i]);
                if (pv.score >= 40) {
                    /* Advisory lenses: every paste ALERT+ is ClickFix/pastejacking.
                     * print_text_advisories internally gates verify at >=40 and
                     * triage/cascade_risk at >=60 (Perspective 95). */
                    TextVerdict ptv;
                    memset(&ptv, 0, sizeof(ptv));
                    ptv.score = pv.score;
                    ptv.n_reasons = 1;
                    snprintf(ptv.reasons[0], sizeof(ptv.reasons[0]),
                             "Shell-pipe: paste-and-run pastejacking");
                    print_text_advisories(&ptv);
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("paste", pv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return pv.score >= g_fail_threshold ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "network") == 0) {
        NetworkVerdict nv = hlse_check_network();
        if (json_out) {
            int i;
            printf("{\"kind\":\"network\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"reasons\":[",
                   nv.score, hlse_action_for_score(nv.score),
                   hlse_severity_for_score(nv.score));
            for (i = 0; i < nv.n_reasons; i++) {
                char esc[512];
                json_escape(nv.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]");
            if (nv.score == 0) {
                const char *bs = hlse_blindspot_for("network");
                if (bs) {
                    char esc_bs[512];
                    json_escape(bs, esc_bs, sizeof(esc_bs));
                    printf(",\"blind_spot\":\"%s\"", esc_bs);
                }
            }
            if (nv.score > 0) {
                int ns = nv.n_reasons;
                const char *conf = ns >= 3 ? "high confidence" :
                                   ns >= 2 ? "corroborated" : "single signal";
                printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
            }
            if (nv.score >= 40) {
                /* Perspective 96: a single N2 (routing injection, +55) or N4
                 * (hosts-file pharming, +50) finding lands in ALERT (40-59)
                 * alone, but used to get no pattern/objective/verify — only
                 * BLOCK+ (60) did, the same gap P95 closed for URL/text/
                 * paste/scan. verify now fires from the ALERT floor;
                 * triage/cascade_risk (post-incident, presumes the user
                 * already acted) stay BLOCK+-only.
                 * Perspective 103: text now shared with the plaintext path
                 * below via network_*_text() accessors. */
                char e[512];
                json_escape(net_pattern_text(), e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                printf(",\"pattern_id\":\"HLSE-NET-C2\"");
                json_escape(network_objective_text(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                json_escape(network_verify_text(),    e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
            }
            if (nv.score >= 60) {
                char e[512];
                json_escape(network_triage_text(),  e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                json_escape(network_cascade_text(), e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
            }
            if (nv.score > 0 && nv.score < 60) {
                const char *ex = hlse_exoneration_for("network", nv.score);
                if (ex) {
                    char e[512];
                    json_escape(ex, e, sizeof(e));
                    printf(",\"exoneration\":\"%s\"", e);
                }
            }
            printf("}\n");
        } else if (nv.score == 0) {
            const char *bs = hlse_blindspot_for("network");
            printf("OK    (network \xe2\x80\x94 no anomalies detected)\n");
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            int i;
            printf("%-7s [%d]  (network)\n",
                   hlse_action_for_score(nv.score), nv.score);
            for (i = 0; i < nv.n_reasons; i++)
                printf("  \xc2\xb7 %s\n", nv.reasons[i]);
            if (nv.score >= 40) {
                printf("  \xe2\x96\xb8 Pattern: %s\n", net_pattern_text());
                printf("  \xe2\x97\x89 Attacker's goal: %s\n", network_objective_text());
                printf("  \xe2\x9c\x93 Verify first: %s\n", network_verify_text());
            }
            if (nv.score >= 60) {
                printf("  \xe2\x9a\x91 Immediate action: %s\n", network_triage_text());
                printf("  \xe2\x8a\x95 Also change: %s\n", network_cascade_text());
            }
            if (nv.score < 60) {
                const char *ex = hlse_exoneration_for("network", nv.score);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        return nv.score >= g_fail_threshold ? 1 : 0;
    }

    if (strcmp(argv[idx], "secret") == 0) {
        /* 1 MiB, BSS-allocated (static) not stack — matches the shipped
         * pre-commit hook's 1 MB file-size guard so no in-scope file is
         * silently truncated (Perspective 105 / P1-2). */
        static char stdin_buf[1u << 20];
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
            {
                const char *aar[16]; char rb[16][300];
                int aq, aqn = sv.n_findings;
                if (aqn > 16) aqn = 16;
                for (aq = 0; aq < aqn; aq++) {
                    snprintf(rb[aq], sizeof(rb[aq]), "%s: %s",
                             sv.findings[aq].type, sv.findings[aq].description);
                    aar[aq] = rb[aq];
                }
                hlse_alert_emit("secret", sv.score,
                    hlse_severity_for_score(sv.score), "(secret scan)", aar, aqn);
            }
            if (json_out) {
                int i;
                printf("{\"kind\":\"secret\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,\"findings\":[",
                       sv.score, hlse_action_for_score(sv.score),
                       hlse_severity_for_score(sv.score));
                for (i = 0; i < sv.n_findings; i++) {
                    char et[64], ed[512];
                    json_escape(sv.findings[i].type, et, sizeof(et));
                    json_escape(sv.findings[i].description, ed, sizeof(ed));
                    printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                           i > 0 ? "," : "", et, ed);
                }
                printf("]");
                printf(",\"confidence\":\"%s\"", hlse_secret_confidence(&sv));
                {
                    const char *rem = hlse_remediation_for("secret", sv.score);
                    if (rem) {
                        char erm[512];
                        json_escape(rem, erm, sizeof(erm));
                        printf(",\"remediation\":\"%s\"", erm);
                    }
                }
                if (sv.score == 0) {
                    const char *bs = hlse_blindspot_for("secret");
                    if (bs) {
                        char esc_bs[512];
                        json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (sv.n_findings > 0) {
                    /* Perspective 99: unconditional on score — a Stripe
                     * publishable key is public-by-design at any score,
                     * not just a probabilistic false-positive hedge. */
                    const char *cav = secret_finding_caveat(sv.findings[0].type);
                    if (cav) {
                        char e[768];
                        json_escape(cav, e, sizeof(e));
                        printf(",\"caveat\":\"%s\"", e);
                    }
                }
                if (sv.score >= 60 && sv.n_findings > 0) {
                    const char *ftype = sv.findings[0].type;
                    const char *sobj  = secret_objective_for(ftype);
                    char e[512], epat[128];
                    secret_pattern_label(ftype, epat, sizeof(epat));
                    json_escape(epat, e, sizeof(e));
                    printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"%s\"", secret_pattern_id(ftype));
                    if (sobj) { json_escape(sobj, e, sizeof(e)); printf(",\"objective\":\"%s\"", e); }
                    json_escape(secret_verify_text(),  e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                    json_escape(secret_triage_text(),  e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                    json_escape(secret_cascade_text(), e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (sv.score > 0 && sv.score < 60) {
                    const char *ex = hlse_exoneration_for("secret", sv.score);
                    if (ex) {
                        char e[512];
                        json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (sv.score == 0) {
                const char *bs = hlse_blindspot_for("secret");
                printf("OK    (secret \xe2\x80\x94 no credentials found)\n");
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                const char *rem = hlse_remediation_for("secret", sv.score);
                const char *conf = hlse_secret_confidence(&sv);
                printf("%-7s [%d]  (secret scan — confidence: %s)\n",
                       hlse_action_for_score(sv.score), sv.score, conf);
                for (i = 0; i < sv.n_findings; i++)
                    printf("  \xc2\xb7 [%s] %s\n",
                           sv.findings[i].type, sv.findings[i].description);
                if (strcmp(conf, "heuristic") == 0)
                    printf("  \xe2\x86\x92 Confidence: heuristic — this is a "
                           "pattern guess (generic VAR=value / high-entropy "
                           "string); confirm it is a live credential.\n");
                if (sv.n_findings > 0) {
                    const char *cav = secret_finding_caveat(sv.findings[0].type);
                    if (cav) printf("  \xe2\x9a\xa0 Caveat: %s\n", cav);
                }
                if (sv.score >= 60 && sv.n_findings > 0) {
                    const char *ftype = sv.findings[0].type;
                    const char *sobj  = secret_objective_for(ftype);
                    char epat[128];
                    secret_pattern_label(ftype, epat, sizeof(epat));
                    printf("  \xe2\x96\xb8 Pattern: %s\n", epat);
                    if (sobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", sobj);
                    printf("  \xe2\x9c\x93 Verify first: %s\n", secret_verify_text());
                    printf("  \xe2\x9a\x91 Immediate action: %s\n", secret_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", secret_cascade_text());
                }
                if (sv.score > 0 && sv.score < 60) {
                    const char *ex = hlse_exoneration_for("secret", sv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
                if (rem) printf("  \xe2\x86\x92 Action: %s\n", rem);
            }
            return sv.score >= g_fail_threshold ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "email") == 0) {
        static char stdin_buf[1u << 20];  /* 1 MiB, BSS (P1-2) */
        const char *headers;
        /* Perspective 106 (P2-3): --from sets a delivery-channel prior that
         * boosts URL/text scores, but email headers are BY DEFINITION
         * received over email — the channel is intrinsic and fixed, so a
         * --from override (especially a non-email one like sms) is
         * meaningless here. The flag was silently ignored, which reads like a
         * bug; make it explicit with a one-line stderr note instead. */
        if (g_from_channel) {
            fprintf(stderr,
                    "hlse: note: --from is ignored for the email subcommand "
                    "\xe2\x80\x94 email headers are intrinsically the email "
                    "channel; the channel prior is not applied\n");
        }
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
            const char *rem = hlse_remediation_for("email", ev.score);
            /* Header forensics (SPF/DKIM/Reply-To/Received) is blind to the
             * message BODY's social engineering. Run text analysis on the same
             * input and surface the attack-pattern lens as ADVISORY only — the
             * email score is unchanged (preserves F1), but a BEC/urgency body
             * that header checks alone would miss is now named. */
            TextVerdict bodytv = hlse_check_text(headers);
            const char *body_pat = hlse_classify_text_attack(&bodytv);
            if (json_out) {
                int i;
                printf("{\"kind\":\"email\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,\"reasons\":[",
                       ev.score, hlse_action_for_score(ev.score),
                       hlse_severity_for_score(ev.score));
                for (i = 0; i < ev.n_reasons; i++) {
                    char esc[512];
                    json_escape(ev.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]");
                if (ev.score == 0 && !body_pat) {
                    const char *bs = hlse_blindspot_for("email");
                    if (bs) {
                        char esc_bs[512];
                        json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (body_pat) {
                    char epat[256];
                    json_escape(body_pat, epat, sizeof(epat));
                    printf(",\"body_pattern\":\"%s\",\"body_score\":%d",
                           epat, bodytv.score);
                    /* Emit pattern and pattern_id from body analysis, plus signal count/confidence */
                    printf(",\"signal_count\":2,\"confidence\":\"two independent signals — header authentication + body text both analyzed\"");
                    TextVerdict btv_hi = bodytv;
                    char e[512];
                    const char *bpat, *bobj, *bvrf, *btri, *bcas, *bex;
                    btv_hi.score = ev.score > bodytv.score ? ev.score : bodytv.score;
                    bpat = hlse_classify_text_attack(&btv_hi);
                    bobj = hlse_text_objective(&btv_hi);
                    bex  = hlse_text_exoneration(&btv_hi);
                    bvrf = hlse_text_verify(&btv_hi);
                    btri = hlse_text_triage(&btv_hi);
                    bcas = hlse_text_cascade(&btv_hi);
                    if (bpat) { json_escape(bpat,e,sizeof(e)); printf(",\"pattern\":\"%s\"",e); }
                    if (bpat) {
                        const char *bid = hlse_text_pattern_id(&btv_hi);
                        if (bid) printf(",\"pattern_id\":\"%s\"", bid);
                    }
                    if (bex && btv_hi.score >= 15 && btv_hi.score < 60) {
                        json_escape(bex,e,sizeof(e)); printf(",\"exoneration\":\"%s\"",e);
                    }
                    /* Perspective 95: verify now fires from the ALERT floor
                     * (btv_hi.score >= 40, the combined header/body score) —
                     * objective/triage/cascade_risk stay gated on ev.score
                     * >= 60 (header-confidence threshold, unchanged). */
                    if (bvrf && btv_hi.score >= 40) {
                        json_escape(bvrf,e,sizeof(e)); printf(",\"verify\":\"%s\"",e);
                    }
                    if (ev.score >= 60) {
                        if (bobj) { json_escape(bobj,e,sizeof(e)); printf(",\"objective\":\"%s\"",e); }
                        if (btri) { json_escape(btri,e,sizeof(e)); printf(",\"triage\":\"%s\"",e); }
                        if (bcas) { json_escape(bcas,e,sizeof(e)); printf(",\"cascade_risk\":\"%s\"",e); }
                    }
                } else if (ev.score >= 60) {
                    /* Header-only BLOCK: synthesise BEC advisory lenses */
                    TextVerdict etv;
                    char e[512];
                    const char *epat2, *eobj, *evrf, *etri, *ecas;
                    memset(&etv, 0, sizeof(etv));
                    etv.score = ev.score;
                    etv.n_reasons = 1;
                    snprintf(etv.reasons[0], sizeof(etv.reasons[0]),
                             "BEC: email header authentication failure "
                             "(SPF/DKIM/Reply-To spoofing)");
                    epat2 = hlse_classify_text_attack(&etv);
                    eobj  = hlse_text_objective(&etv);
                    evrf  = hlse_text_verify(&etv);
                    etri  = hlse_text_triage(&etv);
                    ecas  = hlse_text_cascade(&etv);
                    printf(",\"signal_count\":1,\"confidence\":\"single signal — email header authentication anomalies detected\"");
                    if (epat2) { json_escape(epat2,e,sizeof(e)); printf(",\"pattern\":\"%s\"",e); }
                    if (epat2) { const char *pid = hlse_text_pattern_id(&etv); if (pid) printf(",\"pattern_id\":\"%s\"",pid); }
                    if (eobj)  { json_escape(eobj,e,sizeof(e));  printf(",\"objective\":\"%s\"",e); }
                    if (evrf)  { json_escape(evrf,e,sizeof(e));  printf(",\"verify\":\"%s\"",e); }
                    if (etri)  { json_escape(etri,e,sizeof(e));  printf(",\"triage\":\"%s\"",e); }
                    if (ecas)  { json_escape(ecas,e,sizeof(e));  printf(",\"cascade_risk\":\"%s\"",e); }
                } else if (ev.score > 0) {
                    /* Borderline header score (1-59): emit signal_count, confidence, and exoneration */
                    printf(",\"signal_count\":1");
                    TextVerdict etv;
                    const char *econn = hlse_exoneration_for("email", ev.score);
                    if (econn) {
                        char e[512];
                        json_escape(econn, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                    memset(&etv, 0, sizeof(etv));
                    etv.score = ev.score;
                    printf(",\"confidence\":\"partial signal — some email header concerns but not conclusive spoofing\"");
                }
                if (rem) {
                    char erm[512];
                    json_escape(rem, erm, sizeof(erm));
                    printf(",\"remediation\":\"%s\"", erm);
                }
                printf("}\n");
            } else if (ev.score == 0 && !body_pat) {
                const char *bs = hlse_blindspot_for("email");
                printf("OK    (email \xe2\x80\x94 no spoofing signals)\n");
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                const char *ex = hlse_exoneration_for("email", ev.score);
                if (ev.score == 0)
                    printf("OK    [0]  (email forensics) "
                           "\xe2\x80\x94 headers clean, but body flagged below\n");
                else
                    printf("%-7s [%d]  (email forensics)\n",
                           hlse_action_for_score(ev.score), ev.score);
                for (i = 0; i < ev.n_reasons; i++)
                    printf("  \xc2\xb7 %s\n", ev.reasons[i]);
                if (body_pat) {
                    /* Use email header score for advisory threshold */
                    TextVerdict btv_hi = bodytv;
                    const char *bobj, *bvrf, *btri, *bcas;
                    if (ev.score >= 60) btv_hi.score = ev.score;
                    bobj = hlse_text_objective(&btv_hi);
                    bvrf = hlse_text_verify(&btv_hi);
                    btri = hlse_text_triage(&btv_hi);
                    bcas = hlse_text_cascade(&btv_hi);
                    printf("  \xe2\x96\xb8 Body pattern: %s (body score %d)\n",
                           body_pat, bodytv.score);
                    if (bobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", bobj);
                    /* Perspective 95: verify fires from the ALERT floor
                     * (btv_hi.score >= 40); triage/cascade stay BLOCK+-only. */
                    if (bvrf && btv_hi.score >= 40)
                        printf("  \xe2\x9c\x93 Verify first: %s\n", bvrf);
                    if (ev.score >= 60) {
                        if (btri) printf("  \xe2\x9a\x91 If you acted: %s\n", btri);
                        if (bcas) printf("  \xe2\x8a\x95 Also change: %s\n", bcas);
                    }
                } else if (ev.score >= 60) {
                    /* Header-only BLOCK: synthesise BEC advisory lenses */
                    TextVerdict etv;
                    const char *epat2, *eobj, *evrf, *etri, *ecas;
                    memset(&etv, 0, sizeof(etv));
                    etv.score = ev.score;
                    etv.n_reasons = 1;
                    snprintf(etv.reasons[0], sizeof(etv.reasons[0]),
                             "BEC: email header authentication failure "
                             "(SPF/DKIM/Reply-To spoofing)");
                    epat2 = hlse_classify_text_attack(&etv);
                    eobj  = hlse_text_objective(&etv);
                    evrf  = hlse_text_verify(&etv);
                    etri  = hlse_text_triage(&etv);
                    ecas  = hlse_text_cascade(&etv);
                    if (epat2) printf("  \xe2\x96\xb8 Pattern: %s\n", epat2);
                    if (eobj)  printf("  \xe2\x97\x89 Attacker's goal: %s\n", eobj);
                    if (evrf)  printf("  \xe2\x9c\x93 Verify first: %s\n", evrf);
                    if (etri)  printf("  \xe2\x9a\x91 If you acted: %s\n", etri);
                    if (ecas)  printf("  \xe2\x8a\x95 Also change: %s\n", ecas);
                }
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                if (rem) printf("  \xe2\x86\x92 Action: %s\n", rem);
            }
            return ev.score >= g_fail_threshold ? 1 : 0;
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
            const char *rem = hlse_remediation_for("clipboard", cv.score);
            if (json_out) {
                char eo[256], es[256], er[512], erm[512];
                json_escape(cv.original, eo, sizeof(eo));
                json_escape(cv.swapped, es, sizeof(es));
                json_escape(cv.reason, er, sizeof(er));
                json_escape(rem ? rem : "", erm, sizeof(erm));
                printf("{\"kind\":\"clipboard\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,"
                       "\"is_swap\":%d,"
                       "\"original\":\"%s\",\"swapped\":\"%s\",\"reason\":\"%s\","
                       "\"remediation\":\"%s\"",
                       cv.score, hlse_action_for_score(cv.score),
                       hlse_severity_for_score(cv.score),
                       cv.is_swap, eo, es, er, erm);
                if (cv.score == 0) {
                    const char *bs = hlse_blindspot_for("clipboard");
                    if (bs) {
                        char esc_bs[512];
                        json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (cv.score >= 60) {
                    char e[512];
                    json_escape(clipboard_pattern_text(), e, sizeof(e));
                    printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"HLSE-CLIP-HIJACK\"");
                    json_escape(clipboard_objective_text(), e, sizeof(e));
                    printf(",\"objective\":\"%s\"", e);
                    json_escape(clipboard_verify_text(), e, sizeof(e));
                    printf(",\"verify\":\"%s\"", e);
                    json_escape(clipboard_triage_text(), e, sizeof(e));
                    printf(",\"triage\":\"%s\"", e);
                    json_escape(clipboard_cascade_text(), e, sizeof(e));
                    printf(",\"cascade_risk\":\"%s\"", e);
                }
                printf("}\n");
            } else if (cv.score == 0) {
                const char *bs = hlse_blindspot_for("clipboard");
                printf("OK    (clipboard \xe2\x80\x94 no address swap detected)\n");
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                printf("%-7s [%d]  (clipboard)\n",
                       hlse_action_for_score(cv.score), cv.score);
                if (cv.reason[0]) printf("  \xc2\xb7 %s\n", cv.reason);
                if (rem) printf("  \xe2\x86\x92 Action: %s\n", rem);
                if (cv.score >= 60) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", clipboard_pattern_text());
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", clipboard_objective_text());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", clipboard_verify_text());
                    printf("  \xe2\x9a\x91 If you acted: %s\n", clipboard_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", clipboard_cascade_text());
                }
            }
            return cv.score >= g_fail_threshold ? 1 : 0;
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
            {
                const char *aar[16]; int aq, aqn = fv.n_reasons;
                if (aqn > 16) aqn = 16;
                for (aq = 0; aq < aqn; aq++) aar[aq] = fv.reasons[aq];
                hlse_alert_emit("file", fv.score,
                    hlse_severity_for_score(fv.score), argv[idx + 1], aar, aqn);
            }
            if (json_out) {
                int i;
                char esc[512];
                json_escape(argv[idx + 1], esc, sizeof(esc));
                printf("{\"kind\":\"file\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"path\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"severity\":%d,\"reasons\":[",
                       esc, fv.score, hlse_action_for_score(fv.score),
                       hlse_severity_for_score(fv.score));
                for (i = 0; i < fv.n_reasons; i++) {
                    json_escape(fv.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]");
                if (fv.score == 0) {
                    const char *bs = hlse_blindspot_for("file");
                    if (bs) {
                        char esc_bs[512];
                        json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (fv.score >= 40) {
                    /* Perspective 98: a single medium-confidence heuristic
                     * (e.g. Cabinet-magic/wrong-extension, +40) lands the
                     * file verdict in ALERT (40-59) alone, but this used to
                     * require score >= 60 for ANY advisory content at all —
                     * not even exoneration existed for "file" until this
                     * perspective. pattern/objective/verify now fire from
                     * the ALERT floor; triage/cascade_risk (post-open
                     * incident response) stay BLOCK+-only.
                     * Perspective 101: classification and advisory text now
                     * come from the shared accessors (see file_classify_
                     * pattern/file_masquerade_objective/file_masquerade_verify
                     * above) instead of a fourth independent copy. */
                    const char *fpat = file_classify_pattern(&fv);
                    char e[512];
                    json_escape(fpat, e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"%s\"", file_pattern_id(fpat));
                    json_escape(file_masquerade_objective(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                    json_escape(file_masquerade_verify(),    e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                }
                if (fv.score >= 60) {
                    static const char file_tri[] =
                        "if already opened: disconnect from the network "
                        "immediately; run a full antivirus scan; change "
                        "credentials for any service you were logged into at "
                        "the time; consider a full OS reinstall for high-score "
                        "detections";
                    static const char file_cas[] =
                        "all credentials and session tokens active when the file "
                        "was opened \xe2\x80\x94 malware runs with your session "
                        "context; also check for persistence (startup items, "
                        "scheduled tasks, browser extensions added)";
                    char e[512];
                    json_escape(file_tri, e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                    json_escape(file_cas, e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (fv.score > 0 && fv.score < 60) {
                    const char *ex = hlse_exoneration_for("file", fv.score);
                    if (ex) {
                        char e[512];
                        json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (fv.score == 0) {
                const char *bs = hlse_blindspot_for("file");
                printf("OK    %s\n", argv[idx + 1]);
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(fv.score), fv.score,
                       argv[idx + 1]);
                for (i = 0; i < fv.n_reasons; i++)
                    printf("  \xc2\xb7 %s\n", fv.reasons[i]);
                if (fv.score >= 40) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", file_classify_pattern(&fv));
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", file_masquerade_objective());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", file_masquerade_verify());
                }
                if (fv.score >= 60) {
                    printf("  \xe2\x9a\x91 If you acted: if already opened, disconnect "
                           "from the network; run antivirus; change credentials for "
                           "any active session\n");
                    printf("  \xe2\x8a\x95 Also change: all credentials and session "
                           "tokens active when the file was opened \xe2\x80\x94 check "
                           "for persistence (startup items, scheduled tasks, new "
                           "browser extensions)\n");
                }
                if (fv.score < 60) {
                    const char *ex = hlse_exoneration_for("file", fv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return fv.score >= g_fail_threshold ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "audit") == 0) {
        AuditVerdict av = hlse_audit_all();
        int hi = hlse_audit_hardening_index(&av);
        const char *band = hi >= 90 ? "hardened"
                         : hi >= 70 ? "good"
                         : hi >= 50 ? "fair" : "weak";
        /* Pre-compute severity counts for next_steps guidance */
        int crit_count = 0, high_count = 0;
        { int ci;
          for (ci = 0; ci < av.n_findings; ci++) {
              if (av.findings[ci].severity >= 5) crit_count++;
              else if (av.findings[ci].severity == 4) high_count++;
          }
        }
        if (json_out) {
            int i;
            printf("{\"kind\":\"audit\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,"
                   "\"hardening_index\":%d,\"hardening_band\":\"%s\","
                   "\"crit_count\":%d,\"high_count\":%d,"
                   "\"findings\":[",
                   av.score, hlse_action_for_score(av.score),
                   hlse_severity_for_score(av.score), hi, band,
                   crit_count, high_count);
            for (i = 0; i < av.n_findings; i++) {
                char esc[512];
                const char *fix = (av.findings[i].severity >= 4)
                    ? audit_remediation_for(av.findings[i].description)
                    : NULL;
                json_escape(av.findings[i].description, esc, sizeof(esc));
                printf("%s{\"severity\":%d,\"description\":\"%s\"",
                       i > 0 ? "," : "",
                       av.findings[i].severity, esc);
                if (fix) {
                    char efix[512];
                    json_escape(fix, efix, sizeof(efix));
                    printf(",\"fix\":\"%s\"", efix);
                }
                printf("}");
            }
            printf("]");
            if (av.score == 0) {
                const char *bs = hlse_blindspot_for("audit");
                if (bs) {
                    char esc_bs[512];
                    json_escape(bs, esc_bs, sizeof(esc_bs));
                    printf(",\"blind_spot\":\"%s\"", esc_bs);
                }
            } else {
                char ns[256];
                if (crit_count > 0)
                    snprintf(ns, sizeof(ns),
                             "fix the %d critical finding(s) first \xe2\x80\x94 "
                             "CRITICAL items are actively exploitable",
                             crit_count);
                else if (high_count > 0)
                    snprintf(ns, sizeof(ns),
                             "fix the %d HIGH finding(s) to reach the next "
                             "hardening band (currently: %s)",
                             high_count, band);
                else
                    snprintf(ns, sizeof(ns),
                             "address remaining LOW/MED findings to improve "
                             "the hardening index (currently: %s)",
                             band);
                { char ens[256];
                  json_escape(ns, ens, sizeof(ens));
                  printf(",\"next_steps\":\"%s\"", ens);
                }
            }
            printf("}\n");
        } else if (av.score == 0) {
            const char *bs = hlse_blindspot_for("audit");
            printf("OK    (audit \xe2\x80\x94 no issues found)  "
                   "Hardening index: %d/100 (%s)\n", hi, band);
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
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
                if (s >= 4) {
                    const char *fix = audit_remediation_for(
                        av.findings[i].description);
                    if (fix)
                        printf("  \xe2\x9a\x92 Fix: %s\n", fix);
                }
            }
            if (crit_count > 0)
                printf("\xe2\x86\x92 Next step: fix the %d CRITICAL finding(s) first "
                       "\xe2\x80\x94 these are actively exploitable\n", crit_count);
            else if (high_count > 0)
                printf("\xe2\x86\x92 Next step: fix the %d HIGH finding(s) to improve "
                       "from '%s' toward the next hardening band\n",
                       high_count, band);
            else
                printf("\xe2\x86\x92 Next step: address remaining findings to improve "
                       "the hardening index (currently %s: %d/100)\n",
                       band, hi);
        }
        return av.score >= g_fail_threshold ? 1 : 0;
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
                /* Channel-only risk: content scored 0 but delivery channel adds prior */
                if (g_from_channel) {
                    int d = channel_delta(g_from_channel);
                    if (d > 0) {
                        const char *ch_rsn = channel_reason(g_from_channel);
                        const char *bs2 = hlse_blindspot_for("text");
                        printf("%-7s [%d]  (text) %.60s%s\n",
                               hlse_action_for_score(d), d, argv[idx + 1],
                               strlen(argv[idx + 1]) > 60 ? "..." : "");
                        if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                        if (bs2) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs2);
                        return d >= g_fail_threshold ? 1 : 0;
                    }
                }
                {
                    char canon_brand[64];
                    int has_c = sr.is_url &&
                                hlse_canonical_confirm(argv[idx + 1],
                                                       canon_brand, sizeof(canon_brand));
                    const char *bs = hlse_blindspot_for(
                        has_c ? "url_canonical" : (sr.is_url ? "url" : "text"));
                    printf("OK    (text)\n");
                    if (has_c)
                        printf("  \xe2\x9c\x94 Canonical: confirmed authentic %s domain "
                               "(HLSE brand registry)\n", canon_brand);
                    if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
                }
            } else {
                int i;
                int eff = sr.score;
                const char *ch_rsn = NULL;
                const char *ex;
                if (g_from_channel) {
                    int d = channel_delta(g_from_channel);
                    eff += d; if (eff > 100) eff = 100;
                    ch_rsn = channel_reason(g_from_channel);
                }
                printf("%-7s [%d]  (text) %.60s%s\n",
                       hlse_action_for_score(eff),
                       eff, argv[idx + 1],
                       strlen(argv[idx + 1]) > 60 ? "..." : "");
                for (i = 0; i < sr.n_reasons; i++) {
                    if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                    printf("  \xc2\xb7 %s\n", sr.reasons[i]);
                }
                if (sr.is_url) {
                    Verdict uv = check_url(argv[idx + 1]);
                    print_url_advisories(argv[idx + 1], &uv);
                    ex = hlse_url_exoneration(&uv);
                } else {
                    TextVerdict tv;
                    int ti;
                    memset(&tv, 0, sizeof(tv));
                    tv.score = sr.score;
                    tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                                   ? sr.n_reasons
                                   : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                    for (ti = 0; ti < tv.n_reasons; ti++)
                        snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                                 "%s", sr.reasons[ti]);
                    print_text_advisories(&tv);
                    ex = hlse_text_exoneration(&tv);
                }
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
            {
                int eff_gate = sr.score;
                if (g_from_channel) {
                    int d = channel_delta(g_from_channel);
                    eff_gate += d; if (eff_gate > 100) eff_gate = 100;
                }
                return eff_gate >= g_fail_threshold ? 1 : 0;
            }
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
        /* Push to alert sinks (--syslog/--log-file) if enabled — emitted from
         * the ScanResult so every output branch below is covered uniformly. */
        {
            const char *ar[16];
            int ai, an = sr.n_reasons;
            if (an > 16) an = 16;
            for (ai = 0; ai < an; ai++) ar[ai] = sr.reasons[ai];
            hlse_alert_emit(sr.is_url ? "url" : "text", sr.score,
                            hlse_severity_for_score(sr.score), input, ar, an);
        }
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
            /* Channel-only risk: content scored 0 but delivery channel adds prior */
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                if (d > 0) {
                    const char *ch_rsn = channel_reason(g_from_channel);
                    const char *bs2 = hlse_blindspot_for(sr.is_url ? "url" : "text");
                    printf("%-7s [%d]  %s\n", hlse_action_for_score(d), d, input);
                    if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                    if (bs2) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs2);
                    {
                        int eff_gate = d;
                        return eff_gate >= g_fail_threshold ? 1 : 0;
                    }
                }
            }
            {
                char canon_brand[64];
                int has_c = sr.is_url &&
                            hlse_canonical_confirm(input, canon_brand, sizeof(canon_brand));
                const char *bs = hlse_blindspot_for(
                    has_c ? "url_canonical" : (sr.is_url ? "url" : "text"));
                printf("OK    %s\n", input);
                if (has_c)
                    printf("  \xe2\x9c\x94 Canonical: confirmed authentic %s domain "
                           "(HLSE brand registry)\n", canon_brand);
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            }
        } else {
            int i;
            int eff = sr.score;
            const char *ch_rsn = NULL;
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                eff += d; if (eff > 100) eff = 100;
                ch_rsn = channel_reason(g_from_channel);
            }
            printf("%-7s [%d]  %s\n",
                   hlse_action_for_score(eff), eff, input);
            for (i = 0; i < sr.n_reasons; i++) {
                if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                printf("  \xc2\xb7 %s\n", sr.reasons[i]);
            }
            if (sr.is_url) {
                /* Re-run URL check to get a Verdict for pattern synthesis.
                 * hlse_scan already ran this internally; the cost is low.  */
                Verdict uv = check_url(input);
                const char *ex = hlse_url_exoneration(&uv);
                print_url_advisories(input, &uv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            } else {
                TextVerdict tv;
                const char *ex;
                int ti;
                memset(&tv, 0, sizeof(tv));
                tv.score = sr.score;
                tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                               ? sr.n_reasons
                               : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                for (ti = 0; ti < tv.n_reasons; ti++)
                    snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                             "%s", sr.reasons[ti]);
                ex   = hlse_text_exoneration(&tv);
                print_text_advisories(&tv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        /* Gate uses effective score so --from boost is honoured in exit code. */
        {
            int eff_gate = sr.score;
            if (g_from_channel) {
                int d = channel_delta(g_from_channel);
                eff_gate += d; if (eff_gate > 100) eff_gate = 100;
            }
            return eff_gate >= g_fail_threshold ? 1 : 0;
        }
    }
}
#endif /* HLSE_CORE_AS_LIB */
