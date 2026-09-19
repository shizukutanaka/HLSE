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
#include "hlse_config.h"  /* HlseConfig, hlse_config_load (--config) */
#include "hlse_selftest.h" /* hlse_*_self_test, hlse_benchmark */
#include "hlse_registry.h" /* hlse_list_patterns */
#include "hlse_channel.h"  /* hlse_from_channel, hlse_channel_delta/reason */
#include "hlse_baseline.h" /* hlse_scan_suppress, hlse_baseline_load/clear */
#include "hlse_patterns.h" /* hlse_patterns_load (--patterns) */
#include "hlse_sarif.h"    /* hlse_sarif_add, hlse_sarif_emit */
#include "hlse_manifest.h" /* manifest ecosystem + name parsers */
#include "hlse_githistory.h" /* hlse_scan_git_history */
#include "hlse_meta.h"    /* pattern ids, asset-class blast radius */
#include "hlse_emit.h"    /* advisory text getters, verdict emitters */
#include "hlse_cli.h"     /* HlseCli — parsed-option state */
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
    /* Reasons embed attacker-controlled bytes (URL/query fragments, brand
     * lookalikes); strip terminal-hostile characters once here so every
     * downstream print is safe. JSON sinks escape via hlse_json_escape. */
    hlse_sanitize_display(v->reasons[v->n_reasons]);
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
            strstr(v->reasons[i], "Mixed-script homoglyph") != NULL ||
            strstr(v->reasons[i], "Whole-script confusable") != NULL)
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

/* Script class of a code point, restricted to what homograph analysis needs
 * (defined below at cp_script(); shared with the Punycode/IDN detector).
 * The enum lives here so the raw-UTF-8 detector below can use it too. */
enum { SCR_NEUTRAL = 0, SCR_LATIN = 1, SCR_CONFUSABLE = 2 };
static int cp_script(uint32_t cp);

/* Registries that legitimately host a Latin-confusable script, so a
 * whole-script label there is ordinary internationalisation rather than a
 * spoof. Mirrors the per-script TLD allow-lists Chrome and Firefox use when
 * deciding whether to show an IDN as Unicode or fall back to Punycode. */
static const char *CONFUSABLE_SCRIPT_TLDS[] = {
    ".ru", ".su", ".ua", ".by", ".bg", ".rs", ".mk", ".kz", ".kg",  /* Cyrillic */
    ".gr", ".cy",                                                    /* Greek    */
    ".am",                                                           /* Armenian */
    NULL
};

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
        /* UTS #39 distinguishes two cases the old code collapsed into one:
         *   - MIXED-script: Latin letters alongside confusable ones
         *     ("pаypal", one Cyrillic а) — the script mixing is the tell.
         *   - WHOLE-script confusable: every letter from a single non-Latin
         *     script ("раураӏ", all Cyrillic) — nothing is mixed, so the
         *     mixing tell is absent. This is the harder and more dangerous
         *     class, and calling it "mixed-script" was simply wrong. */
        /* Flags are tracked PER LABEL, because the label is the unit UTS #39
         * analyses and the unit a registry issues. Judging the whole host
         * would be meaningless here: the ASCII ".com" would mark every host
         * as containing Latin, so the whole-script case could never be
         * reached. Reset at each dot; fold the finished label into the
         * host-level answer. */
        int lbl_latin = 0, lbl_confusable = 0;
        int any_mixed_label = 0, any_whole_confusable_label = 0;
        const unsigned char *q = (const unsigned char *)u->host;
        while (*q && k < MAX_HOST - 1) {
            uint32_t cp;
            int nbytes, b, valid = 1;
            if (*q < 0x80) {
                if (*q == '.') {           /* label boundary */
                    if (lbl_confusable)
                        { if (lbl_latin) any_mixed_label = 1;
                          else any_whole_confusable_label = 1; }
                    lbl_latin = lbl_confusable = 0;
                } else if ((*q >= 'a' && *q <= 'z') ||
                           (*q >= 'A' && *q <= 'Z')) {
                    lbl_latin = 1;         /* ASCII letters are Latin too */
                }
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
                int s = cp_script(cp);
                if (s == SCR_LATIN)           lbl_latin = 1;
                else if (s == SCR_CONFUSABLE) lbl_confusable = 1;
                ascii[k++] = f ? f : '?';
            }
            q += nbytes;
        }
        ascii[k] = '\0';
        /* Close out the final label (no trailing dot to trigger the flush). */
        if (lbl_confusable) {
            if (lbl_latin) any_mixed_label = 1;
            else           any_whole_confusable_label = 1;
        }

        /* Now check brand match in the ASCII-collapsed form */
        {
            int i;
            for (i = 0; BRANDS[i] != NULL; i++) {
                if (contains(ascii, BRANDS[i])) {
                    /* Same severity either way — a brand impersonation is an
                     * attack regardless of which class it falls in. Only the
                     * name changes, so the finding says what actually
                     * happened. */
                    if (any_whole_confusable_label && !any_mixed_label)
                        add_reason(v, 60,
                                   "Whole-script confusable: '%s' is written "
                                   "entirely in non-Latin characters but "
                                   "resembles '%s'", u->host, BRANDS[i]);
                    else if (any_mixed_label)
                        add_reason(v, 60,
                                   "Mixed-script homoglyph: "
                                   "'%s' resembles '%s'", u->host, BRANDS[i]);
                    else
                        /* No script mixing and no non-Latin script: the spoof
                         * uses same-script compatibility variants (fullwidth
                         * or mathematical Latin), which render as the brand
                         * but are distinct code points. */
                        add_reason(v, 60,
                                   "Confusable characters: '%s' uses look-alike "
                                   "variant characters resembling '%s'",
                                   u->host, BRANDS[i]);
                    add_brand_canonical(v, BRANDS[i]);
                    return;
                }
            }
        }
        /* No brand match. A single-script non-Latin label under a registry
         * that legitimately serves that script is ordinary
         * internationalisation, not a spoof — the same carve-out Chrome and
         * Firefox make before falling back to Punycode display. Mixed-script
         * labels get no such pass: no registry legitimately issues those. */
        if (!any_mixed_label && !any_whole_confusable_label) {
            /* Non-ASCII, but none of it from a Latin-confusable script — an
             * accented Latin name (münchen.de) or another script entirely
             * (日本.jp). There is nothing for it to be confused WITH, so this
             * is ordinary internationalisation. Warning here penalised every
             * non-English domain for existing, which is not a security
             * signal; browsers do not warn on these either. */
            return;
        }
        if (any_whole_confusable_label && !any_mixed_label) {
            int t;
            for (t = 0; CONFUSABLE_SCRIPT_TLDS[t] != NULL; t++)
                if (ends_with(u->host, CONFUSABLE_SCRIPT_TLDS[t]))
                    return;
        }
        add_reason(v, 25,
                   "Latin-confusable script characters in domain "
                   "(rare for Latin-brand sites)");
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
static int
cp_script(uint32_t cp) {
    if ((cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z')) return SCR_LATIN;
    if (cp >= 0x00C0 && cp <= 0x024F) return SCR_LATIN;        /* Latin-1 + ext */
    /* Fullwidth and mathematical Latin are Script=Latin: they are
     * compatibility variants of ASCII letters, not a different script. They
     * still spoof, but via the confusable fold, not via script mixing. */
    if (cp >= 0xFF21 && cp <= 0xFF3A) return SCR_LATIN;
    if (cp >= 0xFF41 && cp <= 0xFF5A) return SCR_LATIN;
    if (cp >= 0x1D400 && cp <= 0x1D6A3) return SCR_LATIN;
    if (cp >= 0x0400 && cp <= 0x04FF) return SCR_CONFUSABLE;   /* Cyrillic */
    if (cp >= 0x0370 && cp <= 0x03FF) return SCR_CONFUSABLE;   /* Greek */
    if (cp >= 0x0530 && cp <= 0x058F) return SCR_CONFUSABLE;   /* Armenian */
    if (cp >= 0x13A0 && cp <= 0x13F5) return SCR_CONFUSABLE;   /* Cherokee */
    return SCR_NEUTRAL;
}

/* Fold a code point to its ASCII confusable, or 0 if none. ASCII passes
 * through. Conservative, high-confidence mappings only.                 */
static char
cp_fold(uint32_t cp) {
    if (cp < 0x80) return (char)cp;

    /* Range-folded families. The host has already been ASCII-lowercased by the
     * parser (str_tolower), but that cannot touch non-ASCII, so every mapping
     * here returns LOWERCASE Latin — otherwise the folded form would never
     * match the lowercase BRANDS table. */

    /* Fullwidth Latin (U+FF21..FF3A, U+FF41..FF5A). Same script as Latin, so
     * this is a compatibility-variant spoof rather than a script mix, but it
     * renders as an ordinary brand name and must fold. */
    if (cp >= 0xFF21 && cp <= 0xFF3A) return (char)('a' + (int)(cp - 0xFF21));
    if (cp >= 0xFF41 && cp <= 0xFF5A) return (char)('a' + (int)(cp - 0xFF41));

    /* Mathematical alphanumeric Latin: bold, italic, bold-italic, script,
     * fraktur, double-struck, sans, sans-bold, monospace. Each block is 26
     * uppercase then 26 lowercase, contiguous from U+1D400. */
    if (cp >= 0x1D400 && cp <= 0x1D6A3) {
        uint32_t off = (cp - 0x1D400) % 52;
        return (char)('a' + (int)(off % 26));
    }

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
        /* Cyrillic UPPERCASE (U+0410..U+042F). The parser's str_tolower only
         * folds ASCII, so these survive to here and previously mapped to
         * nothing — an all-uppercase spoof never reached the brand table.
         * Only glyphs that are visually identical to their Latin counterpart
         * are listed; near-misses (Б, Л, Ω, σ) are deliberately excluded, since
         * a wrong fold would manufacture brand matches out of legitimate
         * text. U+04C0 palochka is the genuine uppercase 'l' look-alike. */
        case 0x0410: return 'a';  case 0x0412: return 'b';
        case 0x0415: return 'e';  case 0x041A: return 'k';
        case 0x041C: return 'm';  case 0x041D: return 'h';
        case 0x041E: return 'o';  case 0x0420: return 'p';
        case 0x0421: return 'c';  case 0x0422: return 't';
        case 0x0423: return 'y';  case 0x0425: return 'x';
        case 0x0406: return 'i';  case 0x0408: return 'j';
        case 0x0405: return 's';  case 0x04C0: return 'l';
        /* Greek UPPERCASE */
        case 0x0391: return 'a';  case 0x0395: return 'e';
        case 0x0396: return 'z';  case 0x0397: return 'h';
        case 0x0399: return 'i';  case 0x039A: return 'k';
        case 0x039C: return 'm';  case 0x039D: return 'n';
        case 0x03A1: return 'p';  case 0x03A4: return 't';
        case 0x03A5: return 'y';  case 0x03A7: return 'x';
        /* Cherokee (U+13A0..U+13F5). Chrome names Cherokee alongside Cyrillic
         * and Greek as a whole-script-confusable script: its syllabary
         * contains many Latin-capital look-alikes, so ᏢᎪᎩᏢᎪᏞ reads as
         * PAYPAL. Conservative, high-confidence shapes only. */
        case 0x13A2: return 't';  case 0x13AA: return 'a';
        case 0x13A9: return 'y';  case 0x13A1: return 'r';
        case 0x13B3: return 'w';  case 0x13B7: return 'm';
        case 0x13BB: return 'h';  case 0x13D9: return 'v';
        case 0x13DA: return 's';  case 0x13DE: return 'l';
        case 0x13DF: return 'c';  case 0x13E2: return 'p';
        case 0x13E3: return 'r';  case 0x13E6: return 'k';
        case 0x13F3: return 'g';  case 0x13F4: return 'b';
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
                        char redir[HLSE_MAX_URL];
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
                    char url_buf[HLSE_MAX_URL];
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
                                    char syn2[HLSE_MAX_URL];
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
/* ─────────────────────────── JSON output ────────────────────────────── */


/* ──────────────────── CLI-only functions ─────────────────────────────
 * Everything from here to the end of the file is CLI-mode code.
 * Library users (HLSE_CORE_AS_LIB defined) get only check_url + types.
 * The delivery-channel prior itself lives in hlse_channel.c (set via
 * hlse_set_from_channel, read via hlse_from_channel).                 */
#ifndef HLSE_CORE_AS_LIB

int
main(int argc, char **argv) {
    HlseCli o = {0};
    o.fail_threshold = 60;   /* BLOCK — --fail-on overrides */
    HlseConfig cfg;             /* --config defaults; must live for all of
                                   main() — hlse_from_channel()/o.baseline_file/
                                   o.opt_log_file may point into it.        */
    memset(&cfg, 0, sizeof(cfg));
    int argc_flags;   /* argv index where "--" ends option scanning */
    int idx = 1;

    if (argc < 2) {
        /* Apple principle: the first experience IS the product.
         * Instead of a wall of usage text, show a live demo so the
         * user understands in 5 seconds what HLSE does.              */
        printf("HLSE %s — phishing & scam detection\n\n", HLSE_VERSION);

        printf("  Safe URL:\n");
        { Verdict v = check_url("https://github.com");
          printf("    https://github.com");
          printf("  →  %s\n\n", hlse_action_for_score(v.score)); }

        printf("  Phishing URL:\n");
        { Verdict v = check_url("https://g00gle.com");
          int i;
          printf("    https://g00gle.com");
          printf("  →  %s [%d/100]\n", hlse_action_for_score(v.score), v.score);
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

    /* End-of-options boundary. Global flags are matched "anywhere" for
     * convenience, but that must never reach OPERAND positions: an operand is
     * attacker-influenced data (a scanned URL, message, package name, clipboard
     * string). Without a boundary, a crafted operand such as
     *   hlse_core clipboard "--log-file" "/tmp/x"
     * is consumed as a flag — creating a file from scan data, and worse,
     * shifting argv so the real input is never analysed while the process still
     * exits 0 ("safe"). That is a silent detection bypass.
     *
     * `--` marks the end of options: everything after it is data, never a flag.
     * argc_flags bounds every flag loop below; the marker itself is removed
     * once, here, so the subcommand dispatch never sees it. */
    argc_flags = argc;
    {
        int i;
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--") == 0) {
                argc_flags = i;                     /* scan flags only before it */
                { int j; for (j = i; j < argc - 1; j++) argv[j] = argv[j+1]; argc--; }
                break;
            }
        }
        if (argc_flags > argc) argc_flags = argc;
    }

    /* Parse --config <file> FIRST, before any other flag loop: config keys
     * write defaults into the same globals the loops below assign, so an
     * explicit CLI flag always wins. A config `patterns` file is loaded
     * here too — if --patterns is also given, its handler clears the
     * custom registries and replaces it. */
    {
        {
            int i;
            for (i = 1; i < argc_flags - 1; i++) {
                if (strcmp(argv[i], "--config") == 0) {
                    char cerr[256];
                    if (hlse_config_load(argv[i + 1], &cfg,
                                         cerr, sizeof(cerr)) != 0) {
                        fprintf(stderr, "Error: %s\n", cerr);
                        return 2;
                    }
                    hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                    break;
                }
            }
        }
        if (cfg.has_json)         o.json_out            = cfg.json;
        if (cfg.has_sarif)        o.sarif_out           = cfg.sarif;
        if (cfg.has_quiet)        o.quiet               = cfg.quiet;
        if (cfg.has_syslog)       o.opt_syslog          = cfg.syslog;
        if (cfg.has_fingerprints) o.emit_fingerprints = cfg.fingerprints;
        if (cfg.has_git_history)  o.git_history       = cfg.git_history;
        if (cfg.has_fail_on)      o.fail_threshold    = cfg.fail_on;
        if (cfg.from[0])          hlse_set_from_channel(cfg.from);
        if (cfg.baseline[0])      o.baseline_file     = cfg.baseline;
        if (cfg.log_file[0])      o.opt_log_file        = cfg.log_file;
        if (cfg.patterns[0] && hlse_patterns_load(cfg.patterns) != 0) {
            fprintf(stderr, "Error: cannot read config patterns file "
                    "'%s': %s\n", cfg.patterns, strerror(errno));
            return 2;
        }
    }

    /* Boolean global flags: one table, one pass. These were six separate
     * scan loops that differed only in the flag name and the variable set,
     * each restating the argv-shifting logic. Adding a flag is now a row. */
    {
        struct { const char *name; const char *alias; int *flag; } bools[] = {
            { "--json",         NULL, &o.json_out            },
            { "--sarif",        NULL, &o.sarif_out           },
            { "--quiet",        "-q", &o.quiet               },
            { "--syslog",       NULL, &o.opt_syslog          },
            { "--fingerprints", NULL, &o.emit_fingerprints },
            { "--git-history",  NULL, &o.git_history       },
        };
        const int nbools = (int)(sizeof(bools) / sizeof(bools[0]));
        int i, k;
        for (i = 1; i < argc_flags; i++) {
            for (k = 0; k < nbools; k++) {
                if (strcmp(argv[i], bools[k].name) == 0 ||
                    (bools[k].alias && strcmp(argv[i], bools[k].alias) == 0)) {
                    *bools[k].flag = 1;
                    hlse_argv_remove(argv, &argc, &argc_flags, i, 1);
                    i--;            /* re-examine the element shifted into i */
                    break;
                }
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
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--fail-on") == 0) {
                const char *t = argv[i + 1];
                if      (strcmp(t, "log")     == 0) o.fail_threshold = 15;
                else if (strcmp(t, "alert")   == 0) o.fail_threshold = 40;
                else if (strcmp(t, "block")   == 0) o.fail_threshold = 60;
                else if (strcmp(t, "isolate") == 0) o.fail_threshold = 80;
                else {
                    /* Accept a bare numeric threshold (0..100) too. */
                    char *end;
                    long n = strtol(t, &end, 10);
                    if (*end == '\0' && n >= 0 && n <= 100)
                        o.fail_threshold = (int)n;
                    else {
                        fprintf(stderr, "Error: --fail-on expects "
                                "log|alert|block|isolate or 0..100\n");
                        return 2;
                    }
                }
                hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
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
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--from") == 0) {
                const char *ch = argv[i + 1];
                if (strcmp(ch, "email")  == 0 || strcmp(ch, "sms") == 0 ||
                    strcmp(ch, "dm")     == 0 || strcmp(ch, "qr")  == 0 ||
                    strcmp(ch, "manual") == 0) {
                    hlse_set_from_channel(ch);
                } else {
                    fprintf(stderr,
                            "Error: --from expects email|sms|dm|qr|manual\n");
                    return 2;
                }
                hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --baseline <file> (Perspective 107 / P0-1) — suppress findings
     * whose fingerprint is listed, so a brownfield repo's accepted findings
     * do not fail the CI gate forever. */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--baseline") == 0) {
                o.baseline_file = argv[i + 1];
                hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --log-file <path> (value) — append one JSONL record per finding. */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--log-file") == 0) {
                o.opt_log_file = argv[i + 1];
                hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --patterns <file> (Perspective 110 / P0-3) — register custom
     * organization-specific secret patterns without a rebuild. */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--patterns") == 0) {
                const char *ppath = argv[i + 1];
                /* Replace any config-file patterns wholesale so CLI
                 * precedence is clean, not additive. */
                hlse_clear_custom_secret_patterns();
                hlse_clear_custom_brands();
                if (hlse_patterns_load(ppath) != 0) {
                    fprintf(stderr, "Error: cannot read --patterns file '%s': %s\n",
                            ppath, strerror(errno));
                    return 2;
                }
                hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Load the baseline file now that flags are parsed. A missing/unreadable
     * baseline is a usage error — silently ignoring it would let the gate
     * pass on a typo'd path, defeating the purpose. */
    if (o.baseline_file && hlse_baseline_load(o.baseline_file) != 0) {
        fprintf(stderr, "Error: cannot read --baseline file '%s': %s\n",
                o.baseline_file, strerror(errno));
        return 2;
    }
    /* Register cleanup once — covers every one of main()'s many return paths
     * uniformly (atexit failure just reverts to pre-fix behavior: a no-op). */
    if (o.baseline_file) atexit(hlse_baseline_clear);

    /* Open alert sinks now that flags are parsed. A requested but unopenable
     * --log-file is a usage error (same convention as --baseline/--patterns). */
    if ((o.opt_syslog || o.opt_log_file) &&
        hlse_alert_init(o.opt_syslog, o.opt_log_file) != 0) {
        fprintf(stderr, "Error: cannot open --log-file '%s': %s\n",
                o.opt_log_file ? o.opt_log_file : "(syslog only)", strerror(errno));
        return 2;
    }
    if (o.opt_syslog || o.opt_log_file) atexit(hlse_alert_shutdown);

    /* Quiet mode: redirect stdout to /dev/null. If the redirect fails we must
     * not silently keep printing — that would violate the quiet-mode contract
     * (callers rely on the exit code alone). Report and exit with usage error. */
    if (o.quiet && !o.json_out) {
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
        int rc1 = hlse_url_self_test();
        int rc2 = hlse_text_self_test();
        return rc1 || rc2 ? 1 : 0;
    }
    if (strcmp(argv[idx], "--list-patterns") == 0) {
        return hlse_list_patterns(o.json_out);
    }
    if (strcmp(argv[idx], "--benchmark") == 0) {
        return hlse_benchmark();
    }
    if (strcmp(argv[idx], "--stdin") == 0) {
        return hlse_stdin_mode(o.json_out, o.fail_threshold);
    }
    if (strcmp(argv[idx], "-h") == 0 || strcmp(argv[idx], "--help") == 0) {
        hlse_print_usage(argv[0]);
        return 0;
    }

    /* ── scan subcommand ───────────────────────────────────────────────
     * Recursively scan a directory for secrets + file masquerade.
     * Designed for CI/CD pipelines:
     *   ./hlse_core scan /path/to/project
     *   exit 0 = clean, exit 1 = threats found                        */
    if (strcmp(argv[idx], "scan") == 0)
        return hlse_cmd_scan(&o, argc, argv, idx);

    /* ── protect subcommand ──────────────────────────────────────────
     * Usage: hlse_core protect <path> [--ransomware|--smb|--mbr|--net]
     * Without flags: runs all modules applicable to the path.        */
    if (strcmp(argv[idx], "protect") == 0)
        return hlse_cmd_protect(&o, argc, argv, idx);

    if (strcmp(argv[idx], "esp") == 0)
        return hlse_cmd_esp(&o, argc, argv, idx);

    /* ── Supply Chain Defense subcommands ───────────────────────────── */

    if (strcmp(argv[idx], "package") == 0)
        return hlse_cmd_package(&o, argc, argv, idx);

    if (strcmp(argv[idx], "paste") == 0)
        return hlse_cmd_paste(&o, argc, argv, idx);

    if (strcmp(argv[idx], "network") == 0)
        return hlse_cmd_network(&o);

    if (strcmp(argv[idx], "secret") == 0)
        return hlse_cmd_secret(&o, argc, argv, idx);

    if (strcmp(argv[idx], "email") == 0)
        return hlse_cmd_email(&o, argc, argv, idx);

    if (strcmp(argv[idx], "clipboard") == 0)
        return hlse_cmd_clipboard(&o, argc, argv, idx);

    if (strcmp(argv[idx], "file") == 0)
        return hlse_cmd_file(&o, argc, argv, idx);

    if (strcmp(argv[idx], "audit") == 0)
        return hlse_cmd_audit(&o);

    if (strcmp(argv[idx], "text") == 0)
        return hlse_cmd_text(&o, argc, argv, idx);

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
        if (o.json_out) {
            /* For JSON, delegate to the appropriate printer. For text
             * inputs use the ScanResult directly (not hlse_check_text
             * alone) so embedded URL extraction is honoured. */
            if (sr.is_url) {
                Verdict uv = hlse_check_url(input);
                hlse_print_json_url(input, &uv);
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
                hlse_print_json_text(input, &tv);
            }
        } else if (sr.score == 0) {
            /* Channel-only risk: content scored 0 but delivery channel adds prior */
            if (hlse_from_channel()) {
                int d = hlse_channel_delta(hlse_from_channel());
                if (d > 0) {
                    const char *ch_rsn = hlse_channel_reason(hlse_from_channel());
                    const char *bs2 = hlse_blindspot_for(sr.is_url ? "url" : "text");
                    char db[8192];
                    printf("%-7s [%d]  %s\n", hlse_action_for_score(d), d,
                           hlse_display_copy(db, sizeof(db), input));
                    if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                    if (bs2) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs2);
                    {
                        int eff_gate = d;
                        return eff_gate >= o.fail_threshold ? 1 : 0;
                    }
                }
            }
            {
                char canon_brand[64];
                int has_c = sr.is_url &&
                            hlse_canonical_confirm(input, canon_brand, sizeof(canon_brand));
                const char *bs = hlse_blindspot_for(
                    has_c ? "url_canonical" : (sr.is_url ? "url" : "text"));
                char db[8192];
                printf("OK    %s\n",
                       hlse_display_copy(db, sizeof(db), input));
                if (has_c)
                    printf("  \xe2\x9c\x94 Canonical: confirmed authentic %s domain "
                           "(HLSE brand registry)\n", canon_brand);
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            }
        } else {
            int i;
            int eff = sr.score;
            const char *ch_rsn = NULL;
            if (hlse_from_channel()) {
                int d = hlse_channel_delta(hlse_from_channel());
                eff += d; if (eff > 100) eff = 100;
                ch_rsn = hlse_channel_reason(hlse_from_channel());
            }
            {
                char db[8192];
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(eff), eff,
                       hlse_display_copy(db, sizeof(db), input));
            }
            for (i = 0; i < sr.n_reasons; i++) {
                if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                printf("  \xc2\xb7 %s\n", sr.reasons[i]);
            }
            if (sr.is_url) {
                /* Re-run URL check to get a Verdict for pattern synthesis.
                 * hlse_scan already ran this internally; the cost is low.  */
                Verdict uv = hlse_check_url(input);
                const char *ex = hlse_url_exoneration(&uv);
                hlse_print_url_advisories(input, &uv);
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
                hlse_print_text_advisories(&tv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        /* Gate uses effective score so --from boost is honoured in exit code. */
        {
            int eff_gate = sr.score;
            if (hlse_from_channel()) {
                int d = hlse_channel_delta(hlse_from_channel());
                eff_gate += d; if (eff_gate > 100) eff_gate = 100;
            }
            return eff_gate >= o.fail_threshold ? 1 : 0;
        }
    }
}
#endif /* HLSE_CORE_AS_LIB */
