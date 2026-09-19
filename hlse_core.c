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
        if (o.git_history) {
            return hlse_scan_git_history(argv[idx + 1], o.json_out, o.sarif_out,
                               o.emit_fingerprints, o.fail_threshold);
        }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        {
            const char *root = argv[idx + 1];
            int threats = 0, files_scanned = 0, max_depth = 20;
            int gate_hits = 0;  /* findings at/above o.fail_threshold (exit gate) */
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
                                      hlse_file_verdict_pattern_id(&fv), NULL, NULL,
                                      o.emit_fingerprints);
                        if (sup) goto after_file_check;
                        threats++;
                        if (fv.score > max_score) max_score = fv.score;
                        if (fv.score >= o.fail_threshold) gate_hits++;
                        if (o.sarif_out) {
                            char msg[512] = {0};
                            int i;
                            for (i = 0; i < fv.n_reasons; i++) {
                                size_t l = strlen(msg);
                                snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                         i ? "; " : "", fv.reasons[i]);
                            }
                            hlse_sarif_add(sarif_path, 1, "file-masquerade",
                                      hlse_file_verdict_pattern_id(&fv),
                                      msg[0] ? msg : "file masquerade", fv.score);
                        } else if (o.json_out) {
                            int i;
                            char esc[512];
                            hlse_json_escape(fullpath, esc, sizeof(esc));
                            printf("{\"kind\":\"file\",\"hlse_version\":\"" HLSE_VERSION "\","
                                   "\"path\":\"%s\","
                                   "\"score\":%d,\"action\":\"%s\","
                                   "\"severity\":%d,\"reasons\":[",
                                   esc, fv.score, hlse_action_for_score(fv.score),
                                   hlse_severity_for_score(fv.score));
                            for (i = 0; i < fv.n_reasons; i++) {
                                hlse_json_escape(fv.reasons[i], esc, sizeof(esc));
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
                                 * hlse_file_classify_pattern()/file_masquerade_*()
                                 * accessors instead of an inline copy. */
                                const char *fpat = hlse_file_classify_pattern(&fv);
                                hlse_json_escape(fpat, esc, sizeof(esc)); printf(",\"pattern\":\"%s\"",      esc);
                                printf(",\"pattern_id\":\"%s\"", hlse_file_pattern_id(fpat));
                                hlse_json_escape(hlse_file_masquerade_objective(), esc, sizeof(esc)); printf(",\"objective\":\"%s\"", esc);
                                hlse_json_escape(hlse_file_masquerade_verify(),    esc, sizeof(esc)); printf(",\"verify\":\"%s\"",    esc);
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
                                hlse_json_escape(sf_tri, esc, sizeof(esc)); printf(",\"triage\":\"%s\"",       esc);
                                hlse_json_escape(sf_cas, esc, sizeof(esc)); printf(",\"cascade_risk\":\"%s\"", esc);
                            }
                            if (fv.score > 0 && fv.score < 60) {
                                const char *ex = hlse_exoneration_for("file", fv.score);
                                if (ex) {
                                    hlse_json_escape(ex, esc, sizeof(esc));
                                    printf(",\"exoneration\":\"%s\"", esc);
                                }
                            }
                            printf("}\n");
                        } else {
                            int i;
                            char db[8192];
                            printf("%-7s [%d]  %s\n",
                                   hlse_action_for_score(fv.score),
                                   fv.score,
                                   hlse_display_copy(db, sizeof(db), fullpath));
                            for (i = 0; i < fv.n_reasons; i++)
                                printf("  \xc2\xb7 %s\n", fv.reasons[i]);
                            if (fv.score >= 40) {
                                /* Perspective 101: shared with the JSON path
                                 * above (and both standalone `file` sites)
                                 * so plaintext and JSON never again describe
                                 * the same verdict with different wording. */
                                printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_file_classify_pattern(&fv));
                                printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_file_masquerade_objective());
                                printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_file_masquerade_verify());
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
                                /* Indirect prompt injection: an agent reading
                                 * a repo consumes these files directly, so the
                                 * poisoned-document/skill-file path runs
                                 * through `scan`, not just `text`. Checked on
                                 * the raw line — the carriers are invisible,
                                 * so nothing else here would notice them. */
                                {
                                    char inv_r[512];
                                    int inv = hlse_check_invisible_carriers(
                                        line, inv_r, sizeof(inv_r));
                                    if (inv > 0 &&
                                        !hlse_scan_suppress(sarif_path,
                                            "HLSE-TEXT-INVISIBLE", inv_r, line,
                                            o.emit_fingerprints))
                                    {
                                        threats++;
                                        if (inv > max_score) max_score = inv;
                                        if (inv >= o.fail_threshold) gate_hits++;
                                        if (!o.quiet && !o.json_out && !o.sarif_out)
                                            printf("  %s:%d: %s\n",
                                                   sarif_path, lineno, inv_r);
                                    }
                                }
                                SecretVerdict sv = hlse_scan_secrets(line);
                                if (sv.score >= 40) {
                                    int ai;
                                    /* P0-1: baseline/allowlist + inline
                                     * hlse:allow suppression. Distinguisher =
                                     * the redacted finding description (stable
                                     * per distinct secret, line-independent). */
                                    const char *spid = sv.n_findings > 0
                                        ? hlse_secret_pattern_id(sv.findings[0].type)
                                        : "HLSE-SECRET-GENERIC";
                                    const char *sdesc = sv.n_findings > 0
                                        ? sv.findings[0].description : "";
                                    if (hlse_scan_suppress(sarif_path, spid, sdesc, line, o.emit_fingerprints))
                                        continue;
                                    threats++;
                                    if (sv.score > max_score) max_score = sv.score;
                                    if (sv.score >= o.fail_threshold) gate_hits++;
                                    for (ai = 0; ai < sv.n_findings; ai++)
                                        asset_mask |=
                                            hlse_asset_class_of(sv.findings[ai].type);
                                    if (o.sarif_out) {
                                        char msg[512] = {0};
                                        int i;
                                        for (i = 0; i < sv.n_findings; i++) {
                                            size_t l = strlen(msg);
                                            snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                                     i ? "; " : "",
                                                     sv.findings[i].description);
                                        }
                                        hlse_sarif_add(sarif_path, lineno, "secret",
                                                  sv.n_findings > 0
                                                    ? hlse_secret_pattern_id(sv.findings[0].type)
                                                    : "HLSE-SECRET-GENERIC",
                                                  msg[0] ? msg : "secret", sv.score);
                                    } else if (o.json_out) {
                                        int i;
                                        char esc_p[512], et[64], ed[512];
                                        hlse_json_escape(fullpath, esc_p, sizeof(esc_p));
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
                                            hlse_json_escape(sv.findings[i].type, et, sizeof(et));
                                            hlse_json_escape(sv.findings[i].description, ed, sizeof(ed));
                                            printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                                                   i ? "," : "", et, ed);
                                        }
                                        printf("]");
                                        {
                                            const char *conf = hlse_secret_confidence(&sv);
                                            if (conf) {
                                                hlse_json_escape(conf, ed, sizeof(ed));
                                                printf(",\"confidence\":\"%s\"", ed);
                                            }
                                        }
                                        {
                                            const char *rem = hlse_remediation_for("secret", sv.score);
                                            if (rem) {
                                                hlse_json_escape(rem, ed, sizeof(ed));
                                                printf(",\"remediation\":\"%s\"", ed);
                                            }
                                        }
                                        if (sv.n_findings > 0) {
                                            const char *cav = hlse_secret_finding_caveat(sv.findings[0].type);
                                            if (cav) {
                                                hlse_json_escape(cav, ed, sizeof(ed));
                                                printf(",\"caveat\":\"%s\"", ed);
                                            }
                                        }
                                        if (sv.score >= 60 && sv.n_findings > 0) {
                                            const char *ftype = sv.findings[0].type;
                                            const char *sobj  = hlse_secret_objective_for(ftype);
                                            hlse_secret_pattern_label(ftype, esc_p, sizeof(esc_p));
                                            hlse_json_escape(esc_p, ed, sizeof(ed));
                                            printf(",\"pattern\":\"%s\"", ed);
                                            printf(",\"pattern_id\":\"%s\"", hlse_secret_pattern_id(ftype));
                                            if (sobj) {
                                                hlse_json_escape(sobj, ed, sizeof(ed));
                                                printf(",\"objective\":\"%s\"", ed);
                                            }
                                            hlse_json_escape(hlse_secret_verify_text(),  ed, sizeof(ed)); printf(",\"verify\":\"%s\"",       ed);
                                            hlse_json_escape(hlse_secret_triage_text(),  ed, sizeof(ed)); printf(",\"triage\":\"%s\"",       ed);
                                            hlse_json_escape(hlse_secret_cascade_text(), ed, sizeof(ed)); printf(",\"cascade_risk\":\"%s\"", ed);
                                        }
                                        if (sv.score > 0 && sv.score < 60) {
                                            const char *ex = hlse_exoneration_for("secret", sv.score);
                                            if (ex) {
                                                hlse_json_escape(ex, ed, sizeof(ed));
                                                printf(",\"exoneration\":\"%s\"", ed);
                                            }
                                        }
                                        printf("}\n");
                                    } else {
                                        int i;
                                        char db[8192];
                                        printf("%-7s [%d]  %s:%d\n",
                                               hlse_action_for_score(sv.score),
                                               sv.score,
                                               hlse_display_copy(db, sizeof(db),
                                                                 fullpath),
                                               lineno);
                                        for (i = 0; i < sv.n_findings; i++)
                                            printf("  \xc2\xb7 %s\n",
                                                   sv.findings[i].description);
                                        if (sv.n_findings > 0) {
                                            const char *cav = hlse_secret_finding_caveat(sv.findings[0].type);
                                            if (cav) printf("  \xe2\x9a\xa0 Caveat: %s\n", cav);
                                        }
                                        if (sv.score >= 60 && sv.n_findings > 0) {
                                            const char *ftype = sv.findings[0].type;
                                            const char *sobj  = hlse_secret_objective_for(ftype);
                                            char epat[128];
                                            hlse_secret_pattern_label(ftype, epat, sizeof(epat));
                                            printf("  \xe2\x96\xb8 Pattern: %s\n", epat);
                                            if (sobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", sobj);
                                            printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_secret_verify_text());
                                            printf("  \xe2\x9a\x91 Immediate action: %s\n", hlse_secret_triage_text());
                                            printf("  \xe2\x8a\x95 Also change: %s\n", hlse_secret_cascade_text());
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
                                                        url_buf, line,
                                                        o.emit_fingerprints))
                                                    goto url_advance;
                                                threats++;
                                                if (uv.score > max_score) max_score = uv.score;
                                                if (uv.score >= o.fail_threshold)
                                                    gate_hits++;
                                                if (o.sarif_out) {
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
                                                    hlse_sarif_add(sarif_path, lineno,
                                                              "phishing-url",
                                                              hlse_url_pattern_id(&uv),
                                                              msg, uv.score);
                                                } else if (o.json_out) {
                                                    char eu[2048];
                                                    hlse_json_escape(url_buf, eu, sizeof(eu));
                                                    printf("{\"kind\":\"url\",\"path\":\"%s\","
                                                           "\"line\":%d,\"url\":\"%s\","
                                                           "\"score\":%d,\"action\":\"%s\","
                                                           "\"reasons\":[",
                                                           fullpath, lineno, eu, uv.score,
                                                           hlse_action_for_score(uv.score));
                                                    { int kr;
                                                      for (kr = 0; kr < uv.n_reasons; kr++) {
                                                          char er[256];
                                                          hlse_json_escape(uv.reasons[kr], er, sizeof(er));
                                                          printf("%s\"%s\"", kr>0?",":"", er);
                                                      }
                                                    }
                                                    printf("]");
                                                    {
                                                        char ucf_buf[160];
                                                        int u_sig = hlse_confidence_for(&uv, ucf_buf, sizeof(ucf_buf));
                                                        if (u_sig > 0) {
                                                            hlse_json_escape(ucf_buf, eu, sizeof(eu));
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
                                                        if (upat)     { hlse_json_escape(upat,     eu, sizeof(eu)); printf(",\"pattern\":\"%s\"",      eu); }
                                                        if (upat)     { const char *upid = hlse_url_pattern_id(&uv); if (upid) printf(",\"pattern_id\":\"%s\"", upid); }
                                                        if (has_obj)  { hlse_json_escape(uobj_buf, eu, sizeof(eu)); printf(",\"objective\":\"%s\"",    eu); }
                                                        if (has_safe) { hlse_json_escape(usafe,    eu, sizeof(eu)); printf(",\"safe_url\":\"%s\"",     eu); }
                                                        if (uvrf)     { hlse_json_escape(uvrf,     eu, sizeof(eu)); printf(",\"verify\":\"%s\"",       eu); }
                                                    }
                                                    if (uv.score >= 60) {
                                                        const char *ucas = hlse_cascade_risk(&uv);
                                                        char utri_buf[512];
                                                        int has_tri  = hlse_compound_triage(&uv, utri_buf, sizeof(utri_buf));
                                                        if (has_tri)  { hlse_json_escape(utri_buf, eu, sizeof(eu)); printf(",\"triage\":\"%s\"",       eu); }
                                                        if (ucas)     { hlse_json_escape(ucas,     eu, sizeof(eu)); printf(",\"cascade_risk\":\"%s\"", eu); }
                                                    }
                                                    if (uv.score >= 40 && uv.score < 60) {
                                                        const char *uexon = hlse_url_exoneration(&uv);
                                                        if (uexon) {
                                                            hlse_json_escape(uexon, eu, sizeof(eu));
                                                            printf(",\"exoneration\":\"%s\"", eu);
                                                        }
                                                    }
                                                    printf("}\n");
                                                } else {
                                                    int k;
                                                    char db[8192], db2[2048];
                                                    printf("%-7s [%d]  %s:%d  %s\n",
                                                           hlse_action_for_score(uv.score),
                                                           uv.score,
                                                           hlse_display_copy(db, sizeof(db),
                                                                             fullpath),
                                                           lineno,
                                                           hlse_display_copy(db2, sizeof(db2),
                                                                             url_buf));
                                                    for (k = 0; k < uv.n_reasons; k++)
                                                        printf("  \xc2\xb7 %s\n", uv.reasons[k]);
                                                    hlse_print_url_advisories(url_buf, &uv);
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
            if (o.emit_fingerprints) {
                return 0;
            }
            if (o.sarif_out) {
                hlse_sarif_emit(HLSE_VERSION);
            } else if (!o.json_out) {
                if (threats == 0) {
                    const char *bs = hlse_blindspot_for("scan");
                    char db[8192];
                    printf("OK    %s (%d files scanned, 0 threats)\n",
                           hlse_display_copy(db, sizeof(db), root),
                           files_scanned);
                    if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
                } else {
                    char classes[256];
                    int nclasses = hlse_asset_mask_describe(asset_mask, classes,
                                                       sizeof(classes));
                    printf("\n%d threat(s) in %d files under %s\n",
                           threats, files_scanned, root);
                    if (gate_hits > 0 && o.fail_threshold != 60)
                        printf("  %d finding(s) exceeded the --fail-on threshold (%d)\n",
                               gate_hits, o.fail_threshold);
                    /* Immediate action: one-sentence triage keyed to the
                     * most severe asset class (or file/URL threats). */
                    printf("\xe2\x86\x92 Immediate action: %s\n",
                           hlse_scan_immediate_action((unsigned)asset_mask, nclasses));
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
                int nclasses = hlse_asset_mask_describe(asset_mask, classes,
                                                   sizeof(classes));
                hlse_json_escape(root, esc_root, sizeof(esc_root));
                printf("{\"kind\":\"scan_summary\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"target\":\"%s\","
                       "\"files_scanned\":%d,\"threats\":%d,"
                       "\"max_severity\":%d,"
                       "\"gate_hits\":%d,\"fail_threshold\":%d,"
                       "\"asset_classes\":%d,\"blast_radius\":\"%s\"",
                       esc_root, files_scanned, threats,
                       hlse_severity_for_score(max_score),
                       gate_hits, o.fail_threshold,
                       nclasses, classes);
                if (threats == 0) {
                    const char *bs = hlse_blindspot_for("scan");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                } else {
                    const char *ia = hlse_scan_immediate_action((unsigned)asset_mask, nclasses);
                    char esc_ia[512];
                    hlse_json_escape(ia, esc_ia, sizeof(esc_ia));
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

            if (o.json_out) {
                /* JSON output for protect.
                 * Perspective 100: this was the only verdict kind still
                 * missing hlse_version and severity — every other kind
                 * (url/text/file/secret/email/network/esp/package/paste/
                 * clipboard) has carried both since P84/P85; protect was
                 * never brought in line. */
                char esc_path[4096];
                hlse_json_escape(path, esc_path, sizeof(esc_path));
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
                        hlse_json_escape(pv.reasons[i], esc, sizeof(esc));
                        printf("%s\"%s\"", i > 0 ? "," : "", esc);
                    }
                }
                printf("]");
                if (pv.score == 0) {
                    const char *bs = hlse_blindspot_for("protect");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
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
                    hlse_json_escape(hlse_protect_pattern_text(), e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"HLSE-PROTECT-RANSOM\"");
                    hlse_json_escape(hlse_protect_objective_text(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                    hlse_json_escape(hlse_protect_verify_text(),    e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                }
                if (pv.score >= 60) {
                    char e[512];
                    hlse_json_escape(hlse_protect_triage_text(),  e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                    hlse_json_escape(hlse_protect_cascade_text(), e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("protect", pv.score);
                    if (ex) {
                        char e[512];
                        hlse_json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (pv.score == 0) {
                const char *bs = hlse_blindspot_for("protect");
                char db[8192];
                printf("OK    %s\n",
                       hlse_display_copy(db, sizeof(db), path));
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                char db[8192];
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(pv.score), pv.score,
                       hlse_display_copy(db, sizeof(db), path));
                for (i = 0; i < pv.n_reasons; i++) {
                    printf("  \xc2\xb7 %s\n", pv.reasons[i]);
                }
                if (pv.score >= 40) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_protect_pattern_text());
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_protect_objective_text());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_protect_verify_text());
                }
                if (pv.score >= 60) {
                    printf("  \xe2\x9a\x91 Immediate action: %s\n", hlse_protect_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", hlse_protect_cascade_text());
                }
                if (pv.score < 60) {
                    const char *ex = hlse_exoneration_for("protect", pv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return pv.score >= o.fail_threshold ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "esp") == 0) {
        /* EFI System Partition integrity (UEFI bootkit indicators). */
        const char *path = (argc > idx + 1) ? argv[idx + 1] : NULL;
        ProtectionVerdict pv = hlse_esp_verify(path);
        if (o.json_out) {
            int i;
            printf("{\"kind\":\"esp\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"reasons\":[",
                   pv.score, hlse_action_for_score(pv.score),
                   hlse_severity_for_score(pv.score));
            for (i = 0; i < pv.n_reasons; i++) {
                char esc[512];
                hlse_json_escape(pv.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]");
            {
                const char *bs = hlse_blindspot_for("esp");
                if (pv.score == 0 && bs) {
                    char esc_bs[512];
                    hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
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
                hlse_json_escape(hlse_esp_pattern_text(),   e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                printf(",\"pattern_id\":\"HLSE-ESP-BOOTKIT\"");
                hlse_json_escape(hlse_esp_objective_text(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                hlse_json_escape(hlse_esp_verify_text(),     e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                hlse_json_escape(hlse_esp_triage_text(),     e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                hlse_json_escape(hlse_esp_cascade_text(),    e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
            }
            if (pv.score > 0 && pv.score < 60) {
                const char *ex = hlse_exoneration_for("esp", pv.score);
                if (ex) {
                    char e[512];
                    hlse_json_escape(ex, e, sizeof(e));
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
                printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_esp_pattern_text());
                printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_esp_objective_text());
                printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_esp_verify_text());
                printf("  \xe2\x9a\x91 Immediate action: %s\n", hlse_esp_triage_text());
                printf("  \xe2\x8a\x95 Also change: %s\n", hlse_esp_cascade_text());
            } else {
                const char *ex = hlse_exoneration_for("esp", pv.score);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        return pv.score >= o.fail_threshold ? 1 : 0;
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
            eco = (argc > idx + 3) ? argv[idx + 3] : hlse_manifest_ecosystem(mpath);
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
                        got = hlse_manifest_name_npm(&cursor, &in_deps, name, sizeof(name));
                    else
                        got = hlse_manifest_name_pip(line, name, sizeof(name));
                    if (!got || name[0] == '\0') break;
                {
                    PackageVerdict pv = hlse_check_package(name, eco);
                    checked++;
                    if (pv.score >= 40) {
                        threats++;
                        if (pv.score > max_score) max_score = pv.score;
                        if (pv.score >= o.fail_threshold) gate_hits++;
                        if (o.sarif_out) {
                            char msg[512];
                            snprintf(msg, sizeof(msg), "%s",
                                     pv.reason[0] ? pv.reason
                                     : "dependency typosquat");
                            hlse_sarif_add(mpath, lineno, "package-typosquat",
                                      "HLSE-PKG-TYPOSQUAT", msg, pv.score);
                        } else if (o.json_out) {
                            char en[128];
                            int i;
                            hlse_json_escape(name, en, sizeof(en));
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
                            {
                                char db[8192];
                                printf("%-7s [%d]  %s (%s)\n",
                                       hlse_action_for_score(pv.score), pv.score,
                                       hlse_display_copy(db, sizeof(db), name),
                                       eco);
                            }
                            if (pv.reason[0])
                                printf("  \xc2\xb7 %s\n", pv.reason);
                        }
                    }
                }
                    if (!is_npm) break;   /* pip: one name per line */
                }  /* for(;;) drain-line */
            }
            fclose(mf);
            if (o.sarif_out) {
                hlse_sarif_emit(HLSE_VERSION);
            } else if (o.json_out) {
                char ep[4096];
                hlse_json_escape(mpath, ep, sizeof(ep));
                printf("{\"kind\":\"manifest_summary\",\"hlse_version\":\""
                       HLSE_VERSION "\",\"manifest\":\"%s\",\"ecosystem\":\"%s\","
                       "\"packages_checked\":%d,\"threats\":%d,"
                       "\"max_severity\":%d,\"gate_hits\":%d}\n",
                       ep, eco, checked, threats,
                       hlse_severity_for_score(max_score), gate_hits);
            } else if (threats == 0) {
                char db[8192];
                printf("OK    %s (%d packages checked, 0 typosquat risks)\n",
                       hlse_display_copy(db, sizeof(db), mpath), checked);
            } else {
                char db[8192];
                printf("\n%d suspicious package(s) of %d checked in %s\n",
                       threats, checked,
                       hlse_display_copy(db, sizeof(db), mpath));
            }
            return gate_hits > 0 ? 1 : 0;
        }
        {
            const char *eco = (argc > idx + 2) ? argv[idx + 2] : NULL;
            PackageVerdict pv = hlse_check_package(argv[idx + 1], eco);
            {
                const char *aar[1]; int aqn = 0;
                if (pv.reason[0]) { aar[0] = pv.reason; aqn = 1; }
                hlse_alert_emit("package", pv.score,
                    hlse_severity_for_score(pv.score), argv[idx + 1], aar, aqn);
            }
            if (o.json_out) {
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
                    /* reason non-empty => exact match to a known package;
                     * empty => unknown name, which we cannot verify offline. */
                    const char *bs = hlse_blindspot_for(
                        pv.reason[0] ? "package" : "package_unverified");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
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
                    hlse_json_escape(hlse_package_pattern_text(), e, sizeof(e));
                    printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"HLSE-PKG-TYPOSQUAT\"");
                    hlse_json_escape(hlse_package_objective_text(), e, sizeof(e));
                    printf(",\"objective\":\"%s\"", e);
                    hlse_json_escape(hlse_package_verify_text(), e, sizeof(e));
                    printf(",\"verify\":\"%s\"", e);
                }
                if (pv.score >= 60) {
                    char e[512];
                    hlse_json_escape(hlse_package_triage_text(), e, sizeof(e));
                    printf(",\"triage\":\"%s\"", e);
                    hlse_json_escape(hlse_package_cascade_text(), e, sizeof(e));
                    printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("package", pv.score);
                    if (ex) {
                        char e[512];
                        hlse_json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (pv.score == 0) {
                const char *bs = hlse_blindspot_for(
                    pv.reason[0] ? "package" : "package_unverified");
                char db[8192];
                printf("OK    %s\n",
                       hlse_display_copy(db, sizeof(db), argv[idx + 1]));
                /* Mirror the URL canonical-confirmation line: say explicitly
                 * when the name IS recognised, so "OK" is not ambiguous
                 * between "known good" and "never heard of it". */
                if (pv.reason[0]) printf("  \xe2\x9c\x94 %s\n", pv.reason);
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                char db[8192];
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(pv.score), pv.score,
                       hlse_display_copy(db, sizeof(db), argv[idx + 1]));
                if (pv.reason[0])
                    printf("  \xc2\xb7 %s\n", pv.reason);
                if (pv.score >= 40) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_package_pattern_text());
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_package_objective_text());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_package_verify_text());
                }
                if (pv.score >= 60) {
                    printf("  \xe2\x9a\x91 If you acted: %s\n", hlse_package_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", hlse_package_cascade_text());
                }
                if (pv.score < 60) {
                    const char *ex = hlse_exoneration_for("package", pv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return pv.score >= o.fail_threshold ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "paste") == 0) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s paste \"<command text>\"\n", argv[0]);
            return 2;
        }
        {
            PasteVerdict pv = hlse_check_paste(argv[idx + 1]);
            {
                const char *aar[16]; int aq, aqn = pv.n_reasons;
                if (aqn > 16) aqn = 16;
                for (aq = 0; aq < aqn; aq++) aar[aq] = pv.reasons[aq];
                hlse_alert_emit("paste", pv.score,
                    hlse_severity_for_score(pv.score), argv[idx + 1], aar, aqn);
            }
            if (o.json_out) {
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
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
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
                    if (ppat) { char e[512]; hlse_json_escape(ppat,e,sizeof(e)); printf(",\"pattern\":\"%s\"",e); }
                    if (ppat) { const char *pid = hlse_text_pattern_id(&ptv); if (pid) printf(",\"pattern_id\":\"%s\"",pid); }
                    if (pobj) { char e[512]; hlse_json_escape(pobj,e,sizeof(e)); printf(",\"objective\":\"%s\"",e); }
                    if (pvrf) { char e[512]; hlse_json_escape(pvrf,e,sizeof(e)); printf(",\"verify\":\"%s\"",e); }
                    if (pv.score >= 60) {
                        const char *ptri, *pcas;
                        ptri = hlse_text_triage(&ptv);
                        pcas = hlse_text_cascade(&ptv);
                        if (ptri) { char e[512]; hlse_json_escape(ptri,e,sizeof(e)); printf(",\"triage\":\"%s\"",e); }
                        if (pcas) { char e[512]; hlse_json_escape(pcas,e,sizeof(e)); printf(",\"cascade_risk\":\"%s\"",e); }
                    }
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("paste", pv.score);
                    if (ex) {
                        char e[512];
                        hlse_json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf(",\"reasons\":[");
                for (i = 0; i < pv.n_reasons; i++) {
                    char esc[512];
                    hlse_json_escape(pv.reasons[i], esc, sizeof(esc));
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
                     * hlse_print_text_advisories internally gates verify at >=40 and
                     * triage/cascade_risk at >=60 (Perspective 95). */
                    TextVerdict ptv;
                    memset(&ptv, 0, sizeof(ptv));
                    ptv.score = pv.score;
                    ptv.n_reasons = 1;
                    snprintf(ptv.reasons[0], sizeof(ptv.reasons[0]),
                             "Shell-pipe: paste-and-run pastejacking");
                    hlse_print_text_advisories(&ptv);
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("paste", pv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return pv.score >= o.fail_threshold ? 1 : 0;
        }
    }

    if (strcmp(argv[idx], "network") == 0) {
        NetworkVerdict nv = hlse_check_network();
        {
            const char *aar[16]; int aq, aqn = nv.n_reasons;
            if (aqn > 16) aqn = 16;
            for (aq = 0; aq < aqn; aq++) aar[aq] = nv.reasons[aq];
            hlse_alert_emit("network", nv.score,
                hlse_severity_for_score(nv.score), "(network)", aar, aqn);
        }
        if (o.json_out) {
            int i;
            printf("{\"kind\":\"network\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"reasons\":[",
                   nv.score, hlse_action_for_score(nv.score),
                   hlse_severity_for_score(nv.score));
            for (i = 0; i < nv.n_reasons; i++) {
                char esc[512];
                hlse_json_escape(nv.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]");
            if (nv.score == 0) {
                const char *bs = hlse_blindspot_for("network");
                if (bs) {
                    char esc_bs[512];
                    hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
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
                hlse_json_escape(hlse_net_pattern_text(), e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                printf(",\"pattern_id\":\"HLSE-NET-C2\"");
                hlse_json_escape(hlse_network_objective_text(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                hlse_json_escape(hlse_network_verify_text(),    e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
            }
            if (nv.score >= 60) {
                char e[512];
                hlse_json_escape(hlse_network_triage_text(),  e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                hlse_json_escape(hlse_network_cascade_text(), e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
            }
            if (nv.score > 0 && nv.score < 60) {
                const char *ex = hlse_exoneration_for("network", nv.score);
                if (ex) {
                    char e[512];
                    hlse_json_escape(ex, e, sizeof(e));
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
                printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_net_pattern_text());
                printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_network_objective_text());
                printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_network_verify_text());
            }
            if (nv.score >= 60) {
                printf("  \xe2\x9a\x91 Immediate action: %s\n", hlse_network_triage_text());
                printf("  \xe2\x8a\x95 Also change: %s\n", hlse_network_cascade_text());
            }
            if (nv.score < 60) {
                const char *ex = hlse_exoneration_for("network", nv.score);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        return nv.score >= o.fail_threshold ? 1 : 0;
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
            hlse_read_stdin_all(stdin_buf, sizeof(stdin_buf));
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
            if (o.json_out) {
                int i;
                printf("{\"kind\":\"secret\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,\"findings\":[",
                       sv.score, hlse_action_for_score(sv.score),
                       hlse_severity_for_score(sv.score));
                for (i = 0; i < sv.n_findings; i++) {
                    char et[64], ed[512];
                    hlse_json_escape(sv.findings[i].type, et, sizeof(et));
                    hlse_json_escape(sv.findings[i].description, ed, sizeof(ed));
                    printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                           i > 0 ? "," : "", et, ed);
                }
                printf("]");
                printf(",\"confidence\":\"%s\"", hlse_secret_confidence(&sv));
                {
                    const char *rem = hlse_remediation_for("secret", sv.score);
                    if (rem) {
                        char erm[512];
                        hlse_json_escape(rem, erm, sizeof(erm));
                        printf(",\"remediation\":\"%s\"", erm);
                    }
                }
                if (sv.score == 0) {
                    const char *bs = hlse_blindspot_for("secret");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (sv.n_findings > 0) {
                    /* Perspective 99: unconditional on score — a Stripe
                     * publishable key is public-by-design at any score,
                     * not just a probabilistic false-positive hedge. */
                    const char *cav = hlse_secret_finding_caveat(sv.findings[0].type);
                    if (cav) {
                        char e[768];
                        hlse_json_escape(cav, e, sizeof(e));
                        printf(",\"caveat\":\"%s\"", e);
                    }
                }
                if (sv.score >= 60 && sv.n_findings > 0) {
                    const char *ftype = sv.findings[0].type;
                    const char *sobj  = hlse_secret_objective_for(ftype);
                    char e[512], epat[128];
                    hlse_secret_pattern_label(ftype, epat, sizeof(epat));
                    hlse_json_escape(epat, e, sizeof(e));
                    printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"%s\"", hlse_secret_pattern_id(ftype));
                    if (sobj) { hlse_json_escape(sobj, e, sizeof(e)); printf(",\"objective\":\"%s\"", e); }
                    hlse_json_escape(hlse_secret_verify_text(),  e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                    hlse_json_escape(hlse_secret_triage_text(),  e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                    hlse_json_escape(hlse_secret_cascade_text(), e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (sv.score > 0 && sv.score < 60) {
                    const char *ex = hlse_exoneration_for("secret", sv.score);
                    if (ex) {
                        char e[512];
                        hlse_json_escape(ex, e, sizeof(e));
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
                    const char *cav = hlse_secret_finding_caveat(sv.findings[0].type);
                    if (cav) printf("  \xe2\x9a\xa0 Caveat: %s\n", cav);
                }
                if (sv.score >= 60 && sv.n_findings > 0) {
                    const char *ftype = sv.findings[0].type;
                    const char *sobj  = hlse_secret_objective_for(ftype);
                    char epat[128];
                    hlse_secret_pattern_label(ftype, epat, sizeof(epat));
                    printf("  \xe2\x96\xb8 Pattern: %s\n", epat);
                    if (sobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", sobj);
                    printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_secret_verify_text());
                    printf("  \xe2\x9a\x91 Immediate action: %s\n", hlse_secret_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", hlse_secret_cascade_text());
                }
                if (sv.score > 0 && sv.score < 60) {
                    const char *ex = hlse_exoneration_for("secret", sv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
                if (rem) printf("  \xe2\x86\x92 Action: %s\n", rem);
            }
            return sv.score >= o.fail_threshold ? 1 : 0;
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
        if (hlse_from_channel()) {
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
            hlse_read_stdin_all(stdin_buf, sizeof(stdin_buf));
            headers = stdin_buf;
        } else {
            headers = argv[idx + 1];
        }
        {
            EmailVerdict ev = hlse_check_email_headers(headers);
            {
                const char *aar[16]; int aq, aqn = ev.n_reasons;
                if (aqn > 16) aqn = 16;
                for (aq = 0; aq < aqn; aq++) aar[aq] = ev.reasons[aq];
                hlse_alert_emit("email", ev.score,
                    hlse_severity_for_score(ev.score), "(email headers)", aar, aqn);
            }
            const char *rem = hlse_remediation_for("email", ev.score);
            /* Header forensics (SPF/DKIM/Reply-To/Received) is blind to the
             * message BODY's social engineering. Run text analysis on the same
             * input and surface the attack-pattern lens as ADVISORY only — the
             * email score is unchanged (preserves F1), but a BEC/urgency body
             * that header checks alone would miss is now named. */
            TextVerdict bodytv = hlse_check_text(headers);
            const char *body_pat = hlse_classify_text_attack(&bodytv);
            if (o.json_out) {
                int i;
                printf("{\"kind\":\"email\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,\"reasons\":[",
                       ev.score, hlse_action_for_score(ev.score),
                       hlse_severity_for_score(ev.score));
                for (i = 0; i < ev.n_reasons; i++) {
                    char esc[512];
                    hlse_json_escape(ev.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]");
                if (ev.score == 0 && !body_pat) {
                    const char *bs = hlse_blindspot_for("email");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (body_pat) {
                    char epat[256];
                    hlse_json_escape(body_pat, epat, sizeof(epat));
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
                    if (bpat) { hlse_json_escape(bpat,e,sizeof(e)); printf(",\"pattern\":\"%s\"",e); }
                    if (bpat) {
                        const char *bid = hlse_text_pattern_id(&btv_hi);
                        if (bid) printf(",\"pattern_id\":\"%s\"", bid);
                    }
                    if (bex && btv_hi.score >= 15 && btv_hi.score < 60) {
                        hlse_json_escape(bex,e,sizeof(e)); printf(",\"exoneration\":\"%s\"",e);
                    }
                    /* Perspective 95: verify now fires from the ALERT floor
                     * (btv_hi.score >= 40, the combined header/body score) —
                     * objective/triage/cascade_risk stay gated on ev.score
                     * >= 60 (header-confidence threshold, unchanged). */
                    if (bvrf && btv_hi.score >= 40) {
                        hlse_json_escape(bvrf,e,sizeof(e)); printf(",\"verify\":\"%s\"",e);
                    }
                    if (ev.score >= 60) {
                        if (bobj) { hlse_json_escape(bobj,e,sizeof(e)); printf(",\"objective\":\"%s\"",e); }
                        if (btri) { hlse_json_escape(btri,e,sizeof(e)); printf(",\"triage\":\"%s\"",e); }
                        if (bcas) { hlse_json_escape(bcas,e,sizeof(e)); printf(",\"cascade_risk\":\"%s\"",e); }
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
                    if (epat2) { hlse_json_escape(epat2,e,sizeof(e)); printf(",\"pattern\":\"%s\"",e); }
                    if (epat2) { const char *pid = hlse_text_pattern_id(&etv); if (pid) printf(",\"pattern_id\":\"%s\"",pid); }
                    if (eobj)  { hlse_json_escape(eobj,e,sizeof(e));  printf(",\"objective\":\"%s\"",e); }
                    if (evrf)  { hlse_json_escape(evrf,e,sizeof(e));  printf(",\"verify\":\"%s\"",e); }
                    if (etri)  { hlse_json_escape(etri,e,sizeof(e));  printf(",\"triage\":\"%s\"",e); }
                    if (ecas)  { hlse_json_escape(ecas,e,sizeof(e));  printf(",\"cascade_risk\":\"%s\"",e); }
                } else if (ev.score > 0) {
                    /* Borderline header score (1-59): emit signal_count, confidence, and exoneration */
                    printf(",\"signal_count\":1");
                    TextVerdict etv;
                    const char *econn = hlse_exoneration_for("email", ev.score);
                    if (econn) {
                        char e[512];
                        hlse_json_escape(econn, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                    memset(&etv, 0, sizeof(etv));
                    etv.score = ev.score;
                    printf(",\"confidence\":\"partial signal — some email header concerns but not conclusive spoofing\"");
                }
                if (rem) {
                    char erm[512];
                    hlse_json_escape(rem, erm, sizeof(erm));
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
            return ev.score >= o.fail_threshold ? 1 : 0;
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
            {
                const char *aar[1]; int aqn = 0;
                if (cv.reason[0]) { aar[0] = cv.reason; aqn = 1; }
                hlse_alert_emit("clipboard", cv.score,
                    hlse_severity_for_score(cv.score),
                    cv.swapped[0] ? cv.swapped : "(clipboard)", aar, aqn);
            }
            const char *rem = hlse_remediation_for("clipboard", cv.score);
            if (o.json_out) {
                char eo[256], es[256], er[512], erm[512];
                hlse_json_escape(cv.original, eo, sizeof(eo));
                hlse_json_escape(cv.swapped, es, sizeof(es));
                hlse_json_escape(cv.reason, er, sizeof(er));
                hlse_json_escape(rem ? rem : "", erm, sizeof(erm));
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
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (cv.score >= 60) {
                    char e[512];
                    hlse_json_escape(hlse_clipboard_pattern_text(), e, sizeof(e));
                    printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"HLSE-CLIP-HIJACK\"");
                    hlse_json_escape(hlse_clipboard_objective_text(), e, sizeof(e));
                    printf(",\"objective\":\"%s\"", e);
                    hlse_json_escape(hlse_clipboard_verify_text(), e, sizeof(e));
                    printf(",\"verify\":\"%s\"", e);
                    hlse_json_escape(hlse_clipboard_triage_text(), e, sizeof(e));
                    printf(",\"triage\":\"%s\"", e);
                    hlse_json_escape(hlse_clipboard_cascade_text(), e, sizeof(e));
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
                    printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_clipboard_pattern_text());
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_clipboard_objective_text());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_clipboard_verify_text());
                    printf("  \xe2\x9a\x91 If you acted: %s\n", hlse_clipboard_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", hlse_clipboard_cascade_text());
                }
            }
            return cv.score >= o.fail_threshold ? 1 : 0;
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
            if (o.json_out) {
                int i;
                char esc[512];
                hlse_json_escape(argv[idx + 1], esc, sizeof(esc));
                printf("{\"kind\":\"file\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"path\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"severity\":%d,\"reasons\":[",
                       esc, fv.score, hlse_action_for_score(fv.score),
                       hlse_severity_for_score(fv.score));
                for (i = 0; i < fv.n_reasons; i++) {
                    hlse_json_escape(fv.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]");
                if (fv.score == 0) {
                    const char *bs = hlse_blindspot_for("file");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
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
                    const char *fpat = hlse_file_classify_pattern(&fv);
                    char e[512];
                    hlse_json_escape(fpat, e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"%s\"", hlse_file_pattern_id(fpat));
                    hlse_json_escape(hlse_file_masquerade_objective(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                    hlse_json_escape(hlse_file_masquerade_verify(),    e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
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
                    hlse_json_escape(file_tri, e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                    hlse_json_escape(file_cas, e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (fv.score > 0 && fv.score < 60) {
                    const char *ex = hlse_exoneration_for("file", fv.score);
                    if (ex) {
                        char e[512];
                        hlse_json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (fv.score == 0) {
                const char *bs = hlse_blindspot_for("file");
                char db[8192];
                printf("OK    %s\n",
                       hlse_display_copy(db, sizeof(db), argv[idx + 1]));
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                char db[8192];
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(fv.score), fv.score,
                       hlse_display_copy(db, sizeof(db), argv[idx + 1]));
                for (i = 0; i < fv.n_reasons; i++)
                    printf("  \xc2\xb7 %s\n", fv.reasons[i]);
                if (fv.score >= 40) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_file_classify_pattern(&fv));
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_file_masquerade_objective());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_file_masquerade_verify());
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
            return fv.score >= o.fail_threshold ? 1 : 0;
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
        if (o.json_out) {
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
                    ? hlse_audit_remediation_for(av.findings[i].description)
                    : NULL;
                hlse_json_escape(av.findings[i].description, esc, sizeof(esc));
                printf("%s{\"severity\":%d,\"description\":\"%s\"",
                       i > 0 ? "," : "",
                       av.findings[i].severity, esc);
                if (fix) {
                    char efix[512];
                    hlse_json_escape(fix, efix, sizeof(efix));
                    printf(",\"fix\":\"%s\"", efix);
                }
                printf("}");
            }
            printf("]");
            if (av.score == 0) {
                const char *bs = hlse_blindspot_for("audit");
                if (bs) {
                    char esc_bs[512];
                    hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
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
                  hlse_json_escape(ns, ens, sizeof(ens));
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
                int s = (int)av.findings[i].severity;
                if (s < 0 || s > 5) s = 0;
                printf("  [%4s] %s\n", sev_str[s],
                       av.findings[i].description);
                if (s >= 4) {
                    const char *fix = hlse_audit_remediation_for(
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
        return av.score >= o.fail_threshold ? 1 : 0;
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
            if (o.json_out) {
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
                hlse_print_json_text(argv[idx + 1], &tv);
            } else if (sr.score == 0) {
                /* Channel-only risk: content scored 0 but delivery channel adds prior */
                if (hlse_from_channel()) {
                    int d = hlse_channel_delta(hlse_from_channel());
                    if (d > 0) {
                        const char *ch_rsn = hlse_channel_reason(hlse_from_channel());
                        const char *bs2 = hlse_blindspot_for("text");
                        char db[8192];
                        printf("%-7s [%d]  (text) %.60s%s\n",
                               hlse_action_for_score(d), d,
                               hlse_display_copy(db, sizeof(db), argv[idx + 1]),
                               strlen(argv[idx + 1]) > 60 ? "..." : "");
                        if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                        if (bs2) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs2);
                        return d >= o.fail_threshold ? 1 : 0;
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
                if (hlse_from_channel()) {
                    int d = hlse_channel_delta(hlse_from_channel());
                    eff += d; if (eff > 100) eff = 100;
                    ch_rsn = hlse_channel_reason(hlse_from_channel());
                }
                {
                    char db[8192];
                    printf("%-7s [%d]  (text) %.60s%s\n",
                           hlse_action_for_score(eff),
                           eff,
                           hlse_display_copy(db, sizeof(db), argv[idx + 1]),
                           strlen(argv[idx + 1]) > 60 ? "..." : "");
                }
                for (i = 0; i < sr.n_reasons; i++) {
                    if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                    printf("  \xc2\xb7 %s\n", sr.reasons[i]);
                }
                if (sr.is_url) {
                    Verdict uv = check_url(argv[idx + 1]);
                    hlse_print_url_advisories(argv[idx + 1], &uv);
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
                    hlse_print_text_advisories(&tv);
                    ex = hlse_text_exoneration(&tv);
                }
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
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
                Verdict uv = check_url(input);
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
                Verdict uv = check_url(input);
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
