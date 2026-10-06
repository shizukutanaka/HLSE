/* hlse_registry.c — stable HLSE-* pattern_id registry + printer.
 *
 * Extracted from hlse_core.c (split increment 2): the table is pure data
 * plus list_patterns() which touches nothing but printf. Keeping the
 * registry append-only is the contract; see the header comment below.
 */
#include "hlse_registry.h"

#include <stdio.h>
#include <string.h>

#include "hlse_core.h"    /* HLSE_VERSION */
#include "hlse_secrets.h" /* custom-pattern count + label getters */
#include "hlse_meta.h"    /* hlse_secret_pattern_id_r (CUSTOM slug) */
#include "hlse_util.h"    /* hlse_json_escape (custom labels are user text) */

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
    /* manifest-scanner package ids (hlse_cli.c --manifest emitters) */
    { "HLSE-PKG-HOOK",            "package",   "Manifest lifecycle hook executing code (install/prepare)" },
    { "HLSE-PKG-LOCKFILE",        "package",   "Lockfile resolved to an off-registry host" },
    { "HLSE-PKG-ALIAS",           "package",   "npm alias dependency pointing at a different package" },
    { "HLSE-PKG-VCS",             "package",   "VCS/git dependency source (unpinned or off-forge)" },
    { "HLSE-PKG-INDEX",           "package",   "Index URL in manifest pointing off the official registry" },
    { "HLSE-PKG-REGISTRY",        "package",   "Registry config pinning an untrusted registry" },
    { "HLSE-PKG-GOREPLACE",       "package",   "go.mod replace directive redirecting a module source" },
    { "HLSE-PKG-GOREPLACE-L",     "package",   "go.mod replace directive pointing at a local path" },
    { "HLSE-PKG-CARGOPATCH",      "package",   "Cargo [patch] section redirecting a crate source" },
    { "HLSE-PKG-CARGOTC",         "package",   "Cargo config pointing at an untrusted source/toolchain" },
    { "HLSE-PKG-PODSRC",          "package",   "Podfile source pointing off the trunk specs repo" },
    { "HLSE-PKG-GEMSOURCE",       "package",   "Gemfile source pointing off rubygems.org" },
    { "HLSE-PKG-NUGETSRC",        "package",   "NuGet.config package source off nuget.org" },
    { "HLSE-PKG-SWIFTURL",        "package",   "Package.swift dependency URL off the canonical forge" },
    { "HLSE-PKG-DFROM",           "package",   "Dockerfile FROM pulling a suspicious image" },
    { "HLSE-PKG-DPIPESHL",        "package",   "Dockerfile piping a remote script to a shell" },
    { "HLSE-PKG-DADD",            "package",   "Dockerfile ADD fetching a remote URL" },
    { "HLSE-PKG-DCOMPOSE",        "package",   "docker-compose hardening gap (privileged/host mounts)" },
    { "HLSE-PKG-GHAINJ",          "package",   "GitHub Actions expression injection in run: step" },
    { "HLSE-PKG-GHAPWN",          "package",   "pull_request_target pwn-request pattern" },
    { "HLSE-PKG-GHAPRT",          "package",   "pull_request_target checking out untrusted PR code" },
    { "HLSE-PKG-GHAUNPIN",        "package",   "GitHub Actions uses: not pinned to a commit SHA" },
    { "HLSE-PKG-IDEEXEC",         "package",   "IDE/task config executing arbitrary commands" },
    { "HLSE-PKG-MCPRISK",         "package",   "MCP server config declaring risky commands/tools" },
    { "HLSE-SECRET-DISCORD",      "secret",    "Discord bot token" },
    { "HLSE-SECRET-TELEGRAM",     "secret",    "Telegram bot token" },
    { "HLSE-SECRET-URI-CREDS",    "secret",    "Credentials embedded in a URI/DSN" },
    { "HLSE-SECRET-JWT-ALG-NONE", "secret",    "JWT with alg=none (signature bypass)" },
    { "HLSE-SECRET-SEED-PHRASE",  "secret",    "BIP-39 cryptocurrency seed/mnemonic phrase" },
    { "HLSE-TEXT-INVISIBLE",      "text",      "Invisible Unicode carrier characters in text" },
    { "HLSE-NET-C2",             "network",   "Suspicious network activity (C2 / exfiltration)" },
    { "HLSE-CLIP-HIJACK",         "clipboard", "Cryptocurrency clipboard hijack (clipper malware)" },
    { "HLSE-PROTECT-RANSOM",      "protect",   "Ransomware / destructive-malware indicator (file entropy, SMB canary, mass rename)" },
    /* audit finding ids (hlse_audit.c av_add slugs) — per-finding keys */
    { "HLSE-AUDIT-A1-SSHD-UNREADABLE",      "audit", "sshd_config unreadable or missing" },
    { "HLSE-AUDIT-A1-PERMIT-ROOT-LOGIN",    "audit", "sshd PermitRootLogin enabled" },
    { "HLSE-AUDIT-A1-PERMIT-ROOT-LOGIN-OK", "audit", "sshd PermitRootLogin safely disabled" },
    { "HLSE-AUDIT-A1-ROOT-LOGIN-DEFAULT",   "audit", "sshd PermitRootLogin at insecure default" },
    { "HLSE-AUDIT-A1-PASSWORD-AUTH",        "audit", "sshd PasswordAuthentication enabled" },
    { "HLSE-AUDIT-A1-PASSWORD-AUTH-DEFAULT","audit", "sshd PasswordAuthentication at default" },
    { "HLSE-AUDIT-A1-EMPTY-PASSWORDS",      "audit", "sshd PermitEmptyPasswords enabled" },
    { "HLSE-AUDIT-A1-MAX-AUTH-TRIES",       "audit", "sshd MaxAuthTries too permissive" },
    { "HLSE-AUDIT-A1-LOGIN-GRACE-TIME",     "audit", "sshd LoginGraceTime too permissive" },
    { "HLSE-AUDIT-A1-X11-FORWARDING",       "audit", "sshd X11Forwarding enabled" },
    { "HLSE-AUDIT-A1-TCP-FORWARDING",       "audit", "sshd TCP forwarding enabled" },
    { "HLSE-AUDIT-A1-PROTOCOL-V1",          "audit", "sshd protocol v1 enabled" },
    { "HLSE-AUDIT-A1-AUTHORIZED-KEYS-MODE", "audit", "authorized_keys file permissions too open" },
    { "HLSE-AUDIT-A2-SENSITIVE-FILE-MODE",  "audit", "Sensitive system file mode too permissive" },
    { "HLSE-AUDIT-A3-HOSTS-POISONING",      "audit", "hosts file entry redirecting a sensitive name" },
    { "HLSE-AUDIT-A3-CUSTOM-NAMESERVER",    "audit", "resolv.conf pointing at a custom nameserver" },
    { "HLSE-AUDIT-A3-HOSTS-UNREADABLE",     "audit", "hosts/resolv.conf unreadable" },
    { "HLSE-AUDIT-A4-CRON-ENTRY",           "audit", "Suspicious cron entry" },
    { "HLSE-AUDIT-A4-CRONTAB-PATTERN",      "audit", "Suspicious crontab pattern" },
    { "HLSE-AUDIT-A4-CRON-DIR-PATTERN",     "audit", "Suspicious cron.d entry" },
    { "HLSE-AUDIT-A5-PATH-DOT",             "audit", "PATH contains a '.' entry" },
    { "HLSE-AUDIT-A5-PATH-EMPTY",           "audit", "PATH contains an empty entry" },
    { "HLSE-AUDIT-A5-PATH-WRITABLE",        "audit", "PATH contains a world/group-writable dir" },
    { "HLSE-AUDIT-A5-PATH-CLEAN",           "audit", "PATH hygiene clean" },
    { "HLSE-AUDIT-A6-ALIAS-HIJACK",         "audit", "shell rc alias overriding a command" },
    { "HLSE-AUDIT-A6-FUNCTION-OVERRIDE",    "audit", "shell rc function overriding a command" },
    { "HLSE-AUDIT-A6-DEV-TCP-SHELL",        "audit", "shell rc /dev/tcp reverse shell" },
    { "HLSE-AUDIT-A6-NETCAT-E-SHELL",       "audit", "shell rc netcat -e reverse shell" },
    { "HLSE-AUDIT-A6-MKFIFO-NC-SHELL",      "audit", "shell rc mkfifo+nc reverse shell" },
    { "HLSE-AUDIT-A6-SOCAT-SHELL",          "audit", "shell rc socat reverse shell" },
    { "HLSE-AUDIT-A6-DOWNLOAD-PIPE-SHELL",  "audit", "shell rc curl|wget piped to a shell" },
    { "HLSE-AUDIT-A6-SHELL-INVOKE",         "audit", "shell rc invoking a shell" },
    { "HLSE-AUDIT-A6-PROMPT-COMMAND",       "audit", "shell rc PROMPT_COMMAND persistence" },
    { "HLSE-AUDIT-A6-LD-PRELOAD",           "audit", "shell rc LD_PRELOAD/LD_LIBRARY_PATH" },
    { "HLSE-AUDIT-A6-HOME-UNSET",           "audit", "shell rc HOME unset or redirected" },
    { "HLSE-AUDIT-A6-PROFILED-DEV-TCP",     "audit", "profile.d /dev/tcp reverse shell" },
    { "HLSE-AUDIT-A6-PROFILED-REVERSE-TOOL","audit", "profile.d reverse-shell tool" },
    { "HLSE-AUDIT-A6-PROFILED-DOWNLOAD-SHELL","audit","profile.d download-piped-to-shell" },
    { "HLSE-AUDIT-A6-SHELL-RC-CLEAN",       "audit", "shell rc files clean" },
    { "HLSE-AUDIT-A7-SUDOERS-NOPASSWD",     "audit", "sudoers NOPASSWD entry" },
    { "HLSE-AUDIT-A7-SUDOERSD-NOPASSWD",    "audit", "sudoers.d NOPASSWD entry" },
    { "HLSE-AUDIT-A7-SUDOERS-CLEAN",        "audit", "sudoers clean" },
    { "HLSE-AUDIT-A8-EXECSTART-SUSPICIOUS", "audit", "systemd unit suspicious ExecStart" },
    { "HLSE-AUDIT-A8-HOME-UNSET-UNITS",     "audit", "systemd user units with HOME unset" },
    { "HLSE-AUDIT-A8-NO-USER-UNITS",        "audit", "No user systemd units found" },
    { "HLSE-AUDIT-A8-UNITS-CLEAN",          "audit", "systemd units clean" },
    { "HLSE-AUDIT-AX-HOME-SECRET-MODE",     "audit", "Secret-bearing home file mode too open" }
};

/* Emit the full pattern-ID registry. JSON mode → an array of
 * {id, kind, description} objects under a "patterns" key; text mode → an
 * aligned table. Returns 0 (a meta-command, never a failure gate).          */
int
hlse_list_patterns(int json_out) {
    size_t n = sizeof(g_pattern_registry) / sizeof(g_pattern_registry[0]);
    int ncustom = hlse_custom_secret_pattern_count();
    size_t i;
    int ci;
    if (json_out) {
        /* The static registry strings are author-controlled constants, but
         * custom --patterns labels are user-controlled text — they go
         * through hlse_json_escape. */
        printf("{\"kind\":\"pattern_registry\",\"hlse_version\":\"" HLSE_VERSION
               "\",\"count\":%zu,\"patterns\":[", n + (size_t)ncustom);
        for (i = 0; i < n; i++) {
            printf("%s{\"id\":\"%s\",\"kind\":\"%s\",\"description\":\"%s\"}",
                   i > 0 ? "," : "",
                   g_pattern_registry[i].id,
                   g_pattern_registry[i].kind,
                   g_pattern_registry[i].desc);
        }
        for (ci = 0; ci < ncustom; ci++) {
            const char *label = hlse_custom_secret_pattern_label(ci);
            char idbuf[80], esc[256];
            if (!label) continue;
            hlse_json_escape(label, esc, sizeof(esc));
            printf(",{\"id\":\"%s\",\"kind\":\"secret\",\"description\":\"%s\"}",
                   hlse_secret_pattern_id_r(label, idbuf, sizeof(idbuf)),
                   esc);
        }
        printf("]}\n");
    } else {
        printf("HLSE pattern_id registry (%zu stable tokens, append-only)\n", n);
        for (i = 0; i < n; i++)
            printf("  %-28s [%-9s] %s\n",
                   g_pattern_registry[i].id,
                   g_pattern_registry[i].kind,
                   g_pattern_registry[i].desc);
        if (ncustom > 0) {
            printf("custom patterns (--patterns, %d registered)\n", ncustom);
            for (ci = 0; ci < ncustom; ci++) {
                const char *label = hlse_custom_secret_pattern_label(ci);
                char idbuf[80];
                if (!label) continue;
                printf("  %-28s [%-9s] %s\n",
                       hlse_secret_pattern_id_r(label, idbuf, sizeof(idbuf)),
                       "secret", label);
            }
        }
    }
    return 0;
}

