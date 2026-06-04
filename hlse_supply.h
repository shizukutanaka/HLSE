/*
 * hlse_supply.h — Supply Chain Defense Module API
 *
 * Three protection vectors:
 *   S1. Package typosquatting — detect "reqeusts" → "requests"
 *   S2. Pastejacking          — detect hostile commands in copied text
 *   S3. Network safety        — ARP poisoning, DNS hijacking, hosts redirect
 */

#ifndef HLSE_SUPPLY_H
#define HLSE_SUPPLY_H

#ifdef __cplusplus
extern "C" {
#endif

/* ── S1: Package Typosquatting ────────────────────────────────────────── */

#define HLSE_SUPPLY_MAX_MATCHES 5

typedef struct {
    char legit_name[64];     /* the real package this might be a typo of */
    char registry[16];       /* "pip", "npm", "cargo", "go" */
    int  distance;           /* Damerau-Levenshtein distance (1 or 2) */
} PackageMatch;

typedef struct {
    int          score;      /* 0..100 (0 = exact match found → safe) */
    int          n_matches;  /* number of close matches found */
    PackageMatch matches[HLSE_SUPPLY_MAX_MATCHES];
    char         reason[256];
} PackageVerdict;

/* Check a package name against known popular packages.
 * `ecosystem` can be "pip", "npm", "cargo", "go", or NULL (check all).
 * Returns score 0 if exact match found, 50-70 if likely typosquat.    */
PackageVerdict hlse_check_package(const char *pkg_name,
                                   const char *ecosystem);

/* ── S2: Pastejacking Detection ───────────────────────────────────────── */

#define HLSE_PASTE_MAX_REASONS 8

/* Signal bitmask for compound analysis */
#define PASTE_HIDDEN_NEWLINE  0x01
#define PASTE_CURL_PIPE_SH    0x02
#define PASTE_UNICODE_CONTROL 0x04
#define PASTE_SUDO_INJECTION  0x08
#define PASTE_ENCODED_PAYLOAD 0x10
#define PASTE_HISTORY_EVASION 0x20
#define PASTE_BACKGROUND_EXEC 0x40

typedef struct {
    int  score;              /* 0..100 */
    int  signals;            /* bitmask of PASTE_* signals */
    int  n_reasons;
    char reasons[HLSE_PASTE_MAX_REASONS][256];
} PasteVerdict;

/* Analyze text that a user is about to paste into a terminal.
 * Checks for hidden newlines, curl|sh pipes, Unicode tricks,
 * sudo injection, encoded payloads, history evasion.                  */
PasteVerdict hlse_check_paste(const char *text);

/* ── S3: Network Safety ───────────────────────────────────────────────── */

#define HLSE_NET_MAX_REASONS 8

typedef struct {
    int  score;              /* 0..100 */
    int  n_reasons;
    char reasons[HLSE_NET_MAX_REASONS][256];
} NetworkVerdict;

/* Read-only network safety check using /proc and /etc:
 *   - ARP table for duplicate MACs (MITM indicator)
 *   - DNS resolver legitimacy
 *   - /etc/hosts for banking domain redirects
 * No network access. No raw sockets. Root not required.               */
NetworkVerdict hlse_check_network(void);

#ifdef __cplusplus
}
#endif

#endif /* HLSE_SUPPLY_H */
