/*
 * hlse_audit.c — System Hardening Quick-Audit
 *
 * Scans common attack surfaces for misconfigurations:
 *
 *   A1. SSH config audit      — PermitRootLogin, PasswordAuth, authorized_keys
 *   A2. Permission audit      — world-readable secrets, SUID anomalies
 *   A3. DNS/hosts poisoning   — /etc/hosts entries for banking/exchange domains
 *   A4. Cron persistence      — suspicious cron entries (wget, curl|sh, base64)
 *   A5. Firewall status       — iptables/nftables rule count
 *
 * All checks are read-only and non-destructive.
 * No network access. No root required (though some checks are richer
 * with root access).
 *
 * Build: gcc -O2 -c hlse_audit.c -I.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>

#include "hlse_audit.h"
#include "hlse_util.h"

/* ─── helpers ─────────────────────────────────────────────────────────── */

static void
av_add(AuditVerdict *v, int delta, AuditSeverity sev,
       const char *fmt, ...) {
    va_list ap;
    if (v->n_findings >= HLSE_AUDIT_MAX_FINDINGS) return;
    v->findings[v->n_findings].severity = sev;
    v->score += delta;
    if (v->score > 100) v->score = 100;
    va_start(ap, fmt);
    vsnprintf(v->findings[v->n_findings].description,
              sizeof(v->findings[0].description), fmt, ap);
    va_end(ap);
    v->n_findings++;
}

static int
file_contains(const char *path, const char *needle) {
    FILE *fp = hlse_open_system_file(path);
    char line[2048];
    if (!fp) return -1; /* cannot read */
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, needle)) { fclose(fp); return 1; }
    }
    fclose(fp);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * A1: SSH Configuration Audit
 * ═══════════════════════════════════════════════════════════════════════ */

AuditVerdict
hlse_audit_ssh(void) {
    AuditVerdict v;
    const char *sshd_conf = "/etc/ssh/sshd_config";

    memset(&v, 0, sizeof(v));

    /* Check sshd_config */
    {
        FILE *fp = hlse_open_system_file(sshd_conf);
        if (!fp) {
            av_add(&v, 0, AUDIT_INFO, "A1: Cannot read %s (no SSH server?)",
                   sshd_conf);
        } else {
            char line[1024];
            int root_login_found = 0;
            int password_auth_found = 0;

            while (fgets(line, sizeof(line), fp)) {
                /* Skip comments */
                char *p = line;
                while (*p == ' ' || *p == '\t') p++;
                if (*p == '#' || *p == '\n') continue;

                if (strstr(p, "PermitRootLogin")) {
                    root_login_found = 1;
                    if (strstr(p, "yes")) {
                        av_add(&v, 30, AUDIT_HIGH,
                            "A1: PermitRootLogin yes — root SSH access enabled");
                    } else if (strstr(p, "no") || strstr(p, "prohibit-password")) {
                        av_add(&v, 0, AUDIT_PASS,
                            "A1: PermitRootLogin properly restricted");
                    }
                }
                if (strstr(p, "PasswordAuthentication")) {
                    password_auth_found = 1;
                    if (strstr(p, "yes")) {
                        av_add(&v, 20, AUDIT_MEDIUM,
                            "A1: PasswordAuthentication yes — brute-force risk");
                    }
                }
                if (strncmp(p, "Protocol", 8) == 0 && strstr(p, "1")) {
                    av_add(&v, 40, AUDIT_HIGH,
                        "A1: Protocol 1 enabled — SSHv1 is cryptographically broken");
                }
                if (strncmp(p, "MaxAuthTries", 12) == 0) {
                    int tries = 0;
                    const char *tp = p + 12;
                    while (*tp == ' ' || *tp == '\t') tp++;
                    tries = atoi(tp);
                    if (tries > 3) {
                        av_add(&v, 10, AUDIT_LOW,
                            "A1: MaxAuthTries %d > 3 — consider reducing to "
                            "limit brute-force attempts", tries);
                    }
                }
                if (strncmp(p, "PermitEmptyPasswords", 20) == 0
                    && strstr(p, "yes")) {
                    av_add(&v, 50, AUDIT_HIGH,
                        "A1: PermitEmptyPasswords yes — accounts with no "
                        "password are accessible over SSH");
                }
                if (strncmp(p, "X11Forwarding", 13) == 0 && strstr(p, "yes")) {
                    av_add(&v, 15, AUDIT_MEDIUM,
                        "A1: X11Forwarding yes — enables display forwarding "
                        "which can be abused for screen capture / keylogging");
                }
                if (strncmp(p, "AllowTcpForwarding", 18) == 0 && strstr(p, "yes")) {
                    av_add(&v, 15, AUDIT_MEDIUM,
                        "A1: AllowTcpForwarding yes — enables TCP tunneling, "
                        "allowing port-forwarding pivots through this host");
                }
                if (strncmp(p, "LoginGraceTime", 14) == 0) {
                    int grace = 0;
                    const char *gp = p + 14;
                    while (*gp == ' ' || *gp == '\t') gp++;
                    grace = atoi(gp);
                    if (grace > 60 || grace == 0) {
                        av_add(&v, 5, AUDIT_LOW,
                            "A1: LoginGraceTime %d — consider setting to 30s "
                            "to limit connection slot exhaustion", grace);
                    }
                }
            }
            fclose(fp);

            if (!root_login_found) {
                av_add(&v, 15, AUDIT_MEDIUM,
                    "A1: PermitRootLogin not explicitly set (default may be 'yes')");
            }
            if (!password_auth_found) {
                av_add(&v, 10, AUDIT_LOW,
                    "A1: PasswordAuthentication not explicitly set");
            }
        }
    }

    /* Check ~/.ssh/authorized_keys permissions */
    {
        const char *home = getenv("HOME");
        if (home) {
            char ak_path[512];
            struct stat st;
            snprintf(ak_path, sizeof(ak_path), "%s/.ssh/authorized_keys", home);
            if (stat(ak_path, &st) == 0) {
                if (st.st_mode & 0077) {
                    av_add(&v, 25, AUDIT_HIGH,
                        "A1: authorized_keys is group/world-accessible "
                        "(mode %04o)", st.st_mode & 0777);
                }
            }
        }
    }

    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * A2: Permission Audit
 * ═══════════════════════════════════════════════════════════════════════ */

AuditVerdict
hlse_audit_permissions(void) {
    AuditVerdict v;
    memset(&v, 0, sizeof(v));

    /* Check common secret files for world-readable permissions */
    {
        const char *sensitive_files[] = {
            "/etc/shadow", "/etc/gshadow",
            NULL
        };
        int i;
        for (i = 0; sensitive_files[i]; i++) {
            struct stat st;
            if (stat(sensitive_files[i], &st) == 0) {
                if (st.st_mode & 0004) {
                    av_add(&v, 40, AUDIT_CRITICAL,
                        "A2: %s is world-readable (mode %04o)",
                        sensitive_files[i], st.st_mode & 0777);
                }
            }
        }
    }

    /* Check home directory credential and key files */
    {
        const char *home = getenv("HOME");
        if (home) {
            /* { relative path, max permissive bits, score, description } */
            static const struct {
                const char *rel;
                unsigned    bad_bits;  /* mode bits that trigger alert */
                int         score;
                const char *label;
            } HOME_SECRETS[] = {
                { ".env",              0077, 25, "A2: ~/.env is group/world-accessible" },
                { ".aws/credentials",  0077, 35, "A2: ~/.aws/credentials is group/world-accessible" },
                { ".ssh/id_rsa",       0077, 40, "A2: SSH private key ~/.ssh/id_rsa is group/world-accessible" },
                { ".ssh/id_ed25519",   0077, 40, "A2: SSH private key ~/.ssh/id_ed25519 is group/world-accessible" },
                { ".ssh/id_ecdsa",     0077, 40, "A2: SSH private key ~/.ssh/id_ecdsa is group/world-accessible" },
                { ".netrc",            0077, 35, "A2: ~/.netrc (FTP/curl credentials) is group/world-accessible" },
                { ".pgpass",           0077, 30, "A2: ~/.pgpass (PostgreSQL passwords) is group/world-accessible" },
                { ".gnupg/secring.gpg",0077, 35, "A2: GPG secret keyring is group/world-accessible" },
                /* Container / cloud / package credential files */
                { ".docker/config.json", 0077, 35, "A2: ~/.docker/config.json (Docker auth) is group/world-accessible" },
                { ".kube/config",        0077, 40, "A2: ~/.kube/config (Kubernetes credentials) is group/world-accessible" },
                { ".npmrc",              0077, 30, "A2: ~/.npmrc (npm auth token) is group/world-accessible" },
                { ".pypirc",             0077, 25, "A2: ~/.pypirc (PyPI credentials) is group/world-accessible" },
                { ".git-credentials",    0077, 35, "A2: ~/.git-credentials (Git HTTP credentials) is group/world-accessible" },
                /* Cloud SDK credential files */
                { ".config/gcloud/application_default_credentials.json",
                                         0077, 40, "A2: GCP application_default_credentials is group/world-accessible" },
                { ".config/gh/hosts.yml",0077, 35, "A2: GitHub CLI credentials (~/.config/gh/hosts.yml) is group/world-accessible" },
                { ".terraform.d/credentials.tfrc.json",
                                         0077, 35, "A2: Terraform Cloud token is group/world-accessible" },
                { ".azure/credentials",  0077, 35, "A2: Azure CLI credentials (~/.azure/credentials) is group/world-accessible" },
                { ".heroku/credentials.json",
                                         0077, 30, "A2: Heroku credentials are group/world-accessible" },
                { NULL, 0, 0, NULL }
            };
            int i;
            for (i = 0; HOME_SECRETS[i].rel; i++) {
                char path[512];
                struct stat st;
                snprintf(path, sizeof(path), "%s/%s", home, HOME_SECRETS[i].rel);
                if (stat(path, &st) == 0 &&
                    (st.st_mode & HOME_SECRETS[i].bad_bits)) {
                    av_add(&v, HOME_SECRETS[i].score, AUDIT_HIGH,
                        "%s (mode %04o)",
                        HOME_SECRETS[i].label, st.st_mode & 0777);
                }
            }
        }
    }

    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * A3: DNS / Hosts File Poisoning Detection
 * ═══════════════════════════════════════════════════════════════════════ */

static const char *SENSITIVE_DOMAINS[] = {
    /* US Banks */
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "hsbc.com", "barclays.co.uk",
    /* EU Banks */
    "ing.com", "bnpparibas.com", "deutschebank.com", "unicredit.eu",
    "santander.com", "bbva.com",
    /* JP banks */
    "mizuhobank.co.jp", "smbc.co.jp", "bk.mufg.jp",
    "rakuten-bank.co.jp", "japannetbank.co.jp",
    /* Crypto exchanges */
    "coinbase.com", "binance.com", "kraken.com", "bitflyer.jp",
    "bybit.com", "okx.com", "huobi.com", "kucoin.com",
    "gate.io", "bitfinex.com", "gemini.com", "upbit.com",
    /* Payment */
    "paypal.com", "stripe.com", "wise.com", "cashapp.com", "cash.app",
    /* Auth providers */
    "accounts.google.com", "login.microsoftonline.com",
    "appleid.apple.com",
    /* Cloud management consoles — high-value redirect targets */
    "console.aws.amazon.com", "console.cloud.google.com", "portal.azure.com",
    /* SSO/identity */
    "github.com", "okta.com", "auth0.com",
    /* Major social auth targets */
    "twitter.com", "facebook.com",
    /* Hardware wallets / non-custodial */
    "metamask.io", "ledger.com", "trezor.io",
    NULL
};

AuditVerdict
hlse_audit_dns(void) {
    AuditVerdict v;
    FILE *fp;
    char line[1024];

    memset(&v, 0, sizeof(v));

    fp = hlse_open_system_file("/etc/hosts");
    if (!fp) {
        av_add(&v, 0, AUDIT_INFO, "A3: Cannot read /etc/hosts");
        return v;
    }

    while (fgets(line, sizeof(line), fp)) {
        /* Skip comments and blank lines */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        /* Skip localhost entries */
        if (strstr(p, "127.0.0.1") && strstr(p, "localhost")) continue;
        if (strstr(p, "::1") && strstr(p, "localhost")) continue;

        /* Check if any sensitive domain appears in this hosts entry */
        {
            int i;
            char lower[1024];
            size_t k;
            for (k = 0; k < sizeof(lower) - 1 && p[k]; k++)
                lower[k] = (char)tolower((unsigned char)p[k]);
            lower[k] = '\0';

            for (i = 0; SENSITIVE_DOMAINS[i]; i++) {
                if (strstr(lower, SENSITIVE_DOMAINS[i])) {
                    /* This domain is being redirected via /etc/hosts */
                    av_add(&v, 60, AUDIT_CRITICAL,
                        "A3: HOSTS POISONING — %s redirected in /etc/hosts",
                        SENSITIVE_DOMAINS[i]);
                }
            }
        }
    }
    fclose(fp);

    /* Check resolv.conf for suspicious DNS */
    fp = hlse_open_system_file("/etc/resolv.conf");
    if (fp) {
        int nameserver_count = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "nameserver", 10) == 0) {
                nameserver_count++;
                /* Check for suspicious nameservers (non-well-known) */
                char *ns = line + 10;
                while (*ns == ' ') ns++;
                /* Well-known DNS: 8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9 */
                if (strstr(ns, "8.8.8.8") || strstr(ns, "8.8.4.4") ||
                    strstr(ns, "1.1.1.1") || strstr(ns, "1.0.0.1") ||
                    strstr(ns, "9.9.9.9") || strstr(ns, "208.67.") ||
                    strstr(ns, "127.0.0.") || strstr(ns, "::1"))
                {
                    /* Known good */
                } else {
                    av_add(&v, 15, AUDIT_MEDIUM,
                        "A3: Custom nameserver: %.*s (verify this is intentional)",
                        30, ns);
                }
            }
        }
        fclose(fp);
    }

    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * A4: Cron Persistence Detection
 * ═══════════════════════════════════════════════════════════════════════ */

static const char *SUSPICIOUS_CRON_PATTERNS[] = {
    "curl ", "wget ", "curl|", "wget|",
    "| sh", "| bash", "|sh", "|bash",
    "base64 -d", "base64 --decode",
    "/dev/tcp/", "nc -e", "ncat -e",
    "python -c", "python3 -c", "perl -e",
    "eval(", "exec(",
    ".onion",
    "chmod 777", "chmod +s",
    /* Additional reverse-shell and persistence patterns */
    "bash -i", "socat ", "mkfifo ",
    "ruby -e", "php -r", "node -e",
    "openssl s_client", "telnet ",
    NULL
};

AuditVerdict
hlse_audit_cron(void) {
    AuditVerdict v;
    memset(&v, 0, sizeof(v));

    /* Check user's crontab */
    {
        const char *cron_paths[] = {
            "/var/spool/cron/crontabs/",  /* Debian/Ubuntu */
            "/var/spool/cron/",           /* RHEL/CentOS */
            NULL
        };
        int pi;
        for (pi = 0; cron_paths[pi]; pi++) {
            DIR *d = opendir(cron_paths[pi]);
            if (!d) continue;
            {
                struct dirent *ent;
                while ((ent = readdir(d)) != NULL) {
                    char path[512];
                    FILE *fp;
                    char line[2048];

                    if (ent->d_name[0] == '.') continue;
                    snprintf(path, sizeof(path), "%s%s",
                             cron_paths[pi], ent->d_name);
                    /* Open with O_NOFOLLOW|O_NONBLOCK and require a regular
                     * file: a FIFO planted in the cron dir would otherwise
                     * block fopen()/fgets() indefinitely, and a symlink
                     * could redirect the read elsewhere.                 */
                    {
                        int cfd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
                        struct stat cst;
                        if (cfd < 0) continue;
                        if (fstat(cfd, &cst) != 0 || !S_ISREG(cst.st_mode)) {
                            close(cfd);
                            continue;
                        }
                        fp = fdopen(cfd, "r");
                        if (!fp) { close(cfd); continue; }
                    }

                    while (fgets(line, sizeof(line), fp)) {
                        int i;
                        char *p = line;
                        while (*p == ' ' || *p == '\t') p++;
                        if (*p == '#' || *p == '\n') continue;

                        for (i = 0; SUSPICIOUS_CRON_PATTERNS[i]; i++) {
                            if (strstr(p, SUSPICIOUS_CRON_PATTERNS[i])) {
                                av_add(&v, 40, AUDIT_HIGH,
                                    "A4: Suspicious cron entry in %s: "
                                    "%.60s", ent->d_name, p);
                                break;
                            }
                        }
                    }
                    fclose(fp);
                }
            }
            closedir(d);
        }
    }

    /* Also check /etc/cron.d/ */
    {
        DIR *d = opendir("/etc/cron.d");
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                char path[512];
                int i;
                if (ent->d_name[0] == '.') continue;
                snprintf(path, sizeof(path), "/etc/cron.d/%s", ent->d_name);
                for (i = 0; SUSPICIOUS_CRON_PATTERNS[i]; i++) {
                    int r = file_contains(path, SUSPICIOUS_CRON_PATTERNS[i]);
                    if (r == 1) {
                        av_add(&v, 35, AUDIT_HIGH,
                            "A4: Suspicious pattern in /etc/cron.d/%s: '%s'",
                            ent->d_name, SUSPICIOUS_CRON_PATTERNS[i]);
                        break;
                    }
                }
            }
            closedir(d);
        }
    }

    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * A5: Insecure $PATH
 *
 * A writable or current-directory entry in PATH lets an attacker plant a
 * binary that runs under the user's identity for any unqualified command.
 * We flag two well-known footguns: '.' / an empty element (the current
 * directory), and a world-writable directory without the sticky bit.
 * User-owned dirs (e.g. ~/.local/bin) are intentionally NOT flagged.
 * ═══════════════════════════════════════════════════════════════════════ */

AuditVerdict
hlse_audit_path(void) {
    AuditVerdict v;
    const char *path = getenv("PATH");
    const char *s;
    int flagged_cwd = 0;

    memset(&v, 0, sizeof(v));
    if (!path || !*path) {
        av_add(&v, 0, AUDIT_INFO, "A5: PATH is empty or unset");
        return v;
    }

    for (s = path; ; ) {
        const char *colon = strchr(s, ':');
        size_t len = colon ? (size_t)(colon - s) : strlen(s);

        if (len == 0 || (len == 1 && s[0] == '.')) {
            if (!flagged_cwd) {
                av_add(&v, 30, AUDIT_HIGH,
                    "A5: current directory ('.' or empty element) in PATH — "
                    "a planted binary in any cwd can hijack commands");
                flagged_cwd = 1;
            }
        } else if (len < 1024) {
            char dir[1024];
            struct stat st;
            memcpy(dir, s, len);
            dir[len] = '\0';
            if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode) &&
                (st.st_mode & S_IWOTH) && !(st.st_mode & S_ISVTX)) {
                av_add(&v, 35, AUDIT_HIGH,
                    "A5: world-writable directory in PATH: %.180s (mode %04o)",
                    dir, (unsigned)(st.st_mode & 07777));
            }
        }

        if (!colon) break;
        s = colon + 1;
    }

    if (v.n_findings == 0)
        av_add(&v, 0, AUDIT_PASS, "A5: PATH has no writable or '.' entries");
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * A6: Shell startup-file backdoors
 *
 * Appending to ~/.bashrc / ~/.zshrc / ~/.profile is a classic, low-effort
 * persistence and reverse-shell mechanism. We scan the common login/rc files
 * for a small set of HIGH-confidence execution patterns; benign rc lines do
 * not contain reverse-shell device paths or download-piped-to-shell.
 * ═══════════════════════════════════════════════════════════════════════ */

AuditVerdict
hlse_audit_shellrc(void) {
    AuditVerdict v;
    const char *home = getenv("HOME");
    const char *files[] = {
        ".bashrc", ".bash_profile", ".bash_login",
        ".profile", ".zshrc", ".zprofile", NULL
    };
    int fi;

    memset(&v, 0, sizeof(v));
    if (!home) {
        av_add(&v, 0, AUDIT_INFO, "A6: HOME unset — cannot check shell rc files");
        return v;
    }

    for (fi = 0; files[fi]; fi++) {
        char path[512];
        FILE *fp;
        char line[2048];
        int lineno = 0;

        snprintf(path, sizeof(path), "%s/%s", home, files[fi]);
        fp = hlse_open_system_file(path);   /* follows symlinked dotfiles */
        if (!fp) continue;

        while (fgets(line, sizeof(line), fp)) {
            char *p = line;
            lineno++;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '#' || *p == '\n' || *p == '\0') continue;

            if (strstr(p, "/dev/tcp/") || strstr(p, "/dev/udp/")) {
                av_add(&v, 45, AUDIT_CRITICAL,
                    "A6: reverse-shell device path (/dev/tcp) in ~/%s:%d",
                    files[fi], lineno);
            }
            if (strstr(p, "nc -e") || strstr(p, "ncat -e") ||
                strstr(p, "nc.traditional -e")) {
                av_add(&v, 40, AUDIT_CRITICAL,
                    "A6: netcat -e reverse shell in ~/%s:%d", files[fi], lineno);
            }
            if ((strstr(p, "curl ") || strstr(p, "wget ")) &&
                (strstr(p, "| sh")   || strstr(p, "|sh") ||
                 strstr(p, "| bash") || strstr(p, "|bash"))) {
                av_add(&v, 35, AUDIT_HIGH,
                    "A6: download-piped-to-shell in ~/%s:%d "
                    "(persistence/backdoor)", files[fi], lineno);
            }
            if (strstr(p, "LD_PRELOAD=")) {
                av_add(&v, 20, AUDIT_MEDIUM,
                    "A6: LD_PRELOAD set in ~/%s:%d — verify the library is "
                    "trusted", files[fi], lineno);
            }
            if (strstr(p, "socat ") &&
                (strstr(p, "exec:") || strstr(p, "/bin/sh") ||
                 strstr(p, "/bin/bash"))) {
                av_add(&v, 45, AUDIT_CRITICAL,
                    "A6: socat reverse shell in ~/%s:%d", files[fi], lineno);
            }
            if (strstr(p, "bash -i") || strstr(p, "bash -c")) {
                av_add(&v, 30, AUDIT_HIGH,
                    "A6: interactive shell invocation in ~/%s:%d",
                    files[fi], lineno);
            }
            if (strstr(p, "mkfifo ") &&
                (strstr(p, "nc ") || strstr(p, "ncat ") ||
                 strstr(p, "bash") || strstr(p, "sh"))) {
                av_add(&v, 45, AUDIT_CRITICAL,
                    "A6: named-pipe reverse shell (mkfifo+nc) in ~/%s:%d",
                    files[fi], lineno);
            }
            /* PROMPT_COMMAND injection — every command prompt executes payload */
            if (strstr(p, "PROMPT_COMMAND") &&
                (strstr(p, "curl ") || strstr(p, "wget ") ||
                 strstr(p, "/dev/tcp") || strstr(p, "nc ") ||
                 strstr(p, "eval ") || strstr(p, "base64"))) {
                av_add(&v, 40, AUDIT_CRITICAL,
                    "A6: PROMPT_COMMAND injection in ~/%s:%d — "
                    "payload runs on every shell prompt", files[fi], lineno);
            }
            /* function() override of system commands — rootkit-style hiding */
            if (strncmp(p, "function ", 9) == 0 || strncmp(p, "function\t", 9) == 0) {
                /* common commands hijacked to hide malware from ps/ls/top */
                static const char *hid[] = {
                    "ls(", "ps(", "top(", "netstat(", "ss(", "lsof(",
                    "find(", "grep(", "who(", "id(", "ifconfig(", NULL
                };
                int hi;
                for (hi = 0; hid[hi]; hi++) {
                    if (strstr(p, hid[hi])) {
                        av_add(&v, 35, AUDIT_HIGH,
                            "A6: system command '%.*s' overridden by shell "
                            "function in ~/%s:%d — possible rootkit persistence",
                            (int)(strchr(hid[hi], '(') - hid[hi]),
                            hid[hi], files[fi], lineno);
                        break;
                    }
                }
            }
        }
        fclose(fp);
    }

    if (v.n_findings == 0)
        av_add(&v, 0, AUDIT_PASS,
               "A6: No backdoor patterns in shell startup files");
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Unified audit
 * ═══════════════════════════════════════════════════════════════════════ */

AuditVerdict
hlse_audit_all(void) {
    AuditVerdict combined;
    AuditVerdict parts[6];
    int n = 0, i, j;

    memset(&combined, 0, sizeof(combined));

    parts[n++] = hlse_audit_ssh();
    parts[n++] = hlse_audit_permissions();
    parts[n++] = hlse_audit_dns();
    parts[n++] = hlse_audit_cron();
    parts[n++] = hlse_audit_path();
    parts[n++] = hlse_audit_shellrc();

    for (i = 0; i < n; i++) {
        for (j = 0; j < parts[i].n_findings
             && combined.n_findings < HLSE_AUDIT_MAX_FINDINGS; j++) {
            combined.findings[combined.n_findings] = parts[i].findings[j];
            combined.n_findings++;
        }
        combined.score += parts[i].score;
    }
    if (combined.score > 100) combined.score = 100;
    return combined;
}

int
hlse_audit_hardening_index(const AuditVerdict *v) {
    int risk;
    if (!v) return 0;
    risk = v->score;
    if (risk < 0) risk = 0;
    if (risk > 100) risk = 100;
    return 100 - risk;
}
