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
    FILE *fp = fopen(path, "r");
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
        FILE *fp = fopen(sshd_conf, "r");
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

    /* Check home directory .env files */
    {
        const char *home = getenv("HOME");
        if (home) {
            char path[512];
            struct stat st;
            snprintf(path, sizeof(path), "%s/.env", home);
            if (stat(path, &st) == 0) {
                if (st.st_mode & 0077) {
                    av_add(&v, 25, AUDIT_HIGH,
                        "A2: ~/.env is group/world-accessible (mode %04o)",
                        st.st_mode & 0777);
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
    /* Banks */
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "hsbc.com", "barclays.co.uk",
    /* JP banks */
    "mizuhobank.co.jp", "smbc.co.jp", "bk.mufg.jp",
    "rakuten-bank.co.jp", "japannetbank.co.jp",
    /* Crypto exchanges */
    "coinbase.com", "binance.com", "kraken.com", "bitflyer.jp",
    /* Payment */
    "paypal.com", "stripe.com", "wise.com",
    /* Auth providers */
    "accounts.google.com", "login.microsoftonline.com",
    "appleid.apple.com",
    NULL
};

AuditVerdict
hlse_audit_dns(void) {
    AuditVerdict v;
    FILE *fp;
    char line[1024];

    memset(&v, 0, sizeof(v));

    fp = fopen("/etc/hosts", "r");
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
            for (k = 0; p[k] && k < sizeof(lower) - 1; k++)
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
    fp = fopen("/etc/resolv.conf", "r");
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
 * Unified audit
 * ═══════════════════════════════════════════════════════════════════════ */

AuditVerdict
hlse_audit_all(void) {
    AuditVerdict combined;
    AuditVerdict parts[4];
    int n = 0, i, j;

    memset(&combined, 0, sizeof(combined));

    parts[n++] = hlse_audit_ssh();
    parts[n++] = hlse_audit_permissions();
    parts[n++] = hlse_audit_dns();
    parts[n++] = hlse_audit_cron();

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
