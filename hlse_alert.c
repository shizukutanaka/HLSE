/*
 * hlse_alert.c — see hlse_alert.h.
 *
 * Design notes / security posture:
 *  - build_line() is overflow-proof: length is tracked as a clamped size_t and
 *    every append stays within the buffer; there is no unchecked snprintf.
 *  - The log file is opened O_NOFOLLOW: this is a NEW judgment for a fresh,
 *    operator-owned append target (not the trusted-symlinked-system-file case
 *    that hlse_open_system_file() deliberately allows to follow). No legitimate
 *    reason exists for the alert-log path to already be a symlink, and refusing
 *    to follow one closes a local symlink-planting vector.
 *  - 0600 is the sole confidentiality control for secret-bearing findings, so a
 *    failed fchmod() is a hard error, not ignored.
 *  - write() is EINTR/partial-write safe so each record is one intact line —
 *    also the property a future multi-threaded caller relies on for lock-free
 *    non-interleaved output.
 */
#define _POSIX_C_SOURCE 200809L

#include "hlse_alert.h"
#include "hlse_util.h"   /* hlse_json_escape */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include <sys/stat.h>

static int g_syslog_on = 0;
static int g_fd        = -1;   /* -1 => file sink disabled */

static int
priority_for_severity(int severity) {
    switch (severity) {
        case 4: return LOG_ALERT;    /* ISOLATE 80-100 */
        case 3: return LOG_CRIT;     /* BLOCK   60-79  */
        case 2: return LOG_WARNING;  /* ALERT   40-59  (note: not LOG_ALERT) */
        case 1: return LOG_NOTICE;   /* LOG     15-39  */
        default: return LOG_INFO;    /* SAFE    0-14   */
    }
}

int
hlse_alert_init(int use_syslog, const char *log_file_path) {
    /* Idempotent: if already initialized, do nothing (prevents fd/handle leak
     * on a stray second call). */
    if (g_syslog_on || g_fd >= 0) return 0;

    if (use_syslog) { openlog("hlse", LOG_PID, LOG_AUTHPRIV); g_syslog_on = 1; }

    if (log_file_path) {
        struct stat st;
        int fd = open(log_file_path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW,
                      0600);
        if (fd < 0) {
            if (g_syslog_on) { closelog(); g_syslog_on = 0; }
            return -1;
        }
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            errno = EINVAL;              /* S_ISREG reject sets no errno itself */
            close(fd);
            if (g_syslog_on) { closelog(); g_syslog_on = 0; }
            return -1;
        }
        /* 0600 is the confidentiality guarantee; if we cannot enforce it, fail
         * rather than silently append secrets to a wider-readable file. */
        if (fchmod(fd, 0600) != 0) {
            close(fd);
            if (g_syslog_on) { closelog(); g_syslog_on = 0; }
            return -1;
        }
        g_fd = fd;
    }
    return 0;
}

/* Bounded append: copy src at out[len..], never past cap-1, always terminate.
 * Returns the new length (== cap-1 once full, so subsequent appends no-op). */
static size_t
alert_append(char *out, size_t cap, size_t len, const char *src) {
    if (cap == 0) return 0;
    while (*src && len < cap - 1) out[len++] = *src++;
    out[len] = '\0';
    return len;
}

static size_t
build_line(char *out, size_t cap, const char *kind, int score, int severity,
           const char *target, const char **reasons, int n_reasons) {
    char ts[32], num[16], esc[1024];
    time_t now = time(NULL);
    struct tm tmv;
    size_t len = 0;
    int i;

    gmtime_r(&now, &tmv);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tmv);

    out[0] = '\0';
    len = alert_append(out, cap, len, "{\"ts\":\"");
    len = alert_append(out, cap, len, ts);
    len = alert_append(out, cap, len,
                       "\",\"hlse_version\":\"" HLSE_VERSION "\",\"pid\":");
    snprintf(num, sizeof num, "%d", (int)getpid());
    len = alert_append(out, cap, len, num);
    len = alert_append(out, cap, len, ",\"kind\":\"");
    hlse_json_escape(kind ? kind : "", esc, sizeof esc);
    len = alert_append(out, cap, len, esc);
    len = alert_append(out, cap, len, "\",\"target\":\"");
    hlse_json_escape(target ? target : "", esc, sizeof esc);
    len = alert_append(out, cap, len, esc);
    len = alert_append(out, cap, len, "\",\"score\":");
    snprintf(num, sizeof num, "%d", score);
    len = alert_append(out, cap, len, num);
    len = alert_append(out, cap, len, ",\"severity\":");
    snprintf(num, sizeof num, "%d", severity);
    len = alert_append(out, cap, len, num);
    len = alert_append(out, cap, len, ",\"action\":\"");
    len = alert_append(out, cap, len, hlse_action_for_score(score));
    len = alert_append(out, cap, len, "\",\"reasons\":[");
    for (i = 0; reasons && i < n_reasons; i++) {
        if (i > 0) len = alert_append(out, cap, len, ",");
        len = alert_append(out, cap, len, "\"");
        hlse_json_escape(reasons[i] ? reasons[i] : "", esc, sizeof esc);
        len = alert_append(out, cap, len, esc);
        len = alert_append(out, cap, len, "\"");
    }
    len = alert_append(out, cap, len, "]}");
    return len;
}

static void
write_all_fd(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; break; }
        if (w == 0) break;
        off += (size_t)w;
    }
}

void
hlse_alert_emit(const char *kind, int score, int severity,
                const char *target, const char **reasons, int n_reasons) {
    char line[4096];
    size_t len;

    if (!g_syslog_on && g_fd < 0) return;   /* fast no-op */

    len = build_line(line, sizeof line, kind, score, severity,
                     target, reasons, n_reasons);

    if (g_syslog_on)
        syslog(priority_for_severity(severity), "%s", line);

    if (g_fd >= 0) {
        if (len + 1 < sizeof line) line[len++] = '\n';
        write_all_fd(g_fd, line, len);
    }
}

void
hlse_alert_emit_url(const char *url, const Verdict *v) {
    const char *r[16];
    int i, n = v->n_reasons;
    if (n > (int)(sizeof r / sizeof r[0])) n = (int)(sizeof r / sizeof r[0]);
    for (i = 0; i < n; i++) r[i] = v->reasons[i];
    hlse_alert_emit("url", v->score, hlse_severity_for_score(v->score),
                    url, r, n);
}

void
hlse_alert_emit_text(const char *text, const TextVerdict *v) {
    const char *r[16];
    int i, n = v->n_reasons;
    if (n > (int)(sizeof r / sizeof r[0])) n = (int)(sizeof r / sizeof r[0]);
    for (i = 0; i < n; i++) r[i] = v->reasons[i];
    hlse_alert_emit("text", v->score, hlse_severity_for_score(v->score),
                    text, r, n);
}

void
hlse_alert_shutdown(void) {
    if (g_syslog_on) { closelog(); g_syslog_on = 0; }
    if (g_fd >= 0)   { close(g_fd); g_fd = -1; }
}
