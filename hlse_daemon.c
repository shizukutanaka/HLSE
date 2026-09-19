/* hlse_daemon.c — hlsed resident file-integrity monitor.
 *
 * Poll-based design over fanotify/FSEvents on purpose: identical code on
 * Linux and macOS, rootless, deterministic, and a sweep interval cheap
 * enough for the directories this product watches (config dirs, web
 * roots, drop zones). Event APIs can be layered under the same dedup
 * table later without changing the contract.
 *
 * Invariants kept from SPECIFICATION.md §1: no network, no threads,
 * bounded buffers, read-only file access. Untrusted watch-dir entries are
 * opened O_RDONLY|O_NOFOLLOW|O_NONBLOCK and only ever read, matching the
 * directory-scan path's rules. */
#include "hlse_daemon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/file.h>

#include "hlse_config.h"
#include "hlse_core.h"    /* hlse_severity_for_score, HLSE_VERSION */
#include "hlse_file.h"
#include "hlse_secrets.h"
#include "hlse_alert.h"

/* ── tunables ────────────────────────────────────────────────────────── */
#define DAEMON_DEFAULT_INTERVAL_S  60     /* `scan-interval` unset        */
#define DAEMON_DEFAULT_THRESHOLD   40     /* `fail-on` unset → ALERT band */
#define DAEMON_MAX_DEPTH           8      /* walk recursion cap           */
#define DAEMON_MAX_ENTRIES      100000    /* files per sweep cap          */
#define DAEMON_SEEN_MAX           4096    /* dedup table entries          */
#define DAEMON_SECRET_READ_CAP  (256*1024)/* bytes of a file secret-scanned*/

/* Directories never worth watching into — same exclusions the `scan`
 * command uses, plus VCS internals and dependency trees. */
static const char *SKIP_DIRS[] = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv",
    ".idea", ".vscode", "dist", "build", "target", NULL
};

/* ── signal flags ────────────────────────────────────────────────────── */
static volatile sig_atomic_t g_stop   = 0;
static volatile sig_atomic_t g_reload = 0;

static void on_term(int sig) { (void)sig; g_stop   = 1; }
static void on_hup (int sig) { (void)sig; g_reload = 1; }

/* ── dedup table: path → last seen (mtime,size) ────────────────────────
 * In-memory only, per the SECURITY.md carve-out. Circular eviction once
 * full — the evicted tuple simply gets re-scanned next sweep, which is a
 * false repeat alert at worst, never a missed change. */
typedef struct {
    char      path[1024];
    long long mtime;
    long long size;
} SeenEntry;

static SeenEntry g_seen[DAEMON_SEEN_MAX];
static int       g_seen_n;      /* entries appended (<= MAX) */
static int       g_seen_evict;  /* next circular slot to overwrite */

/* 1 when (path,mtime,size) is already recorded; records and returns 0
 * when new/changed. */
static int
seen_lookup_or_record(const char *path, long long mtime, long long size) {
    int i;
    for (i = 0; i < g_seen_n; i++) {
        if (g_seen[i].mtime == mtime && g_seen[i].size == size &&
            strcmp(g_seen[i].path, path) == 0)
            return 1;
    }
    if (g_seen_n < DAEMON_SEEN_MAX) {
        i = g_seen_n++;
    } else {
        i = g_seen_evict;
        g_seen_evict = (g_seen_evict + 1) % DAEMON_SEEN_MAX;
    }
    snprintf(g_seen[i].path, sizeof(g_seen[i].path), "%s", path);
    g_seen[i].mtime = mtime;
    g_seen[i].size  = size;
    return 0;
}

/* ── per-file detection ──────────────────────────────────────────────── */

/* Alert sinks get the same payload a one-shot `hlse_core file` would
 * emit, plus a human line on stderr so journalctl/`tail -f` sees it. */
static void
report_finding(const char *kind, int score, const char *operand,
               const char *const *reasons, int n_reasons) {
    int i;
    fprintf(stderr, "hlsed: %-6s score=%3d %s\n", kind, score, operand);
    for (i = 0; i < n_reasons; i++)
        fprintf(stderr, "hlsed:        %s\n", reasons[i]);
    hlse_alert_emit(kind, score, hlse_severity_for_score(score),
                    operand, (const char **)reasons, n_reasons);
}

/* Safe bounded read of an untrusted path for the secrets scan.
 * O_NOFOLLOW + O_NONBLOCK + fstat S_ISREG — identical rules to the
 * directory-scan path. Returns bytes read or -1. */
static long
read_file_bounded(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    struct stat st;
    ssize_t n;
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }
    if (st.st_size > (off_t)cap) { close(fd); return -1; }
    n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return (long)n;
}

static void
scan_new_file(const char *path, int threshold) {
    FileVerdict fv = hlse_check_file(path);
    /* sized to the larger of the two producer caps (secret findings 16
     * outnumber file reasons 8) so both loops below stay in bounds */
    const char *rr[HLSE_SECRET_MAX_FINDINGS];
    int i;

    if (fv.score >= threshold) {
        for (i = 0; i < fv.n_reasons && i < HLSE_FILE_MAX_REASONS; i++)
            rr[i] = fv.reasons[i];
        report_finding("file", fv.score, path, rr, i);
    }

    /* Content-level secret scan on the same file. The read cap means
     * files larger than DAEMON_SECRET_READ_CAP are skipped rather than
     * partially scanned — a stated cap beats a partial-credential match. */
    {
        static char buf[DAEMON_SECRET_READ_CAP];
        if (read_file_bounded(path, buf, sizeof(buf)) > 0) {
            SecretVerdict sv = hlse_scan_secrets(buf);
            if (sv.score >= threshold) {
                static char sreasons[HLSE_SECRET_MAX_FINDINGS][256];
                int n = 0;
                for (i = 0;
                     i < sv.n_findings && i < HLSE_SECRET_MAX_FINDINGS; i++) {
                    snprintf(sreasons[i], sizeof(sreasons[i]),
                             "Secret detected: %s", sv.findings[i].type);
                    rr[i] = sreasons[i];
                    n++;
                }
                report_finding("secret", sv.score, path, rr, n);
            }
        }
    }
}

/* ── directory walk ──────────────────────────────────────────────────── */
static void
walk(const char *dir, int depth, int threshold, long *entries) {
    DIR *d;
    struct dirent *de;
    int i;

    if (depth > DAEMON_MAX_DEPTH || *entries > DAEMON_MAX_ENTRIES) return;
    d = opendir(dir);
    if (!d) return;
    while (!g_stop && (de = readdir(d)) != NULL) {
        char path[1200];
        struct stat st;

        if (de->d_name[0] == '.' &&
            (de->d_name[1] == '\0' ||
             (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;

        if (snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >=
            (int)sizeof(path))
            continue;                       /* overlong path: skip */
        if (lstat(path, &st) != 0) continue;
        (*entries)++;

        if (S_ISDIR(st.st_mode)) {
            for (i = 0; SKIP_DIRS[i]; i++)
                if (strcmp(de->d_name, SKIP_DIRS[i]) == 0) break;
            if (SKIP_DIRS[i]) continue;
            walk(path, depth + 1, threshold, entries);
        } else if (S_ISREG(st.st_mode)) {
            /* lstat+S_ISREG rejects symlink entries outright — we never
             * follow attacker-planted links out of the watch dir. */
            if (!seen_lookup_or_record(path, (long long)st.st_mtime,
                                       (long long)st.st_size))
                scan_new_file(path, threshold);
        }
    }
    closedir(d);
}

/* ── config / pid-file plumbing ──────────────────────────────────────── */
static int  g_pid_fd = -1;
static char g_pid_path[1024];

static void
pidfile_cleanup(void) {
    if (g_pid_fd >= 0) { close(g_pid_fd); g_pid_fd = -1; }
    if (g_pid_path[0]) { unlink(g_pid_path); g_pid_path[0] = '\0'; }
}

/* Create + exclusively lock the PID file. Fails when another hlsed holds
 * it — a second daemon instance would double-alert and fight the lock. */
static int
pidfile_acquire(const char *path) {
    char buf[32];
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) { close(fd); return -2; }
    snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    if (write(fd, buf, strlen(buf)) < 0) { /* best-effort content */ }
    g_pid_fd = fd;
    snprintf(g_pid_path, sizeof(g_pid_path), "%s", path);
    return 0;
}

/* Init sinks on first call; on reload, shut down and reopen so a swapped
 * log-file path takes effect. */
static int
apply_alert_sinks(const HlseConfig *cfg, int reload) {
    int use_syslog  = cfg->has_syslog ? cfg->syslog : 0;
    const char *log = cfg->log_file[0] ? cfg->log_file : NULL;
    if (reload) hlse_alert_shutdown();
    if ((use_syslog || log) &&
        hlse_alert_init(use_syslog, log) != 0)
        return -1;
    return 0;
}

/* ── main loop ───────────────────────────────────────────────────────── */
int
hlse_daemon_run(const char *config_path) {
    HlseConfig cfg;
    char cerr[256];
    struct sigaction sa;
    int interval, threshold, i, n_reloads = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sa.sa_handler = on_hup;
    sigaction(SIGHUP,  &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    if (hlse_config_load(config_path, &cfg, cerr, sizeof(cerr)) != 0) {
        fprintf(stderr, "hlsed: %s\n", cerr);
        return 2;
    }
    if (cfg.n_watch == 0) {
        fprintf(stderr, "hlsed: %s: no 'watch' entries — nothing to monitor\n",
                config_path);
        return 2;
    }
    for (i = 0; i < cfg.n_watch; i++) {
        struct stat st;
        if (stat(cfg.watch[i], &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "hlsed: watch path '%s': %s\n", cfg.watch[i],
                    strerror(errno));
            return 2;
        }
    }
    interval  = cfg.scan_interval > 0 ? cfg.scan_interval
                                    : DAEMON_DEFAULT_INTERVAL_S;
    threshold = cfg.has_fail_on ? cfg.fail_on : DAEMON_DEFAULT_THRESHOLD;

    if (apply_alert_sinks(&cfg, 0) != 0) {
        fprintf(stderr, "hlsed: cannot open log-file '%s': %s\n",
                cfg.log_file, strerror(errno));
        return 2;
    }

    if (cfg.pid_file[0]) {
        int prc = pidfile_acquire(cfg.pid_file);
        if (prc == -2) {
            fprintf(stderr, "hlsed: '%s' is locked — another hlsed is "
                    "running\n", cfg.pid_file);
            return 1;
        }
        if (prc != 0) {
            fprintf(stderr, "hlsed: cannot write pid-file '%s': %s\n",
                    cfg.pid_file, strerror(errno));
            return 2;
        }
    }

    fprintf(stderr, "hlsed %s: watching %d director%s, interval %ds, "
            "threshold %d\n",
            HLSE_VERSION, cfg.n_watch, cfg.n_watch == 1 ? "y" : "ies",
            interval, threshold);

    while (!g_stop) {
        long entries = 0;
        for (i = 0; i < cfg.n_watch && !g_stop; i++)
            walk(cfg.watch[i], 0, threshold, &entries);

        if (g_reload) {
            HlseConfig ncfg;
            g_reload = 0;
            if (hlse_config_load(config_path, &ncfg,
                                 cerr, sizeof(cerr)) == 0) {
                cfg = ncfg;
                interval  = cfg.scan_interval > 0 ? cfg.scan_interval
                                                  : DAEMON_DEFAULT_INTERVAL_S;
                threshold = cfg.has_fail_on ? cfg.fail_on
                                            : DAEMON_DEFAULT_THRESHOLD;
                if (strcmp(cfg.pid_file, g_pid_path) != 0) {
                    /* pid-file moved: release the old lock, take the new */
                    pidfile_cleanup();
                    if (cfg.pid_file[0] &&
                        pidfile_acquire(cfg.pid_file) != 0)
                        fprintf(stderr, "hlsed: reload: cannot lock new "
                                "pid-file '%s'\n", cfg.pid_file);
                }
                if (apply_alert_sinks(&cfg, 1) != 0)
                    fprintf(stderr, "hlsed: reload: log-file '%s' "
                            "unusable: %s\n", cfg.log_file, strerror(errno));
                fprintf(stderr, "hlsed: reloaded %s\n", config_path);
                n_reloads++;
            } else {
                fprintf(stderr, "hlsed: reload failed, keeping old config: "
                        "%s\n", cerr);
            }
        }

        /* Interruptible sleep: signals break nanosleep early so stop /
         * reload act promptly rather than after a full interval. */
        {
            struct timespec ts;
            ts.tv_sec  = interval;
            ts.tv_nsec = 0;
            while (!g_stop && !g_reload &&
                   nanosleep(&ts, &ts) != 0 && errno == EINTR)
                ;
        }
    }

    fprintf(stderr, "hlsed: stopped (%d reload%s)\n",
            n_reloads, n_reloads == 1 ? "" : "s");
    pidfile_cleanup();
    hlse_alert_shutdown();
    return 0;
}
