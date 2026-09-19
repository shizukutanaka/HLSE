/* hlsed.c — resident file-integrity monitor daemon.
 *
 * Usage:
 *   hlsed --config <file>    run the monitor (foreground; supervisor-ready)
 *   hlsed --check <file>     validate the config and exit 0/2
 *   hlsed --version | -h
 *
 * Everything operational lives in the config file — `watch`, `scan-interval`,
 * `pid-file`, `log-file`, `syslog`, `fail-on`, `patterns` — so a deploy is one
 * file. The daemon never forks or detaches: run it under systemd
 * (Type=simple), launchd, or `nohup` for background operation.
 *
 * Signals: SIGTERM/SIGINT stop cleanly (PID file removed); SIGHUP reloads
 * the config in place. */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "hlse_daemon.h"
#include "hlse_config.h"
#include "hlse_core.h"     /* HLSE_VERSION */

static void
usage(FILE *out) {
    fputs(
        "hlsed — HLSE resident file-integrity monitor\n"
        "\n"
        "  hlsed --config <file>   run the monitor (foreground)\n"
        "  hlsed --check <file>    validate config + watch dirs, exit 0/2\n"
        "  hlsed --version         version string\n"
        "  hlsed -h, --help        this help\n"
        "\n"
        "Config keys (see hlse_config.h): watch, scan-interval, pid-file,\n"
        "log-file, syslog, fail-on, patterns. Signals: SIGTERM/SIGINT stop,\n"
        "SIGHUP reloads the config. The daemon runs in the foreground by\n"
        "design — supervise it with systemd (Type=simple) or launchd.\n",
        out);
}

/* `--check`: parse config, verify every watch dir exists. Shares the
 * daemon's validation rules but stops before signals/pid/sinks. */
static int
check_config(const char *path) {
    HlseConfig cfg;
    char cerr[256];
    int i, bad = 0;
    if (hlse_config_load(path, &cfg, cerr, sizeof(cerr)) != 0) {
        fprintf(stderr, "hlsed: %s\n", cerr);
        return 2;
    }
    if (cfg.n_watch == 0) {
        fprintf(stderr, "hlsed: %s: no 'watch' entries\n", path);
        return 2;
    }
    for (i = 0; i < cfg.n_watch; i++) {
        struct stat st;
        if (stat(cfg.watch[i], &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "hlsed: watch '%s': not a directory\n",
                    cfg.watch[i]);
            bad = 1;
        }
    }
    if (bad) return 2;
    printf("hlsed: config OK — %d watch dir%s, interval %ds\n",
           cfg.n_watch, cfg.n_watch == 1 ? "" : "s",
           cfg.scan_interval > 0 ? cfg.scan_interval : 60);
    return 0;
}

int
main(int argc, char **argv) {
    if (argc == 2 && (!strcmp(argv[1], "--version") ||
                      !strcmp(argv[1], "-V"))) {
        puts(HLSE_VERSION);
        return 0;
    }
    if (argc == 2 && (!strcmp(argv[1], "--help") ||
                      !strcmp(argv[1], "-h"))) {
        usage(stdout);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--check"))
        return check_config(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "--config"))
        return hlse_daemon_run(argv[2]);

    usage(stderr);
    return 2;
}
