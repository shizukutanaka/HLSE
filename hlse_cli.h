/* hlse_cli.h — the CLI's parsed-option state. main() fills this during
 * argv parsing (defaults + --config + explicit flags) and hands it to the
 * subcommand handlers in hlse_cli.c. Replaced the file-scope g_* statics. */
#ifndef HLSE_CLI_H
#define HLSE_CLI_H

typedef struct {
    int json_out;              /* --json */
    int quiet;                 /* --quiet / -q */
    int sarif_out;             /* --sarif */
    int opt_syslog;            /* --syslog */
    const char *opt_log_file;  /* --log-file <path> (may point into cfg) */
    const char *baseline_file; /* --baseline <file> (may point into cfg) */
    int emit_fingerprints;     /* --fingerprints */
    int git_history;           /* --git-history */
    int fail_threshold;        /* --fail-on, default 60 (BLOCK) */
} HlseCli;

#endif /* HLSE_CLI_H */
int hlse_cmd_protect(const HlseCli *o, int argc, char **argv, int idx);
int hlse_cmd_esp(const HlseCli *o, int argc, char **argv, int idx);
int hlse_cmd_esp(const HlseCli *o, int argc, char **argv, int idx);
int hlse_cmd_clipboard(const HlseCli *o, int argc, char **argv, int idx);
