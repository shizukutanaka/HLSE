/* hlse_config.h — runtime configuration file for the hlse_core CLI.
 *
 * Format: one `key = value` directive per line (the '=' is optional —
 * `key value` is accepted too). '#' comments and blank lines ignored.
 * Keys map 1:1 to the CLI's global flags, spelled the same way minus
 * the leading dashes:
 *
 *   json | sarif | quiet | syslog | fingerprints | git-history   bool
 *   fail-on      log | alert | block | isolate | 0..100
 *   from         email | sms | dm | qr | manual
 *   baseline     <path>     (like --baseline)
 *   log-file     <path>     (like --log-file)
 *   patterns     <path>     (like --patterns)
 *
 * Bools accept true|yes|on|1 / false|no|off|0. Path values may be
 * wrapped in double quotes when they contain spaces.
 *
 * The file is loaded BEFORE argv parsing, so any flag given on the
 * command line overrides the config default (a config's `patterns`
 * file is skipped entirely when --patterns is passed).
 *
 * Unknown keys and malformed values are hard errors — silently
 * ignoring a typo'd key would let a gate run with the wrong posture.
 *
 * Example:
 *   # CI posture for this repo
 *   fail-on   = alert
 *   patterns  = security/hlse-patterns.txt
 *   baseline  = security/.hlse-baseline
 *   log-file  = /var/log/hlse/findings.jsonl
 */
#ifndef HLSE_CONFIG_H
#define HLSE_CONFIG_H

#include <stddef.h>

typedef struct {
    int has_json;         int json;
    int has_sarif;        int sarif;
    int has_quiet;        int quiet;
    int has_syslog;       int syslog;
    int has_fingerprints; int fingerprints;
    int has_git_history;  int git_history;
    int has_fail_on;      int fail_on;    /* resolved 0..100  */
    char from[16];                        /* "" when unset    */
    char baseline[1024];
    char log_file[1024];
    char patterns[1024];
} HlseConfig;

/* Parse `path` into `cfg` (zeroed by caller or callee — contents are
 * fully overwritten). Returns 0 on success; on failure returns -1 and
 * writes a "path:line: reason" message into `err` (always NUL-terminated
 * when errcap > 0). */
int hlse_config_load(const char *path, HlseConfig *cfg,
                     char *err, size_t errcap);

#endif /* HLSE_CONFIG_H */
