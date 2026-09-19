/* hlse_config.c — `key = value` runtime configuration for the CLI.
 *
 * Deliberately minimal: fixed buffers, no allocation, no nested
 * sections, no includes from other HLSE modules. See hlse_config.h
 * for the accepted keys and value syntax. */
#include "hlse_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

static void
cfg_err(char *err, size_t cap, const char *path, int lineno,
        const char *msg) {
    if (!err || cap == 0) return;
    if (lineno > 0)
        snprintf(err, cap, "%s:%d: %s", path, lineno, msg);
    else
        snprintf(err, cap, "%s: %s", path, msg);
}

/* left/right-trim in place; returns pointer into s. */
static char *
cfg_trim(char *s) {
    char *e;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' ||
                     e[-1] == '\r' || e[-1] == '\n'))
        *--e = '\0';
    return s;
}

static int
cfg_bool(const char *v, int *out) {
    if (strcmp(v, "true")  == 0 || strcmp(v, "yes") == 0 ||
        strcmp(v, "on")    == 0 || strcmp(v, "1")   == 0) { *out = 1; return 1; }
    if (strcmp(v, "false") == 0 || strcmp(v, "no")  == 0 ||
        strcmp(v, "off")   == 0 || strcmp(v, "0")   == 0) { *out = 0; return 1; }
    return 0;
}

static int
cfg_fail_on(const char *v, int *out) {
    if      (strcmp(v, "log")     == 0) { *out = 15; return 1; }
    else if (strcmp(v, "alert")   == 0) { *out = 40; return 1; }
    else if (strcmp(v, "block")   == 0) { *out = 60; return 1; }
    else if (strcmp(v, "isolate") == 0) { *out = 80; return 1; }
    else {
        char *end;
        long n = strtol(v, &end, 10);
        if (*end == '\0' && end != v && n >= 0 && n <= 100) {
            *out = (int)n;
            return 1;
        }
    }
    return 0;
}

static int
cfg_from(const char *v) {
    return strcmp(v, "email")  == 0 || strcmp(v, "sms")    == 0 ||
           strcmp(v, "dm")     == 0 || strcmp(v, "qr")     == 0 ||
           strcmp(v, "manual") == 0;
}

/* Copy `v` into dst[cap], stripping one layer of surrounding double
 * quotes. Returns 0 on success, -1 if empty or truncated. */
static int
cfg_path(char *dst, size_t cap, const char *v) {
    size_t n;
    if (v[0] == '"') {
        const char *close = strrchr(v + 1, '"');
        if (!close || close == v + 1) return -1;
        n = (size_t)(close - (v + 1));
        v = v + 1;
    } else {
        n = strlen(v);
    }
    if (n == 0 || n >= cap) return -1;
    memcpy(dst, v, n);
    dst[n] = '\0';
    return 0;
}

int
hlse_config_load(const char *path, HlseConfig *cfg,
                 char *err, size_t errcap) {
    FILE *fp;
    char line[1200];
    int lineno = 0;

    memset(cfg, 0, sizeof(*cfg));
    fp = fopen(path, "r");
    if (!fp) {
        if (err && errcap > 0)
            snprintf(err, errcap, "cannot read config file '%s': %s",
                     path, strerror(errno));
        return -1;
    }
    /* A group/world-writable config can be edited to weaken the gate
     * (fail-on = 100, a swapped baseline/patterns file). Warn rather than
     * fail — the operator named this file explicitly and shared-group
     * CI setups are legitimate — but never stay silent about it. */
    {
        struct stat st;
        if (fstat(fileno(fp), &st) == 0 && (st.st_mode & 0022))
            fprintf(stderr, "hlse: warning: config file '%s' is group- or "
                    "world-writable (mode %04o) — it controls the detection "
                    "gate\n", path, st.st_mode & 0777);
    }
    while (fgets(line, sizeof(line), fp)) {
        char *s, *key, *v, *p;
        lineno++;
        s = cfg_trim(line);
        if (*s == '#' || *s == '\0') continue;

        /* key = token up to whitespace or '='; value = remainder after
         * optional ws, '=', ws. */
        key = s;
        for (p = s; *p && *p != '=' && *p != ' ' && *p != '\t'; p++)
            ;
        if (*p) *p++ = '\0';
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '=') p++;
        while (*p == ' ' || *p == '\t') p++;
        v = p;
        if (*v == '\0') {
            cfg_err(err, errcap, path, lineno, "missing value");
            fclose(fp);
            return -1;
        }

        if      (strcmp(key, "json")         == 0) {
            cfg->has_json = 1;
            if (!cfg_bool(v, &cfg->json)) goto bad_bool;
        }
        else if (strcmp(key, "sarif")        == 0) {
            cfg->has_sarif = 1;
            if (!cfg_bool(v, &cfg->sarif)) goto bad_bool;
        }
        else if (strcmp(key, "quiet")        == 0) {
            cfg->has_quiet = 1;
            if (!cfg_bool(v, &cfg->quiet)) goto bad_bool;
        }
        else if (strcmp(key, "syslog")       == 0) {
            cfg->has_syslog = 1;
            if (!cfg_bool(v, &cfg->syslog)) goto bad_bool;
        }
        else if (strcmp(key, "fingerprints") == 0) {
            cfg->has_fingerprints = 1;
            if (!cfg_bool(v, &cfg->fingerprints)) goto bad_bool;
        }
        else if (strcmp(key, "git-history")  == 0) {
            cfg->has_git_history = 1;
            if (!cfg_bool(v, &cfg->git_history)) goto bad_bool;
        }
        else if (strcmp(key, "fail-on")      == 0) {
            cfg->has_fail_on = 1;
            if (!cfg_fail_on(v, &cfg->fail_on)) {
                cfg_err(err, errcap, path, lineno,
                        "fail-on expects log|alert|block|isolate or 0..100");
                fclose(fp);
                return -1;
            }
        }
        else if (strcmp(key, "from")         == 0) {
            if (!cfg_from(v)) {
                cfg_err(err, errcap, path, lineno,
                        "from expects email|sms|dm|qr|manual");
                fclose(fp);
                return -1;
            }
            snprintf(cfg->from, sizeof(cfg->from), "%s", v);
        }
        else if (strcmp(key, "baseline")     == 0) {
            if (cfg_path(cfg->baseline, sizeof(cfg->baseline), v) != 0)
                goto bad_path;
        }
        else if (strcmp(key, "log-file")     == 0) {
            if (cfg_path(cfg->log_file, sizeof(cfg->log_file), v) != 0)
                goto bad_path;
        }
        else if (strcmp(key, "patterns")     == 0) {
            if (cfg_path(cfg->patterns, sizeof(cfg->patterns), v) != 0)
                goto bad_path;
        }
        else {
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "unknown config key '%s' (expected json|sarif|quiet|"
                     "syslog|fingerprints|git-history|fail-on|from|"
                     "baseline|log-file|patterns)", key);
            cfg_err(err, errcap, path, lineno, msg);
            fclose(fp);
            return -1;
        }
        continue;

    bad_bool:
        cfg_err(err, errcap, path, lineno,
                "expected true|yes|on|1 or false|no|off|0");
        fclose(fp);
        return -1;
    bad_path:
        cfg_err(err, errcap, path, lineno,
                "bad path value (empty, overlong, or unterminated quote)");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}
