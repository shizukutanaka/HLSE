/* hlse_main.c — CLI entry point for hlse_core.
 *
 * Everything here is CLI-mode code: the no-args demo, option parsing
 * into HlseCli, alert-sink init, and one-line dispatch to the
 * hlse_cmd_* handlers in hlse_cli.c. Library users (libhlse.so,
 * hlse-server, hlsed) link the engine without this file — it is not
 * in CORE_SRC, so HLSE_CORE_AS_LIB builds never see a main().        */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include "hlse_core.h"   /* Verdict, ScanResult, public API declarations */
#include "hlse_text.h"   /* TextVerdict, hlse_check_text */
#include "hlse_config.h"  /* HlseConfig, hlse_config_load (--config) */
#include "hlse_selftest.h" /* hlse_*_self_test, hlse_benchmark */
#include "hlse_registry.h" /* hlse_list_patterns */
#include "hlse_channel.h"  /* hlse_from_channel, hlse_channel_delta/reason */
#include "hlse_baseline.h" /* hlse_baseline_load/clear (--baseline) */
#include "hlse_patterns.h" /* hlse_patterns_load (--patterns) */
#include "hlse_emit.h"    /* hlse_print_* advisory emitters, stdin_mode */
#include "hlse_cli.h"     /* HlseCli + hlse_cmd_* handlers */
#include "hlse_util.h"    /* hlse_display_copy (operand echo sanitize) */
#include "hlse_alert.h"   /* hlse_alert_init/emit/shutdown */
#include "hlse_secrets.h" /* hlse_clear_custom_secret_patterns/brands */

#define HLSE_BUILD_DATE    __DATE__

/* Subcommand dispatch table — the handler signature is uniform so a
 * new subcommand is one line here and nowhere else. `network`/`audit`
 * take only the options struct; thin wrappers adapt them.            */
static int cmd_network_(const HlseCli *o, int argc, char **argv, int idx) {
    (void)argc; (void)argv; (void)idx;
    return hlse_cmd_network(o);
}
static int cmd_audit_(const HlseCli *o, int argc, char **argv, int idx) {
    (void)argc; (void)argv; (void)idx;
    return hlse_cmd_audit(o);
}

static const struct {
    const char *name;
    int (*fn)(const HlseCli *, int, char **, int);
} SUBCOMMANDS[] = {
    /* hlse_core scan <dir> — recursive secrets + masquerade; exit 1 on hit */
    { "scan",      hlse_cmd_scan      },
    /* hlse_core protect <path> [--ransomware|--smb|--mbr|--net] */
    { "protect",   hlse_cmd_protect   },
    { "esp",       hlse_cmd_esp       },
    { "package",   hlse_cmd_package   },
    { "paste",     hlse_cmd_paste     },
    { "secret",    hlse_cmd_secret    },
    { "email",     hlse_cmd_email     },
    { "clipboard", hlse_cmd_clipboard },
    { "file",      hlse_cmd_file      },
    { "text",      hlse_cmd_text      },
    { "network",   cmd_network_       },
    { "audit",     cmd_audit_         },
};

int
main(int argc, char **argv) {
    HlseCli o = {0};
    o.fail_threshold = 60;   /* BLOCK — --fail-on overrides */
    HlseConfig cfg;             /* --config defaults; must live for all of
                                   main() — hlse_from_channel()/o.baseline_file/
                                   o.opt_log_file may point into it.        */
    memset(&cfg, 0, sizeof(cfg));
    int argc_flags;   /* argv index where "--" ends option scanning */
    int idx = 1;

    if (argc < 2) {
        /* Apple principle: the first experience IS the product.
         * Instead of a wall of usage text, show a live demo so the
         * user understands in 5 seconds what HLSE does.              */
        printf("HLSE %s — phishing & scam detection\n\n", HLSE_VERSION);

        printf("  Safe URL:\n");
        { Verdict v = hlse_check_url("https://github.com");
          printf("    https://github.com");
          printf("  →  %s\n\n", hlse_action_for_score(v.score)); }

        printf("  Phishing URL:\n");
        { Verdict v = hlse_check_url("https://g00gle.com");
          int i;
          printf("    https://g00gle.com");
          printf("  →  %s [%d/100]\n", hlse_action_for_score(v.score), v.score);
          for (i = 0; i < v.n_reasons; i++)
              printf("      %s\n", v.reasons[i]);
          printf("\n"); }

        printf("  Safe message:\n");
        { TextVerdict v = hlse_check_text("Meeting at 3pm tomorrow");
          printf("    \"Meeting at 3pm tomorrow\"");
          printf("  →  %s\n\n", hlse_text_action_for_score(v.score)); }

        printf("  Scam message:\n");
        { TextVerdict v = hlse_check_text(
              "URGENT: Buy iTunes gift cards immediately to unlock your account");
          int i;
          printf("    \"URGENT: Buy iTunes gift cards...\"\n");
          printf("                                     →  %s [%d/100]\n",
                 hlse_text_action_for_score(v.score), v.score);
          for (i = 0; i < v.n_reasons; i++)
              printf("      %s\n", v.reasons[i]);
          printf("\n"); }

        printf("Try it:  %s <url>           Scan a URL\n", argv[0]);
        printf("         %s text \"<msg>\"    Scan text\n", argv[0]);
        printf("         %s package <name>  Check for typosquat\n", argv[0]);
        printf("         %s paste \"<cmd>\"   Check pasted command\n", argv[0]);
        printf("         %s protect <dir>   Ransomware scan\n", argv[0]);
        printf("         %s network         Network safety check\n", argv[0]);
        printf("         %s --help          All options\n", argv[0]);

        return 0;
    }

    /* End-of-options boundary. Global flags are matched "anywhere" for
     * convenience, but that must never reach OPERAND positions: an operand is
     * attacker-influenced data (a scanned URL, message, package name, clipboard
     * string). Without a boundary, a crafted operand such as
     *   hlse_core clipboard "--log-file" "/tmp/x"
     * is consumed as a flag — creating a file from scan data, and worse,
     * shifting argv so the real input is never analysed while the process still
     * exits 0 ("safe"). That is a silent detection bypass.
     *
     * `--` marks the end of options: everything after it is data, never a flag.
     * argc_flags bounds every flag loop below; the marker itself is removed
     * once, here, so the subcommand dispatch never sees it. */
    argc_flags = argc;
    {
        int i;
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--") == 0) {
                argc_flags = i;                     /* scan flags only before it */
                { int j; for (j = i; j < argc - 1; j++) argv[j] = argv[j+1]; argc--; }
                break;
            }
        }
        if (argc_flags > argc) argc_flags = argc;
    }

    /* Parse --config <file> FIRST, before any other flag loop: config keys
     * write defaults into the same globals the loops below assign, so an
     * explicit CLI flag always wins. A config `patterns` file is loaded
     * here too — if --patterns is also given, its handler clears the
     * custom registries and replaces it. */
    {
        {
            int i;
            for (i = 1; i < argc_flags - 1; i++) {
                if (strcmp(argv[i], "--config") == 0) {
                    char cerr[256];
                    if (hlse_config_load(argv[i + 1], &cfg,
                                         cerr, sizeof(cerr)) != 0) {
                        fprintf(stderr, "Error: %s\n", cerr);
                        return 2;
                    }
                    hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                    break;
                }
            }
        }
        if (cfg.has_json)         o.json_out            = cfg.json;
        if (cfg.has_sarif)        o.sarif_out           = cfg.sarif;
        if (cfg.has_quiet)        o.quiet               = cfg.quiet;
        if (cfg.has_syslog)       o.opt_syslog          = cfg.syslog;
        if (cfg.has_fingerprints) o.emit_fingerprints = cfg.fingerprints;
        if (cfg.has_git_history)  o.git_history       = cfg.git_history;
        if (cfg.has_fail_on)      o.fail_threshold    = cfg.fail_on;
        if (cfg.from[0])          hlse_set_from_channel(cfg.from);
        if (cfg.baseline[0])      o.baseline_file     = cfg.baseline;
        if (cfg.log_file[0])      o.opt_log_file        = cfg.log_file;
        if (cfg.patterns[0] && hlse_patterns_load(cfg.patterns) != 0) {
            fprintf(stderr, "Error: cannot read config patterns file "
                    "'%s': %s\n", cfg.patterns, strerror(errno));
            return 2;
        }
    }

    /* Boolean global flags: one table, one pass. These were six separate
     * scan loops that differed only in the flag name and the variable set,
     * each restating the argv-shifting logic. Adding a flag is now a row. */
    {
        struct { const char *name; const char *alias; int *flag; } bools[] = {
            { "--json",         NULL, &o.json_out            },
            { "--sarif",        NULL, &o.sarif_out           },
            { "--quiet",        "-q", &o.quiet               },
            { "--syslog",       NULL, &o.opt_syslog          },
            { "--fingerprints", NULL, &o.emit_fingerprints },
            { "--git-history",  NULL, &o.git_history       },
        };
        const int nbools = (int)(sizeof(bools) / sizeof(bools[0]));
        int i, k;
        for (i = 1; i < argc_flags; i++) {
            for (k = 0; k < nbools; k++) {
                if (strcmp(argv[i], bools[k].name) == 0 ||
                    (bools[k].alias && strcmp(argv[i], bools[k].alias) == 0)) {
                    *bools[k].flag = 1;
                    hlse_argv_remove(argv, &argc, &argc_flags, i, 1);
                    i--;            /* re-examine the element shifted into i */
                    break;
                }
            }
        }
    }

    /* Parse --fail-on <tier> (anywhere) — the machine consumer's risk gate.
     * The exit code (1 = threat) collapses five severity tiers into pass/fail;
     * hardcoding the boundary at BLOCK(60) imposes one risk posture on every
     * pipeline. A payments repo may want to fail at ALERT(40); a noisy docs
     * repo only at ISOLATE(80). This sets the score at/above which the process
     * exits 1. Default stays 60 (block) for backward compatibility.        */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--fail-on") == 0) {
                const char *t = argv[i + 1];
                if      (strcmp(t, "log")     == 0) o.fail_threshold = 15;
                else if (strcmp(t, "alert")   == 0) o.fail_threshold = 40;
                else if (strcmp(t, "block")   == 0) o.fail_threshold = 60;
                else if (strcmp(t, "isolate") == 0) o.fail_threshold = 80;
                else {
                    /* Accept a bare numeric threshold (0..100) too. */
                    char *end;
                    long n = strtol(t, &end, 10);
                    if (*end == '\0' && n >= 0 && n <= 100)
                        o.fail_threshold = (int)n;
                    else {
                        fprintf(stderr, "Error: --fail-on expects "
                                "log|alert|block|isolate or 0..100\n");
                        return 2;
                    }
                }
                hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --from <channel> — delivery-channel prior for URL risk boost.
     * Socratic: the same URL in an unsolicited SMS is riskier than one typed
     * by hand.  The flag lets callers supply that context so the verdict
     * reflects real-world threat priors, not just URL structure alone.     */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--from") == 0) {
                const char *ch = argv[i + 1];
                if (strcmp(ch, "email")  == 0 || strcmp(ch, "sms") == 0 ||
                    strcmp(ch, "dm")     == 0 || strcmp(ch, "qr")  == 0 ||
                    strcmp(ch, "manual") == 0) {
                    hlse_set_from_channel(ch);
                } else {
                    fprintf(stderr,
                            "Error: --from expects email|sms|dm|qr|manual\n");
                    return 2;
                }
                hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --baseline <file> (Perspective 107 / P0-1) — suppress findings
     * whose fingerprint is listed, so a brownfield repo's accepted findings
     * do not fail the CI gate forever. */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--baseline") == 0) {
                o.baseline_file = argv[i + 1];
                hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --log-file <path> (value) — append one JSONL record per finding. */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--log-file") == 0) {
                o.opt_log_file = argv[i + 1];
                hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Parse --patterns <file> (Perspective 110 / P0-3) — register custom
     * organization-specific secret patterns without a rebuild. */
    {
        int i;
        for (i = 1; i < argc_flags - 1; i++) {
            if (strcmp(argv[i], "--patterns") == 0) {
                const char *ppath = argv[i + 1];
                /* Replace any config-file patterns wholesale so CLI
                 * precedence is clean, not additive. */
                hlse_clear_custom_secret_patterns();
                hlse_clear_custom_brands();
                if (hlse_patterns_load(ppath) != 0) {
                    fprintf(stderr, "Error: cannot read --patterns file '%s': %s\n",
                            ppath, strerror(errno));
                    return 2;
                }
                hlse_argv_remove(argv, &argc, &argc_flags, i, 2);
                break;
            }
        }
    }

    /* Every legitimate flag was consumed above, so a '-'-leading token left
     * inside the flag region is an unknown option — except dispatch flags
     * (--version/--stdin/...) and subcommand-local flags (--mbr/--smb/...)
     * which are recognised downstream. Reject the rest: without this check a
     * typo'd flag (--baselne) falls through to the operand position and is
     * scanned as literal text — a fake SAFE verdict, exit 0. `--` still
     * separates real operands that begin with '-'. */
    {
        static const char *const dash_ok[] = {
            "-h", "--help", "-V", "--version", "--self-test", "--benchmark",
            "--stdin", "--list-patterns",
            "--manifest", "--mbr", "--ransomware", "--smb", "--net",
        };
        int i, k;
        for (i = 1; i < argc_flags; i++) {
            if (argv[i][0] != '-') continue;
            for (k = 0; k < (int)(sizeof(dash_ok) / sizeof(dash_ok[0])); k++)
                if (strcmp(argv[i], dash_ok[k]) == 0) break;
            if (k == (int)(sizeof(dash_ok) / sizeof(dash_ok[0]))) {
                fprintf(stderr, "unknown option: %s "
                        "(use -- before operands that begin with '-')\n",
                        argv[i]);
                return 2;
            }
        }
    }

    /* Load the baseline file now that flags are parsed. A missing/unreadable
     * baseline is a usage error — silently ignoring it would let the gate
     * pass on a typo'd path, defeating the purpose. */
    if (o.baseline_file && hlse_baseline_load(o.baseline_file) != 0) {
        fprintf(stderr, "Error: cannot read --baseline file '%s': %s\n",
                o.baseline_file, strerror(errno));
        return 2;
    }
    /* Register cleanup once — covers every one of main()'s many return paths
     * uniformly (atexit failure just reverts to pre-fix behavior: a no-op). */
    if (o.baseline_file) atexit(hlse_baseline_clear);

    /* Open alert sinks now that flags are parsed. A requested but unopenable
     * --log-file is a usage error (same convention as --baseline/--patterns). */
    if ((o.opt_syslog || o.opt_log_file) &&
        hlse_alert_init(o.opt_syslog, o.opt_log_file) != 0) {
        fprintf(stderr, "Error: cannot open --log-file '%s': %s\n",
                o.opt_log_file ? o.opt_log_file : "(syslog only)", strerror(errno));
        return 2;
    }
    if (o.opt_syslog || o.opt_log_file) atexit(hlse_alert_shutdown);

    /* Quiet mode: redirect stdout to /dev/null. If the redirect fails we must
     * not silently keep printing — that would violate the quiet-mode contract
     * (callers rely on the exit code alone). Report and exit with usage error. */
    if (o.quiet && !o.json_out) {
        if (freopen("/dev/null", "w", stdout) == NULL) {
            fprintf(stderr, "Error: --quiet could not redirect stdout\n");
            return 2;
        }
    }

    if (strcmp(argv[idx], "-V") == 0 || strcmp(argv[idx], "--version") == 0) {
        printf("hlse_core %s (built %s)\n", HLSE_VERSION, HLSE_BUILD_DATE);
        return 0;
    }
    if (strcmp(argv[idx], "--self-test") == 0) {
        int rc1 = hlse_url_self_test();
        int rc2 = hlse_text_self_test();
        return rc1 || rc2 ? 1 : 0;
    }
    if (strcmp(argv[idx], "--list-patterns") == 0) {
        return hlse_list_patterns(o.json_out);
    }
    if (strcmp(argv[idx], "--benchmark") == 0) {
        return hlse_benchmark();
    }
    if (strcmp(argv[idx], "--stdin") == 0) {
        return hlse_stdin_mode(o.json_out, o.fail_threshold);
    }
    if (strcmp(argv[idx], "-h") == 0 || strcmp(argv[idx], "--help") == 0) {
        hlse_print_usage(argv[0]);
        return 0;
    }

    {
        size_t ci;
        for (ci = 0; ci < sizeof(SUBCOMMANDS)/sizeof(SUBCOMMANDS[0]); ci++) {
            if (strcmp(argv[idx], SUBCOMMANDS[ci].name) == 0)
                return SUBCOMMANDS[ci].fn(&o, argc, argv, idx);
        }
    }

    /* Default: use unified scan (auto-detects URL vs text) */
    {
        const char *input = argv[idx];

        /* Empty string → nothing to scan */
        if (!input || !input[0]) {
            fprintf(stderr, "Nothing to scan. Pass a URL or message.\n");
            return 2;
        }

        /* Use unified scan API */
        ScanResult sr = hlse_scan(input);
        /* Push to alert sinks (--syslog/--log-file) if enabled — emitted from
         * the ScanResult so every output branch below is covered uniformly. */
        {
            const char *ar[16];
            int ai, an = sr.n_reasons;
            if (an > 16) an = 16;
            for (ai = 0; ai < an; ai++) ar[ai] = sr.reasons[ai];
            hlse_alert_emit(sr.is_url ? "url" : "text", sr.score,
                            hlse_severity_for_score(sr.score), input, ar, an);
        }
        if (o.json_out) {
            /* For JSON, delegate to the appropriate printer. For text
             * inputs use the ScanResult directly (not hlse_check_text
             * alone) so embedded URL extraction is honoured. */
            if (sr.is_url) {
                Verdict uv = hlse_check_url(input);
                hlse_print_json_url(input, &uv);
            } else {
                TextVerdict tv;
                int ti;
                memset(&tv, 0, sizeof(tv));
                tv.score = sr.score;
                tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                               ? sr.n_reasons : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                for (ti = 0; ti < tv.n_reasons; ti++)
                    snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                             "%s", sr.reasons[ti]);
                hlse_print_json_text(input, &tv);
            }
        } else if (sr.score == 0) {
            /* Channel-only risk: content scored 0 but delivery channel adds prior */
            if (hlse_from_channel()) {
                int d = hlse_channel_delta(hlse_from_channel());
                if (d > 0) {
                    const char *ch_rsn = hlse_channel_reason(hlse_from_channel());
                    const char *bs2 = hlse_blindspot_for(sr.is_url ? "url" : "text");
                    char db[8192];
                    printf("%-7s [%d]  %s\n", hlse_action_for_score(d), d,
                           hlse_display_copy(db, sizeof(db), input));
                    if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                    if (bs2) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs2);
                    {
                        int eff_gate = d;
                        return eff_gate >= o.fail_threshold ? 1 : 0;
                    }
                }
            }
            {
                char canon_brand[64];
                int has_c = sr.is_url &&
                            hlse_canonical_confirm(input, canon_brand, sizeof(canon_brand));
                const char *bs = hlse_blindspot_for(
                    has_c ? "url_canonical" : (sr.is_url ? "url" : "text"));
                char db[8192];
                printf("OK    %s\n",
                       hlse_display_copy(db, sizeof(db), input));
                if (has_c)
                    printf("  \xe2\x9c\x94 Canonical: confirmed authentic %s domain "
                           "(HLSE brand registry)\n", canon_brand);
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            }
        } else {
            int i;
            int eff = sr.score;
            const char *ch_rsn = NULL;
            if (hlse_from_channel()) {
                int d = hlse_channel_delta(hlse_from_channel());
                eff += d; if (eff > 100) eff = 100;
                ch_rsn = hlse_channel_reason(hlse_from_channel());
            }
            {
                char db[8192];
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(eff), eff,
                       hlse_display_copy(db, sizeof(db), input));
            }
            for (i = 0; i < sr.n_reasons; i++) {
                if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                printf("  \xc2\xb7 %s\n", sr.reasons[i]);
            }
            if (sr.is_url) {
                /* Re-run URL check to get a Verdict for pattern synthesis.
                 * hlse_scan already ran this internally; the cost is low.  */
                Verdict uv = hlse_check_url(input);
                const char *ex = hlse_url_exoneration(&uv);
                hlse_print_url_advisories(input, &uv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            } else {
                TextVerdict tv;
                const char *ex;
                int ti;
                memset(&tv, 0, sizeof(tv));
                tv.score = sr.score;
                tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                               ? sr.n_reasons
                               : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                for (ti = 0; ti < tv.n_reasons; ti++)
                    snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                             "%s", sr.reasons[ti]);
                ex   = hlse_text_exoneration(&tv);
                hlse_print_text_advisories(&tv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        /* Gate uses effective score so --from boost is honoured in exit code. */
        {
            int eff_gate = sr.score;
            if (hlse_from_channel()) {
                int d = hlse_channel_delta(hlse_from_channel());
                eff_gate += d; if (eff_gate > 100) eff_gate = 100;
            }
            return eff_gate >= o.fail_threshold ? 1 : 0;
        }
    }
}
