/* hlse_cli.c — per-subcommand handlers for the hlse_core CLI driver.
 * Each takes the parsed options plus argv (idx points at the subcommand
 * name) and returns the process exit status. Extracted verbatim from
 * main() (split increments 10+); flag state arrives via HlseCli. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "hlse_core.h"
#include "hlse_protect.h"
#include "hlse_secrets.h"
#include "hlse_supply.h"
#include "hlse_file.h"
#include "hlse_audit.h"
#include "hlse_meta.h"
#include "hlse_emit.h"
#include "hlse_util.h"
#include "hlse_alert.h"
#include "hlse_cli.h"

int
hlse_cmd_protect(const HlseCli *o, int argc, char **argv, int idx) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s protect <path> [--ransomware|--smb|--mbr|--net]\n", argv[0]);
            return 2;
        }
        {
            const char *path = argv[idx + 1];
            int modules = 0;

            /* Verify path exists */
            if (access(path, F_OK) != 0) {
                fprintf(stderr, "Error: cannot access '%s': %s\n",
                        path, strerror(errno));
                return 2;
            }
            int ai;

            /* Parse module flags */
            for (ai = idx + 2; ai < argc; ai++) {
                if (strcmp(argv[ai], "--ransomware") == 0) modules |= HLSE_PROTECT_RANSOMWARE;
                else if (strcmp(argv[ai], "--smb") == 0)   modules |= HLSE_PROTECT_SMB;
                else if (strcmp(argv[ai], "--mbr") == 0)   modules |= HLSE_PROTECT_MBR;
                else if (strcmp(argv[ai], "--net") == 0)    modules |= HLSE_PROTECT_NETWORK_DRIVE;
            }
            if (modules == 0) {
                /* Auto-detect: if path starts with /dev/, use MBR; else file-based */
                if (strncmp(path, "/dev/", 5) == 0) {
                    modules = HLSE_PROTECT_MBR;
                } else {
                    modules = HLSE_PROTECT_RANSOMWARE | HLSE_PROTECT_SMB | HLSE_PROTECT_NETWORK_DRIVE;
                }
            }

            ProtectionVerdict pv = hlse_protect_scan(path, modules);
            {
                const char *aar[16]; int aq, aqn = pv.n_reasons;
                if (aqn > 16) aqn = 16;
                for (aq = 0; aq < aqn; aq++) aar[aq] = pv.reasons[aq];
                hlse_alert_emit("protect", pv.score,
                    hlse_severity_for_score(pv.score), path, aar, aqn);
            }

            if (o->json_out) {
                /* JSON output for protect.
                 * Perspective 100: this was the only verdict kind still
                 * missing hlse_version and severity — every other kind
                 * (url/text/file/secret/email/network/esp/package/paste/
                 * clipboard) has carried both since P84/P85; protect was
                 * never brought in line. */
                char esc_path[4096];
                hlse_json_escape(path, esc_path, sizeof(esc_path));
                printf("{\"kind\":\"protect\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"target\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"severity\":%d,\"reasons\":[",
                       esc_path, pv.score,
                       hlse_action_for_score(pv.score),
                       hlse_severity_for_score(pv.score));
                {
                    int i;
                    for (i = 0; i < pv.n_reasons; i++) {
                        char esc[512];
                        hlse_json_escape(pv.reasons[i], esc, sizeof(esc));
                        printf("%s\"%s\"", i > 0 ? "," : "", esc);
                    }
                }
                printf("]");
                if (pv.score == 0) {
                    const char *bs = hlse_blindspot_for("protect");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (pv.score > 0) {
                    int ns = pv.n_reasons;
                    const char *conf = ns >= 3 ? "high confidence" :
                                       ns >= 2 ? "corroborated" : "single signal";
                    printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
                }
                if (pv.score >= 40) {
                    /* Perspective 100: a single SMB canary-file access (+40)
                     * or mass-rename detection (+40) lands the protect
                     * verdict in ALERT (40-59) alone — the same gap P95-98
                     * closed for other kinds. pattern/objective/verify now
                     * fire from the ALERT floor; triage/cascade_risk
                     * (disconnect-network incident response) stay
                     * BLOCK+-only (>= 60).
                     * Perspective 103: text now shared with the plaintext
                     * path below via protect_*_text() accessors. */
                    char e[512];
                    hlse_json_escape(hlse_protect_pattern_text(), e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"HLSE-PROTECT-RANSOM\"");
                    hlse_json_escape(hlse_protect_objective_text(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                    hlse_json_escape(hlse_protect_verify_text(),    e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                }
                if (pv.score >= 60) {
                    char e[512];
                    hlse_json_escape(hlse_protect_triage_text(),  e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                    hlse_json_escape(hlse_protect_cascade_text(), e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("protect", pv.score);
                    if (ex) {
                        char e[512];
                        hlse_json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (pv.score == 0) {
                const char *bs = hlse_blindspot_for("protect");
                char db[8192];
                printf("OK    %s\n",
                       hlse_display_copy(db, sizeof(db), path));
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                char db[8192];
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(pv.score), pv.score,
                       hlse_display_copy(db, sizeof(db), path));
                for (i = 0; i < pv.n_reasons; i++) {
                    printf("  \xc2\xb7 %s\n", pv.reasons[i]);
                }
                if (pv.score >= 40) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_protect_pattern_text());
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_protect_objective_text());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_protect_verify_text());
                }
                if (pv.score >= 60) {
                    printf("  \xe2\x9a\x91 Immediate action: %s\n", hlse_protect_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", hlse_protect_cascade_text());
                }
                if (pv.score < 60) {
                    const char *ex = hlse_exoneration_for("protect", pv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return pv.score >= o->fail_threshold ? 1 : 0;
        }
}

int
hlse_cmd_esp(const HlseCli *o, int argc, char **argv, int idx) {
        /* EFI System Partition integrity (UEFI bootkit indicators). */
        const char *path = (argc > idx + 1) ? argv[idx + 1] : NULL;
        ProtectionVerdict pv = hlse_esp_verify(path);
        if (o->json_out) {
            int i;
            printf("{\"kind\":\"esp\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"reasons\":[",
                   pv.score, hlse_action_for_score(pv.score),
                   hlse_severity_for_score(pv.score));
            for (i = 0; i < pv.n_reasons; i++) {
                char esc[512];
                hlse_json_escape(pv.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]");
            {
                const char *bs = hlse_blindspot_for("esp");
                if (pv.score == 0 && bs) {
                    char esc_bs[512];
                    hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                    printf(",\"blind_spot\":\"%s\"", esc_bs);
                }
            }
            if (pv.score > 0) {
                int ns = pv.n_reasons;
                const char *conf = ns >= 3 ? "high confidence" :
                                   ns >= 2 ? "corroborated" : "single signal";
                printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
            }
            if (pv.score >= 60) {
                char e[512];
                hlse_json_escape(hlse_esp_pattern_text(),   e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                printf(",\"pattern_id\":\"HLSE-ESP-BOOTKIT\"");
                hlse_json_escape(hlse_esp_objective_text(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                hlse_json_escape(hlse_esp_verify_text(),     e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                hlse_json_escape(hlse_esp_triage_text(),     e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                hlse_json_escape(hlse_esp_cascade_text(),    e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
            }
            if (pv.score > 0 && pv.score < 60) {
                const char *ex = hlse_exoneration_for("esp", pv.score);
                if (ex) {
                    char e[512];
                    hlse_json_escape(ex, e, sizeof(e));
                    printf(",\"exoneration\":\"%s\"", e);
                }
            }
            printf("}\n");
        } else if (pv.score == 0) {
            const char *bs = hlse_blindspot_for("esp");
            printf("OK    (esp)%s%s\n",
                   pv.n_reasons ? " \xe2\x80\x94 " : "",
                   pv.n_reasons ? pv.reasons[0] : "");
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            int i;
            printf("%-7s [%d]  (esp)\n",
                   hlse_action_for_score(pv.score), pv.score);
            for (i = 0; i < pv.n_reasons; i++)
                printf("  \xc2\xb7 %s\n", pv.reasons[i]);
            if (pv.score >= 60) {
                printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_esp_pattern_text());
                printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_esp_objective_text());
                printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_esp_verify_text());
                printf("  \xe2\x9a\x91 Immediate action: %s\n", hlse_esp_triage_text());
                printf("  \xe2\x8a\x95 Also change: %s\n", hlse_esp_cascade_text());
            } else {
                const char *ex = hlse_exoneration_for("esp", pv.score);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        return pv.score >= o->fail_threshold ? 1 : 0;
}

int
hlse_cmd_clipboard(const HlseCli *o, int argc, char **argv, int idx) {
        if (argc < idx + 3) {
            fprintf(stderr,
                    "Usage: %s clipboard \"<copied addr>\" \"<pasted addr>\"\n",
                    argv[0]);
            return 2;
        }
        {
            CryptoSwapVerdict cv =
                hlse_check_crypto_swap(argv[idx + 1], argv[idx + 2]);
            {
                const char *aar[1]; int aqn = 0;
                if (cv.reason[0]) { aar[0] = cv.reason; aqn = 1; }
                hlse_alert_emit("clipboard", cv.score,
                    hlse_severity_for_score(cv.score),
                    cv.swapped[0] ? cv.swapped : "(clipboard)", aar, aqn);
            }
            const char *rem = hlse_remediation_for("clipboard", cv.score);
            if (o->json_out) {
                char eo[256], es[256], er[512], erm[512];
                hlse_json_escape(cv.original, eo, sizeof(eo));
                hlse_json_escape(cv.swapped, es, sizeof(es));
                hlse_json_escape(cv.reason, er, sizeof(er));
                hlse_json_escape(rem ? rem : "", erm, sizeof(erm));
                printf("{\"kind\":\"clipboard\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,"
                       "\"is_swap\":%d,"
                       "\"original\":\"%s\",\"swapped\":\"%s\",\"reason\":\"%s\","
                       "\"remediation\":\"%s\"",
                       cv.score, hlse_action_for_score(cv.score),
                       hlse_severity_for_score(cv.score),
                       cv.is_swap, eo, es, er, erm);
                if (cv.score == 0) {
                    const char *bs = hlse_blindspot_for("clipboard");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (cv.score >= 60) {
                    char e[512];
                    hlse_json_escape(hlse_clipboard_pattern_text(), e, sizeof(e));
                    printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"HLSE-CLIP-HIJACK\"");
                    hlse_json_escape(hlse_clipboard_objective_text(), e, sizeof(e));
                    printf(",\"objective\":\"%s\"", e);
                    hlse_json_escape(hlse_clipboard_verify_text(), e, sizeof(e));
                    printf(",\"verify\":\"%s\"", e);
                    hlse_json_escape(hlse_clipboard_triage_text(), e, sizeof(e));
                    printf(",\"triage\":\"%s\"", e);
                    hlse_json_escape(hlse_clipboard_cascade_text(), e, sizeof(e));
                    printf(",\"cascade_risk\":\"%s\"", e);
                }
                printf("}\n");
            } else if (cv.score == 0) {
                const char *bs = hlse_blindspot_for("clipboard");
                printf("OK    (clipboard \xe2\x80\x94 no address swap detected)\n");
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                printf("%-7s [%d]  (clipboard)\n",
                       hlse_action_for_score(cv.score), cv.score);
                if (cv.reason[0]) printf("  \xc2\xb7 %s\n", cv.reason);
                if (rem) printf("  \xe2\x86\x92 Action: %s\n", rem);
                if (cv.score >= 60) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_clipboard_pattern_text());
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_clipboard_objective_text());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_clipboard_verify_text());
                    printf("  \xe2\x9a\x91 If you acted: %s\n", hlse_clipboard_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", hlse_clipboard_cascade_text());
                }
            }
            return cv.score >= o->fail_threshold ? 1 : 0;
        }
}

int
hlse_cmd_audit(const HlseCli *o) {
        AuditVerdict av = hlse_audit_all();
        int hi = hlse_audit_hardening_index(&av);
        const char *band = hi >= 90 ? "hardened"
                         : hi >= 70 ? "good"
                         : hi >= 50 ? "fair" : "weak";
        /* Pre-compute severity counts for next_steps guidance */
        int crit_count = 0, high_count = 0;
        { int ci;
          for (ci = 0; ci < av.n_findings; ci++) {
              if (av.findings[ci].severity >= 5) crit_count++;
              else if (av.findings[ci].severity == 4) high_count++;
          }
        }
        if (o->json_out) {
            int i;
            printf("{\"kind\":\"audit\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,"
                   "\"hardening_index\":%d,\"hardening_band\":\"%s\","
                   "\"crit_count\":%d,\"high_count\":%d,"
                   "\"findings\":[",
                   av.score, hlse_action_for_score(av.score),
                   hlse_severity_for_score(av.score), hi, band,
                   crit_count, high_count);
            for (i = 0; i < av.n_findings; i++) {
                char esc[512];
                const char *fix = (av.findings[i].severity >= 4)
                    ? hlse_audit_remediation_for(av.findings[i].description)
                    : NULL;
                hlse_json_escape(av.findings[i].description, esc, sizeof(esc));
                printf("%s{\"severity\":%d,\"description\":\"%s\"",
                       i > 0 ? "," : "",
                       av.findings[i].severity, esc);
                if (fix) {
                    char efix[512];
                    hlse_json_escape(fix, efix, sizeof(efix));
                    printf(",\"fix\":\"%s\"", efix);
                }
                printf("}");
            }
            printf("]");
            if (av.score == 0) {
                const char *bs = hlse_blindspot_for("audit");
                if (bs) {
                    char esc_bs[512];
                    hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                    printf(",\"blind_spot\":\"%s\"", esc_bs);
                }
            } else {
                char ns[256];
                if (crit_count > 0)
                    snprintf(ns, sizeof(ns),
                             "fix the %d critical finding(s) first \xe2\x80\x94 "
                             "CRITICAL items are actively exploitable",
                             crit_count);
                else if (high_count > 0)
                    snprintf(ns, sizeof(ns),
                             "fix the %d HIGH finding(s) to reach the next "
                             "hardening band (currently: %s)",
                             high_count, band);
                else
                    snprintf(ns, sizeof(ns),
                             "address remaining LOW/MED findings to improve "
                             "the hardening index (currently: %s)",
                             band);
                { char ens[256];
                  hlse_json_escape(ns, ens, sizeof(ens));
                  printf(",\"next_steps\":\"%s\"", ens);
                }
            }
            printf("}\n");
        } else if (av.score == 0) {
            const char *bs = hlse_blindspot_for("audit");
            printf("OK    (audit \xe2\x80\x94 no issues found)  "
                   "Hardening index: %d/100 (%s)\n", hi, band);
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            int i;
            printf("%-7s [%d]  (system audit)  Hardening index: %d/100 (%s)\n",
                   hlse_action_for_score(av.score), av.score, hi, band);
            for (i = 0; i < av.n_findings; i++) {
                const char *sev_str[] = {
                    "PASS", "INFO", "LOW", "MED", "HIGH", "CRIT"
                };
                int s = (int)av.findings[i].severity;
                if (s < 0 || s > 5) s = 0;
                printf("  [%4s] %s\n", sev_str[s],
                       av.findings[i].description);
                if (s >= 4) {
                    const char *fix = hlse_audit_remediation_for(
                        av.findings[i].description);
                    if (fix)
                        printf("  \xe2\x9a\x92 Fix: %s\n", fix);
                }
            }
            if (crit_count > 0)
                printf("\xe2\x86\x92 Next step: fix the %d CRITICAL finding(s) first "
                       "\xe2\x80\x94 these are actively exploitable\n", crit_count);
            else if (high_count > 0)
                printf("\xe2\x86\x92 Next step: fix the %d HIGH finding(s) to improve "
                       "from '%s' toward the next hardening band\n",
                       high_count, band);
            else
                printf("\xe2\x86\x92 Next step: address remaining findings to improve "
                       "the hardening index (currently %s: %d/100)\n",
                       band, hi);
        }
        return av.score >= o->fail_threshold ? 1 : 0;
}

int
hlse_cmd_file(const HlseCli *o, int argc, char **argv, int idx) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s file <filepath>\n", argv[0]);
            return 2;
        }
        {
            FileVerdict fv;
            /* If the file exists on disk, do full magic-byte + filename
             * analysis. If not, still check the NAME for disguise tricks
             * (RLO, double extension, lure words) — these are dangerous
             * regardless of whether the file is present locally.        */
            if (access(argv[idx + 1], F_OK) == 0) {
                fv = hlse_check_file(argv[idx + 1]);
            } else {
                const char *base = strrchr(argv[idx + 1], '/');
                base = base ? base + 1 : argv[idx + 1];
                fv = hlse_check_filename(base);
            }
            {
                const char *aar[16]; int aq, aqn = fv.n_reasons;
                if (aqn > 16) aqn = 16;
                for (aq = 0; aq < aqn; aq++) aar[aq] = fv.reasons[aq];
                hlse_alert_emit("file", fv.score,
                    hlse_severity_for_score(fv.score), argv[idx + 1], aar, aqn);
            }
            if (o->json_out) {
                int i;
                char esc[512];
                hlse_json_escape(argv[idx + 1], esc, sizeof(esc));
                printf("{\"kind\":\"file\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"path\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"severity\":%d,\"reasons\":[",
                       esc, fv.score, hlse_action_for_score(fv.score),
                       hlse_severity_for_score(fv.score));
                for (i = 0; i < fv.n_reasons; i++) {
                    hlse_json_escape(fv.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]");
                if (fv.score == 0) {
                    const char *bs = hlse_blindspot_for("file");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (fv.score >= 40) {
                    /* Perspective 98: a single medium-confidence heuristic
                     * (e.g. Cabinet-magic/wrong-extension, +40) lands the
                     * file verdict in ALERT (40-59) alone, but this used to
                     * require score >= 60 for ANY advisory content at all —
                     * not even exoneration existed for "file" until this
                     * perspective. pattern/objective/verify now fire from
                     * the ALERT floor; triage/cascade_risk (post-open
                     * incident response) stay BLOCK+-only.
                     * Perspective 101: classification and advisory text now
                     * come from the shared accessors (see file_classify_
                     * pattern/file_masquerade_objective/file_masquerade_verify
                     * above) instead of a fourth independent copy. */
                    const char *fpat = hlse_file_classify_pattern(&fv);
                    char e[512];
                    hlse_json_escape(fpat, e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"%s\"", hlse_file_pattern_id(fpat));
                    hlse_json_escape(hlse_file_masquerade_objective(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                    hlse_json_escape(hlse_file_masquerade_verify(),    e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                }
                if (fv.score >= 60) {
                    static const char file_tri[] =
                        "if already opened: disconnect from the network "
                        "immediately; run a full antivirus scan; change "
                        "credentials for any service you were logged into at "
                        "the time; consider a full OS reinstall for high-score "
                        "detections";
                    static const char file_cas[] =
                        "all credentials and session tokens active when the file "
                        "was opened \xe2\x80\x94 malware runs with your session "
                        "context; also check for persistence (startup items, "
                        "scheduled tasks, browser extensions added)";
                    char e[512];
                    hlse_json_escape(file_tri, e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                    hlse_json_escape(file_cas, e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (fv.score > 0 && fv.score < 60) {
                    const char *ex = hlse_exoneration_for("file", fv.score);
                    if (ex) {
                        char e[512];
                        hlse_json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (fv.score == 0) {
                const char *bs = hlse_blindspot_for("file");
                char db[8192];
                printf("OK    %s\n",
                       hlse_display_copy(db, sizeof(db), argv[idx + 1]));
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                char db[8192];
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(fv.score), fv.score,
                       hlse_display_copy(db, sizeof(db), argv[idx + 1]));
                for (i = 0; i < fv.n_reasons; i++)
                    printf("  \xc2\xb7 %s\n", fv.reasons[i]);
                if (fv.score >= 40) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_file_classify_pattern(&fv));
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_file_masquerade_objective());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_file_masquerade_verify());
                }
                if (fv.score >= 60) {
                    printf("  \xe2\x9a\x91 If you acted: if already opened, disconnect "
                           "from the network; run antivirus; change credentials for "
                           "any active session\n");
                    printf("  \xe2\x8a\x95 Also change: all credentials and session "
                           "tokens active when the file was opened \xe2\x80\x94 check "
                           "for persistence (startup items, scheduled tasks, new "
                           "browser extensions)\n");
                }
                if (fv.score < 60) {
                    const char *ex = hlse_exoneration_for("file", fv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return fv.score >= o->fail_threshold ? 1 : 0;
        }
}

int
hlse_cmd_network(const HlseCli *o) {
        NetworkVerdict nv = hlse_check_network();
        {
            const char *aar[16]; int aq, aqn = nv.n_reasons;
            if (aqn > 16) aqn = 16;
            for (aq = 0; aq < aqn; aq++) aar[aq] = nv.reasons[aq];
            hlse_alert_emit("network", nv.score,
                hlse_severity_for_score(nv.score), "(network)", aar, aqn);
        }
        if (o->json_out) {
            int i;
            printf("{\"kind\":\"network\",\"hlse_version\":\"" HLSE_VERSION "\","
                   "\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"reasons\":[",
                   nv.score, hlse_action_for_score(nv.score),
                   hlse_severity_for_score(nv.score));
            for (i = 0; i < nv.n_reasons; i++) {
                char esc[512];
                hlse_json_escape(nv.reasons[i], esc, sizeof(esc));
                printf("%s\"%s\"", i > 0 ? "," : "", esc);
            }
            printf("]");
            if (nv.score == 0) {
                const char *bs = hlse_blindspot_for("network");
                if (bs) {
                    char esc_bs[512];
                    hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                    printf(",\"blind_spot\":\"%s\"", esc_bs);
                }
            }
            if (nv.score > 0) {
                int ns = nv.n_reasons;
                const char *conf = ns >= 3 ? "high confidence" :
                                   ns >= 2 ? "corroborated" : "single signal";
                printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
            }
            if (nv.score >= 40) {
                /* Perspective 96: a single N2 (routing injection, +55) or N4
                 * (hosts-file pharming, +50) finding lands in ALERT (40-59)
                 * alone, but used to get no pattern/objective/verify — only
                 * BLOCK+ (60) did, the same gap P95 closed for URL/text/
                 * paste/scan. verify now fires from the ALERT floor;
                 * triage/cascade_risk (post-incident, presumes the user
                 * already acted) stay BLOCK+-only.
                 * Perspective 103: text now shared with the plaintext path
                 * below via network_*_text() accessors. */
                char e[512];
                hlse_json_escape(hlse_net_pattern_text(), e, sizeof(e)); printf(",\"pattern\":\"%s\"", e);
                printf(",\"pattern_id\":\"HLSE-NET-C2\"");
                hlse_json_escape(hlse_network_objective_text(), e, sizeof(e)); printf(",\"objective\":\"%s\"", e);
                hlse_json_escape(hlse_network_verify_text(),    e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
            }
            if (nv.score >= 60) {
                char e[512];
                hlse_json_escape(hlse_network_triage_text(),  e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                hlse_json_escape(hlse_network_cascade_text(), e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
            }
            if (nv.score > 0 && nv.score < 60) {
                const char *ex = hlse_exoneration_for("network", nv.score);
                if (ex) {
                    char e[512];
                    hlse_json_escape(ex, e, sizeof(e));
                    printf(",\"exoneration\":\"%s\"", e);
                }
            }
            printf("}\n");
        } else if (nv.score == 0) {
            const char *bs = hlse_blindspot_for("network");
            printf("OK    (network \xe2\x80\x94 no anomalies detected)\n");
            if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
        } else {
            int i;
            printf("%-7s [%d]  (network)\n",
                   hlse_action_for_score(nv.score), nv.score);
            for (i = 0; i < nv.n_reasons; i++)
                printf("  \xc2\xb7 %s\n", nv.reasons[i]);
            if (nv.score >= 40) {
                printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_net_pattern_text());
                printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_network_objective_text());
                printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_network_verify_text());
            }
            if (nv.score >= 60) {
                printf("  \xe2\x9a\x91 Immediate action: %s\n", hlse_network_triage_text());
                printf("  \xe2\x8a\x95 Also change: %s\n", hlse_network_cascade_text());
            }
            if (nv.score < 60) {
                const char *ex = hlse_exoneration_for("network", nv.score);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
        }
        return nv.score >= o->fail_threshold ? 1 : 0;
}

int
hlse_cmd_paste(const HlseCli *o, int argc, char **argv, int idx) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s paste \"<command text>\"\n", argv[0]);
            return 2;
        }
        {
            PasteVerdict pv = hlse_check_paste(argv[idx + 1]);
            {
                const char *aar[16]; int aq, aqn = pv.n_reasons;
                if (aqn > 16) aqn = 16;
                for (aq = 0; aq < aqn; aq++) aar[aq] = pv.reasons[aq];
                hlse_alert_emit("paste", pv.score,
                    hlse_severity_for_score(pv.score), argv[idx + 1], aar, aqn);
            }
            if (o->json_out) {
                int i;
                printf("{\"kind\":\"paste\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,\"signals\":%d",
                       pv.score, hlse_action_for_score(pv.score),
                       hlse_severity_for_score(pv.score), pv.signals);
                if (pv.score == 0) {
                    const char *bs = hlse_blindspot_for("paste");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (pv.score > 0) {
                    /* Count distinct PASTE_* signal families from the bitmask —
                     * the epistemic complement to the score: how many independent
                     * detectors corroborate this paste threat. */
                    int ns = 0, bits = pv.signals;
                    while (bits) { ns += bits & 1; bits >>= 1; }
                    if (ns == 0) ns = pv.n_reasons;  /* fallback if bitmask empty */
                    {
                        const char *conf = ns >= 3 ? "high confidence" :
                                           ns >= 2 ? "corroborated" : "single signal";
                        printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
                    }
                }
                if (pv.score >= 40) {
                    /* Build a minimal TextVerdict so the existing advisory
                     * machinery fires: "Shell-pipe" triggers ClickFix
                     * classification in hlse_classify_text_attack().
                     * Perspective 95: pattern/objective/verify now fire from
                     * the ALERT floor (40); triage/cascade_risk stay
                     * BLOCK+-only (60) since post-incident guidance presumes
                     * the user already acted. */
                    TextVerdict ptv;
                    const char *ppat, *pobj, *pvrf;
                    memset(&ptv, 0, sizeof(ptv));
                    ptv.score = pv.score;
                    ptv.n_reasons = 1;
                    snprintf(ptv.reasons[0], sizeof(ptv.reasons[0]),
                             "Shell-pipe: paste-and-run pastejacking");
                    ppat = hlse_classify_text_attack(&ptv);
                    pobj = hlse_text_objective(&ptv);
                    pvrf = hlse_text_verify(&ptv);
                    if (ppat) { char e[512]; hlse_json_escape(ppat,e,sizeof(e)); printf(",\"pattern\":\"%s\"",e); }
                    if (ppat) { const char *pid = hlse_text_pattern_id(&ptv); if (pid) printf(",\"pattern_id\":\"%s\"",pid); }
                    if (pobj) { char e[512]; hlse_json_escape(pobj,e,sizeof(e)); printf(",\"objective\":\"%s\"",e); }
                    if (pvrf) { char e[512]; hlse_json_escape(pvrf,e,sizeof(e)); printf(",\"verify\":\"%s\"",e); }
                    if (pv.score >= 60) {
                        const char *ptri, *pcas;
                        ptri = hlse_text_triage(&ptv);
                        pcas = hlse_text_cascade(&ptv);
                        if (ptri) { char e[512]; hlse_json_escape(ptri,e,sizeof(e)); printf(",\"triage\":\"%s\"",e); }
                        if (pcas) { char e[512]; hlse_json_escape(pcas,e,sizeof(e)); printf(",\"cascade_risk\":\"%s\"",e); }
                    }
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("paste", pv.score);
                    if (ex) {
                        char e[512];
                        hlse_json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf(",\"reasons\":[");
                for (i = 0; i < pv.n_reasons; i++) {
                    char esc[512];
                    hlse_json_escape(pv.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]}\n");
            } else if (pv.score == 0) {
                const char *bs = hlse_blindspot_for("paste");
                printf("OK    (paste)\n");
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                printf("%-7s [%d]  (paste)\n",
                       hlse_action_for_score(pv.score), pv.score);
                for (i = 0; i < pv.n_reasons; i++)
                    printf("  \xc2\xb7 %s\n", pv.reasons[i]);
                if (pv.score >= 40) {
                    /* Advisory lenses: every paste ALERT+ is ClickFix/pastejacking.
                     * hlse_print_text_advisories internally gates verify at >=40 and
                     * triage/cascade_risk at >=60 (Perspective 95). */
                    TextVerdict ptv;
                    memset(&ptv, 0, sizeof(ptv));
                    ptv.score = pv.score;
                    ptv.n_reasons = 1;
                    snprintf(ptv.reasons[0], sizeof(ptv.reasons[0]),
                             "Shell-pipe: paste-and-run pastejacking");
                    hlse_print_text_advisories(&ptv);
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("paste", pv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return pv.score >= o->fail_threshold ? 1 : 0;
        }
}
