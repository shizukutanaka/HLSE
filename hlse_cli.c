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
#include "hlse_manifest.h"
#include "hlse_sarif.h"
#include "hlse_baseline.h"
#include "hlse_channel.h"
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

int
hlse_cmd_email(const HlseCli *o, int argc, char **argv, int idx) {
        static char stdin_buf[1u << 20];  /* 1 MiB, BSS (P1-2) */
        const char *headers;
        /* Perspective 106 (P2-3): --from sets a delivery-channel prior that
         * boosts URL/text scores, but email headers are BY DEFINITION
         * received over email — the channel is intrinsic and fixed, so a
         * --from override (especially a non-email one like sms) is
         * meaningless here. The flag was silently ignored, which reads like a
         * bug; make it explicit with a one-line stderr note instead. */
        if (hlse_from_channel()) {
            fprintf(stderr,
                    "hlse: note: --from is ignored for the email subcommand "
                    "\xe2\x80\x94 email headers are intrinsically the email "
                    "channel; the channel prior is not applied\n");
        }
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s email \"<headers>\" | %s email --stdin\n",
                    argv[0], argv[0]);
            return 2;
        } else if (strcmp(argv[idx + 1], "--stdin") == 0) {
            hlse_read_stdin_all(stdin_buf, sizeof(stdin_buf));
            headers = stdin_buf;
        } else {
            headers = argv[idx + 1];
        }
        {
            EmailVerdict ev = hlse_check_email_headers(headers);
            {
                const char *aar[16]; int aq, aqn = ev.n_reasons;
                if (aqn > 16) aqn = 16;
                for (aq = 0; aq < aqn; aq++) aar[aq] = ev.reasons[aq];
                hlse_alert_emit("email", ev.score,
                    hlse_severity_for_score(ev.score), "(email headers)", aar, aqn);
            }
            const char *rem = hlse_remediation_for("email", ev.score);
            /* Header forensics (SPF/DKIM/Reply-To/Received) is blind to the
             * message BODY's social engineering. Run text analysis on the same
             * input and surface the attack-pattern lens as ADVISORY only — the
             * email score is unchanged (preserves F1), but a BEC/urgency body
             * that header checks alone would miss is now named. */
            TextVerdict bodytv = hlse_check_text(headers);
            const char *body_pat = hlse_classify_text_attack(&bodytv);
            if (o->json_out) {
                int i;
                printf("{\"kind\":\"email\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,\"reasons\":[",
                       ev.score, hlse_action_for_score(ev.score),
                       hlse_severity_for_score(ev.score));
                for (i = 0; i < ev.n_reasons; i++) {
                    char esc[512];
                    hlse_json_escape(ev.reasons[i], esc, sizeof(esc));
                    printf("%s\"%s\"", i > 0 ? "," : "", esc);
                }
                printf("]");
                if (ev.score == 0 && !body_pat) {
                    const char *bs = hlse_blindspot_for("email");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (body_pat) {
                    char epat[256];
                    hlse_json_escape(body_pat, epat, sizeof(epat));
                    printf(",\"body_pattern\":\"%s\",\"body_score\":%d",
                           epat, bodytv.score);
                    /* Emit pattern and pattern_id from body analysis, plus signal count/confidence */
                    printf(",\"signal_count\":2,\"confidence\":\"two independent signals — header authentication + body text both analyzed\"");
                    TextVerdict btv_hi = bodytv;
                    char e[512];
                    const char *bpat, *bobj, *bvrf, *btri, *bcas, *bex;
                    btv_hi.score = ev.score > bodytv.score ? ev.score : bodytv.score;
                    bpat = hlse_classify_text_attack(&btv_hi);
                    bobj = hlse_text_objective(&btv_hi);
                    bex  = hlse_text_exoneration(&btv_hi);
                    bvrf = hlse_text_verify(&btv_hi);
                    btri = hlse_text_triage(&btv_hi);
                    bcas = hlse_text_cascade(&btv_hi);
                    if (bpat) { hlse_json_escape(bpat,e,sizeof(e)); printf(",\"pattern\":\"%s\"",e); }
                    if (bpat) {
                        const char *bid = hlse_text_pattern_id(&btv_hi);
                        if (bid) printf(",\"pattern_id\":\"%s\"", bid);
                    }
                    if (bex && btv_hi.score >= 15 && btv_hi.score < 60) {
                        hlse_json_escape(bex,e,sizeof(e)); printf(",\"exoneration\":\"%s\"",e);
                    }
                    /* Perspective 95: verify now fires from the ALERT floor
                     * (btv_hi.score >= 40, the combined header/body score) —
                     * objective/triage/cascade_risk stay gated on ev.score
                     * >= 60 (header-confidence threshold, unchanged). */
                    if (bvrf && btv_hi.score >= 40) {
                        hlse_json_escape(bvrf,e,sizeof(e)); printf(",\"verify\":\"%s\"",e);
                    }
                    if (ev.score >= 60) {
                        if (bobj) { hlse_json_escape(bobj,e,sizeof(e)); printf(",\"objective\":\"%s\"",e); }
                        if (btri) { hlse_json_escape(btri,e,sizeof(e)); printf(",\"triage\":\"%s\"",e); }
                        if (bcas) { hlse_json_escape(bcas,e,sizeof(e)); printf(",\"cascade_risk\":\"%s\"",e); }
                    }
                } else if (ev.score >= 60) {
                    /* Header-only BLOCK: synthesise BEC advisory lenses */
                    TextVerdict etv;
                    char e[512];
                    const char *epat2, *eobj, *evrf, *etri, *ecas;
                    memset(&etv, 0, sizeof(etv));
                    etv.score = ev.score;
                    etv.n_reasons = 1;
                    snprintf(etv.reasons[0], sizeof(etv.reasons[0]),
                             "BEC: email header authentication failure "
                             "(SPF/DKIM/Reply-To spoofing)");
                    epat2 = hlse_classify_text_attack(&etv);
                    eobj  = hlse_text_objective(&etv);
                    evrf  = hlse_text_verify(&etv);
                    etri  = hlse_text_triage(&etv);
                    ecas  = hlse_text_cascade(&etv);
                    printf(",\"signal_count\":1,\"confidence\":\"single signal — email header authentication anomalies detected\"");
                    if (epat2) { hlse_json_escape(epat2,e,sizeof(e)); printf(",\"pattern\":\"%s\"",e); }
                    if (epat2) { const char *pid = hlse_text_pattern_id(&etv); if (pid) printf(",\"pattern_id\":\"%s\"",pid); }
                    if (eobj)  { hlse_json_escape(eobj,e,sizeof(e));  printf(",\"objective\":\"%s\"",e); }
                    if (evrf)  { hlse_json_escape(evrf,e,sizeof(e));  printf(",\"verify\":\"%s\"",e); }
                    if (etri)  { hlse_json_escape(etri,e,sizeof(e));  printf(",\"triage\":\"%s\"",e); }
                    if (ecas)  { hlse_json_escape(ecas,e,sizeof(e));  printf(",\"cascade_risk\":\"%s\"",e); }
                } else if (ev.score > 0) {
                    /* Borderline header score (1-59): emit signal_count, confidence, and exoneration */
                    printf(",\"signal_count\":1");
                    TextVerdict etv;
                    const char *econn = hlse_exoneration_for("email", ev.score);
                    if (econn) {
                        char e[512];
                        hlse_json_escape(econn, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                    memset(&etv, 0, sizeof(etv));
                    etv.score = ev.score;
                    printf(",\"confidence\":\"partial signal — some email header concerns but not conclusive spoofing\"");
                }
                if (rem) {
                    char erm[512];
                    hlse_json_escape(rem, erm, sizeof(erm));
                    printf(",\"remediation\":\"%s\"", erm);
                }
                printf("}\n");
            } else if (ev.score == 0 && !body_pat) {
                const char *bs = hlse_blindspot_for("email");
                printf("OK    (email \xe2\x80\x94 no spoofing signals)\n");
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                const char *ex = hlse_exoneration_for("email", ev.score);
                if (ev.score == 0)
                    printf("OK    [0]  (email forensics) "
                           "\xe2\x80\x94 headers clean, but body flagged below\n");
                else
                    printf("%-7s [%d]  (email forensics)\n",
                           hlse_action_for_score(ev.score), ev.score);
                for (i = 0; i < ev.n_reasons; i++)
                    printf("  \xc2\xb7 %s\n", ev.reasons[i]);
                if (body_pat) {
                    /* Use email header score for advisory threshold */
                    TextVerdict btv_hi = bodytv;
                    const char *bobj, *bvrf, *btri, *bcas;
                    if (ev.score >= 60) btv_hi.score = ev.score;
                    bobj = hlse_text_objective(&btv_hi);
                    bvrf = hlse_text_verify(&btv_hi);
                    btri = hlse_text_triage(&btv_hi);
                    bcas = hlse_text_cascade(&btv_hi);
                    printf("  \xe2\x96\xb8 Body pattern: %s (body score %d)\n",
                           body_pat, bodytv.score);
                    if (bobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", bobj);
                    /* Perspective 95: verify fires from the ALERT floor
                     * (btv_hi.score >= 40); triage/cascade stay BLOCK+-only. */
                    if (bvrf && btv_hi.score >= 40)
                        printf("  \xe2\x9c\x93 Verify first: %s\n", bvrf);
                    if (ev.score >= 60) {
                        if (btri) printf("  \xe2\x9a\x91 If you acted: %s\n", btri);
                        if (bcas) printf("  \xe2\x8a\x95 Also change: %s\n", bcas);
                    }
                } else if (ev.score >= 60) {
                    /* Header-only BLOCK: synthesise BEC advisory lenses */
                    TextVerdict etv;
                    const char *epat2, *eobj, *evrf, *etri, *ecas;
                    memset(&etv, 0, sizeof(etv));
                    etv.score = ev.score;
                    etv.n_reasons = 1;
                    snprintf(etv.reasons[0], sizeof(etv.reasons[0]),
                             "BEC: email header authentication failure "
                             "(SPF/DKIM/Reply-To spoofing)");
                    epat2 = hlse_classify_text_attack(&etv);
                    eobj  = hlse_text_objective(&etv);
                    evrf  = hlse_text_verify(&etv);
                    etri  = hlse_text_triage(&etv);
                    ecas  = hlse_text_cascade(&etv);
                    if (epat2) printf("  \xe2\x96\xb8 Pattern: %s\n", epat2);
                    if (eobj)  printf("  \xe2\x97\x89 Attacker's goal: %s\n", eobj);
                    if (evrf)  printf("  \xe2\x9c\x93 Verify first: %s\n", evrf);
                    if (etri)  printf("  \xe2\x9a\x91 If you acted: %s\n", etri);
                    if (ecas)  printf("  \xe2\x8a\x95 Also change: %s\n", ecas);
                }
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                if (rem) printf("  \xe2\x86\x92 Action: %s\n", rem);
            }
            return ev.score >= o->fail_threshold ? 1 : 0;
        }
}

int
hlse_cmd_secret(const HlseCli *o, int argc, char **argv, int idx) {
        /* 1 MiB, BSS-allocated (static) not stack — matches the shipped
         * pre-commit hook's 1 MB file-size guard so no in-scope file is
         * silently truncated (Perspective 105 / P1-2). */
        static char stdin_buf[1u << 20];
        const char *text;
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s secret \"<text>\" | %s secret --stdin\n",
                    argv[0], argv[0]);
            return 2;
        } else if (strcmp(argv[idx + 1], "--stdin") == 0) {
            hlse_read_stdin_all(stdin_buf, sizeof(stdin_buf));
            text = stdin_buf;
        } else {
            text = argv[idx + 1];
        }
        {
            SecretVerdict sv = hlse_scan_secrets(text);
            {
                const char *aar[16]; char rb[16][300];
                int aq, aqn = sv.n_findings;
                if (aqn > 16) aqn = 16;
                for (aq = 0; aq < aqn; aq++) {
                    snprintf(rb[aq], sizeof(rb[aq]), "%s: %s",
                             sv.findings[aq].type, sv.findings[aq].description);
                    aar[aq] = rb[aq];
                }
                hlse_alert_emit("secret", sv.score,
                    hlse_severity_for_score(sv.score), "(secret scan)", aar, aqn);
            }
            if (o->json_out) {
                int i;
                printf("{\"kind\":\"secret\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,\"findings\":[",
                       sv.score, hlse_action_for_score(sv.score),
                       hlse_severity_for_score(sv.score));
                for (i = 0; i < sv.n_findings; i++) {
                    char et[64], ed[512];
                    hlse_json_escape(sv.findings[i].type, et, sizeof(et));
                    hlse_json_escape(sv.findings[i].description, ed, sizeof(ed));
                    printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                           i > 0 ? "," : "", et, ed);
                }
                printf("]");
                printf(",\"confidence\":\"%s\"", hlse_secret_confidence(&sv));
                {
                    const char *rem = hlse_remediation_for("secret", sv.score);
                    if (rem) {
                        char erm[512];
                        hlse_json_escape(rem, erm, sizeof(erm));
                        printf(",\"remediation\":\"%s\"", erm);
                    }
                }
                if (sv.score == 0) {
                    const char *bs = hlse_blindspot_for("secret");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (sv.n_findings > 0) {
                    /* Perspective 99: unconditional on score — a Stripe
                     * publishable key is public-by-design at any score,
                     * not just a probabilistic false-positive hedge. */
                    const char *cav = hlse_secret_finding_caveat(sv.findings[0].type);
                    if (cav) {
                        char e[768];
                        hlse_json_escape(cav, e, sizeof(e));
                        printf(",\"caveat\":\"%s\"", e);
                    }
                }
                if (sv.score >= 60 && sv.n_findings > 0) {
                    const char *ftype = sv.findings[0].type;
                    const char *sobj  = hlse_secret_objective_for(ftype);
                    char e[512], epat[128];
                    hlse_secret_pattern_label(ftype, epat, sizeof(epat));
                    hlse_json_escape(epat, e, sizeof(e));
                    printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"%s\"", hlse_secret_pattern_id(ftype));
                    if (sobj) { hlse_json_escape(sobj, e, sizeof(e)); printf(",\"objective\":\"%s\"", e); }
                    hlse_json_escape(hlse_secret_verify_text(),  e, sizeof(e)); printf(",\"verify\":\"%s\"", e);
                    hlse_json_escape(hlse_secret_triage_text(),  e, sizeof(e)); printf(",\"triage\":\"%s\"", e);
                    hlse_json_escape(hlse_secret_cascade_text(), e, sizeof(e)); printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (sv.score > 0 && sv.score < 60) {
                    const char *ex = hlse_exoneration_for("secret", sv.score);
                    if (ex) {
                        char e[512];
                        hlse_json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (sv.score == 0) {
                const char *bs = hlse_blindspot_for("secret");
                printf("OK    (secret \xe2\x80\x94 no credentials found)\n");
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                int i;
                const char *rem = hlse_remediation_for("secret", sv.score);
                const char *conf = hlse_secret_confidence(&sv);
                printf("%-7s [%d]  (secret scan — confidence: %s)\n",
                       hlse_action_for_score(sv.score), sv.score, conf);
                for (i = 0; i < sv.n_findings; i++)
                    printf("  \xc2\xb7 [%s] %s\n",
                           sv.findings[i].type, sv.findings[i].description);
                if (strcmp(conf, "heuristic") == 0)
                    printf("  \xe2\x86\x92 Confidence: heuristic — this is a "
                           "pattern guess (generic VAR=value / high-entropy "
                           "string); confirm it is a live credential.\n");
                if (sv.n_findings > 0) {
                    const char *cav = hlse_secret_finding_caveat(sv.findings[0].type);
                    if (cav) printf("  \xe2\x9a\xa0 Caveat: %s\n", cav);
                }
                if (sv.score >= 60 && sv.n_findings > 0) {
                    const char *ftype = sv.findings[0].type;
                    const char *sobj  = hlse_secret_objective_for(ftype);
                    char epat[128];
                    hlse_secret_pattern_label(ftype, epat, sizeof(epat));
                    printf("  \xe2\x96\xb8 Pattern: %s\n", epat);
                    if (sobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", sobj);
                    printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_secret_verify_text());
                    printf("  \xe2\x9a\x91 Immediate action: %s\n", hlse_secret_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", hlse_secret_cascade_text());
                }
                if (sv.score > 0 && sv.score < 60) {
                    const char *ex = hlse_exoneration_for("secret", sv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
                if (rem) printf("  \xe2\x86\x92 Action: %s\n", rem);
            }
            return sv.score >= o->fail_threshold ? 1 : 0;
        }
}

int
hlse_cmd_package(const HlseCli *o, int argc, char **argv, int idx) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s package <name> [pip|npm|cargo|go]\n"
                    "       %s package --manifest <file> [pip|npm|cargo|go|gem]\n",
                    argv[0], argv[0]);
            return 2;
        }
        /* --manifest <file>: scan every dependency in a manifest (P1-8). */
        if (strcmp(argv[idx + 1], "--manifest") == 0) {
            const char *mpath, *eco;
            FILE *mf;
            char line[4096];
            int in_deps = 0, checked = 0, threats = 0, gate_hits = 0;
            int max_score = 0, lineno = 0;
            if (argc < idx + 3) {
                fprintf(stderr, "Usage: %s package --manifest <file> [eco]\n",
                        argv[0]);
                return 2;
            }
            mpath = argv[idx + 2];
            eco = (argc > idx + 3) ? argv[idx + 3] : hlse_manifest_ecosystem(mpath);
            if (!eco) {
                fprintf(stderr, "Error: cannot infer ecosystem from '%s' \xe2\x80\x94 "
                        "pass one explicitly (pip|npm|cargo|go|gem)\n", mpath);
                return 2;
            }
            mf = fopen(mpath, "r");
            if (!mf) {
                fprintf(stderr, "Error: cannot read manifest '%s': %s\n",
                        mpath, strerror(errno));
                return 2;
            }
            while (fgets(line, sizeof(line), mf)) {
                char name[128];
                const char *cursor = line;
                int is_npm = (strcmp(eco, "npm") == 0);
                lineno++;
                /* npm: a line may hold several "name":"ver" pairs (compact
                 * object form), so drain the cursor. pip: one name per line. */
                for (;;) {
                    int got;
                    if (is_npm)
                        got = hlse_manifest_name_npm(&cursor, &in_deps, name, sizeof(name));
                    else
                        got = hlse_manifest_name_pip(line, name, sizeof(name));
                    if (!got || name[0] == '\0') break;
                {
                    PackageVerdict pv = hlse_check_package(name, eco);
                    checked++;
                    if (pv.score >= 40) {
                        threats++;
                        if (pv.score > max_score) max_score = pv.score;
                        if (pv.score >= o->fail_threshold) gate_hits++;
                        if (o->sarif_out) {
                            char msg[512];
                            snprintf(msg, sizeof(msg), "%s",
                                     pv.reason[0] ? pv.reason
                                     : "dependency typosquat");
                            hlse_sarif_add(mpath, lineno, "package-typosquat",
                                      "HLSE-PKG-TYPOSQUAT", msg, pv.score);
                        } else if (o->json_out) {
                            char en[128];
                            int i;
                            hlse_json_escape(name, en, sizeof(en));
                            printf("{\"kind\":\"package\",\"hlse_version\":\""
                                   HLSE_VERSION "\",\"name\":\"%s\","
                                   "\"ecosystem\":\"%s\",\"score\":%d,"
                                   "\"action\":\"%s\",\"severity\":%d,"
                                   "\"pattern_id\":\"HLSE-PKG-TYPOSQUAT\","
                                   "\"matches\":[",
                                   en, eco, pv.score,
                                   hlse_action_for_score(pv.score),
                                   hlse_severity_for_score(pv.score));
                            for (i = 0; i < pv.n_matches; i++)
                                printf("%s{\"name\":\"%s\",\"registry\":\"%s\","
                                       "\"distance\":%d}", i ? "," : "",
                                       pv.matches[i].legit_name,
                                       pv.matches[i].registry,
                                       pv.matches[i].distance);
                            printf("]}\n");
                        } else {
                            {
                                char db[8192];
                                printf("%-7s [%d]  %s (%s)\n",
                                       hlse_action_for_score(pv.score), pv.score,
                                       hlse_display_copy(db, sizeof(db), name),
                                       eco);
                            }
                            if (pv.reason[0])
                                printf("  \xc2\xb7 %s\n", pv.reason);
                        }
                    }
                }
                    if (!is_npm) break;   /* pip: one name per line */
                }  /* for(;;) drain-line */
            }
            fclose(mf);
            if (o->sarif_out) {
                hlse_sarif_emit(HLSE_VERSION);
            } else if (o->json_out) {
                char ep[4096];
                hlse_json_escape(mpath, ep, sizeof(ep));
                printf("{\"kind\":\"manifest_summary\",\"hlse_version\":\""
                       HLSE_VERSION "\",\"manifest\":\"%s\",\"ecosystem\":\"%s\","
                       "\"packages_checked\":%d,\"threats\":%d,"
                       "\"max_severity\":%d,\"gate_hits\":%d}\n",
                       ep, eco, checked, threats,
                       hlse_severity_for_score(max_score), gate_hits);
            } else if (threats == 0) {
                char db[8192];
                printf("OK    %s (%d packages checked, 0 typosquat risks)\n",
                       hlse_display_copy(db, sizeof(db), mpath), checked);
            } else {
                char db[8192];
                printf("\n%d suspicious package(s) of %d checked in %s\n",
                       threats, checked,
                       hlse_display_copy(db, sizeof(db), mpath));
            }
            return gate_hits > 0 ? 1 : 0;
        }
        {
            const char *eco = (argc > idx + 2) ? argv[idx + 2] : NULL;
            PackageVerdict pv = hlse_check_package(argv[idx + 1], eco);
            {
                const char *aar[1]; int aqn = 0;
                if (pv.reason[0]) { aar[0] = pv.reason; aqn = 1; }
                hlse_alert_emit("package", pv.score,
                    hlse_severity_for_score(pv.score), argv[idx + 1], aar, aqn);
            }
            if (o->json_out) {
                printf("{\"kind\":\"package\",\"hlse_version\":\"" HLSE_VERSION "\","
                       "\"name\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"severity\":%d",
                       argv[idx + 1], pv.score, hlse_action_for_score(pv.score),
                       hlse_severity_for_score(pv.score));
                if (pv.n_matches > 0) {
                    int i;
                    printf(",\"matches\":[");
                    for (i = 0; i < pv.n_matches; i++) {
                        printf("%s{\"name\":\"%s\",\"registry\":\"%s\","
                               "\"distance\":%d}",
                               i > 0 ? "," : "",
                               pv.matches[i].legit_name,
                               pv.matches[i].registry,
                               pv.matches[i].distance);
                    }
                    printf("]");
                }
                if (pv.score == 0) {
                    /* reason non-empty => exact match to a known package;
                     * empty => unknown name, which we cannot verify offline. */
                    const char *bs = hlse_blindspot_for(
                        pv.reason[0] ? "package" : "package_unverified");
                    if (bs) {
                        char esc_bs[512];
                        hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
                        printf(",\"blind_spot\":\"%s\"", esc_bs);
                    }
                }
                if (pv.score > 0) {
                    int ns = pv.n_matches > 0 ? pv.n_matches : 1;
                    const char *conf = ns >= 3 ? "high confidence" :
                                       ns >= 2 ? "corroborated" : "single signal";
                    printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
                }
                if (pv.score >= 40) {
                    /* Perspective 97: a name matching 2+ registries at once
                     * (e.g. "reqests" ~ pip "requests" dist-1 AND cargo
                     * "reqwest" dist-2, when no ecosystem is given) lands at
                     * score 50 alone — the n_matches==1 amplifier to 70 never
                     * fires — but pattern/objective/verify used to require
                     * >= 60, the same gap P95/P96 closed elsewhere.
                     * Perspective 103: text now shared with the plaintext
                     * path below via package_*_text() accessors. */
                    char e[512];
                    hlse_json_escape(hlse_package_pattern_text(), e, sizeof(e));
                    printf(",\"pattern\":\"%s\"", e);
                    printf(",\"pattern_id\":\"HLSE-PKG-TYPOSQUAT\"");
                    hlse_json_escape(hlse_package_objective_text(), e, sizeof(e));
                    printf(",\"objective\":\"%s\"", e);
                    hlse_json_escape(hlse_package_verify_text(), e, sizeof(e));
                    printf(",\"verify\":\"%s\"", e);
                }
                if (pv.score >= 60) {
                    char e[512];
                    hlse_json_escape(hlse_package_triage_text(), e, sizeof(e));
                    printf(",\"triage\":\"%s\"", e);
                    hlse_json_escape(hlse_package_cascade_text(), e, sizeof(e));
                    printf(",\"cascade_risk\":\"%s\"", e);
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("package", pv.score);
                    if (ex) {
                        char e[512];
                        hlse_json_escape(ex, e, sizeof(e));
                        printf(",\"exoneration\":\"%s\"", e);
                    }
                }
                printf("}\n");
            } else if (pv.score == 0) {
                const char *bs = hlse_blindspot_for(
                    pv.reason[0] ? "package" : "package_unverified");
                char db[8192];
                printf("OK    %s\n",
                       hlse_display_copy(db, sizeof(db), argv[idx + 1]));
                /* Mirror the URL canonical-confirmation line: say explicitly
                 * when the name IS recognised, so "OK" is not ambiguous
                 * between "known good" and "never heard of it". */
                if (pv.reason[0]) printf("  \xe2\x9c\x94 %s\n", pv.reason);
                if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
            } else {
                char db[8192];
                printf("%-7s [%d]  %s\n",
                       hlse_action_for_score(pv.score), pv.score,
                       hlse_display_copy(db, sizeof(db), argv[idx + 1]));
                if (pv.reason[0])
                    printf("  \xc2\xb7 %s\n", pv.reason);
                if (pv.score >= 40) {
                    printf("  \xe2\x96\xb8 Pattern: %s\n", hlse_package_pattern_text());
                    printf("  \xe2\x97\x89 Attacker's goal: %s\n", hlse_package_objective_text());
                    printf("  \xe2\x9c\x93 Verify first: %s\n", hlse_package_verify_text());
                }
                if (pv.score >= 60) {
                    printf("  \xe2\x9a\x91 If you acted: %s\n", hlse_package_triage_text());
                    printf("  \xe2\x8a\x95 Also change: %s\n", hlse_package_cascade_text());
                }
                if (pv.score < 60) {
                    const char *ex = hlse_exoneration_for("package", pv.score);
                    if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                }
            }
            return pv.score >= o->fail_threshold ? 1 : 0;
        }
}
