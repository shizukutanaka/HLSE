/* hlse_cli.c — per-subcommand handlers for the hlse_core CLI driver.
 * Each takes the parsed options plus argv (idx points at the subcommand
 * name) and returns the process exit status. Extracted verbatim from
 * main() (split increments 10+); flag state arrives via HlseCli. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
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
#include "hlse_githistory.h"
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
            hlse_alert_emit_rows("protect", pv.score,
                hlse_severity_for_score(pv.score), path,
                pv.reasons, sizeof pv.reasons[0], pv.n_reasons);

            if (o->json_out) {
                /* JSON output for protect.
                 * Perspective 100: this was the only verdict kind still
                 * missing hlse_version and severity — every other kind
                 * (url/text/file/secret/email/network/esp/package/paste/
                 * clipboard) has carried both since P84/P85; protect was
                 * never brought in line. */
                char esc_path[4096];
                hlse_json_escape(path, esc_path, sizeof(esc_path));
                hlse_json_open("protect");
                       printf(",\"target\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"severity\":%d,\"reasons\":[",
                       esc_path, pv.score,
                       hlse_action_for_score(pv.score),
                       hlse_severity_for_score(pv.score));
                {
                    int i;
                    for (i = 0; i < pv.n_reasons; i++)
                        hlse_json_str_elem(i, pv.reasons[i]);
                }
                printf("]");
                if (pv.score == 0) {
                    const char *bs = hlse_blindspot_for("protect");
                    if (bs) {
                        hlse_json_str_field("blind_spot", bs);
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
                    
                    hlse_json_str_field("pattern", hlse_protect_pattern_text());
                    printf(",\"pattern_id\":\"HLSE-PROTECT-RANSOM\"");
                    hlse_json_str_field("objective", hlse_protect_objective_text());
                    hlse_json_str_field("verify", hlse_protect_verify_text());
                }
                if (pv.score >= 60) {
                    
                    hlse_json_str_field("triage", hlse_protect_triage_text());
                    hlse_json_str_field("cascade_risk", hlse_protect_cascade_text());
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("protect", pv.score);
                    if (ex) {
                        
                        hlse_json_str_field("exoneration", ex);
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
        hlse_alert_emit_rows("esp", pv.score,
            hlse_severity_for_score(pv.score), path ? path : "(esp)",
            pv.reasons, sizeof pv.reasons[0], pv.n_reasons);
        if (o->json_out) {
            int i;
            hlse_json_open("esp");
                   printf(",\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"reasons\":[",
                   pv.score, hlse_action_for_score(pv.score),
                   hlse_severity_for_score(pv.score));
            for (i = 0; i < pv.n_reasons; i++)
                        hlse_json_str_elem(i, pv.reasons[i]);
            printf("]");
            {
                const char *bs = hlse_blindspot_for("esp");
                if (pv.score == 0 && bs) {
                    
                    hlse_json_str_field("blind_spot", bs);
                }
            }
            if (pv.score > 0) {
                int ns = pv.n_reasons;
                const char *conf = ns >= 3 ? "high confidence" :
                                   ns >= 2 ? "corroborated" : "single signal";
                printf(",\"signal_count\":%d,\"confidence\":\"%s\"", ns, conf);
            }
            if (pv.score >= 60) {
                
                hlse_json_str_field("pattern", hlse_esp_pattern_text());
                printf(",\"pattern_id\":\"HLSE-ESP-BOOTKIT\"");
                hlse_json_str_field("objective", hlse_esp_objective_text());
                hlse_json_str_field("verify", hlse_esp_verify_text());
                hlse_json_str_field("triage", hlse_esp_triage_text());
                hlse_json_str_field("cascade_risk", hlse_esp_cascade_text());
            }
            if (pv.score > 0 && pv.score < 60) {
                const char *ex = hlse_exoneration_for("esp", pv.score);
                if (ex) {
                    
                    hlse_json_str_field("exoneration", ex);
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
            hlse_alert_emit_rows("clipboard", cv.score,
                hlse_severity_for_score(cv.score),
                cv.swapped[0] ? cv.swapped : "(clipboard)",
                cv.reason, sizeof cv.reason, cv.reason[0] ? 1 : 0);
            const char *rem = hlse_remediation_for("clipboard", cv.score);
            if (o->json_out) {
                char eo[256], es[256], er[512], erm[512];
                hlse_json_escape(cv.original, eo, sizeof(eo));
                hlse_json_escape(cv.swapped, es, sizeof(es));
                hlse_json_escape(cv.reason, er, sizeof(er));
                hlse_json_escape(rem ? rem : "", erm, sizeof(erm));
                hlse_json_open("clipboard");
                       printf(",\"score\":%d,\"action\":\"%s\","
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
                        
                        hlse_json_str_field("blind_spot", bs);
                    }
                }
                if (cv.score >= 60) {
                    
                    hlse_json_str_field("pattern", hlse_clipboard_pattern_text());
                    printf(",\"pattern_id\":\"HLSE-CLIP-HIJACK\"");
                    hlse_json_str_field("objective", hlse_clipboard_objective_text());
                    hlse_json_str_field("verify", hlse_clipboard_verify_text());
                    hlse_json_str_field("triage", hlse_clipboard_triage_text());
                    hlse_json_str_field("cascade_risk", hlse_clipboard_cascade_text());
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
        hlse_alert_emit_rows("audit", av.score,
            hlse_severity_for_score(av.score), "(system audit)",
            &av.findings[0].description, sizeof av.findings[0],
            av.n_findings);
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
            hlse_json_open("audit");
                   printf(",\"score\":%d,\"action\":\"%s\","
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
                    
                    hlse_json_str_field("fix", fix);
                }
                printf("}");
            }
            printf("]");
            if (av.score == 0) {
                const char *bs = hlse_blindspot_for("audit");
                if (bs) {
                    
                    hlse_json_str_field("blind_spot", bs);
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
                { 
                  hlse_json_str_field("next_steps", ns);
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
            hlse_alert_emit_rows("file", fv.score,
                hlse_severity_for_score(fv.score), argv[idx + 1],
                fv.reasons, sizeof fv.reasons[0], fv.n_reasons);
            if (o->json_out) {
                int i;
                char esc[512];
                hlse_json_escape(argv[idx + 1], esc, sizeof(esc));
                hlse_json_open("file");
                       printf(",\"path\":\"%s\",\"score\":%d,"
                       "\"action\":\"%s\",\"severity\":%d,\"reasons\":[",
                       esc, fv.score, hlse_action_for_score(fv.score),
                       hlse_severity_for_score(fv.score));
                for (i = 0; i < fv.n_reasons; i++)
                    hlse_json_str_elem(i, fv.reasons[i]);
                printf("]");
                if (fv.score == 0) {
                    const char *bs = hlse_blindspot_for("file");
                    if (bs) {
                        
                        hlse_json_str_field("blind_spot", bs);
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
                    
                    hlse_json_str_field("pattern", fpat);
                    printf(",\"pattern_id\":\"%s\"", hlse_file_pattern_id(fpat));
                    hlse_json_str_field("objective", hlse_file_masquerade_objective());
                    hlse_json_str_field("verify", hlse_file_masquerade_verify());
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
                    
                    hlse_json_str_field("triage", file_tri);
                    hlse_json_str_field("cascade_risk", file_cas);
                }
                if (fv.score > 0 && fv.score < 60) {
                    const char *ex = hlse_exoneration_for("file", fv.score);
                    if (ex) {
                        
                        hlse_json_str_field("exoneration", ex);
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
        hlse_alert_emit_rows("network", nv.score,
            hlse_severity_for_score(nv.score), "(network)",
            nv.reasons, sizeof nv.reasons[0], nv.n_reasons);
        if (o->json_out) {
            int i;
            hlse_json_open("network");
                   printf(",\"score\":%d,\"action\":\"%s\","
                   "\"severity\":%d,\"reasons\":[",
                   nv.score, hlse_action_for_score(nv.score),
                   hlse_severity_for_score(nv.score));
            for (i = 0; i < nv.n_reasons; i++)
                        hlse_json_str_elem(i, nv.reasons[i]);
            printf("]");
            if (nv.score == 0) {
                const char *bs = hlse_blindspot_for("network");
                if (bs) {
                    
                    hlse_json_str_field("blind_spot", bs);
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
                
                hlse_json_str_field("pattern", hlse_net_pattern_text());
                printf(",\"pattern_id\":\"HLSE-NET-C2\"");
                hlse_json_str_field("objective", hlse_network_objective_text());
                hlse_json_str_field("verify", hlse_network_verify_text());
            }
            if (nv.score >= 60) {
                
                hlse_json_str_field("triage", hlse_network_triage_text());
                hlse_json_str_field("cascade_risk", hlse_network_cascade_text());
            }
            if (nv.score > 0 && nv.score < 60) {
                const char *ex = hlse_exoneration_for("network", nv.score);
                if (ex) {
                    
                    hlse_json_str_field("exoneration", ex);
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
            hlse_alert_emit_rows("paste", pv.score,
                hlse_severity_for_score(pv.score), argv[idx + 1],
                pv.reasons, sizeof pv.reasons[0], pv.n_reasons);
            if (o->json_out) {
                int i;
                hlse_json_open("paste");
                       printf(",\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,\"signals\":%d",
                       pv.score, hlse_action_for_score(pv.score),
                       hlse_severity_for_score(pv.score), pv.signals);
                if (pv.score == 0) {
                    const char *bs = hlse_blindspot_for("paste");
                    if (bs) {
                        
                        hlse_json_str_field("blind_spot", bs);
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
                    if (ppat) {  hlse_json_str_field("pattern", ppat); }
                    if (ppat) { const char *pid = hlse_text_pattern_id(&ptv); if (pid) printf(",\"pattern_id\":\"%s\"",pid); }
                    if (pobj) {  hlse_json_str_field("objective", pobj); }
                    if (pvrf) { hlse_json_str_field("verify", pvrf); }
                    if (pv.score >= 60) {
                        const char *ptri, *pcas;
                        ptri = hlse_text_triage(&ptv);
                        pcas = hlse_text_cascade(&ptv);
                        if (ptri) {  hlse_json_str_field("triage", ptri); }
                        if (pcas) { hlse_json_str_field("cascade_risk", pcas); }
                    }
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("paste", pv.score);
                    if (ex) {
                        
                        hlse_json_str_field("exoneration", ex);
                    }
                }
                printf(",\"reasons\":[");
                for (i = 0; i < pv.n_reasons; i++)
                        hlse_json_str_elem(i, pv.reasons[i]);
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
            hlse_alert_emit_rows("email", ev.score,
                hlse_severity_for_score(ev.score), "(email headers)",
                ev.reasons, sizeof ev.reasons[0], ev.n_reasons);
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
                hlse_json_open("email");
                       printf(",\"score\":%d,\"action\":\"%s\","
                       "\"severity\":%d,\"reasons\":[",
                       ev.score, hlse_action_for_score(ev.score),
                       hlse_severity_for_score(ev.score));
                for (i = 0; i < ev.n_reasons; i++)
                        hlse_json_str_elem(i, ev.reasons[i]);
                printf("]");
                if (ev.score == 0 && !body_pat) {
                    const char *bs = hlse_blindspot_for("email");
                    if (bs) {
                        
                        hlse_json_str_field("blind_spot", bs);
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
                    
                    const char *bpat, *bobj, *bvrf, *btri, *bcas, *bex;
                    btv_hi.score = ev.score > bodytv.score ? ev.score : bodytv.score;
                    bpat = hlse_classify_text_attack(&btv_hi);
                    bobj = hlse_text_objective(&btv_hi);
                    bex  = hlse_text_exoneration(&btv_hi);
                    bvrf = hlse_text_verify(&btv_hi);
                    btri = hlse_text_triage(&btv_hi);
                    bcas = hlse_text_cascade(&btv_hi);
                    if (bpat) { hlse_json_str_field("pattern", bpat); }
                    if (bpat) {
                        const char *bid = hlse_text_pattern_id(&btv_hi);
                        if (bid) printf(",\"pattern_id\":\"%s\"", bid);
                    }
                    if (bex && btv_hi.score >= 15 && btv_hi.score < 60) {
                        hlse_json_str_field("exoneration", bex);
                    }
                    /* Perspective 95: verify now fires from the ALERT floor
                     * (btv_hi.score >= 40, the combined header/body score) —
                     * objective/triage/cascade_risk stay gated on ev.score
                     * >= 60 (header-confidence threshold, unchanged). */
                    if (bvrf && btv_hi.score >= 40) {
                        hlse_json_str_field("verify", bvrf);
                    }
                    if (ev.score >= 60) {
                        if (bobj) { hlse_json_str_field("objective", bobj); }
                        if (btri) { hlse_json_str_field("triage", btri); }
                        if (bcas) { hlse_json_str_field("cascade_risk", bcas); }
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
                    printf(",\"signal_count\":1,\"confidence\":\"single signal — email header authentication anomalies detected\"");
                    if (epat2) { hlse_json_str_field("pattern", epat2); }
                    if (epat2) { const char *pid = hlse_text_pattern_id(&etv); if (pid) printf(",\"pattern_id\":\"%s\"",pid); }
                    if (eobj)  { hlse_json_str_field("objective", eobj); }
                    if (evrf)  { hlse_json_str_field("verify", evrf); }
                    if (etri)  { hlse_json_str_field("triage", etri); }
                    if (ecas)  { hlse_json_str_field("cascade_risk", ecas); }
                } else if (ev.score > 0) {
                    /* Borderline header score (1-59): emit signal_count, confidence, and exoneration */
                    printf(",\"signal_count\":1");
                    TextVerdict etv;
                    const char *econn = hlse_exoneration_for("email", ev.score);
                    if (econn) {
                        
                        hlse_json_str_field("exoneration", econn);
                    }
                    memset(&etv, 0, sizeof(etv));
                    etv.score = ev.score;
                    printf(",\"confidence\":\"partial signal — some email header concerns but not conclusive spoofing\"");
                }
                if (rem) {
                    
                    hlse_json_str_field("remediation", rem);
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
                hlse_json_open("secret");
                       printf(",\"score\":%d,\"action\":\"%s\","
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
                        
                        hlse_json_str_field("remediation", rem);
                    }
                }
                if (sv.score == 0) {
                    const char *bs = hlse_blindspot_for("secret");
                    if (bs) {
                        
                        hlse_json_str_field("blind_spot", bs);
                    }
                }
                if (sv.n_findings > 0) {
                    /* Perspective 99: unconditional on score — a Stripe
                     * publishable key is public-by-design at any score,
                     * not just a probabilistic false-positive hedge. */
                    const char *cav = hlse_secret_finding_caveat(sv.findings[0].type);
                    if (cav) {
                        
                        hlse_json_str_field("caveat", cav);
                    }
                }
                if (sv.score >= 60 && sv.n_findings > 0) {
                    const char *ftype = sv.findings[0].type;
                    const char *sobj  = hlse_secret_objective_for(ftype);
                    char epat[128];
                    hlse_secret_pattern_label(ftype, epat, sizeof(epat));
                    hlse_json_str_field("pattern", epat);
                    printf(",\"pattern_id\":\"%s\"", hlse_secret_pattern_id(ftype));
                    if (sobj) { hlse_json_str_field("objective", sobj); }
                    hlse_json_str_field("verify", hlse_secret_verify_text());
                    hlse_json_str_field("triage", hlse_secret_triage_text());
                    hlse_json_str_field("cascade_risk", hlse_secret_cascade_text());
                }
                if (sv.score > 0 && sv.score < 60) {
                    const char *ex = hlse_exoneration_for("secret", sv.score);
                    if (ex) {
                        
                        hlse_json_str_field("exoneration", ex);
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
                if (is_npm) {
                    /* Lifecycle-hook risk (Shai-Hulud-style install worms). */
                    char hout[4][HLSE_HOOK_REASON_LEN];
                    int  hsc[4];
                    size_t hn = hlse_manifest_hook_flags(line, hout, hsc, 4);
                    size_t hi;
                    for (hi = 0; hi < hn; hi++) {
                        threats++;
                        hlse_alert_emit_rows("package", hsc[hi],
                            hlse_severity_for_score(hsc[hi]), mpath,
                            hout[hi], sizeof hout[hi], 1);
                        if (hsc[hi] > max_score) max_score = hsc[hi];
                        if (hsc[hi] >= o->fail_threshold) gate_hits++;
                        if (o->sarif_out) {
                            hlse_sarif_add(mpath, lineno, "package-lifecycle-hook",
                                      "HLSE-PKG-HOOK", hout[hi], hsc[hi]);
                        } else if (o->json_out) {
                            char eh[192], hk[64], ehk[64];
                            const char *colon = strchr(hout[hi], ':');
                            if (colon) {
                                size_t kl = (size_t)(colon - hout[hi]);
                                if (kl >= sizeof(hk)) kl = sizeof(hk) - 1;
                                memcpy(hk, hout[hi], kl); hk[kl] = '\0';
                            } else {
                                snprintf(hk, sizeof(hk), "%s", hout[hi]);
                            }
                            hlse_json_escape(hk, ehk, sizeof(ehk));
                            hlse_json_escape(hout[hi], eh, sizeof(eh));
                            hlse_json_open("package");
                            printf(",\"name\":\"%s\",\"ecosystem\":\"npm\","
                                   "\"score\":%d,\"action\":\"%s\",\"severity\":%d,"
                                   "\"pattern_id\":\"HLSE-PKG-HOOK\",\"reason\":\"%s\"}\n",
                                   ehk, hsc[hi],
                                   hlse_action_for_score(hsc[hi]),
                                   hlse_severity_for_score(hsc[hi]), eh);
                        } else {
                            printf("%-7s [%d]  suspicious lifecycle hook: %s\n",
                                   hlse_action_for_score(hsc[hi]), hsc[hi],
                                   hout[hi]);
                        }
                    }
                }
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
                        hlse_alert_emit_rows("package", pv.score,
                            hlse_severity_for_score(pv.score), name,
                            pv.reason, sizeof pv.reason, pv.reason[0] ? 1 : 0);
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
                            hlse_json_open("package");
                            printf(",\"name\":\"%s\","
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
                hlse_json_open("manifest_summary");
                printf(",\"manifest\":\"%s\",\"ecosystem\":\"%s\","
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
            hlse_alert_emit_rows("package", pv.score,
                hlse_severity_for_score(pv.score), argv[idx + 1],
                pv.reason, sizeof pv.reason, pv.reason[0] ? 1 : 0);
            if (o->json_out) {
                hlse_json_open("package");
                printf(",\"name\":\"%s\",\"score\":%d,"
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
                        
                        hlse_json_str_field("blind_spot", bs);
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
                    
                    hlse_json_str_field("pattern", hlse_package_pattern_text());
                    printf(",\"pattern_id\":\"HLSE-PKG-TYPOSQUAT\"");
                    hlse_json_str_field("objective", hlse_package_objective_text());
                    hlse_json_str_field("verify", hlse_package_verify_text());
                }
                if (pv.score >= 60) {
                    
                    hlse_json_str_field("triage", hlse_package_triage_text());
                    hlse_json_str_field("cascade_risk", hlse_package_cascade_text());
                }
                if (pv.score > 0 && pv.score < 60) {
                    const char *ex = hlse_exoneration_for("package", pv.score);
                    if (ex) {
                        
                        hlse_json_str_field("exoneration", ex);
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

int
hlse_cmd_text(const HlseCli *o, int argc, char **argv, int idx) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s text \"<message>\"\n", argv[0]);
            return 2;
        }
        {
            /* Use unified scan — it runs text detection AND extracts
             * embedded URLs. This catches "Click here: https://g00gle.com" */
            ScanResult sr = hlse_scan(argv[idx + 1]);
            hlse_alert_emit_rows(sr.is_url ? "url" : "text", sr.score,
                hlse_severity_for_score(sr.score), argv[idx + 1],
                sr.reasons, sizeof sr.reasons[0], sr.n_reasons);
            if (o->json_out) {
                /* Build TextVerdict from the unified ScanResult so the JSON
                 * path honours embedded URL extraction (same as human path). */
                TextVerdict tv;
                int ti;
                memset(&tv, 0, sizeof(tv));
                tv.score = sr.score;
                tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                               ? sr.n_reasons : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                for (ti = 0; ti < tv.n_reasons; ti++)
                    snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                             "%s", sr.reasons[ti]);
                hlse_print_json_text(argv[idx + 1], &tv);
            } else if (sr.score == 0) {
                /* Channel-only risk: content scored 0 but delivery channel adds prior */
                if (hlse_from_channel()) {
                    int d = hlse_channel_delta(hlse_from_channel());
                    if (d > 0) {
                        const char *ch_rsn = hlse_channel_reason(hlse_from_channel());
                        const char *bs2 = hlse_blindspot_for("text");
                        char db[8192];
                        printf("%-7s [%d]  (text) %.60s%s\n",
                               hlse_action_for_score(d), d,
                               hlse_display_copy(db, sizeof(db), argv[idx + 1]),
                               strlen(argv[idx + 1]) > 60 ? "..." : "");
                        if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                        if (bs2) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs2);
                        return d >= o->fail_threshold ? 1 : 0;
                    }
                }
                {
                    char canon_brand[64];
                    int has_c = sr.is_url &&
                                hlse_canonical_confirm(argv[idx + 1],
                                                       canon_brand, sizeof(canon_brand));
                    const char *bs = hlse_blindspot_for(
                        has_c ? "url_canonical" : (sr.is_url ? "url" : "text"));
                    printf("OK    (text)\n");
                    if (has_c)
                        printf("  \xe2\x9c\x94 Canonical: confirmed authentic %s domain "
                               "(HLSE brand registry)\n", canon_brand);
                    if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
                }
            } else {
                int i;
                int eff = sr.score;
                const char *ch_rsn = NULL;
                const char *ex;
                if (hlse_from_channel()) {
                    int d = hlse_channel_delta(hlse_from_channel());
                    eff += d; if (eff > 100) eff = 100;
                    ch_rsn = hlse_channel_reason(hlse_from_channel());
                }
                {
                    char db[8192];
                    printf("%-7s [%d]  (text) %.60s%s\n",
                           hlse_action_for_score(eff),
                           eff,
                           hlse_display_copy(db, sizeof(db), argv[idx + 1]),
                           strlen(argv[idx + 1]) > 60 ? "..." : "");
                }
                for (i = 0; i < sr.n_reasons; i++) {
                    if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                    printf("  \xc2\xb7 %s\n", sr.reasons[i]);
                }
                if (sr.is_url) {
                    Verdict uv = hlse_check_url(argv[idx + 1]);
                    hlse_print_url_advisories(argv[idx + 1], &uv);
                    ex = hlse_url_exoneration(&uv);
                } else {
                    TextVerdict tv;
                    int ti;
                    memset(&tv, 0, sizeof(tv));
                    tv.score = sr.score;
                    tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                                   ? sr.n_reasons
                                   : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                    for (ti = 0; ti < tv.n_reasons; ti++)
                        snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                                 "%s", sr.reasons[ti]);
                    hlse_print_text_advisories(&tv);
                    ex = hlse_text_exoneration(&tv);
                }
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
            }
            {
                int eff_gate = sr.score;
                if (hlse_from_channel()) {
                    int d = hlse_channel_delta(hlse_from_channel());
                    eff_gate += d; if (eff_gate > 100) eff_gate = 100;
                }
                return eff_gate >= o->fail_threshold ? 1 : 0;
            }
        }
}

int
hlse_cmd_scan(const HlseCli *o, int argc, char **argv, int idx) {
        if (argc < idx + 2) {
            fprintf(stderr, "Usage: %s scan <directory> [--git-history]\n",
                    argv[0]);
            return 2;
        }
        /* --git-history (Perspective 111 / P0-2): scan every commit in the
         * repo's history for secrets, not just the working tree. Entirely
         * different algorithm (git subprocess stream vs. directory walk),
         * so it branches out before the normal walker below. */
        if (o->git_history) {
            return hlse_scan_git_history(argv[idx + 1], o->json_out, o->sarif_out,
                               o->emit_fingerprints, o->fail_threshold);
        }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        {
            const char *root = argv[idx + 1];
            int threats = 0, files_scanned = 0, max_depth = 20;
            int gate_hits = 0;  /* findings at/above o->fail_threshold (exit gate) */
            int max_score = 0;  /* highest score seen — for max_severity in summary */
            unsigned asset_mask = 0;  /* blast-radius: classes seen across scan */
            struct stat root_st;

            /* Verify directory exists and is accessible */
            if (stat(root, &root_st) != 0) {
                fprintf(stderr, "Error: cannot access '%s': %s\n",
                        root, strerror(errno));
                return 2;
            }
            if (!S_ISDIR(root_st.st_mode)) {
                fprintf(stderr, "Error: '%s' is not a directory\n", root);
                return 2;
            }

            /* Simple iterative directory walker using a stack.
             * Avoids unbounded recursion for deeply nested trees.     */
            struct { char path[4096]; int depth; } stack[512];
            int sp = 0;

            /* cppcheck-suppress legacyUninitvar  ; snprintf writes stack[0].path, it is not read uninitialized */
            snprintf(stack[0].path, sizeof(stack[0].path), "%s", root);
            stack[0].depth = 0;
            sp = 1;

            while (sp > 0) {
                char cur_path[4096];
                int depth;
                DIR *d;
                struct dirent *ent;

                sp--;
                snprintf(cur_path, sizeof(cur_path), "%s", stack[sp].path);
                depth = stack[sp].depth;
                d = opendir(cur_path);
                if (!d) continue;

                while ((ent = readdir(d)) != NULL) {
                    char fullpath[8192];
                    struct stat st;
                    /* Skip only the '.' and '..' entries — NOT all dotfiles.
                     * A blanket dot-skip would silently ignore .env, .npmrc,
                     * .pypirc, .git-credentials, .aws/credentials … which are
                     * the single highest-value secret-bearing files. Dot-named
                     * directories (.git, .svn) are filtered by SKIP_DIRS below. */
                    if (ent->d_name[0] == '.' &&
                        (ent->d_name[1] == '\0' ||
                         (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
                        continue;

                    if (strlen(cur_path) + strlen(ent->d_name) + 2 >= sizeof(fullpath))
                        continue;  /* path too long — skip */
                    snprintf(fullpath, sizeof(fullpath), "%s/%s",
                             cur_path, ent->d_name);

                    /* Compute path relative to scan root for SARIF URIs.
                     * GitHub code scanning requires relative URIs so it can
                     * map findings back to repo files.                       */
                    const char *sarif_path = fullpath;
                    {
                        size_t rlen = strlen(root);
                        while (rlen > 1 && root[rlen - 1] == '/') rlen--;
                        if (strncmp(fullpath, root, rlen) == 0 &&
                            fullpath[rlen] == '/')
                            sarif_path = fullpath + rlen + 1;
                    }

                    /* lstat (not stat): a symlink is classified as S_ISLNK,
                     * so it is neither recursed into (a symlinked dir would
                     * let the scan escape the target tree or loop) nor read
                     * (a symlinked file like x.env -> /etc/shadow would leak
                     * a file outside the tree). Per SPECIFICATION.md §1.   */
                    if (lstat(fullpath, &st) != 0) continue;

                    if (S_ISDIR(st.st_mode)) {
                        /* Skip vendor/build directories that produce
                         * false positives and slow down scans.
                         * Same list as eslint/ruff/semgrep defaults. */
                        static const char *SKIP_DIRS[] = {
                            "node_modules", "__pycache__", ".venv",
                            "venv", "env", "vendor", "build", "dist",
                            "target", ".tox", ".mypy_cache", ".pytest_cache",
                            ".cargo", ".npm", "coverage", ".next",
                            /* VCS metadata dirs — large, binary, no secrets to
                             * surface; previously skipped by the blanket dot
                             * filter, now skipped explicitly.                  */
                            ".git", ".svn", ".hg",
                            NULL
                        };
                        int skip = 0;
                        { int k;
                          for (k = 0; SKIP_DIRS[k]; k++) {
                              if (strcmp(ent->d_name, SKIP_DIRS[k]) == 0) {
                                  skip = 1; break;
                              }
                          }
                        }
                        if (skip) continue;

                        if (depth < max_depth && sp < 510) {
                            snprintf(stack[sp].path, sizeof(stack[sp].path),
                                     "%s", fullpath);
                            stack[sp].depth = depth + 1;
                            sp++;
                        }
                        continue;
                    }

                    if (!S_ISREG(st.st_mode)) continue;
                    files_scanned++;

                    /* Check 1: file masquerade */
                    FileVerdict fv = hlse_check_file(fullpath);
                    if (fv.score >= 40) {
                        /* P0-1: baseline/allowlist suppression. Whole-file
                         * finding — no inline-allow line context. */
                        int sup = hlse_scan_suppress(sarif_path,
                                      hlse_file_verdict_pattern_id(&fv), NULL, NULL,
                                      o->emit_fingerprints);
                        if (sup) goto after_file_check;
                        threats++;
                        hlse_alert_emit_rows("file", fv.score,
                            hlse_severity_for_score(fv.score), fullpath,
                            fv.reasons, sizeof fv.reasons[0], fv.n_reasons);
                        if (fv.score > max_score) max_score = fv.score;
                        if (fv.score >= o->fail_threshold) gate_hits++;
                        if (o->sarif_out) {
                            char msg[512] = {0};
                            int i;
                            for (i = 0; i < fv.n_reasons; i++) {
                                size_t l = strlen(msg);
                                snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                         i ? "; " : "", fv.reasons[i]);
                            }
                            hlse_sarif_add(sarif_path, 1, "file-masquerade",
                                      hlse_file_verdict_pattern_id(&fv),
                                      msg[0] ? msg : "file masquerade", fv.score);
                        } else if (o->json_out) {
                            int i;
                            char esc[512];
                            hlse_json_escape(fullpath, esc, sizeof(esc));
                            hlse_json_open("file");
                                   printf(",\"path\":\"%s\","
                                   "\"score\":%d,\"action\":\"%s\","
                                   "\"severity\":%d,\"reasons\":[",
                                   esc, fv.score, hlse_action_for_score(fv.score),
                                   hlse_severity_for_score(fv.score));
                            for (i = 0; i < fv.n_reasons; i++)
                    hlse_json_str_elem(i, fv.reasons[i]);
                            printf("]");
                            if (fv.score >= 40) {
                                /* Perspective 98: matches the standalone
                                 * `file` JSON path — pattern/objective/verify
                                 * fire from the ALERT floor (40); triage/
                                 * cascade_risk stay BLOCK+-only (60).
                                 * Perspective 101: classification and the two
                                 * advisory lines now come from the shared
                                 * hlse_file_classify_pattern()/file_masquerade_*()
                                 * accessors instead of an inline copy. */
                                const char *fpat = hlse_file_classify_pattern(&fv);
                                hlse_json_str_field("pattern", fpat);
                                printf(",\"pattern_id\":\"%s\"", hlse_file_pattern_id(fpat));
                                hlse_json_str_field("objective", hlse_file_masquerade_objective());
                                hlse_json_str_field("verify", hlse_file_masquerade_verify());
                            }
                            if (fv.score >= 60) {
                                static const char sf_tri[] =
                                    "if already opened: disconnect from the network "
                                    "immediately; run a full antivirus scan; change "
                                    "credentials for any service you were logged into at "
                                    "the time; consider a full OS reinstall for high-score "
                                    "detections";
                                static const char sf_cas[] =
                                    "all credentials and session tokens active when the file "
                                    "was opened \xe2\x80\x94 malware runs with your session "
                                    "context; also check for persistence (startup items, "
                                    "scheduled tasks, browser extensions added)";
                                hlse_json_str_field("triage", sf_tri);
                                hlse_json_str_field("cascade_risk", sf_cas);
                            }
                            if (fv.score > 0 && fv.score < 60) {
                                const char *ex = hlse_exoneration_for("file", fv.score);
                                if (ex) {
                                    hlse_json_str_field("exoneration", ex);
                                }
                            }
                            printf("}\n");
                        } else {
                            int i;
                            char db[8192];
                            printf("%-7s [%d]  %s\n",
                                   hlse_action_for_score(fv.score),
                                   fv.score,
                                   hlse_display_copy(db, sizeof(db), fullpath));
                            for (i = 0; i < fv.n_reasons; i++)
                                printf("  \xc2\xb7 %s\n", fv.reasons[i]);
                            if (fv.score >= 40) {
                                /* Perspective 101: shared with the JSON path
                                 * above (and both standalone `file` sites)
                                 * so plaintext and JSON never again describe
                                 * the same verdict with different wording. */
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
                            if (fv.score > 0 && fv.score < 60) {
                                const char *ex = hlse_exoneration_for("file", fv.score);
                                if (ex) printf("  \xe2\x86\xba Could be benign: %s\n", ex);
                            }
                        }
                    }
                    after_file_check: ;  /* P0-1 suppression jump target */

                    /* Check 2: secrets in text files. Large files are NOT
                     * skipped outright (a 2 MB log or DB dump routinely
                     * contains leaked credentials) — instead we scan up to a
                     * byte budget so work stays bounded on huge files.       */
                    if (st.st_size > 0) {
                        /* Re-open with O_NOFOLLOW + S_ISREG (defends the
                         * lstat→open TOCTOU window); never follow a symlink
                         * swapped in after classification. */
                        FILE *fp = NULL;
                        int sfd = open(fullpath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
                        if (sfd >= 0) {
                            struct stat sst;
                            if (fstat(sfd, &sst) == 0 && S_ISREG(sst.st_mode))
                                fp = fdopen(sfd, "r");
                            if (!fp) close(sfd);
                        }
                        if (fp) {
                            char line[4096];
                            int lineno = 0;
                            /* Bound the bytes inspected per file (8 MB) so a
                             * giant file cannot stall the scan, while still
                             * covering far more than the old 1 MB hard skip. */
                            size_t scanned_bytes = 0;
                            const size_t SCAN_BUDGET = 8u * 1024u * 1024u;
                            while (scanned_bytes < SCAN_BUDGET &&
                                   fgets(line, sizeof(line), fp)) {
                                lineno++;
                                scanned_bytes += strlen(line);
                                /* Indirect prompt injection: an agent reading
                                 * a repo consumes these files directly, so the
                                 * poisoned-document/skill-file path runs
                                 * through `scan`, not just `text`. Checked on
                                 * the raw line — the carriers are invisible,
                                 * so nothing else here would notice them. */
                                {
                                    char inv_r[512];
                                    int inv = hlse_check_invisible_carriers(
                                        line, inv_r, sizeof(inv_r));
                                    if (inv > 0 &&
                                        !hlse_scan_suppress(sarif_path,
                                            "HLSE-TEXT-INVISIBLE", inv_r, line,
                                            o->emit_fingerprints))
                                    {
                                        threats++;
                                        {
                                            const char *ir = inv_r;
                                            hlse_alert_emit("text", inv,
                                                hlse_severity_for_score(inv),
                                                sarif_path, &ir, 1);
                                        }
                                        if (inv > max_score) max_score = inv;
                                        if (inv >= o->fail_threshold) gate_hits++;
                                        if (!o->quiet && !o->json_out && !o->sarif_out)
                                            printf("  %s:%d: %s\n",
                                                   sarif_path, lineno, inv_r);
                                    }
                                }
                                SecretVerdict sv = hlse_scan_secrets(line);
                                if (sv.score >= 40) {
                                    int ai;
                                    /* P0-1: baseline/allowlist + inline
                                     * hlse:allow suppression. Distinguisher =
                                     * the redacted finding description (stable
                                     * per distinct secret, line-independent). */
                                    const char *spid = sv.n_findings > 0
                                        ? hlse_secret_pattern_id(sv.findings[0].type)
                                        : "HLSE-SECRET-GENERIC";
                                    const char *sdesc = sv.n_findings > 0
                                        ? sv.findings[0].description : "";
                                    if (hlse_scan_suppress(sarif_path, spid, sdesc, line, o->emit_fingerprints))
                                        continue;
                                    threats++;
                                    hlse_alert_emit_rows("secret", sv.score,
                                        hlse_severity_for_score(sv.score),
                                        sarif_path, sv.findings,
                                        sizeof sv.findings[0], sv.n_findings);
                                    if (sv.score > max_score) max_score = sv.score;
                                    if (sv.score >= o->fail_threshold) gate_hits++;
                                    for (ai = 0; ai < sv.n_findings; ai++)
                                        asset_mask |=
                                            hlse_asset_class_of(sv.findings[ai].type);
                                    if (o->sarif_out) {
                                        char msg[512] = {0};
                                        int i;
                                        for (i = 0; i < sv.n_findings; i++) {
                                            size_t l = strlen(msg);
                                            snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                                     i ? "; " : "",
                                                     sv.findings[i].description);
                                        }
                                        hlse_sarif_add(sarif_path, lineno, "secret",
                                                  sv.n_findings > 0
                                                    ? hlse_secret_pattern_id(sv.findings[0].type)
                                                    : "HLSE-SECRET-GENERIC",
                                                  msg[0] ? msg : "secret", sv.score);
                                    } else if (o->json_out) {
                                        int i;
                                        char esc_p[512], et[64], ed[512];
                                        hlse_json_escape(fullpath, esc_p, sizeof(esc_p));
                                        /* Emit findings:[{type,description}] per spec §5.2
                                         * (same schema as the standalone secret subcommand). */
                                        hlse_json_open("secret");
                                        printf(",\"path\":\"%s\","
                                               "\"line\":%d,\"score\":%d,"
                                               "\"action\":\"%s\",\"severity\":%d,"
                                               "\"findings\":[",
                                               esc_p, lineno, sv.score,
                                               hlse_action_for_score(sv.score),
                                               hlse_severity_for_score(sv.score));
                                        for (i = 0; i < sv.n_findings; i++) {
                                            hlse_json_escape(sv.findings[i].type, et, sizeof(et));
                                            hlse_json_escape(sv.findings[i].description, ed, sizeof(ed));
                                            printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                                                   i ? "," : "", et, ed);
                                        }
                                        printf("]");
                                        {
                                            const char *conf = hlse_secret_confidence(&sv);
                                            if (conf) {
                                                hlse_json_str_field("confidence", conf);
                                            }
                                        }
                                        {
                                            const char *rem = hlse_remediation_for("secret", sv.score);
                                            if (rem) {
                                                hlse_json_str_field("remediation", rem);
                                            }
                                        }
                                        if (sv.n_findings > 0) {
                                            const char *cav = hlse_secret_finding_caveat(sv.findings[0].type);
                                            if (cav) {
                                                hlse_json_str_field("caveat", cav);
                                            }
                                        }
                                        if (sv.score >= 60 && sv.n_findings > 0) {
                                            const char *ftype = sv.findings[0].type;
                                            const char *sobj  = hlse_secret_objective_for(ftype);
                                            hlse_secret_pattern_label(ftype, esc_p, sizeof(esc_p));
                                            hlse_json_str_field("pattern", esc_p);
                                            printf(",\"pattern_id\":\"%s\"", hlse_secret_pattern_id(ftype));
                                            if (sobj) {
                                                hlse_json_str_field("objective", sobj);
                                            }
                                            hlse_json_str_field("verify", hlse_secret_verify_text());
                                            hlse_json_str_field("triage", hlse_secret_triage_text());
                                            hlse_json_str_field("cascade_risk", hlse_secret_cascade_text());
                                        }
                                        if (sv.score > 0 && sv.score < 60) {
                                            const char *ex = hlse_exoneration_for("secret", sv.score);
                                            if (ex) {
                                                hlse_json_str_field("exoneration", ex);
                                            }
                                        }
                                        printf("}\n");
                                    } else {
                                        int i;
                                        char db[8192];
                                        printf("%-7s [%d]  %s:%d\n",
                                               hlse_action_for_score(sv.score),
                                               sv.score,
                                               hlse_display_copy(db, sizeof(db),
                                                                 fullpath),
                                               lineno);
                                        for (i = 0; i < sv.n_findings; i++)
                                            printf("  \xc2\xb7 %s\n",
                                                   sv.findings[i].description);
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
                                    }
                                }

                                /* Check 3: phishing URLs embedded in text */
                                {
                                    const char *p = line;
                                    while ((p = strstr(p, "http")) != NULL) {
                                        if (strncmp(p, "http://", 7) != 0 &&
                                            strncmp(p, "https://", 8) != 0) {
                                            p += 4; continue;
                                        }
                                        char url_buf[HLSE_MAX_URL];
                                        int ui = 0;
                                        while (p[ui] && p[ui] != ' ' && p[ui] != '\t'
                                               && p[ui] != '\n' && p[ui] != '"'
                                               && p[ui] != '\'' && p[ui] != '>'
                                               && p[ui] != ')' && ui < 2047) {
                                            url_buf[ui] = p[ui]; ui++;
                                        }
                                        url_buf[ui] = '\0';
                                        {
                                            Verdict uv = hlse_check_url(url_buf);
                                            if (uv.score >= 40) {
                                                /* P0-1: baseline/allowlist +
                                                 * inline hlse:allow. Use the
                                                 * relative path + url as the
                                                 * distinguisher; on suppression
                                                 * fall through to p += ui. */
                                                if (hlse_scan_suppress(sarif_path,
                                                        hlse_url_pattern_id(&uv),
                                                        url_buf, line,
                                                        o->emit_fingerprints))
                                                    goto url_advance;
                                                threats++;
                                                hlse_alert_emit_rows("url",
                                                    uv.score,
                                                    hlse_severity_for_score(uv.score),
                                                    url_buf, uv.reasons,
                                                    sizeof uv.reasons[0],
                                                    uv.n_reasons);
                                                if (uv.score > max_score) max_score = uv.score;
                                                if (uv.score >= o->fail_threshold)
                                                    gate_hits++;
                                                if (o->sarif_out) {
                                                    char msg[512] = {0};
                                                    int k;
                                                    size_t l0 = strlen(url_buf) < 200 ?
                                                                strlen(url_buf) : 200;
                                                    snprintf(msg, sizeof(msg),
                                                             "Phishing URL: %.*s — ",
                                                             (int)l0, url_buf);
                                                    for (k = 0; k < uv.n_reasons; k++) {
                                                        size_t l = strlen(msg);
                                                        snprintf(msg + l, sizeof(msg) - l,
                                                                 "%s%s", k ? "; " : "",
                                                                 uv.reasons[k]);
                                                    }
                                                    hlse_sarif_add(sarif_path, lineno,
                                                              "phishing-url",
                                                              hlse_url_pattern_id(&uv),
                                                              msg, uv.score);
                                                } else if (o->json_out) {
                                                    char eu[HLSE_MAX_URL];
                                                    hlse_json_escape(url_buf, eu, sizeof(eu));
                                                    printf("{\"kind\":\"url\",\"path\":\"%s\","
                                                           "\"line\":%d,\"url\":\"%s\","
                                                           "\"score\":%d,\"action\":\"%s\","
                                                           "\"reasons\":[",
                                                           fullpath, lineno, eu, uv.score,
                                                           hlse_action_for_score(uv.score));
                                                    { int kr;
                                                      for (kr = 0; kr < uv.n_reasons; kr++) {
                                                          
                                                          hlse_json_str_elem(kr, uv.reasons[kr]);
                                                      }
                                                    }
                                                    printf("]");
                                                    {
                                                        char ucf_buf[160];
                                                        int u_sig = hlse_confidence_for(&uv, ucf_buf, sizeof(ucf_buf));
                                                        if (u_sig > 0) {
                                                            hlse_json_escape(ucf_buf, eu, sizeof(eu));
                                                            printf(",\"signal_count\":%d,\"confidence\":\"%s\"", u_sig, eu);
                                                        }
                                                    }
                                                    if (uv.score >= 40) {
                                                        /* Perspective 95: pattern/pattern_id/objective/safe_url/verify
                                                         * now fire from the ALERT floor (40), matching the standalone
                                                         * URL JSON path — an embedded URL scored ALERT used to emit
                                                         * only raw reasons + exoneration while the same URL scanned
                                                         * standalone got the full advisory. triage/cascade_risk stay
                                                         * BLOCK+-only (60): post-incident guidance presumes the user
                                                         * already acted, which only high confidence warrants. */
                                                        const char *upat = hlse_classify_url_attack(&uv);
                                                        const char *uvrf = hlse_verification_for(&uv);
                                                        char uobj_buf[320], usafe[384];
                                                        int has_obj  = hlse_compound_objective(&uv, uobj_buf, sizeof(uobj_buf));
                                                        int has_safe = hlse_safe_destinations(&uv, usafe, sizeof(usafe));
                                                        if (upat)     { hlse_json_str_field("pattern", upat); }
                                                        if (upat)     { const char *upid = hlse_url_pattern_id(&uv); if (upid) printf(",\"pattern_id\":\"%s\"", upid); }
                                                        if (has_obj)  { hlse_json_str_field("objective", uobj_buf); }
                                                        if (has_safe) { hlse_json_str_field("safe_url", usafe); }
                                                        if (uvrf)     { hlse_json_str_field("verify", uvrf); }
                                                    }
                                                    if (uv.score >= 60) {
                                                        const char *ucas = hlse_cascade_risk(&uv);
                                                        char utri_buf[512];
                                                        int has_tri  = hlse_compound_triage(&uv, utri_buf, sizeof(utri_buf));
                                                        if (has_tri)  { hlse_json_str_field("triage", utri_buf); }
                                                        if (ucas)     { hlse_json_str_field("cascade_risk", ucas); }
                                                    }
                                                    if (uv.score >= 40 && uv.score < 60) {
                                                        const char *uexon = hlse_url_exoneration(&uv);
                                                        if (uexon) {
                                                            hlse_json_str_field("exoneration", uexon);
                                                        }
                                                    }
                                                    printf("}\n");
                                                } else {
                                                    int k;
                                                    char db[8192], db2[HLSE_MAX_URL];
                                                    printf("%-7s [%d]  %s:%d  %s\n",
                                                           hlse_action_for_score(uv.score),
                                                           uv.score,
                                                           hlse_display_copy(db, sizeof(db),
                                                                             fullpath),
                                                           lineno,
                                                           hlse_display_copy(db2, sizeof(db2),
                                                                             url_buf));
                                                    for (k = 0; k < uv.n_reasons; k++)
                                                        printf("  \xc2\xb7 %s\n", uv.reasons[k]);
                                                    hlse_print_url_advisories(url_buf, &uv);
                                                    if (uv.score >= 40 && uv.score < 60) {
                                                        const char *uexon = hlse_url_exoneration(&uv);
                                                        if (uexon)
                                                            printf("  \xe2\x86\xba Could be benign: %s\n", uexon);
                                                    }
                                                }
                                            }
                                        }
                                        url_advance:            /* P0-1 target */
                                        p += ui;
                                    }
                                }
                            }
                            fclose(fp);
                        }
                    }
                }
                closedir(d);
            }

            /* --fingerprints mode emits only the per-finding fingerprint lines
             * (for baseline generation); skip the summary and never fail the
             * gate — generating a baseline must exit 0. */
            if (o->emit_fingerprints) {
                return 0;
            }
            if (o->sarif_out) {
                hlse_sarif_emit(HLSE_VERSION);
            } else if (!o->json_out) {
                if (threats == 0) {
                    const char *bs = hlse_blindspot_for("scan");
                    char db[8192];
                    printf("OK    %s (%d files scanned, 0 threats)\n",
                           hlse_display_copy(db, sizeof(db), root),
                           files_scanned);
                    if (bs) printf("  \xe2\x84\xb9 Blind spot: %s\n", bs);
                } else {
                    char classes[256];
                    int nclasses = hlse_asset_mask_describe(asset_mask, classes,
                                                       sizeof(classes));
                    printf("\n%d threat(s) in %d files under %s\n",
                           threats, files_scanned, root);
                    if (gate_hits > 0 && o->fail_threshold != 60)
                        printf("  %d finding(s) exceeded the --fail-on threshold (%d)\n",
                               gate_hits, o->fail_threshold);
                    /* Immediate action: one-sentence triage keyed to the
                     * most severe asset class (or file/URL threats). */
                    printf("\xe2\x86\x92 Immediate action: %s\n",
                           hlse_scan_immediate_action((unsigned)asset_mask, nclasses));
                    /* Blast radius: credentials spanning 2+ asset classes let
                     * an attacker pivot across systems — worse than the count
                     * alone suggests. */
                    if (nclasses >= 2)
                        printf("\xe2\x9a\xa0  BLAST RADIUS: leaked credentials "
                               "span %d asset classes (%s) — an attacker can "
                               "pivot across these systems. Rotate ALL of them "
                               "and assume lateral movement.\n",
                               nclasses, classes);
                }
            } else {
                /* NDJSON: final summary line for CI tooling */
                char esc_root[4096], classes[256];
                int nclasses = hlse_asset_mask_describe(asset_mask, classes,
                                                   sizeof(classes));
                hlse_json_escape(root, esc_root, sizeof(esc_root));
                hlse_json_open("scan_summary");
                       printf(",\"target\":\"%s\","
                       "\"files_scanned\":%d,\"threats\":%d,"
                       "\"max_severity\":%d,"
                       "\"gate_hits\":%d,\"fail_threshold\":%d,"
                       "\"asset_classes\":%d,\"blast_radius\":\"%s\"",
                       esc_root, files_scanned, threats,
                       hlse_severity_for_score(max_score),
                       gate_hits, o->fail_threshold,
                       nclasses, classes);
                if (threats == 0) {
                    const char *bs = hlse_blindspot_for("scan");
                    if (bs) {
                        
                        hlse_json_str_field("blind_spot", bs);
                    }
                } else {
                    const char *ia = hlse_scan_immediate_action((unsigned)asset_mask, nclasses);
                    
                    hlse_json_str_field("immediate_action", ia);
                }
                printf("}\n");
            }
            return gate_hits > 0 ? 1 : 0;
        }
#pragma GCC diagnostic pop
}
