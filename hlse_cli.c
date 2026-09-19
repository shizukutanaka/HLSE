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
