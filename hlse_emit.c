/* hlse_emit.c — CLI output layer: the human-readable advisory getters
 * (Pattern / Objective / Verify / Triage / Cascade text per detector kind)
 * plus the verdict emitters (JSON + human advisories for url and text).
 * Extracted verbatim from hlse_core.c (split increment 8) with hlse_*
 * exports. printf-based; reads no flag globals. */
#include <stdio.h>

#define MAX_URL 2048  /* matches the engine url buffer bound */
#include <string.h>
#include <stddef.h>
#include "hlse_core.h"
#include "hlse_text.h"
#include "hlse_util.h"
#include "hlse_emit.h"
#include "hlse_channel.h"

/* Per-finding remediation hint for HIGH/CRIT audit findings.
 * Returns a short command or action string, or NULL if no specific fix
 * is available for this finding. Keyed to the A-code prefix + keywords. */
const char *
hlse_audit_remediation_for(const char *desc)
{
    if (!desc) return NULL;
    /* A1: SSH configuration */
    if (strncmp(desc, "A1:", 3) == 0) {
        if (strstr(desc, "PermitRootLogin yes"))
            return "sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "PasswordAuthentication yes"))
            return "sudo sed -i 's/PasswordAuthentication yes/"
                   "PasswordAuthentication no/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "Protocol 1"))
            return "sudo sed -i 's/^Protocol 1/Protocol 2/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "PermitEmptyPasswords"))
            return "sudo sed -i 's/PermitEmptyPasswords yes/"
                   "PermitEmptyPasswords no/'"
                   " /etc/ssh/sshd_config && sudo systemctl reload ssh";
        if (strstr(desc, "authorized_keys"))
            return "chmod 600 ~/.ssh/authorized_keys";
        return "sudo nano /etc/ssh/sshd_config  # correct the flagged setting,"
               " then: sudo systemctl reload ssh";
    }
    /* A2: File permission issues */
    if (strncmp(desc, "A2:", 3) == 0) {
        if (strstr(desc, "id_rsa") || strstr(desc, "id_ed25519")
            || strstr(desc, "id_ecdsa"))
            return "chmod 600 ~/.ssh/id_rsa  # (or id_ed25519 / id_ecdsa)";
        if (strstr(desc, ".aws/credentials"))
            return "chmod 600 ~/.aws/credentials";
        if (strstr(desc, ".env"))
            return "chmod 600 ~/.env";
        if (strstr(desc, ".netrc"))
            return "chmod 600 ~/.netrc";
        if (strstr(desc, ".pgpass"))
            return "chmod 600 ~/.pgpass";
        if (strstr(desc, ".docker/config.json"))
            return "chmod 600 ~/.docker/config.json";
        if (strstr(desc, ".kube/config"))
            return "chmod 600 ~/.kube/config";
        if (strstr(desc, "gnupg") || strstr(desc, "GPG"))
            return "chmod 700 ~/.gnupg && chmod 600 ~/.gnupg/secring.gpg";
        return "chmod go-rwx <file>  # remove group/other read permission"
               " from the flagged file";
    }
    /* A3: DNS / hosts file poisoning */
    if (strncmp(desc, "A3:", 3) == 0) {
        if (strstr(desc, "/etc/hosts"))
            return "sudo diff /etc/hosts /etc/hosts.bak 2>/dev/null ||"
                   " sudo cp /etc/hosts /etc/hosts.bak;"
                   " review /etc/hosts for unexpected entries";
        return "review the flagged DNS resolver or hosts file entry";
    }
    /* A4: Cron persistence */
    if (strncmp(desc, "A4:", 3) == 0)
        return "crontab -l  # review; then: crontab -e to remove"
               " the suspicious entry";
    /* A5: Insecure PATH */
    if (strncmp(desc, "A5:", 3) == 0)
        return "remove '.' and any world-writable directories from PATH"
               " in ~/.bashrc or ~/.profile; then: source ~/.bashrc";
    /* A6: Shell startup backdoor */
    if (strncmp(desc, "A6:", 3) == 0)
        return "nano ~/.bashrc  # (or ~/.profile / ~/.bash_profile)"
               " — remove the flagged line, then: source ~/.bashrc";
    /* A7: Sudoers NOPASSWD */
    if (strncmp(desc, "A7:", 3) == 0)
        return "sudo visudo  # change 'NOPASSWD: ALL' to 'ALL'"
               " to require a password for sudo";
    /* A8: Systemd user unit persistence */
    if (strncmp(desc, "A8:", 3) == 0)
        return "systemctl --user disable <unit> &&"
               " systemctl --user stop <unit>;"
               " then: rm ~/.config/systemd/user/<unit>.service";
    return NULL;
}

/* Map a credential type label to what access it grants the attacker.
 *
 * Socratic question (Perspective 99): "'Stripe Live Publishable' matches the
 * strstr(type, \"Stripe\") branch below and is told it grants 'ability to
 * issue charges, view customer payment data, and issue refunds' — but a
 * publishable key (pk_live_) cannot do any of that by Stripe's own design;
 * only a SECRET key (sk_live_/rk_live_) can. Reachable whenever this finding
 * combines with another to cross the >=60 objective/remediation/triage
 * threshold (e.g. alongside a JWT), telling the user their exposed
 * publishable key just handed an attacker refund access — false, and exactly
 * the kind of over-claim that erodes trust in every other correct verdict."
 *
 * Exact-match this label BEFORE the generic Stripe substring check so a
 * publishable key gets the accurate (and much calmer) objective instead of
 * inheriting the secret-key narrative.                                     */
const char *
hlse_secret_objective_for(const char *type)
{
    if (!type || !type[0]) return NULL;
    if (strcmp(type, "Stripe Live Publishable") == 0)
        return "none directly \xe2\x80\x94 publishable keys are designed to be "
               "embedded in public client-side code and cannot create charges, "
               "issue refunds, or read customer payment data; only a paired "
               "SECRET key (sk_live_/rk_live_) grants that access";
    if (strstr(type, "AWS"))
        return "cloud API access \xe2\x80\x94 S3 read/write, EC2 control, and IAM "
               "privilege escalation; all resources visible to this key are at risk";
    if (strstr(type, "GitHub") || strstr(type, "GitLab"))
        return "source code and CI/CD pipeline access \xe2\x80\x94 read/write "
               "repositories, access CI secrets, trigger workflows";
    if (strstr(type, "Stripe"))
        return "payment processing \xe2\x80\x94 ability to issue charges, view "
               "customer payment data, and issue refunds";
    if (strstr(type, "Google") || strstr(type, "GCP"))
        return "Google Cloud API access \xe2\x80\x94 Maps, Analytics, or Cloud "
               "resources depending on key scope";
    if (strstr(type, "Slack"))
        return "workspace access \xe2\x80\x94 read messages and files across "
               "channels, post as the bot user or the token owner";
    if (strstr(type, "SSH") || strstr(type, "Private Key")
        || strstr(type, "RSA") || strstr(type, "OPENSSH"))
        return "server authentication \xe2\x80\x94 SSH access to every host that "
               "trusts this key (check authorized_keys)";
    if (strstr(type, "Database") || strstr(type, "Postgres")
        || strstr(type, "MySQL") || strstr(type, "Mongo"))
        return "database read/write access \xe2\x80\x94 plaintext query access "
               "to all records in the connected database";
    if (strstr(type, "Twilio") || strstr(type, "SendGrid")
        || strstr(type, "Mailgun"))
        return "messaging API access \xe2\x80\x94 send SMS/email as your account, "
               "read inbound messages, and incur billing charges";
    return "authenticated access to the associated service and any resource "
           "this credential controls";
}

/* Perspective 99: a factual correction for credential TYPES that are
 * public-by-design and therefore not "compromised" in the sense the rest of
 * the secret advisory assumes. Unlike hlse_exoneration_for() (a probabilistic
 * "might be a false positive" hedge for a score band), this is an
 * unconditional, type-specific fact: Stripe publishable keys are ALWAYS
 * meant to be public, at any score. Returns NULL for every other type. */
const char *
hlse_secret_finding_caveat(const char *type) {
    if (!type) return NULL;
    if (strcmp(type, "Stripe Live Publishable") == 0)
        return "Stripe publishable keys (pk_live_/pk_test_) are designed to "
               "be public \xe2\x80\x94 embedded in checkout pages, mobile "
               "apps, and browser JavaScript by every Stripe integration. "
               "Stripe's own documentation confirms they cannot create "
               "charges, issue refunds, or read customer payment data. "
               "Rotation is not required for this key; if a paired SECRET "
               "key (sk_live_/rk_live_) was also exposed, that one needs "
               "immediate rotation instead.";
    return NULL;
}

/* Socratic question (Perspective 102): "The P101 audit found the file kind's
 * pattern/objective/verify text duplicated four ways and consolidated it —
 * does 'secret' have the exact same problem?" Answer: yes. The pattern label
 * ("exposed credential — %s"), verify, triage, and cascade_risk text were
 * each independently copy-pasted at the standalone `secret` JSON site and
 * the scan-embedded JSON site (identical strings, two names: sec_vrf/ss_vrf,
 * sec_tri/ss_tri, sec_cas/ss_cas), and ALSO reduced to shorter, differently-
 * worded printf literals at the two plaintext sites — so a `secret` verdict
 * read as JSON and the same verdict read as plaintext described the
 * independent verification step differently. Consolidated into shared
 * accessors, mirroring hlse_file_masquerade_objective()/hlse_file_masquerade_verify();
 * every one of the four sites and both output formats now say the same
 * thing. Pure refactor — no detection logic, score, or field value changed. */
void
hlse_secret_pattern_label(const char *ftype, char *buf, size_t buflen) {
    snprintf(buf, buflen, "exposed credential \xe2\x80\x94 %s", ftype);
}

const char *
hlse_secret_verify_text(void) {
    /* Deliberately avoids the phrase "blast radius" — `scan` has a distinct,
     * unrelated BLAST RADIUS warning for credentials found across multiple
     * asset classes (P102 caught the two colliding in scan's plaintext
     * output once JSON/plaintext text was unified). */
    return "check access logs for this credential BEFORE revoking "
           "\xe2\x80\x94 audit trails (AWS CloudTrail, GitHub audit "
           "log) reveal whether it was already used and exactly what "
           "was accessed";
}

const char *
hlse_secret_triage_text(void) {
    return "revoke or rotate the credential immediately (do not "
           "delete \xe2\x80\x94 rotate to cut off access before the key is "
           "gone); purge from git history with git filter-repo or "
           "BFG Repo Cleaner \xe2\x80\x94 assume every clone already has it";
}

const char *
hlse_secret_cascade_text(void) {
    return "every other credential in the same file, repository, "
           "or environment \xe2\x80\x94 treat everything co-located as "
           "potentially leaked; also rotate any secret that shared "
           "the same passphrase or was stored alongside this one";
}

/* Socratic question (Perspective 103): "P101/P102 found and fixed the same
 * JSON/plaintext duplication-and-drift for file and secret — do protect,
 * network, and package have it too?" Yes: each kind's JSON path built its
 * advisory lines from `static const char[]` literals, while the matching
 * plaintext path re-typed shorter, differently-worded printf literals for
 * the exact same verdict. Consolidated into shared accessors, one group per
 * kind, following the same naming convention as the file/secret ones above.
 * Pure refactor — every JSON value is unchanged; only the plaintext wording
 * is upgraded to match (previously-shortened) JSON text word-for-word. */
const char *
hlse_protect_pattern_text(void) {
    return "ransomware / destructive malware indicators detected";
}

const char *
hlse_protect_objective_text(void) {
    return "data destruction and extortion \xe2\x80\x94 ransomware encrypts "
           "accessible files and demands payment; credentials are "
           "often harvested before encryption begins";
}

const char *
hlse_protect_verify_text(void) {
    return "photograph or copy the ransom note before any other "
           "action \xe2\x80\x94 it contains the attacker's ID, contact, "
           "and decryption instructions; consult NCSC/CISA or law "
           "enforcement BEFORE paying \xe2\x80\x94 free decryptors may exist";
}

const char *
hlse_protect_triage_text(void) {
    return "IMMEDIATELY disconnect from the network (unplug Ethernet, "
           "disable WiFi and Bluetooth) \xe2\x80\x94 this stops lateral "
           "movement and stops encryption spreading to network shares; "
           "do NOT reboot \xe2\x80\x94 volatile memory may contain keys; "
           "preserve all logs and report to law enforcement";
}

const char *
hlse_protect_cascade_text(void) {
    return "all credentials on this machine and any network shares "
           "it accessed \xe2\x80\x94 ransomware groups commonly harvest "
           "credentials before encrypting; rotate domain admin, file "
           "server, VPN, and cloud credentials from a clean device";
}

const char *
hlse_net_pattern_text(void) {
    return "suspicious network activity (C2 / exfiltration indicator)";
}

const char *
hlse_network_objective_text(void) {
    return "data exfiltration or persistent access \xe2\x80\x94 an active "
           "process may be beaconing to a command-and-control server, "
           "exfiltrating credentials, or establishing lateral movement";
}

const char *
hlse_network_verify_text(void) {
    return "identify the process owning the suspicious connection: "
           "'lsof -i' or 'ss -tp' on Linux, 'netstat -b' on Windows; "
           "verify it against your known installed software before "
           "taking any disruptive action";
}

const char *
hlse_network_triage_text(void) {
    return "if the process is unrecognised: kill it and isolate the "
           "host from the network; preserve network capture (tcpdump) "
           "and process memory before rebooting \xe2\x80\x94 evidence is lost "
           "on reboot; report to your security team or law enforcement";
}

const char *
hlse_network_cascade_text(void) {
    return "credentials stored on this machine (browser, credential "
           "manager, SSH keys, cloud CLI tokens) \xe2\x80\x94 an active "
           "C2 connection may already be exfiltrating them; rotate all "
           "from a clean device before the machine is brought back online";
}

const char *
hlse_package_pattern_text(void) {
    return "dependency confusion / typosquat supply-chain attack";
}

const char *
hlse_package_objective_text(void) {
    return "arbitrary code execution \xe2\x80\x94 package install scripts "
           "run with your user privileges; any secret readable from "
           "your shell (API keys, tokens, SSH keys) is at risk";
}

const char *
hlse_package_verify_text(void) {
    return "verify the exact package name on the official registry "
           "page before installing; if you must proceed, install "
           "with --ignore-scripts (npm/pnpm) or --no-build (uv/pip) "
           "so a malicious preinstall/postinstall/prepare hook "
           "cannot run \xe2\x80\x94 lifecycle scripts execute with your "
           "privileges before install even completes; most "
           "ecosystems also support --dry-run to preview first";
}

const char *
hlse_package_triage_text(void) {
    return "if already installed, remove the package immediately "
           "(pip uninstall / npm uninstall / cargo remove) and "
           "inspect the lifecycle scripts (preinstall/postinstall/"
           "prepare); self-propagating worms (Shai-Hulud) run a "
           "disk-wide secret scan (TruffleHog), so rotate EVERY "
           "credential on the machine, not just shell-environment "
           "ones \xe2\x80\x94 if you publish packages, revoke your "
           "npm/PyPI token FIRST, before the worm can republish "
           "from your account";
}

const char *
hlse_package_cascade_text(void) {
    return "if you maintain packages, your registry publish token is "
           "the worm's self-propagation vector \xe2\x80\x94 it "
           "republishes the payload into YOUR packages, infecting "
           "every downstream user; revoke the token and audit your "
           "published versions for unexpected releases, plus all "
           "disk-resident API keys, SSH keys, and cloud credentials "
           "a TruffleHog-style scan would harvest";
}

/* Perspective 104: esp and clipboard are BLOCK+-only (score is always 0 or
 * >=60/70 — no ALERT-band split needed, unlike file/secret/protect/network/
 * package), but they had the same JSON/plaintext duplication-and-drift the
 * P101-103 accessors fixed elsewhere. Consolidated here. */
const char *
hlse_esp_pattern_text(void) {
    return "UEFI bootkit indicator in EFI System Partition";
}

const char *
hlse_esp_objective_text(void) {
    return "persistent firmware-level access \xe2\x80\x94 a bootkit "
           "survives OS reinstall; it executes before the OS boots "
           "and can disable security software, log keystrokes, and "
           "intercept disk encryption before the OS sees it";
}

const char *
hlse_esp_verify_text(void) {
    return "run a second scan with a different tool (CHIPSEC, "
           "vendor UEFI integrity check) before taking disruptive "
           "action \xe2\x80\x94 bootkit false positives exist and the "
           "remediation is destructive; check Secure Boot status "
           "first (mokutil --sb-state)";
}

const char *
hlse_esp_triage_text(void) {
    return "do NOT reinstall the OS first \xe2\x80\x94 it will not "
           "remove a bootkit; consult an incident-response specialist; "
           "if confirmed, flash the UEFI firmware from a vendor-signed "
           "image and replace Secure Boot enrollment keys "
           "(mokutil --reset)";
}

const char *
hlse_esp_cascade_text(void) {
    return "all credentials and disk encryption keys on this machine "
           "\xe2\x80\x94 a bootkit has pre-OS access to encrypted volumes "
           "and can log all keystrokes before encryption; rotate from "
           "a clean device and consider the machine untrusted until "
           "the firmware is re-flashed";
}

const char *
hlse_clipboard_pattern_text(void) {
    return "cryptocurrency clipboard hijack (clipper malware)";
}

const char *
hlse_clipboard_objective_text(void) {
    return "cryptocurrency theft \xe2\x80\x94 your copied address was "
           "silently replaced; funds sent reach the attacker's wallet "
           "and cannot be recovered";
}

const char *
hlse_clipboard_verify_text(void) {
    return "re-copy the address from the recipient's own verified "
           "source and compare every character in your wallet app "
           "before confirming the transaction";
}

const char *
hlse_clipboard_triage_text(void) {
    return "if you already sent funds: contact your exchange or "
           "wallet provider immediately \xe2\x80\x94 crypto transfers "
           "are irreversible; file a report with law enforcement "
           "and the exchange's fraud team";
}

const char *
hlse_clipboard_cascade_text(void) {
    return "every crypto address you have copied since the last "
           "clean boot \xe2\x80\x94 clipper malware intercepts all "
           "clipboard activity; assume all recent copies were "
           "redirected and run a full malware scan before "
           "transacting again";
}

void
hlse_print_json_url(const char *url, const Verdict *v) {
    char escaped_url[MAX_URL * 2];
    const char *pat  = hlse_classify_url_attack(v);
    const char *pid  = hlse_url_pattern_id(v);  /* stable HLSE-URL-* token */
    const char *vrf  = hlse_verification_for(v);
    const char *cas  = hlse_cascade_risk(v);
    const char *exon = hlse_url_exoneration(v); /* NULL outside [15,59] */
    char obj_buf[320] = "";
    char tri_buf[512] = "";
    char asc_diff_buf[256] = "";
    char cf_buf[160] = "";
    char esc_pat[256] = "";
    char esc_obj[320] = "";
    char esc_vrf[512] = "";
    char esc_tri[1024] = "";
    char esc_cas[512] = "";
    char esc_asc[384] = "";
    char esc_cf[320] = "";
    char esc_exon[512] = "";
    char safe[384]; /* compound "https://A and https://B" */
    char esc_safe[768] = "";
    char conf[160];
    char esc_conf[320] = "";
    char canon_brand[64];
    int  has_obj    = hlse_compound_objective(v, obj_buf, sizeof(obj_buf));
    int  has_safe   = hlse_safe_destinations(v, safe, sizeof(safe));
    int  has_conf   = hlse_confusable_report(url, conf, sizeof(conf));
    int  has_asc    = hlse_ascii_diff(v, asc_diff_buf, sizeof(asc_diff_buf));
    int  signal_cnt = hlse_confidence_for(v, cf_buf, sizeof(cf_buf));
    int  has_tri    = hlse_compound_triage(v, tri_buf, sizeof(tri_buf));
    int  has_canon  = (v->score == 0) &&
                      hlse_canonical_confirm(url, canon_brand, sizeof(canon_brand));
    hlse_json_escape(url, escaped_url, sizeof(escaped_url));
    if (pat)     hlse_json_escape(pat,          esc_pat,  sizeof(esc_pat));
    if (has_obj) hlse_json_escape(obj_buf,      esc_obj,  sizeof(esc_obj));
    if (vrf)     hlse_json_escape(vrf,          esc_vrf,  sizeof(esc_vrf));
    if (has_tri) hlse_json_escape(tri_buf,      esc_tri,  sizeof(esc_tri));
    if (cas)     hlse_json_escape(cas,          esc_cas,  sizeof(esc_cas));
    if (has_asc) hlse_json_escape(asc_diff_buf, esc_asc,  sizeof(esc_asc));
    if (signal_cnt > 0) hlse_json_escape(cf_buf, esc_cf,  sizeof(esc_cf));
    if (has_safe) hlse_json_escape(safe, esc_safe, sizeof(esc_safe));
    if (has_conf) hlse_json_escape(conf, esc_conf, sizeof(esc_conf));
    if (exon)    hlse_json_escape(exon, esc_exon, sizeof(esc_exon));
    printf("{\"kind\":\"url\",\"hlse_version\":\"" HLSE_VERSION "\","
           "\"target\":\"%s\",\"score\":%d,\"action\":\"%s\","
           "\"severity\":%d",
           escaped_url, v->score, hlse_action_for_score(v->score),
           hlse_severity_for_score(v->score));
    if (signal_cnt > 0) printf(",\"signal_count\":%d,\"confidence\":\"%s\"",
                               signal_cnt, esc_cf);
    if (has_canon)  printf(",\"canonical_brand\":\"%s\"", canon_brand);
    if (v->score == 0) {
        /* Use the narrower post-authentication caveat when the domain was
         * positively confirmed against the brand registry — the generic
         * "pixel-perfect clone" blind spot contradicts a canonical confirm. */
        const char *bs = hlse_blindspot_for(has_canon ? "url_canonical" : "url");
        if (bs) {
            char esc_bs[512];
            hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
            printf(",\"blind_spot\":\"%s\"", esc_bs);
        }
    }
    if (pat)        printf(",\"pattern\":\"%s\"", esc_pat);
    if (pid)        printf(",\"pattern_id\":\"%s\"", pid); /* stable SIEM token */
    if (has_obj)    printf(",\"objective\":\"%s\"", esc_obj);
    if (has_conf)   printf(",\"confusable\":\"%s\"", esc_conf);
    if (has_asc)    printf(",\"ascii_diff\":\"%s\"", esc_asc);
    if (has_safe)   printf(",\"safe_url\":\"%s\"", esc_safe);
    if (vrf)        printf(",\"verify\":\"%s\"", esc_vrf);
    if (has_tri)    printf(",\"triage\":\"%s\"", esc_tri);
    if (cas)        printf(",\"cascade_risk\":\"%s\"", esc_cas);
    if (exon)       printf(",\"exoneration\":\"%s\"", esc_exon);
    if (hlse_from_channel()) {
        int d   = hlse_channel_delta(hlse_from_channel());
        int eff = v->score + d; if (eff > 100) eff = 100;
        printf(",\"channel\":\"%s\",\"channel_delta\":%d,\"effective_score\":%d,"
               "\"effective_action\":\"%s\",\"effective_severity\":%d",
               hlse_from_channel(), d, eff, hlse_action_for_score(eff),
               hlse_severity_for_score(eff));
        {
            const char *ch_rsn = hlse_channel_reason(hlse_from_channel());
            if (ch_rsn) {
                char esc_ch[512];
                hlse_json_escape(ch_rsn, esc_ch, sizeof(esc_ch));
                printf(",\"channel_reason\":\"%s\"", esc_ch);
            }
        }
    }
    printf(",\"reasons\":[");
    {
        int i;
        for (i = 0; i < v->n_reasons; i++) {
            char esc[256];
            hlse_json_escape(v->reasons[i], esc, sizeof(esc));
            printf("%s\"%s\"", i > 0 ? "," : "", esc);
        }
    }
    printf("]}\n");
}

void
hlse_print_json_text(const char *text, const TextVerdict *v) {
    char esc[1024];
    char preview[256];
    const char *pat  = hlse_classify_text_attack(v);
    const char *pid  = hlse_text_pattern_id(v);   /* stable HLSE-* token */
    const char *tobj = hlse_text_objective(v);    /* NULL outside score >= 60 */
    const char *tvrf = hlse_text_verify(v);       /* NULL outside score >= 40 (P95) */
    const char *ttri = hlse_text_triage(v);       /* NULL outside score >= 60 */
    const char *tcas = hlse_text_cascade(v);      /* NULL outside score >= 60 */
    const char *exon = hlse_text_exoneration(v);  /* NULL outside [15,59] */
    char cf_buf[160] = "";
    char esc_pat[256] = "";
    char esc_tobj[512] = "";
    char esc_tvrf[512] = "";
    char esc_ttri[640] = "";
    char esc_tcas[512] = "";
    char esc_exon[512] = "";
    char esc_cf[320] = "";
    int  sig_cnt = hlse_text_confidence(v, cf_buf, sizeof(cf_buf));
    /* Truncate long text for the JSON preview */
    {
        size_t n = strlen(text);
        if (n > 120) n = 120;
        memcpy(preview, text, n);
        preview[n] = '\0';
    }
    hlse_json_escape(preview, esc, sizeof(esc));
    if (pat)        hlse_json_escape(pat,    esc_pat,  sizeof(esc_pat));
    if (tobj)       hlse_json_escape(tobj,   esc_tobj, sizeof(esc_tobj));
    if (tvrf)       hlse_json_escape(tvrf,   esc_tvrf, sizeof(esc_tvrf));
    if (ttri)       hlse_json_escape(ttri,   esc_ttri, sizeof(esc_ttri));
    if (tcas)       hlse_json_escape(tcas,   esc_tcas, sizeof(esc_tcas));
    if (exon)       hlse_json_escape(exon,   esc_exon, sizeof(esc_exon));
    if (sig_cnt > 0) hlse_json_escape(cf_buf, esc_cf,  sizeof(esc_cf));
    printf("{\"kind\":\"text\",\"hlse_version\":\"" HLSE_VERSION "\","
           "\"target\":\"%s\",\"score\":%d,\"action\":\"%s\","
           "\"severity\":%d",
           esc, v->score, hlse_text_action_for_score(v->score),
           hlse_severity_for_score(v->score));
    if (sig_cnt > 0) printf(",\"signal_count\":%d,\"confidence\":\"%s\"",
                            sig_cnt, esc_cf);
    if (v->score == 0) {
        const char *bs = hlse_blindspot_for("text");
        if (bs) {
            char esc_bs[512];
            hlse_json_escape(bs, esc_bs, sizeof(esc_bs));
            printf(",\"blind_spot\":\"%s\"", esc_bs);
        }
    }
    if (pat)  printf(",\"pattern\":\"%s\"",     esc_pat);
    if (pid)  printf(",\"pattern_id\":\"%s\"", pid);   /* stable SIEM token */
    if (tobj) printf(",\"objective\":\"%s\"",   esc_tobj);
    if (tvrf) printf(",\"verify\":\"%s\"",      esc_tvrf);
    if (ttri) printf(",\"triage\":\"%s\"",      esc_ttri);
    if (tcas) printf(",\"cascade_risk\":\"%s\"",esc_tcas);
    if (exon) printf(",\"exoneration\":\"%s\"", esc_exon);
    if (hlse_from_channel()) {
        int d   = hlse_channel_delta(hlse_from_channel());
        int eff = v->score + d; if (eff > 100) eff = 100;
        printf(",\"channel\":\"%s\",\"channel_delta\":%d,\"effective_score\":%d,"
               "\"effective_action\":\"%s\",\"effective_severity\":%d",
               hlse_from_channel(), d, eff, hlse_text_action_for_score(eff),
               hlse_severity_for_score(eff));
        {
            const char *ch_rsn = hlse_channel_reason(hlse_from_channel());
            if (ch_rsn) {
                char esc_ch[512];
                hlse_json_escape(ch_rsn, esc_ch, sizeof(esc_ch));
                printf(",\"channel_reason\":\"%s\"", esc_ch);
            }
        }
    }
    printf(",\"reasons\":[");
    {
        int i;
        for (i = 0; i < v->n_reasons; i++) {
            char r[256];
            hlse_json_escape(v->reasons[i], r, sizeof(r));
            printf("%s\"%s\"", i > 0 ? "," : "", r);
        }
    }
    printf("]}\n");
}

/* Print the per-URL human-readable advisory lines for an actionable verdict —
 * the synthesis lenses layered on top of the raw per-signal reasons:
 *   ▸ Pattern             attack-class label
 *   ⌖ Disguised char      first non-ASCII confusable codepoint
 *   ◉ Attacker's goal     objective / asset at risk
 *   → Safe destination    canonical brand domain to use instead
 *   ✓ Verify independently  high-confidence (>=60) confirmation test
 *   ⚑ If already clicked  post-click incident triage
 *   ⊕ Also change         password-reuse cascade risk (other accounts)
 *
 * Centralised so the three text output sites (stdin / `text` subcommand /
 * default auto-detect) cannot drift out of sync — every lens fires from one
 * place. `url` is the raw input (needed for confusable/host inspection); `uv`
 * is its URL verdict. Each line is conditional, so a low-score verdict prints
 * only the lenses that apply.                                                */
void
hlse_print_url_advisories(const char *url, const Verdict *uv) {
    const char *pat = hlse_classify_url_attack(uv);
    const char *vrf = hlse_verification_for(uv);
    const char *cas = hlse_cascade_risk(uv);
    char obj_buf[320];
    char safe[384]; /* 384: compound "https://A and https://B" fits in 2*128+8 */
    char conf[160];
    char asc_diff[256];
    char cf_buf[160];
    char tri_buf[512]; /* 512: compound two-step triage */
    if (pat) printf("  \xe2\x96\xb8 Pattern: %s\n", pat);
    if (hlse_confidence_for(uv, cf_buf, sizeof(cf_buf)))
        printf("  \xe2\x9a\x96 Confidence: %s\n", cf_buf);  /* ⚖ */
    if (hlse_confusable_report(url, conf, sizeof(conf)))
        printf("  \xe2\x8c\x96 Disguised char: %s\n", conf);
    if (hlse_ascii_diff(uv, asc_diff, sizeof(asc_diff)))
        printf("  \xe2\x8c\x96 ASCII lookalike: %s\n", asc_diff);
    if (hlse_compound_objective(uv, obj_buf, sizeof(obj_buf)))
        printf("  \xe2\x97\x89 Attacker's goal: %s\n", obj_buf);
    if (hlse_safe_destinations(uv, safe, sizeof(safe)))
        printf("  \xe2\x86\x92 Safe destination: %s\n", safe);
    if (vrf) printf("  \xe2\x9c\x93 Verify independently: %s\n", vrf);
    if (hlse_compound_triage(uv, tri_buf, sizeof(tri_buf)))
        printf("  \xe2\x9a\x91 If already clicked: %s\n", tri_buf);
    if (cas) printf("  \xe2\x8a\x95 Also change: %s\n", cas);  /* ⊕ */
}

/* Print the per-text human-readable advisory lines for an actionable text
 * verdict — the text counterpart of hlse_print_url_advisories(). Layers the same
 * synthesis lenses on top of the raw per-signal reasons:
 *   ▸ Pattern           social-engineering attack-class label
 *   ◉ Attacker's goal   asset at risk (score >= 60)
 *   ✓ Verify first      pre-action verification check (score >= 60)
 *   ⚖ Confidence        how many independent signal families concur
 *   ⚑ If you acted      post-response triage (score >= 60)
 *   ⊕ Also change       cascade risk — other accounts at stake (score >= 60)
 *
 * Centralised so the three text output sites (stdin / `text` subcommand /
 * default auto-detect) cannot drift out of sync — exactly the guarantee
 * hlse_print_url_advisories() gives the URL path. Like its URL sibling, this does
 * NOT print the "↺ Could be benign" exoneration or the "· <channel>" line:
 * those depend on caller-local state (channel reason) and are emitted by each
 * caller after this returns. Each line is conditional, so a low-score verdict
 * prints only the lenses that apply.                                         */
void
hlse_print_text_advisories(const TextVerdict *tv) {
    const char *tpat = hlse_classify_text_attack(tv);
    const char *tobj = hlse_text_objective(tv);
    const char *tvrf = hlse_text_verify(tv);
    const char *ttri = hlse_text_triage(tv);
    const char *tcas = hlse_text_cascade(tv);
    char tcf[160];
    if (tpat) printf("  \xe2\x96\xb8 Pattern: %s\n", tpat);
    if (tobj) printf("  \xe2\x97\x89 Attacker's goal: %s\n", tobj);
    if (tvrf) printf("  \xe2\x9c\x93 Verify first: %s\n", tvrf);
    if (hlse_text_confidence(tv, tcf, sizeof(tcf)))
        printf("  \xe2\x9a\x96 Confidence: %s\n", tcf);
    if (ttri) printf("  \xe2\x9a\x91 If you acted: %s\n", ttri);
    if (tcas) printf("  \xe2\x8a\x95 Also change: %s\n", tcas);
}

/* ─────────────────────────── stdin pipe mode ────────────────────────── */

int
hlse_stdin_mode(int json_out, int fail_threshold) {
    char line[MAX_URL];
    int  any_threat = 0;

    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r'))
            line[--n] = '\0';
        if (n == 0) continue;

        ScanResult sr = hlse_scan(line);
        if (json_out) {
            /* JSON uses specific formatters for structured output.
             * For text lines, reuse sr (not hlse_check_text alone) so
             * embedded URL extraction is honoured — same as GAP-N fix. */
            if (sr.is_url) {
                Verdict uv = hlse_check_url(line);
                hlse_print_json_url(line, &uv);
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
                hlse_print_json_text(line, &tv);
            }
        } else if (sr.score == 0) {
            /* Channel-only risk: content scored 0 but delivery channel adds prior */
            if (hlse_from_channel()) {
                int d = hlse_channel_delta(hlse_from_channel());
                if (d > 0) {
                    const char *ch_rsn = hlse_channel_reason(hlse_from_channel());
                    char db[8192];
                    printf("%-7s [%d]  %s\n", hlse_action_for_score(d), d,
                           hlse_display_copy(db, sizeof(db), line));
                    if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                    continue;
                }
            }
            {
                char canon_brand[64];
                char db[8192];
                printf("OK    %s\n", hlse_display_copy(db, sizeof(db), line));
                if (sr.is_url && hlse_canonical_confirm(line, canon_brand, sizeof(canon_brand)))
                    printf("  \xe2\x9c\x94 Canonical: confirmed authentic %s domain "
                           "(HLSE brand registry)\n", canon_brand);
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
                       hlse_display_copy(db, sizeof(db), line));
            }
            for (i = 0; i < sr.n_reasons; i++) {
                /* Amplifier lines are derived meta-labels, not independently
                 * detected facts; the ▸ Pattern line already expresses them
                 * in user-facing language. Keep them in JSON; filter here. */
                if (strncmp(sr.reasons[i], "Amplifier:", 10) == 0) continue;
                printf("  \xc2\xb7 %s\n", sr.reasons[i]);  /* · */
            }
            if (sr.is_url) {
                Verdict uv = hlse_check_url(line);
                const char *url_ex = hlse_url_exoneration(&uv);
                hlse_print_url_advisories(line, &uv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (url_ex) printf("  \xe2\x86\xba Could be benign: %s\n", url_ex);
            } else {
                TextVerdict tv;
                const char *tex;
                int ti;
                memset(&tv, 0, sizeof(tv));
                tv.score = sr.score;
                tv.n_reasons = sr.n_reasons < (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]))
                               ? sr.n_reasons
                               : (int)(sizeof(tv.reasons)/sizeof(tv.reasons[0]));
                for (ti = 0; ti < tv.n_reasons; ti++)
                    snprintf(tv.reasons[ti], sizeof(tv.reasons[0]),
                             "%s", sr.reasons[ti]);
                tex  = hlse_text_exoneration(&tv);
                hlse_print_text_advisories(&tv);
                if (ch_rsn) printf("  \xc2\xb7 %s\n", ch_rsn);
                if (tex) printf("  \xe2\x86\xba Could be benign: %s\n", tex);
            }
        }
        /* Gate uses effective score (raw + channel boost) so that e.g.
         * --from sms raises exit 0 → exit 1 when boost crosses the threshold. */
        {
            int eff_gate = sr.score;
            if (hlse_from_channel()) {
                int d = hlse_channel_delta(hlse_from_channel());
                eff_gate += d; if (eff_gate > 100) eff_gate = 100;
            }
            if (eff_gate >= fail_threshold) any_threat = 1;
        }
    }
    return any_threat ? 1 : 0;
}

/* ─────────────────────────── main ─────────────────────────────────── */

void
hlse_print_usage(const char *prog) {
    fprintf(stderr,
        "HLSE %s — Human-Layer Security Engine\n"
        "\n"
        "Scanning:\n"
        "  %s <url>                    Scan a URL for phishing\n"
        "  %s text \"<message>\"         Scan text for scam patterns\n"
        "  %s <any input>              Auto-detect URL or text\n"
        "\n"
        "Protection:\n"
        "  %s protect <path>           Ransomware / SMB / canary check\n"
        "  %s protect /dev/sda --mbr   MBR/GPT integrity (needs root)\n"
        "  %s esp [path]               UEFI/ESP bootkit-string scan\n"
        "  %s scan <directory>          Recursive secret + file scan (CI/CD)\n"
        "  %s scan <dir> --git-history  Scan every commit ever made, not just the working tree\n"
        "  %s secret \"<text>\"          Scan text/stdin for leaked credentials\n"
        "  %s email \"<headers>\"        Email-header forensics (SPF/DKIM, BEC)\n"
        "  %s clipboard <copied> <pasted>  Crypto address-swap (clipper) check\n"
        "  %s package <name> [eco]     Package typosquat check\n"
        "  %s package --manifest <f>   Scan every dep in requirements.txt / package.json\n"
        "  %s paste \"<command>\"        Pastejacking detection\n"
        "  %s network                  ARP / DNS / hosts safety check\n"
        "  %s file <path>              File masquerade detection\n"
        "  %s audit                    System hardening audit\n"
        "\n"
        "Options:\n"
        "  %s --json <subcommand>      JSON output\n"
        "  %s --sarif scan <dir>       SARIF 2.1.0 output (GitHub code scanning)\n"
        "  %s -q | --quiet             Exit code only (CI/CD mode)\n"
        "  %s --fail-on <tier>         Exit-1 gate: log|alert|block|isolate|0-100 (default block)\n"
        "  %s --from <channel>         Delivery channel: email|sms|dm|qr|manual (boosts URL & text score)\n"
        "  %s --baseline <file>        scan: suppress findings whose fingerprint is listed (CI adoption)\n"
        "  %s --fingerprints scan <d>  scan: emit one fingerprint per finding (generate a baseline)\n"
        "  %s --patterns <file>        Load custom org-specific secret patterns (no rebuild needed)\n"
        "  %s --config <file>          Load flag defaults from a key=value file\n"
        "  %s --syslog                 Push findings to syslog (LOG_AUTHPRIV)\n"
        "  %s --log-file <file>        Append one JSONL record per finding (0600)\n"
        "  %s -- <input>               End of options: everything after is data, not flags\n"
        "  %s --stdin [--json]         Pipe mode (one input per line)\n"
        "  %s --self-test              Built-in tests\n"
        "  %s --benchmark              Corpus benchmark\n"
        "  %s --list-patterns [--json] List stable pattern_id tokens (SIEM/SOAR registry)\n"
        "  %s --version | -V           Version\n"
        "  %s -h | --help              Show this help\n"
        "\n"
        "Baseline workflow (brownfield CI adoption):\n"
        "  %s --fingerprints scan . > .hlse-baseline   # accept today's findings\n"
        "  %s --baseline .hlse-baseline scan .          # only NEW findings fail\n"
        "  Inline suppression: put `hlse:allow` on a line to skip its findings.\n"
        "\n"
        "Custom patterns (%s --patterns <file>), one directive per line:\n"
        "  SECRET <prefix> <min_suffix> <charset> <score> <label...>\n"
        "    charset is alnum|alnum_dash|hex|alpha|digit.\n"
        "    Example: SECRET ACME_KEY_ 20 alnum 85 ACME Internal API Key\n"
        "  BRAND <name> <owned_domain1>[,<owned_domain2>...]\n"
        "    Protects your org's name/executives in email BEC display-name checks.\n"
        "    Example: BRAND acmecorp acmecorp.com,acme-corp.com\n"
        "\n"
        "Exit code: 0 = safe, 1 = threat (>= --fail-on, default block/60), 2 = usage error\n",
        HLSE_VERSION,
        prog, prog, prog,                                /* scanning: 3 */
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, /* protection: 14 */
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, /* options: 18 */
        prog, prog, prog); /* baseline workflow: 2 + custom patterns: 1 */
}

/* Read all of stdin into buf (NUL-terminated, truncated to cap-1 bytes).
 *
 * Perspective 105 (P1-2): the previous version truncated silently at cap-1,
 * so a secret past the buffer end read as "clean" (exit 0) — a false
 * negative demonstrated through the shipped pre-commit hook. Now: if input
 * exceeds the buffer, drain the rest of stdin so a pipe writer does not
 * block on a full pipe, and print a clear warning to stderr naming how many
 * bytes were dropped so the caller knows the result is not authoritative.
 * The buffers were also enlarged to 1 MiB (see the --stdin call sites),
 * matching the shipped hook's own 1 MB file-size guard, so the demonstrated
 * gap is closed outright and the warning is a backstop for larger inputs. */
size_t
hlse_read_stdin_all(char *buf, size_t cap) {
    size_t total = 0, r;
    if (cap == 0) return 0;
    while (total < cap - 1 &&
           (r = fread(buf + total, 1, cap - 1 - total, stdin)) > 0)
        total += r;
    buf[total] = '\0';
    if (total == cap - 1) {
        /* Buffer filled exactly — there may be more input we cannot hold.
         * Drain and count the overflow so the warning is precise, and so a
         * writer piping into us does not block on a full pipe. */
        size_t dropped = 0;
        char sink[8192];
        while ((r = fread(sink, 1, sizeof(sink), stdin)) > 0) dropped += r;
        if (dropped > 0) {
            fprintf(stderr,
                    "hlse: warning: stdin exceeded %zu-byte buffer; %zu byte(s) "
                    "dropped \xe2\x80\x94 scan of the truncated tail was skipped, "
                    "so a clean result is NOT authoritative for the full input\n",
                    cap - 1, dropped);
        }
    }
    return total;
}



/* Remove `n` argv elements starting at index `i`, keeping BOTH argc and the
 * end-of-options boundary in step.
 *
 * The boundary decrement is the part that is easy to miss and expensive to get
 * wrong: every removal slides the operands left by n, so a boundary left
 * unchanged admits n operands into the flag-scanning range. Data written after
 * `--` then gets parsed as options — which is exactly the bug the `--` marker
 * exists to prevent. Doing the bookkeeping in one place is the only way this
 * invariant stays true; it previously had to be restated at eleven call sites,
 * and was wrong at all of them. */
void
hlse_argv_remove(char **argv, int *argc, int *argc_flags, int i, int n) {
    int j;
    for (j = i; j + n < *argc; j++) argv[j] = argv[j + n];
    *argc -= n;
    if (i < *argc_flags) {
        *argc_flags -= n;
        if (*argc_flags < i) *argc_flags = i;
    }
}
