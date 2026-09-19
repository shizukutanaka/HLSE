/* hlse_githistory.c — `scan <dir> --git-history`: stream `git log --all -p`
 * and scan only added lines for secrets. Extracted verbatim from
 * hlse_core.c (split increment 6).
 *
 * Spawned via fork()+execlp(), never popen()/system(): the directory
 * path is a discrete argv element, never shell-interpreted. `git log`
 * performs no network I/O — the zero-network guarantee holds. */
#include "hlse_githistory.h"
#include "hlse_baseline.h"
#include "hlse_sarif.h"
#include "hlse_secrets.h"
#include "hlse_util.h"
#include "hlse_core.h"
#include "hlse_meta.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

/* ── Git history scanning (Perspective 111, roadmap P0-2) ──────────────────
 * `scan <dir> --git-history` finds secrets ANYWHERE in the repo's commit
 * history, not just the current working tree — the primary use case for
 * commercial secret scanners (gitleaks/trufflehog): a credential that was
 * committed and later deleted is still readable by anyone who clones the
 * repo, and a working-tree-only scan never sees it.
 *
 * Implementation: stream `git log --all -p` (every commit, unified diff,
 * every ref) and scan only ADDED lines ('+' lines, excluding the '+++'
 * file-header marker) — the lines that introduced a secret at the moment it
 * entered history. This needs one git subprocess for the whole history
 * (not one per blob), keeping it fast even on repos with thousands of
 * commits.
 *
 * Spawned via fork()+execlp(), never popen()/system(): the directory path
 * is passed as a discrete argv element to git, so it is never interpreted
 * by a shell and no combination of characters in `dir` can inject a command.
 * `git log` performs no network I/O (only fetch/pull/clone do), so this
 * preserves HLSE's zero-network-calls guarantee — verified by the existing
 * CI privacy tripwire, which traces socket-family syscalls, not process
 * spawns. */
static FILE *
git_history_open(const char *dir, pid_t *out_pid) {
    int pipefd[2];
    pid_t pid;
    if (pipe(pipefd) != 0) return NULL;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }
    if (pid == 0) {
        /* Child: redirect stdout to the pipe, stderr to /dev/null (git
         * prints progress/warnings we don't want mixed into our stream). */
        int devnull;
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execlp("git", "git", "-C", dir, "log", "--all", "-p", "--no-color",
               "--full-history", (char *)NULL);
        _exit(127); /* execlp failed — git not installed / not found in PATH */
    }
    close(pipefd[1]);
    *out_pid = pid;
    return fdopen(pipefd[0], "r");
}

/* Scan every commit in `root`'s history for secrets. Returns the process
 * exit code (0 = clean, 1 = threat, 2 = usage/environment error). */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
int
hlse_scan_git_history(const char *root, int json_out, int sarif_out,
                         int emit_fingerprints, int fail_threshold) {
    FILE *gp;
    pid_t pid;
    char line[8192];
    char commit[41] = "";
    char curpath[4096] = "";
    int commits_seen = 0, threats = 0, gate_hits = 0, max_score = 0;
    unsigned asset_mask = 0;
    int child_status;

    gp = git_history_open(root, &pid);
    if (!gp) {
        fprintf(stderr, "Error: cannot start 'git log' for '%s': %s\n",
                root, strerror(errno));
        return 2;
    }

    while (fgets(line, sizeof(line), gp)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';

        if (strncmp(line, "commit ", 7) == 0) {
            snprintf(commit, sizeof(commit), "%.40s", line + 7);
            commits_seen++;
            continue;
        }
        if (strncmp(line, "+++ ", 4) == 0) {
            const char *p = line + 4;
            if (strncmp(p, "b/", 2) == 0) p += 2;
            if (strcmp(p, "/dev/null") != 0) {
                /* Explicit bounded copy (not snprintf(dst, sizeof(dst), "%s",
                 * p)) — `p` derives from `line` (larger than `curpath`), and
                 * -Wformat-truncation cannot see that silent truncation here
                 * is harmless (curpath is a display label, not a real path
                 * used for I/O), so make the bound explicit instead of
                 * suppressing the warning. */
                size_t plen = strlen(p);
                if (plen >= sizeof(curpath)) plen = sizeof(curpath) - 1;
                memcpy(curpath, p, plen);
                curpath[plen] = '\0';
            } else {
                curpath[0] = '\0'; /* file was deleted in this commit */
            }
            continue;
        }
        /* An added line: starts with '+' but is not the "+++ " file header
         * and is not the empty "+" (context-only artifact). */
        if (line[0] == '+' && strncmp(line, "+++", 3) != 0 && n > 1) {
            const char *content = line + 1;
            SecretVerdict sv = hlse_scan_secrets(content);
            if (sv.score >= 40) {
                const char *spid = sv.n_findings > 0
                    ? hlse_secret_pattern_id(sv.findings[0].type)
                    : "HLSE-SECRET-GENERIC";
                const char *sdesc = sv.n_findings > 0
                    ? sv.findings[0].description : "";
                char loc[4200];
                snprintf(loc, sizeof(loc), "%s@%.7s",
                         curpath[0] ? curpath : "(unknown path)", commit);
                /* Baseline/allowlist suppression reuses the same fingerprint
                 * mechanism as the working-tree scan (P0-1); the "line" for
                 * inline hlse:allow purposes is this diff line itself. */
                if (hlse_scan_suppress(loc, spid, sdesc, content, emit_fingerprints))
                    continue;
                threats++;
                if (sv.score > max_score) max_score = sv.score;
                if (sv.score >= fail_threshold) gate_hits++;
                {
                    int ai;
                    for (ai = 0; ai < sv.n_findings; ai++)
                        asset_mask |= hlse_asset_class_of(sv.findings[ai].type);
                }
                if (sarif_out) {
                    char msg[512] = {0};
                    int i;
                    for (i = 0; i < sv.n_findings; i++) {
                        size_t l = strlen(msg);
                        snprintf(msg + l, sizeof(msg) - l, "%s%s",
                                 i ? "; " : "", sv.findings[i].description);
                    }
                    snprintf(msg + strlen(msg), sizeof(msg) - strlen(msg),
                             " (commit %.7s)", commit);
                    hlse_sarif_add(curpath[0] ? curpath : "(unknown path)", 1,
                              "secret", spid, msg[0] ? msg : "secret", sv.score);
                } else if (json_out) {
                    int i;
                    char ep[4096], ed[512];
                    hlse_json_escape(curpath, ep, sizeof(ep));
                    printf("{\"kind\":\"secret\",\"hlse_version\":\"" HLSE_VERSION
                           "\",\"path\":\"%s\",\"commit\":\"%s\",\"score\":%d,"
                           "\"action\":\"%s\",\"severity\":%d,\"findings\":[",
                           ep, commit, sv.score, hlse_action_for_score(sv.score),
                           hlse_severity_for_score(sv.score));
                    for (i = 0; i < sv.n_findings; i++) {
                        hlse_json_escape(sv.findings[i].description, ed, sizeof(ed));
                        printf("%s{\"type\":\"%s\",\"description\":\"%s\"}",
                               i ? "," : "", sv.findings[i].type, ed);
                    }
                    printf("],\"pattern_id\":\"%s\"}\n", spid);
                } else {
                    int i;
                    char db[8192];
                    printf("%-7s [%d]  %s@%.7s\n",
                           hlse_action_for_score(sv.score), sv.score,
                           hlse_display_copy(db, sizeof(db),
                                   curpath[0] ? curpath : "(unknown path)"),
                           commit);
                    for (i = 0; i < sv.n_findings; i++)
                        printf("  \xc2\xb7 %s\n", sv.findings[i].description);
                }
            }
        }
    }
    fclose(gp);
    /* Reap the child and distinguish real failure from a clean scan. A
     * non-zero exit with zero commits seen means `git log` itself failed
     * (not a repo, corrupt repo, etc.) — report it as a usage error rather
     * than silently printing "OK, 0 commits scanned", which would read as
     * "scanned and clean" instead of "did not scan anything at all". */
    if (waitpid(pid, &child_status, 0) == pid &&
        WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0) {
        int code = WEXITSTATUS(child_status);
        if (code == 127) {
            fprintf(stderr, "Error: 'git' not found in PATH \xe2\x80\x94 "
                    "--git-history requires the git binary\n");
        } else if (commits_seen == 0) {
            fprintf(stderr, "Error: '%s' is not a git repository (git log "
                    "exited %d) \xe2\x80\x94 --git-history requires a git "
                    "repository\n", root, code);
        } else {
            /* git produced partial output before failing; still report what
             * was found, but note the scan may be incomplete. */
            fprintf(stderr, "hlse: warning: 'git log' exited %d after %d "
                    "commit(s) \xe2\x80\x94 history scan may be incomplete\n",
                    code, commits_seen);
        }
        if (commits_seen == 0) return 2;
    }

    if (sarif_out) {
        hlse_sarif_emit(HLSE_VERSION);
    } else if (json_out) {
        char ep[4096], classes[256];
        int nclasses = hlse_asset_mask_describe(asset_mask, classes, sizeof(classes));
        hlse_json_escape(root, ep, sizeof(ep));
        printf("{\"kind\":\"scan_summary\",\"hlse_version\":\"" HLSE_VERSION "\","
               "\"target\":\"%s\",\"mode\":\"git-history\","
               "\"commits_scanned\":%d,\"threats\":%d,"
               "\"max_severity\":%d,\"gate_hits\":%d,\"fail_threshold\":%d,"
               "\"asset_classes\":%d,\"blast_radius\":\"%s\"}\n",
               ep, commits_seen, threats, hlse_severity_for_score(max_score),
               gate_hits, fail_threshold, nclasses, classes);
    } else if (threats == 0) {
        char db[8192];
        printf("OK    %s (%d commits scanned, 0 secrets found in history)\n",
               hlse_display_copy(db, sizeof(db), root), commits_seen);
    } else {
        char db[8192];
        printf("\n%d secret(s) found across %d commits in %s history\n",
               threats, commits_seen,
               hlse_display_copy(db, sizeof(db), root));
        printf("\xe2\x86\x92 Immediate action: rotate every credential found above "
               "\xe2\x80\x94 they are readable in every existing clone regardless "
               "of the current working tree, and deleting the file does not "
               "remove them from history (use git filter-repo or BFG)\n");
    }
    return gate_hits > 0 ? 1 : 0;
}
#pragma GCC diagnostic pop
