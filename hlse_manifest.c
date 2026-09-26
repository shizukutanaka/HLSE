/* hlse_manifest.c — manifest dependency-file parsers (package --manifest).
 * Extracted verbatim from hlse_core.c (split increment 6); pure
 * orchestration helpers around hlse_check_package(). */
#include "hlse_manifest.h"
#include <stdio.h>
#include <string.h>

/* ── Manifest scanning (Perspective 108, roadmap P1-8) ─────────────────────
 * The single-name `package <name>` check is impractical for real dependency
 * files. `package --manifest <file>` parses a manifest and runs the existing
 * hlse_check_package() over every declared dependency. Ecosystem is inferred
 * from the filename or given explicitly. Pure orchestration of the existing
 * detector — no scoring change, F1 unchanged. */

/* Infer package ecosystem from a manifest filename (basename match). Returns
 * a canonical eco string or NULL if unrecognised. */
const char *
hlse_manifest_ecosystem(const char *path) {
    const char *b = strrchr(path, '/');
    b = b ? b + 1 : path;
    if (strncmp(b, "requirements", 12) == 0 || strcmp(b, "Pipfile") == 0)
        return "pip";
    if (strcmp(b, "package.json") == 0 ||
        strcmp(b, "package-lock.json") == 0) return "npm";
    if (strcmp(b, "Cargo.toml") == 0 || strcmp(b, "Cargo.lock") == 0)
        return "cargo";
    if (strcmp(b, "go.mod") == 0) return "go";
    if (strcmp(b, "Gemfile") == 0 || strcmp(b, "Gemfile.lock") == 0)
        return "gem";
    return NULL;
}

/* Extract the leading pip/requirements-style package name from a line into
 * out (name = leading run of [A-Za-z0-9._-], stopping at a version operator
 * or extras bracket). Returns 1 if a name was found, else 0. Skips blank
 * lines, comments, and pip options (-r/-e/--). */
int
hlse_manifest_name_pip(const char *line, char *out, size_t outcap) {
    const char *s = line;
    size_t n = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '\0' || *s == '\n' || *s == '#' || *s == '-') return 0;
    while (*s && n + 1 < outcap &&
           ((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') ||
            (*s >= '0' && *s <= '9') || *s == '.' || *s == '_' || *s == '-'))
        out[n++] = *s++;
    out[n] = '\0';
    return n > 0;
}

/* Extract the next npm dependency name at/after *cursor, tracking whether we
 * are inside a *dependencies object via *in_deps. Handles both the canonical
 * one-dep-per-line layout and the compact single-line object form, and can be
 * called repeatedly on the same line: it advances *cursor past what it
 * consumed. A dependency entry is  "name" : "version"  inside a dependencies
 * object. Returns 1 and fills out when a name is extracted, 0 when the current
 * text is exhausted. */
int
hlse_manifest_name_npm(const char **cursor, int *in_deps, char *out, size_t outcap) {
    const char *p = *cursor;
    for (;;) {
        if (!*in_deps) {
            /* Look for a dependencies-section keyword on this text. */
            const char *k = NULL, *cands[4]; int ci, best = -1;
            cands[0] = strstr(p, "\"dependencies\"");
            cands[1] = strstr(p, "\"devDependencies\"");
            cands[2] = strstr(p, "\"peerDependencies\"");
            cands[3] = strstr(p, "\"optionalDependencies\"");
            for (ci = 0; ci < 4; ci++)
                if (cands[ci] && (best < 0 || cands[ci] < cands[best])) best = ci;
            if (best < 0) { *cursor = p + strlen(p); return 0; }
            k = strchr(cands[best], '{');
            if (!k) { *cursor = p + strlen(p); return 0; }
            *in_deps = 1;
            p = k + 1;
            continue;
        }
        /* In a deps object: the next '}' closes it; the next '"' before it
         * starts a "name": "ver" entry. */
        {
            const char *close = strchr(p, '}');
            const char *q = strchr(p, '"');
            size_t n = 0;
            const char *r;
            if (!q || (close && close < q)) {
                if (close) { *in_deps = 0; p = close + 1; continue; }
                *cursor = p + strlen(p); return 0;
            }
            r = q + 1;
            while (*r && *r != '"' && n + 1 < outcap) out[n++] = *r++;
            out[n] = '\0';
            if (*r != '"') { *cursor = p + strlen(p); return 0; }
            r++;                                  /* past closing quote */
            while (*r == ' ' || *r == '\t') r++;
            if (*r != ':') { p = r; continue; }   /* not a key — keep scanning */
            *cursor = r + 1;
            if (n > 0) return 1;
        }
    }
}


/* ── npm lifecycle-hook risk ─────────────────────────────────────────────
 * 2025's self-propagating npm worms (Shai-Hulud and the s1ngularity/Nx
 * fallout) execute from install hooks — "postinstall": "node bundle.js"
 * is the canonical Shai-Hulud loader. Lifecycle commands that read the
 * process environment AND open egress, decode+run opaque payloads, or
 * fetch|pipe|execute remote code are near-absent from legitimate
 * packages. Line-scoped: hook entries are `"key": "cmd"` on one line.  */

static int
mh_ci(const char *hay, const char *needle) {
    /* case-insensitive substring */
    for (; *hay; hay++) {
        const char *h = hay, *n = needle;
        while (*h && *n && (*h | 0x20) == (*n | 0x20)) { h++; n++; }
        if (!*n) return 1;
    }
    return 0;
}

static const char *const HOOK_KEYS[] = {
    "\"preinstall\"", "\"install\"", "\"postinstall\"",
    "\"prepare\"", "\"prepack\"", "\"postpack\"",
    "\"prepublish\"", "\"prepublishOnly\"", "\"postpublish\"",
    NULL
};

size_t
hlse_manifest_hook_flags(const char *line, char out[][HLSE_HOOK_REASON_LEN],
                         int scores[], size_t outcap) {
    size_t n = 0;
    int k;
    for (k = 0; HOOK_KEYS[k] && n < outcap; k++) {
        const char *kp = strstr(line, HOOK_KEYS[k]);
        const char *val;
        if (!kp) continue;
        kp += strlen(HOOK_KEYS[k]);
        while (*kp == ' ' || *kp == '\t') kp++;
        if (*kp != ':') continue;
        val = kp + 1;                    /* command text after the colon */
        {
            const char *hook = HOOK_KEYS[k];
            char hb[64];
            size_t hl = strlen(hook);
            if (hl >= sizeof(hb)) hl = sizeof(hb) - 1;
            memcpy(hb, hook + 1, hl - 2);  /* strip quotes */
            hb[hl - 2] = '\0';

            /* Hard IoCs — straight worm/campaign artefacts. */
            if (mh_ci(val, "node bundle.js")) {
                snprintf(out[n], HLSE_HOOK_REASON_LEN,
                    "%s: runs 'node bundle.js' — canonical Shai-Hulud "
                    "loader name", hb);
                scores[n++] = 75;
            } else if (mh_ci(val, "webhook.site") ||
                       mh_ci(val, "webhook-test")) {
                snprintf(out[n], HLSE_HOOK_REASON_LEN,
                    "%s: posts to a webhook collector — Shai-Hulud "
                    "exfil endpoint", hb);
                scores[n++] = 75;
            } else if (mh_ci(val, "trufflehog")) {
                snprintf(out[n], HLSE_HOOK_REASON_LEN,
                    "%s: invokes trufflehog — secret-harvesting tool "
                    "abused by npm worms", hb);
                scores[n++] = 70;
            } else {
                /* Compound tells. */
                int env = mh_ci(val, "process.env") || mh_ci(val, "printenv")
                          || mh_ci(val, "/proc/self/environ");
                int egress = mh_ci(val, "curl") || mh_ci(val, "wget")
                             || mh_ci(val, "fetch(") || mh_ci(val, "axios")
                             || mh_ci(val, "http:") || mh_ci(val, "https:")
                             || mh_ci(val, "xmlhttprequest")
                             || mh_ci(val, "node:http")
                             || mh_ci(val, "node:https");
                int pipe_sh = (mh_ci(val, "|sh") || mh_ci(val, "| sh")
                               || mh_ci(val, "|bash") || mh_ci(val, "| bash")
                               || mh_ci(val, "|node") || mh_ci(val, "| node"));
                int credfile = mh_ci(val, ".aws/credentials")
                               || mh_ci(val, "/.aws/") || mh_ci(val, "id_rsa")
                               || mh_ci(val, "/.ssh/") || mh_ci(val, ".npmrc")
                               || (mh_ci(val, "gcloud") && mh_ci(val, "cred"));
                int opaque = mh_ci(val, "eval(") || mh_ci(val, "node -e")
                             || mh_ci(val, "node --eval") || mh_ci(val, "atob(")
                             || mh_ci(val, "buffer.from")
                             || mh_ci(val, "frombase64string")
                             || mh_ci(val, "base64 -d")
                             || mh_ci(val, "base64 --decode");

                if (env && egress) {
                    snprintf(out[n], HLSE_HOOK_REASON_LEN,
                        "%s: reads process.env and opens network egress — "
                        "install-hook secret harvesting", hb);
                    scores[n++] = 65;
                } else if (egress && pipe_sh) {
                    snprintf(out[n], HLSE_HOOK_REASON_LEN,
                        "%s: fetches and pipes remote code to an "
                        "interpreter", hb);
                    scores[n++] = 65;
                } else if (credfile && egress) {
                    snprintf(out[n], HLSE_HOOK_REASON_LEN,
                        "%s: touches credential files and opens network "
                        "egress", hb);
                    scores[n++] = 65;
                } else if (env && credfile) {
                    snprintf(out[n], HLSE_HOOK_REASON_LEN,
                        "%s: reads process.env and credential files", hb);
                    scores[n++] = 55;
                } else if (opaque) {
                    snprintf(out[n], HLSE_HOOK_REASON_LEN,
                        "%s: decodes/evaluates an opaque payload "
                        "(eval/atob/base64/node -e)", hb);
                    scores[n++] = 50;
                }
            }
        }
    }
    return n;
}
