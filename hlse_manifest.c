/* hlse_manifest.c — manifest dependency-file parsers (package --manifest).
 * Extracted verbatim from hlse_core.c (split increment 6); pure
 * orchestration helpers around hlse_check_package(). */
#include "hlse_manifest.h"
#include "hlse_util.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

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
        strcmp(b, "package-lock.json") == 0 ||
        strcmp(b, "yarn.lock") == 0 ||
        strcmp(b, "pnpm-lock.yaml") == 0) return "npm";
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
            } else if (mh_ci(val, "setup_bun.js") ||
                       mh_ci(val, "bun_environment.js") ||
                       mh_ci(val, "node setup_bun")) {
                snprintf(out[n], HLSE_HOOK_REASON_LEN,
                    "%s: runs 'setup_bun.js'/'bun_environment.js' — "
                    "Shai-Hulud 2.0 (Nov 2025 second wave) loader name", hb);
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

/* Lockfile poisoning: a `resolved`/`resolution`/`tarball` field whose URL
 * points off-registry redirects the install to an attacker host — the
 * dependency-substitution vector documented by Liran Tal / Snyk (2021) and
 * still routine in poisoned PR lockfiles. Extracts the lowercased host of
 * the first resolved-style URL on the line; returns 0 when there is none. */
int
hlse_manifest_resolved_host(const char *line, char *out, size_t outcap) {
    static const char *const KEYS[] = {
        "\"resolved\"", "\"resolution\"", "\"tarball\"",
        "resolved \"", "resolved '", "resolved:",
        "resolution:", "tarball:",
        NULL
    };
    int k;
    if (out && outcap) out[0] = '\0';
    if (!line || !out || outcap == 0) return 0;
    for (k = 0; KEYS[k]; k++) {
        const char *kp = strstr(line, KEYS[k]);
        const char *u;
        size_t n = 0;
        if (!kp) continue;
        u = strstr(kp + strlen(KEYS[k]), "https://");
        if (!u) u = strstr(kp + strlen(KEYS[k]), "http://");
        if (!u) continue;
        u += (strncmp(u, "https://", 8) == 0) ? 8 : 7;
        while (*u && *u != '/' && *u != '"' && *u != '\'' &&
               *u != ' ' && *u != '\t' && *u != ')' && *u != '>' &&
               n + 1 < outcap)
            out[n++] = (char)tolower((unsigned char)*u++);
        out[n] = '\0';
        {   /* strip userinfo (user[:pass]@host) then any :port */
            char *at = strrchr(out, '@');
            if (at) memmove(out, at + 1, strlen(at + 1) + 1);
            {
                char *c = strchr(out, ':');
                if (c) *c = '\0';
            }
        }
        if (out[0]) return 1;
    }
    return 0;
}

/* Registry hosts a lockfile's resolved URL may legitimately point at.
 * Subdomains match (x.github.com); lookalike suffixes do not
 * (evilgithub.com). */
static const char *const REGISTRY_HOSTS[] = {
    "registry.npmjs.org", "registry.yarnpkg.com", "npmjs.com",
    "github.com", "codeload.github.com", "api.github.com",
    "gitlab.com", "bitbucket.org", "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    NULL
};

int
hlse_manifest_resolved_suspicious(const char *host) {
    int i;
    if (!host || !host[0]) return 0;
    for (i = 0; REGISTRY_HOSTS[i]; i++) {
        const char *h = REGISTRY_HOSTS[i];
        size_t hl = strlen(h), n = strlen(host);
        if (n == hl && strcmp(host, h) == 0) return 0;
        if (n > hl + 1 && host[n - hl - 1] == '.' &&
            strcmp(host + n - hl, h) == 0) return 0;
    }
    return 1;
}

/* VCS / direct-URL dependency source: pip accepts
 * `git+https://host/repo.git#egg=pkg`, `pkg @ https://host/pkg.tar.gz`;
 * npm accepts `"dep": "git+https://host/x.git"` or a bare tarball URL as
 * the version field. The dependency name (#egg= / key) says nothing
 * about where the code actually comes from — an off-forge source is
 * dependency substitution the typosquat check cannot see (a VCS URL has
 * no registry pinning the name). Returns the host on such a reference.
 * `resolved`-style fields are skipped: the resolved check owns them.  */
int
hlse_manifest_vcs_host(const char *line, char *out, size_t outcap) {
    static const char *const RESOLVED_KEYS[] = {
        "\"resolved\"", "resolved ", "resolved:",
        "\"resolution\"", "resolution:",
        "\"tarball\"", "tarball:",
        NULL
    };
    static const char *const VCS_MARKERS[] = {
        "git+", "hg+", "svn+", "bzr+", NULL
    };
    static const char *const DIRECT_EXTS[] = {
        ".git", ".tgz", ".tar.gz", ".zip", ".whl", ".tar",
        NULL
    };
    const char *u = NULL, *scheme_end;
    size_t n = 0;
    int i;

    if (out && outcap) out[0] = '\0';
    if (!line || !out || outcap == 0) return 0;
    for (i = 0; RESOLVED_KEYS[i]; i++)
        if (strstr(line, RESOLVED_KEYS[i])) return 0;

    /* a vcs marker prefix makes any following scheme a VCS reference */
    for (i = 0; VCS_MARKERS[i]; i++) {
        const char *m = strstr(line, VCS_MARKERS[i]);
        if (m) {
            const char *sep = strstr(m + strlen(VCS_MARKERS[i]), "://");
            if (sep) { u = sep; break; }
        }
    }
    if (!u) {
        /* bare scheme: keep it if the URL is a direct artifact reference
         * (PEP 440 `name @ url`, or a recognisable archive/.git tail) */
        const char *s = strstr(line, "://");
        if (!s) return 0;
        {
            int direct = strstr(line, " @ ") != NULL ||
                         strstr(line, "\" @ \"") != NULL ||
                         strstr(line, "@https") != NULL ||
                         strstr(line, "@ http") != NULL;
            for (i = 0; DIRECT_EXTS[i] && !direct; i++)
                if (strstr(line, DIRECT_EXTS[i])) direct = 1;
            if (!direct) return 0;
            u = s;
        }
    }
    scheme_end = u + 3;
    while (*scheme_end && *scheme_end != '/' && *scheme_end != '"' &&
           *scheme_end != '\'' && *scheme_end != ' ' &&
           *scheme_end != '\t' && *scheme_end != '#' &&
           *scheme_end != ')' && *scheme_end != '>' &&
           n + 1 < outcap)
        out[n++] = (char)tolower((unsigned char)*scheme_end++);
    out[n] = '\0';
    {   /* strip userinfo (user[:pass]@host) then any :port */
        char *at = strrchr(out, '@');
        if (at) memmove(out, at + 1, strlen(at + 1) + 1);
        { char *c = strchr(out, ':'); if (c) *c = '\0'; }
    }
    if (!out[0]) return 0;
    /* reject a 'host' that is really a path fragment */
    if (!strchr(out, '.')) return 0;
    return 1;
}

/* pip resolver-redirect flags: --index-url/--extra-index-url change
 * where every dependency resolves from; --find-links adds an alternate
 * download location; --trusted-host disables TLS verification for a
 * host. Extracts the flag's target host (URL or bare host:port).      */
int
hlse_manifest_index_host(const char *line, char *out, size_t outcap) {
    static const char *const FLAGS[] = {
        "--index-url", "--extra-index-url", "--find-links",
        "--trusted-host", NULL
    };
    const char *v = NULL;
    size_t n = 0;
    int i;
    if (out && outcap) out[0] = '\0';
    if (!line || !out || outcap == 0) return 0;
    for (i = 0; FLAGS[i]; i++) {
        const char *f = strstr(line, FLAGS[i]);
        if (!f) continue;
        v = f + strlen(FLAGS[i]);
        while (*v == ' ' || *v == '\t' || *v == '=') v++;
        break;
    }
    if (!v || !*v) return 0;
    /* skip an inline comment start or a dangling flag */
    if (*v == '#') return 0;
    if (strncmp(v, "https://", 8) == 0) v += 8;
    else if (strncmp(v, "http://", 7) == 0) v += 7;
    /* bare host (e.g. --trusted-host) or scheme already skipped */
    while (*v && *v != '/' && *v != '"' && *v != '\'' &&
           *v != ' ' && *v != '\t' && *v != '#' &&
           *v != ')' && *v != '>' && n + 1 < outcap)
        out[n++] = (char)tolower((unsigned char)*v++);
    out[n] = '\0';
    {   /* strip userinfo then :port */
        char *at = strrchr(out, '@');
        if (at) memmove(out, at + 1, strlen(at + 1) + 1);
        { char *c = strchr(out, ':'); if (c) *c = '\0'; }
    }
    if (!out[0] || !strchr(out, '.')) return 0;
    return 1;
}
