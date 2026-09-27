/* hlse_manifest.h — manifest dependency-file parsers (package --manifest).
 * Extracted verbatim from hlse_core.c (split increment 6); pure
 * orchestration helpers around hlse_check_package(). */
#ifndef HLSE_MANIFEST_H
#define HLSE_MANIFEST_H

#include <stddef.h>

/* Infer package ecosystem from a manifest filename (basename match).
 * Returns a canonical eco string or NULL if unrecognised. */
const char *hlse_manifest_ecosystem(const char *path);

/* Extract a pip requirement name from a requirements.txt-style line. */
int hlse_manifest_name_pip(const char *line, char *out, size_t outcap);

/* Extract the next dependency name from a package.json-style stream. */
int hlse_manifest_name_npm(const char **cursor, int *in_deps,
                         char *out, size_t outcap);

#define HLSE_HOOK_REASON_LEN 192

/* Scan one line of a package.json for npm lifecycle-hook risk (the
 * 2025 self-propagating-worm pattern: preinstall/install/postinstall/
 * prepare hooks that harvest the process environment, fetch-and-pipe
 * remote code, or run opaque decoded payloads). Returns the number of
 * findings; out[i] holds the display reason and scores[i] its score. */
size_t hlse_manifest_hook_flags(const char *line,
                                char out[][HLSE_HOOK_REASON_LEN],
                                int scores[], size_t outcap);

#endif /* HLSE_MANIFEST_H */

/* Lockfile poisoning: extract the host of a resolved-style URL on a
 * manifest line (resolved/resolution/tarball, JSON or yarn/pnpm style).
 * Returns 1 with the lowercased host in out, or 0 when absent. */
int hlse_manifest_resolved_host(const char *line, char *out, size_t outcap);

/* Returns 1 when the resolved URL's host is outside the package
 * registries/git hosts a lockfile may legitimately reference. */
int hlse_manifest_resolved_suspicious(const char *host);

/* Extract the host of a VCS/direct-URL dependency source on a manifest
 * line (git+/hg+/svn+/bzr+ URLs, PEP 440 `name @ url`, archive tails).
 * Returns 1 with the lowercased host in out, or 0 when absent. Check the
 * host with hlse_manifest_resolved_suspicious. */
int hlse_manifest_vcs_host(const char *line, char *out, size_t outcap);

/* Extract the target host of a pip resolver-redirect flag
 * (--index-url/--extra-index-url/--find-links/--trusted-host).
 * Returns 1 with the lowercased host in out, or 0 when absent. */
int hlse_manifest_index_host(const char *line, char *out, size_t outcap);

/* Extract an npm: alias target name on a manifest line — the package
 * actually installed under the declared key. Returns 1 with the target
 * (scope kept, version stripped) or 0. */
int hlse_manifest_alias_target(const char *line, char *out, size_t outcap);

/* Extract the quoted manifest key preceding position pos
 * ("key": value). Returns 1 with the key in out, or 0. */
int hlse_manifest_key_before(const char *line, const char *pos,
                             char *out, size_t outcap);

/* Extract the registry-override target host (npmrc registry= /
 * @scope:registry= / disturl=, cargo registry=). Returns 1 with the
 * host in out, or 0. */
int hlse_manifest_registry_host(const char *line, char *out, size_t outcap);

/* go.mod replace directive target host (=> host/path), 0 for local
 * path replacements. */
int hlse_manifest_replace_host(const char *line, char *out, size_t outcap);

/* go.mod replace directive with a local-path target (=> ./ ../ /).
 * Returns 1 when the replacement is a filesystem path. */
int hlse_manifest_replace_local(const char *line);

/* Cargo.toml [patch.*] / [replace] table header. Returns 1 on a
 * redirection table header line. */
int hlse_manifest_cargo_patch(const char *line);

/* nuget.config <add … value="url"> package-source host. Returns 1
 * with the lowercased host in out, or 0. */
int hlse_manifest_nuget_source(const char *line, char *out, size_t outcap);

/* Package.swift .package(url:)/Package.resolved "location" fetch
 * host. Returns 1 with the lowercased host in out, or 0. */
int hlse_manifest_swift_url(const char *line, char *out, size_t outcap);

/* Gemfile source "url" / source: "url" target host. Returns 1 with
 * host, or 0. */
int hlse_manifest_source_host(const char *line, char *out, size_t outcap);

/* Dockerfile FROM registry host ('host/' segment when it carries a
 * '.' or ':'). Returns 1 with host, or 0 for hub short names. */
int hlse_manifest_docker_from(const char *line, char *out, size_t outcap);

/* Dockerfile RUN/CMD/ENTRYPOINT fetch|pipe|interpreter (curl|sh). */
int hlse_manifest_docker_pipeshell(const char *line);

/* Dockerfile ADD http(s):// remote fetch. */
int hlse_manifest_docker_add_remote(const char *line);

/* devcontainer.json lifecycle/mount risk and .vscode folderOpen/
 * binary-path risk — return score + reason, 0 when clean. */
/* 1 when a line's value looks executable (pipe/fetch/interpreter/
 * opaque-encode) — shared by the exec-config family checks. */
int hlse_manifest_execish(const char *line);

int hlse_manifest_devc_risk(const char *line, char *reason,
                            size_t rcap);
int hlse_manifest_vsc_risk(const char *line, char *reason,
                           size_t rcap);

/* docker-compose sandbox-strength check — returns score + reason,
 * 0 when the line is clean. */
int hlse_manifest_docker_compose(const char *line, char *reason,
                                 size_t rcap);

/* .pre-commit local-hook and .gitlab-ci.yml include/script risk —
 * return score + reason, 0 when clean. */
int hlse_manifest_pck_risk(const char *line, char *reason,
                           size_t rcap);
int hlse_manifest_glci_risk(const char *line, char *reason,
                            size_t rcap);

/* composer.json autoload-files / lifecycle-script / repository
 * redirection risk — return score + reason, 0 when clean. */
int hlse_manifest_comp_risk(const char *line, char *reason,
                            size_t rcap);

/* Platform-automation config risk (gitpod/netlify/vercel/Procfile/
 * app.json/Jenkinsfile/tsconfig) — return score + reason, 0 clean. */
int hlse_manifest_plat_risk(const char *line, char *reason,
                            size_t rcap);

/* Distro package build-script risk (PKGBUILD, APKBUILD,
 * pkgname.install, *.ebuild, *.spec) — fetch-exec lines 55,
 * install-hook scriptlets 45, 0 clean. */
int hlse_manifest_pkbb_risk(const char *line, char *reason,
                            size_t rcap);

/* GitHub Actions 'uses: owner/repo@ref' — fills ref (empty when
 * unpinned). Returns 1 on a uses line, 0 otherwise. */
int hlse_manifest_gha_uses(const char *line, char *ref, size_t refcap);

/* 'pull_request_target' trigger — runs fork code with repo secrets. */
int hlse_manifest_gha_prt(const char *line);

/* Returns the canonical untrusted ${{ }} context path found on the
 * line (github.event.issue.title …), NULL when none. */
const char *hlse_manifest_gha_inj(const char *line);

/* 1 = block-scalar run/script key (run: |), 2 = inline run/script
 * value to scan directly, 0 = not a script key. */
int hlse_manifest_gha_scriptkey(const char *line);

/* MCP server-config risk — per line; returns score and fills reason,
 * 0 when clean. Covers pipe-to-shell installs, bare-shell command,
 * fetch-execute command, privileged container, plaintext remote
 * endpoint, and opaque -c/-enc argument strings. */
int hlse_manifest_mcp_risk(const char *line, char *reason, size_t rcap);

/* .cargo/config.toml build-toolchain override key (rustc-wrapper,
 * runner, linker, pre/post-build) or NULL. */
const char *hlse_manifest_cargo_toolchain(const char *line);
