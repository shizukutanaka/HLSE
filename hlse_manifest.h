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
