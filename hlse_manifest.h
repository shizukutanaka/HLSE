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

#endif /* HLSE_MANIFEST_H */
