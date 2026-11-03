/* hlse_cli.h -- entry points shared between the CLI translation units
 * (hlse_cli.c, hlse_selftest.c, hlse_patterns.c, hlse_githistory.c).
 * Executable-only; never part of the library. */
#ifndef HLSE_CLI_H
#define HLSE_CLI_H

#include <stddef.h>       /* size_t */
#include "hlse_file.h"    /* FileVerdict */

int cli_self_test(void);   /* --self-test : returns 0 when every case passes */
int cli_benchmark(void);   /* --benchmark : returns 0 when acceptance holds  */
int cli_list_patterns(int json_out); /* --list-patterns : always returns 0   */
int cli_scan_git_history(const char *root, int json_out, int sarif_out,
                         int fail_threshold);
                         /* scan --git-history : process exit code          */

/* Shared helpers, defined in hlse_cli.c / hlse_patterns.c, reused across
 * the CLI translation units so each ladder exists exactly once. */
unsigned    asset_class_of(const char *type);
int         asset_mask_describe(unsigned mask, char *out, size_t outsz);
void        sarif_add(const char *path, int line, const char *rule,
                      const char *pattern_id, const char *message, int score);
void        sarif_emit(const char *tool_version);
int         hlse_scan_suppress(const char *relpath, const char *pattern_id,
                               const char *match, const char *line);
const char *file_pattern_id(const char *fpat);
const char *file_verdict_pattern_id(const FileVerdict *fv);
const char *file_classify_pattern(const FileVerdict *fv);
const char *secret_pattern_id(const char *ftype);

#endif /* HLSE_CLI_H */
