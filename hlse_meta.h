/* hlse_meta.h — report-metadata helpers shared by the scan driver,
 * git-history scan, and emitters. Extracted verbatim from hlse_core.c
 * (split increment 6). */
#ifndef HLSE_META_H
#define HLSE_META_H

#include <stddef.h>
#include "hlse_file.h"

/* Blast-radius asset classes for a set of leaked secret types. */
unsigned    hlse_asset_class_of(const char *type);
int         hlse_asset_mask_describe(unsigned mask, char *out, size_t outsz);
const char *hlse_scan_immediate_action(unsigned mask, int nclasses);

/* Stable machine-readable pattern ids / advisory labels for file and
 * secret verdicts — the HLSE-FILE- and HLSE-SECRET- token ladders used
 * by SARIF and JSON emitters. */
const char *hlse_file_pattern_id(const char *fpat);
const char *hlse_file_verdict_pattern_id(const FileVerdict *fv);
const char *hlse_file_classify_pattern(const FileVerdict *fv);
const char *hlse_file_masquerade_objective(void);
const char *hlse_file_masquerade_verify(void);
const char *hlse_secret_pattern_id(const char *ftype);

#endif /* HLSE_META_H */
