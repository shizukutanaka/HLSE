/* hlse_core_internal.h -- engine internals shared between hlse_core.c and
 * hlse_cli.c. NOT part of the public API (that is hlse_core.h): nothing here is
 * stable, and library users must not include it. */
#ifndef HLSE_CORE_INTERNAL_H
#define HLSE_CORE_INTERNAL_H

#include "hlse_core.h"   /* Verdict */

#define MAX_URL    2048
#define MAX_HOST    256
#define MAX_PATH   1024

/* The URL engine entry point the CLI's per-line and scan paths call directly
 * (hlse_scan wraps it with text handling). */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
Verdict check_url(const char *raw_url);

#endif /* HLSE_CORE_INTERNAL_H */
