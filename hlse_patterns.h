/* hlse_patterns.h — custom pattern config file (--patterns).
 *
 * Extracted verbatim from hlse_core.c (split increment 5). The built-in
 * credential patterns and brand list are compiled in and cannot name an
 * organization's internal token formats or protect its own
 * name/executives without a rebuild — a real commercial-adoption blocker.
 * `--patterns <file>` loads a small, non-regex config format and registers
 * each entry via hlse_register_custom_secret_pattern() /
 * hlse_register_custom_brand() (hlse_secrets.c), which hlse_scan_secrets()
 * and hlse_check_email_headers() then check using the exact same logic as
 * their built-in tables. Purely additive — the benchmark corpus never
 * passes --patterns, so F1 is unaffected.
 *
 * File format (one directive per line; '#' comments and blank lines
 * ignored):
 *   SECRET <prefix> <min_suffix> <charset> <score> <label...>
 *   BRAND  <name> <owned_domain1>[,<owned_domain2>...]
 * charset is one of: alnum | alnum_dash | hex | alpha | digit
 * SECRET's label is free text (may contain spaces) to end of line.
 * BRAND's owned-domains list has no spaces (comma-separated, up to 4).
 *
 * Example:
 *   # ACME Corp internal API keys and impersonation targets
 *   SECRET ACME_KEY_ 20 alnum 85 ACME Internal API Key
 *   BRAND acmecorp acmecorp.com,acme-corp.com
 */
#ifndef HLSE_PATTERNS_H
#define HLSE_PATTERNS_H

/* Load and register custom patterns/brands from `path`. Returns 0 on
 * success (individual malformed lines are skipped with a warning), -1
 * when the file cannot be opened. */
int hlse_patterns_load(const char *path);

#endif /* HLSE_PATTERNS_H */
