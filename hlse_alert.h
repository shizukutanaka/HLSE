/*
 * hlse_alert.h — Push alert sink: syslog and/or an append-only JSONL log.
 *
 * A pull-model scanner returns a verdict and exits; a resident/daemon (and a
 * CLI operator who wants findings recorded) needs verdicts PUSHED to a durable
 * channel. This module writes one JSON object per finding to syslog
 * (LOG_AUTHPRIV) and/or a 0600 append-only file. Dependency-free (libc only),
 * zero network. Sinks are opt-in via hlse_alert_init(); if neither is enabled,
 * hlse_alert_emit() is a no-op so call sites need no guard.
 */
#ifndef HLSE_ALERT_H
#define HLSE_ALERT_H

#include "hlse_core.h"   /* Verdict, HLSE_VERSION */
#include "hlse_text.h"   /* TextVerdict */

#ifdef __cplusplus
extern "C" {
#endif

/* Enable sinks. use_syslog != 0 -> openlog("hlse", LOG_PID, LOG_AUTHPRIV).
 * log_file_path != NULL -> open O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW, mode
 * 0600 (findings may carry secret fragments; 0600 is the confidentiality
 * control, so a failed fchmod is treated as a hard error). Both may be on.
 * Returns 0 on success, -1 if a requested log file could not be opened as a
 * regular file with 0600 perms (caller should treat like --baseline/--patterns
 * failure). Idempotent: a second call while already initialized is a no-op. */
int hlse_alert_init(int use_syslog, const char *log_file_path);

/* Emit one verdict to every enabled sink (no-op if none). severity is
 * hlse_severity_for_score(score) (0..4); reasons is n_reasons NUL-terminated
 * strings (may be NULL when n_reasons == 0). */
void hlse_alert_emit(const char *kind, int score, int severity,
                     const char *target, const char **reasons, int n_reasons);

/* Convenience wrappers for the two verdict types the default CLI path builds. */
void hlse_alert_emit_url(const char *url, const Verdict *v);
void hlse_alert_emit_text(const char *text, const TextVerdict *v);

/* Idempotent teardown (closelog / close fd). Safe if init was never called.
 * Register with atexit(hlse_alert_shutdown) after a successful init. */
void hlse_alert_shutdown(void);

#ifdef __cplusplus
}
#endif
#endif /* HLSE_ALERT_H */
