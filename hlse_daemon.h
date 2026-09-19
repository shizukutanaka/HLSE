/* hlse_daemon.h — hlsed resident file-integrity monitor.
 *
 * Poll-based FIM: every `scan-interval` seconds the daemon walks each
 * `watch` directory and re-scans files whose (path, mtime, size) tuple
 * is not in the in-memory dedup table, running the existing detectors
 * (file masquerade + secret scan) on the delta only — incremental
 * scanning, no event API, no new platform dependency, works rootless
 * on Linux and macOS alike.
 *
 * All state is in-memory and dies with the process (SECURITY.md scoped
 * carve-out). Signals: SIGTERM/SIGINT stop cleanly; SIGHUP reloads the
 * config file (watch list, interval, thresholds, alert sinks). */
#ifndef HLSE_DAEMON_H
#define HLSE_DAEMON_H

/* Load `config_path`, validate it (>=1 watch dir, all readable), install
 * signal handlers + PID-file lock, and run the sweep loop until SIGTERM/
 * SIGINT. Returns a process exit code: 0 clean stop, 2 usage/config error,
 * 1 runtime failure (e.g. another instance holds the PID lock). */
int hlse_daemon_run(const char *config_path);

#endif /* HLSE_DAEMON_H */
