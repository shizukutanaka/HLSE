/* hlse_emit.h — CLI output layer (see hlse_emit.c). */
#ifndef HLSE_EMIT_H
#define HLSE_EMIT_H

#include <stddef.h>
#include "hlse_core.h"
#include "hlse_text.h"

const char *hlse_audit_remediation_for(const char *desc);
const char *hlse_secret_objective_for(const char *type);
const char *hlse_secret_finding_caveat(const char *type);
void hlse_secret_pattern_label(const char *ftype, char *buf, size_t buflen);
const char *hlse_secret_verify_text(void);
const char *hlse_secret_triage_text(void);
const char *hlse_secret_cascade_text(void);
const char *hlse_protect_pattern_text(void);
const char *hlse_protect_objective_text(void);
const char *hlse_protect_verify_text(void);
const char *hlse_protect_triage_text(void);
const char *hlse_protect_cascade_text(void);
const char *hlse_net_pattern_text(void);
const char *hlse_network_objective_text(void);
const char *hlse_network_verify_text(void);
const char *hlse_network_triage_text(void);
const char *hlse_network_cascade_text(void);
const char *hlse_package_pattern_text(void);
const char *hlse_package_objective_text(void);
const char *hlse_package_verify_text(void);
const char *hlse_package_triage_text(void);
const char *hlse_package_cascade_text(void);
const char *hlse_esp_pattern_text(void);
const char *hlse_esp_objective_text(void);
const char *hlse_esp_verify_text(void);
const char *hlse_esp_triage_text(void);
const char *hlse_esp_cascade_text(void);
const char *hlse_clipboard_pattern_text(void);
const char *hlse_clipboard_objective_text(void);
const char *hlse_clipboard_verify_text(void);
const char *hlse_clipboard_triage_text(void);
const char *hlse_clipboard_cascade_text(void);
void hlse_print_json_url(const char *url, const Verdict *v);
void hlse_print_json_text(const char *text, const TextVerdict *v);
void hlse_print_url_advisories(const char *url, const Verdict *uv);
void hlse_print_text_advisories(const TextVerdict *tv);

#endif /* HLSE_EMIT_H */
int    hlse_stdin_mode(int json_out, int fail_threshold);
void   hlse_print_usage(const char *prog);
size_t hlse_read_stdin_all(char *buf, size_t cap);
void   hlse_argv_remove(char **argv, int *argc, int *argc_flags, int i, int n);
