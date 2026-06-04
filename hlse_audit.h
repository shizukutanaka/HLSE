/*
 * hlse_audit.h — System Hardening Quick-Audit API
 *
 * Read-only checks for common misconfigurations:
 *   A1. SSH config (root login, password auth, key permissions)
 *   A2. File permissions (world-readable secrets, .env exposure)
 *   A3. DNS/hosts poisoning (banking domains redirected)
 *   A4. Cron persistence (suspicious scheduled tasks)
 */

#ifndef HLSE_AUDIT_H
#define HLSE_AUDIT_H

#ifdef __cplusplus
extern "C" {
#endif

#define HLSE_AUDIT_MAX_FINDINGS 24

typedef enum {
    AUDIT_PASS     = 0,
    AUDIT_INFO     = 1,
    AUDIT_LOW      = 2,
    AUDIT_MEDIUM   = 3,
    AUDIT_HIGH     = 4,
    AUDIT_CRITICAL = 5
} AuditSeverity;

typedef struct {
    AuditSeverity severity;
    char          description[256];
} AuditFinding;

typedef struct {
    int          score;     /* 0..100 */
    int          n_findings;
    AuditFinding findings[HLSE_AUDIT_MAX_FINDINGS];
} AuditVerdict;

/* Individual module audits */
AuditVerdict hlse_audit_ssh(void);
AuditVerdict hlse_audit_permissions(void);
AuditVerdict hlse_audit_dns(void);
AuditVerdict hlse_audit_cron(void);

/* Run all audits and combine results */
AuditVerdict hlse_audit_all(void);

#ifdef __cplusplus
}
#endif

#endif /* HLSE_AUDIT_H */
