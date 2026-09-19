/* hlse_sarif.h — SARIF 2.1.0 accumulation + emission (GitHub
 * code-scanning compatible). Extracted verbatim from hlse_core.c
 * (split increment 6).
 *
 * Streaming callers feed each finding via hlse_sarif_add(); the SARIF
 * document is emitted once at the end via hlse_sarif_emit(). Findings
 * beyond SARIF_MAX_FINDINGS are dropped with a truncation note. */
#ifndef HLSE_SARIF_H
#define HLSE_SARIF_H

void hlse_sarif_add(const char *path, int line, const char *rule,
                    const char *pattern_id, const char *message, int score);
void hlse_sarif_emit(const char *tool_version);

#endif /* HLSE_SARIF_H */
