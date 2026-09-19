/* hlse_githistory.h — `scan <dir> --git-history`: stream `git log --all -p`
 * and scan added lines for secrets that entered history even if since
 * deleted. Extracted verbatim from hlse_core.c (split increment 6). */
#ifndef HLSE_GITHISTORY_H
#define HLSE_GITHISTORY_H

/* Returns the gate code: 0 clean, 1 if any finding >= fail_threshold,
 * 2 on runtime error. */
int hlse_scan_git_history(const char *root, int json_out, int sarif_out,
                          int emit_fingerprints, int fail_threshold);

#endif /* HLSE_GITHISTORY_H */
