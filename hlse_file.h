/*
 * hlse_file.h — File Masquerade Detection API
 *
 * Detects files that pretend to be something they're not:
 *   - Double extensions (invoice.pdf.exe)
 *   - Magic byte mismatch (PE header in a .pdf)
 *   - Right-to-left override (hides real extension)
 *   - Office macro indicators
 *   - Social engineering lure filenames
 */

#ifndef HLSE_FILE_H
#define HLSE_FILE_H

#ifdef __cplusplus
extern "C" {
#endif

#define HLSE_FILE_MAX_REASONS 8

typedef struct {
    int  score;     /* 0..100 */
    int  n_reasons;
    char reasons[HLSE_FILE_MAX_REASONS][256];
    /* Nonzero when the file's bytes were actually read, so the magic-byte
     * checks (F2/F3) could run. Zero for hlse_check_filename(), for a file
     * that does not exist, and for one that exists but could not be opened
     * (permissions, a non-regular file). In that last case the checks are
     * skipped silently and the verdict rests on the NAME alone, which is a
     * far weaker claim than a full inspection — callers must not present a
     * score of 0 as "this file is clean" without saying so.               */
    int  content_read;
} FileVerdict;

/* Full check: reads file from disk (magic bytes, macros, etc.)
 * Read-only. Never modifies or executes the file.                     */
FileVerdict hlse_check_file(const char *filepath);

/* Filename-only check: no disk access. Useful for screening email
 * attachments BEFORE downloading.                                      */
FileVerdict hlse_check_filename(const char *filename);

#ifdef __cplusplus
}
#endif

#endif /* HLSE_FILE_H */
