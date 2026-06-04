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
