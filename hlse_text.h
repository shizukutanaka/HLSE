/* hlse_text.h — public API for text scam detection */
#ifndef HLSE_TEXT_H
#define HLSE_TEXT_H

#include <stddef.h>   /* size_t */

typedef struct {
    int  score;          /* 0..100 */
    int  n_reasons;
    char reasons[16][192];
} TextVerdict;

/* Analyse `raw_text` for phishing/scam patterns.
 * Returns a verdict; if score < 15, all fields are zeroed.   */
TextVerdict hlse_check_text(const char *raw_text);

/* Detect invisible instruction carriers aimed at AI agents (indirect prompt
 * injection): Unicode Tags-block payloads outside legitimate emoji tag
 * sequences, and long zero-width runs used as a hidden data channel.
 *
 * Returns 0 when clean, else a score (70 Tags payload, 40 zero-width run) and
 * writes an explanatory line into `reason` when it is non-NULL. Structural
 * only — an injection written in ordinary visible prose is out of scope.
 *
 * Exposed because file/directory scanning needs it too: the realistic path is
 * an agent reading a poisoned document or skill file, not a human pasting the
 * text in. Must be given the RAW bytes — normalization strips these code
 * points and would erase the evidence. */
int hlse_check_invisible_carriers(const char *text, char *reason,
                                  size_t reason_size);

/* Map a numeric score to an action label string. */
const char *hlse_text_action_for_score(int score);

#endif /* HLSE_TEXT_H */
