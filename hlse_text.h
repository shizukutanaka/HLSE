/* hlse_text.h — public API for text scam detection */
#ifndef HLSE_TEXT_H
#define HLSE_TEXT_H

typedef struct {
    int  score;          /* 0..100 */
    int  n_reasons;
    char reasons[16][192];
} TextVerdict;

/* Analyse `raw_text` for phishing/scam patterns.
 * Returns a verdict; if score < 15, all fields are zeroed.   */
TextVerdict hlse_check_text(const char *raw_text);

/* Map a numeric score to an action label string. */
const char *hlse_text_action_for_score(int score);

#endif /* HLSE_TEXT_H */
