/* hlse_selftest.h — built-in self-test and corpus benchmark entry points.
 * CLI-only (--self-test / --benchmark); the functions exercise the public
 * API and print PASS/FAIL lines to stdout. Each returns 0 on all-pass. */
#ifndef HLSE_SELFTEST_H
#define HLSE_SELFTEST_H

int hlse_url_self_test(void);   /* URL phishing corpus cases   */
int hlse_text_self_test(void);  /* text scam corpus cases      */
int hlse_benchmark(void);       /* F1 / FP corpus benchmark    */

#endif /* HLSE_SELFTEST_H */
