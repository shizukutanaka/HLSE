/* hlse_cli.h -- entry points shared between the CLI translation units
 * (hlse_cli.c, hlse_selftest.c, hlse_patterns.c). Executable-only; never
 * part of the library. */
#ifndef HLSE_CLI_H
#define HLSE_CLI_H

int cli_self_test(void);   /* --self-test : returns 0 when every case passes */
int cli_benchmark(void);   /* --benchmark : returns 0 when acceptance holds  */
int cli_list_patterns(int json_out); /* --list-patterns : always returns 0   */

#endif /* HLSE_CLI_H */
