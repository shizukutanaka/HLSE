/*
 * tests/hlse_protect_tests.c
 *
 * Tests for ransomware, network drive, SMB, and MBR protection modules.
 *
 * Build: gcc -O2 -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE \
 *            -o tests/protect_tests tests/hlse_protect_tests.c \
 *            hlse_protect.c -I. -lm
 * Run:   ./tests/protect_tests
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <utime.h>
#include <time.h>
#include "../hlse_protect.h"

static int total = 0, passed = 0, failed = 0;

#define TEST(name) do { total++; printf("  %-55s", name); fflush(stdout); } while(0)
#define PASS()     do { passed++; printf("PASS\n"); } while(0)
#define FAIL(msg)  do { failed++; printf("FAIL — %s\n", msg); } while(0)

/* Create a temp directory with controlled files for testing. */
static char tmpdir[256];

static void
setup_tmpdir(void) {
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/hlse_test_%d", getpid());
    mkdir(tmpdir, 0755);
}

static void
cleanup_tmpdir(void) {
    /* Safe recursive delete without system() shell injection risk.
     * Simple approach: unlink files then rmdir. Not recursive into
     * subdirs (our tests don't create them).                          */
    DIR *d = opendir(tmpdir);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", tmpdir, ent->d_name);
            unlink(path);
        }
        closedir(d);
    }
    rmdir(tmpdir);
}

static void
create_file(const char *name, const char *content, size_t len) {
    char path[512];
    FILE *fp;
    snprintf(path, sizeof(path), "%s/%s", tmpdir, name);
    fp = fopen(path, "wb");
    if (fp) {
        fwrite(content, 1, len, fp);
        fclose(fp);
    }
}

static void
create_random_file(const char *name, size_t len) {
    char path[512];
    FILE *fp;
    size_t i;
    snprintf(path, sizeof(path), "%s/%s", tmpdir, name);
    fp = fopen(path, "wb");
    if (fp) {
        for (i = 0; i < len; i++) {
            /* High entropy pseudo-random data */
            unsigned char c = (unsigned char)((i * 1103515245 + 12345) >> 8);
            fputc(c, fp);
        }
        fclose(fp);
    }
}

/* High-entropy file that carries a known compression magic prefix.
 * Simulates a legitimate .gz/.zip/.jpg the entropy heuristic must
 * NOT flag as ransomware-encrypted.                                  */
static void
create_compressed_file(const char *name, const unsigned char *magic,
                       size_t magic_len, size_t len) {
    char path[512];
    FILE *fp;
    size_t i;
    snprintf(path, sizeof(path), "%s/%s", tmpdir, name);
    fp = fopen(path, "wb");
    if (fp) {
        fwrite(magic, 1, magic_len, fp);
        for (i = magic_len; i < len; i++) {
            unsigned char c = (unsigned char)((i * 1103515245 + 12345) >> 8);
            fputc(c, fp);
        }
        fclose(fp);
    }
}

/* ─── Ransomware tests ────────────────────────────────────────────────── */

static void
test_ransomware_clean_directory(void) {
    setup_tmpdir();
    create_file("document.txt", "Hello world, this is a normal document.\n", 40);
    create_file("report.docx", "PK\x03\x04 fake docx header content here.\n", 40);
    create_file("photo.jpg", "\xff\xd8\xff\xe0 JFIF header placeholder data\n", 40);

    TEST("Ransomware: clean directory → SAFE");
    ProtectionVerdict v = hlse_ransomware_check_directory(tmpdir);
    if (v.score < 40) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

static void
test_ransomware_note_detection(void) {
    setup_tmpdir();
    create_file("document.txt", "Normal file\n", 12);
    create_file("readme.txt", "All your files have been encrypted.\n", 36);

    TEST("Ransomware: ransom note detected");
    ProtectionVerdict v = hlse_ransomware_check_directory(tmpdir);
    if (v.score >= 30) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

static void
test_ransomware_extension_mutation(void) {
    setup_tmpdir();
    int i;
    for (i = 0; i < 10; i++) {
        char name[64];
        snprintf(name, sizeof(name), "file%d.locked", i);
        create_file(name, "encrypted data placeholder\n", 27);
    }

    TEST("Ransomware: mass .locked extension");
    ProtectionVerdict v = hlse_ransomware_check_directory(tmpdir);
    if (v.score >= 30) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

static void
test_ransomware_entropy_spike(void) {
    setup_tmpdir();
    /* Create 10 high-entropy files simulating encryption */
    int i;
    for (i = 0; i < 10; i++) {
        char name[64];
        snprintf(name, sizeof(name), "data_%d.bin", i);
        create_random_file(name, 4096);
    }

    TEST("Ransomware: entropy spike (many high-entropy files)");
    ProtectionVerdict v = hlse_ransomware_check_directory(tmpdir);
    if (v.score >= 25) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

static void
test_ransomware_compressed_not_flagged(void) {
    setup_tmpdir();
    /* A directory full of legitimate high-entropy compressed files
     * (gzip/zip/jpeg) must NOT trigger a ransomware entropy alert.
     * This is the classic false positive the literature warns about. */
    static const unsigned char GZIP[]  = { 0x1F, 0x8B };
    static const unsigned char ZIP[]   = { 0x50, 0x4B, 0x03, 0x04 };
    static const unsigned char JPEG[]  = { 0xFF, 0xD8, 0xFF, 0xE0 };
    static const unsigned char RAR[]   = { 0x52, 0x61, 0x72, 0x21 };
    static const unsigned char SZ[]    = { 0x37, 0x7A, 0xBC, 0xAF };
    static const unsigned char PNG[]   = { 0x89, 0x50, 0x4E, 0x47 };
    static const unsigned char MP4[]   = { 0x00, 0x00, 0x00, 0x18,
                                           0x66, 0x74, 0x79, 0x70 };
    static const unsigned char PDF[]   = { 0x25, 0x50, 0x44, 0x46 };
    static const unsigned char XZ[]    = { 0xFD, 0x37, 0x7A, 0x58 };
    static const unsigned char BZ2[]   = { 0x42, 0x5A, 0x68 };
    static const unsigned char ZSTD[]  = { 0x28, 0xB5, 0x2F, 0xFD };
    int i;
    for (i = 0; i < 2; i++) {
        char name[64];
        snprintf(name, sizeof(name), "archive_%d.gz", i);
        create_compressed_file(name, GZIP, sizeof(GZIP), 8192);
        snprintf(name, sizeof(name), "backup_%d.zip", i);
        create_compressed_file(name, ZIP, sizeof(ZIP), 8192);
        snprintf(name, sizeof(name), "photo_%d.jpg", i);
        create_compressed_file(name, JPEG, sizeof(JPEG), 8192);
        snprintf(name, sizeof(name), "data_%d.rar", i);
        create_compressed_file(name, RAR, sizeof(RAR), 8192);
        snprintf(name, sizeof(name), "files_%d.7z", i);
        create_compressed_file(name, SZ, sizeof(SZ), 8192);
        snprintf(name, sizeof(name), "image_%d.png", i);
        create_compressed_file(name, PNG, sizeof(PNG), 8192);
        snprintf(name, sizeof(name), "video_%d.mp4", i);
        create_compressed_file(name, MP4, sizeof(MP4), 8192);
        snprintf(name, sizeof(name), "doc_%d.pdf", i);
        create_compressed_file(name, PDF, sizeof(PDF), 8192);
        snprintf(name, sizeof(name), "log_%d.xz", i);
        create_compressed_file(name, XZ, sizeof(XZ), 8192);
        snprintf(name, sizeof(name), "old_%d.bz2", i);
        create_compressed_file(name, BZ2, sizeof(BZ2), 8192);
        snprintf(name, sizeof(name), "new_%d.zst", i);
        create_compressed_file(name, ZSTD, sizeof(ZSTD), 8192);
    }

    TEST("Ransomware: all compressed/media formats NOT flagged");
    ProtectionVerdict v = hlse_ransomware_check_directory(tmpdir);
    if (v.score < 25) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "false positive score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

static void
test_ransomware_shadow_deletion_api(void) {
    /* The shadow-deletion check is an API a daemon calls; the reference
     * implementation returns a clean verdict when no such command is
     * observed. Verify it runs safely and reports no false positive. */
    TEST("Ransomware: shadow-deletion API returns clean by default");
    ProtectionVerdict v = hlse_ransomware_check_shadow_deletion();
    if (v.score == 0 && v.module == HLSE_PROTECT_RANSOMWARE) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
}

static void
test_ransomware_compound(void) {
    setup_tmpdir();
    /* Ransom note + encrypted extensions + high entropy = BLOCK */
    create_file("HOW_TO_DECRYPT.txt", "Send 1 BTC to recover\n", 22);
    int i;
    for (i = 0; i < 8; i++) {
        char name[64];
        snprintf(name, sizeof(name), "important_%d.encrypted", i);
        create_random_file(name, 4096);
    }

    TEST("Ransomware: compound (note + ext + entropy) → BLOCK");
    ProtectionVerdict v = hlse_ransomware_check_directory(tmpdir);
    if (v.score >= 60) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

/* ─── Network drive tests ─────────────────────────────────────────────── */

static void
test_netdrive_mounts(void) {
    TEST("Network drive: /proc/mounts readable");
    ProtectionVerdict v = hlse_netdrive_check_mounts();
    /* Should not crash; score depends on actual system mounts */
    if (v.score <= 100) { PASS(); }
    else { FAIL("invalid score"); }
}

static void
test_netdrive_path_clean(void) {
    setup_tmpdir();
    create_file("normal.txt", "Normal file content on share\n", 29);

    TEST("Network drive: clean path → low score");
    ProtectionVerdict v = hlse_netdrive_check_path(tmpdir);
    if (v.score < 60) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

/* ─── SMB tests ───────────────────────────────────────────────────────── */

static void
test_smb_canary_untouched(void) {
    setup_tmpdir();
    create_file(".canary_hlse_do_not_delete", "canary\n", 7);

    /* Explicitly set the canary's atime to NOW so the test is
     * deterministic regardless of filesystem mount options
     * (relatime/noatime can otherwise leave atime stale). The detector
     * fires when the canary was accessed within the last 5 minutes. */
    {
        char canpath[512];
        struct utimbuf tb;
        time_t now = time(NULL);
        snprintf(canpath, sizeof(canpath), "%s/.canary_hlse_do_not_delete",
                 tmpdir);
        tb.actime = now;
        tb.modtime = now - 3600;  /* mtime older, atime recent */
        utime(canpath, &tb);
    }

    TEST("SMB: canary detection works (fires on recent access)");
    ProtectionVerdict v = hlse_smb_check_canary(tmpdir);
    if (v.score >= 30 && v.score <= 100) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

static void
test_smb_log_clean(void) {
    setup_tmpdir();
    char logpath[512];
    snprintf(logpath, sizeof(logpath), "%s/smbd.log", tmpdir);
    FILE *fp = fopen(logpath, "w");
    if (fp) {
        fprintf(fp, "client connected\n");
        fprintf(fp, "open file report.pdf\n");
        fprintf(fp, "close file report.pdf\n");
        fclose(fp);
    }

    TEST("SMB: clean log → low score");
    ProtectionVerdict v = hlse_smb_check_log(logpath);
    if (v.score < 40) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

static void
test_smb_log_attack(void) {
    setup_tmpdir();
    char logpath[512];
    snprintf(logpath, sizeof(logpath), "%s/smbd_attack.log", tmpdir);
    FILE *fp = fopen(logpath, "w");
    if (fp) {
        int i;
        for (i = 0; i < 200; i++)
            fprintf(fp, "connect from 10.0.0.%d\n", i % 256);
        for (i = 0; i < 1500; i++)
            fprintf(fp, "open file%d.docx\n", i);
        for (i = 0; i < 100; i++)
            fprintf(fp, "rename file%d.docx file%d.locked\n", i, i);
        fclose(fp);
    }

    TEST("SMB: attack log (flood+enum+rename) → BLOCK");
    ProtectionVerdict v = hlse_smb_check_log(logpath);
    if (v.score >= 60) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

/* ─── MBR tests ───────────────────────────────────────────────────────── */

static void
test_mbr_valid(void) {
    setup_tmpdir();
    char devpath[512];
    snprintf(devpath, sizeof(devpath), "%s/fake_mbr", tmpdir);

    /* Create a fake valid MBR */
    unsigned char mbr[512];
    memset(mbr, 0, sizeof(mbr));
    mbr[0] = 0xEB;     /* JMP short */
    mbr[1] = 0x5A;
    mbr[2] = 0x90;     /* NOP */
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    FILE *fp = fopen(devpath, "wb");
    if (fp) { fwrite(mbr, 1, 512, fp); fclose(fp); }

    TEST("MBR: valid signature + JMP → SAFE");
    ProtectionVerdict v = hlse_mbr_verify(devpath);
    if (v.score < 40) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

static void
test_mbr_ransom_note(void) {
    setup_tmpdir();
    char devpath[512];
    snprintf(devpath, sizeof(devpath), "%s/petya_mbr", tmpdir);

    /* MBR locker with a ransom note embedded in the boot sector — the
     * Petya/NotPetya pattern. Should be flagged ISOLATE. */
    unsigned char mbr[512];
    memset(mbr, 0, sizeof(mbr));
    mbr[0] = 0xFA;  /* CLI — not a JMP, suspicious */
    {
        const char *note = "Send 1 bitcoin to decrypt your locked files";
        memcpy(mbr + 200, note, strlen(note));
    }
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    FILE *fp = fopen(devpath, "wb");
    if (fp) { fwrite(mbr, 1, 512, fp); fclose(fp); }

    TEST("MBR: embedded ransom note → ISOLATE");
    ProtectionVerdict v = hlse_mbr_verify(devpath);
    if (v.score >= 80) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

static void
test_mbr_tampered(void) {
    setup_tmpdir();
    char devpath[512];
    snprintf(devpath, sizeof(devpath), "%s/tampered_mbr", tmpdir);

    /* Create a tampered MBR — no boot signature */
    unsigned char mbr[512];
    memset(mbr, 0xCC, sizeof(mbr));  /* INT3 fill = suspicious */
    mbr[510] = 0x00;
    mbr[511] = 0x00;  /* Invalid signature */

    FILE *fp = fopen(devpath, "wb");
    if (fp) { fwrite(mbr, 1, 512, fp); fclose(fp); }

    TEST("MBR: tampered (no signature, unusual first byte) → HIGH");
    ProtectionVerdict v = hlse_mbr_verify(devpath);
    if (v.score >= 60) { PASS(); }
    else {
        char buf[128];
        snprintf(buf, sizeof(buf), "score=%d, reasons:", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

static void
test_gpt_valid(void) {
    setup_tmpdir();
    char devpath[512];
    snprintf(devpath, sizeof(devpath), "%s/fake_gpt", tmpdir);

    unsigned char disk[1024];
    memset(disk, 0, sizeof(disk));
    /* Protective MBR */
    disk[0] = 0xEB; disk[510] = 0x55; disk[511] = 0xAA;
    /* GPT header at LBA1 */
    memcpy(disk + 512, "EFI PART", 8);

    FILE *fp = fopen(devpath, "wb");
    if (fp) { fwrite(disk, 1, 1024, fp); fclose(fp); }

    TEST("GPT: valid EFI PART signature → SAFE");
    ProtectionVerdict v = hlse_gpt_verify(devpath);
    if (v.score < 40) { PASS(); }
    else {
        char buf[64]; snprintf(buf, sizeof(buf), "score=%d", v.score);
        FAIL(buf);
    }
    cleanup_tmpdir();
}

/* ─── Score bounds ────────────────────────────────────────────────────── */

static void
test_score_bounds(void) {
    TEST("Score bounds: all results 0..100");
    setup_tmpdir();

    ProtectionVerdict v1 = hlse_ransomware_check_directory(tmpdir);
    ProtectionVerdict v2 = hlse_netdrive_check_mounts();
    ProtectionVerdict v3 = hlse_smb_check_canary(tmpdir);

    int all_ok = (v1.score >= 0 && v1.score <= 100 &&
                  v2.score >= 0 && v2.score <= 100 &&
                  v3.score >= 0 && v3.score <= 100);
    if (all_ok) { PASS(); }
    else { FAIL("score out of range"); }

    cleanup_tmpdir();
}

/* ─── main ────────────────────────────────────────────────────────────── */

int
main(void) {
    printf("HLSE Protect — Protection Module Tests\n");
    printf("══════════════════════════════════════════\n\n");

    printf("Ransomware protection:\n");
    test_ransomware_clean_directory();
    test_ransomware_note_detection();
    test_ransomware_extension_mutation();
    test_ransomware_entropy_spike();
    test_ransomware_compressed_not_flagged();
    test_ransomware_shadow_deletion_api();
    test_ransomware_compound();

    printf("\nNetwork drive protection:\n");
    test_netdrive_mounts();
    test_netdrive_path_clean();

    printf("\nSMB server protection:\n");
    test_smb_canary_untouched();
    test_smb_log_clean();
    test_smb_log_attack();

    printf("\nMBR/GPT protection:\n");
    test_mbr_valid();
    test_mbr_ransom_note();
    test_mbr_tampered();
    test_gpt_valid();

    printf("\nInvariants:\n");
    test_score_bounds();

    printf("\n══════════════════════════════════════════\n");
    printf("Protection tests: %d/%d passed", passed, total);
    if (failed > 0) printf(", %d FAILED", failed);
    printf("\n══════════════════════════════════════════\n");

    return failed > 0 ? 1 : 0;
}
