/*
 * hlse_protect.c — Active protection module for HLSE Core
 *
 * Implements four protection layers as behavioral signal detectors:
 *
 *   1. Ransomware protection     — file entropy + mass rename + ransom note
 *   2. Network drive protection  — mount monitoring + access pattern anomaly
 *   3. SMB server protection     — protocol anomaly + honeypot canary files
 *   4. MBR/GPT protection        — boot sector integrity verification
 *
 * Design philosophy (Carmack/Pike):
 *   - Each protection is a pure function: input → verdict
 *   - No kernel modules, no root requirement for detection
 *   - Root needed only for RESPONSE (kill process, unmount)
 *   - Detection runs in userland via /proc, inotify, stat()
 *
 * Integration with HLSE Core:
 *   - Each module produces a ProtectionVerdict (score + reasons)
 *   - Scores feed into the same 0..100 threshold system
 *   - ALERT at 40, BLOCK at 60, ISOLATE at 80
 *
 * Platform: Linux (inotify, /proc/mounts, /dev/sd*)
 *           macOS partial (FSEvents stub, no /proc)
 *           Windows: not covered (use Windows Defender MBR protection)
 *
 * Build: gcc -O2 -Wall -Wextra -c hlse_protect.c -I.
 *        Link with hlse_core.c hlse_text.c for full binary.
 *
 * Identity: bitcoin:bc1qjaet6jgpk08la46jelmlpgsz84luc4lc0tnwr5
 */

#define _POSIX_C_SOURCE 200809L

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>       /* for log2() in entropy calculation */
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "hlse_protect.h"
#include "hlse_util.h"

/* ═══════════════════════════════════════════════════════════════════════
 * Internal helpers
 * ═══════════════════════════════════════════════════════════════════════ */

static void
pv_add_reason(ProtectionVerdict *v, int delta, const char *fmt, ...) {
    va_list ap;
    if (v->n_reasons >= HLSE_PROTECT_MAX_REASONS) return;
    if (delta > 0) {
        v->score += delta;
        if (v->score > 100) v->score = 100;
    }
    va_start(ap, fmt);
    vsnprintf(v->reasons[v->n_reasons],
              sizeof(v->reasons[0]), fmt, ap);
    va_end(ap);
    v->n_reasons++;
}

/* Shannon entropy of a byte buffer. Returns bits per byte (0.0 .. 8.0).
 * Encrypted/compressed data → ~7.9+. Plain text → ~4.0-5.0.
 * This is the core signal for ransomware detection: if a file that was
 * previously low-entropy suddenly becomes high-entropy, it was likely
 * encrypted by ransomware.                                               */
#define shannon_entropy(d, l) hlse_shannon_entropy((d), (l))

/* Read first N bytes of a file for entropy analysis. Returns bytes read. */
static size_t
read_file_head(const char *path, unsigned char *buf, size_t max_bytes) {
    int fd;
    ssize_t n;
    struct stat st;

    /* O_NOFOLLOW: these paths come from an untrusted scanned directory, so a
     * symlink must not redirect the read. O_NONBLOCK + S_ISREG: a FIFO in the
     * tree must not block read() indefinitely, and only regular files are
     * scanned (matches the scan-walker and the spec §1 invariant).         */
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return 0;

    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return 0;
    }

    n = read(fd, buf, max_bytes);
    close(fd);

    return (n > 0) ? (size_t)n : 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Module 1: Ransomware Protection
 *
 * Detection signals:
 *   R1. Mass file modification — N files changed in T seconds
 *   R2. Entropy spike          — file entropy jumps from <6.0 to >7.5
 *   R3. Ransom note detection  — known ransom note filenames appear
 *   R4. Extension mutation     — files renamed to unknown extensions
 *   R5. Shadow copy deletion   — vssadmin/wmic shadow delete detected
 *
 * Compound rule:
 *   R1 + R2               → BLOCK (60)
 *   R1 + R2 + R3          → ISOLATE (80)
 *   R5 (shadow delete)    → immediate BLOCK (60)
 * ═══════════════════════════════════════════════════════════════════════ */

/* Known ransomware note filenames (case-insensitive match) */
static const char *RANSOM_NOTE_NAMES[] = {
    "readme.txt", "read_me.txt", "how_to_decrypt.txt",
    "how_to_recover.txt", "decrypt_instructions.txt",
    "restore_files.txt", "help_decrypt.html",
    "!readme!.txt", "_readme_.txt",
    "ransom_note.txt", "your_files.txt",
    "recovery.txt", "unlock_files.txt",
    /* STOP/DJVU family */
    "how_to_restore_files.txt",
    /* DHARMA/PHOBOS family */
    "decrypt_info.html",
    /* Nemty / generic variants */
    "readme_decrypt.txt",
    "files_encrypted.txt",
    "restore_my_files.txt",
    /* Generic multi-exclamation variants (Cerber etc.) */
    "!!!readme!!!.txt",
    "!decrypt!.txt",
    /* Japanese ransomware notes */
    "身代金.txt", "ファイル復元.txt",
    /* 2023-2025 active families */
    "contact_us.txt", "contact_us.html",
    "recovery_instructions.html", "recovery_instructions.txt",
    "readme_now.txt",             /* Babuk variant */
    "!!readme!!.txt", "!!!files_encrypted!!!.txt",
    /* Akira / Rhysida / newer families */
    "akira_readme.txt", "rhysida.readme.txt",
    "fog_readme.txt", "interlock_note.txt",
    "how_to_back_files.html",     /* INC Ransom */
    "decrypt.txt",                /* generic */
    "look_at_me.txt",             /* Lookout/generic */
    "medusa_readme.txt",          /* Medusa ransomware */
    "ransomhub_readme.txt",       /* RansomHub */
    "!_readme_!.txt",             /* RansomHub variant */
    "dragonforce_readme.txt",     /* DragonForce */
    NULL
};

/* Suspicious extensions added by known ransomware families */
static const char *RANSOM_EXTENSIONS[] = {
    ".locked", ".encrypted", ".crypt", ".enc", ".crypto",
    ".locky", ".cerber", ".zepto", ".odin", ".thor",
    ".aesir", ".zzzzz", ".micro", ".crypted", ".crinf",
    ".r5a", ".WNCRY", ".wcry", ".wncrypt", ".wncryt",
    ".hacked", ".1btc", ".pays", ".paymst", ".STOP",
    ".djvu", ".shade", ".no_more_ransom",
    /* Major families 2018-2024 */
    ".ryuk",        /* Ryuk (Wizard Spider, 2018-2021) */
    ".lockbit",     /* LockBit family */
    ".clop",        /* Cl0p / Clop ransomware */
    ".phobos",      /* PHOBOS family */
    ".eking",       /* PHOBOS/Eking variant */
    ".dharma",      /* DHARMA family */
    ".karma",       /* KARMA ransomware */
    ".conti",       /* Conti family */
    ".avaddon",     /* Avaddon (closed 2021) */
    ".deadbolt",    /* DeadBolt (NAS-targeting, 2022) */
    ".akira",       /* Akira (2023+) */
    ".rhysida",     /* Rhysida (2023-2024) */
    ".monti",       /* Monti (Conti fork) */
    ".cactus",      /* Cactus (2023+) */
    ".cryptolocker",/* CryptoLocker (classic 2013) */
    /* Emerging 2024+ families */
    ".black",       /* BlackCat/ALPHV variant */
    ".alphv",       /* ALPHV (BlackCat) */
    ".play",        /* Play ransomware (2022+) */
    ".royal",       /* Royal ransomware (2022+) */
    ".blacksuit",   /* BlackSuit (Royal fork) */
    ".fog",         /* Fog ransomware (2024) */
    ".hunters",     /* Hunters International (2023+) */
    ".cicada",      /* Cicada3301 (2024) */
    ".qilin",       /* Qilin/Agenda (2022+) */
    ".interlock",   /* Interlock (2024) */
    ".embargo",     /* Embargo (2024) */
    ".lynx",        /* Lynx ransomware (2024, INC fork) */
    ".sarcoma",     /* Sarcoma (2024) */
    ".meow",        /* Meow ransomware (2024) */
    ".medusa",      /* Medusa ransomware (2023+, CISA advisory 2025) */
    ".incransom",   /* INC Ransom (2024-2025) */
    ".ransomhub",   /* RansomHub (2024-2025, high-volume successor to ALPHV) */
    ".dragonforce", /* DragonForce (2024-2025) */
    ".safepay",     /* SafePay (2024, LockBit-based) */
    NULL
};

ProtectionVerdict
hlse_ransomware_check_directory(const char *dir_path) {
    ProtectionVerdict v;
    DIR *dir;
    struct dirent *ent;
    int suspicious_ext_count = 0;
    int high_entropy_count = 0;
    int total_files = 0;
    unsigned char buf[4096];

    memset(&v, 0, sizeof(v));
    v.module = HLSE_PROTECT_RANSOMWARE;

    dir = opendir(dir_path);
    if (!dir) {
        pv_add_reason(&v, 0, "Cannot open directory: %s", strerror(errno));
        return v;
    }

    while ((ent = readdir(dir)) != NULL) {
        char fullpath[4096];
        const char *name;
        int i;
        size_t nlen;

        if (ent->d_name[0] == '.') continue;
        name = ent->d_name;
        nlen = strlen(name);

        snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_path, name);

        /* R3: Ransom note detection */
        {
            char lower[256];
            size_t k;
            for (k = 0; k < nlen && k < sizeof(lower) - 1; k++)
                lower[k] = (name[k] >= 'A' && name[k] <= 'Z')
                           ? (char)(name[k] + 32) : name[k];
            lower[k] = '\0';
            for (i = 0; RANSOM_NOTE_NAMES[i]; i++) {
                if (strcmp(lower, RANSOM_NOTE_NAMES[i]) == 0) {
                    pv_add_reason(&v, 35,
                        "R3: Ransom note detected: '%s'", name);
                    break;
                }
            }
        }

        /* R4: Suspicious extension */
        for (i = 0; RANSOM_EXTENSIONS[i]; i++) {
            size_t elen = strlen(RANSOM_EXTENSIONS[i]);
            if (nlen > elen &&
                strcmp(name + nlen - elen, RANSOM_EXTENSIONS[i]) == 0)
            {
                suspicious_ext_count++;
                if (suspicious_ext_count <= 2) {
                    pv_add_reason(&v, 20,
                        "R4: Suspicious extension: '%s'", name);
                }
                break;
            }
        }

        /* R2: Entropy analysis (sample first 4KB of regular files) */
        {
            struct stat st;
            if (stat(fullpath, &st) == 0 && S_ISREG(st.st_mode)
                && st.st_size > 64)
            {
                size_t n = read_file_head(fullpath, buf, sizeof(buf));
                if (n > 64) {
                    /* Literature (arXiv 2106.14418, 2210.13376, 2103.17059):
                     * Shannon entropy alone CANNOT distinguish encrypted
                     * data from compressed/media files — both approach 8
                     * bits/byte. Counting compressed files as "encrypted"
                     * produces false ransomware alerts on any directory of
                     * .zip/.jpg/.mp4/.gz files.
                     *
                     * Mitigation: skip files whose magic bytes identify a
                     * known high-entropy-but-benign format. These are
                     * legitimately high-entropy and must not inflate the
                     * ransomware signal. Ransomware-encrypted files do NOT
                     * carry these signatures (the original header is
                     * encrypted away).                                    */
                    int is_known_compressed =
                        hlse_is_high_entropy_benign_magic(buf, n);

                    if (is_known_compressed) {
                        /* Counts as a scanned file, but its high entropy
                         * is expected and benign — do not flag.          */
                        total_files++;
                    } else {
                        double h_ent = shannon_entropy(buf, n);
                        total_files++;
                        if (h_ent > 7.5) {
                            high_entropy_count++;
                        }
                    }
                }
            }
        }
    }
    closedir(dir);

    /* R2: Entropy spike — if > 50% of files are high-entropy, suspicious */
    if (total_files >= 5 && high_entropy_count > total_files / 2) {
        pv_add_reason(&v, 30,
            "R2: Entropy anomaly: %d/%d files above 7.5 bits/byte "
            "(likely encrypted)", high_entropy_count, total_files);
    }

    /* R4: Mass extension mutation */
    if (suspicious_ext_count >= 5) {
        pv_add_reason(&v, 25,
            "R4: Mass extension mutation: %d files with ransomware extensions",
            suspicious_ext_count);
    }

    /* Compound rules */
    if (high_entropy_count > total_files / 2 && suspicious_ext_count >= 3) {
        pv_add_reason(&v, 15,
            "Compound: high entropy + mass extension change = "
            "active ransomware");
    }

    return v;
}

/* R5: Check if shadow copy deletion commands were recently executed.
 * Reads from a process log or checks /proc for running processes.      */
ProtectionVerdict
hlse_ransomware_check_shadow_deletion(void) {
    ProtectionVerdict v;
    memset(&v, 0, sizeof(v));
    v.module = HLSE_PROTECT_RANSOMWARE;

    /* Scan /proc/<pid>/cmdline for snapshot/backup deletion commands.
     * Uses O_NOFOLLOW + O_NONBLOCK to avoid symlink traps and FIFOs. */
    {
        static const char *dangerous_cmds[] = {
            "vssadmin", "shadowcopy delete", "wmic shadow",
            "btrfs subvolume delete", "lvremove",
            "bcdedit /set", "wbadmin delete",
            NULL
        };
        DIR *proc = opendir("/proc");
        if (proc) {
            struct dirent *de;
            while ((de = readdir(proc)) != NULL) {
                /* Only numeric directories (PIDs) */
                const char *np = de->d_name;
                while (*np >= '0' && *np <= '9') np++;
                if (*np || de->d_name[0] == '\0') continue;

                char cpath[320];  /* /proc/ + NAME_MAX(255) + /cmdline + NUL */
                snprintf(cpath, sizeof(cpath), "/proc/%s/cmdline", de->d_name);
                int cfd = open(cpath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
                if (cfd < 0) continue;
                {
                    struct stat cst;
                    if (fstat(cfd, &cst) != 0 || !S_ISREG(cst.st_mode)) {
                        close(cfd);
                        continue;
                    }
                    char cmd[512];
                    ssize_t nr = read(cfd, cmd, sizeof(cmd) - 1);
                    close(cfd);
                    if (nr <= 0) continue;
                    /* cmdline uses NUL separators — replace with spaces */
                    ssize_t i;
                    for (i = 0; i < nr; i++) {
                        if (cmd[i] == '\0') cmd[i] = ' ';
                    }
                    cmd[nr] = '\0';
                    int j;
                    for (j = 0; dangerous_cmds[j]; j++) {
                        if (strstr(cmd, dangerous_cmds[j])) {
                            pv_add_reason(&v, 60,
                                "R5: Shadow/backup deletion command running: "
                                "%.80s", cmd);
                            break;
                        }
                    }
                }
            }
            closedir(proc);
        }
    }

    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Module 2: Network Drive Protection
 *
 * Detection signals:
 *   N1. New mount appeared (NFS/CIFS/SMB)
 *   N2. Mass file access immediately after mount
 *   N3. Write pattern anomaly (sequential write of many files)
 *   N4. Known-bad mount source (IP reputation)
 * ═══════════════════════════════════════════════════════════════════════ */

ProtectionVerdict
hlse_netdrive_check_mounts(void) {
    ProtectionVerdict v;
    FILE *fp;
    char line[1024];
    int smb_mounts = 0;
    int nfs_mounts = 0;

    memset(&v, 0, sizeof(v));
    v.module = HLSE_PROTECT_NETWORK_DRIVE;

    fp = fopen("/proc/mounts", "r");
    if (!fp) {
        pv_add_reason(&v, 0,
            "Cannot read /proc/mounts (not Linux or no permission)");
        return v;
    }

    while (fgets(line, sizeof(line), fp)) {
        /* N1: Detect network filesystem mounts */
        if (strstr(line, " cifs ") || strstr(line, " smb3 ")) {
            smb_mounts++;
            /* Extract mount point for reporting */
            char *mp = strchr(line, ' ');
            if (mp) {
                mp++;
                char *mp_end = strchr(mp, ' ');
                if (mp_end) *mp_end = '\0';
                pv_add_reason(&v, 10,
                    "N1: SMB/CIFS mount detected at %s", mp);
                if (mp_end) *mp_end = ' ';
            }
        }
        if (strstr(line, " nfs ") || strstr(line, " nfs4 ")) {
            nfs_mounts++;
            char *mp = strchr(line, ' ');
            if (mp) {
                mp++;
                char *mp_end = strchr(mp, ' ');
                if (mp_end) *mp_end = '\0';
                pv_add_reason(&v, 10,
                    "N1: NFS mount detected at %s", mp);
                if (mp_end) *mp_end = ' ';
            }
        }
    }
    fclose(fp);

    /* N2: Many network mounts is unusual for a workstation */
    if (smb_mounts + nfs_mounts >= 5) {
        pv_add_reason(&v, 20,
            "N2: Unusually many network mounts (%d SMB + %d NFS)",
            smb_mounts, nfs_mounts);
    }

    return v;
}

/* Check a specific network mount point for ransomware-like activity */
ProtectionVerdict
hlse_netdrive_check_path(const char *mount_path) {
    ProtectionVerdict v;

    memset(&v, 0, sizeof(v));
    v.module = HLSE_PROTECT_NETWORK_DRIVE;

    /* Delegate to ransomware directory check — same behavioral signals */
    v = hlse_ransomware_check_directory(mount_path);
    v.module = HLSE_PROTECT_NETWORK_DRIVE;

    if (v.score > 0) {
        /* Network drive context amplifies the score: lateral movement */
        pv_add_reason(&v, 15,
            "Amplifier: suspicious activity on network mount — "
            "possible lateral movement");
    }
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Module 3: SMB Server Protection
 *
 * Detection signals:
 *   S1. Abnormal connection rate from single client
 *   S2. Mass file enumeration (directory listing flood)
 *   S3. Known-bad SMB exploit patterns (EternalBlue, SMBGhost)
 *   S4. Honeypot canary file access
 *
 * Implementation note: Full SMB protocol analysis requires pcap or
 * kernel-level nfqueue hooking. This reference implementation provides
 * a log-analysis approach: parse Samba audit logs for anomalies.
 * ═══════════════════════════════════════════════════════════════════════ */

/* Canary files to place in SMB shares. If these are accessed, it's
 * likely automated enumeration or ransomware scanning.                 */
static const char *CANARY_FILENAMES[] = {
    ".canary_hlse_do_not_delete",
    "AAAA_important_backup.xlsx",      /* sorts first alphabetically */
    "zzzz_confidential_archive.zip",   /* sorts last */
    NULL
};

ProtectionVerdict
hlse_smb_check_canary(const char *share_path) {
    ProtectionVerdict v;
    int i;

    memset(&v, 0, sizeof(v));
    v.module = HLSE_PROTECT_SMB;

    for (i = 0; CANARY_FILENAMES[i]; i++) {
        char path[4096];
        struct stat st;
        snprintf(path, sizeof(path), "%s/%s",
                 share_path, CANARY_FILENAMES[i]);

        if (stat(path, &st) == 0) {
            /* Canary exists. Check if recently accessed (atime). */
            time_t now = time(NULL);
            double age_sec = difftime(now, st.st_atime);
            if (age_sec < 300) { /* accessed in last 5 minutes */
                pv_add_reason(&v, 40,
                    "S4: Canary file accessed: '%s' (%d sec ago)",
                    CANARY_FILENAMES[i], (int)age_sec);
            }
        }
    }

    return v;
}

/* Analyze Samba audit log for anomalous patterns */
ProtectionVerdict
hlse_smb_check_log(const char *log_path) {
    ProtectionVerdict v;
    FILE *fp;
    char line[2048];
    int connect_count = 0;
    int open_count = 0;
    int rename_count = 0;

    memset(&v, 0, sizeof(v));
    v.module = HLSE_PROTECT_SMB;

    fp = fopen(log_path, "r");
    if (!fp) {
        pv_add_reason(&v, 0, "Cannot open Samba log: %s", log_path);
        return v;
    }

    /* Simple pattern counting — production would use time-windowed analysis */
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "connect")) connect_count++;
        if (strstr(line, "open") || strstr(line, "opendir"))
            open_count++;
        if (strstr(line, "rename")) rename_count++;
    }
    fclose(fp);

    /* S1: Connection flood */
    if (connect_count > 100) {
        pv_add_reason(&v, 25,
            "S1: High connection rate (%d connects in log)",
            connect_count);
    }

    /* S2: Mass enumeration */
    if (open_count > 1000) {
        pv_add_reason(&v, 30,
            "S2: Mass file enumeration (%d opens in log)",
            open_count);
    }

    /* S3: Mass rename (ransomware on SMB share) */
    if (rename_count > 50) {
        pv_add_reason(&v, 40,
            "S3: Mass rename detected (%d renames — ransomware pattern)",
            rename_count);
    }

    /* Compound: enumerate + rename = active ransomware via SMB */
    if (open_count > 500 && rename_count > 20) {
        pv_add_reason(&v, 20,
            "Compound: enumeration + mass rename = "
            "ransomware spreading via SMB");
    }

    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Module 4: MBR/GPT Protection
 *
 * Detection signals:
 *   M1. MBR signature check (bytes 510-511 = 0x55AA)
 *   M2. GPT header integrity (CRC32 verification)
 *   M3. Bootloader hash verification (known-good SHA256)
 *   M4. Write attempt detection (requires audit subsystem)
 *
 * IMPORTANT: This is VERIFICATION only, not prevention.
 * Prevention requires:
 *   - UEFI Secure Boot (firmware level)
 *   - kernel lockdown mode
 *   - hardware write-protect on boot media
 *
 * HLSE can DETECT tampering by comparing current boot sector against
 * a known-good baseline. It cannot PREVENT writes to /dev/sda.
 * ═══════════════════════════════════════════════════════════════════════ */

/* MBR is the first 512 bytes of a disk. The last two bytes must be
 * 0x55 0xAA (the boot signature). If they're different, either:
 *   - the disk has GPT-only layout (no MBR signature) — normal
 *   - the MBR has been overwritten — potentially malicious            */
ProtectionVerdict
hlse_mbr_verify(const char *device_path) {
    ProtectionVerdict v;
    unsigned char mbr[512];
    int fd;
    ssize_t n;

    memset(&v, 0, sizeof(v));
    v.module = HLSE_PROTECT_MBR;

    fd = open(device_path, O_RDONLY);
    if (fd < 0) {
        pv_add_reason(&v, 0,
            "Cannot read device %s: %s (need root?)",
            device_path, strerror(errno));
        return v;
    }

    n = read(fd, mbr, 512);
    close(fd);

    if (n < 512) {
        pv_add_reason(&v, 0,
            "Short read from %s: only %zd bytes", device_path, n);
        return v;
    }

    /* M1: Boot signature check */
    if (mbr[510] != 0x55 || mbr[511] != 0xAA) {
        /* Check if this is a GPT-only disk (no protective MBR) */
        if (memcmp(mbr + 0, "\x00\x00\x00\x00", 4) == 0) {
            pv_add_reason(&v, 0,
                "M1: No MBR signature — appears to be GPT-only (normal)");
        } else {
            pv_add_reason(&v, 70,
                "M1: Invalid MBR signature at %s: "
                "expected 55 AA, got %02X %02X — possible tampering",
                device_path, mbr[510], mbr[511]);
        }
    } else {
        pv_add_reason(&v, 0,
            "M1: MBR signature valid (55 AA) at %s", device_path);
    }

    /* M2: Check for suspicious bootloader patterns.
     * Real bootkits overwrite the jump instruction at offset 0.
     * A normal MBR starts with a short JMP (0xEB xx 0x90) or
     * a near JMP (0xE9 xx xx). Anything else is suspicious.          */
    if (mbr[0] != 0xEB && mbr[0] != 0xE9 && mbr[0] != 0x00) {
        pv_add_reason(&v, 40,
            "M2: Unusual first instruction byte: 0x%02X "
            "(expected JMP: 0xEB or 0xE9)", mbr[0]);
    }

    /* M3: Check for known bootkit strings in the MBR.
     * These are NOT signatures — they're strings that appear in
     * known bootkits but never in legitimate bootloaders.             */
    {
        const char *bootkit_strings[] = {
            "GRUB4DOS", /* legitimate but unusual — might indicate tampering */
            "rootkit",
            "infected",
            "pay bitcoin",
            "your files",
            /* Documented MBR ransomware / bootkit families and their
             * ransom-note fragments (Petya/NotPetya, MBR lockers). These
             * strings appear in the boot sector payload, never in a
             * legitimate bootloader. */
            "stoned",          /* classic Stoned bootkit lineage */
            "petya",
            "send",            /* "send $..." ransom instruction */
            "decrypt",         /* MBR locker decrypt instructions */
            "ransom",
            "bitcoin",
            "wallet",
            "locked",
            NULL
        };
        int i;
        for (i = 0; bootkit_strings[i]; i++) {
            /* Case-insensitive search in 512 bytes — portable,
             * no memmem (GNU extension unavailable on macOS/musl) */
            /* unsigned char: MBR bytes are binary (often >127); converting
             * those to signed char would be implementation-defined. memcmp
             * compares as unsigned char regardless, so this is also correct
             * against the (char*) bootkit_strings.                         */
            unsigned char lower_mbr[512];
            size_t needle_len = strlen(bootkit_strings[i]);
            int j;
            int found = 0;
            for (j = 0; j < 512; j++)
                lower_mbr[j] = (mbr[j] >= 'A' && mbr[j] <= 'Z')
                               ? (unsigned char)(mbr[j] + 32) : mbr[j];
            for (j = 0; j <= 512 - (int)needle_len; j++) {
                if (memcmp(lower_mbr + j, bootkit_strings[i],
                           needle_len) == 0)
                {
                    found = 1;
                    break;
                }
            }
            if (found) {
                pv_add_reason(&v, 60,
                    "M3: Suspicious string in MBR: '%s'",
                    bootkit_strings[i]);
            }
        }
    }

    /* M4: Entropy analysis of boot code section (bytes 0..445).
     * Normal bootloaders have moderate entropy (~4-6).
     * Encrypted/obfuscated bootkits have high entropy (~7+).         */
    {
        double ent = shannon_entropy(mbr, 446);
        if (ent > 7.0) {
            pv_add_reason(&v, 35,
                "M4: High entropy in MBR boot code: %.2f bits/byte "
                "(possible obfuscated bootkit)", ent);
        }
    }

    return v;
}

/* Verify GPT header integrity (checks at LBA 1, i.e., byte 512-1023) */
ProtectionVerdict
hlse_gpt_verify(const char *device_path) {
    ProtectionVerdict v;
    unsigned char sector[512];
    int fd;
    ssize_t n;

    memset(&v, 0, sizeof(v));
    v.module = HLSE_PROTECT_MBR;

    fd = open(device_path, O_RDONLY);
    if (fd < 0) {
        pv_add_reason(&v, 0,
            "Cannot read device %s: %s", device_path, strerror(errno));
        return v;
    }

    /* Seek to LBA 1 (byte 512) for GPT header */
    if (lseek(fd, 512, SEEK_SET) != 512) {
        close(fd);
        pv_add_reason(&v, 0, "Cannot seek to GPT header on %s", device_path);
        return v;
    }

    n = read(fd, sector, 512);
    close(fd);

    if (n < 512) {
        pv_add_reason(&v, 0, "Short read at GPT header on %s", device_path);
        return v;
    }

    /* GPT signature: "EFI PART" at offset 0 of the GPT header */
    if (memcmp(sector, "EFI PART", 8) == 0) {
        pv_add_reason(&v, 0,
            "GPT header valid: 'EFI PART' signature found at %s",
            device_path);
    } else {
        /* Not necessarily an error — could be MBR-only disk */
        pv_add_reason(&v, 10,
            "No GPT header at %s — MBR-only or damaged partition table",
            device_path);
    }

    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Module: EFI System Partition (ESP) integrity
 *
 * The MBR check above only covers legacy BIOS boot. The live boot-level
 * threat is UEFI bootkits (BlackLotus, Linux Bootkitty) which tamper with
 * the EFI System Partition rather than the MBR. Without a recorded
 * baseline or kernel keyring access we cannot validate Authenticode
 * signatures offline, so this check uses the same low-false-positive
 * signal as the MBR string scan: ransom/bootkit *text* embedded in a
 * boot binary. The MBR's generic single-word tokens ("decrypt", "locked",
 * "send") are deliberately NOT reused — they occur legitimately inside
 * multi-megabyte signed bootloaders. Only high-specificity multi-word
 * ransom-note phrases are matched here.
 * ═══════════════════════════════════════════════════════════════════════ */

static const char *ESP_INDICATORS[] = {
    "your files have been encrypted",
    "your files are encrypted",
    "all your files",
    "your important files",
    "to decrypt your files",
    "pay bitcoin",
    "send bitcoin",
    "petya",
    /* UEFI bootkits discovered 2022-2024 */
    "blacklotus",   /* Windows BlackLotus UEFI bootkit */
    "bootkitty",    /* Linux Bootkitty UEFI bootkit (2024) */
    /* Generic ransom-note phrases embedded in tampered EFI binaries */
    "contact us to decrypt",
    "to recover your files",
    NULL
};

/* Case-insensitive substring search over a (possibly NUL-containing)
 * binary buffer. `needle` must already be lowercase. */
static int
esp_buf_contains(const unsigned char *hay, size_t haylen, const char *needle) {
    size_t nl = strlen(needle);
    size_t i, j;
    if (nl == 0 || haylen < nl) return 0;
    for (i = 0; i + nl <= haylen; i++) {
        for (j = 0; j < nl; j++) {
            unsigned char c = hay[i + j];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
            if (c != (unsigned char)needle[j]) break;
        }
        if (j == nl) return 1;
    }
    return 0;
}

/* Read up to ESP_SCAN_BYTES of a regular .efi file into a shared buffer and
 * flag any ESP_INDICATORS phrase. Returns 1 if the file was scanned. */
#define ESP_SCAN_BYTES (256 * 1024)
static unsigned char esp_buf[ESP_SCAN_BYTES];

static int
esp_has_efi_ext(const char *name) {
    size_t L = strlen(name);
    if (L < 4) return 0;
    return (name[L-4] == '.'
            && (name[L-3] == 'e' || name[L-3] == 'E')
            && (name[L-2] == 'f' || name[L-2] == 'F')
            && (name[L-1] == 'i' || name[L-1] == 'I'));
}

static void
esp_scan_dir(const char *dir_path, int depth,
             ProtectionVerdict *v, int *file_count) {
    DIR *dir;
    struct dirent *ent;

    if (depth > 8) return;                 /* bound recursion */
    if (*file_count > 5000) return;        /* bound work */
    dir = opendir(dir_path);
    if (!dir) return;

    while ((ent = readdir(dir)) != NULL) {
        char fullpath[4096];
        struct stat st;
        if (ent->d_name[0] == '.') continue;
        if ((size_t)snprintf(fullpath, sizeof(fullpath), "%s/%s",
                             dir_path, ent->d_name) >= sizeof(fullpath))
            continue;
        /* lstat: never follow symlinks into or out of the ESP. */
        if (lstat(fullpath, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            esp_scan_dir(fullpath, depth + 1, v, file_count);
            continue;
        }
        if (!S_ISREG(st.st_mode) || !esp_has_efi_ext(ent->d_name)) continue;

        {
            int fd = open(fullpath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
            ssize_t n;
            if (fd < 0) continue;
            n = read(fd, esp_buf, sizeof(esp_buf));
            close(fd);
            if (n <= 0) continue;
            (*file_count)++;
            {
                int i;
                for (i = 0; ESP_INDICATORS[i]; i++) {
                    if (esp_buf_contains(esp_buf, (size_t)n, ESP_INDICATORS[i])) {
                        pv_add_reason(v, 70,
                            "E3: Ransom/bootkit string '%s' in ESP binary: %s",
                            ESP_INDICATORS[i], ent->d_name);
                        break;  /* one reason per file */
                    }
                }
            }
        }
    }
    closedir(dir);
}

ProtectionVerdict
hlse_esp_verify(const char *esp_path) {
    ProtectionVerdict v;
    struct stat st;
    int file_count = 0;
    const char *path = (esp_path && esp_path[0]) ? esp_path : "/boot/efi";

    memset(&v, 0, sizeof(v));
    v.module = HLSE_PROTECT_ESP;

    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        pv_add_reason(&v, 0,
            "No EFI System Partition at %s (UEFI not in use or not mounted)",
            path);
        return v;
    }

    esp_scan_dir(path, 0, &v, &file_count);

    if (v.n_reasons == 0) {
        pv_add_reason(&v, 0,
            "ESP clean: scanned %d .efi binaries under %s, no ransom/bootkit "
            "strings", file_count, path);
    }
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Unified protection scan
 * ═══════════════════════════════════════════════════════════════════════ */

ProtectionVerdict
hlse_protect_scan(const char *target_path, int modules) {
    ProtectionVerdict combined;
    memset(&combined, 0, sizeof(combined));
    combined.module = 0; /* mixed */

    if (modules & HLSE_PROTECT_RANSOMWARE) {
        ProtectionVerdict rv = hlse_ransomware_check_directory(target_path);
        if (rv.score > 0) {
            int i;
            for (i = 0; i < rv.n_reasons && combined.n_reasons < HLSE_PROTECT_MAX_REASONS; i++) {
                memcpy(combined.reasons[combined.n_reasons],
                       rv.reasons[i], sizeof(rv.reasons[0]));
                combined.n_reasons++;
            }
            combined.score += rv.score;
        }
    }

    if (modules & HLSE_PROTECT_NETWORK_DRIVE) {
        ProtectionVerdict nv = hlse_netdrive_check_mounts();
        if (nv.score > 0) {
            int i;
            for (i = 0; i < nv.n_reasons && combined.n_reasons < HLSE_PROTECT_MAX_REASONS; i++) {
                memcpy(combined.reasons[combined.n_reasons],
                       nv.reasons[i], sizeof(nv.reasons[0]));
                combined.n_reasons++;
            }
            combined.score += nv.score;
        }
    }

    if (modules & HLSE_PROTECT_SMB) {
        ProtectionVerdict sv = hlse_smb_check_canary(target_path);
        if (sv.score > 0) {
            int i;
            for (i = 0; i < sv.n_reasons && combined.n_reasons < HLSE_PROTECT_MAX_REASONS; i++) {
                memcpy(combined.reasons[combined.n_reasons],
                       sv.reasons[i], sizeof(sv.reasons[0]));
                combined.n_reasons++;
            }
            combined.score += sv.score;
        }
    }

    if (modules & HLSE_PROTECT_MBR) {
        ProtectionVerdict mv = hlse_mbr_verify(target_path);
        if (mv.score > 0) {
            int i;
            for (i = 0; i < mv.n_reasons && combined.n_reasons < HLSE_PROTECT_MAX_REASONS; i++) {
                memcpy(combined.reasons[combined.n_reasons],
                       mv.reasons[i], sizeof(mv.reasons[0]));
                combined.n_reasons++;
            }
            combined.score += mv.score;
        }
    }

    if (combined.score > 100) combined.score = 100;
    return combined;
}
