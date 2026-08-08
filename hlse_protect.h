/*
 * hlse_protect.h — Public API for HLSE active protection modules.
 *
 * Four protection layers:
 *   1. Ransomware   — file entropy + mass rename + ransom note detection
 *   2. Network drive — mount monitoring + access pattern anomaly
 *   3. SMB server    — audit log analysis + honeypot canary files
 *   4. MBR/GPT       — boot sector integrity verification
 *
 * Each function returns a ProtectionVerdict (score + reasons).
 * Scores use the same 0..100 threshold as hlse_core:
 *   0..14 SAFE, 15..39 LOG, 40..59 ALERT, 60..79 BLOCK, 80+ ISOLATE
 */

#ifndef HLSE_PROTECT_H
#define HLSE_PROTECT_H

#ifdef __cplusplus
extern "C" {
#endif

#define HLSE_PROTECT_MAX_REASONS 16

/* Module identifiers (bitmask for hlse_protect_scan) */
#define HLSE_PROTECT_RANSOMWARE     0x01
#define HLSE_PROTECT_NETWORK_DRIVE  0x02
#define HLSE_PROTECT_SMB            0x04
#define HLSE_PROTECT_MBR            0x08
#define HLSE_PROTECT_ESP            0x10  /* standalone; not in _ALL */
#define HLSE_PROTECT_ALL            0x0F

typedef struct {
    int  score;          /* 0..100 */
    int  module;         /* which module produced this (bitmask) */
    int  n_reasons;
    char reasons[HLSE_PROTECT_MAX_REASONS][256];
} ProtectionVerdict;

/* ── Module 1: Ransomware ─────────────────────────────────────────────
 *
 * Scans a directory for signs of ransomware activity:
 *   - Ransom note files (readme.txt, how_to_decrypt.txt, etc.)
 *   - Suspicious file extensions (.locked, .encrypted, .WNCRY, etc.)
 *   - Entropy anomaly (>50% of files above 7.5 bits/byte)
 *
 * Does NOT require root. Does NOT modify files.                       */
ProtectionVerdict hlse_ransomware_check_directory(const char *dir_path);

/* Check for shadow copy / snapshot deletion commands in process list.
 * Requires /proc access (Linux).                                      */
ProtectionVerdict hlse_ransomware_check_shadow_deletion(void);

/* ── Module 2: Network Drive ──────────────────────────────────────────
 *
 * Enumerates /proc/mounts for NFS/CIFS/SMB mounts.
 * Flags unusual mount count (>5 network mounts on a workstation).     */
ProtectionVerdict hlse_netdrive_check_mounts(void);

/* Run ransomware detection on a specific network mount path.
 * Adds "lateral movement" amplifier to the score.                     */
ProtectionVerdict hlse_netdrive_check_path(const char *mount_path);

/* ── Module 3: SMB Server ─────────────────────────────────────────────
 *
 * Honeypot canary file check: place canary files in SMB shares.
 * If they're accessed recently, automated scanning is occurring.      */
ProtectionVerdict hlse_smb_check_canary(const char *share_path);

/* Parse Samba audit log for anomalous patterns:
 *   - Connection flood (>100 connects)
 *   - Mass enumeration (>1000 opens)
 *   - Mass rename (>50 renames — ransomware pattern)                  */
ProtectionVerdict hlse_smb_check_log(const char *log_path);

/* ── Module 4: MBR/GPT ────────────────────────────────────────────────
 *
 * Read-only verification of boot sector integrity.
 *   - MBR signature check (55 AA at bytes 510-511)
 *   - First instruction validation (JMP expected)
 *   - Suspicious string scan (bootkit indicators)
 *   - Entropy analysis of boot code (obfuscation detection)
 *
 * Requires read access to block device (typically root).
 * Does NOT modify the disk.                                           */
ProtectionVerdict hlse_mbr_verify(const char *device_path);

/* GPT header validation (EFI PART signature at LBA 1). */
ProtectionVerdict hlse_gpt_verify(const char *device_path);

/* EFI System Partition integrity: walk the ESP (default "/boot/efi" if
 * `esp_path` is NULL/empty) and flag .efi binaries containing
 * high-specificity ransom/bootkit text. Modernises boot-integrity
 * coverage from the legacy MBR toward UEFI bootkits (BlackLotus,
 * Bootkitty). Read-only; never follows symlinks.                       */
ProtectionVerdict hlse_esp_verify(const char *esp_path);

/* ── Unified scan ─────────────────────────────────────────────────────
 *
 * Run multiple protection modules in one call.
 *
 * `modules` is a bitmask of HLSE_PROTECT_* constants.
 * `target_path` is the directory/device to scan:
 *   - For RANSOMWARE + NETWORK + SMB: a directory path
 *   - For MBR: a block device path (/dev/sda)
 *
 * Example:
 *     ProtectionVerdict v = hlse_protect_scan(
 *         "/home/user/Documents",
 *         HLSE_PROTECT_RANSOMWARE | HLSE_PROTECT_SMB);                */
ProtectionVerdict hlse_protect_scan(const char *target_path, int modules);

#ifdef __cplusplus
}
#endif

#endif /* HLSE_PROTECT_H */
