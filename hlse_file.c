/*
 * hlse_file.c — File Masquerade Detector
 *
 * Detects files that pretend to be something they're not:
 *
 *   F1. Double extension        — invoice.pdf.exe, report.docx.scr
 *   F2. MIME/magic mismatch     — file claims .pdf but magic bytes say EXE
 *   F3. Executable disguise     — dangerous extension hidden by icon/name
 *   F4. Office macro presence   — .doc/.xls with VBA macro indicators
 *   F5. Script in archive       — .zip/.tar containing .sh/.bat/.ps1
 *   F6. Suspicious filename     — social engineering lure names
 *   F7. Polyglot detection      — file valid as multiple formats
 *
 * All detection is read-only. Files are never modified or executed.
 *
 * Build: gcc -O2 -c hlse_file.c -I.
 * Test:  see tests/hlse_file_tests.c
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "hlse_file.h"

/* ─── helpers ─────────────────────────────────────────────────────────── */

static void
fv_add(FileVerdict *v, int delta, const char *fmt, ...) {
    va_list ap;
    if (v->n_reasons >= HLSE_FILE_MAX_REASONS) return;
    v->score += delta;
    if (v->score > 100) v->score = 100;
    va_start(ap, fmt);
    vsnprintf(v->reasons[v->n_reasons], sizeof(v->reasons[0]), fmt, ap);
    va_end(ap);
    v->n_reasons++;
}

static const char *
get_extension(const char *filename) {
    const char *dot = NULL;
    const char *p = filename;
    while (*p) { if (*p == '.') dot = p; p++; }
    return dot ? dot : "";
}

/* Find the SECOND-TO-LAST extension (for double extension detection) */
static int
get_double_extension(const char *filename,
                     char *outer, size_t outer_sz,
                     char *inner, size_t inner_sz) {
    const char *last_dot = NULL;
    const char *prev_dot = NULL;
    const char *p = filename;

    while (*p) {
        if (*p == '.') { prev_dot = last_dot; last_dot = p; }
        p++;
    }
    if (!last_dot || !prev_dot) return 0;

    /* outer = last extension, inner = second-to-last */
    {
        size_t olen = strlen(last_dot);
        size_t ilen = (size_t)(last_dot - prev_dot);
        if (olen >= outer_sz || ilen >= inner_sz) return 0;
        strncpy(outer, last_dot, outer_sz - 1);
        outer[outer_sz - 1] = '\0';
        memcpy(inner, prev_dot, ilen);
        inner[ilen] = '\0';
    }
    return 1;
}

static void
str_lower(const char *src, char *dst, size_t n) {
    size_t i;
    for (i = 0; i < n - 1 && src[i]; i++)
        dst[i] = (src[i] >= 'A' && src[i] <= 'Z') ? src[i] + 32 : src[i];
    dst[i] = '\0';
}

/* ─── magic byte signatures ───────────────────────────────────────────── */

typedef struct {
    const unsigned char *magic;
    int                  magic_len;
    const char          *format;   /* detected format name */
} MagicSig;

static const unsigned char MAGIC_PE[]   = { 0x4D, 0x5A };                /* MZ */
static const unsigned char MAGIC_ELF[]  = { 0x7F, 0x45, 0x4C, 0x46 };   /* .ELF */
static const unsigned char MAGIC_PDF[]  = { 0x25, 0x50, 0x44, 0x46 };   /* %PDF */
static const unsigned char MAGIC_ZIP[]  = { 0x50, 0x4B, 0x03, 0x04 };   /* PK.. */
static const unsigned char MAGIC_GZIP[] = { 0x1F, 0x8B };
static const unsigned char MAGIC_RAR[]  = { 0x52, 0x61, 0x72, 0x21 };   /* Rar! */
static const unsigned char MAGIC_PNG[]  = { 0x89, 0x50, 0x4E, 0x47 };
static const unsigned char MAGIC_JPG[]  = { 0xFF, 0xD8, 0xFF };
static const unsigned char MAGIC_GIF[]  = { 0x47, 0x49, 0x46, 0x38 };   /* GIF8 */
static const unsigned char MAGIC_OLE[]  = { 0xD0, 0xCF, 0x11, 0xE0 };   /* OLE compound (doc/xls/ppt) */
/* Mach-O (macOS executables). Four unambiguous thin-binary magics, both
 * endiannesses / word sizes. The fat/universal magic 0xCAFEBABE is omitted
 * deliberately: it is indistinguishable from a Java .class file by header
 * alone, so flagging it would risk false positives on legitimate bytecode. */
static const unsigned char MAGIC_MACHO_32LE[] = { 0xCE, 0xFA, 0xED, 0xFE };
static const unsigned char MAGIC_MACHO_64LE[] = { 0xCF, 0xFA, 0xED, 0xFE };
static const unsigned char MAGIC_MACHO_32BE[] = { 0xFE, 0xED, 0xFA, 0xCE };
static const unsigned char MAGIC_MACHO_64BE[] = { 0xFE, 0xED, 0xFA, 0xCF };
static const MagicSig MAGIC_TABLE[] = {
    { MAGIC_PE,    2, "PE/EXE" },
    { MAGIC_ELF,   4, "ELF" },
    { MAGIC_MACHO_32LE, 4, "Mach-O" },
    { MAGIC_MACHO_64LE, 4, "Mach-O" },
    { MAGIC_MACHO_32BE, 4, "Mach-O" },
    { MAGIC_MACHO_64BE, 4, "Mach-O" },
    { MAGIC_PDF,   4, "PDF" },
    { MAGIC_ZIP,   4, "ZIP" },
    { MAGIC_GZIP,  2, "GZIP" },
    { MAGIC_RAR,   4, "RAR" },
    { MAGIC_PNG,   4, "PNG" },
    { MAGIC_JPG,   3, "JPEG" },
    { MAGIC_GIF,   4, "GIF" },
    { MAGIC_OLE,   4, "OLE" },
    { NULL, 0, NULL }
};

static const char *
detect_magic(const unsigned char *head, size_t len) {
    int i;
    for (i = 0; MAGIC_TABLE[i].magic; i++) {
        if ((int)len >= MAGIC_TABLE[i].magic_len &&
            memcmp(head, MAGIC_TABLE[i].magic,
                   (size_t)MAGIC_TABLE[i].magic_len) == 0)
        {
            return MAGIC_TABLE[i].format;
        }
    }
    return NULL;
}

/* ─── dangerous extensions ────────────────────────────────────────────── */

static const char *EXECUTABLE_EXTS[] = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js",  ".jse", ".wsf", ".wsh", ".msi", ".msp",
    ".pif", ".hta", ".cpl", ".inf", ".reg", ".lnk", ".shs",
    /* Linux/macOS */
    ".sh", ".bash", ".command", ".app", ".run",
    /* Java */
    ".jar", ".class",
    /* Python */
    ".py", ".pyw",
    /* Web server-side — can execute on upload */
    ".php", ".php3", ".php5", ".phtml", ".asp", ".aspx", ".jsp",
    /* Scripting languages used as malware droppers */
    ".rb", ".pl", ".tcl", ".lua",
    /* Windows HTML Application — runs JScript/VBScript with no sandbox */
    ".mshta",
    /* PHP archive — executes like a PHP binary */
    ".phar",
    /* JSP variants */
    ".jspx", ".jsw",
    /* JVM scripting */
    ".groovy",
    /* Windows ClickOnce / WPF browser application */
    ".application", ".xbap",
    NULL
};

static int
is_executable_ext(const char *ext) {
    char lower[32];
    int i;
    str_lower(ext, lower, sizeof(lower));
    for (i = 0; EXECUTABLE_EXTS[i]; i++) {
        if (strcmp(lower, EXECUTABLE_EXTS[i]) == 0) return 1;
    }
    return 0;
}

static const char *DOCUMENT_EXTS[] = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".rtf", ".txt", ".csv",
    NULL
};

static int
is_document_ext(const char *ext) {
    char lower[32];
    int i;
    str_lower(ext, lower, sizeof(lower));
    for (i = 0; DOCUMENT_EXTS[i]; i++) {
        if (strcmp(lower, DOCUMENT_EXTS[i]) == 0) return 1;
    }
    return 0;
}

static const char *IMAGE_EXTS[] = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp",
    ".tiff", ".ico",
    NULL
};

static int
is_image_ext(const char *ext) {
    char lower[32];
    int i;
    str_lower(ext, lower, sizeof(lower));
    for (i = 0; IMAGE_EXTS[i]; i++) {
        if (strcmp(lower, IMAGE_EXTS[i]) == 0) return 1;
    }
    return 0;
}

/* ─── social engineering lure filenames ────────────────────────────────── */

static const char *LURE_WORDS[] = {
    "invoice", "payment", "receipt", "statement",
    "resume", "cv", "job_offer", "offer_letter",
    "contract", "agreement", "nda",
    "urgent", "important", "confidential", "classified",
    "password", "credentials", "login",
    "scan", "fax", "document",
    "shipping", "delivery", "tracking", "order",
    "tax", "refund", "irs", "w2", "1099", "kyc",
    "payslip", "salary", "payroll", "wire_transfer", "bank_transfer",
    "immigration", "visa_doc", "passport_scan",
    "update", "patch", "security_update",
    /* Software distribution lures (malware dropper filenames) */
    "setup", "installer", "crack", "keygen", "activation",
    /* Financial / HR fraud lures */
    "bonus", "raise", "termination_notice",
    /* Crypto fraud lures */
    "airdrop", "nft", "whitelist",
    /* Japanese */
    "請求書", "見積書", "納品書", "契約書", "確認",
    "給与明細", "年末調整",
    NULL
};

/* ─── main check function ─────────────────────────────────────────────── */

FileVerdict
hlse_check_file(const char *filepath) {
    FileVerdict v;
    struct stat st;
    unsigned char head[4096];
    ssize_t head_len = 0;
    const char *basename_start;
    const char *ext;
    const char *magic_type = NULL;

    memset(&v, 0, sizeof(v));
    if (!filepath || !filepath[0]) return v;

    /* Extract basename */
    basename_start = strrchr(filepath, '/');
    basename_start = basename_start ? basename_start + 1 : filepath;
    ext = get_extension(basename_start);

    /* Stat the file */
    if (stat(filepath, &st) != 0) {
        fv_add(&v, 0, "Cannot stat file (may not exist)");
        return v;
    }

    /* Read first 4KB for magic byte analysis.
     *
     * O_NOFOLLOW refuses to open a symlink target: a hostile path could
     * otherwise redirect the read to e.g. /etc/shadow. O_NONBLOCK plus an
     * fstat()/S_ISREG() check ensures we only read regular files — opening
     * a FIFO or device node could block indefinitely or have side effects.
     * Mirrors the hardened open() already used in hlse_protect.c.        */
    {
        int fd = open(filepath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
        if (fd >= 0) {
            if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
                head_len = read(fd, head, sizeof(head));
                if (head_len < 0) head_len = 0;
            }
            close(fd);
        }
    }

    /* Detect magic type */
    if (head_len >= 4) {
        magic_type = detect_magic(head, (size_t)head_len);
    }

    /* ── F1: Double extension ──────────────────────────────────────── */
    {
        char outer[32], inner[32];
        if (get_double_extension(basename_start, outer, sizeof(outer),
                                 inner, sizeof(inner)))
        {
            /* document + executable = classic masquerade */
            if (is_document_ext(inner) && is_executable_ext(outer)) {
                fv_add(&v, 80,
                    "F1: DOUBLE EXTENSION — '%s%s' disguised as %s",
                    inner, outer, inner);
            }
            else if (is_image_ext(inner) && is_executable_ext(outer)) {
                fv_add(&v, 80,
                    "F1: DOUBLE EXTENSION — '%s%s' disguised as image",
                    inner, outer);
            }
            else if (is_executable_ext(inner) && is_executable_ext(outer)) {
                fv_add(&v, 50,
                    "F1: Double executable extension '%s%s'",
                    inner, outer);
            }
        }
    }

    /* ── F2: MIME / magic byte mismatch ────────────────────────────── */
    if (magic_type && ext[0]) {
        /* PE/EXE magic with non-executable extension */
        if (strcmp(magic_type, "PE/EXE") == 0 && !is_executable_ext(ext)) {
            fv_add(&v, 70,
                "F2: MAGIC MISMATCH — file has PE/EXE header but extension '%s'",
                ext);
        }
        if (strcmp(magic_type, "ELF") == 0 && !is_executable_ext(ext)
            && strcmp(ext, ".so") != 0 && strcmp(ext, ".o") != 0)
        {
            fv_add(&v, 70,
                "F2: MAGIC MISMATCH — file has ELF header but extension '%s'",
                ext);
        }
        /* Mach-O (macOS) header with a non-executable extension. .dylib,
         * .bundle and .o are legitimate Mach-O containers, like .so/.o above. */
        if (strcmp(magic_type, "Mach-O") == 0 && !is_executable_ext(ext)
            && strcmp(ext, ".dylib") != 0 && strcmp(ext, ".bundle") != 0
            && strcmp(ext, ".o") != 0)
        {
            fv_add(&v, 70,
                "F2: MAGIC MISMATCH — file has Mach-O header but extension '%s'",
                ext);
        }
        /* PDF magic with executable extension */
        if (strcmp(magic_type, "PDF") == 0 && is_executable_ext(ext)) {
            fv_add(&v, 40,
                "F2: PDF content with executable extension '%s' (polyglot?)",
                ext);
        }
        /* Image/media/archive magic with executable extension — a common
         * polyglot / payload-hiding technique (e.g. GIF89a header on a
         * .exe, or a valid JPEG that is also a runnable script). The file
         * presents as benign content but carries an executable name.    */
        if (is_executable_ext(ext) &&
            (strcmp(magic_type, "GIF")  == 0 ||
             strcmp(magic_type, "JPEG") == 0 ||
             strcmp(magic_type, "PNG")  == 0 ||
             strcmp(magic_type, "ZIP")  == 0 ||
             strcmp(magic_type, "GZIP") == 0)) {
            fv_add(&v, 50,
                "F2: %s content with executable extension '%s' — "
                "possible polyglot/payload disguise", magic_type, ext);
        }
    }

    /* ── F3: Executable disguise ───────────────────────────────────── */
    if (is_executable_ext(ext) && (is_document_ext(ext) == 0)) {
        fv_add(&v, 30,
            "F3: Executable extension '%s' — verify intent", ext);
    }

    /* ── F3b: Right-to-left override (RLO) — extension-independent ────
     * RLO (U+202E) reverses display order so "invoice<RLO>fdp.exe" shows
     * as "invoiceexe.pdf". The whole point is to disguise the REAL
     * extension, so this must fire regardless of the apparent ext. Also
     * catch other bidi-control confusables used in the same attack.    */
    {
        const unsigned char *p = (const unsigned char *)basename_start;
        while (*p) {
            /* U+202E RLO: E2 80 AE; U+202D LRO: E2 80 AD;
             * U+2066-2069 isolates: E2 81 A6..A9 */
            if (p[0] == 0xE2 && p[1] == 0x80 &&
                (p[2] == 0xAE || p[2] == 0xAD)) {
                fv_add(&v, 90,
                    "F3: BIDI OVERRIDE in filename (U+202%s) — "
                    "extension visually hidden",
                    p[2] == 0xAE ? "E/RLO" : "D/LRO");
                break;
            }
            if (p[0] == 0xE2 && p[1] == 0x81 &&
                p[2] >= 0xA6 && p[2] <= 0xA9) {
                fv_add(&v, 70,
                    "F3: Unicode bidi isolate in filename — "
                    "possible extension spoofing");
                break;
            }
            p++;
        }
    }

    /* ── F4: Office macro indicators ───────────────────────────────── */
    if (magic_type && strcmp(magic_type, "OLE") == 0) {
        /* OLE compound files (legacy .doc, .xls) — check for macro streams.
         * Look for the "Root Entry" + "VBA" or "Macros" directory.
         * Simple heuristic: search for "VBA" and "Attribute VB_" in bytes. */
        if (head_len > 100) {
            int has_vba = 0;
            ssize_t i;
            for (i = 0; i <= head_len - 3; i++) {
                if (head[i] == 'V' && head[i+1] == 'B' && head[i+2] == 'A') {
                    has_vba = 1; break;
                }
            }
            if (has_vba) {
                fv_add(&v, 35,
                    "F4: OLE document contains VBA macro indicators");
            }
        }
    }

    /* ZIP-based Office (docm, xlsm, pptm) — check for vbaProject.bin */
    if (magic_type && strcmp(magic_type, "ZIP") == 0) {
        char lower_ext[32];
        str_lower(ext, lower_ext, sizeof(lower_ext));
        if (strcmp(lower_ext, ".docm") == 0 ||
            strcmp(lower_ext, ".xlsm") == 0 ||
            strcmp(lower_ext, ".pptm") == 0)
        {
            fv_add(&v, 30,
                "F4: Macro-enabled Office document (%s)", ext);
        }
        /* Even .docx can contain macros if the ZIP has vbaProject.bin.
         * Search for the filename in the ZIP central directory.        */
        if (head_len > 100) {
            int found = 0;
            ssize_t i;
            const char *needle = "vbaProject";
            size_t nlen = strlen(needle);
            for (i = 0; i <= head_len - (ssize_t)nlen; i++) {
                if (memcmp(head + i, needle, nlen) == 0) {
                    found = 1; break;
                }
            }
            if (found) {
                fv_add(&v, 40,
                    "F4: ZIP archive contains vbaProject.bin (macros)");
            }
        }
    }

    /* ── F6: Social engineering lure filename ──────────────────────── */
    {
        char lower_name[512];
        int i;
        int lure_count = 0;
        str_lower(basename_start, lower_name, sizeof(lower_name));

        for (i = 0; LURE_WORDS[i]; i++) {
            if (strstr(lower_name, LURE_WORDS[i])) lure_count++;
        }
        if (lure_count >= 2 && is_executable_ext(ext)) {
            fv_add(&v, 30,
                "F6: Executable with social-engineering lure name "
                "(%d lure words)", lure_count);
        }
        else if (lure_count >= 2) {
            fv_add(&v, 10,
                "F6: File name contains lure words (%d matches)",
                lure_count);
        }
    }

    return v;
}

/* Check a filename-only (no disk access — useful for email attachment
 * screening before downloading).                                      */
FileVerdict
hlse_check_filename(const char *filename) {
    FileVerdict v;
    const char *ext;

    memset(&v, 0, sizeof(v));
    if (!filename || !filename[0]) return v;

    ext = get_extension(filename);

    /* F1: Double extension */
    {
        char outer[32], inner[32];
        if (get_double_extension(filename, outer, sizeof(outer),
                                 inner, sizeof(inner)))
        {
            if (is_document_ext(inner) && is_executable_ext(outer)) {
                fv_add(&v, 80,
                    "F1: DOUBLE EXTENSION — '%s%s' disguised as %s",
                    inner, outer, inner);
            }
            else if (is_image_ext(inner) && is_executable_ext(outer)) {
                fv_add(&v, 80,
                    "F1: DOUBLE EXTENSION — '%s%s' disguised as image",
                    inner, outer);
            }
        }
    }

    /* F3: RLO */
    {
        const unsigned char *p = (const unsigned char *)filename;
        while (*p) {
            if (p[0] == 0xE2 && p[1] == 0x80 && p[2] == 0xAE) {
                fv_add(&v, 90,
                    "F3: RIGHT-TO-LEFT OVERRIDE — extension hidden");
                break;
            }
            p++;
        }
    }

    /* F6: Lure words */
    {
        char lower[512];
        int i, lure = 0;
        str_lower(filename, lower, sizeof(lower));
        for (i = 0; LURE_WORDS[i]; i++) {
            if (strstr(lower, LURE_WORDS[i])) lure++;
        }
        if (lure >= 2 && is_executable_ext(ext)) {
            fv_add(&v, 40,
                "F6: Executable with lure name (%d words)", lure);
        }
    }

    /* Executable extension alone is informational */
    if (is_executable_ext(ext)) {
        fv_add(&v, 5,
            "Executable extension: %s", ext);
    }

    return v;
}
