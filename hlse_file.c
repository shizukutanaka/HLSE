/*
 * hlse_file.c — File Masquerade Detector
 *
 * Detects files that pretend to be something they're not:
 *
 *   F1. Double extension        — invoice.pdf.exe, report.docx.scr
 *   F2. MIME/magic mismatch     — file claims .pdf but magic bytes say EXE
 *   F3. Executable disguise     — dangerous extension hidden by icon/name
 *   F4. Office macro presence   — .doc/.xls with VBA macro indicators
 *   F5. Scripted SVG            — <svg> carrying <script>/handlers
 *   F6. Suspicious filename     — social engineering lure names
 *   F7. ICS invite phishing     — VCALENDAR embedding malicious links
 *   F8. Launcher/shortcut       — .desktop/.url/.webloc payload carriers
 *   F9. Weaponized .lnk         — embedded interpreter/download command
 *   F10. NetNTLM leak           — shell-meta file referencing \\UNC/WebDAV
 *   F11. HTML smuggling         — script reassembling a payload client-side
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
#include "hlse_core.h"   /* hlse_check_url — embedded links are scored by
                        * the URL engine rather than reimplemented here */
#include "hlse_util.h"

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
    /* Reasons embed the filename under analysis; sanitise display-hostile
     * characters at the choke point. */
    hlse_sanitize_display(v->reasons[v->n_reasons]);
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
static const unsigned char MAGIC_7ZIP[] = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }; /* 7-Zip */
static const unsigned char MAGIC_CAB[]  = { 0x4D, 0x53, 0x43, 0x46 };   /* MSCF — Windows Cabinet */
static const unsigned char MAGIC_WASM[] = { 0x00, 0x61, 0x73, 0x6D };   /* \0asm — WebAssembly */
static const unsigned char MAGIC_SHEBANG[] = { 0x23, 0x21 };           /* #! — script shebang */
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
    { MAGIC_7ZIP,  6, "7ZIP" },
    { MAGIC_CAB,   4, "Cabinet" },
    { MAGIC_WASM,  4, "WebAssembly" },
    { MAGIC_PNG,   4, "PNG" },
    { MAGIC_JPG,   3, "JPEG" },
    { MAGIC_GIF,   4, "GIF" },
    { MAGIC_OLE,   4, "OLE" },
    { MAGIC_SHEBANG, 2, "Script" },
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

/* HTML has no single fixed magic byte — it may begin with "<!DOCTYPE html>",
 * "<html", "<head", "<script", or "<?xml" (for XHTML/SVG), possibly after a
 * UTF-8 BOM and/or leading whitespace, in any case. Detect it separately so
 * HTML-smuggling files wearing a document extension (invoice.pdf that is
 * really HTML) can be flagged. Returns 1 if the head looks like HTML/XML
 * markup with an HTML-ish tag.                                            */
static int
looks_like_html(const unsigned char *head, size_t len) {
    size_t i = 0;
    char low[64];
    size_t n = 0;
    /* Skip UTF-8 BOM */
    if (len >= 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF)
        i = 3;
    /* Skip leading whitespace */
    while (i < len && (head[i] == ' ' || head[i] == '\t' ||
                       head[i] == '\r' || head[i] == '\n'))
        i++;
    if (i >= len || head[i] != '<') return 0;
    /* Lowercase a small window starting at the '<' for case-insensitive cmp */
    for (; i < len && n < sizeof(low) - 1; i++)
        low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    return (strncmp(low, "<!doctype html", 14) == 0 ||
            strncmp(low, "<html", 5) == 0 ||
            strncmp(low, "<head", 5) == 0 ||
            strncmp(low, "<script", 7) == 0 ||
            strncmp(low, "<!-- ", 5) == 0 ||  /* HTML comment lead-in */
            strncmp(low, "<svg", 4) == 0);
}

/* ─── dangerous extensions ────────────────────────────────────────────── */

static const char *EXECUTABLE_EXTS[] = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js",  ".jse", ".wsf", ".wsh", ".msi", ".msp",
    ".pif", ".hta", ".cpl", ".inf", ".reg", ".lnk", ".shs",
    /* Linux/macOS */
    ".sh", ".bash", ".command", ".app", ".run",
    /* macOS installer packages */
    ".pkg", ".mpkg",
    /* Macro-enabled Office documents (bypass Mark-of-the-Web in many configs) */
    ".docm", ".xlsm", ".pptm", ".xlam", ".ppam", ".xlsb",
    /* Java */
    ".jar", ".class",
    /* Python */
    ".py", ".pyw",
    /* Web server-side — can execute on upload */
    ".php", ".php3", ".php5", ".phtml", ".asp", ".aspx", ".jsp",
    /* Scripting languages used as malware droppers */
    ".rb", ".pl", ".tcl", ".lua",
    /* Windows shared libraries — commonly used as sideload/injection payloads */
    ".dll",
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
    /* Windows Management / Script Component (msc duplicate-free) */
    ".msc",
    /* PowerShell XML formats */
    ".ps1xml", ".cdxml",
    /* Internet Shortcut (can embed URLs that auto-execute) */
    ".url",
    /* Linux/macOS launcher files — Exec=/URL payload carriers
     * (APT36 .desktop dropper campaign, Aug 2025) */
    ".desktop", ".webloc",
    /* Excel/Word add-ins — shellcode delivery vector via COM (2021-2023 spike) */
    ".xll", ".wll",
    /* Compiled HTML Help — executes embedded JScript via hhctrl.ocx */
    ".chm",
    /* Windows Script Component / Script Encoder */
    ".sct", ".wsc",
    /* Remote Desktop connection file — can auto-connect to attacker RDP */
    ".rdp",
    /* Windows Task Scheduler job (XML form: .job used in older style) */
    ".job",
    /* OneNote embedded-attachment execution (top phishing vector 2022-2023) */
    ".one", ".onetoc2",
    /* Disk-container MOTW bypass: ISO/IMG/VHD drop files without MOTW flag */
    ".iso", ".img", ".vhd", ".vhdx",
    /* Macro-enabled PowerPoint variants */
    ".ppsm", ".potm",
    /* Excel Internet Query — fetches and executes remote content when opened */
    ".iqy",
    /* Windows Theme/ThemeBleed (CVE-2023-38146): NTLM hash theft via UNC path */
    ".theme", ".themepack",
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
    /* Media containers — also passive data a user never expects to execute */
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".mkv", ".flac",
    ".epub", ".mobi",
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
    /* Tech-lure dropper names */
    "driver", "codec", "plugin", "extension",
    /* Software brand impersonation (OS/browser update lures) */
    "windows", "chrome", "firefox", "adobe", "flash", "java",
    "system", "microsoft", "google",
    /* Document lures */
    "proof", "memo", "form", "benefit",
    "leaked", "private", "confidential_",
    /* Additional corporate social-engineering lures */
    "readme", "report", "notification", "policy",
    "hr", "compliance", "legal", "notice",
    /* Malware attention names */
    "hacked", "breach", "exposed",
    /* Japanese */
    "請求書", "見積書", "納品書", "契約書", "確認",
    "給与明細", "年末調整",
    NULL
};

/* Scripted-SVG smuggling: an SVG that carries executable script. Most filters
 * treat SVG as a passive image, but an <svg> containing <script>, an inline
 * event handler (onload/onerror/onclick/onmouseover), a <foreignObject>, a
 * javascript: URI, or an embedded base64 payload is a top 2026 phishing-
 * delivery vector (MITRE ATT&CK T1027.017, Securelist SVG-phishing). Scans the
 * already-read first 4 KB case-insensitively. Fires regardless of extension
 * (a scripted SVG IS the attack), including for XML-declared SVGs that begin
 * with "<?xml ...?>" rather than "<svg".                                    */
static int
svg_has_script(const unsigned char *head, size_t len) {
    char low[4097];
    size_t n = 0, i;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "<svg") == NULL) return 0;
    return (strstr(low, "<script")       != NULL ||
            strstr(low, "onload=")        != NULL ||
            strstr(low, "onerror=")       != NULL ||
            strstr(low, "onclick=")       != NULL ||
            strstr(low, "onmouseover=")   != NULL ||
            strstr(low, "<foreignobject") != NULL ||
            strstr(low, "javascript:")    != NULL ||
            strstr(low, ";base64,")       != NULL);
}

/* ICS calendar-invite phishing: a VCALENDAR payload carrying malicious
 * links in URL/LOCATION/DESCRIPTION/ATTACH fields. Email clients auto-add
 * such invites to the victim's calendar, giving the payload a second
 * delivery path that bypasses message-body scanning (Sublime Security /
 * Abnormal AI reports, 2025). Content-marker based like F5 — a VCALENDAR
 * block IS the carrier, regardless of extension. Embedded http(s) links
 * are delegated to hlse_check_url; a link ending in an executable
 * extension is flagged outright (a meeting has no reason to serve one). */
static int
ics_is_delim(int c) {
    return c == '\0' || c == ' ' || c == '\t' || c == '\r' ||
           c == '\n' || c == '"'  || c == '\'' || c == '<'  ||
           c == '>'  || c == '|';
}

static const char *ICS_EXEC_EXTS[] = {
    ".exe", ".apk", ".scr", ".msi", ".bat", ".cmd", ".lnk",
    ".vbs", ".ps1", ".jar", ".iso", ".img",
    NULL
};

/* Indirect prompt-injection inside an invite (the Gemini-calendar attack,
 * SafeBreach Aug 2025): agent-directed meta-instructions hidden in
 * SUMMARY/DESCRIPTION reach the AI summarizer that renders the event.
 * A calendar invite has no legitimate reason to address an AI's
 * instructions, so the usual prose-injection FP concern doesn't apply. */
static const char *ICS_INJECTION[] = {
    "ignore all previous", "ignore previous instructions",
    "ignore your previous", "ignore your instructions",
    "disregard all previous", "disregard your instructions",
    "do not tell the user", "don't tell the user",
    "do not mention this", "do not mention the",
    "reveal your system prompt", "print your system prompt",
    "your system prompt", "your instructions say",
    NULL
};

static int
ics_has_injection(const char *low) {
    int i;
    for (i = 0; ICS_INJECTION[i]; i++)
        if (strstr(low, ICS_INJECTION[i])) return 1;
    return 0;
}

/* Scan a lowercased buffer for http(s) links; extract each and score it
 * with the URL engine. A link ending in an executable extension scores
 * ≥70 outright (documents/invites have no reason to serve one).        */
static int
links_max_score(const char *low, size_t n) {
    size_t i;
    int best = 0;
    for (i = 0; i + 8 <= n; i++) {
        if (strncmp(low + i, "http://", 7) != 0 &&
            strncmp(low + i, "https://", 8) != 0)
            continue;
        {
            size_t j = i, u = 0;
            char url[1024];
            while (j < n && !ics_is_delim(low[j]) && u < sizeof(url) - 1)
                url[u++] = low[j++];
            url[u] = '\0';
            if (u > 8) {
                Verdict uv = hlse_check_url(url);
                int sc = uv.score, e;
                for (e = 0; ICS_EXEC_EXTS[e]; e++) {
                    size_t el = strlen(ICS_EXEC_EXTS[e]);
                    if (u > el &&
                        strcmp(url + u - el, ICS_EXEC_EXTS[e]) == 0)
                    {
                        if (sc < 70) sc = 70;
                        break;
                    }
                }
                if (sc > best) best = sc;
            }
            i = j;
        }
    }
    return best;
}

/* Returns the highest embedded-link score in a VCALENDAR payload
 * (0 = clean / not ICS); sets *out_inj when agent-directed injection
 * phrasing is present.                                                */
static int
ics_suspicious_link(const unsigned char *head, size_t len, int *out_inj) {
    char low[4097];
    size_t n = 0, i;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    *out_inj = 0;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "begin:vcalendar") == NULL) return 0;
    if (ics_has_injection(low)) *out_inj = 1;
    return links_max_score(low, n);
}

/* Launcher/shortcut carriers: .desktop Exec= droppers (APT36, Aug 2025),
 * .url InternetShortcut and .webloc plist files carrying phishing links.
 * Content-marker based, like F5/F7. For .desktop the Exec= value is the
 * payload: download-and-execute is the documented dropper pattern.     */
static int
launcher_payload_score(const unsigned char *head, size_t len) {
    char low[4097];
    size_t n = 0, i;
    int best = 0, is_desktop, is_shortcut;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    is_desktop  = strstr(low, "[desktop entry") != NULL;
    is_shortcut = strstr(low, "[internetshortcut") != NULL ||
                  (strstr(low, "<plist") != NULL &&
                   strstr(low, "<key>url") != NULL);
    if (!is_desktop && !is_shortcut) return 0;
    best = links_max_score(low, n);
    /* Remote-resource references that never become http(s) links:
     * URL=\\host\share or IconFile=\\… pull from SMB/WebDAV the moment
     * Explorer renders the shortcut (the NetNTLM-leak pattern —
     * CVE-2025-24071 and the NCC .scf advisory); file:// targets
     * sidestep the URL engine's scheme check entirely. */
    if (strstr(low, "\\\\") != NULL || strstr(low, "webdav") != NULL ||
        strstr(low, "davwwwroot") != NULL) {
        if (best < 65) best = 65;
    } else if (strstr(low, "file://") != NULL) {
        if (best < 55) best = 55;
    }
    if (is_desktop) {
        const char *e = strstr(low, "exec=");
        if (e) {
            char ex[1024];
            size_t u = 0;
            int dl, shell;
            e += 5;
            while (*e && *e != '\n' && *e != '\r' && u < sizeof(ex) - 1)
                ex[u++] = *e++;
            ex[u] = '\0';
            dl = strstr(ex, "curl ")  != NULL || strstr(ex, "curl\t") ||
                 strstr(ex, "wget ")  != NULL || strstr(ex, "wget\t");
            shell = strstr(ex, "| sh")  != NULL || strstr(ex, "|sh")   ||
                    strstr(ex, "| bash") != NULL || strstr(ex, "|bash") ||
                    strstr(ex, "sh -c")  != NULL || strstr(ex, "bash -c");
            if (dl && (shell || strstr(ex, "/tmp/") != NULL ||
                       strstr(ex, "chmod") != NULL)) {
                if (best < 70) best = 70;   /* fetch → /tmp|pipe → exec */
            } else if (strstr(ex, "base64 -d") || strstr(ex, "base64 --decode") ||
                       strstr(ex, "xxd -r")     || strstr(ex, "openssl") ||
                       strstr(ex, "eval ")      || strstr(ex, "python -c") ||
                       strstr(ex, "perl -e")) {
                if (best < 55) best = 55;   /* opaque decode/exec */
            } else if (dl) {
                if (best < 35) best = 35;   /* bare download in launcher */
            }
        }
    }
    return best;
}

/* Windows Shell Link (.lnk) weaponization — the maldocs→LNK loader chain
 * (emotet/QakBot/APT dropper pattern): the shortcut's UTF-16LE command
 * line carries powershell -enc / cmd /c / mshta / certutil -urlcache /
 * a remote fetch. The header is 4C 00 00 00 followed by the fixed
 * LinkCLSID. We string-scan the header+strings region for interpreter
 * and download commands in both UTF-16LE and ASCII.                  */
static const unsigned char LNK_MAGIC[4] = { 0x4C, 0x00, 0x00, 0x00 };
static const unsigned char LNK_CLSID[16] = {
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};

static int
buf_has_utf16le(const unsigned char *buf, size_t len, const char *needle) {
    size_t nl = strlen(needle), i;
    if (len < nl * 2) return 0;
    for (i = 0; i + nl * 2 <= len; i += 2) {
        size_t k;
        for (k = 0; k < nl; k++) {
            int c = buf[i + k * 2];
            if (c >= 'A' && c <= 'Z') c += 32;   /* ASCII case fold */
            if (c != (unsigned char)needle[k] ||
                buf[i + k * 2 + 1] != 0)
                break;
        }
        if (k == nl) return 1;
    }
    return 0;
}

static int
buf_has_ascii(const unsigned char *buf, size_t len, const char *needle) {
    size_t nl = strlen(needle), i;
    if (len < nl) return 0;
    for (i = 0; i + nl <= len; i++) {
        size_t k;
        for (k = 0; k < nl; k++) {
            int c = buf[i + k];
            int nn = (unsigned char)needle[k];
            if (c >= 'A' && c <= 'Z') c += 32;
            if (nn >= 'A' && nn <= 'Z') nn += 32;
            if (c != nn) break;
        }
        if (k == nl) return 1;
    }
    return 0;
}

static const char *LNK_DANGEROUS[] = {
    "powershell", "-enc", "-encodedcommand", "cmd /c", "cmd.exe /c",
    "mshta", "wscript", "cscript", "rundll32", "regsvr32",
    "bitsadmin", "certutil", "wmic", "msbuild",
    "curl", "wget", "http://", "https://", "ftp://",
    "\\\\", "davwwwroot", "webdav", "file://",
    NULL
};

static int
lnk_weaponized(const unsigned char *head, size_t len) {
    size_t i;
    int hits = 0;
    if (len < 20) return 0;
    if (memcmp(head, LNK_MAGIC, 4) != 0 ||
        memcmp(head + 4, LNK_CLSID, 16) != 0)
        return 0;
    for (i = 0; LNK_DANGEROUS[i]; i++) {
        if (buf_has_utf16le(head, len, LNK_DANGEROUS[i]) ||
            buf_has_ascii(head, len, LNK_DANGEROUS[i]))
            hits++;
    }
    return hits;
}

/* Shell-metadata carriers whose icon/URL fields fetch remote resources
 * on render: desktop.ini ([.ShellClassInfo] + IconResource=), .scf
 * ([Shell] + IconFile=), .library-ms / .searchConnector-ms XML, and any
 * file carrying an IconFile=/IconUNC= key. A \\host\share UNC or WebDAV
 * reference makes Explorer contact the attacker share on VIEW — the
 * NetNTLM credential leak behind CVE-2025-24071 and the NCC .scf
 * advisory. Local icon paths (C:\…) contain no '\\' prefix and pass. */
static int
unc_leak_score(const unsigned char *head, size_t len) {
    char low[4097];
    size_t n = 0, i;
    int carrier;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    carrier = strstr(low, "[.shellclassinfo")          != NULL ||
              strstr(low, "[shell]")                  != NULL ||
              strstr(low, "<librarydescription")      != NULL ||
              strstr(low, "searchconnectordescription") != NULL ||
              strstr(low, "iconfile")                != NULL ||
              strstr(low, "iconresource")            != NULL ||
              strstr(low, "iconunc")                 != NULL;
    if (!carrier) return 0;
    if (strstr(low, "\\\\") != NULL) return 70;   /* UNC → SMB leak */
    if (strstr(low, "webdav") != NULL || strstr(low, "davwwwroot") != NULL)
        return 65;                              /* WebDAV redirector  */
    return 0;
}

/* HTML smuggling (Microsoft/Nobelium advisories, 2021+): an HTML
 * attachment whose inline script reassembles a payload client-side —
 * base64 via atob(), materialized through Blob/createObjectURL or
 * msSaveBlob, delivered via a download= attribute or a programmatic
 * click(). The payload never crosses the wire as a file, so gateway
 * scanning misses it; presence of the decode+materialize+deliver
 * pattern inside a <script> is the tell.                              */
static int
html_smuggling_score(const unsigned char *head, size_t len) {
    char low[4097];
    size_t n = 0, i;
    int m = 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "<script") == NULL) return 0;
    if (strstr(low, "atob(") != NULL ||
        strstr(low, "fromcharcode") != NULL) m++;
    if (strstr(low, "blob(") != NULL ||
        strstr(low, "createobjecturl") != NULL ||
        strstr(low, "mssaveblob") != NULL) m++;
    if (strstr(low, "download=") != NULL ||
        strstr(low, "download =") != NULL ||
        strstr(low, ".click()") != NULL) m++;
    if (m >= 2) return 65;
    if (m == 1 && strstr(low, ";base64,") != NULL) return 55;
    if (m == 1) return 35;
    return 0;
}

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
        /* HTML has no fixed magic byte; detect it only if nothing else hit. */
        if (!magic_type && looks_like_html(head, (size_t)head_len))
            magic_type = "HTML";
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
            (strcmp(magic_type, "GIF")         == 0 ||
             strcmp(magic_type, "JPEG")        == 0 ||
             strcmp(magic_type, "PNG")         == 0 ||
             strcmp(magic_type, "ZIP")         == 0 ||
             strcmp(magic_type, "GZIP")        == 0 ||
             strcmp(magic_type, "7ZIP")        == 0 ||
             strcmp(magic_type, "Cabinet")     == 0 ||
             strcmp(magic_type, "WebAssembly") == 0)) {
            fv_add(&v, 50,
                "F2: %s content with executable extension '%s' — "
                "possible polyglot/payload disguise", magic_type, ext);
        }
        /* WebAssembly binary masquerading as non-wasm — emerging attack vector */
        if (strcmp(magic_type, "WebAssembly") == 0 &&
            strcmp(ext, ".wasm") != 0 && strcmp(ext, ".wat") != 0) {
            fv_add(&v, 55,
                "F2: WebAssembly binary with extension '%s' — "
                "possible WASM payload disguise", ext);
        }
        /* Cabinet file with non-cab extension — common for dropper delivery */
        if (strcmp(magic_type, "Cabinet") == 0 &&
            strcmp(ext, ".cab") != 0 && strcmp(ext, ".msi") != 0) {
            fv_add(&v, 40,
                "F2: Windows Cabinet (MSCF) magic with extension '%s' — "
                "possible dropper disguise", ext);
        }
        /* Shebang (#!) script wearing a passive document/image extension —
         * e.g. "invoice.pdf" or "photo.jpg" that is really a runnable shell /
         * python / perl script. The victim double-clicks expecting inert data
         * and runs attacker code instead.                                  */
        if (strcmp(magic_type, "Script") == 0 &&
            (is_document_ext(ext) || is_image_ext(ext))) {
            fv_add(&v, 60,
                "F2: MAGIC MISMATCH — file has script shebang (#!) but "
                "extension '%s' implies passive data", ext);
        }
        /* HTML content wearing a document/image extension — HTML smuggling.
         * A "invoice.pdf" or "statement.doc" that is actually HTML opens in
         * the browser and can run embedded JS / reconstruct a payload from
         * an in-page blob (top phishing delivery vector 2023-2025).
         * (.svg is excluded here — an HTML/SVG file with an .svg extension is
         * not a masquerade; the script-in-SVG concern is separate.)         */
        if (strcmp(magic_type, "HTML") == 0 &&
            (is_document_ext(ext) || is_image_ext(ext)) &&
            strcmp(ext, ".svg") != 0 && strcmp(ext, ".html") != 0 &&
            strcmp(ext, ".htm") != 0) {
            fv_add(&v, 55,
                "F2: MAGIC MISMATCH — file is HTML but extension '%s' implies "
                "a document/image (possible HTML-smuggling phish)", ext);
        }
    }

    /* ── F5: Scripted-SVG smuggling ────────────────────────────────────
     * An SVG carrying <script>/event-handler/foreignObject/javascript:/
     * base64 payload. Extension-independent: unlike F2 (which excludes .svg
     * as a non-masquerade), a scripted SVG is itself the delivery vehicle. */
    if (head_len > 0 && svg_has_script(head, (size_t)head_len)) {
        fv_add(&v, 55,
            "F5: SCRIPTED SVG — image contains executable script "
            "(<script>/event handler/foreignObject) — SVG-smuggling phish");
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

    /* ZIP-based Office (docm/xlsm/pptm/ppsm/potm) — check for vbaProject.bin */
    if (magic_type && strcmp(magic_type, "ZIP") == 0) {
        char lower_ext[32];
        str_lower(ext, lower_ext, sizeof(lower_ext));
        if (strcmp(lower_ext, ".docm") == 0 ||
            strcmp(lower_ext, ".xlsm") == 0 ||
            strcmp(lower_ext, ".pptm") == 0 ||
            strcmp(lower_ext, ".ppsm") == 0 ||
            strcmp(lower_ext, ".potm") == 0)
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

    /* ── F7: Calendar-invite (ICS) phishing ────────────────────────── */
    if (head_len > 0) {
        int inj = 0;
        int ics = ics_suspicious_link(head, (size_t)head_len, &inj);
        if (inj) {
            fv_add(&v, 55,
                "F7: CALENDAR INVITE contains AI-directed instructions — "
                "indirect prompt injection delivered through an invite "
                "(Gemini-calendar attack)");
        }
        if (ics >= 40) {
            fv_add(&v, ics > 65 ? 65 : ics,
                "F7: CALENDAR INVITE embeds suspicious link "
                "(embedded URL score %d)", ics);
        }
    }

    /* ── F8: Launcher / shortcut carriers (.desktop/.url/.webloc) ──── */
    if (head_len > 0) {
        int lsc = launcher_payload_score(head, (size_t)head_len);
        if (lsc >= 40) {
            fv_add(&v, lsc > 65 ? 65 : lsc,
                "F8: LAUNCHER file runs remote download/command or links "
                "to a suspicious URL (score %d)", lsc);
        }
    }

    /* ── F9: Weaponized .lnk — script interpreter / download in the
     *      shortcut's embedded command line ───────────────────────── */
    if (head_len > 20) {
        int lnk_hits = lnk_weaponized(head, (size_t)head_len);
        if (lnk_hits >= 1) {
            fv_add(&v, lnk_hits >= 2 ? 70 : 60,
                "F9: .LNK shortcut embeds %d interpreter/download "
                "command%s — document-delivered loader pattern",
                lnk_hits, lnk_hits == 1 ? "" : "s");
        }
    }

    /* ── F10: UNC/WebDAV references in shell-meta carriers — viewing
     *      the file leaks NetNTLM credentials to a remote share ────── */
    if (head_len > 0) {
        int unc = unc_leak_score(head, (size_t)head_len);
        if (unc >= 40) {
            fv_add(&v, unc > 65 ? 65 : unc,
                "F10: SHELL-META file references a remote resource — "
                "viewing it leaks NetNTLM credentials over SMB/WebDAV "
                "(score %d)", unc);
        }
    }

    /* ── F11: HTML smuggling — script that reassembles a payload ───── */
    if (head_len > 0) {
        int smug = html_smuggling_score(head, (size_t)head_len);
        if (smug >= 40) {
            fv_add(&v, smug > 65 ? 65 : smug,
                "F11: HTML SMUGGLING — script decodes and delivers a "
                "payload client-side (atob/Blob/download pattern, "
                "score %d)", smug);
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
            else if (is_executable_ext(inner) && is_executable_ext(outer)) {
                fv_add(&v, 50,
                    "F1: Double executable extension '%s%s'",
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
