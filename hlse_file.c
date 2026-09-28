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
 *   F12. ZIP-slip               — archive member with ../ or absolute path
 *   F13. Credential-harvest form — HTML <form> posting a password to a
 *        remote absolute URL (fake-login attachment)
 *   F14-F21 — script cradles, .reg persistence, PDF/RTF auto-actions,
 *        rc-file persistence, reverse shells, <base>/meta-refresh
 *   F22. OOXML macro smuggling — vbaProject.bin inside a container
 *        named like a macro-free format (renamed .docm)
 *   F23-F24 — Makefile $(shell)/!= parse-time exec, Terraform
 *        external/provisioner plan-apply exec
 *   F25. Privileged K8s manifest — apiVersion/kind YAML requesting
 *        privileged containers, host namespaces, dangerous caps
 *   F26. docker-compose privilege — privileged/host-ns/docker.sock/
 *        host-root mounts in compose services
 *   F27. YAML unsafe-load tags — !!python/object, !ruby/, !!perl/
 *   F28. pickle/.pth exec — GLOBAL opcode to system/eval/subprocess,
 *        .pth import-line startup exec
 *   F29. autorun.inf — [autorun] open/shell self-execute keys
 *   F30. WPAD .pac hijack — FindProxyForURL returning remote PROXY
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
#include "hlse_secrets.h" /* hlse_check_email_headers — mail carrier
                           * forensics (F58)                          */
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
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1",
    ".psd1", ".pssc", ".psrc", ".vbs",
    ".vbe", ".js",  ".jse", ".mjs", ".cjs", ".ksh",
    ".wsf", ".wsh", ".ws",  ".msi", ".msp",
    /* AutoIt + VB6-era script carriers — .au3 is a classic dropper
     * language, .a3x its compiled form, .kix a KiXtart logon
     * script; .frm/.bas/.cls/.vbp carry executable VB6 code      */
    ".au3", ".a3x", ".kix", ".frm", ".bas", ".cls", ".vbp",
    /* Installer script carriers — NSIS (.nsi/.nsh), Inno Setup
     * (.iss/.isl), WiX (.wxs): all embed executable sections that
     * run on install and are abused as dropper delivery         */
    ".nsi", ".nsh", ".iss", ".isl", ".wxs",
    /* ClickOnce deployment manifest — the sibling of .application
     * that carries the payload reference                        */
    ".manifest",
    /* Server-side code carriers — global.asa runs ASP session/
     * application events, .inc is a script-include that executes
     * inline, .plx is a Perl executable script                  */
    ".asa", ".inc", ".plx",
    /* Visio stencil/template carriers (OLE objects; .vstm is the
     * macro-enabled template) + Excel toolbar (.xlb) and legacy
     * Excel-4 macro variants (.xlv) — .xlm already listed        */
    ".vss", ".vssx", ".vst", ".vstm", ".vstx", ".xlb", ".xlv",
    ".pif", ".hta", ".cpl", ".inf", ".reg", ".lnk", ".shs",
    /* Linux/macOS */
    ".sh", ".bash", ".command", ".app", ".run",
    /* Alternate shells — zsh/fish/nushell scripts execute on open
     * in the same class as .sh/.bash                        */
    ".zsh", ".fish", ".nu",
    /* awk/sed script files — awk's system()/| getline and sed's e
     * command execute arbitrary shell                     */
    ".awk", ".sed",
    /* macOS installer packages + Safari web archive (bundled live
     * web content incl. scripts — attachment lure vector) */
    ".pkg", ".mpkg", ".webarchive",
    /* macOS script/automation carriers — .scpt/.scptd are compiled
     * AppleScript (exec on open), .osax is a Scripting Addition
     * (legacy persistence), .workflow/.wflow are Automator action
     * bundles that run their steps on double-click            */
    ".scpt", ".scptd", ".applescript", ".osax",
    ".workflow", ".wflow",
    /* Remaining disk-image carriers — mounting one runs autorun /
     * drops a writable filesystem the OS trusts more than a bare
     * download (.dmg macOS, .vmdk/.qcow2 VM, .toast/.sparseimage/
     * .flp/.ima legacy/floppy images)                          */
    ".dmg", ".vmdk", ".qcow2", ".toast", ".sparseimage",
    ".flp", ".ima",
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
    /* Remaining macro/template Office carriers — .dotm/.xltm/.sldm are
     * macro-enabled templates, .docb is the binary .docm counterpart  */
    ".dotm", ".xltm", ".sldm", ".docb",
    /* Legacy/lesser Office attack surface — Access databases carry VBA
     * + autoexec macros, Visio/Publisher files embed OLE objects,
     * .wpd is WordPerfect (OLE object carrier); .rtf stays on the
     * safe-extension list — its exploits are caught by the content
     * check (rtf_embed_score) rather than the name alone           */
    ".mdb", ".accdb", ".vsdx", ".vsdm", ".pub", ".wpd",
    /* Excel Internet Query — fetches and executes remote content when opened */
    ".iqy",
    /* Jupyter notebook — code cells run on execution and output cells
     * can carry executable HTML/JS that renders on open            */
    ".ipynb",
    /* Office Data Connection — OLE DB connection string + command
     * text drives queries against attacker-controlled backends    */
    ".odc",
    /* Windows Theme/ThemeBleed (CVE-2023-38146): NTLM hash theft via UNC path */
    ".theme", ".themepack", ".deskthemepack",
    /* Explorer/library/search hijack files — .library-ms forces Explorer
     * onto an attacker-controlled WebDAV share (CVE-2024-38112 class),
     * .search-ms drives Explorer searches against remote shares,
     * .settingcontent-ms executes DeepLink commands (CVE-2018-8414)   */
    ".library-ms", ".search-ms", ".settingcontent-ms",
    /* Shell Command File — IconFile can point at a remote share,
     * harvesting NetNTLM on folder open                               */
    ".scf",
    /* Windows Sidebar gadget / pinned-site shortcut — both auto-resolve
     * remote package resources on open                                */
    ".gadget", ".website",
    /* ClickOnce application reference — used in the SolarWinds-era
     * loader chain to bootstrap remote payloads                        */
    ".appref-ms",
    /* PostScript / Windows metafile carriers — .ps/.eps are a full
     * programming language whose renderer (Ghostscript/macOS Preview)
     * has a rich RCE history; .wmf/.emf metafiles carry executable
     * Escape records (MS05-053 class)                                */
    ".ps", ".eps", ".wmf", ".emf",
    /* Windows deployment-image carriers — .esd (Electronic Software
     * Delivery) and .ffu (Full Flash Update) are WIM-class install
     * images that drop arbitrary payloads (.wim already listed)    */
    ".esd", ".ffu",
    /* Legacy help/archive containers — .hlp is WinHelp (winhlp32 exploit
     * surface, executables embedded in help topics); .cab is a Windows
     * install/extraction container; .ace/.arj/.lha/.lzh/.zoo are obsolete
     * archives still seen as mail-borne executable wrappers (.lzh/.lha
     * historically favored in JP-targeted campaigns); .uue is uuencoded
     * binary content — a transport for executable payloads              */
    ".hlp", ".cab", ".ace", ".arj", ".lha", ".lzh", ".zoo", ".uue",
    /* VSTO Office add-in deployment manifest — ClickOnce-installs a
     * managed add-in on open (Office-side code exec); .accde is a
     * compiled-locked Access DB (VBA + autoexec like .mdb/.accdb)    */
    ".vsto", ".accde",
    /* .accda is a compiled Access add-in — same VBA/autoexec surface
     * as .accde/.mdb/.accdb (the .laccdb lock file is a transient
     * byproduct, not a carrier, and stays unlisted)                */
    ".accda",
    /* MIME-HTML saved web pages (.mht/.mhtml) — bundled live web
     * content incl. scripts; IE-mode / legacy Edge execute embedded
     * script on open, making them documented mail-borne lures      */
    ".mht", ".mhtml",
    /* Hangul Word Processor — OLE/BAT-embedded script carrier used
     * heavily in KR-targeted lure documents (.hwp/.hwpx)           */
    ".hwp", ".hwpx",
    /* Windows app packages — MSIX/AppX sideload an installed app
     * (AppX signature-spoof chain, CVE-2021-43890; Emotet/BazarLoader
     * used .appx as the installer carrier)                        */
    ".appx", ".appxbundle", ".msix", ".msixbundle",
    /* Android split/bundle packages — same sideload class as .apk
     * (bundled APK sets sideload additional code)                  */
    ".xapk", ".apks", ".apkm",
    /* Apple signing carrier — .provisioningprofile is the
     * enterprise-sideload signing artifact (ad-hoc app install);
     * .mobileconfig stays content-gated in the MOBILECONFIG rule
     * (wifi profiles are benign, root-CA/vpn payloads flag)        */
    ".provisioningprofile",
    /* Linux package-install reference / ClickOnce manifest pointer
     * — flatpakref resolves to a remote repo+app install (sandbox
     * escapes notwithstanding), .deploy is the ClickOnce deployment
     * manifest sibling of .application                             */
    ".flatpakref", ".deploy",
    /* VM appliance / disk-image carriers — mounting one runs a full
     * machine/image payload; same class as .vhd/.iso/.dmg          */
    ".ova", ".ovf", ".wim", ".vdi",
    /* ActiveX / MSI transform — .ocx is a loadable COM code object
     * (legacy web-embed exec), .mst applies with an MSI install    */
    ".ocx", ".mst",
    /* Legacy Office carriers — .xla is the 97-2003 Excel add-in
     * (VBA project inside), .ade/.adp are compiled Access project
     * files that run VBA without showing source                  */
    ".xla", ".ade", ".adp",
    /* 97-2003 macro-bearing Office forms: .xlm = Excel 4.0 macro
     * sheet (macro-malware classic), .ppa = PowerPoint add-in,
     * .dot/.xlt/.pot = legacy templates that can carry VBA       */
    ".xlm", ".ppa", ".dot", ".xlt", ".pot",
    /* Message containers — .eml/.msg ship a full email (with its
     * own links and attachments) inside an attachment; the classic
     * 'invoice.eml' phishing carrier                             */
    ".eml", ".msg",
    /* Outlook message carriers — .otm is a VBA-macro-capable mail
     * template, .oft a custom form with script handlers, .nws the
     * OE news-message sibling of .eml                              */
    ".otm", ".oft", ".nws",
    /* S/MIME message carriers — .p7m is an enveloped (encrypted)
     * message with full attachments inside, .p7s a detached
     * signature that gives a lure a 'signed' veneer              */
    ".p7m", ".p7s",
    /* Cursor payloads — .ani animated cursors parse on preview
     * (historic ANIH exploit class, still parsed by the shell);
     * .cur is the static sibling                                  */
    ".cur", ".ani",
    /* Ichitaro documents (.jtd/.jtt) — the dominant JP-document
     * APT carrier class (historic Ichitaro zero-days; the format
     * parses OLE/structured content on open)                      */
    ".jtd", ".jtt",
    /* Web-shell / server-side handler carriers — .ashx/.asmx/.svc
     * are IIS handler+service extensions (the classic ASP.NET web
     * shell shapes alongside .aspx); .jspf is the JSP fragment
     * form; .war deploys servlets; .cgi/.wsgi are gateway entries;
     * .cfm/.cfc/.cfr are ColdFusion (routinely exploited);
     * .do/.action are Struts mappings (Struts exploit class)     */
    ".jspf", ".ashx", ".asmx", ".svc", ".war", ".cgi",
    ".cfm", ".cfc", ".cfr", ".do", ".action", ".wsgi",
    /* Windows Contacts — .contact/.group resolve IconPaths over
     * UNC (credential-leak class); .desklink is the send-to
     * launcher sibling. .msu runs wusa.exe package installs     */
    ".contact", ".group", ".desklink", ".msu",
    /* InfoPath + OneNote package + RDM — .xsn/.xsf form templates
     * carry script code and external data connections; .onepkg is
     * the OneNote packaged carrier; .rdg hands a session list to
     * the remote-desktop manager                                   */
    ".xsn", ".xsf", ".onepkg", ".rdg",
    /* Compiled AppleScript (.osa runs under osascript) and the
     * macOS flat-package installer variant (.fpkg feeds the
     * same Installer.app path as .pkg)                            */
    ".osa", ".fpkg",
    /* Font carriers — raster/bitmap/PostScript fonts parse inside
     * font engines and the X server (historic font-parsing
     * exploit class; .ttf/.otf stay out as everyday formats)     */
    ".fon", ".fnt", ".pfa", ".pfb", ".bdf", ".pcf", ".snf",
    /* .appinstaller is the MSIX URI-handler manifest — feeds
     * ms-appinstaller straight into Installer.app from a click
     * (the CVE-2021-43890 spoof chain used by Emotet/BazarLoader) */
    ".appinstaller",
    /* .udl — Microsoft OLE DB Data Link: double-click opens a
     * connection-string dialog that can carry provider strings
     * reaching remote SMB/NTLM endpoints (credential-relay lure) */
    ".udl",
    /* .prf — Outlook profile file: importing it silently registers
     * attacker-controlled mail accounts/servers (credential +
     * persistence channel)                                          */
    ".prf",
    /* .diagcab — Windows diagnostics cabinet: launches msdiag.exe
     * troubleshooters that can stage arbitrary executables (a real
     * malspam carrier; distinct from the plain .cab archive)      */
    ".diagcab",
    /* .diagpkg — same diagnostics-package family (msdiag.exe);
     * .jnlp — Java Web Start descriptor: references a remote jar and
     * hands javaws an arbitrary download+launch instruction;
     * .xaml — WPF/workflow markup whose ObjectDataProvider can run
     * arbitrary methods (markup-embedded code execution)          */
    ".diagpkg", ".jnlp", ".xaml",
    /* .ipsw — iOS restore image (forced-downgrade / profile-injection
     * carrier); .sparsebundle — macOS disk-image bundle, same risk
     * class as .dmg                                                */
    ".ipsw", ".sparsebundle",
    /* Media playlist/redirector carriers — a playlist that references
     * a remote stream is a documented malspam redirector (.wvx is a
     * Windows Media metafile; .m3u/.m3u8/.pls/.vlc can carry remote
     * URLs a media player will dereference)                         */
    ".wvx", ".wax", ".m3u", ".m3u8", ".pls", ".vlc",
    /* Linux app-installer bundles — .flatpak/.snap carry arbitrary
     * executables (same delivery class as .appx/.msi on Windows)   */
    ".flatpak", ".snap",
    /* .zipx — WinZip extended archive (same archive-carrier class
     * as .zip/.rar/7z already flagged)                              */
    ".zipx",
    /* .shb — Windows ShellScrap object file (a documented malware
     * carrier: a shortcut binary that runs a command on drag/
     * preview)                                                     */
    ".shb",
    /* .wbk — Word auto-backup copy (a full .doc clone that can
     * carry macros; emailed as an innocuous-looking attachment)    */
    ".wbk",
    /* OpenDocument / legacy StarOffice templates — .ots/.ott/.otg/
     * .stw are macro-capable templates delivered as attachments    */
    ".ots", ".ott", ".otg", ".stw",
    /* StarOffice/OpenOffice 1.x legacy formats — pre-ODF siblings of
     * .ods/.odt that carry macros + OLE objects the same way       */
    ".sxc", ".sxi", ".sdd", ".sxw", ".sxm",
    /* Niche ODF carriers — .odg/.odb/.odf (draw/database/formula)
     * are macro-capable and rare enough to flag; .odt/.ods/.odp
     * stay on the safe list alongside .docx/.xlsx/.pptx          */
    ".odg", ".odb", ".odf",
    /* MS Access project/macro carriers — .mad/.maf/.mam/.maq/.mat/
     * .maw are Access containers that can carry VBA (same carrier
     * class as .mdb/.accdb already flagged)                        */
    ".mad", ".maf", ".mam", ".maq", ".mat", ".maw",
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
    if (is_shortcut) {
        /* A shortcut's URL= value is opened verbatim by Explorer/the
         * browser: script and MIME/ITS-help schemes are execution
         * primitives that never pass through the http(s) link scan. */
        if (strstr(low, "javascript:") || strstr(low, "vbscript:") ||
            strstr(low, "jscript:")    || strstr(low, "data:text/html") ||
            strstr(low, "ms-its")      || strstr(low, "mk:@msitstore") ||
            strstr(low, "mhtml:")) {
            if (best < 65) best = 65;
        }
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
              strstr(low, "iconunc")                 != NULL ||
              /* Windows .theme — ThemeBleed/CVE-2024-38030 class:
               * [Theme]/[Slideshow] sections carry Wallpaper=,
               * ItemNPath= or ImagesRootPIDL values that may point
               * at a remote UNC and leak NetNTLM on load.         */
              strstr(low, "[theme]")                 != NULL ||
              strstr(low, "[slideshow]")             != NULL ||
              strstr(low, "[visualstyles]")          != NULL ||
              strstr(low, "wallpaper=")              != NULL ||
              strstr(low, "imagesrootpidl")          != NULL ||
              /* freedesktop `.desktop`/KDE `.directory` files — Icon=
               * or Exec= pointing at \\host\share leaks NetNTLM on
               * folder view, same class as desktop.ini/scf         */
              strstr(low, "[desktop entry]")         != NULL ||
              strstr(low, "icon=")                   != NULL;
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

/* Credential-harvest form (classic phishing attachment, Cofense/
 * Microsoft reports): an HTML file carrying a <form> whose action
 * posts credentials to an absolute remote URL plus a password input —
 * the standalone "fake login page" shipped as an attachment. The form
 * needs no script: it renders and submits with nothing but the file.
 * FP guard: relative action targets and forms without a password
 * field stay clean.                                                */
static int
credential_form_score(const unsigned char *head, size_t len) {
    char low[4097];
    size_t n = 0, i;
    const char *a;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "<form") == NULL) return 0;
    /* password capture is the tell: an input typed password, or the
     * literal word inside the form's field set */
    if (strstr(low, "password") == NULL &&
        strstr(low, "passwd") == NULL) return 0;
    /* action must be present and absolute http(s) — a relative action
     * posts back to the hosting site (normal behaviour) */
    a = strstr(low, "action=");
    if (!a) a = strstr(low, "action =");
    if (!a) return 0;
    a = strchr(a, '=') + 1;
    while (*a == ' ' || *a == '\t') a++;
    if (*a == '"' || *a == '\'') a++;
    if (strncmp(a, "http://", 7) != 0 && strncmp(a, "https://", 8) != 0)
        return 0;
    return 55;
}

/* Script download-cradles (MITRE T1059/T1105): the dominant shape of
 * real-world droppers — an interpreter fetches and executes a remote
 * or encoded second stage. In a script-extension file any single
 * cradle term is suspicious; for other extensions we require a
 * fetch+execute PAIR so documentation/mentions stay clean.
 * Encoded-command flags (-enc/-e/-ec, FromBase64String) are standalone
 * obfuscation tells in script files.                               */
static int
is_script_ext(const char *ext) {
    static const char *const S[] = {
        ".ps1", ".psm1", ".psd1", ".ps1xml", ".pssc", ".psrc",
        ".bat", ".cmd", ".vbs", ".vbe", ".js",
        ".jse", ".mjs", ".cjs", ".ksh", ".wsf", ".wsh", ".ws",
        ".hta", ".sh", ".py", ".reg", ".au3", ".a3x", ".kix",
        ".nsi", ".nsh", ".iss", ".isl", ".wxs", ".manifest",
        ".asa", ".inc", ".plx", ".vss", ".vssx", ".vst",
        ".vstm", ".vstx", ".xlb", ".xlv",
        NULL
    };
    char lower[32];
    int i;
    if (!ext) return 0;
    str_lower(ext, lower, sizeof(lower));
    for (i = 0; S[i]; i++)
        if (strcmp(lower, S[i]) == 0) return 1;
    return 0;
}

static int
script_cradle_score(const unsigned char *head, size_t len,
                    const char *ext) {
    static const char *const FETCH[] = {
        "downloadstring", "downloadfile", "net.webclient",
        "invoke-webrequest", "invoke-restmethod", "curl ",
        "wget ", "bitsadmin", "certutil", "invoke-expression http",
        "iex http", "start-bitstransfer", NULL
    };
    static const char *const EXEC[] = {
        "invoke-expression", "iex(", "iex ", "invoke-command",
        "wscript.shell", "powershell", "cmd /c", "cmd.exe /c",
        "rundll32", "regsvr32", "mshta", "start-process",
        "| sh", "|sh", "| bash", "|bash", "| python", "eval(",
        "os.system", "subprocess", NULL
    };
    static const char *const OBFUSC[] = {
        "frombase64string", "encodedcommand", "-w hidden",
        "-windowstyle hidden", "-ep bypass", "executionpolicy bypass",
        "-nop ", "-nope", NULL
    };
    char low[4097];
    size_t n = 0, i;
    int nf = 0, ne = 0, no = 0, script, enc_cmd = 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    for (i = 0; FETCH[i]; i++) if (strstr(low, FETCH[i])) nf++;
    for (i = 0; EXEC[i]; i++) if (strstr(low, EXEC[i])) ne++;
    for (i = 0; OBFUSC[i]; i++) if (strstr(low, OBFUSC[i])) no++;
    /* `-enc`/`-e`/`-ec` is ALSO the abbreviation for -Encoding in
     * benign scripts — only flag when followed by a long base64 run
     * (the actual encoded-command payload).                          */
    {
        const char *ec = low;
        while ((ec = strstr(ec, "-e")) != NULL) {
            const char *a;
            int run = 0;
            if (!(ec[2] == 'n' && ec[3] == 'c') &&
                !(ec[2] == 'c' && (ec[3] == ' ' || ec[3] == '\t')) &&
                !(ec[2] == ' ' || ec[2] == '\t')) { ec += 2; continue; }
            a = ec + 2;
            while (*a == 'n' || *a == 'c' || *a == ' ' ||
                   *a == '\t' || *a == '"') a++;
            while ((a[run] >= 'A' && a[run] <= 'Z') ||
                   (a[run] >= 'a' && a[run] <= 'z') ||
                   (a[run] >= '0' && a[run] <= '9') ||
                   a[run] == '+' || a[run] == '/' || a[run] == '=')
                run++;
            if (run >= 16) enc_cmd = 1;
            ec += 2;
        }
    }
    if (nf == 0 && ne == 0 && no == 0 && !enc_cmd) return 0;
    script = is_script_ext(ext);
    if (nf >= 1 && ne >= 1) return script ? 65 : 55;
    if (script && nf >= 1) return 55;
    if (enc_cmd) return script ? 60 : 50;
    if (script && no >= 1 && (nf >= 1 || ne >= 1)) return 60;
    if (script && no >= 1) return 45;
    if (no >= 1 && ne >= 1) return 50;
    return 0;
}

/* .reg persistence: a registry script that writes an autostart or
 * debugger-hijack key. Run/RunOnce/IFEO/Winlogon keys are the classic
 * surviving-reboot primitive; a .reg attachment installing one is a
 * near-unambiguous persistence attempt (double-click → silent merge). */
static int
reg_persistence_score(const unsigned char *head, size_t len,
                      const char *ext) {
    char low[4097];
    size_t n = 0, i;
    if (!ext) return 0;
    {   char e[32];
        str_lower(ext, e, sizeof(e));
        if (strcmp(e, ".reg") != 0) return 0;
    }
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "hkey") && !strstr(low, "hkcu") &&
        !strstr(low, "hklm") && !strstr(low, "hkcr") &&
        !strstr(low, "hk_u") && !strstr(low, "hku"))
        return 0;
    if (strstr(low, "\\run") || strstr(low, "runonce") ||
        strstr(low, "image file execution options") ||
        strstr(low, "debugger") || strstr(low, "winlogon") ||
        strstr(low, "userinit") || strstr(low, "shell\\"))
        return 65;
    return 0;
}

/* PDF auto-actions (Adobe/Foxit phishing advisories): document-level
 * triggers that run JavaScript or launch a program when the file is
 * merely opened — /OpenAction, /AA (additional actions), /JS +
 * /JavaScript, /Launch, /EmbeddedFile. A receipt/invoices PDF that
 * phishes needs no exploit: open == run. FP guard: requires the %
 * PDF magic AND an action keyword, not just the word in prose.      */
static int
pdf_action_score(const unsigned char *head, size_t len) {
    char low[4097];
    size_t n = 0, i;
    int act = 0, payload = 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    if (len < 5 || memcmp(head, "%PDF-", 5) != 0) return 0;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "/openaction") || strstr(low, "/aa ") ||
        strstr(low, "/aa<") || strstr(low, "/aa/"))
        act++;
    if (strstr(low, "/launch") || strstr(low, "/embeddedfile") ||
        strstr(low, "/embeddedfiles"))
        payload++;
    if (strstr(low, "/js") || strstr(low, "/javascript"))
        payload++;
    if (act && payload) return 65;
    if (payload >= 2) return 60;   /* embedded file + JS, no open hook */
    if (payload == 1) return 40;   /* latent capability, no trigger */
    return 0;
}

/* RTF object embedding (CVE-2017-11882 family, still shipping in 2024+
 * phishing): \objdata carries an OLE object payload; \*\template with
 * a URL fetches a remote DOT on open ("template injection" — loads
 * the malicious doc from the attacker server, bypassing attachment
 * sandboxes). {\pict + .exe/.dll bytes is the file-embed variant.   */
static int
rtf_embed_score(const unsigned char *head, size_t len) {
    char low[4097];
    size_t n = 0, i;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    if (len < 5 || memcmp(head, "{\\rtf", 5) != 0) return 0;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "\\objdata") || strstr(low, "\\objocx") ||
        strstr(low, "\\objclass"))
        return 65;
    if (strstr(low, "\\*\\template") &&
        (strstr(low, "http:") || strstr(low, "https:") ||
         strstr(low, "\\\\")))
        return 65;
    if (strstr(low, "\\*\\objdata") || strstr(low, "\\object"))
        return 40;
    return 0;
}

/* ZIP-slip (Snyk disclosure, CVE-2018-1002200 family): a member name
 * inside a ZIP archive carrying a `..` path segment, an absolute path,
 * or a drive letter escapes the extraction directory on unpack. The
 * local-file-header walk stays inside the bounded head buffer and
 * resyncs on the next PK\x03\x04 signature when a compressed size of 0
 * (streaming write) can't be trusted to skip the data.               */
static int
zip_name_is_traversal(const unsigned char *name, size_t nl) {
    size_t i;
    if (nl >= 1 && (name[0] == '/' || name[0] == '\\')) return 1;
    if (nl >= 2 && name[1] == ':' &&
        ((name[0] | 0x20) >= 'a' && (name[0] | 0x20) <= 'z')) return 1;
    for (i = 0; i + 1 < nl; i++) {
        if (name[i] == '.' && name[i + 1] == '.' &&
            (i == 0 || name[i - 1] == '/' || name[i - 1] == '\\') &&
            (i + 2 == nl || name[i + 2] == '/' || name[i + 2] == '\\'))
            return 1;                     /* ../ or ..\ segment       */
    }
    return 0;
}

static int
zip_slip_score(const unsigned char *head, size_t len, int *vba_seen) {
    size_t off = 0;
    if (vba_seen) *vba_seen = 0;
    if (len < 30 || memcmp(head, MAGIC_ZIP, 4) != 0) return 0;
    while (off + 30 <= len && memcmp(head + off, MAGIC_ZIP, 4) == 0) {
        unsigned nl = (unsigned)head[off + 26] |
                      ((unsigned)head[off + 27] << 8);
        unsigned el = (unsigned)head[off + 28] |
                      ((unsigned)head[off + 29] << 8);
        unsigned long cs = (unsigned long)head[off + 18] |
                      ((unsigned long)head[off + 19] << 8) |
                      ((unsigned long)head[off + 20] << 16) |
                      ((unsigned long)head[off + 21] << 24);
        size_t noff = off + 30;
        if (noff + nl > len) break;
        if (vba_seen && nl >= 14) {
            /* basename match on the last path segment — word/
             * vbaProject.bin is the VBA project member            */
            const unsigned char *nm = head + noff;
            size_t base = nl;
            size_t i;
            for (i = 0; i < nl; i++)
                if (nm[i] == '/' || nm[i] == '\\') base = i + 1;
            if (nl - base == 14) {
                static const char VBA[] = "vbaProject.bin";
                size_t k;
                int same = 1;
                for (k = 0; k < 14; k++)
                    if ((nm[base + k] | 0x20) !=
                        (unsigned char)(VBA[k] | 0x20)) {
                        same = 0;
                        break;
                    }
                if (same) *vba_seen = 1;
            }
        }
        if (zip_name_is_traversal(head + noff, nl)) return 70;
        noff += nl + el;
        if (cs == 0) {
            /* data-descriptor entry: resync on the next local header */
            size_t j = noff;
            off = len;                       /* stop unless resynced */
            while (j + 30 <= len) {
                if (memcmp(head + j, MAGIC_ZIP, 4) == 0) { off = j; break; }
                j++;
            }
        } else {
            off = noff + cs;
        }
    }
    return 0;
}

/* ─── main check function ─────────────────────────────────────────────── */

/* ─── F18: rc/persistence-file content ────────────────────────────────
 * Filenames that a shell, sshd, or git reads automatically on every
 * login/commit — a single line in .bashrc/.zshrc/.gitconfig/
 * authorized_keys/crontab is a code-exec persistence primitive
 * (LD_PRELOAD userland rootkits, PROMPT_COMMAND hooks, core.hooksPath
 * redirect — the GitBless class, authorized_keys forced-command).
 * Filename-keyed: the same lines in an arbitrary file are inert.    */
static int
is_rc_persist_name(const char *basename) {
    static const char *const names[] = {
        ".bashrc", ".zshrc", ".zshenv", ".bash_profile", ".zprofile",
        ".profile", ".bash_login", ".kshrc", "profile", "crontab",
        "authorized_keys", "authorized_keys2", ".gitconfig",
        ".envrc", "config", NULL
    };
    char low[64];
    int i;
    str_lower(basename, low, sizeof(low));
    for (i = 0; names[i]; i++)
        if (strcmp(low, names[i]) == 0) return 1;
    /* kubeconfig / *.kubeconfig — dropped kubeconfigs carry cluster
     * creds and exec plugins that run on every kubectl call      */
    if (strstr(low, "kubeconfig") != NULL) return 1;
    return 0;
}

static int
rc_persist_score(const unsigned char *head, size_t len,
                 const char *basename, const char *filepath) {
    char low[4097];
    size_t n = 0, i;
    int sc = 0;
    int ssh_rc = 0;
    const char *dotgit;
    /* .ssh/rc + .ssh/environment are not rc-named but sshd sources
     * them on every login (PermitUserRC) — the path is the carrier */
    if (!is_rc_persist_name(basename)) {
        char lb[64], lp[512];
        str_lower(basename, lb, sizeof(lb));
        str_lower(filepath, lp, sizeof(lp));
        if (strstr(lp, ".ssh/") != NULL &&
            (strcmp(lb, "rc") == 0 || strcmp(lb, "environment") == 0))
            ssh_rc = 1;
        else
            return 0;
    }
    /* a plain `config` only counts inside .git/, .ssh/, .aws/, .kube/
     * or .docker/ (systemd unit files and other `config` basenames
     * stay out) */
    {
        char lown[64];
        str_lower(basename, lown, sizeof(lown));
        if (strcmp(lown, "config") == 0) {
            char lp[512];
            str_lower(filepath, lp, sizeof(lp));
            if (strstr(lp, ".git/") == NULL &&
                strstr(lp, ".ssh/") == NULL &&
                strstr(lp, ".aws/") == NULL &&
                strstr(lp, ".kube/") == NULL &&
                strstr(lp, ".docker/") == NULL)
                return 0;
        }
    }
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    /* userland rootkit primitives — env-var injection into every
     * future process */
    if (strstr(low, "ld_preload") || strstr(low, "dyld_insert") ||
        strstr(low, "ld_library_path") || strstr(low, "ld_audit"))
        return 65;
    /* .ssh/rc is a shell script run on every sshd login;
     * .ssh/environment injects vars into every sshd session —
     * BASH_ENV/Perl/Python env hooks there are the same primitive
     * as LD_PRELOAD in a shell rc                                  */
    if (ssh_rc) {
        if (strstr(low, "bash_env") || strstr(low, "perl5opt") ||
            strstr(low, "pythoninspect") || strstr(low, "perl5lib") ||
            strstr(low, "curl") || strstr(low, "wget") ||
            strstr(low, "sh -c") || strstr(low, "/bin/") ||
            strstr(low, "system") || strchr(low, '`') ||
            strstr(low, "$(") || strstr(low, "nc "))
            return 55;
    } else if (strstr(low, "bash_env") || strstr(low, "perl5opt") ||
               strstr(low, "pythoninspect"))
        sc = sc < 55 ? 55 : sc;
    /* shell hook / alias hijack */
    if (strstr(low, "prompt_command") || strstr(low, "precmd") ||
        strstr(low, "alias sudo") || strstr(low, "alias ssh") ||
        strstr(low, "trap ") )
        sc = sc < 55 ? 55 : sc;
    /* git config redirects (GitBless: core.hooksPath → attacker dir,
     * core.sshCommand → attacker wrapper, url.insteadOf → host swap) */
    dotgit = strstr(low, "hookspath");
    if (dotgit || strstr(low, "hooks.path")) {
        sc = sc < 60 ? 60 : sc;
    }
    if (strstr(low, "sshcommand"))
        sc = sc < 45 ? 45 : sc;
    if (strstr(low, "insteadof"))
        sc = sc < 50 ? 50 : sc;
    /* authorized_keys options that force a command or open tunnels */
    if (strstr(low, "ssh-rsa") || strstr(low, "ssh-ed25519") ||
        strstr(low, "ecdsa-sha2")) {
        if (strstr(low, "command=") || strstr(low, "environment=") ||
            strstr(low, "permitopen") || strstr(low, "permitlisten") ||
            strstr(low, "permituserenv"))
            sc = sc < 50 ? 50 : sc;
    }
    /* ssh client config — ProxyCommand/LocalCommand run a program on
     * connect; `Match exec` is the same primitive (CVE-2023-51385
     * class); PermitLocalCommand+LocalCommand is the dormant pair */
    if (strstr(low, "proxycommand") || strstr(low, "localcommand") ||
        strstr(low, "match exec"))
        sc = sc < 55 ? 55 : sc;
    if (strstr(low, "permitlocalcommand"))
        sc = sc < 40 ? 40 : sc;
    /* aws/kube credential-execution hooks — `credential_process` (aws)
     * and an `exec:` block carrying `command:` (kubeconfig exec plugin)
     * run an external program on every SDK/kubectl auth */
    if (strstr(low, "credential_process"))
        sc = sc < 55 ? 55 : sc;
    if (strstr(low, "exec:") && strstr(low, "command:"))
        sc = sc < 55 ? 55 : sc;
    /* kubeconfig credential container — a dropped kubeconfig hands
     * over cluster access (token/client-key/password) even without
     * an exec plugin                                          */
    if (strstr(low, "clusters:") && strstr(low, "users:") &&
        (strstr(low, "token") || strstr(low, "client-key") ||
         strstr(low, "password") || strstr(low, "client-certificate-data") ||
         strstr(low, "client-key-data")))
        sc = sc < 45 ? 45 : sc;
    /* .envrc is a shell script direnv runs on `cd` — after the
     * one-time `direnv allow` the reviewer rubber-stamps, every
     * visit re-executes it. Only exec-shaped content flags; a plain
     * `export A=b` envrc is direnv's normal case.                */
    {
        char lown2[64];
        str_lower(basename, lown2, sizeof(lown2));
        if (strcmp(lown2, ".envrc") == 0 &&
            (strstr(low, "curl") || strstr(low, "wget") ||
             strstr(low, "eval") || strstr(low, "source ") ||
             strstr(low, "sh -c") || strstr(low, "bash -c") ||
             strstr(low, "exec ") || strstr(low, ". /")))
            sc = sc < 55 ? 55 : sc;
    }
    /* git exec config — INI sections hide the dotted name: under
     * [core] the key is bare `fsmonitor`/`editor`/`pager`, under
     * [filter "x"] it is `clean`/`smudge`, under [credential] it is
     * `helper`. Flag only when the VALUE names a program a shell
     * would run (path / `!` shell form / interpreter / fetch) — a
     * bare `editor = vim` is the most common gitconfig line ever
     * written and must stay clean.                               */
    {
        static const char *const EK[] = {
            "fsmonitor", "editor", "pager", "external",
            "clean", "smudge", "helper", "program", "cmd", NULL
        };
        static const char *const EXECISH[] = {
            "/", "!", "-c", "sh ", "curl", "wget", "python",
            "ruby", "perl", "node ", "powershell", "pwsh", NULL
        };
        int ei, ej;
        for (ei = 0; EK[ei]; ei++) {
            char pat[48];
            const char *kp, *vp;
            size_t kl;
            snprintf(pat, sizeof(pat), "%s", EK[ei]);
            kp = strstr(low, pat);
            while (kp) {
                /* key must be at a token boundary: preceded by
                 * start/newline/space/tab, and followed by
                 * space/tab/= so `editors` or `helperx` don't hit */
                int left_ok = (kp == low) || kp[-1] == '\n' ||
                              kp[-1] == ' ' || kp[-1] == '\t' ||
                              kp[-1] == '.';
                kl = strlen(pat);
                if (!left_ok ||
                    (kp[kl] && kp[kl] != ' ' && kp[kl] != '\t' &&
                     kp[kl] != '=')) {
                    kp = strstr(kp + 1, pat);
                    continue;
                }
                vp = strchr(kp, '=');
                if (!vp) { kp = strstr(kp + 1, pat); continue; }
                vp++;
                {
                    const char *eol = strchr(vp, '\n');
                    char val[128];
                    size_t vn = eol ? (size_t)(eol - vp)
                                    : strlen(vp);
                    if (vn >= sizeof(val)) vn = sizeof(val) - 1;
                    memcpy(val, vp, vn);
                    val[vn] = '\0';
                    for (ej = 0; EXECISH[ej]; ej++)
                        if (strstr(val, EXECISH[ej])) {
                            sc = sc < 55 ? 55 : sc;
                            break;
                        }
                }
                break;  /* first occurrence of this key is enough */
            }
        }
        /* include.path pulls an arbitrary file into the config —
         * the included file's exec keys land on the victim anyway */
        if (strstr(low, "include") && strstr(low, "path") &&
            strstr(low, "="))
            sc = sc < 40 ? 40 : sc;
    }
    return sc;
}


/* ─── F19: reverse-shell primitives in file content ───────────────────
 * bash -i >& /dev/tcp, nc -e, socat exec, python socket+dup2 — the
 * interactive-shell-back-to-attacker family. Content-driven (applies
 * to any file: a Makefile or cron line is just as live).          */
static int
revshell_score(const unsigned char *head, size_t len) {
    char low[4097];
    size_t n = 0, i;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "/dev/tcp/")) return 65;
    if (strstr(low, "nc -e ") || strstr(low, "ncat -e") ||
        strstr(low, "nc.exe -e") || strstr(low, "ncat.exe -e"))
        return 60;
    if (strstr(low, "socat") &&
        (strstr(low, "exec:") || strstr(low, "exec =")))
        return 60;
    if (strstr(low, "bash -i") &&
        (strstr(low, ">&") || strstr(low, "0>&")))
        return 60;
    if (strstr(low, "socket") && strstr(low, "dup2") &&
        (strstr(low, "pty") || strstr(low, "/bin/sh") ||
         strstr(low, "/bin/bash")))
        return 60;
    return 0;
}

/* ─── F20: HTML <base> hijack — one tag repoints every relative link,
 *      form action and image on the page to the attacker's host ──── */
static int
base_hijack_score(const unsigned char *head, size_t len) {
    char low[4097];
    size_t n = 0, i;
    const char *b, *h;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    b = strstr(low, "<base");
    if (!b) return 0;
    h = strstr(b, "href");
    if (!h) return 0;
    /* bounded: href must land inside the tag */
    {
        const char *gt = strchr(b, '>');
        if (gt && h > gt) return 0;
    }
    if (strstr(h, "http://") || strstr(h, "https://"))
        return 55;
    /* protocol-relative — inherits whatever scheme the page had */
    h += 4;
    while (*h == ' ' || *h == '=' || *h == '"' || *h == '\'') h++;
    if (h[0] == '/' && h[1] == '/') return 50;
    return 0;
}

/* ─── F21: <meta http-equiv=refresh> redirect — a static HTML file that
 *      throws the viewer to a remote page on open (the "attachment that
 *      is just a redirect" phish; gateways render it as inert HTML) ── */
static int
meta_refresh_score(const unsigned char *head, size_t len) {
    char low[4097];
    size_t n = 0, i;
    const char *m;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    m = strstr(low, "<meta");
    while (m) {
        const char *gt = strchr(m, '>');
        const char *end = gt ? gt : low + n;
        const char *r = strstr(m, "refresh");
        const char *u;
        if (r && r < end && (u = strstr(m, "url")) && u < end) {
            u += 3;
            while (u < end && (*u == ' ' || *u == '=' || *u == '"' ||
                   *u == '\'' || *u == ';' || (*u >= '0' && *u <= '9')))
                u++;
            if (u + 8 <= end &&
                (strncmp(u, "http://", 7) == 0 ||
                 strncmp(u, "https://", 8) == 0))
                return 55;
            if (u + 2 <= end && u[0] == '/' && u[1] == '/')
                return 50;
        }
        m = gt ? strstr(gt, "<meta") : NULL;
    }
    return 0;
}

/* word-boundary prefix match: p[0..kl)==key, preceded by YAML key
 * boundary (start/space/{/,), followed by ':' — shared by the YAML
 * scorers below. Iterates via *cur; returns value cursor after ':'
 * or NULL.                                                        */
static const char *
yaml_key_val(const char *low, const char *key, const char **cur) {
    size_t kl = strlen(key);
    const char *p = *cur ? *cur : low;
    while ((p = strstr(p, key)) != NULL) {
        const char *v = p + kl;
        if ((p == low || isspace((unsigned char)p[-1]) ||
             p[-1] == '{' || p[-1] == ',') && *v == ':') {
            *cur = p + kl;
            return v + 1;
        }
        p += kl;
    }
    *cur = NULL;
    return NULL;
}

static int
yaml_key_present(const char *low, const char *key) {
    const char *cur = NULL;
    return yaml_key_val(low, key, &cur) != NULL;
}

static int
yaml_bool_true(const char *low, const char *key) {
    const char *cur = NULL, *v;
    while ((v = yaml_key_val(low, key, &cur)) != NULL) {
        while (*v == ' ' || *v == '\t') v++;
        if (strncmp(v, "true", 4) == 0) return 1;
    }
    return 0;
}

/* ─── F25: privileged Kubernetes manifest — a .yaml/.yml doc carrying
 *      apiVersion:/kind: that requests privilege the PodSecurity
 *      baseline/restricted profiles forbid: privileged containers,
 *      host-namespace sharing, hostPath mounts, dangerous capabilities.
 *      A dropped manifest runs with one `kubectl apply` (container-
 *      breakout class).                                               */


static int
k8s_priv_score(const unsigned char *head, size_t len, const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    int sc = 0;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".yaml") != 0 && strcmp(extl, ".yml") != 0)
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "apiversion:") || !strstr(low, "kind:"))
        return 0;
    if (yaml_bool_true(low, "privileged"))
        sc = 70;
    if (strstr(low, "sys_admin") ||
        (strstr(low, "capabilities:") &&
         (strstr(low, "- all") || strstr(low, "[all]") ||
          strstr(low, "\"all\"") || strstr(low, "'all'")))) {
        if (sc < 65) sc = 65;
    }
    if (yaml_bool_true(low, "hostpid") || yaml_bool_true(low, "hostipc") ||
        yaml_bool_true(low, "hostnetwork")) {
        if (sc < 55) sc = 55;
    }
    if (yaml_bool_true(low, "allowprivilegeescalation")) {
        if (sc < 45) sc = 45;
    }
    {
        const char *p = low;
        while ((p = strstr(p, "hostpath")) != NULL) {
            if ((p == low || isspace((unsigned char)p[-1]) ||
                 p[-1] == '{' || p[-1] == ',') && p[8] == ':') {
                if (sc < 30) sc = 30;
                break;
            }
            p += 8;
        }
    }
    return sc;
}

/* F26: docker-compose privilege — services that run privileged,
 * share host namespaces, mount the docker socket or host root, or
 * add dangerous caps. Gate: compose-named file or services:+image:/
 * build: body (a plain YAML with a `services:` key is already a
 * compose-shaped doc).                                             */
static int
compose_priv_score(const unsigned char *head, size_t len,
                   const char *basename_start, const char *ext) {
    char extl[32], lown[64], low[4097];
    size_t n = 0, i;
    int sc = 0;
    const char *cur;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".yaml") != 0 && strcmp(extl, ".yml") != 0)
        return 0;
    str_lower(basename_start, lown, sizeof(lown));
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(lown, "compose") &&
        !(yaml_key_present(low, "services") &&
          (yaml_key_present(low, "image") ||
           yaml_key_present(low, "build") ||
           yaml_key_present(low, "container_name"))))
        return 0;
    if (yaml_bool_true(low, "privileged"))
        sc = 70;
    /* host-namespace modes take the value `host` (optionally quoted) */
    {
        static const char *const NSKEYS[] = {
            "network_mode", "pid", "ipc", "uts", "cgroup",
            "userns_mode", NULL
        };
        for (i = 0; NSKEYS[i]; i++) {
            cur = NULL;
            const char *v;
            while ((v = yaml_key_val(low, NSKEYS[i], &cur)) != NULL) {
                while (*v == ' ' || *v == '\t' || *v == '"' ||
                       *v == '\'') v++;
                if (strncmp(v, "host", 4) == 0) {
                    if (sc < 55) sc = 55;
                    break;
                }
            }
        }
    }
    if (yaml_key_present(low, "cap_add") &&
        (strstr(low, "sys_admin") || strstr(low, "- all") ||
         strstr(low, "[all]"))) {
        if (sc < 65) sc = 65;
    }
    if (strstr(low, "/var/run/docker.sock") ||
        strstr(low, "/run/docker.sock")) {
        if (sc < 60) sc = 60;
    }
    /* host-root / sensitive-dir bind mounts */
    if (strstr(low, "- /:") || strstr(low, "- \"/:") ||
        strstr(low, "- '/:") || strstr(low, "- /etc:") ||
        strstr(low, "- /etc/") || strstr(low, "- /root:") ||
        strstr(low, "- /root/") || strstr(low, "- /boot") ||
        strstr(low, "- /dev/") || strstr(low, "- /proc") ||
        strstr(low, "- /sys/") || strstr(low, "- /sys:")) {
        if (sc < 50) sc = 50;
    }
    if (yaml_key_present(low, "security_opt") &&
        strstr(low, "unconfined")) {
        if (sc < 40) sc = 40;
    }
    return sc;
}

/* ─── F27: YAML unsafe-load tags — !!python/object[...], !ruby/…,
 *      !!perl/… are inert text until yaml.load / unsafe_load /
 *      Psych.load instantiates them into arbitrary objects (the
 *      deserialization-gadget RCE class). Only fires on executable
 *      tag families — CloudFormation !Ref/!GetAtt and ordinary
 *      custom tags stay clean.                                   */
static int
yaml_unsafe_tag_score(const unsigned char *head, size_t len,
                      const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".yaml") != 0 && strcmp(extl, ".yml") != 0)
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "!!python/") || strstr(low, "!python/object") ||
        strstr(low, "!python/name") || strstr(low, "!python/module") ||
        strstr(low, "!ruby/") || strstr(low, "!!perl/") ||
        strstr(low, "!perl/") || strstr(low, "!!php/") ||
        strstr(low, "!php/object"))
        return 65;
    return 0;
}

/* ─── F28: pickle/.pth code-exec — pickle GLOBAL opcodes referencing
 *      system/eval/exec/subprocess (the ML-supply-chain payload
 *      class: a "model" that runs code on load), and .pth files
 *      carrying an `import` line (site-packages .pth lines starting
 *      with `import` execute at interpreter startup).          */
static int
py_exec_score(const unsigned char *head, size_t len, const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strcmp(extl, ".pkl") == 0 || strcmp(extl, ".pickle") == 0 ||
        strcmp(extl, ".pth") == 0) {
        /* pickle GLOBAL/STACK_GLOBAL refs — same byte pattern in
         * text and binary protocols (`c<mod>\n<name>` / `\x93`) */
        if (strstr(low, "cposix\nsystem") || strstr(low, "cnt\nsystem") ||
            strstr(low, "cos\nsystem") || strstr(low, "cos\npopen") ||
            strstr(low, "csubprocess") || strstr(low, "cpty\n") ||
            strstr(low, "c__builtin__\neval") ||
            strstr(low, "c__builtin__\nexec") ||
            strstr(low, "c__builtin__\nsystem"))
            return 70;
    }
    if (strcmp(extl, ".pth") == 0) {
        /* .pth exec: a line whose first token is `import` runs at
         * interpreter startup under site-packages */
        const char *p = low;
        if (strncmp(p, "import ", 7) == 0) return 65;
        while ((p = strstr(p, "\nimport ")) != NULL) {
            return 65;
        }
        if (strstr(low, "\nimport\t")) return 65;
    }
    return 0;
}

/* ─── F29: autorun.inf — [autorun] open=/shellexecute=/shell\…\command=
 *      keys made removable media self-execute (USB worm class; modern
 *      Windows suppresses it but the file is still a lure) ────────── */
static int
autorun_score(const unsigned char *head, size_t len, const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".inf") != 0) return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "[autorun]")) return 0;
    if (strstr(low, "\nopen=") || strstr(low, "\nshellexecute=") ||
        strstr(low, "shell\\") || strstr(low, "\nshell=") ||
        strstr(low, "\nopen =") )
        return 55;
    return 0;
}

/* ─── F30: WPAD/.pac proxy hijack — a proxy auto-config script that
 *      returns PROXY/SOCKS directives routes all browser traffic
 *      through the named host (a dropped .pac is a traffic-
 *      interception payload, not a document) ─────────────────────── */
static int
pac_hijack_score(const unsigned char *head, size_t len, const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    const char *p;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".pac") != 0 && strcmp(extl, ".dat") != 0)
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "findproxyforurl")) return 0;
    p = low;
    for (;;) {
        const char *pp = strstr(p, "proxy ");
        const char *ps = strstr(p, "socks");
        const char *hit = (pp && ps) ? (pp < ps ? pp : ps)
                                     : (pp ? pp : ps);
        const char *q;
        if (!hit) break;
        q = hit + (hit == pp ? 6 : 5);
        while (*q == ' ' || *q == '\t' || *q == '"' || *q == '\'' ||
               (*q >= '0' && *q <= '9')) q++;
        /* skip localhost/local resolver */
        if (strncmp(q, "127.", 4) && strncmp(q, "localhost", 9) &&
            strncmp(q, "[::1]", 5))
            return 45;
        p = q;
    }
    return 0;
}

/* ─── F31: XML XXE / entity-expansion bomb — <!ENTITY … SYSTEM
 *      "file:///…|http://…"> exfiltrates local files on parse;
 *      nested entity declarations expand exponentially (billion
 *      laughs). Fires on parser-fed XML-family docs. ─────────────── */
static int
xml_xxe_score(const unsigned char *head, size_t len, const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    static const char *const XEXT[] = {
        ".xml", ".svg", ".xsl", ".xslt", ".dtd", ".xsd", ".rss",
        ".atom", ".plist", ".resx", ".config", ".rels", NULL
    };
    str_lower(ext ? ext : "", extl, sizeof(extl));
    for (i = 0; XEXT[i]; i++)
        if (strcmp(extl, XEXT[i]) == 0) break;
    if (!XEXT[i]) return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "<!entity") && !strstr(low, "<!doctype"))
        return 0;
    /* external entity / external DTD — SYSTEM or PUBLIC identifier */
    if ((strstr(low, "<!entity") || strstr(low, "<!doctype")) &&
        (strstr(low, "system") || strstr(low, "public")))
        return 65;
    /* entity-expansion bomb: an entity declaration whose quoted value
     * itself references other entities (&name;) */
    {
        const char *p = low;
        while ((p = strstr(p, "<!entity")) != NULL) {
            const char *q = strchr(p, '"');
            const char *e;
            if (!q) q = strchr(p, '\'');
            if (!q) { p += 8; continue; }
            e = strchr(q + 1, *q);
            if (!e) { p += 8; continue; }
            for (q++; q < e; q++)
                if (*q == '&') return 55;
            p = e;
        }
    }
    return 0;
}

/* ─── F32: MSBuild inline task / Exec — <UsingTask> with a code
 *      task factory compiles+runs embedded C# at build; <Exec> runs
 *      a raw command. A vendored .*proj builds to code-exec. ───────── */
static int
msbuild_exec_score(const unsigned char *head, size_t len,
                   const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    static const char *const MEXT[] = {
        ".csproj", ".vbproj", ".fsproj", ".proj", ".targets",
        ".props", ".xproj", ".vcxproj", ".vcproj", ".wixproj",
        ".sqlproj", ".ccproj", ".pubxml", NULL
    };
    str_lower(ext ? ext : "", extl, sizeof(extl));
    for (i = 0; MEXT[i]; i++)
        if (strcmp(extl, MEXT[i]) == 0) break;
    if (!MEXT[i]) return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "<usingtask") &&
        (strstr(low, "codetaskfactory") ||
         strstr(low, "roslyncodetaskfactory") ||
         strstr(low, "taskfactory")))
        return 60;
    if (strstr(low, "<exec ") || strstr(low, "<exec\t") ||
        strstr(low, "<exec>"))
        return 55;
    return 0;
}

/* ─── F33: debugger rc exec — .gdbinit/.lldbinit runs `shell`/`command
 *      script import` lines when a developer opens the repo under a
 *      debugger (autoexec-on-tool-start class) ────────────────────── */
static int
dbgrc_score(const unsigned char *head, size_t len,
            const char *basename_start) {
    char lown[64], low[4097];
    size_t n = 0, i;
    str_lower(basename_start, lown, sizeof(lown));
    if (strcmp(lown, ".gdbinit") && strcmp(lown, "gdbinit") &&
        strcmp(lown, ".lldbinit") && strcmp(lown, "lldbinit") &&
        strcmp(lown, ".gdbinitearly"))
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strncmp(low, "shell ", 6) == 0 || strstr(low, "\nshell ") ||
        strstr(low, "command script import") ||
        strstr(low, "process launch"))
        return 45;
    return 0;
}

/* ─── F34: SQL exec — COPY … FROM/TO PROGRAM pipes a shell command
 *      through the DB superuser; `\!` runs a host shell; LOAD /
 *      LANGUAGE C links a shared object (Postgres RCE class) ──────── */
static int
sql_exec_score(const unsigned char *head, size_t len, const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".sql") != 0) return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if ((strstr(low, "copy") && strstr(low, " program")) ||
        strstr(low, "language c") || strstr(low, "language 'c'") ||
        strstr(low, "language \"c\"") ||
        strncmp(low, "load '", 6) == 0 || strstr(low, "\nload '"))
        return 55;
    if (strstr(low, "\n\\!") || strncmp(low, "\\!", 2) == 0)
        return 50;
    return 0;
}

/* ─── F35: interpreter autoexec — sitecustomize.py / usercustomize.py
 *      run on EVERY python startup (dropped into site-packages or a
 *      dir on PYTHONPATH); a file with that name + exec markers is a
 *      persistence payload, not a module ──────────────────────────── */
static int
py_autoexec_score(const unsigned char *head, size_t len,
                  const char *basename_start) {
    char lown[64], low[4097];
    size_t n = 0, i;
    str_lower(basename_start, lown, sizeof(lown));
    if (strcmp(lown, "sitecustomize.py") &&
        strcmp(lown, "usercustomize.py") && strcmp(lown, "conftest.py"))
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "os.system") || strstr(low, "os.popen") ||
        strstr(low, "subprocess") || strstr(low, "socket.socket") ||
        strstr(low, "eval(") || strstr(low, "exec(") ||
        strstr(low, "__import__") || strstr(low, "urllib") ||
        strstr(low, "requests.") || strstr(low, "base64"))
        return 55;
    return 0;
}

/* ─── F41: .wsf/.wsh scriptlet — <job><script> wraps WScript code;
 *      with CreateObject/Shell it is the classic JScript/VBScript
 *      dropper (a text file that executes via wscript) ────────────── */
static int
wsf_scriptlet_score(const unsigned char *head, size_t len,
                    const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".wsf") && strcmp(extl, ".wsh")) return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "<script") || !strstr(low, "<job"))
        return 0;
    if (strstr(low, "createobject") || strstr(low, "wscript.shell") ||
        strstr(low, "shell.application") || strstr(low, ".run(") ||
        strstr(low, ".exec(") || strstr(low, "getobject"))
        return 55;
    return 45;
}

/* ─── F42: .inf install sections — [DefaultInstall] blocks run via
 *      rundll32/cmstp; RunPreSetupCommands/AddService/exec keys mean
 *      a double-click or cmstp invocation is code exec ────────────── */
static int
inf_install_score(const unsigned char *head, size_t len,
                  const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".inf") != 0) return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "[defaultinstall") && !strstr(low, "[install"))
        return 0;
    if (strstr(low, "runpresetupcommands") ||
        strstr(low, "runpostsetupcommands") ||
        strstr(low, "addservice") || strstr(low, "updatesysownfiles") ||
        strstr(low, "copyfiles") || strstr(low, "delnodes"))
        return 55;
    return 40;
}

/* ─── F43: ClickOnce .application/.manifest — a <deployment codebase=
 *      pointing at a remote URL installs+runs code from that host on
 *      open (ClickOnce phishing class) ────────────────────────────── */
static int
clickonce_score(const unsigned char *head, size_t len, const char *ext) {
    char extl[40], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".application") && strcmp(extl, ".manifest") &&
        strcmp(extl, ".vsto") && strcmp(extl, ".appref-ms") &&
        strcmp(extl, ".appinstaller"))
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    /* .appref-ms is not XML: its whole content is the remote reference
     * "http://host/app.application#Culture=…" — an http(s)/UNC pointer
     * IS the payload. */
    if (strcmp(extl, ".appref-ms") == 0)
        return (strstr(low, "http://") || strstr(low, "https://") ||
                strstr(low, "\\\\")) ? 55 : 0;
    /* .appinstaller — App Installer manifest; a remote Uri= on
     * <AppInstaller>/<MainPackage> installs+launches the msix/bundle */
    if (strcmp(extl, ".appinstaller") == 0) {
        if (!strstr(low, "<appinstaller") && !strstr(low, "<mainpackage"))
            return 0;
        return (strstr(low, "uri=\"http") || strstr(low, "uri='http") ||
                strstr(low, "uri=\"\\\\")) ? 55 : 0;
    }
    if (!strstr(low, "<deployment") && !strstr(low, "<assembly"))
        return 0;
    if (strstr(low, "codebase=\"http") || strstr(low, "codebase='http") ||
        strstr(low, "codebase=\"\\\\") ||
        strstr(low, "codebase='\\\\"))
        return 55;
    return 0;
}

/* ─── F44: spreadsheet formula injection — .slk SYLK EEXEC()/EXEC()
 *      runs at open (no macro prompt); .iqy/.rqy WEB queries and .csv
 *      cells starting with =/+/-/@ + exec primitive are DDE/cmd
 *      injection — Excel/Calc executes them on open ──────────────── */
static int
formula_injection_score(const unsigned char *head, size_t len,
    const char *ext) {
    char extl[40], low[4097];
    size_t n = 0, i;
    const char *p;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strcmp(extl, ".slk") == 0 || strcmp(extl, ".sylk") == 0) {
        if (strstr(low, "eexec(") || strstr(low, ";eexec") ||
            strstr(low, "exec(\"") || strstr(low, ";eopen"))
            return 55;   /* SYLK macro auto-exec — no prompt in Excel */
        return 0;
    }
    if (strcmp(extl, ".iqy") == 0 || strcmp(extl, ".rqy") == 0 ||
        strcmp(extl, ".dsy") == 0) {
        if (strstr(low, "web") && (strstr(low, "http://") ||
            strstr(low, "https://") || strstr(low, "\\\\")))
            return 45;   /* Excel web query pulling a remote source */
        return 0;
    }
    if (strcmp(extl, ".csv") != 0 && strcmp(extl, ".tsv") != 0 &&
        strcmp(extl, ".txt") != 0)
        return 0;
    /* CSV/TSV: a cell whose first char is =,+,-,@ followed by a cmd/
     * DDE/WEBSERVICE/hyperlink primitive fires on open in Excel */
    p = low;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';' ||
               *p == '"' || *p == '\'')
            p++;
        if (*p == '=' || *p == '+' || *p == '-' || *p == '@') {
            const char *q = p + 1;
            if (strncmp(q, "cmd", 3) == 0 || strncmp(q, "dde", 3) == 0 ||
                strncmp(q, "msexcel", 7) == 0 ||
                strstr(q, "webservice(") == q ||
                strstr(q, "hyperlink(\"http") == q ||
                strstr(q, "hyperlink('http") == q)
                return 50;
        }
        while (*p && *p != '\n' && *p != ',') p++;
        if (*p == ',') { p++; continue; }
        while (*p && *p != '\n') p++;
        if (*p) p++;
    }
    return 0;
}

/* ─── F45: .jnlp Java Web Start — javaws fetches+launches jars from
 *      the codebase on open (post-Java-9 phish resurfacing) ───────── */
static int
jnlp_score(const unsigned char *head, size_t len, const char *ext) {
    char extl[40], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".jnlp"))
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "<jnlp"))
        return 0;
    if (strstr(low, "codebase=\"http") || strstr(low, "codebase='http") ||
        strstr(low, "codebase=\"\\\\") ||
        strstr(low, "href=\"http") || strstr(low, "href='http") ||
        strstr(low, "url=\"http"))
        return 50;
    return 0;
}

/* ─── F46: .sct COM scriptlet — regsvr32 scrobj.dll runs the embedded
 *      script with no file-type prompt (Squiblydoo bypass) ────────── */
static int
sct_scriptlet_score(const unsigned char *head, size_t len,
    const char *ext) {
    char extl[40], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".sct"))
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "<scriptlet"))
        return 0;
    if (!strstr(low, "<script") && !strstr(low, "<registration"))
        return 0;
    if (strstr(low, "createobject") || strstr(low, "getobject") ||
        strstr(low, "wscript.shell") || strstr(low, "shell.application") ||
        strstr(low, "powershell") || strstr(low, "cmd.exe") ||
        strstr(low, ".run ") || strstr(low, ".exec "))
        return 55;
    return 45;
}

/* ─── F49: install-carrier extensions — an extension bundle (.vsix/
 *      .xpi/.crx/.oxt/.nex/.safariextz) installs code into the editor/
 *      browser on add; a cert/key file (.cer/.crt/.der/.p12/.pfx) writes
 *      the trust store on import. Extension-gated only. ────────────── */
static int
install_carrier_score(const char *ext) {
    char extl[40];
    static const char *const BUNDLES[] = {
        ".vsix", ".xpi", ".crx", ".nex", ".safariextz", ".oxt",
        ".whl", ".egg", ".gem", ".nupkg", ".apk", ".ipa",
        NULL
    };
    static const char *const CERTS[] = {
        ".cer", ".crt", ".der", ".p12", ".pfx", ".p7b", ".p7r",
        NULL
    };
    int i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    for (i = 0; BUNDLES[i]; i++)
        if (strcmp(extl, BUNDLES[i]) == 0) return 35;
    for (i = 0; CERTS[i]; i++)
        if (strcmp(extl, CERTS[i]) == 0) return 30;
    return 0;
}

/* ─── F50: Homebrew formula exec — a .rb formula's install{} block
 *      runs on `brew install`; system/curl/wget inside one is an
 *      install-time code-exec vector (tap supply chain) ───────────── */
static int
brew_formula_score(const unsigned char *head, size_t len,
    const char *ext) {
    char extl[40], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".rb"))
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "< formula") && !strstr(low, "<formula"))
        return 0;
    if (strstr(low, "system ") || strstr(low, "system(") ||
        strstr(low, "curl ") || strstr(low, "wget ") ||
        strstr(low, "open(") || strstr(low, "eval "))
        return 55;
    return 0;   /* a plain formula is ordinary .rb — no signal */
}

/* ─── F51: .cabal custom build — `build-type: Custom`/`custom-setup`
 *      delegates the build to a Setup.hs script that runs at
 *      `cabal build` time ─────────────────────────────────────────── */
static int
cabal_custom_score(const unsigned char *head, size_t len,
    const char *ext) {
    char extl[40], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".cabal"))
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (strstr(low, "build-type:") && strstr(low, "custom"))
        return 40;
    if (strstr(low, "custom-setup"))
        return 40;
    return 0;
}

/* ─── F52–F55: server-config attack surface — dropped config files
 *      that change what the server does with later content ────────── */
static int
serverconfig_score(const unsigned char *head, size_t len,
    const char *basename_start) {
    char low[4097], bn[256];
    size_t n = 0, i;
    str_lower(basename_start ? basename_start : "", bn, sizeof(bn));
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';

    /* F52 .htaccess — a dropped Apache override file: PHP handler
     * coercion (AddType/SetHandler/php_flag) turns an upload dir into
     * a webshell; Redirect/RewriteRule to a remote host skims traffic */
    if (strcmp(bn, ".htaccess") == 0) {
        if (strstr(low, "addtype") || strstr(low, "sethandler") ||
            strstr(low, "php_flag") || strstr(low, "php_value") ||
            (strstr(low, "options") && strstr(low, "execcgi")) ||
            strstr(low, "php_flag engine"))
            return 55;
        if (strstr(low, "redirect") ||
            (strstr(low, "rewriterule") &&
             (strstr(low, "http://") || strstr(low, "https://"))))
            return 50;
        return 0;
    }
    /* F53 .user.ini — PHP per-dir ini: auto_prepend_file runs on every
     * request in that dir (persistence planted by an upload) */
    if (strcmp(bn, ".user.ini") == 0 || strstr(bn, ".user.ini")) {
        if (strstr(low, "auto_prepend_file") ||
            strstr(low, "auto_append_file"))
            return 55;
        return 0;
    }
    /* F54 web.config — IIS: httpRedirect sends all traffic to a
     * remote host; a <handlers>/<httpHandlers> script mapping execs */
    if (strcmp(bn, "web.config") == 0 || strcmp(bn, "web.debug.config") == 0 ||
        strcmp(bn, "web.release.config") == 0) {
        if (strstr(low, "httpredirect") ||
            (strstr(low, "<add") && strstr(low, "handler") &&
             strstr(low, "verb")) ||
            (strstr(low, "rewrite") && strstr(low, "action") &&
             strstr(low, "url=\"http")))
            return 55;
        return 0;
    }
    /* F55 Office add-in manifest — an .xml whose <OfficeApp>/
     * <SourceLocation> points at a remote page loads attacker content
     * inside Office on add (taskpane phishing) */
    if (strstr(bn, ".xml") || strcmp(bn, "manifest.xml") == 0) {
        if ((strstr(low, "<officeapp") || strstr(low, "<officeappsettings")) ||
            (strstr(low, "sourcelocation") &&
             (strstr(low, "defaultvalue=\"http") ||
              strstr(low, "defaultvalue='http"))))
            return 50;
        return 0;
    }
    return 0;
}

/* ─── F56: system-config carrier — a file named like a host config
 *      that changes privilege/resolution/library resolution when
 *      dropped in place ─────────────────────────────────────────── */
static int
sysconfig_carrier_score(const unsigned char *head, size_t len,
    const char *basename_start) {
    char low[4097], bn[256];
    size_t n = 0, i;
    str_lower(basename_start ? basename_start : "", bn, sizeof(bn));
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';

    /* sudoers / sudoers.d / doas.conf — passwordless privilege grant.
     * A dropped fragment `u ALL=(ALL) NOPASSWD: ALL` / `permit nopass`
     * is instant root. */
    if (strcmp(bn, "sudoers") == 0 || strstr(bn, "sudoers") != NULL ||
        strcmp(bn, "doas.conf") == 0) {
        if (strstr(low, "nopasswd") || strstr(low, "nopass") ||
            strstr(low, "permit nopass"))
            return 60;
        if (strstr(low, "all=(all") || strstr(low, "all=("))
            return 40;
        return 0;
    }
    /* ld.so.preload / ld.so.conf.d — the loader injects the listed .so
     * into every dynamically-linked process (rootkit persistence). */
    if (strcmp(bn, "ld.so.preload") == 0 ||
        strstr(bn, "ld.so.conf") != NULL ||
        strcmp(bn, "ld-musl") == 0) {
        return 55;
    }
    /* environment= LD_PRELOAD/LD_LIBRARY_PATH in a unit/conf — same
     * injection through a service manager */
    if ((strstr(bn, ".conf") != NULL || strstr(bn, ".service") != NULL ||
         strcmp(bn, "environment") == 0) &&
        (strstr(low, "ld_preload") || strstr(low, "ld_library_path") ||
         strstr(low, "dyld_insert_libraries")))
        return 55;
    /* hosts / resolv.conf — a dropped resolver/hosts file silently
     * remaps auth and bank domains to attacker IPs */
    if (strcmp(bn, "hosts") == 0 || strcmp(bn, "resolv.conf") == 0 ||
        strcmp(bn, "nsswitch.conf") == 0) {
        int hijack = 0;
        /* a non-loopback IP mapped to a hostname = domain hijack */
        const char *ln = low;
        while (*ln) {
            const char *eol = strchr(ln, '\n');
            size_t ll = eol ? (size_t)(eol - ln) : strlen(ln);
            if (ll > 0 && ll < 400 && ln[0] != '#' &&
                ln[0] != '\xef' /* BOM-ish guard */) {
                /* crude: starts with an IPv4 address not in
                 * 0./127./169.254/10./192.168/172.16-31 */
                unsigned a, b;
                if (sscanf(ln, "%u.%u", &a, &b) == 2 &&
                    !(a == 0 || a == 127 || a == 10 ||
                      (a == 169 && b == 254) ||
                      (a == 172 && b >= 16 && b <= 31) ||
                      (a == 192 && b == 168) || a >= 224))
                    hijack = 1;
            }
            if (!eol) break;
            ln = eol + 1;
        }
        if (strstr(low, "nameserver") != NULL &&
            strcmp(bn, "resolv.conf") == 0)
            return 45;
        if (hijack)
            return 45;
        if (strcmp(bn, "hosts") == 0 || strcmp(bn, "nsswitch.conf") == 0)
            return 30;
        return 0;
    }
    /* cron/at access-control lists — a dropped cron.deny/at.allow
     * re-enables scheduled jobs for accounts that shouldn't have them */
    if (strcmp(bn, "cron.allow") == 0 || strcmp(bn, "cron.deny") == 0 ||
        strcmp(bn, "at.allow") == 0 || strcmp(bn, "at.deny") == 0)
        return 30;
    /* crontab / cron.d — the file itself is a persistence schedule */
    if (strcmp(bn, "crontab") == 0 || strstr(bn, ".cron") != NULL) {
        if (strstr(low, "* *") || strchr(low, '*') != NULL)
            return 40;
        return 0;
    }
    /* authorized_keys — a dropped file grants its embedded key SSH
     * access; content option keys (command=/from=) are F18's, the
     * bare filename is the persistence carrier */
    if (strcmp(bn, "authorized_keys") == 0 ||
        strcmp(bn, "authorized_keys2") == 0)
        return 50;
    /* mail-delivery redirects — .forward hands every message to the
     * attacker; .procmailrc/.mailfilter with a `|` recipe pipes mail
     * through a program (execution on delivery); /etc/aliases does
     * the same at the MTA: `name: |program` runs it on delivery */
    if (strcmp(bn, ".forward") == 0)
        return 45;
    if (strcmp(bn, "aliases") == 0 || strcmp(bn, "aliases.db") == 0 ||
        strcmp(bn, ".aliases") == 0) {
        if (strchr(low, '|') != NULL)
            return 50;
        return 30;
    }
    /* dovecot.conf — `!include` pulls in an attacker config and
     * mail_plugins/mail_plugin_dir loads .so modules into the IMAP
     * daemon (auth bypass / session snooping at delivery time) */
    if (strcmp(bn, "dovecot.conf") == 0 ||
        strstr(bn, "dovecot") != NULL) {
        if (strstr(low, "!include") || strstr(low, "mail_plugin"))
            return 45;
        return 30;
    }
    /* .maildroprc — courier maildrop recipes with |program run on
     * delivery, same primitive as .procmailrc                       */
    if (strcmp(bn, ".maildroprc") == 0 || strcmp(bn, "mailfilter") == 0) {
        if (strchr(low, '|') != NULL)
            return 55;
        return 40;
    }
    /* rsyslog/syslog-ng daemon hooks — omprog spawns a program per
     * log line; syslog-ng program() does the same as a destination  */
    if (strcmp(bn, "rsyslog.conf") == 0 || strstr(bn, "rsyslog") != NULL) {
        if (strstr(low, "omprog") || strstr(low, "ompipe") ||
            strstr(low, "ommail"))
            return 50;
        return 30;
    }
    if (strcmp(bn, "syslog-ng.conf") == 0 ||
        strstr(bn, "syslog-ng") != NULL) {
        if (strstr(low, "program(") || strstr(low, "program (") ||
            strstr(low, "mail("))
            return 45;
        return 30;
    }
    /* snmpd.conf — exec/extend/pass/traphandle run a command per
     * SNMP query or trap; the file is a daemon-side exec hook       */
    if (strcmp(bn, "snmpd.conf") == 0 || strstr(bn, "snmpd") != NULL) {
        if (strstr(low, "exec ") || strstr(low, "extend") ||
            strstr(low, "pass_persist") || strstr(low, "traphandle") ||
            strstr(low, "monitor"))
            return 50;
        return 30;
    }
    /* dhclient / dhcpcd hooks — enter/exit-hooks run a script as
     * root on every DHCP lease renew                                */
    if (strstr(bn, "dhclient") != NULL || strstr(bn, "dhcp") != NULL) {
        if (strstr(low, "exit-hooks") || strstr(low, "enter-hooks") ||
            strstr(low, "script") || strchr(low, '|') != NULL)
            return 45;
        return 0;
    }
    /* wifi credential containers — wpa_supplicant network{} and
     * hostapd.conf carry the PSK/passphrase in cleartext           */
    if (strstr(bn, "wpa_supplicant") != NULL ||
        strstr(bn, "hostapd") != NULL) {
        if (strstr(low, "psk=") || strstr(low, "wpa_passphrase") ||
            strstr(low, "password=") || strstr(low, "key_mgmt"))
            return 45;
        return 30;
    }
    if (strcmp(bn, ".procmailrc") == 0 || strcmp(bn, ".mailfilter") == 0) {
        if (strchr(low, '|') != NULL)
            return 55;
        return 40;
    }
    /* X login scripts — run on every graphical login */
    if (strcmp(bn, ".xinitrc") == 0 || strcmp(bn, ".xsession") == 0 ||
        strcmp(bn, ".xprofile") == 0)
        return 45;
    /* launchd plist — RunAtLoad/KeepAlive/WatchPaths fires the payload
     * on load/login; the classic macOS persistence carrier */
    if (strstr(bn, ".plist") != NULL &&
        (strstr(low, "runatload") || strstr(low, "keepalive") ||
         strstr(low, "watchpaths") || strstr(low, "startinterval") ||
         strstr(low, "programarguments") || strstr(low, "<key>program</key>")))
        return 55;
    /* Info.plist — a .app bundle that hides itself (LSUIElement/
     * LSBackgroundOnly) while declaring an executable is the stealth
     * persistence shape */
    if (strstr(bn, ".plist") != NULL &&
        strstr(low, "cfbundleexecutable") &&
        (strstr(low, "lsuielement") || strstr(low, "lsbackgroundonly")))
        return 50;
    /* udev rules — RUN+=/PROGRAM=/IMPORT{program} fire when a device
     * is plugged (badusb / rogue-device execution) */
    if (strstr(bn, ".rules") != NULL &&
        (strstr(low, "run+=") || strstr(low, "run =") ||
         strstr(low, "program=") || strstr(low, "import{program}") ||
         strstr(low, "import{")))
        return 55;
    /* polkit rules are JS evaluated on every authorization — a rule
     * that spawns a process is persistence by privilege check */
    if (strstr(bn, ".rules") != NULL &&
        strstr(low, "polkit") &&
        (strstr(low, "spawn") || strstr(low, "unixprocess") ||
         strstr(low, "system(")))
        return 50;
    /* productbuild .dist — the installer definition can target
     * LaunchDaemons/LaunchAgents, planting a daemon on install */
    if (strstr(bn, ".dist") != NULL &&
        (strstr(low, "launchdaemons") || strstr(low, "launchagents") ||
         strstr(low, "/library/")))
        return 50;
    /* .curlrc/.wgetrc — every curl/wget invocation applies them: an
     * output/output_document/directory_prefix + url/input pair redirects
     * downloads to an attacker path without a visible flag */
    if (strcmp(bn, ".curlrc") == 0 || strcmp(bn, "_curlrc") == 0 ||
        strcmp(bn, ".wgetrc") == 0) {
        if ((strstr(low, "output") || strstr(low, "directory_prefix") ||
             strstr(low, "dir_prefix")) &&
            (strstr(low, "url") || strstr(low, "input") ||
             strstr(low, "http")))
            return 50;
        return 40;
    }
    /* .vimrc / init.vim / init.lua — editor startup files evaluate
     * autocmd/system()/os.execute()/io.popen on every launch */
    if (strcmp(bn, ".vimrc") == 0 || strcmp(bn, "_vimrc") == 0 ||
        strcmp(bn, "init.vim") == 0 || strcmp(bn, "init.lua") == 0 ||
        strcmp(bn, ".exrc") == 0 || strcmp(bn, "_exrc") == 0) {
        if (strstr(low, "autocmd") || strstr(low, "system(") ||
            strstr(low, "os.execute") || strstr(low, "io.popen") ||
            strstr(low, ":!") || strstr(low, "vim.fn"))
            return 50;
        return 0;   /* ordinary vim config — no signal */
    }
    /* win.ini / system.ini — run= / load= auto-starts a program at
     * boot; a shell= line that is not the default explorer.exe
     * reassigns the shell outright (classic INI persistence) */
    if (strcmp(bn, "win.ini") == 0 || strcmp(bn, "system.ini") == 0) {
        if (strstr(low, "run=") || strstr(low, "load="))
            return 50;
        if (strstr(low, "shell=") &&
            strstr(low, "shell=explorer.exe") == NULL)
            return 50;
        return 0;
    }
    /* CMakeLists.txt — execute_process / ExternalProject run at
     * configure/build time; a fetch or shell-pipe in one is a
     * build-time payload (the CMake form of the Makefile $(shell) check) */
    if (strcmp(bn, "cmakelists.txt") == 0) {
        if ((strstr(low, "execute_process") ||
             strstr(low, "externalproject") ||
             strstr(low, "add_custom_command") ||
             strstr(low, "add_custom_target")) &&
            (strstr(low, "curl") || strstr(low, "wget") ||
             strstr(low, "invoke-webrequest") || strstr(low, "bitsadmin") ||
             strstr(low, "| sh") || strstr(low, "|sh") ||
             strstr(low, "base64")))
            return 55;
        return 0;
    }
    /* .library-ms / .searchConnector-ms — Windows library/search
     * descriptors whose <url>/<simpleLocation><url> point at a remote
     * http:// or UNC share: opening the folder leaks the NTLM hash
     * and shows attacker-controlled content as a local library */
    if (strstr(bn, ".library-ms") != NULL ||
        strstr(bn, ".searchconnector-ms") != NULL) {
        if (strstr(low, "\\\\") || strstr(low, "http:") ||
            strstr(low, "https:"))
            return 45;
        return 0;
    }
    /* .inputrc — readline key bindings; a macro binding that maps a key
     * to a string ending in a newline types an attacker command the
     * next time the victim presses that key in any readline app */
    if (strcmp(bn, ".inputrc") == 0 || strcmp(bn, "_inputrc") == 0) {
        if ((strstr(low, "\":") || strstr(low, "\"\":")) &&
            (strstr(low, "\\n") || strstr(low, "\\r") ||
             strstr(low, "^m") || strstr(low, "\\cm")))
            return 45;
        return 0;
    }
    /* .xbindkeysrc — maps a key chord to a shell command; the file's
     * whole purpose is keypress-exec, so only flag when a bound command
     * reaches a fetcher/shell/destructor primitive */
    if (strcmp(bn, ".xbindkeysrc") == 0) {
        if (strstr(low, "curl") || strstr(low, "wget") ||
            strstr(low, "http") || strstr(low, "sh -c") ||
            strstr(low, "bash ") || strstr(low, "rm -") ||
            strstr(low, "nc ") || strstr(low, "ncat"))
            return 50;
        return 0;
    }
    /* .my.cnf — mysql/mariadb client config: a `pager =`/`tee =`
     * directive runs an external program / pipes output on every
     * session; `nopager`/`no-auto-rehash` style flags don't match
     * the `key =` form */
    if (strcmp(bn, ".my.cnf") == 0 || strcmp(bn, "my.ini") == 0 ||
        strcmp(bn, "my.cnf") == 0) {
        if (strstr(low, "pager =") || strstr(low, "pager=") ||
            strstr(low, "tee =") || strstr(low, "tee="))
            return 50;
        return 0;
    }
    /* .sqliterc / .psqlrc — DB-client startup files: sqlite `.shell`/
     * `.system`/`.output` and psql `\!`/`\o`/`copy … program` run or
     * pipe to external commands on connect */
    if (strcmp(bn, ".sqliterc") == 0 || strcmp(bn, "sqliterc") == 0) {
        if (strstr(low, ".shell") || strstr(low, ".system") ||
            strstr(low, ".output") || strstr(low, ".once"))
            return 50;
        return 0;
    }
    if (strcmp(bn, ".psqlrc") == 0 || strcmp(bn, "psqlrc") == 0 ||
        strcmp(bn, "psqlrc.conf") == 0) {
        if (strstr(low, "\\!") || strstr(low, "\\o") ||
            strstr(low, "program") || strstr(low, "\\copy"))
            return 45;
        return 0;
    }
    /* Build-file carriers — wscript (waf), SConstruct (scons),
     * meson.build, Rakefile/Rakefile.rb, Earthfile, Taskfile: all run
     * embedded code at build/configure time. An exec or fetch primitive
     * in one is the build-time equivalent of Makefile $(shell curl). */
    if (strcmp(bn, "wscript") == 0 || strcmp(bn, "sconstruct") == 0 ||
        strcmp(bn, "meson.build") == 0 || strcmp(bn, "rakefile") == 0 ||
        strcmp(bn, "rakefile.rb") == 0 || strcmp(bn, "earthfile") == 0 ||
        strcmp(bn, "taskfile.yml") == 0 || strcmp(bn, "taskfile.yaml") == 0) {
        if (strstr(low, "os.system") || strstr(low, "subprocess") ||
            strstr(low, "run_command") || strstr(low, "run_target") ||
            strstr(low, "system(") || strstr(low, "system \"") ||
            strstr(low, "sh \"") || strstr(low, "`") ||
            strstr(low, "curl") || strstr(low, "wget") ||
            strstr(low, "invoke-webrequest") || strstr(low, "http") ||
            strstr(low, "eval ") || strstr(low, "exec(") ||
            strstr(low, "| sh") || strstr(low, "|sh") ||
            strstr(low, "base64"))
            return 55;
        return 0;
    }
    /* Editor / repl / session startup files that evaluate code on
     * launch — the "drop a rc, own the next session" family:
     * init.el/.emacs (elisp), .Rprofile (R), .ghci (haskell),
     * .latexmkrc (perl), .conkyrc (${exec}), activate/activate_this.py
     * (venv activation runs arbitrary shell), .octaverc/.jl startup. */
    if (strcmp(bn, "init.el") == 0 || strcmp(bn, ".emacs") == 0 ||
        strcmp(bn, "early-init.el") == 0 ||
        strcmp(bn, ".rprofile") == 0 || strcmp(bn, "rprofile.site") == 0 ||
        strcmp(bn, ".ghci") == 0 || strcmp(bn, "ghci.conf") == 0 ||
        strcmp(bn, ".latexmkrc") == 0 ||
        strcmp(bn, ".conkyrc") == 0 || strcmp(bn, "conky.conf") == 0 ||
        strcmp(bn, "activate") == 0 || strcmp(bn, "activate_this.py") == 0 ||
        strcmp(bn, "activate.csh") == 0 || strcmp(bn, "activate.fish") == 0 ||
        strcmp(bn, ".octaverc") == 0 || strcmp(bn, "octaverc") == 0) {
        if (strstr(low, "shell-command") || strstr(low, "call-process") ||
            strstr(low, "start-process") || strstr(low, "system") ||
            strstr(low, "os.execute") || strstr(low, "io.popen") ||
            strstr(low, "${exec") || strstr(low, "${texeci") ||
            strstr(low, "exec") || strstr(low, ":!") ||
            strstr(low, "curl") || strstr(low, "wget") ||
            strstr(low, "eval") || strstr(low, "`") ||
            strstr(low, "| sh") || strstr(low, "|sh"))
            return 50;
        return 0;
    }
    /* .gdbinit / .lldbinit — debugger startup files run their embedded
     * commands (incl. python/shell blocks) whenever gdb/lldb opens in
     * that directory — a dropped .gdbinit next to a repo is exec on
     * "just debugged it" */
    if (strcmp(bn, ".gdbinit") == 0 || strcmp(bn, "gdbinit") == 0 ||
        strcmp(bn, ".lldbinit") == 0 || strcmp(bn, "lldbinit") == 0) {
        if (strstr(low, "shell") || strstr(low, "python") ||
            strstr(low, "system") || strstr(low, "source") ||
            strstr(low, "eval") || strstr(low, "command script"))
            return 50;
        return 0;
    }
    /* .msmtprc passwordeval / .fetchmailrc postconnect|mda /
     * .isyncrc PassCmd / .ripgreprc --pre — mailer/searcher configs
     * that run an external command on every invocation; a dropped
     * one turns "check mail / grep" into payload exec */
    if (strcmp(bn, ".msmtprc") == 0 || strcmp(bn, "msmtprc") == 0) {
        if (strstr(low, "passwordeval"))
            return 50;
        return 0;
    }
    if (strcmp(bn, ".fetchmailrc") == 0 || strcmp(bn, "fetchmailrc") == 0) {
        if (strstr(low, "postconnect") || strstr(low, "preconnect") ||
            strstr(low, "mda") || strstr(low, "bsmtp"))
            return 45;
        return 0;
    }
    if (strcmp(bn, ".isyncrc") == 0 || strcmp(bn, "mbsyncrc") == 0 ||
        strcmp(bn, ".mbsyncrc") == 0) {
        if (strstr(low, "passcmd") || strstr(low, "pipecommand"))
            return 50;
        return 0;
    }
    if (strcmp(bn, ".ripgreprc") == 0 || strcmp(bn, "ripgreprc") == 0) {
        if (strstr(low, "--pre") || strstr(low, "--hostname-bin"))
            return 50;
        return 0;
    }
    /* package-manager config hijack — .npmrc/.yarnrc/.yarnrc.yml can
     * re-point the registry (dependency confusion), change the script
     * shell (script-shell = exec on lifecycle scripts), whitelist http
     * registries, or name a plugin; .pnpmfile.cjs runs JS hooks on
     * every install; .gemrc sources: redirects gem resolution */
    if (strcmp(bn, ".npmrc") == 0 || strcmp(bn, "npmrc") == 0 ||
        strcmp(bn, ".yarnrc") == 0 || strcmp(bn, ".yarnrc.yml") == 0 ||
        strcmp(bn, ".yarnrc.yaml") == 0 || strcmp(bn, "yarnrc.yml") == 0) {
        if (strstr(low, "registry") || strstr(low, "script-shell") ||
            strstr(low, "unsafehttpwhitelist") ||
            strstr(low, "npmregistryserver") ||
            strstr(low, "plugin"))
            return 50;
        return 0;
    }
    if (strstr(bn, ".pnpmfile.") != NULL || strcmp(bn, "pnpmfile.cjs") == 0 ||
        strcmp(bn, "pnpmfile.js") == 0) {
        if (strstr(low, "eval") || strstr(low, "require(") ||
            strstr(low, "curl") || strstr(low, "wget") ||
            strstr(low, "child_process") || strstr(low, "exec"))
            return 50;
        return 45;
    }
    if (strcmp(bn, ".gemrc") == 0 || strcmp(bn, "gemrc") == 0) {
        if (strstr(low, ":source") || strstr(low, "source") ||
            strstr(low, "http"))
            return 45;
        return 0;
    }
    /* cargo config.toml — [build] rustc-wrapper / paths / [alias] let a
     * config swap the compiler binary or override dep paths; a dropped
     * config.toml inside .cargo/ runs the wrapper on every rustc call.
     * Basename alone is too generic to flag (every tool ships one), so
     * it gates on the cargo-specific keys. */
    if (strcmp(bn, "config.toml") == 0) {
        if (strstr(low, "rustc-wrapper") || strstr(low, "rustflags") ||
            strstr(low, "[alias]") || strstr(low, "[patch.") ||
            strstr(low, "[source.") || strstr(low, "[path"))
            return 50;
        return 0;
    }
    /* docker config.json — credsStore/credHelpers name an external
     * credential-helper binary docker executes on login/pull; auths
     * with a bearer or helper is the cred-steal surface */
    if (strcmp(bn, "config.json") == 0) {
        if (strstr(low, "credsstore") || strstr(low, "credhelpers") ||
            strstr(low, "credstore"))
            return 50;
        return 0;
    }
    /* maven settings.xml — <mirror>/<server>/<proxy> redirect every
     * artifact resolution to an attacker host (Maven dependency
     * confusion; the mirror element is what makes it dangerous) */
    if (strcmp(bn, "settings.xml") == 0 ||
        strcmp(bn, "settings-security.xml") == 0 ||
        strcmp(bn, "toolchains.xml") == 0) {
        if (strstr(low, "<mirror") || strstr(low, "<server") ||
            strstr(low, "<proxy") || strstr(low, "<url"))
            return 45;
        return 0;
    }
    /* gradle init/settings/build scripts — init.gradle(.kts) runs on
     * EVERY build in the user home; build.gradle/.kts and
     * settings.gradle(.kts) run at configure time. eval/exec/url
     * inside one is a build-time payload */
    if (strstr(bn, "init.gradle") != NULL ||
        strstr(bn, "settings.gradle") != NULL ||
        strstr(bn, "build.gradle") != NULL) {
        if (strstr(low, "eval") || strstr(low, "exec") ||
            strstr(low, "curl") || strstr(low, "wget") ||
            strstr(low, "http") || strstr(low, "url"))
            return 50;
        return 0;
    }
    /* credential-store carriers — .pgpass/.boto/.pypirc/.dockercfg/
     * .dockerconfigjson/.htpasswd are plaintext or lightly-encoded
     * auth files; arriving as a file means credentials in transit */
    if (strcmp(bn, ".pgpass") == 0 || strcmp(bn, "pgpass.conf") == 0) {
        if (strchr(low, ':') != NULL && strchr(low, '@') == NULL)
            return 45;
        return 40;
    }
    if (strcmp(bn, ".boto") == 0 || strcmp(bn, "boto") == 0) {
        if (strstr(low, "aws_") || strstr(low, "credential"))
            return 50;
        return 40;
    }
    if (strcmp(bn, ".pypirc") == 0 || strcmp(bn, "pypirc") == 0) {
        if (strstr(low, "repository") || strstr(low, "password") ||
            strstr(low, "username"))
            return 45;
        return 40;
    }
    if (strcmp(bn, ".dockercfg") == 0 ||
        strcmp(bn, ".dockerconfigjson") == 0 ||
        strcmp(bn, "dockercfg") == 0) {
        if (strstr(low, "auths") || strstr(low, "auth"))
            return 50;
        return 40;
    }
    if (strcmp(bn, ".htpasswd") == 0 || strcmp(bn, "htpasswd") == 0) {
        if (strchr(low, ':') != NULL &&
            (strstr(low, "$apr") || strstr(low, "$2y") ||
             strstr(low, "{sha}") || strchr(low, '$')))
            return 45;
        return 40;
    }
    /* .htdigest — the digest-auth sibling of htpasswd (realm:user:hash) */
    if (strcmp(bn, ".htdigest") == 0 || strcmp(bn, "htdigest") == 0) {
        if (strchr(low, ':') != NULL && strchr(low, '$') != NULL)
            return 45;
        return 40;
    }
    /* git-credentials / .git-credentials — plaintext
     * `https://user:token@host` lines the credential-store helper
     * replays to remotes. A captured file is a ready-made token set */
    if (strcmp(bn, "git-credentials") == 0 ||
        strcmp(bn, ".git-credentials") == 0 ||
        strcmp(bn, "git-credentials.txt") == 0) {
        if (strstr(low, "://") && strchr(low, '@'))
            return 55;
        return 40;
    }
    /* PostgreSQL service file — pg_service.conf / .pg_service carries
     * host+user+password for named connection services           */
    if (strcmp(bn, "pg_service.conf") == 0 ||
        strcmp(bn, ".pg_service.conf") == 0 ||
        strcmp(bn, ".pg_service") == 0) {
        if (strstr(low, "password") || strstr(low, "host"))
            return 50;
        return 40;
    }
    /* squid.conf — a proxy config dropped in place becomes the
     * egress path; `http_access allow all` makes it an open
     * relay and url_rewrite/ssl_bump are interception hooks   */
    if (strcmp(bn, "squid.conf") == 0) {
        if (strstr(low, "http_access allow all") ||
            strstr(low, "url_rewrite") || strstr(low, "ssl_bump") ||
            strstr(low, "ssl bump"))
            return 45;
        return 0;
    }
    /* systemd timer/socket/path units — a dropped .timer/.socket/.path
     * activates the paired .service on schedule/connect/path-change;
     * activation keys are the content gate (a bare unit name is not
     * dangerous on its own) */
    if (strstr(bn, ".timer") != NULL || strstr(bn, ".socket") != NULL ||
        strstr(bn, ".path") != NULL) {
        if (strstr(low, "[timer]") || strstr(low, "[socket]") ||
            strstr(low, "[path]") || strstr(low, "oncalendar") ||
            strstr(low, "listenstream") || strstr(low, "onbootsec") ||
            strstr(low, "accept="))
            return 45;
        return 0;
    }
    /* service-spawner configs — xinetd/inetd/supervisord/runit run a
     * named binary per connection or on boot */
    if (strcmp(bn, "xinetd.conf") == 0 || strcmp(bn, "inetd.conf") == 0 ||
        strcmp(bn, "supervisord.conf") == 0 ||
        strcmp(bn, "supervisor.conf") == 0) {
        if (strstr(low, "server") || strstr(low, "command") ||
            strstr(low, "socket_type") || strstr(low, "[program:"))
            return 50;
        return 0;
    }
    /* mimeapps.list / defaults.list — reassigns x-scheme-handler or
     * MIME defaults so xdg-open launches the attacker's .desktop */
    if (strcmp(bn, "mimeapps.list") == 0 ||
        strcmp(bn, "defaults.list") == 0) {
        /* only scheme-handler reassignment is the remote vector — a
         * plain text/plain=vim.desktop local mapping stays clean */
        if (strstr(low, "x-scheme-handler"))
            return 45;
        return 0;
    }
    /* package/build descriptor carriers — Pipfile [[source]] and
     * MODULE.bazel/WORKSPACE http_archive/git_repository redirect what
     * gets fetched; Brewfile tap/brew/cask installs named packages;
     * conanfile.py runs Python on conan install; Dangerfile/Guardfile/
     * Capfile run ruby in CI/watchers — each is a resolver or
     * per-invocation exec surface */
    if (strcmp(bn, "pipfile") == 0 || strcmp(bn, "pipfile.lock") == 0) {
        if (strstr(low, "source") || strstr(low, "url") ||
            strstr(low, "http"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "module.bazel") == 0 || strcmp(bn, "workspace") == 0 ||
        strcmp(bn, "workspace.bazel") == 0 ||
        strcmp(bn, "workspace.bzlmod") == 0) {
        /* remote-fetch/repo-override primitives only — bazel_dep and
         * plain http:// are ordinary declarations, not the vector */
        if (strstr(low, "http_archive") || strstr(low, "git_repository") ||
            strstr(low, "new_git_repository") ||
            strstr(low, "local_repository") ||
            strstr(low, "register_toolchains"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "brewfile") == 0) {
        if (strstr(low, "tap ") || strstr(low, "brew ") ||
            strstr(low, "cask ") || strstr(low, "mas ") ||
            strstr(low, "whalebrew "))
            return 45;
        return 0;
    }
    if (strcmp(bn, "conanfile.py") == 0) {
        if (strstr(low, "os.system") || strstr(low, "subprocess") ||
            strstr(low, "eval(") || strstr(low, "exec(") ||
            strstr(low, "curl") || strstr(low, "wget") ||
            strstr(low, "tools.download") || strstr(low, "tools.get"))
            return 50;
        return 0;   /* a plain conanfile.py is the normal case */
    }
    /* fastlane/chef/thor ruby toolfiles — same `sh`/`system`/eval
     * surface as Dangerfile: each runs ruby at tool invocation */
    if (strcmp(bn, "dangerfile") == 0 || strcmp(bn, "guardfile") == 0 ||
        strcmp(bn, "capfile") == 0 || strcmp(bn, "snapfile") == 0 ||
        strcmp(bn, "gymfile") == 0 || strcmp(bn, "matchfile") == 0 ||
        strcmp(bn, "deliverfile") == 0 || strcmp(bn, "scanfile") == 0 ||
        strcmp(bn, "screengrabfile") == 0 || strcmp(bn, "pilotfile") == 0 ||
        strcmp(bn, "pluginfile") == 0 || strcmp(bn, "appfile") == 0 ||
        strcmp(bn, "berksfile") == 0 || strcmp(bn, "cheffile") == 0 ||
        strcmp(bn, "thorfile") == 0 || strcmp(bn, "fastfile") == 0 ||
        strcmp(bn, "rakefile") == 0 || strcmp(bn, "policyfile.rb") == 0) {
        if (strstr(low, "sh ") || strstr(low, "sh(") ||
            strstr(low, "system") || strstr(low, "`") ||
            strstr(low, "eval") || strstr(low, "curl") ||
            strstr(low, "wget") || strstr(low, "exec") ||
            strstr(low, "git:") || strstr(low, ":git") ||
            strstr(low, "cookbook") || strstr(low, "source "))
            return 45;
        return 0;
    }
    /* downloader/hook configs — aria2 on-download-* runs a script per
     * finished fetch; pacman XferCommand runs a fetcher as root;
     * makepkg DLAGENTS override per-protocol fetch commands; apt
     * *-Invoke/Pre-Install-Pkgs/Post-Invoke run during apt (root);
     * sources.list deb lines repoint the whole package feed;
     * .rtorrent.rc execute/schedule runs on torrent events */
    if (strcmp(bn, "aria2.conf") == 0 || strcmp(bn, ".aria2.conf") == 0 ||
        strcmp(bn, "aria2c.conf") == 0) {
        if (strstr(low, "on-download") || strstr(low, "on-bt-") ||
            strstr(low, "command") || strstr(low, "rpc-secret") ||
            strstr(low, "save-session-interval"))
            return 50;
        return 0;
    }
    if (strcmp(bn, "pacman.conf") == 0) {
        if (strstr(low, "xfercommand") || strstr(low, "siglevel = never") ||
            strstr(low, "syncfirst"))
            return 50;
        return 0;
    }
    if (strcmp(bn, "makepkg.conf") == 0) {
        if (strstr(low, "dlagents") || strstr(low, "buildenv") ||
            strstr(low, "integrity_check"))
            return 50;
        return 0;
    }
    if (strcmp(bn, "apt.conf") == 0 || strstr(bn, "apt.conf") != NULL) {
        if (strstr(low, "-invoke") || strstr(low, "pre-install") ||
            strstr(low, "post-invoke") || strstr(low, "dpkg::"))
            return 55;
        return 0;
    }
    if (strcmp(bn, "sources.list") == 0 ||
        strcmp(bn, "sources.list.d") == 0) {
        if (strstr(low, "deb ") || strstr(low, "deb-src") ||
            strstr(low, "signed-by") || strstr(low, "http"))
            return 45;
        return 0;
    }
    if (strcmp(bn, ".rtorrent.rc") == 0 || strcmp(bn, "rtorrent.rc") == 0) {
        if (strstr(low, "execute") || strstr(low, "schedule") ||
            strstr(low, "system.method"))
            return 50;
        return 0;
    }
    /* kernel/boot config carriers — sysctl.conf core_pattern=| runs a
     * program as root on any crash; xorg.conf ModulePath loads .so as
     * the X server; grub/syslinux/isolinux/pxelinux/loader configs can
     * rewrite kernel args or chain-load an attacker image */
    if (strcmp(bn, "sysctl.conf") == 0 || strstr(bn, "sysctl") != NULL) {
        if ((strstr(low, "core_pattern") && strchr(low, '|')) ||
            strstr(low, "core_pattern=|") || strstr(low, "core_pattern ="))
            return 55;
        /* hardening removal: ASLR/ptrace/kptr/dmesg/perf restricted off,
         * unprivileged user namespaces on — each weakens a boundary an
         * attacker wants down before exploiting                          */
        if (((strstr(low, "randomize_va_space") ||
              strstr(low, "kptr_restrict") ||
              strstr(low, "dmesg_restrict") ||
              strstr(low, "ptrace_scope") ||
              strstr(low, "perf_event_paranoid") ||
              strstr(low, "unprivileged_bpf_disabled")) &&
             (strstr(low, "= 0") || strstr(low, "=0") ||
              strstr(low, "= -1") || strstr(low, "=-1"))) ||
            (strstr(low, "unprivileged_userns_clone") &&
             (strstr(low, "= 1") || strstr(low, "=1"))))
            return 40;
        return 0;
    }
    if (strcmp(bn, "xorg.conf") == 0 || strstr(bn, "xorg.conf") != NULL) {
        if (strstr(low, "modulepath") || strstr(low, "load \"") ||
            strstr(low, "fontpath") || strstr(low, "serverlayout"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "grub.cfg") == 0 || strcmp(bn, "grub.conf") == 0 ||
        strcmp(bn, "menu.lst") == 0 || strcmp(bn, "syslinux.cfg") == 0 ||
        strcmp(bn, "isolinux.cfg") == 0 || strcmp(bn, "pxelinux.cfg") == 0 ||
        strcmp(bn, "loader.conf") == 0 || strstr(bn, "grub.d") != NULL ||
        strstr(bn, "_custom") != NULL) {
        if (strstr(low, "init=") || strstr(low, "rdinit") ||
            strstr(low, "chainloader") || strstr(low, "configfile") ||
            strstr(low, "source ") || strstr(low, "module") ||
            strstr(low, "linux ") || strstr(low, "append "))
            return 50;
        return 0;
    }
    /* anacrontab — same scheduled-exec carrier as crontab */
    if (strcmp(bn, "anacrontab") == 0) {
        if (strstr(low, "/") && (strstr(low, "*") || strstr(low, "@") ||
            strstr(low, "daily") || strstr(low, "weekly") ||
            strstr(low, "monthly")))
            return 40;
        return 0;
    }
    /* dir-locals.el — Emacs evaluates `(eval …)` dir-local entries when
     * ANY file in the directory is opened: a dropped .dir-locals.el in
     * a repo is exec-on-open for every contributor */
    if (strcmp(bn, ".dir-locals.el") == 0 ||
        strcmp(bn, "dir-locals.el") == 0 ||
        strcmp(bn, ".dir-locals-2.el") == 0) {
        if (strstr(low, "(eval") || strstr(low, "shell-command") ||
            strstr(low, "call-process"))
            return 55;
        return 0;
    }
    /* repo-fetch / hook-pipeline carriers — .gitmodules url points the
     * next submodule update at an attacker repo; .pre-commit-config
     * repo: clones+runs hook code on every commit; terragrunt.hcl
     * before_/after_/error_hook runs commands around terraform;
     * plugins.sbt/build.sbt addSbtPlugin+resolvers fetch and load code
     * at sbt start; uv.toml index-url/extra-index-url/find-links
     * repoints the python resolver; pyproject.toml [[tool.poetry
     * .source]]/[tool.uv] does the same inside a generic filename */
    if (strcmp(bn, ".gitmodules") == 0) {
        if (strstr(low, "url") || strstr(low, "http") ||
            strchr(low, '@'))
            return 45;
        return 0;
    }
    if (strcmp(bn, ".pre-commit-config.yaml") == 0 ||
        strcmp(bn, ".pre-commit-config.yml") == 0) {
        if (strstr(low, "repo:") && strstr(low, "http"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "terragrunt.hcl") == 0 ||
        strcmp(bn, ".terraformrc") == 0 || strcmp(bn, "terraform.rc") == 0) {
        if (strstr(low, "before_hook") || strstr(low, "after_hook") ||
            strstr(low, "error_hook") || strstr(low, "execute") ||
            strstr(low, "run_cmd") || strstr(low, "dev_overrides") ||
            strstr(low, "plugin_cache") ||
            strstr(low, "provider_installation"))
            return 50;
        return 0;
    }
    if (strcmp(bn, "plugins.sbt") == 0 || strcmp(bn, "build.sbt") == 0 ||
        strcmp(bn, "plugins.scala") == 0) {
        if (strstr(low, "addsbtplugin") || strstr(low, "resolver") ||
            strstr(low, "http"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "uv.toml") == 0 || strcmp(bn, ".uv.toml") == 0) {
        if (strstr(low, "index-url") || strstr(low, "extra-index-url") ||
            strstr(low, "find-links") || strstr(low, "no-index"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "pyproject.toml") == 0) {
        if (strstr(low, "tool.poetry.source") ||
            strstr(low, "tool.uv") || strstr(low, "index-url") ||
            strstr(low, "extra-index-url") || strstr(low, "find-links"))
            return 45;
        return 0;
    }
    /* setup.cfg resolver hooks — [easy_install] index_url /
     * dependency_links / find-links repoint the setuptools resolver
     * just like pyproject index-url                                       */
    if (strcmp(bn, "setup.cfg") == 0) {
        if (strstr(low, "index_url") || strstr(low, "index-url") ||
            strstr(low, "dependency_links") || strstr(low, "find-links") ||
            strstr(low, "easy_install"))
            return 45;
        return 0;
    }
    /* generic settings.json — only fires on keys that name a program
     * another tool will run: vscode *.executablePath / interpreterPath
     * point the editor at an attacker binary; transmission
     * script-torrent-done-* runs a script per finished download */
    if (strcmp(bn, "settings.json") == 0) {
        if (strstr(low, "executablepath") ||
            strstr(low, "interpreterpath") ||
            strstr(low, "script-torrent-done") ||
            strstr(low, "git.path"))
            return 50;
        return 0;
    }
    /* daemon-side exec hooks — rsyncd.conf pre-/post-xfer exec run per
     * transfer; crypttab keyscript/precheck/postcheck run as root in
     * the initramfs on every boot; ansible.cfg *_plugins and *_paths
     * load Python modules as code on every run */
    if (strcmp(bn, "rsyncd.conf") == 0 || strcmp(bn, "rsyncd.secrets") == 0) {
        if (strstr(low, "xfer exec") || strstr(low, "early exec") ||
            strstr(low, "exec =") || strstr(low, "secrets file") ||
            strstr(low, "rsyncable"))
            return 50;
        return 0;
    }
    if (strcmp(bn, "crypttab") == 0 || strcmp(bn, "crypttab.d") == 0) {
        if (strstr(low, "keyscript") || strstr(low, "precheck") ||
            strstr(low, "postcheck"))
            return 55;
        return 0;
    }
    if (strcmp(bn, "ansible.cfg") == 0) {
        if (strstr(low, "_plugins") || strstr(low, "_paths") ||
            strstr(low, "library") || strstr(low, "module_utils") ||
            strstr(low, "stdout_callback") || strstr(low, "connection"))
            return 45;
        return 0;
    }
    /* VCS / client-side hook configs — .hgrc [hooks]/[extensions] run a
     * shell line or load Python on hg events; lynx.cfg EXTERNAL/
     * DOWNLOADER/PRINTER/SYSTEM_EDITOR names a program lynx runs;
     * .offlineimaprc *tunnel, *eval, and *hook eval python or run ssh;
     * .authinfo stores machine/login/password credentials */
    if (strcmp(bn, ".hgrc") == 0 || strcmp(bn, "hgrc") == 0 ||
        strcmp(bn, "mercurial.ini") == 0) {
        if ((strstr(low, "[hooks]") || strstr(low, "[extensions]") ||
             strstr(low, "update") || strstr(low, "commit")) &&
            strchr(low, '='))
            return 50;
        return 0;
    }
    if (strcmp(bn, "lynx.cfg") == 0 || strcmp(bn, "lynxrc") == 0 ||
        strcmp(bn, ".lynxrc") == 0) {
        if (strstr(low, "external") || strstr(low, "downloader") ||
            strstr(low, "printer") || strstr(low, "system_editor") ||
            strstr(low, "trusted_exec"))
            return 45;
        return 0;
    }
    if (strcmp(bn, ".offlineimaprc") == 0 || strcmp(bn, "offlineimaprc") == 0 ||
        strcmp(bn, "offlineimap.conf") == 0) {
        if (strstr(low, "preauthtunnel") || strstr(low, "postauthtunnel") ||
            strstr(low, "remotepasseval") || strstr(low, "hook") ||
            strstr(low, "eval"))
            return 50;
        return 0;
    }
    if (strcmp(bn, ".authinfo") == 0 || strcmp(bn, "authinfo") == 0 ||
        strcmp(bn, ".authinfo.gpg") == 0) {
        if (strstr(low, "machine") && (strstr(low, "password") ||
            strstr(low, "login") || strstr(low, "port")))
            return 40;
        return 0;
    }
    /* webshell bodies — a dropped server-side page that reads a request
     * param into eval/system/exec is the classic RCE webshell;
     * .sql with xp_cmdshell, INTO OUTFILE, sp_oa* or COPY PROGRAM
     * turns a query file into host command execution; .lua os.execute/
     * dofile(loadstring over http) does the same for lua hosts */
    if (strstr(bn, ".php") || strstr(bn, ".phtml") ||
        strstr(bn, ".php5") || strstr(bn, ".pht") ||
        strstr(bn, ".phar") || strstr(bn, ".inc")) {
        if ((strstr(low, "eval(") || strstr(low, "assert(") ||
             strstr(low, "system(") || strstr(low, "passthru(") ||
             strstr(low, "exec(") || strstr(low, "popen(") ||
             strstr(low, "proc_open") || strstr(low, "shell_exec") ||
             strstr(low, "`") || strstr(low, "preg_replace")) &&
            (strstr(low, "$_") || strstr(low, "request") ||
             strstr(low, "post[") || strstr(low, "get[")))
            return 75;
        if ((strstr(low, "base64_decode") || strstr(low, "gzinflate") ||
             strstr(low, "gzuncompress") || strstr(low, "str_rot13") ||
             strstr(low, "strrev")) &&
            (strstr(low, "eval") || strstr(low, "assert") ||
             strstr(low, "$_") || strstr(low, "post") ||
             strstr(low, "get")))
            return 60;
        if (strstr(low, "move_uploaded_file") && strstr(low, "_files"))
            return 50;
        return 0;
    }
    if (strstr(bn, ".jsp") || strstr(bn, ".jspx") ||
        strstr(bn, ".jspf")) {
        if ((strstr(low, "exec(") || strstr(low, "exec ") ||
             strstr(low, "processbuilder") ||
             strstr(low, "getruntime")) &&
            (strstr(low, "request") || strstr(low, "getparameter") ||
             strstr(low, "param")))
            return 75;
        return 0;
    }
    if (strstr(bn, ".asp") || strstr(bn, ".aspx") ||
        strstr(bn, ".ashx") || strstr(bn, ".asmx") ||
        strstr(bn, ".cer")) {
        if (strstr(low, "wscript.shell") || strstr(low, "createobject") ||
            strstr(low, "process.start") || strstr(low, "cmd.exe") ||
            strstr(low, "powershell") || strstr(low, "executeglobal") ||
            strstr(low, "shell.application") ||
            strstr(low, "request.form") || strstr(low, "request(") ||
            strstr(low, "eval("))
            return 75;
        return 0;
    }
    if (strstr(bn, ".cfm") || strstr(bn, ".cfc")) {
        if (strstr(low, "cfexecute") || strstr(low, "cfhttp") ||
            strstr(low, "createobject") || strstr(low, "evaluate("))
            return 60;
        return 0;
    }
    if (strstr(bn, ".pl") || strstr(bn, ".cgi")) {
        if ((strstr(low, "system(") || strstr(low, "exec(") ||
             strstr(low, "open2") || strstr(low, "open3") ||
             strstr(low, "`") || strstr(low, "qx(")) &&
            (strstr(low, "param(") || strstr(low, "env") ||
             strstr(low, "stdin") || strstr(low, "query")))
            return 55;
        return 0;
    }
    if (strstr(bn, ".lua")) {
        if (strstr(low, "os.execute") || strstr(low, "io.popen") ||
            strstr(low, "loadstring") ||
            (strstr(low, "dofile") && strstr(low, "http")) ||
            (strstr(low, "load(") && strstr(low, "http")))
            return 55;
        return 0;
    }
    if (strstr(bn, ".sql")) {
        if (strstr(low, "xp_cmdshell") || strstr(low, "into outfile") ||
            strstr(low, "into dumpfile") || strstr(low, "load_file") ||
            strstr(low, "sp_oacreate") || strstr(low, "sp_oamethod") ||
            (strstr(low, "sp_executesql") && strstr(low, "master.")) ||
            (strstr(low, "copy ") && strstr(low, "program")) ||
            strstr(low, "lo_import") || strstr(low, "lo_export") ||
            strstr(low, "pg_read_file") || strstr(low, "sys_eval") ||
            strstr(low, "sys_exec") || strstr(low, "utl_file") ||
            strstr(low, "sqlmap"))
            return 60;
        return 0;
    }
    if (strstr(bn, ".hta")) {
        if (strstr(low, "activexobject") || strstr(low, "wscript.shell") ||
            strstr(low, "shell.application") || strstr(low, "run(") ||
            strstr(low, "exec(") || strstr(low, "powershell") ||
            strstr(low, "mshta") || strstr(low, "vbscript") ||
            strstr(low, "javascript:") || strstr(low, "createobject"))
            return 55;
        return 0;
    }
    if (strstr(bn, ".wsf") || strstr(bn, ".wsh")) {
        if (strstr(low, "<script") || strstr(low, "run(") ||
            strstr(low, "exec(") || strstr(low, "cscript") ||
            strstr(low, "wscript"))
            return 50;
        return 0;
    }
    if (strstr(bn, ".css") || strstr(bn, ".htc")) {
        if (strstr(low, "expression(") || strstr(low, "behavior") ||
            strstr(low, "-moz-binding") || strstr(low, "javascript:") ||
            strstr(low, "vbscript:") || strstr(low, "binding:"))
            return 45;
        return 0;
    }
    if (strstr(bn, ".ics") || strstr(bn, ".ical") ||
        strstr(bn, ".ifb")) {
        if ((strstr(low, "attach") || strstr(low, "url")) &&
            strstr(low, "http"))
            return 35;
        return 0;
    }
    if (strstr(bn, ".lsp") || strstr(bn, ".mnl") ||
        strcmp(bn, "acad.lsp") == 0 || strcmp(bn, "acaddoc.lsp") == 0) {
        if (strstr(low, "(command") || strstr(low, "startapp") ||
            strstr(low, "vl-cmdf") || strstr(low, "arxload") ||
            (strstr(low, "(load") && strstr(low, "http")) ||
            strstr(low, "shell"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "startup.m") == 0 || strcmp(bn, "finish.m") == 0 ||
        strcmp(bn, "init.m") == 0) {
        if (strstr(low, "system") || strstr(low, "eval") ||
            strstr(low, "unix(") || strstr(low, "dos(") ||
            strstr(low, "urlread") || strstr(low, "websave") ||
            strstr(low, "run(") || strstr(low, "import") ||
            strstr(low, "pacletinstall") || strstr(low, "install"))
            return 45;
        return 0;
    }
    /* private-key material arriving as a file — the key itself is the
     * credential, so `file id_rsa` is a disclosure event; a bare
     * CERTIFICATE/PUBLIC KEY block is public material, not a leak */
    if (strstr(low, "private key") || strstr(low, "openssh-key-v1") ||
        strstr(low, "putty-user-key-file")) {
        if ((strstr(low, "begin") && strstr(low, "private")) ||
            strstr(low, "openssh-key-v1") ||
            strstr(low, "putty-user-key-file"))
            return 80;
        if (strstr(low, "certificate") || strstr(low, "public"))
            return 30;
        return 0;
    }
    if (strcmp(bn, "id_rsa") == 0 || strcmp(bn, "id_dsa") == 0 ||
        strcmp(bn, "id_ecdsa") == 0 || strcmp(bn, "id_ed25519") == 0 ||
        strcmp(bn, "identity") == 0) {
        if (strstr(low, "private") || strstr(low, "begin") ||
            strstr(low, "mii") || strstr(low, "key"))
            return 80;
        return 0;
    }
    /* credential containers — wallet.dat, .kirbi, .ccache, *.dmp,
     * browser stores are exfiltration or replay material arriving as
     * files; the basename alone is the signal (content is binary) */
    if (strcmp(bn, "wallet.dat") == 0 || strcmp(bn, "electrum.dat") == 0 ||
        strcmp(bn, "wallet.aes.json") == 0 || strstr(bn, ".wallet") ||
        strstr(bn, ".keys"))
        return 45;
    if (strstr(bn, ".kirbi") || strstr(bn, ".ccache") ||
        strstr(bn, ".ktb") || strcmp(bn, "krbtgt") == 0)
        return 55;
    if (strstr(bn, ".dmp") || strstr(bn, ".mdmp") ||
        strstr(bn, ".dump") || strcmp(bn, "core") == 0 ||
        strcmp(bn, "lsass.dmp") == 0 || strcmp(bn, "memory.dmp") == 0 ||
        strcmp(bn, "hiberfil.sys") == 0 || strcmp(bn, "pagefile.sys") == 0)
        return 45;
    if (strcmp(bn, "logins.json") == 0 || strcmp(bn, "key4.db") == 0 ||
        strcmp(bn, "key3.db") == 0 || strcmp(bn, "cert8.db") == 0 ||
        strcmp(bn, "cert9.db") == 0 || strcmp(bn, "cookies.sqlite") == 0 ||
        strcmp(bn, "signons.sqlite") == 0 || strcmp(bn, "formhistory.sqlite") == 0 ||
        strcmp(bn, "login data") == 0 || strcmp(bn, "web data") == 0 ||
        strcmp(bn, "secring.gpg") == 0 || strcmp(bn, "secring.skr") == 0 ||
        strstr(bn, ".kdbx") || strstr(bn, ".kdb") ||
        strstr(bn, ".keychain") || strstr(bn, ".agilekeychain") ||
        strstr(bn, ".opvault") || strstr(bn, ".keystore") ||
        strstr(bn, ".jks") || strstr(bn, ".ppk"))
        return 45;
    /* .pem/.key/.p8 — public cert material is LOG; the PRIVATE block
     * above already returns 80 for key material */
    if (strstr(bn, ".pem") || strstr(bn, ".p8") ||
        strstr(bn, ".key"))
        return 30;
    if (strcmp(bn, "cookies.txt") == 0 || strcmp(bn, ".mozilla") == 0) {
        if (strstr(low, "true") || strstr(low, "false") ||
            strstr(low, "netscape") || strstr(low, ".com"))
            return 45;
        return 0;
    }
    /* desktop/launcher carriers — .desktop Exec= runs on double-click;
     * .theme SCRNSAVE.EXE swaps the screensaver for a binary;
     * .settingcontent-ms DeepLink/Cpl auto-launches (CVE-2018-8414);
     * .application/.appref-ms codebase is a ClickOnce deploy feed */
    if (strstr(bn, ".desktop") || strcmp(bn, ".directory") == 0) {
        if (strstr(low, "exec=") || strstr(low, "tryexec") ||
            strstr(low, "x-kde"))
            return 50;
        return 0;
    }
    if (strstr(bn, ".theme") || strstr(bn, ".themepack") ||
        strstr(bn, "deskthemepack")) {
        if (strstr(low, "scrnsave") || strstr(low, ".scr") ||
            strstr(low, "visualstyles") || strstr(low, "msstyles"))
            return 50;
        return 0;
    }
    if (strstr(bn, ".settingcontent-ms")) {
        if (strstr(low, "deeplink") || strstr(low, "hostpage") ||
            strstr(low, "cpl") || strstr(low, "executable") ||
            strstr(low, "arguments"))
            return 60;
        return 0;
    }
    if (strstr(bn, ".application") || strstr(bn, ".appref-ms")) {
        if (strstr(low, "codebase") || strstr(low, "deploymentprovider") ||
            strstr(low, "dependency") || strstr(low, "http"))
            return 50;
        return 0;
    }
    /* msbuild / build-descriptor exec — csproj Exec/PreBuildEvent/
     * UsingTask run at build; *.cmake execute_process/file(DOWNLOAD)
     * run at configure; build.ninja rule command= runs at build */
    if (strstr(bn, ".csproj") || strstr(bn, ".fsproj") ||
        strstr(bn, ".vcxproj") || strstr(bn, ".vbproj") ||
        strstr(bn, ".targets") || strstr(bn, ".props") ||
        (strstr(bn, ".proj") != NULL && strstr(bn, ".proj")[5] == '\0')) {
        if (strstr(low, "exec") || strstr(low, "prebuild") ||
            strstr(low, "postbuild") || strstr(low, "usingtask") ||
            strstr(low, "codetask") || strstr(low, "beforetargets") ||
            strstr(low, "aftertargets") || strstr(low, "downloadfile") ||
            strstr(low, "webclient"))
            return 55;
        return 0;
    }
    if (strstr(bn, ".cmake") && strcmp(bn, "cmakelists.txt") != 0) {
        if (strstr(low, "execute_process") || strstr(low, "file(download") ||
            strstr(low, "externalproject") || strstr(low, "curl") ||
            strstr(low, "wget") || strstr(low, "invoke-webrequest"))
            return 55;
        return 0;
    }
    if (strstr(bn, ".ninja") || strcmp(bn, "build.ninja") == 0) {
        if (strstr(low, "command =") || strstr(low, "command="))
            return 50;
        return 0;
    }
    /* resolver-redirect remainder — go.mod replace/go.work use point
     * module resolution elsewhere; Gemfile/gems.rb source/git/path
     * repoints bundler; nuget.config packageSources repoints nuget */
    if (strcmp(bn, "go.mod") == 0 || strcmp(bn, "go.work") == 0) {
        if (strstr(low, "replace") || strstr(low, "retract"))
            return 40;
        return 0;
    }
    /* Gemfile: every file has a `source` — the dep-confusion vector
     * is the non-registry specifiers :git/git:/path:/eval_gemfile */
    if (strcmp(bn, "gemfile") == 0 || strcmp(bn, "gems.rb") == 0) {
        if (strstr(low, ":git") || strstr(low, "git:") ||
            strstr(low, "path:") || strstr(low, "eval_gemfile") ||
            strstr(low, "instance_eval"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "nuget.config") == 0 || strcmp(bn, "nugetconfig") == 0) {
        if (strstr(low, "packagesources") || strstr(low, "add key") ||
            (strstr(low, "value=") && strstr(low, "http")))
            return 45;
        return 0;
    }
    /* remaining CI configs — cloudbuild steps run images+args; woodpecker
     * steps run commands; both arrive as files that CI executes */
    if (strcmp(bn, "cloudbuild.yaml") == 0 ||
        strcmp(bn, "cloudbuild.yml") == 0) {
        if (strstr(low, "steps") || strstr(low, "args") ||
            strstr(low, "entrypoint") || strstr(low, "script"))
            return 50;
        return 0;
    }
    if (strcmp(bn, ".woodpecker.yml") == 0 ||
        strcmp(bn, ".woodpecker.yaml") == 0 ||
        strcmp(bn, "woodpecker.yml") == 0) {
        if ((strstr(low, "commands") || strstr(low, "script") ||
             strstr(low, "steps")) &&
            (strstr(low, "curl") || strstr(low, "wget") ||
             strstr(low, "http") || strstr(low, "|sh") ||
             strstr(low, "| sh") || strstr(low, "nc ") ||
             strstr(low, "bash")))
            return 45;
        return 0;
    }
    /* vscode task/debug launch — tasks.json command/shell runs on the
     * build task; launch.json program/runtimeExecutable launches a
     * binary on F5; both generic basenames so key-gated */
    if (strcmp(bn, "tasks.json") == 0) {
        /* "command" is the schema — the vector is a command that
         * fetches or shells out */
        if ((strstr(low, "\"command\"") || strstr(low, "\"shell\"") ||
             strstr(low, "\"script\"")) &&
            (strstr(low, "curl") || strstr(low, "wget") ||
             strstr(low, "http") || strstr(low, "powershell") ||
             strstr(low, "cmd") || strstr(low, "bash") ||
             strstr(low, "sh ") || strstr(low, "nc ") ||
             strstr(low, "base64") || strstr(low, "eval")))
            return 50;
        return 0;
    }
    if (strcmp(bn, "launch.json") == 0) {
        if (strstr(low, "\"program\"") || strstr(low, "runtimeexecutable") ||
            strstr(low, "\"prelaunchtask\"") || strstr(low, "\"runtime\""))
            return 45;
        return 0;
    }
    /* AI-assistant instruction carriers — .cursorrules/copilot-
     * instructions.md/CLAUDE.md/AGENTS.md/.windsurfrules are read into
     * the model context by coding assistants; a payload line
     * (fetch|pipe|decode-exec) is a prompt-injection supply-chain
     * vector. Keyed tightly to exec payloads so real docs stay clean */
    if (strcmp(bn, ".cursorrules") == 0 || strcmp(bn, ".windsurfrules") == 0 ||
        strcmp(bn, "copilot-instructions.md") == 0 ||
        strcmp(bn, "claude.md") == 0 || strcmp(bn, "agents.md") == 0 ||
        strcmp(bn, ".cursorrules.md") == 0) {
        if (((strstr(low, "curl") || strstr(low, "wget") ||
              strstr(low, "invoke-webrequest") || strstr(low, "iwr ")) &&
             strstr(low, "http")) || strstr(low, "| sh") ||
            strstr(low, "|sh") || strstr(low, "base64 -d") ||
            strstr(low, "nc -e") || strstr(low, "eval $(") ||
            strstr(low, "bash -c") || strstr(low, "iex("))
            return 50;
        return 0;
    }
    /* IaC/k8s descriptor redirects — kustomization resources/bases/
     * helmCharts pull remote manifests; Chart.yaml dependencies pull
     * remote charts; tfvars/tfstate carry plaintext infra secrets;
     * credentials.json service_account/private_key is a cloud key;
     * .env carries runtime secrets */
    if (strcmp(bn, "kustomization.yaml") == 0 ||
        strcmp(bn, "kustomization.yml") == 0 ||
        strcmp(bn, "kustomization") == 0) {
        if ((strstr(low, "resources") || strstr(low, "bases") ||
             strstr(low, "helmcharts") || strstr(low, "generators") ||
             strstr(low, "patches")) &&
            (strstr(low, "http") || strstr(low, "git@") ||
             strstr(low, ".git")))
            return 45;
        return 0;
    }
    if (strcmp(bn, "chart.yaml") == 0 || strcmp(bn, "chart.yml") == 0) {
        if (strstr(low, "dependencies") || strstr(low, "repository") ||
            (strstr(low, "icon") && strstr(low, "http")))
            return 40;
        return 0;
    }
    if (strstr(bn, ".tfvars") || strstr(bn, ".tfstate") ||
        strcmp(bn, "terraform.tfstate") == 0 ||
        strstr(bn, "tfstate")) {
        if (strstr(low, "password") || strstr(low, "secret") ||
            strstr(low, "private_key") || strstr(low, "access_key") ||
            strstr(low, "api_key") || strstr(low, "token") ||
            strstr(low, "client_secret") || strstr(low, "resources") ||
            strstr(low, "backend"))
            return 50;
        return 0;
    }
    if (strcmp(bn, "credentials.json") == 0 ||
        strstr(bn, "service-account") != NULL ||
        strstr(bn, "service_account") != NULL ||
        strstr(bn, "client_secret") != NULL || strstr(bn, "-key.json") != NULL) {
        if (strstr(low, "service_account") || strstr(low, "private_key") ||
            strstr(low, "client_secret") || strstr(low, "refresh_token") ||
            strstr(low, "token_uri") || strstr(low, "auth_uri") ||
            strstr(low, "installed"))
            return 65;
        return 0;
    }
    {
        /* .env / .env* / *.env — runtime-secrets files; a delivered
         * one is either a leak or an attempt to set attacker env */
        size_t bl_ = strlen(bn);
        if ((strncmp(bn, ".env", 4) == 0 ||
             (bl_ > 4 && strcmp(bn + bl_ - 4, ".env") == 0) ||
             strcmp(bn, "env.list") == 0 || strcmp(bn, "envfile") == 0) &&
            strstr(bn, "example") == NULL && strstr(bn, "sample") == NULL &&
            strstr(bn, "template") == NULL && strstr(bn, "dist") == NULL) {
            if (strstr(low, "password") || strstr(low, "secret") ||
                strstr(low, "token") || strstr(low, "key") ||
                strstr(low, "api") || strstr(low, "private") ||
                strstr(low, "credential"))
                return 45;
            return 0;
        }
    }
    /* FTP/remote-access credential stores — the harvested-file list
     * every infostealer targets: filezilla sitemanager, winscp.ini,
     * cisco .pcf enc_GroupPwd, remmina/vnc saved sessions, mRemoteNG
     * confCons.xml, RDCMan .rdg */
    if (strcmp(bn, "sitemanager.xml") == 0 ||
        strcmp(bn, "filezilla.xml") == 0 || strcmp(bn, "recentservers.xml") == 0 ||
        strcmp(bn, "queue.sqlite3") == 0) {
        if (strstr(low, "pass") || strstr(low, "user") ||
            strstr(low, "host") || strstr(low, "logontype"))
            return 55;
        return 0;
    }
    if (strcmp(bn, "winscp.ini") == 0) {
        if (strstr(low, "password") || strstr(low, "hostname") ||
            strstr(low, "hostkey") || strstr(low, "[sessions"))
            return 55;
        return 0;
    }
    if (strstr(bn, ".pcf") || strcmp(bn, "vpn.pcf") == 0) {
        if (strstr(low, "enc_grouppwd") || strstr(low, "host") ||
            strstr(low, "groupname") || strstr(low, "username"))
            return 50;
        return 0;
    }
    if (strstr(bn, ".remmina") || strstr(bn, ".remmina.prefs")) {
        if (strstr(low, "password") || strstr(low, "server") ||
            strstr(low, "ssh") || strstr(low, "protocol"))
            return 45;
        return 0;
    }
    if (strstr(bn, ".vnc") != NULL) {
        if (strstr(low, "password") || strstr(low, "host"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "confcons.xml") == 0 || strstr(bn, "mremoteng") != NULL ||
        strcmp(bn, "connections.xml") == 0 || strstr(bn, ".rdg")) {
        if (strstr(low, "password") || strstr(low, "hostname") ||
            strstr(low, "protocol") || strstr(low, "username"))
            return 55;
        return 0;
    }
    /* macOS profile/location carriers — .terminal CommandString runs a
     * shell line on double-click; .ftploc/.afploc/.vloc/.mailloc/
     * .newsloc/.fileloc open a remote share or client */
    if (strstr(bn, ".terminal")) {
        if (strstr(low, "commandstring") || strstr(low, "runcommandasshell") ||
            (strstr(low, "customtitle") && strstr(low, "exec")))
            return 60;
        return 0;
    }
    if (strstr(bn, ".ftploc") || strstr(bn, ".afploc") ||
        strstr(bn, ".vloc") || strstr(bn, ".mailloc") ||
        strstr(bn, ".newsloc") || strstr(bn, ".fileloc")) {
        if (strstr(low, "url") || strstr(low, "ftp:") ||
            strstr(low, "afp:") || strstr(low, "vnc:") ||
            strstr(low, "http"))
            return 45;
        return 0;
    }
    /* mail-delivery and notification hooks — sieve pipe/execute/
     * vnd.dovecot.* run a program per delivered message; getmailrc/
     * fdm.conf/.esmtprc mda/pipe/filter entries run the delivery agent;
     * dunstrc script= runs on every notification; .xscreensaver
     * programs: lists what the screensaver launches */
    if (strstr(bn, ".sieve") || strstr(bn, "dovecot.sieve")) {
        if (strstr(low, "pipe") || strstr(low, "execute") ||
            strstr(low, "vnd.dovecot") || strstr(low, "filter") ||
            (strstr(low, "include") && strstr(low, "http")))
            return 55;
        return 0;
    }
    if (strcmp(bn, "getmailrc") == 0 || strcmp(bn, "fdm.conf") == 0 ||
        strcmp(bn, ".esmtprc") == 0) {
        if (strstr(low, "mda") || strstr(low, "pipe") ||
            strstr(low, "filter") || strstr(low, "external") ||
            strstr(low, "preconnect") || strstr(low, "postconnect") ||
            strstr(low, "path ="))
            return 50;
        return 0;
    }
    if (strcmp(bn, "dunstrc") == 0) {
        if (strstr(low, "script") || strstr(low, "always_run_script") ||
            strstr(low, "browser") || strstr(low, "on_"))
            return 45;
        return 0;
    }
    if (strcmp(bn, ".xscreensaver") == 0) {
        if (strstr(low, "programs") || strstr(low, "exec") ||
            strstr(low, "capturestderr"))
            return 40;
        return 0;
    }
    if (strcmp(bn, "gtkrc") == 0 || strstr(bn, ".gtkrc") != NULL) {
        if (strstr(low, "engine") || strstr(low, "module_path") ||
            strstr(low, "pixmap_path") || strstr(low, "include"))
            return 45;
        return 0;
    }
    /* mail/message carriers — .eml/.emlx/.msg/.mbox deliver phishing
     * content; .vcf/.vcard PHOTO/URL/SOUND URI refs fetch remote on
     * import                                                */
    if (strstr(bn, ".eml") || strstr(bn, ".emlx") ||
        strstr(bn, ".msg") || strstr(bn, ".mbox")) {
        if ((strstr(low, "from:") || strstr(low, "subject:")) &&
            (strstr(low, "http") || strstr(low, "attachment") ||
             strstr(low, "href") || strstr(low, "click")))
            return 35;
        return 0;
    }
    if (strstr(bn, ".vcf") || strstr(bn, ".vcard")) {
        if ((strstr(low, "photo") || strstr(low, "url") ||
             strstr(low, "sound") || strstr(low, "logo")) &&
            (strstr(low, "uri") || strstr(low, "http")))
            return 35;
        return 0;
    }
    /* tool configs that are code — *.config.{js,ts,mjs,cjs} and
     * *.conf.js are evaluated by the tool at startup; the Python/Ruby
     * hook files (conftest.py hooks run at pytest collection, setup.py
     * runs at pip install, config.ru at rackup) are the same shape */
    {
        const char *cext;
        int is_tool_cfg = 0;
        if ((cext = strstr(bn, ".config.")) != NULL &&
            (!strcmp(cext, ".config.js") || !strcmp(cext, ".config.ts") ||
             !strcmp(cext, ".config.mjs") || !strcmp(cext, ".config.cjs") ||
             !strcmp(cext, ".config.mts")))
            is_tool_cfg = 1;
        if (strstr(bn, ".conf.js") || strstr(bn, ".conf.ts") ||
            strstr(bn, "gulpfile.") || strstr(bn, "gruntfile.") ||
            strcmp(bn, "conftest.py") == 0 || strcmp(bn, "noxfile.py") == 0 ||
            strcmp(bn, "setup.py") == 0 || strcmp(bn, "config.ru") == 0 ||
            strcmp(bn, "tsconfig.json") == 0 || strcmp(bn, "jsconfig.json") == 0 ||
            strcmp(bn, "jsr.json") == 0 || strcmp(bn, "deno.json") == 0 ||
            strcmp(bn, "deno.jsonc") == 0 || strcmp(bn, "bunfig.toml") == 0)
            is_tool_cfg = 1;
        if (is_tool_cfg &&
            (strstr(low, "require(") || strstr(low, "import ") ||
             strstr(low, "plugins") || strstr(low, "presets") ||
             strstr(low, "exec") || strstr(low, "spawn") ||
             strstr(low, "child_process") || strstr(low, "eval") ||
             strstr(low, "curl") || strstr(low, "wget") ||
             strstr(low, "http") || strstr(low, "setup(") ||
             strstr(low, "cmdclass") || strstr(low, "entry_points") ||
             strstr(low, "pytest") || strstr(low, "fixture") ||
             strstr(low, "hookimpl") || strstr(low, "tasks") ||
             strstr(low, "paths") || strstr(low, "extends") ||
             strstr(low, "imports") || strstr(low, "importmap") ||
             strstr(low, "registry") || strstr(low, "trusteddependencies") ||
             strstr(low, "postinstall") || strstr(low, "loader") ||
             strstr(low, "map ") || strstr(low, "use ") ||
             strstr(low, "run ") || strstr(low, "process.")))
            return 40;
    }
    /* CI/build descriptor remainder — wercker/bitrise/concourse/
     * netlify/vercel/now/fly/app.yaml/render/heroku/railway/app.json
     * all declare commands or remote resources CI/deploy runs */
    if (strcmp(bn, "wercker.yml") == 0 || strcmp(bn, "bitrise.yml") == 0 ||
        strcmp(bn, "bitrise.yaml") == 0 || strcmp(bn, "pipeline.yml") == 0 ||
        strcmp(bn, "pipeline.yaml") == 0 || strcmp(bn, "concourse.yml") == 0) {
        /* the vector is a runnable step/image — schema keys like
         * `steps:` alone are the normal empty case */
        if (strstr(low, "script") || strstr(low, "run:") ||
            strstr(low, "command") || strstr(low, "exec") ||
            strstr(low, "curl") || strstr(low, "wget") ||
            strstr(low, "bash") || strstr(low, "powershell") ||
            strstr(low, "entrypoint") || strstr(low, "args") ||
            strstr(low, "path:") || strstr(low, "privileged") ||
            strstr(low, "params") || strstr(low, "image") ||
            strstr(low, "cwd") || strstr(low, "run_if"))
            return 45;
        return 0;
    }
    if (strstr(bn, ".nomad") || strstr(bn, ".hcl") ||
        strcmp(bn, "nomad.hcl") == 0 || strcmp(bn, "consul.hcl") == 0 ||
        strcmp(bn, "vault.hcl") == 0 || strstr(bn, "waypoint") != NULL) {
        if (strstr(low, "task") || strstr(low, "driver") ||
            strstr(low, "config") || strstr(low, "command") ||
            strstr(low, "artifact") || strstr(low, "template") ||
            strstr(low, "provisioner") || strstr(low, "script") ||
            strstr(low, "check") || strstr(low, "listener") ||
            strstr(low, "plugin") || strstr(low, "source") ||
            strstr(low, "build") || strstr(low, "job") ||
            strstr(low, "exec") || strstr(low, "shell"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "serverless.yml") == 0 || strcmp(bn, "serverless.yaml") == 0 ||
        strcmp(bn, "serverless.ts") == 0 || strcmp(bn, "serverless.js") == 0 ||
        strcmp(bn, "sst.config.ts") == 0 || strcmp(bn, "sst.config.js") == 0) {
        if (strstr(low, "plugins") || strstr(low, "functions") ||
            strstr(low, "provider") || strstr(low, "resources") ||
            strstr(low, "hooks") || strstr(low, "custom"))
            return 40;
        return 0;
    }
    if (strcmp(bn, "netlify.toml") == 0 || strcmp(bn, "netlify.yaml") == 0) {
        if (strstr(low, "command") || strstr(low, "plugins") ||
            strstr(low, "package") || strstr(low, "edge_functions") ||
            strstr(low, "redirects") || strstr(low, "functions") ||
            strstr(low, "build"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "vercel.json") == 0 || strcmp(bn, "now.json") == 0) {
        if (strstr(low, "functions") || strstr(low, "rewrites") ||
            strstr(low, "redirects") || strstr(low, "crons") ||
            strstr(low, "builds") || strstr(low, "cleanurls") ||
            strstr(low, "regions"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "fly.toml") == 0 || (strstr(bn, "fly.") != NULL &&
        strstr(bn, ".toml") != NULL)) {
        if (strstr(low, "release_command") || strstr(low, "exec") ||
            strstr(low, "cmd") || strstr(low, "entrypoint") ||
            strstr(low, "mounts") || strstr(low, "processes") ||
            strstr(low, "checks") || strstr(low, "deploy") ||
            strstr(low, "services"))
            return 45;
        return 0;
    }
    if (strcmp(bn, "app.yaml") == 0 || strcmp(bn, "app.yml") == 0 ||
        strcmp(bn, "appengine-web.xml") == 0 ||
        strcmp(bn, "render.yaml") == 0 || strcmp(bn, "heroku.yml") == 0 ||
        strcmp(bn, "app.json") == 0 || strcmp(bn, "dokku.json") == 0 ||
        strcmp(bn, "railway.json") == 0 || strcmp(bn, "railway.toml") == 0) {
        if (strstr(low, "entrypoint") || strstr(low, "runtime") ||
            strstr(low, "handlers") || strstr(low, "env_variables") ||
            strstr(low, "inbound_services") || strstr(low, "script") ||
            strstr(low, "buildcommand") || strstr(low, "startcommand") ||
            strstr(low, "predeploycommand") || strstr(low, "healthcheck") ||
            strstr(low, "run") || strstr(low, "scripts") ||
            strstr(low, "build") || strstr(low, "release") ||
            strstr(low, "formation") || strstr(low, "addons") ||
            strstr(low, "buildpacks") || strstr(low, "cron"))
            return 45;
        return 0;
    }
    /* java container/framework configs — server.xml/context.xml/
     * web.xml/spring/struts/beans instantiate classes, realms and
     * datasources; log4j/logback ${jndi: is the Log4Shell lookup;
     * MANIFEST Premain/Agent-Class/Class-Path is a java-agent exec */
    if (strcmp(bn, "server.xml") == 0 || strcmp(bn, "context.xml") == 0 ||
        strcmp(bn, "tomcat-users.xml") == 0 || strcmp(bn, "web.xml") == 0 ||
        strcmp(bn, "weblogic.xml") == 0 || strcmp(bn, "beans.xml") == 0 ||
        strcmp(bn, "applicationcontext.xml") == 0 ||
        strcmp(bn, "struts.xml") == 0 || strcmp(bn, "faces-config.xml") == 0 ||
        strcmp(bn, "ejb-jar.xml") == 0 || strcmp(bn, "persistence.xml") == 0 ||
        strcmp(bn, "hibernate.cfg.xml") == 0 ||
        (strstr(bn, "spring") != NULL && strstr(bn, ".xml") != NULL) ||
        (strstr(bn, "jboss") != NULL && strstr(bn, ".xml") != NULL)) {
        if (strstr(low, "classname") || strstr(low, "listener") ||
            strstr(low, "resource") || strstr(low, "jndi") ||
            strstr(low, "servlet-class") || strstr(low, "filter-class") ||
            strstr(low, "listener-class") || strstr(low, "<bean ") ||
            strstr(low, "factory-bean") || strstr(low, "init-method") ||
            strstr(low, "valve") || strstr(low, "realm") ||
            strstr(low, "environment") || strstr(low, "password") ||
            strstr(low, "datasource") || strstr(low, "connection-url") ||
            strstr(low, "driver-class") || strstr(low, "destroy-method"))
            return 50;
        return 0;
    }
    if (strstr(bn, "log4j") != NULL || strstr(bn, "logback") != NULL ||
        strcmp(bn, "logging.properties") == 0 ||
        strcmp(bn, "log4j2-test.xml") == 0) {
        if (strstr(low, "${jndi") || strstr(low, "jndi") ||
            strstr(low, "socketappender") || strstr(low, "smtpappender") ||
            strstr(low, "jmsappender") || strstr(low, "script") ||
            strstr(low, "lookup") || strstr(low, "http") ||
            strstr(low, "write"))
            return 55;
        return 0;
    }
    if (strcmp(bn, "manifest.mf") == 0) {
        if (strstr(low, "premain-class") || strstr(low, "agent-class") ||
            strstr(low, "launcher-agent-class") || strstr(low, "class-path") ||
            strstr(low, "main-class") || strstr(low, "extension-name") ||
            strstr(low, "can-redefine") || strstr(low, "can-retransform"))
            return 50;
        return 0;
    }
    if (strstr(bn, ".slk") != NULL && strstr(bn, ".slk")[4] == 0) {
        if (strstr(low, "cmd") || strstr(low, "exec") ||
            strstr(low, "shell") || strstr(low, "dde") ||
            strstr(low, "macro") || strstr(low, "formula"))
            return 55;
        return 0;
    }
    /* ecosystem descriptors — pubspec git/hosted deps, deps.edn
     * :git/url, mix.exs git/path deps, project.clj repositories,
     * shard.yml github deps, composer.json scripts/repositories,
     * cabal.project source-repository-package, stack.yaml extra-deps,
     * rebar.config hooks, dune run/system actions, *.nix flake inputs/
     * fetchurl/shellHook, nimble tasks, deno tasks/imports, bunfig
     * registry — each repoints the resolver or runs at tool time */
    if (strcmp(bn, "pubspec.yaml") == 0 || strcmp(bn, "pubspec.lock") == 0 ||
        strcmp(bn, "pubspec_overrides.yaml") == 0 ||
        strcmp(bn, "deps.edn") == 0 || strcmp(bn, "bb.edn") == 0 ||
        strcmp(bn, "build.edn") == 0 || strcmp(bn, "mix.exs") == 0 ||
        strcmp(bn, "project.clj") == 0 || strcmp(bn, "build.boot") == 0 ||
        strcmp(bn, "shard.yml") == 0 || strcmp(bn, "shard.lock") == 0 ||
        strcmp(bn, "composer.json") == 0 || strcmp(bn, "composer.lock") == 0 ||
        strcmp(bn, "cabal.project") == 0 || strcmp(bn, "stack.yaml") == 0 ||
        strcmp(bn, "stack.yml") == 0 || strcmp(bn, "rebar.config") == 0 ||
        strcmp(bn, "rebar3.config") == 0 || strcmp(bn, "dune") == 0 ||
        strcmp(bn, "dune-project") == 0 || strstr(bn, ".opam") != NULL ||
        strstr(bn, ".nix") != NULL || strcmp(bn, "guix.scm") == 0 ||
        strcmp(bn, "manifest.scm") == 0 || strcmp(bn, "channels.scm") == 0 ||
        strcmp(bn, "nim.cfg") == 0 || strstr(bn, ".nimble") != NULL ||
        strstr(bn, ".nims") != NULL || strcmp(bn, "nimble") == 0) {
        if (strstr(low, "git:") || strstr(low, ":git") ||
            strstr(low, "github:") || strstr(low, "gitlab:") ||
            strstr(low, "hosted:") || strstr(low, "path:") ||
            strstr(low, "dependency_overrides") ||
            strstr(low, "source-repository") || strstr(low, "location") ||
            strstr(low, "extra-deps") || strstr(low, "repositories") ||
            strstr(low, "\"scripts\"") || strstr(low, "minimum-stability") ||
            strstr(low, "allow-plugins") || strstr(low, "depexts") ||
            strstr(low, "pin-depends") || strstr(low, "dev-repo") ||
            strstr(low, "fetchurl") || strstr(low, "fetchgit") ||
            strstr(low, "fetchtarball") || strstr(low, "builtins") ||
            strstr(low, "inputs") || strstr(low, "shellhook") ||
            strstr(low, "installphase") || strstr(low, "buildcommand") ||
            strstr(low, "origin") || strstr(low, "channels") ||
            strstr(low, "writeShellScript") || strstr(low, "mkderivation") ||
            strstr(low, "(rule") || strstr(low, "(action") ||
            strstr(low, "(run") || strstr(low, "(system") ||
            strstr(low, "(bash") || strstr(low, "task") ||
            strstr(low, "requires") || strstr(low, "hooks") ||
            strstr(low, "post_hooks") || strstr(low, "pre_hooks") ||
            strstr(low, "escript") || strstr(low, "erl_opts") ||
            strstr(low, "eval_in_leiningen") || strstr(low, "deftask") ||
            strstr(low, "set-env!") || strstr(low, "executables") ||
            strstr(low, "targets") || strstr(low, "switch") ||
            strstr(low, "installdirs") || strstr(low, "srcDir") ||
            strstr(low, "scripts"))
            return 45;
        return 0;
    }
    /* vscode multi-root workspace — folders/settings/tasks can point
     * interpreters and language-server binaries at attacker paths */
    if (strstr(bn, ".code-workspace") != NULL) {
        if (strstr(low, "\"tasks\"") || strstr(low, "\"launch\"") ||
            strstr(low, "executablepath") || strstr(low, "server.path") ||
            strstr(low, "defaultinterpreterpath") ||
            strstr(low, "alternatetools") || strstr(low, "\"terminal\"") ||
            strstr(low, "\"folders\"") || strstr(low, "\"extensions\""))
            return 45;
        return 0;
    }
    /* makefile family — recipes run on `make`; fetch/eval primitives */
    if (strcmp(bn, "makefile") == 0 || strcmp(bn, "gnumakefile") == 0 ||
        strcmp(bn, "bsdmakefile") == 0 || strstr(bn, "makefile.") != NULL) {
        /* $(shell …) is normal make syntax — the vector is a fetch or
         * interpreter inside it or a recipe line */
        if (strstr(low, "$(shell curl") || strstr(low, "$(shell wget") ||
            strstr(low, "$(shell nc") || strstr(low, "$(shell sh") ||
            strstr(low, "$(shell bash") || strstr(low, "$(shell eval") ||
            strstr(low, "$(shell python") || strstr(low, "$(shell perl") ||
            strstr(low, "$(shell ruby") || strstr(low, "$(shell php") ||
            strstr(low, "$(shell node") || strstr(low, "$(shell http") ||
            strstr(low, "-include") || strstr(low, "curl") ||
            strstr(low, "wget") || strstr(low, "nc ") ||
            strstr(low, "powershell") || strstr(low, "invoke-webrequest") ||
            strstr(low, "bitsadmin") || strstr(low, "certutil") ||
            strstr(low, "iwr ") || strstr(low, "iex(") ||
            strstr(low, "base64") || strstr(low, "|sh") ||
            strstr(low, "| sh") || strstr(low, "|bash") ||
            strstr(low, "| bash"))
            return 45;
        return 0;
    }
    /* .rhosts — `+ host` / host lines grant passwordless rsh/rlogin
     * trust to the listed host: a dropped .rhosts is an auth bypass */
    if (strcmp(bn, ".rhosts") == 0 || strcmp(bn, "hosts.equiv") == 0)
        return (strstr(low, "+") != NULL || strstr(low, ".com") ||
                strstr(low, ".net") || strstr(low, ".org") ||
                strchr(low, '.')) ? 50 : 40;
    /* .netrc — plaintext `machine X login Y password Z` credentials
     * for ftp/curl/rsync — a captured .netrc is a credential file */
    if (strcmp(bn, ".netrc") == 0 || strcmp(bn, "_netrc") == 0)
        return (strstr(low, "machine ") && strstr(low, "password"))
                ? 50 : 40;
    /* .har — HTTP archive exports carry live session cookies and
     * authorization headers (a stolen-session file) */
    if (strstr(bn, ".har") != NULL &&
        (strstr(low, "\"cookies\"") || strstr(low, "\"authorization\"") ||
         strstr(low, "\"set-cookie\"") || strstr(low, "\"password\"") ||
         strstr(low, "\"token\"")))
        return 45;
    /* Network device configs — running-config / startup-config /
     * device .cfg with enable password / SNMP community / crypto keys
     * leaks the device creds (and is itself a config drop that
     * rewrites a host) */
    if (strstr(bn, ".cfg") != NULL || strcmp(bn, "running-config") == 0 ||
        strcmp(bn, "startup-config") == 0 ||
        strncmp(bn, "running", 7) == 0) {
        if (strstr(low, "enable password") || strstr(low, "enable secret") ||
            strstr(low, "snmp-server community") ||
            strstr(low, "crypto isakmp key") ||
            strstr(low, "tacacs-server key") ||
            strstr(low, "radius-server key") ||
            (strstr(low, "username ") && strstr(low, "password")))
            return 45;
    }
    /* modprobe.d — `install <mod> <cmd>` / post-install hooks execute a
     * command when the module is loaded */
    if (strstr(bn, ".conf") != NULL &&
        (strstr(low, "post-install") || strstr(low, "pre-remove") ||
         (strstr(low, "install ") &&
          (strstr(low, "modprobe") || strstr(low, "/bin/") ||
           strstr(low, "/tmp/") || strstr(low, "/dev/")))))
        return 55;
    /* tmpfiles.d — a `f+`/`w`/`d`/`L` line plants or overwrites files
     * (incl. authorized_keys) on boot */
    if ((strstr(bn, ".conf") != NULL || strcmp(bn, "tmpfiles") == 0) &&
        (strstr(low, "\nf+ ") || strstr(low, "\nf ") ||
         strstr(low, "\nw ") || strstr(low, "\nd ") ||
         strstr(low, "f+ /") || strstr(low, "w /") ||
         strstr(low, "d /") || strstr(low, "l /")))
        return 40;
    /* shell login files — sourced at login/zsh startup; .zshenv is the
     * aggressive one (every zsh, incl. non-interactive). The common
     * .bashrc/.zshrc/.profile are excluded — ubiquitous in dotfiles and
     * already covered by F18's content gate. */
    if (strcmp(bn, ".zshenv") == 0 || strcmp(bn, ".zprofile") == 0 ||
        strcmp(bn, ".zlogin") == 0)
        return 50;
    if (strcmp(bn, ".bash_profile") == 0 || strcmp(bn, ".bash_login") == 0 ||
        strcmp(bn, ".bash_logout") == 0)
        return 40;
    /* other tool launch configs that eval content on startup —
     * config.fish runs on every fish shell, .tmux.conf `run-shell`
     * executes a script, .muttrc hooks sendmail/mailcap, .screenrc
     * `exec` runs commands — same persistence class as shell rc */
    if (strcmp(bn, "config.fish") == 0 ||
        strcmp(bn, ".tmux.conf") == 0 || strcmp(bn, "tmux.conf") == 0 ||
        strcmp(bn, ".muttrc") == 0 || strcmp(bn, "muttrc") == 0 ||
        strcmp(bn, ".screenrc") == 0 ||
        strcmp(bn, "config.exs") == 0)
        return 45;
    /* package-manager configs — an index-url/channel override hands the
     * resolver to an attacker mirror (dependency confusion at install) */
    if (strcmp(bn, "pip.conf") == 0 || strcmp(bn, "pip.ini") == 0 ||
        strcmp(bn, "condarc") == 0 || strcmp(bn, ".condarc") == 0) {
        if (strstr(low, "index-url") || strstr(low, "extra-index") ||
            strstr(low, "channels") || strstr(low, "trusted-host"))
            return 50;
        return 35;
    }
    /* sshd_config — PermitRootLogin/AuthorizedKeysFile/ForceCommand
     * swaps out the remote-access policy itself */
    if (strcmp(bn, "sshd_config") == 0) {
        if (strstr(low, "permitrootlogin yes") ||
            strstr(low, "permitemptypasswords yes") ||
            strstr(low, "authorizedkeysfile") ||
            strstr(low, "forcecommand") ||
            strstr(low, "permituserenvironment yes"))
            return 60;
        return 30;
    }
    /* web/proxy daemon configs — proxy_pass/rewrite/backend hands the
     * traffic to an attacker upstream */
    if (strcmp(bn, "nginx.conf") == 0 || strcmp(bn, "httpd.conf") == 0 ||
        strcmp(bn, "apache2.conf") == 0 || strcmp(bn, "haproxy.cfg") == 0 ||
        strcmp(bn, "caddyfile") == 0 || strcmp(bn, "traefik.yml") == 0 ||
        strcmp(bn, "traefik.yaml") == 0) {
        if (strstr(low, "proxy_pass") || strstr(low, "redirect") ||
            strstr(low, "server ") || strstr(low, "backend"))
            return 45;
        return 30;
    }
    /* auth databases — a dropped passwd/shadow/group replaces the
     * account list wholesale */
    if (strcmp(bn, "shadow") == 0 || strcmp(bn, "passwd") == 0 ||
        strcmp(bn, "group") == 0 || strcmp(bn, "gshadow") == 0 ||
        strcmp(bn, "master.passwd") == 0) {
        if (strchr(low, ':') != NULL && strstr(low, ":") != NULL &&
            (strstr(low, "root") || strchr(low, '$') != NULL ||
             strstr(low, ":x:") || strstr(low, ":::")))
            return 55;
        return 30;
    }
    /* DB service configs — bind-all + no-auth is silent data exposure */
    if (strcmp(bn, "redis.conf") == 0 || strcmp(bn, "mongod.conf") == 0 ||
        strcmp(bn, "postgresql.conf") == 0 || strcmp(bn, "my.cnf") == 0 ||
        strcmp(bn, "my.ini") == 0 || strcmp(bn, "elasticsearch.yml") == 0) {
        if ((strstr(low, "bind 0.0.0.0") || strstr(low, "bind: 0.0.0.0") ||
             strstr(low, "bind_ip = 0.0.0.0") || strstr(low, "host: 0.0.0.0") ||
             strstr(low, "listen_addresses") ||
             strstr(low, "network.host")) &&
            (strstr(low, "protected-mode no") ||
             strstr(low, "protected-mode: no") ||
             strstr(low, "authorization: disabled") ||
             strstr(low, "noauth") || strstr(low, "requirepass") == NULL))
            return 55;
        if (strstr(low, "0.0.0.0"))
            return 40;
        return 0;
    }
    /* WireGuard — a [Peer] AllowedIPs 0.0.0.0/0 routes ALL traffic
     * through the attacker's endpoint */
    if ((strstr(bn, ".conf") != NULL) &&
        strstr(low, "[interface]") && strstr(low, "[peer]")) {
        if (strstr(low, "allowedips") &&
            (strstr(low, "0.0.0.0/0") || strstr(low, "::/0")))
            return 55;
        return 40;
    }
    /* php.ini — auto_prepend/allow_url_include execute attacker code on
     * every request; disable_functions= empties the sandbox */
    if (strcmp(bn, "php.ini") == 0 || strcmp(bn, "php-cli.ini") == 0) {
        if (strstr(low, "auto_prepend_file") ||
            strstr(low, "auto_append_file") ||
            strstr(low, "allow_url_include"))
            return 55;
        if (strstr(low, "disable_functions") || strstr(low, "open_basedir"))
            return 40;
        return 0;
    }
    return 0;
}

/* ─── F57: lockfile registry poisoning — a lockfile's resolved/source/
 *      remote URL pointing off the official registry (or at cleartext
 *      http) swaps the package a `install` fetches. Scans each
 *      resolved/source/url/remote key's URL, extracts the host, and
 *      requires it to sit on the ecosystem's official registry or a
 *      common git forge (git deps are legitimate); anything else is a
 *      poisoned dependency. Basename-gated so random JSON/YAML with a
 *      'source' key elsewhere stays clean.                           */
static const char *const LOCKFILE_NAMES[] = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "poetry.lock", "uv.lock", "gemfile.lock",
    "composer.lock", "cargo.lock", "packages.lock.json", NULL
};
static const char *const REGISTRY_HOSTS[] = {
    /* official package registries + ubiquitous git forges (git+https
     * deps are a normal lockfile pattern)                        */
    "registry.npmjs.org", "registry.yarnpkg.com",
    "pypi.org", "files.pythonhosted.org",
    "rubygems.org", "packagist.org", "repo.packagist.org",
    "crates.io", "static.crates.io", "index.crates.io",
    "github.com", "codeload.github.com", "gitlab.com",
    "bitbucket.org", "dev.azure.com", "objects.githubusercontent.com",
    "proxy.golang.org", "sum.golang.org", NULL
};
static int
host_on_allowlist(const char *host, size_t hlen) {
    int i;
    for (i = 0; REGISTRY_HOSTS[i]; i++) {
        const char *h = REGISTRY_HOSTS[i];
        size_t hl = strlen(h);
        /* exact match, or host ends with ".<registry>" (subdomain) */
        if (hlen == hl && memcmp(host, h, hl) == 0)
            return 1;
        if (hlen > hl + 1 && memcmp(host + hlen - hl, h, hl) == 0 &&
            host[hlen - hl - 1] == '.')
            return 1;
    }
    return 0;
}
static int
lockfile_url_score(const unsigned char *head, size_t len,
    const char *basename_start) {
    static const char *const KEYS[] = {
        "\"resolved\"", "resolved:", "\"source\"", "source =",
        "source=", "remote:", "\"remote\"", "\"url\"", "url =",
        "url=", "download =", "download=", "tarball:",
        "\"tarball\"", "resolution:", "\"resolution\"", NULL
    };
    char low[8193], bn[256];
    size_t n = 0, i;
    int is_lf = 0;
    str_lower(basename_start ? basename_start : "", bn, sizeof(bn));
    for (i = 0; LOCKFILE_NAMES[i]; i++)
        if (strcmp(bn, LOCKFILE_NAMES[i]) == 0) { is_lf = 1; break; }
    if (!is_lf)
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';

    {
        int cleartext = 0, offreg = 0;
        int k;
        for (k = 0; KEYS[k]; k++) {
            const char *p = low;
            size_t kl = strlen(KEYS[k]);
            while ((p = strstr(p, KEYS[k])) != NULL) {
                /* a URL should appear within ~64 chars of the key */
                const char *win = p + kl;
                const char *wlim = win + 64;
                const char *u;
                if (wlim > low + n) wlim = low + n;
                for (u = win; u + 6 < wlim; u++) {
                    if (memcmp(u, "http://", 7) == 0 ||
                        memcmp(u, "https://", 8) == 0) {
                        int https = (u[4] == 's');
                        const char *host = u + (https ? 8 : 7);
                        const char *hend = host;
                        while (hend < low + n &&
                               ((*hend >= 'a' && *hend <= 'z') ||
                                (*hend >= '0' && *hend <= '9') ||
                                *hend == '.' || *hend == '-' ||
                                *hend == '[' || *hend == ']'))
                            hend++;
                        if (hend > host) {
                            if (!https)
                                cleartext = 1;
                            if (!host_on_allowlist(host,
                                    (size_t)(hend - host)))
                                offreg = 1;
                        }
                        break;
                    }
                }
                p += kl;
            }
        }
        if (offreg)
            return 55;
        if (cleartext)
            return 45;
    }
    return 0;
}

/* ─── F48: .ica Citrix launch file — a [WFClient]/[ApplicationServers]
 *      descriptor whose Address=/InitialProgram= launches a remote
 *      published application on open (Citrix phishing delivery) ───── */
static int
ica_launch_score(const unsigned char *head, size_t len,
    const char *ext) {
    char extl[40], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".ica"))
        return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "[wfclient]") && !strstr(low, "[applicationservers]") &&
        !strstr(low, "[application"))
        return 0;
    if (strstr(low, "initialprogram=") || strstr(low, "address="))
        return 45;
    return 0;
}

/* ─── F39: tar member slip — a ustar/v7 member name or ustar prefix
 *      carrying '..' or an absolute path escapes the extract dir on
 *      permissive untars (busybox, custom extractors). Reuses the
 *      zip-slip segment matcher ──────────────────────────────────── */
static int
tar_slip_score(const unsigned char *head, size_t len) {
    size_t off = 0;
    if (len < 512) return 0;
    /* ustar magic at 257; v7 tar has no magic — require 'ustar' or a
     * plausible typeflag+checksum to stay deterministic */
    while (off + 512 <= len) {
        const unsigned char *h = head + off;
        int ustar = memcmp(h + 257, "ustar", 5) == 0;
        char typeflag = (char)h[156];
        if (!ustar &&
            !(typeflag == '0' || typeflag == '\0' || typeflag == '5' ||
              typeflag == '7'))
            break;
        if (zip_name_is_traversal(h, 100)) return 70;
        if (h[0] == '/' || (h[0] >= 'a' && h[0] <= 'z' && h[1] == ':') ||
            (h[0] >= 'A' && h[0] <= 'Z' && h[1] == ':'))
            return 70;
        if (ustar && zip_name_is_traversal(h + 345, 155)) return 70;
        {
            /* octal size at offset 124 (11 digits + NUL/space) */
            unsigned long sz = 0;
            int i;
            for (i = 0; i < 11; i++) {
                unsigned char c = h[124 + i];
                if (c >= '0' && c <= '7') sz = sz * 8 + (c - '0');
            }
            off += 512 + ((sz + 511) & ~511UL);
        }
        if (off + 512 > len) break;
        if (head[off] == '\0') break;
    }
    return 0;
}

/* ─── F40: build-tool exec+fetch — build.gradle/.kts/.sbt (and vendored
 *      mvn/ant xml) that exec a downloader = code exec at build time.
 *      exec/commandLine/processBuilder alone is normal build tooling;
 *      combined with curl|wget|url fetch it is a supply-chain hole ── */
static int
build_exec_score(const unsigned char *head, size_t len,
                 const char *basename_start, const char *ext) {
    char extl[32], lown[64], low[4097];
    size_t n = 0, i;
    int is_build = 0;
    static const char *const BEXT[] = {
        ".gradle", ".kts", ".sbt", NULL
    };
    str_lower(ext ? ext : "", extl, sizeof(extl));
    for (i = 0; BEXT[i]; i++)
        if (strcmp(extl, BEXT[i]) == 0) { is_build = 1; break; }
    if (!is_build) {
        str_lower(basename_start, lown, sizeof(lown));
        if (strncmp(lown, "build.gradle", 12) == 0 ||
            strncmp(lown, "settings.gradle", 15) == 0 ||
            strcmp(lown, "pom.xml") == 0 || strcmp(lown, "build.xml") == 0 ||
            strcmp(lown, "setup.cfg") == 0)
            is_build = 1;
    }
    if (!is_build) return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    /* exec primitive present? */
    if (!strstr(low, "exec") && !strstr(low, "commandline") &&
        !strstr(low, "processbuilder") && !strstr(low, "dolast") &&
        !strstr(low, "ant.exec"))
        return 0;
    /* plus a fetch/exfil primitive? */
    if (strstr(low, "curl") || strstr(low, "wget") ||
        strstr(low, "invoke-webrequest") || strstr(low, "iwr ") ||
        strstr(low, "url.openstream") || strstr(low, "new url(") ||
        strstr(low, "httpclient"))
        return 55;
    /* gradle 'repositories' / maven mirrors to an unknown host is the
     * quieter variant: injected repo substitutes all artifacts */
    if (strstr(low, "repositories") &&
        (strstr(low, "jitpack") || strstr(low, "maven { url") ||
         strstr(low, "ivy { url") || strstr(low, "url \"http://")))
        return 45;
    return 0;
}

/* ─── F36: .rdp rogue redirect — an emailed .rdp that redirects
 *      drives/clipboard/smartcards to a remote desktop lets the rogue
 *      server read local files and harvest input (rogue-RDP class).
 *      Full-address alone is normal; redirection keys are the tell ─── */
static int
rdp_redirect_score(const unsigned char *head, size_t len,
                   const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    int sc = 0;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".rdp") != 0) return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "full address:s:")) return 0;
    if (strstr(low, "drivestoredirect")) sc = 55;
    else if (strstr(low, "redirectsmartcards")) {
        if (sc < 45) sc = 45;
    }
    if (strstr(low, "redirectclipboard") ||
        strstr(low, "redirectprinters") || strstr(low, "redirectcomports") ||
        strstr(low, "camerastoredirect")) {
        if (sc < 40) sc = 40;
    }
    return sc;
}

/* ─── F37: .ovpn script hooks — up/down/route-up/ipchange/learn-
 *      address run a script as root around tunnel events;
 *      'management' opens a remote-control socket; script-security
 *      ≥2 enables them ──────────────────────────────────────────── */
static int
ovpn_hook_score(const unsigned char *head, size_t len, const char *ext) {
    char extl[32], low[4097];
    size_t n = 0, i;
    int sc = 0;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".ovpn") != 0) return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "client") && !strstr(low, "dev tun") &&
        !strstr(low, "dev tap") && !strstr(low, "remote "))
        return 0;   /* not recognisably an openvpn config */
    {
        static const char *const HOOKS[] = {
            "\nup ", "\ndown ", "\nroute-up ", "\nipchange ",
            "\nlearn-address", "\nclient-connect", "\ntls-verify ",
            "\nauth-user-pass-verify", NULL
        };
        for (i = 0; HOOKS[i]; i++)
            if (strstr(low, HOOKS[i]) ||
                strncmp(low, HOOKS[i] + 1, strlen(HOOKS[i]) - 1) == 0) {
                sc = 55;
                break;
            }
    }
    if (strstr(low, "\nmanagement ") ||
        strncmp(low, "management ", 11) == 0) {
        if (sc < 45) sc = 45;
    }
    if (strstr(low, "script-security 3") && sc < 50) sc = 50;
    return sc;
}

/* ─── F38: .mobileconfig rogue profile — a config profile can install
 *      a root CA (com.apple.security.*) → silent TLS interception on
 *      the device, or set a global HTTP proxy / managed VPN ───────── */
static int
mobileconfig_score(const unsigned char *head, size_t len,
                   const char *ext) {
    char extl[40], low[4097];
    size_t n = 0, i;
    str_lower(ext ? ext : "", extl, sizeof(extl));
    if (strcmp(extl, ".mobileconfig") != 0) return 0;
    if (len > sizeof(low) - 1) len = sizeof(low) - 1;
    for (i = 0; i < len; i++) low[n++] = (char)tolower(head[i]);
    low[n] = '\0';
    if (!strstr(low, "payloadtype")) return 0;
    if (strstr(low, "com.apple.security.root") ||
        strstr(low, "com.apple.security.pkcs") ||
        strstr(low, "com.apple.security.pem"))
        return 60;
    if (strstr(low, "com.apple.proxy") || strstr(low, "com.apple.vpn"))
        return 55;
    if (strstr(low, "com.apple.dns") || strstr(low, "com.apple.ldap"))
        return 45;
    return 0;
}

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

    /* UTF-16 evasion: a BOM-prefixed UTF-16 file stores ASCII text
     * with interleaved NUL/high bytes, hiding it from every
     * string-based check below (a UTF-16 .ps1 download cradle reads
     * as a plain file). Decode in place — the decoded length is always
     * shorter than the source span, so dst never overruns src. */
    if (head_len >= 4) {
        int le = (head[0] == 0xff && head[1] == 0xfe);
        int be = (head[0] == 0xfe && head[1] == 0xff);
        if (le || be) {
            ssize_t si = 2, di = 0;
            while (si + 1 < head_len) {
                unsigned char c = le ? head[si] : head[si + 1];
                head[di++] = c ? c : (unsigned char)'?';
                si += 2;
            }
            head_len = di;
            fv_add(&v, 15,
                "F47: UTF-16 encoded content — decoded for analysis "
                "(encoding can evade string-based detection)");
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
            int has_streams = 0;
            int has_auto = 0;
            ssize_t i;
            for (i = 0; i <= head_len - 3; i++) {
                if (head[i] == 'V' && head[i+1] == 'B' && head[i+2] == 'A') {
                    has_vba = 1; break;
                }
            }
            /* "VBA" in document text is weak (a doc can merely mention
             * VBA); macro storage streams (Macros/, _VBA_PROJECT,
             * PROJECT/dir) are structural — and an auto-executing entry
             * point (AutoOpen/Document_Open/…) is the maldoc payload
             * itself (Emotet/Dridex class). */
            for (i = 0; i <= head_len - 6; i++) {
                if (memcmp(head + i, "Macros", 6) == 0 ||
                    (i <= head_len - 7 &&
                     memcmp(head + i, "PROJECT", 7) == 0)) {
                    has_streams = 1; break;
                }
            }
            for (i = 0; i <= head_len - 8; i++) {
                if (memcmp(head + i, "AutoOpen", 8) == 0 ||
                    memcmp(head + i, "AutoExec", 8) == 0 ||
                    (i <= head_len - 13 &&
                     memcmp(head + i, "Document_Open", 13) == 0) ||
                    (i <= head_len - 13 &&
                     memcmp(head + i, "Workbook_Open", 13) == 0)) {
                    has_auto = 1; break;
                }
            }
            if (has_auto)
                fv_add(&v, 65,
                    "F4: OLE document contains auto-executing VBA macro "
                    "(AutoOpen/Document_Open)");
            else if (has_vba && has_streams)
                fv_add(&v, 55,
                    "F4: OLE document contains VBA macro storage streams");
            else if (has_vba)
                fv_add(&v, 35,
                    "F4: OLE document contains VBA macro indicators");
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

    /* ── F12: ZIP-slip — archive member escaping the extract dir ───── */
    if (head_len > 30) {
        int vba = 0;
        int zs = zip_slip_score(head, (size_t)head_len, &vba);
        if (zs > 0) {
            fv_add(&v, zs,
                "F12: ZIP-SLIP — archive member name escapes the "
                "extraction directory (../ traversal or absolute path)");
        }
        /* ── F22: OOXML macro smuggling — a vbaProject.bin member in
         *      a container named like a macro-free format (.docx/
         *      .xlsx/.pptx) is a renamed .docm — the extension tells
         *      the user "no macros" while the payload ships anyway.
         *      Real .docm/.xlsm score lower: the macros there are
         *      declared by the format itself. ──────────────────────── */
        if (vba) {
            char lex[32];
            int fs;
            str_lower(ext, lex, sizeof(lex));
            if (!strcmp(lex, ".docx") || !strcmp(lex, ".xlsx") ||
                !strcmp(lex, ".pptx") || !strcmp(lex, ".doc") ||
                !strcmp(lex, ".xls")  || !strcmp(lex, ".ppt") ||
                !strcmp(lex, ".dotx") || !strcmp(lex, ".xltx") ||
                !strcmp(lex, ".potx") || !strcmp(lex, ".vsdx"))
                fs = 65;
            else if (!strcmp(lex, ".docm") || !strcmp(lex, ".xlsm") ||
                     !strcmp(lex, ".pptm") || !strcmp(lex, ".dotm") ||
                     !strcmp(lex, ".xltm") || !strcmp(lex, ".potm"))
                fs = 35;
            else
                fs = 50;
            fv_add(&v, fs,
                "F22: OOXML MACRO SMUGGLING — vbaProject.bin member "
                "in container named '%s'%s",
                lex[0] ? lex : "(no extension)",
                fs == 65 ? " — the extension says macro-free "
                           "(renamed macro doc)" : "");
        }
    }

    /* ── F13: credential-harvest form — HTML attachment posting a
     *      password to a remote URL ───────────────────────────────── */
    if (head_len > 0) {
        int cf = credential_form_score(head, (size_t)head_len);
        if (cf > 0) {
            fv_add(&v, cf,
                "F13: CREDENTIAL-HARVEST form — HTML <form> posts a "
                "password field to an absolute remote URL (fake-login "
                "attachment pattern)");
        }
    }

    /* ── F23: Makefile parse-time exec — `$(shell …)` and
     *      `!=`/`$(!=)` BSD-make form run while make PARSES the
     *      file: `make -n`, `make -q`, even tab-completion executes
     *      it. Only exec-shaped arguments flag — `$(shell pwd)` /
     *      `$(shell date)` are idiomatic build glue. ────────────── */
    if (head_len > 0) {
        char lown[64], extl[32];
        int is_mk;
        str_lower(basename_start, lown, sizeof(lown));
        str_lower(ext ? ext : "", extl, sizeof(extl));
        is_mk = (strncmp(lown, "makefile", 8) == 0 ||
                 strcmp(lown, "gnumakefile") == 0 ||
                 strcmp(extl, ".mk") == 0);
        if (is_mk) {
            char low[4097];
            size_t n = 0, k;
            static const char *const MX[] = {
                "curl", "wget", "http", "sh -c", "bash", "python",
                "perl", "ruby", "eval", "/tmp", "~", "id_rsa",
                ".ssh", NULL
            };
            const char *sh;
            for (k = 0; k < (size_t)head_len &&
                        n < sizeof(low) - 1; k++)
                low[n++] = (char)tolower(head[k]);
            low[n] = '\0';
            sh = strstr(low, "$(shell");
            if (!sh) sh = strstr(low, "!=");
            if (sh) {
                int hit = 0;
                for (k = 0; MX[k]; k++)
                    if (strstr(sh, MX[k])) { hit = 1; break; }
                if (hit)
                    fv_add(&v, 55,
                        "F23: MAKEFILE PARSE-TIME EXEC — $(shell)/!= "
                        "runs a fetch-or-shell command while make "
                        "parses the file (even make -n) (score 55)");
            }
        }
    }

    /* ── F24: Terraform plan/apply-time exec — `external` data
     *      sources run their `program` during `terraform plan` (the
     *      documented malicious-module RCE class); `local-exec` /
     *      `remote-exec` provisioners run on apply. A vendored .tf
     *      file you never audited still executes. ────────────────── */
    if (head_len > 0) {
        char extl[32];
        str_lower(ext ? ext : "", extl, sizeof(extl));
        if (strcmp(extl, ".tf") == 0 || strcmp(extl, ".tf.json") == 0) {
            char low[4097];
            size_t n = 0, k;
            for (k = 0; k < (size_t)head_len && n < sizeof(low) - 1; k++)
                low[n++] = (char)tolower(head[k]);
            low[n] = '\0';
            if ((strstr(low, "external") && strstr(low, "program")) ||
                strstr(low, "local-exec") || strstr(low, "remote-exec") ||
                (strstr(low, "provisioner") && strstr(low, "command")))
                fv_add(&v, 55,
                    "F24: TF EXEC — external data source / provisioner "
                    "runs a program during terraform plan or apply "
                    "(score 55)");
        }
    }

    /* ── F25: privileged Kubernetes manifest — apiVersion/kind YAML
     *      asking for privileged containers, host namespaces,
     *      dangerous caps or hostPath mounts (PodSecurity baseline/
     *      restricted violations; container-breakout class) ────────── */
    if (head_len > 0) {
        int kp = k8s_priv_score(head, (size_t)head_len, ext);
        if (kp > 0) {
            fv_add(&v, kp,
                "F25: K8S PRIVILEGED — manifest requests privileged/"
                "host-namespace/capability escalation (score %d)", kp);
        }
    }

    /* ── F26: docker-compose privilege — compose service running
     *      privileged, sharing host namespaces, mounting docker.sock
     *      or host root, or adding dangerous caps ──────────────────── */
    if (head_len > 0) {
        int cp = compose_priv_score(head, (size_t)head_len,
                                    basename_start, ext);
        if (cp > 0) {
            fv_add(&v, cp,
                "F26: COMPOSE PRIVILEGED — docker-compose service runs "
                "privileged / host-namespace / docker.sock / host-root "
                "mount (score %d)", cp);
        }
    }

    /* ── F27: YAML unsafe-load tags — !!python/object / !ruby/…
     *      deserialize into arbitrary objects under yaml.load /
     *      Psych.load (gadget RCE class) ─────────────────────────── */
    if (head_len > 0) {
        int yt = yaml_unsafe_tag_score(head, (size_t)head_len, ext);
        if (yt > 0) {
            fv_add(&v, yt,
                "F27: YAML UNSAFE-LOAD TAG — executable deserialization "
                "tag (!!python/object, !ruby/, …) — instantiates code "
                "under yaml.load/unsafe_load (score %d)", yt);
        }
    }

    /* ── F28: pickle/.pth code-exec — pickle GLOBAL refs to system/
     *      eval/exec/subprocess, or a .pth `import` line executing
     *      at interpreter startup ─────────────────────────────────── */
    if (head_len > 0) {
        int pe = py_exec_score(head, (size_t)head_len, ext);
        if (pe > 0) {
            fv_add(&v, pe,
                "F28: PY EXEC — pickle GLOBAL opcode references system/"
                "eval/subprocess, or .pth import-line exec (score %d)",
                pe);
        }
    }

    /* ── F29: autorun.inf — [autorun] open=/shellexecute=/shell\…
     *      self-executing removable-media lure ─────────────────────── */
    if (head_len > 0) {
        int ar = autorun_score(head, (size_t)head_len, ext);
        if (ar > 0) {
            fv_add(&v, ar,
                "F29: AUTORUN — [autorun] open/shell command key "
                "self-executes on media mount (score %d)", ar);
        }
    }

    /* ── F30: .pac WPAD hijack — FindProxyForURL returning a remote
     *      PROXY/SOCKS routes all browser traffic via attacker ─────── */
    if (head_len > 0) {
        int ph = pac_hijack_score(head, (size_t)head_len, ext);
        if (ph > 0) {
            fv_add(&v, ph,
                "F30: WPAD PROXY HIJACK — .pac returns a remote "
                "PROXY/SOCKS for all traffic (score %d)", ph);
        }
    }

    /* ── F31: XML XXE / entity bomb — external entities or nested
     *      entity declarations in parser-fed XML-family docs ──────── */
    if (head_len > 0) {
        int xx = xml_xxe_score(head, (size_t)head_len, ext);
        if (xx > 0) {
            fv_add(&v, xx,
                "F31: XML XXE/BOMB — external entity (file/URL leak on "
                "parse) or entity-expansion bomb (score %d)", xx);
        }
    }

    /* ── F32: MSBuild inline task — <UsingTask> code factory or
     *      <Exec> runs embedded code/commands at build ────────────── */
    if (head_len > 0) {
        int mb = msbuild_exec_score(head, (size_t)head_len, ext);
        if (mb > 0) {
            fv_add(&v, mb,
                "F32: MSBUILD EXEC — inline task factory or <Exec> "
                "runs code during build (score %d)", mb);
        }
    }

    /* ── F33: debugger rc — .gdbinit/.lldbinit shell/script lines
     *      execute when the repo is opened under a debugger ────────── */
    if (head_len > 0) {
        int db = dbgrc_score(head, (size_t)head_len, basename_start);
        if (db > 0) {
            fv_add(&v, db,
                "F33: DEBUGGER RC — .gdbinit/.lldbinit runs shell/"
                "script commands on debugger start (score %d)", db);
        }
    }

    /* ── F34: SQL exec — COPY … PROGRAM / \! / LANGUAGE C reach the
     *      host shell or a shared object via the DB ───────────────── */
    if (head_len > 0) {
        int sq = sql_exec_score(head, (size_t)head_len, ext);
        if (sq > 0) {
            fv_add(&v, sq,
                "F34: SQL EXEC — COPY PROGRAM / \\! / LANGUAGE C runs "
                "shell or a shared object via the database (score %d)",
                sq);
        }
    }

    /* ── F35: interpreter autoexec — sitecustomize.py/usercustomize.py
     *      run at every python startup; exec markers flag a dropped
     *      persistence payload ────────────────────────────────────── */
    if (head_len > 0) {
        int pa = py_autoexec_score(head, (size_t)head_len,
                                   basename_start);
        if (pa > 0) {
            fv_add(&v, pa,
                "F35: PY AUTOEXEC — sitecustomize/usercustomize module "
                "runs at every interpreter start (score %d)", pa);
        }
    }

    /* ── F36: .rdp rogue redirect — drive/clipboard/smartcard
     *      redirection to a remote desktop exfiltrates local files ─── */
    if (head_len > 0) {
        int rd = rdp_redirect_score(head, (size_t)head_len, ext);
        if (rd > 0) {
            fv_add(&v, rd,
                "F36: RDP REDIRECT — .rdp redirects drives/clipboard/"
                "devices to a remote server (rogue-RDP file theft, "
                "score %d)", rd);
        }
    }

    /* ── F37: .ovpn script hooks — up/down/management execute or
     *      remote-control the tunnel context (root script exec) ───── */
    if (head_len > 0) {
        int ov = ovpn_hook_score(head, (size_t)head_len, ext);
        if (ov > 0) {
            fv_add(&v, ov,
                "F37: OVPN HOOK — up/down/route-up script hooks or the "
                "management socket run/control code as root (score %d)",
                ov);
        }
    }

    /* ── F38: .mobileconfig rogue profile — root-CA/proxy/VPN payload
     *      types silently intercept or reroute device traffic ──────── */
    if (head_len > 0) {
        int mc = mobileconfig_score(head, (size_t)head_len, ext);
        if (mc > 0) {
            fv_add(&v, mc,
                "F38: MOBILECONFIG — profile installs a root CA / proxy /"
                " VPN payload (silent traffic interception, score %d)",
                mc);
        }
    }

    /* ── F41: .wsf/.wsh scriptlet — <job><script> with shell object
     *      calls executes via wscript ──────────────────────────────── */
    if (head_len > 0) {
        int ws = wsf_scriptlet_score(head, (size_t)head_len, ext);
        if (ws > 0) {
            fv_add(&v, ws,
                "F41: WSF SCRIPTLET — <job><script> script-host "
                "package runs via wscript (score %d)", ws);
        }
    }

    /* ── F42: .inf install sections — [DefaultInstall] with exec/
     *      copy/service keys runs via rundll32/cmstp ──────────────── */
    if (head_len > 0) {
        int ins = inf_install_score(head, (size_t)head_len, ext);
        if (ins > 0) {
            fv_add(&v, ins,
                "F42: INF INSTALL — [DefaultInstall] with exec/service "
                "keys runs via rundll32/cmstp (score %d)", ins);
        }
    }

    /* ── F43: ClickOnce manifest — <deployment codebase=> at a remote
     *      URL/UNC installs+runs code on open ─────────────────────── */
    if (head_len > 0) {
        int co = clickonce_score(head, (size_t)head_len, ext);
        if (co > 0) {
            fv_add(&v, co,
                "F43: CLICKONCE — deployment codebase is a remote "
                "URL/UNC (installs+runs remote code, score %d)", co);
        }
    }

    /* ── F44: spreadsheet formula injection — .slk SYLK EEXEC, .iqy
     *      WEB query, .csv/.tsv =cmd|/DDE cells run on open ───────── */
    if (head_len > 0) {
        int fi = formula_injection_score(head, (size_t)head_len, ext);
        if (fi > 0) {
            fv_add(&v, fi,
                "F44: FORMULA INJECTION — spreadsheet cell/query runs "
                "a command or remote fetch on open (score %d)", fi);
        }
    }

    /* ── F45: .jnlp — javaws fetches+launches jars from the codebase ── */
    if (head_len > 0) {
        int js = jnlp_score(head, (size_t)head_len, ext);
        if (js > 0) {
            fv_add(&v, js,
                "F45: JNLP — Java Web Start descriptor pulls jars from "
                "a remote codebase (score %d)", js);
        }
    }

    /* ── F46: .sct COM scriptlet — regsvr32 scrobj runs the embedded
     *      script with no file-type prompt ────────────────────────── */
    if (head_len > 0) {
        int ss = sct_scriptlet_score(head, (size_t)head_len, ext);
        if (ss > 0) {
            fv_add(&v, ss,
                "F46: SCT SCRIPTLET — COM scriptlet runs via regsvr32 "
                "scrobj.dll bypass (score %d)", ss);
        }
    }

    /* ── F48: .ica Citrix launch — [WFClient] Address/InitialProgram
     *      launches a remote published app on open ────────────────── */
    if (head_len > 0) {
        int ica = ica_launch_score(head, (size_t)head_len, ext);
        if (ica > 0) {
            fv_add(&v, ica,
                "F48: ICA LAUNCH — Citrix descriptor launches a remote "
                "application on open (score %d)", ica);
        }
    }

    /* ── F56: system-config carrier — sudoers/doas nopasswd grant,
     *      ld.so.preload persistence, hosts/resolv.conf DNS hijack,
     *      crontab persistence schedule ────────────────────────────── */
    if (head_len > 0) {
        int sc = sysconfig_carrier_score(head, (size_t)head_len,
                                         basename_start);
        if (sc > 0) {
            fv_add(&v, sc,
                "F56: SYSTEM CONFIG — filename is a host config that "
                "changes privilege/resolution when dropped in place "
                "(score %d)", sc);
        }
    }

    /* ── F58: mail carrier forensics — a .eml/.msg/.mbox file's header
     *      block goes through the same email-forensics engine as the
     *      `email` subcommand, so display-name spoofing / Reply-To
     *      redirect / auth failures in a dropped mail file score
     *      instead of passing as a harmless text file ─────────────── */
    if (head_len > 0) {
        char bn2[256];
        str_lower(basename_start, bn2, sizeof(bn2));
        if (strstr(bn2, ".eml") || strstr(bn2, ".emlx") ||
            strstr(bn2, ".msg") || strstr(bn2, ".mbox")) {
            char hbuf[4097];
            EmailVerdict ev;
            int i;
            memcpy(hbuf, head, (size_t)head_len);
            hbuf[head_len] = '\0';
            ev = hlse_check_email_headers(hbuf);
            if (ev.score > 0) {
                fv_add(&v, ev.score,
                    "F58: EMAIL FORENSICS — mail file headers score %d",
                    ev.score);
                for (i = 0; i < ev.n_reasons; i++)
                    fv_add(&v, 0, "    · %s", ev.reasons[i]);
            }
        }
    }

    /* ── F57: lockfile registry poisoning — resolved/source URL off the
     *      official registry (or cleartext http) swaps the package an
     *      install fetches ────────────────────────────────────────── */
    if (head_len > 0) {
        int sc = lockfile_url_score(head, (size_t)head_len,
                                    basename_start);
        if (sc > 0) {
            fv_add(&v, sc,
                "F57: LOCKFILE POISON — resolved/source URL points off "
                "the official registry or over cleartext http "
                "(score %d)", sc);
        }
    }

    /* ── F52–F55: dropped server-config files — .htaccess php handler
     *      /redirect, .user.ini auto_prepend_file, web.config
     *      httpRedirect, Office add-in manifest SourceLocation ──────── */
    if (head_len > 0) {
        int sc = serverconfig_score(head, (size_t)head_len,
                                    basename_start);
        if (sc > 0) {
            fv_add(&v, sc,
                "F52-55: SERVER CONFIG — dropped config changes what "
                "the server does with later content (score %d)", sc);
        }
    }

    /* ── F49: install-carrier extensions — extension bundles and
     *      cert/key files write code/trust on install ─────────────── */
    {
        int ic = install_carrier_score(ext);
        if (ic > 0) {
            fv_add(&v, ic,
                "F49: INSTALL CARRIER — %s extension type installs code "
                "or trust material on open (score %d)", ext, ic);
        }
    }

    /* ── F50: Homebrew formula exec — install{} runs on brew install ── */
    if (head_len > 0) {
        int bf = brew_formula_score(head, (size_t)head_len, ext);
        if (bf > 0) {
            fv_add(&v, bf,
                "F50: BREW FORMULA — formula install block executes "
                "commands at brew install time (score %d)", bf);
        }
    }

    /* ── F51: .cabal custom build — build-type:Custom delegates to a
     *      Setup.hs script at build time ──────────────────────────── */
    if (head_len > 0) {
        int cb = cabal_custom_score(head, (size_t)head_len, ext);
        if (cb > 0) {
            fv_add(&v, cb,
                "F51: CABAL CUSTOM BUILD — build-type:Custom runs a "
                "Setup.hs script at build time (score %d)", cb);
        }
    }

    /* ── F39: tar member slip — member name/prefix with '..' or an
     *      absolute path escapes the extract dir on permissive untars ─ */
    if (head_len > 0) {
        int ts = tar_slip_score(head, (size_t)head_len);
        if (ts > 0) {
            fv_add(&v, ts,
                "F39: TAR-SLIP — archive member name escapes the "
                "extraction directory (../ or absolute path, score %d)",
                ts);
        }
    }

    /* ── F40: build-tool exec+fetch — build.gradle/.kts/.sbt (or
     *      pom.xml/build.xml/setup.cfg) that exec a downloader runs
     *      remote code at build time ──────────────────────────────── */
    if (head_len > 0) {
        int bx = build_exec_score(head, (size_t)head_len,
                                  basename_start, ext);
        if (bx > 0) {
            fv_add(&v, bx,
                "F40: BUILD EXEC — build script execs a fetch/downloader "
                "(supply-chain exec at build time, score %d)", bx);
        }
    }

    /* ── F14: script download-cradle — LOLBin/interpreter stagers in
     *      script files (IEX+DownloadString, curl|bash, certutil,
     *      encoded -enc payloads, mshta/regsvr32/rundll32) ────────── */
    if (head_len > 0) {
        int sc = script_cradle_score(head, (size_t)head_len, ext);
        if (sc > 0) {
            fv_add(&v, sc,
                "F14: SCRIPT CRADLE — file content fetches and/or "
                "executes remote or encoded payloads (download-"
                "exec cradle, score %d)", sc);
        }
    }

    /* ── F15: .reg persistence — registry file writes a Run/IFEO/
     *      Winlogon key (autostart via double-clicked .reg) ───────── */
    if (head_len > 0) {
        int rp = reg_persistence_score(head, (size_t)head_len, ext);
        if (rp > 0) {
            fv_add(&v, rp,
                "F15: REG PERSISTENCE — .reg file installs an autostart/"
                "debugger key (Run, RunOnce, IFEO, Winlogon)");
        }
    }

    /* ── F16: PDF auto-actions — /OpenAction, /JS, /Launch, /AA fire
     *      on open (Foxit/Adobe phishing advisories) ─────────────── */
    if (head_len > 0) {
        int pa = pdf_action_score(head, (size_t)head_len);
        if (pa > 0) {
            fv_add(&v, pa,
                "F16: PDF AUTO-ACTION — document runs JavaScript or "
                "launches a program on open (/OpenAction//JS//Launch)");
        }
    }

    /* ── F17: RTF object embedding / remote template — \objdata OLE
     *      payload or \*\template fetching a remote DOT ───────────── */
    if (head_len > 0) {
        int rt = rtf_embed_score(head, (size_t)head_len);
        if (rt > 0) {
            fv_add(&v, rt,
                "F17: RTF OBJECT EMBED — \\objdata OLE object or remote "
                "template reference (CVE-2017-11882 / template-"
                "injection family)");
        }
    }

        /* ── F21: meta-refresh redirect — static HTML that bounces the
     *      viewer to a remote page on open ─────────────────────────── */
    if (head_len > 0) {
        int mr = meta_refresh_score(head, (size_t)head_len);
        if (mr > 0) {
            fv_add(&v, mr,
                "F21: META REFRESH — HTML redirects the viewer to a "
                "remote page on open (file-gated redirect phish)");
        }
    }

    /* ── F19: reverse-shell primitives — /dev/tcp, nc -e, socat exec,
     *      python socket+dup2 (content-driven, any file) ──────────── */
    if (head_len > 0) {
        int rs = revshell_score(head, (size_t)head_len);
        if (rs > 0) {
            fv_add(&v, rs,
                "F19: REVERSE SHELL — file content opens an interactive "
                "shell back to a remote host (/dev/tcp/nc -e/socat/"
                "pty.spawn family)");
        }
    }

    /* ── F20: HTML <base href> hijack — repoints every relative URL ── */
    if (head_len > 0) {
        int bh = base_hijack_score(head, (size_t)head_len);
        if (bh > 0) {
            fv_add(&v, bh,
                "F20: BASE HIJACK — <base href> repoints every relative "
                "link, form action and image to a remote host");
        }
    }

    /* ── F18: rc/persistence-file content — shell rc, git config,
     *      authorized_keys: env rootkits, hooksPath redirect,
     *      forced-command options ─────────────────────────────────── */
    if (head_len > 0) {
        int rc = rc_persist_score(head, (size_t)head_len,
                                  basename_start, filepath);
        if (rc > 0) {
            fv_add(&v, rc,
                "F18: PERSISTENCE FILE — shell/git/ssh config carries "
                "code-exec or redirect keys (LD_PRELOAD/hooksPath/"
                "forced-command family)");
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
