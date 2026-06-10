/*
 * hlse_util.c — Shared numeric/string utilities for HLSE
 *
 * See hlse_util.h for the rationale. These implementations were
 * previously duplicated; this is the single source of truth.
 */

#include "hlse_util.h"

#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* ── Shannon entropy ──────────────────────────────────────────────────── */

double
hlse_shannon_entropy(const unsigned char *data, size_t len) {
    unsigned long freq[256];
    size_t i;
    double entropy = 0.0;

    if (len == 0) return 0.0;

    memset(freq, 0, sizeof(freq));
    for (i = 0; i < len; i++) freq[data[i]]++;

    for (i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        {
            double p = (double)freq[i] / (double)len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

double
hlse_shannon_entropy_str(const char *s) {
    if (!s) return 0.0;
    return hlse_shannon_entropy((const unsigned char *)s, strlen(s));
}

/* ── Damerau-Levenshtein edit distance ────────────────────────────────── */

int
hlse_edit_distance(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    /* +1 for the zero row/column */
    int d[HLSE_DL_MAXLEN + 1][HLSE_DL_MAXLEN + 1];
    size_t i, j;

    if (la > HLSE_DL_MAXLEN || lb > HLSE_DL_MAXLEN) return HLSE_DL_MAX;

    for (i = 0; i <= la; i++) d[i][0] = (int)i;
    for (j = 0; j <= lb; j++) d[0][j] = (int)j;

    for (i = 1; i <= la; i++) {
        for (j = 1; j <= lb; j++) {
            int cost = (a[i-1] == b[j-1]) ? 0 : 1;
            int del = d[i-1][j] + 1;
            int ins = d[i][j-1] + 1;
            int sub = d[i-1][j-1] + cost;
            int best = del;

            if (ins < best) best = ins;
            if (sub < best) best = sub;

            /* Adjacent transposition (Damerau extension): a single swap
             * costs 1, independent of `cost` (canonical OSA form). The two
             * differ only when all four characters are equal, in which case
             * the substitution path already yields the optimum, so the
             * result is unchanged — this is purely for clarity/correctness. */
            if (i > 1 && j > 1 &&
                a[i-1] == b[j-2] && a[i-2] == b[j-1]) {
                int tra = d[i-2][j-2] + 1;
                if (tra < best) best = tra;
            }
            d[i][j] = best;
        }
    }
    return d[la][lb];
}

/* ── Known benign high-entropy file signatures ────────────────────────── */

int
hlse_is_high_entropy_benign_magic(const unsigned char *buf, size_t n) {
    if (n < 4) return 0;

    /* ZIP/JAR/DOCX/XLSX: PK\x03\x04 */
    if (buf[0]==0x50 && buf[1]==0x4B && buf[2]==0x03 && buf[3]==0x04) return 1;
    /* GZIP: 1F 8B */
    if (buf[0]==0x1F && buf[1]==0x8B) return 1;
    /* RAR: Rar! */
    if (buf[0]==0x52 && buf[1]==0x61 && buf[2]==0x72 && buf[3]==0x21) return 1;
    /* 7z: 37 7A BC AF */
    if (buf[0]==0x37 && buf[1]==0x7A && buf[2]==0xBC && buf[3]==0xAF) return 1;
    /* JPEG: FF D8 FF */
    if (buf[0]==0xFF && buf[1]==0xD8 && buf[2]==0xFF) return 1;
    /* PNG: 89 50 4E 47 */
    if (buf[0]==0x89 && buf[1]==0x50 && buf[2]==0x4E && buf[3]==0x47) return 1;
    /* MP4/MOV ftyp box (offset 4): ....ftyp */
    if (n >= 8 && buf[4]==0x66 && buf[5]==0x74 && buf[6]==0x79 && buf[7]==0x70)
        return 1;
    /* PDF: %PDF (compressed streams inside) */
    if (buf[0]==0x25 && buf[1]==0x50 && buf[2]==0x44 && buf[3]==0x46) return 1;
    /* XZ: FD 37 7A 58 */
    if (buf[0]==0xFD && buf[1]==0x37 && buf[2]==0x7A && buf[3]==0x58) return 1;
    /* BZIP2: BZh */
    if (buf[0]==0x42 && buf[1]==0x5A && buf[2]==0x68) return 1;
    /* Zstandard: 28 B5 2F FD */
    if (buf[0]==0x28 && buf[1]==0xB5 && buf[2]==0x2F && buf[3]==0xFD) return 1;
    /* LZ4 frame: 04 22 4D 18 */
    if (buf[0]==0x04 && buf[1]==0x22 && buf[2]==0x4D && buf[3]==0x18) return 1;
    /* WebP: RIFF....WEBP (bytes 0-3 = "RIFF", 8-11 = "WEBP") */
    if (n >= 12 &&
        buf[0]==0x52 && buf[1]==0x49 && buf[2]==0x46 && buf[3]==0x46 &&
        buf[8]==0x57 && buf[9]==0x45 && buf[10]==0x42 && buf[11]==0x50) return 1;
    /* FLAC lossless audio: fLaC */
    if (buf[0]==0x66 && buf[1]==0x4C && buf[2]==0x61 && buf[3]==0x43) return 1;
    /* GIF: GIF87a / GIF89a */
    if (buf[0]==0x47 && buf[1]==0x49 && buf[2]==0x46 && buf[3]==0x38) return 1;
    /* OGG container (Ogg Vorbis/Opus/FLAC streams): OggS */
    if (buf[0]==0x4F && buf[1]==0x67 && buf[2]==0x67 && buf[3]==0x53) return 1;
    /* SQLite database: SQLite format 3 */
    if (n >= 6 && buf[0]==0x53 && buf[1]==0x51 && buf[2]==0x4C &&
        buf[3]==0x69 && buf[4]==0x74 && buf[5]==0x65) return 1;
    /* MP3 with ID3 tag: "ID3" */
    if (buf[0]==0x49 && buf[1]==0x44 && buf[2]==0x33) return 1;
    /* TIFF little-endian: II + 0x2A 0x00 */
    if (buf[0]==0x49 && buf[1]==0x49 && buf[2]==0x2A && buf[3]==0x00) return 1;
    /* TIFF big-endian: MM + 0x00 0x2A */
    if (buf[0]==0x4D && buf[1]==0x4D && buf[2]==0x00 && buf[3]==0x2A) return 1;
    /* AVI: RIFF....AVI  (bytes 0-3 = "RIFF", 8-11 = "AVI ") */
    if (n >= 12 &&
        buf[0]==0x52 && buf[1]==0x49 && buf[2]==0x46 && buf[3]==0x46 &&
        buf[8]==0x41 && buf[9]==0x56 && buf[10]==0x49 && buf[11]==0x20) return 1;
    /* WAV: RIFF....WAVE */
    if (n >= 12 &&
        buf[0]==0x52 && buf[1]==0x49 && buf[2]==0x46 && buf[3]==0x46 &&
        buf[8]==0x57 && buf[9]==0x41 && buf[10]==0x56 && buf[11]==0x45) return 1;
    /* EBML/WebM/Matroska: 1A 45 DF A3 */
    if (buf[0]==0x1A && buf[1]==0x45 && buf[2]==0xDF && buf[3]==0xA3) return 1;
    /* HDF5: 89 48 44 46 0D 0A 1A 0A (common in ML/scientific workflows) */
    if (n >= 8 &&
        buf[0]==0x89 && buf[1]==0x48 && buf[2]==0x44 && buf[3]==0x46 &&
        buf[4]==0x0D && buf[5]==0x0A && buf[6]==0x1A && buf[7]==0x0A) return 1;
    /* Apache Parquet: PAR1 at start (big data columnar format) */
    if (buf[0]==0x50 && buf[1]==0x41 && buf[2]==0x52 && buf[3]==0x31) return 1;

    return 0;
}

/* ── Safe open of a fixed/trusted system file ─────────────────────────── */

FILE *
hlse_open_system_file(const char *path) {
    int fd;
    struct stat st;
    FILE *fp;

    if (!path) return NULL;

    /* O_NONBLOCK so a FIFO planted at the path returns immediately instead of
     * blocking; S_ISREG (via fstat on the opened fd) then rejects anything
     * that is not a regular file. We intentionally do NOT pass O_NOFOLLOW:
     * these are fixed, root-owned paths that may legitimately be symlinks
     * (e.g. /etc/resolv.conf on systemd). For a regular file O_NONBLOCK has
     * no effect on subsequent reads, so buffered stdio behaves normally.   */
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return NULL;

    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return NULL;
    }

    fp = fdopen(fd, "r");
    if (!fp) { close(fd); return NULL; }
    return fp;
}
