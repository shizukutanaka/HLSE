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

    /* OpenType font: OTTO (high entropy, found in web projects) */
    if (buf[0]==0x4F && buf[1]==0x54 && buf[2]==0x54 && buf[3]==0x4F) return 1;
    /* WOFF web font: wOFF */
    if (buf[0]==0x77 && buf[1]==0x4F && buf[2]==0x46 && buf[3]==0x46) return 1;
    /* WOFF2 web font: wOF2 */
    if (buf[0]==0x77 && buf[1]==0x4F && buf[2]==0x46 && buf[3]==0x32) return 1;
    /* Apache Arrow IPC stream/file format */
    if (n >= 6 &&
        buf[0]==0x41 && buf[1]==0x52 && buf[2]==0x52 && buf[3]==0x4F &&
        buf[4]==0x57 && buf[5]==0x31) return 1;
    /* DER-encoded X.509 certificate: SEQUENCE tag 0x30 + length 0x82 */
    if (buf[0]==0x30 && buf[1]==0x82) return 1;
    /* Snappy framing format: \xFF\x06\x00\x00 */
    if (buf[0]==0xFF && buf[1]==0x06 && buf[2]==0x00 && buf[3]==0x00) return 1;

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

/* Shared JSON string escaper (see hlse_util.h). Bounded, always terminates. */
void
hlse_json_escape(const char *s, char *out, size_t out_size) {
    size_t k = 0;
    if (out_size == 0) return;
    while (*s && k < out_size - 7) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  out[k++] = '\\'; out[k++] = '"';  break;
            case '\\': out[k++] = '\\'; out[k++] = '\\'; break;
            case '\n': out[k++] = '\\'; out[k++] = 'n';  break;
            case '\r': out[k++] = '\\'; out[k++] = 'r';  break;
            case '\t': out[k++] = '\\'; out[k++] = 't';  break;
            default:
                if (c < 0x20) {
                    static const char hexd[] = "0123456789abcdef";
                    out[k++] = '\\'; out[k++] = 'u'; out[k++] = '0'; out[k++] = '0';
                    out[k++] = hexd[(c >> 4) & 0xF];
                    out[k++] = hexd[c & 0xF];
                } else {
                    out[k++] = (char)c;
                }
        }
        s++;
    }
    out[k] = '\0';
}

/* Standard CRC-32 (IEEE 802.3 / zlib, reflected polynomial 0xEDB88320).
 * Table-free: the bitwise form is ~8x slower but costs no static table and
 * runs on inputs of 30 bytes here, where the difference is unmeasurable. */
unsigned long
hlse_crc32(const unsigned char *data, size_t len) {
    unsigned long crc = 0xFFFFFFFFUL;
    size_t i;
    int k;
    if (!data) return 0;
    for (i = 0; i < len; i++) {
        crc ^= (unsigned long)data[i];
        for (k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320UL & (unsigned long)(-(long)(crc & 1)));
    }
    return (crc ^ 0xFFFFFFFFUL) & 0xFFFFFFFFUL;
}

/* Encode a 32-bit value as base62, left-padded with '0' to exactly 6 chars
 * (6 base62 digits hold 62^6 > 2^32, so every CRC-32 fits). `out` must have
 * room for 7 bytes. This is the encoding GitHub uses for the checksum suffix
 * of its token formats. */
void
hlse_base62_6(unsigned long v, char *out) {
    static const char A[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    int i;
    if (!out) return;
    out[6] = '\0';
    for (i = 5; i >= 0; i--) {
        out[i] = A[v % 62u];
        v /= 62u;
    }
}

/* Pearson chi-square goodness-of-fit of a byte buffer against the uniform
 * distribution (256 bins, 255 degrees of freedom).
 *
 * Why this exists alongside Shannon entropy: entropy alone cannot separate
 * ENCRYPTED from COMPRESSED data — both sit near 8 bits/byte — which is the
 * dominant false-positive source in entropy-based ransomware detection.
 * Compression leaves residual structure in the byte histogram, so compressed
 * data lands far from uniform, while cipher output is uniform by design.
 *
 * Interpretation: for truly uniform data the statistic is distributed around
 * df = 255 with sd = sqrt(2*255) ~= 22.6, so values within roughly 185..325
 * are unremarkable. Published measurements put encrypted files near 253 and
 * compressed files in the high hundreds to low thousands.
 *
 * Returns -1.0 if the sample is too small for the statistic to mean anything
 * (each bin wants an expected count >= 5, i.e. n >= 1280). */
double
hlse_chi_square_uniform(const unsigned char *data, size_t len) {
    unsigned long counts[256];
    double expected, chi = 0.0;
    size_t i;
    int b;

    if (!data || len < 1280) return -1.0;
    for (b = 0; b < 256; b++) counts[b] = 0;
    for (i = 0; i < len; i++) counts[data[i]]++;

    expected = (double)len / 256.0;
    for (b = 0; b < 256; b++) {
        double d = (double)counts[b] - expected;
        chi += (d * d) / expected;
    }
    return chi;
}

/* Derive the AWS account ID that owns an access key ID, offline.
 *
 * AWS key IDs are a 4-character resource-type prefix (AKIA long-term user,
 * ASIA temporary/STS, and others) followed by 16 base32 characters. The
 * account number is not a lookup — it is encoded in the identifier itself:
 * take the first 6 bytes of the decoded body, mask 0x7FFFFFFFFF80 and shift
 * right 7. Publicly documented (Tal Be'ery; WithSecure's bitwise analysis of
 * AWS key identifiers) and implemented in several open-source extractors.
 *
 * This matters for a leaked credential: the single most useful fact for
 * whoever has to respond is WHICH account to rotate and audit, and getting it
 * needs no call to sts:GetAccessKeyInfo — which suits a scanner that must
 * never touch the network.
 *
 * Also serves as a structural check: a well-formed key ID is exactly 20
 * characters with a valid base32 body, so a random look-alike fails here.
 *
 * Writes a 12-digit zero-padded account ID into `out` (needs 13 bytes).
 * Returns 1 on success, 0 if `key` is not a structurally valid key ID. */
int
hlse_aws_account_from_key(const char *key, char *out, size_t out_size) {
    static const char A32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned long long v = 0, z, acct;
    int i;

    if (!key || !out || out_size < 13) return 0;
    for (i = 0; i < 20; i++) if (!key[i]) return 0;   /* need 20 chars */
    if (key[20] != '\0' &&
        ((key[20] >= 'A' && key[20] <= 'Z') ||
         (key[20] >= '0' && key[20] <= '9')))
        return 0;                                     /* longer than 20 => not a key ID */

    /* Body must be base32; accumulate the first 10 chars = 50 bits, then drop
     * the low 2 so the top 48 bits are exactly the first 6 bytes. */
    for (i = 4; i < 14; i++) {
        const char *p = strchr(A32, key[i]);
        if (!p || key[i] == '\0') return 0;
        v = (v << 5) | (unsigned long long)(p - A32);
    }
    /* Remaining body characters still have to be valid base32. */
    for (i = 14; i < 20; i++)
        if (!strchr(A32, key[i])) return 0;

    z = v >> 2;
    acct = (z & 0x7FFFFFFFFF80ULL) >> 7;
    /* Format into a buffer the compiler can size-check, then copy out bounded.
     * out_size is a runtime value, so formatting straight into it trips
     * -Wformat-truncation=2. The masked value spans at most 36 bits, so the
     * 12-digit field is always sufficient. */
    {
        char tmp[24];
        size_t n;
        snprintf(tmp, sizeof tmp, "%012llu", acct);
        n = strlen(tmp);
        if (n >= out_size) n = out_size - 1;
        memcpy(out, tmp, n);
        out[n] = '\0';
    }
    return 1;
}
