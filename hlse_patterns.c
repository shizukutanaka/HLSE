/* hlse_patterns.c — custom pattern config file (--patterns).
 * Extracted verbatim from hlse_core.c (split increment 5); see
 * hlse_patterns.h for the format spec. */
#include "hlse_patterns.h"
#include "hlse_secrets.h"   /* HlseCharset, hlse_register_custom_* */
#include <stdio.h>
#include <string.h>

static int
patterns_charset_from_name(const char *name, HlseCharset *out) {
    if (strcmp(name, "alnum")      == 0) { *out = HLSE_CHARSET_ALNUM;      return 1; }
    if (strcmp(name, "alnum_dash") == 0) { *out = HLSE_CHARSET_ALNUM_DASH; return 1; }
    if (strcmp(name, "hex")        == 0) { *out = HLSE_CHARSET_HEX;        return 1; }
    if (strcmp(name, "alpha")      == 0) { *out = HLSE_CHARSET_ALPHA;      return 1; }
    if (strcmp(name, "digit")      == 0) { *out = HLSE_CHARSET_DIGIT;      return 1; }
    return 0;
}

static int
patterns_load_secret_line(const char *path, int lineno, const char *rest) {
    char prefix[32], charset_name[16], label[256];
    int min_suffix = 0, score = 0, consumed = 0;
    HlseCharset cs;
    if (sscanf(rest, "%31s %d %15s %d %n", prefix, &min_suffix,
               charset_name, &score, &consumed) != 4) {
        fprintf(stderr, "hlse: warning: %s:%d: malformed SECRET line, "
                "skipped\n", path, lineno);
        return 0;
    }
    if (!patterns_charset_from_name(charset_name, &cs)) {
        fprintf(stderr, "hlse: warning: %s:%d: unknown charset '%s' "
                "(expected alnum|alnum_dash|hex|alpha|digit), skipped\n",
                path, lineno, charset_name);
        return 0;
    }
    {
        const char *lp = rest + consumed;
        size_t n;
        while (*lp == ' ' || *lp == '\t') lp++;
        snprintf(label, sizeof(label), "%s", lp);
        n = strlen(label);
        while (n > 0 && (label[n-1] == '\n' || label[n-1] == '\r'))
            label[--n] = '\0';
        if (n == 0) {
            fprintf(stderr, "hlse: warning: %s:%d: missing label, skipped\n",
                    path, lineno);
            return 0;
        }
    }
    if (!hlse_register_custom_secret_pattern(prefix, min_suffix, cs,
                                              label, score)) {
        fprintf(stderr, "hlse: warning: %s:%d: pattern rejected (bad field "
                "or registry full), skipped\n", path, lineno);
        return 0;
    }
    return 1;
}

/* Parse a BRAND line's remainder as "<name> <domains>", where <domains> is
 * the LAST whitespace-delimited token (comma-separated, no internal
 * spaces by construction) and <name> is everything before it. Splitting
 * from the end (not sscanf's %s, which stops at the first space) lets
 * <name> itself contain spaces — real organization names commonly do
 * ("Acme Corp", not "AcmeCorp"), matching how the built-in brand table
 * already handles multi-word entries like "office 365" / "human resources"
 * via contains_word()'s literal substring match. */
static int
patterns_load_brand_line(const char *path, int lineno, const char *rest) {
    char name[64], domains[512];
    char buf[600];
    size_t len;
    const char *end, *split, *name_end, *name_start;
    size_t domlen, namelen;

    snprintf(buf, sizeof(buf), "%s", rest);
    len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' ||
                       buf[len-1] == ' '  || buf[len-1] == '\t'))
        buf[--len] = '\0';
    end = buf + len;

    split = end;
    while (split > buf && split[-1] != ' ' && split[-1] != '\t') split--;
    if (split == buf || split == end) {
        fprintf(stderr, "hlse: warning: %s:%d: malformed BRAND line "
                "(expected: BRAND <name> <domain1>[,<domain2>...]), "
                "skipped\n", path, lineno);
        return 0;
    }
    domlen = (size_t)(end - split);
    if (domlen >= sizeof(domains)) domlen = sizeof(domains) - 1;
    memcpy(domains, split, domlen);
    domains[domlen] = '\0';

    name_end = split;
    while (name_end > buf && (name_end[-1] == ' ' || name_end[-1] == '\t'))
        name_end--;
    name_start = buf;
    while (name_start < name_end && (*name_start == ' ' || *name_start == '\t'))
        name_start++;
    namelen = (size_t)(name_end - name_start);
    if (namelen == 0 || namelen >= sizeof(name)) {
        fprintf(stderr, "hlse: warning: %s:%d: malformed BRAND line "
                "(expected: BRAND <name> <domain1>[,<domain2>...]), "
                "skipped\n", path, lineno);
        return 0;
    }
    memcpy(name, name_start, namelen);
    name[namelen] = '\0';

    if (!hlse_register_custom_brand(name, domains)) {
        fprintf(stderr, "hlse: warning: %s:%d: brand rejected (bad field "
                "or registry full), skipped\n", path, lineno);
        return 0;
    }
    return 1;
}

int
hlse_patterns_load(const char *path) {
    FILE *fp = fopen(path, "r");
    char line[512];
    int lineno = 0, loaded = 0;
    if (!fp) return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *s = line;
        char directive[16];
        int consumed = 0;
        lineno++;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0') continue;
        if (sscanf(s, "%15s %n", directive, &consumed) != 1) {
            fprintf(stderr, "hlse: warning: %s:%d: malformed line, skipped\n",
                    path, lineno);
            continue;
        }
        if (strcmp(directive, "SECRET") == 0) {
            loaded += patterns_load_secret_line(path, lineno, s + consumed);
        } else if (strcmp(directive, "BRAND") == 0) {
            loaded += patterns_load_brand_line(path, lineno, s + consumed);
        } else {
            fprintf(stderr, "hlse: warning: %s:%d: unknown directive '%s' "
                    "(expected SECRET or BRAND), skipped\n",
                    path, lineno, directive);
        }
    }
    fclose(fp);
    if (loaded == 0) {
        fprintf(stderr, "hlse: warning: %s: no valid SECRET/BRAND entries "
                "loaded\n", path);
    }
    return 0;
}
