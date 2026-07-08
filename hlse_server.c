/*
 * hlse_server.c — HLSE local HTTP/JSON API + web dashboard server.
 *
 * A small, dependency-free HTTP/1.1 server (POSIX sockets + libc + pthreads)
 * that exposes the HLSE detection engine over a JSON API and serves the
 * bundled web dashboard. Consistent with HLSE's zero-third-party-dependency,
 * minimal-attack-surface design.
 *
 * Build (see Makefile target `hlse-server`):
 *   cc -DHLSE_CORE_AS_LIB -o hlse-server hlse_server.c \
 *      hlse_core.c hlse_text.c hlse_protect.c hlse_secrets.c \
 *      hlse_supply.c hlse_file.c hlse_audit.c hlse_util.c -I. -lm -lpthread
 *
 * Run:
 *   ./hlse-server --host 127.0.0.1 --port 8080 --webroot ./web
 *   open http://127.0.0.1:8080
 *
 * Endpoints (all responses are application/json unless static):
 *   GET  /                     -> web/index.html
 *   GET  /app.js /style.css    -> bundled static assets (exact-route allowlist)
 *   GET  /api/v1/health        -> {"status":"ok","version":"..."}
 *   GET  /api/v1/version       -> {"version":"..."}
 *   POST /api/v1/scan/url      {"url":"..."}              -> verdict
 *   POST /api/v1/scan/text     {"text":"..."}             -> verdict
 *   POST /api/v1/scan/secrets  {"text":"..."}             -> secret findings
 *   POST /api/v1/scan/file     {"filename":"","content":""} -> masquerade + secrets
 *
 * Concurrency model:
 *   One detached pthread per accepted connection, capped at MAX_CONCURRENT
 *   simultaneous connections (excess connections get an immediate 503 from
 *   the accept loop, no thread spawned). This is safe because every request
 *   handler is reentrant: hlse_scan() / hlse_scan_secrets() /
 *   hlse_check_filename() only read `static const` tables (documented
 *   thread-safe in hlse_core.h), and the server never calls the engine's
 *   non-thread-safe mutators (hlse_register_custom_secret_pattern() /
 *   hlse_register_custom_brand()). All per-request state lives in a
 *   stack-allocated ConnCtx — there are no shared mutable globals in the
 *   request path, so there is nothing for two threads to race on.
 *
 * Security posture:
 *   - Binds to 127.0.0.1 by default (loopback only).
 *   - Request body capped (MAX_BODY); oversized -> 413.
 *   - Static files served ONLY via a fixed 3-route allowlist -- the request
 *     path is never concatenated into a filesystem path, so directory
 *     traversal is structurally impossible.
 *   - Security headers (CSP, X-Content-Type-Options, Referrer-Policy,
 *     X-Frame-Options) on every response.
 *   - Per-connection recv/send timeout; SIGPIPE ignored; graceful
 *     SIGINT/SIGTERM (new connections stop being accepted; in-flight
 *     threads finish naturally).
 *   - Bounded concurrency (MAX_CONCURRENT) guards against fork-bomb-style
 *     resource exhaustion from a burst of connections.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "hlse_core.h"
#include "hlse_secrets.h"
#include "hlse_file.h"

#define HLSE_SERVER_VERSION "1.1.0"

#define MAX_HEADER       8192    /* max request-line + headers */
#define MAX_BODY        65536    /* 64 KiB request body cap */
#define MAX_REQUEST     (MAX_HEADER + MAX_BODY)
#define RECV_TIMEOUT_S      10
#define BACKLOG            128
#define MAX_CONCURRENT      64   /* bounded thread-per-connection cap */

static volatile sig_atomic_t g_stop = 0;
static const char *g_webroot = "./web";

/* Active-connection counter, adjusted with GCC/Clang atomic builtins so the
 * accept loop and every connection thread can update it without a mutex. */
static volatile int g_active_conns = 0;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* Per-connection state. Everything a request handler needs to read or write
 * lives here — nothing is a shared global, so concurrent connection threads
 * never touch each other's data. */
typedef struct {
    int  fd;
    int  suppress_body;   /* set for HEAD: emit headers, no body */
    int  status;          /* status of the most recent response (access log) */
    char method[8];
    char path[1024];
} ConnCtx;

/* --------------------------- JSON helpers ---------------------------- */

/* Append `src` to `dst` (size cap `cap`, current length *len), JSON-escaping
 * control chars and quotes. Truncates safely if the buffer is exhausted. */
static void
json_escape_append(char *dst, size_t cap, size_t *len, const char *src) {
    size_t i;
    for (i = 0; src[i]; i++) {
        unsigned char c = (unsigned char)src[i];
        char buf[8];
        const char *rep = NULL;
        int n = 1;
        switch (c) {
            case '"':  rep = "\\\""; n = 2; break;
            case '\\': rep = "\\\\"; n = 2; break;
            case '\n': rep = "\\n";  n = 2; break;
            case '\r': rep = "\\r";  n = 2; break;
            case '\t': rep = "\\t";  n = 2; break;
            default:
                if (c < 0x20) {
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    rep = buf; n = 6;
                } else {
                    buf[0] = (char)c; buf[1] = '\0';
                    rep = buf; n = 1;
                }
        }
        if (*len + (size_t)n + 1 >= cap) return;  /* leave room for NUL */
        memcpy(dst + *len, rep, (size_t)n);
        *len += (size_t)n;
        dst[*len] = '\0';
    }
}

/* Extract a string field named `key` from a flat JSON object into `out`.
 * Minimal but robust: finds "key", skips ':' and whitespace, then reads a
 * double-quoted string, decoding \" \\ \/ \n \r \t \b \f and \uXXXX (BMP,
 * emitted as UTF-8). Returns 1 on success, 0 if the field is absent/invalid.
 * This is deliberately tiny -- the only untrusted parser in the server, so it
 * is also exercised by unit tests. Pure function of its arguments: no shared
 * state, safe to call from any number of threads concurrently. */
static int
json_get_string(const char *json, const char *key, char *out, size_t outsz) {
    char needle[64];
    const char *p;
    size_t w = 0;

    if (outsz == 0) return 0;
    out[0] = '\0';
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return 0;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return 0;
    p++;

    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p;
        if (c == '\\') {
            p++;
            switch (*p) {
                case '"':  if (w + 1 < outsz) out[w++] = '"';  break;
                case '\\': if (w + 1 < outsz) out[w++] = '\\'; break;
                case '/':  if (w + 1 < outsz) out[w++] = '/';  break;
                case 'n':  if (w + 1 < outsz) out[w++] = '\n'; break;
                case 'r':  if (w + 1 < outsz) out[w++] = '\r'; break;
                case 't':  if (w + 1 < outsz) out[w++] = '\t'; break;
                case 'b':  if (w + 1 < outsz) out[w++] = '\b'; break;
                case 'f':  if (w + 1 < outsz) out[w++] = '\f'; break;
                case 'u': {
                    /* \uXXXX -> UTF-8 (BMP only). */
                    unsigned int cp = 0;
                    int k, ok = 1;
                    for (k = 1; k <= 4; k++) {
                        char h = p[k];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                        else { ok = 0; break; }
                    }
                    if (!ok) { return 0; }
                    p += 4;
                    if (cp < 0x80) {
                        if (w + 1 < outsz) out[w++] = (char)cp;
                    } else if (cp < 0x800) {
                        if (w + 2 < outsz) {
                            out[w++] = (char)(0xC0 | (cp >> 6));
                            out[w++] = (char)(0x80 | (cp & 0x3F));
                        }
                    } else {
                        if (w + 3 < outsz) {
                            out[w++] = (char)(0xE0 | (cp >> 12));
                            out[w++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                            out[w++] = (char)(0x80 | (cp & 0x3F));
                        }
                    }
                    break;
                }
                default: return 0;  /* invalid escape */
            }
            if (*p) p++;
        } else {
            if (w + 1 < outsz) out[w++] = (char)c;
            p++;
        }
    }
    if (*p != '"') return 0;  /* unterminated string */
    out[w] = '\0';
    return 1;
}

/* --------------------------- HTTP writing ---------------------------- */

static const char *SECURITY_HEADERS =
    "X-Content-Type-Options: nosniff\r\n"
    "X-Frame-Options: DENY\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'\r\n";

static void
write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return;
        }
        off += (size_t)n;
    }
}

static void
send_response(ConnCtx *cx, int status, const char *status_text,
              const char *content_type, const char *body, size_t body_len) {
    char header[1024];
    int hn = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Server: hlse-server/%s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        status, status_text, HLSE_SERVER_VERSION, content_type, body_len,
        SECURITY_HEADERS);
    if (hn < 0) return;
    cx->status = status;
    write_all(cx->fd, header, (size_t)hn);
    if (body_len && !cx->suppress_body) write_all(cx->fd, body, body_len);
}

static void
send_json(ConnCtx *cx, int status, const char *status_text, const char *json) {
    send_response(cx, status, status_text, "application/json; charset=utf-8",
                  json, strlen(json));
}

static void
send_error(ConnCtx *cx, int status, const char *status_text, const char *message) {
    char body[512];
    size_t len = 0;
    body[0] = '\0';
    strncpy(body, "{\"error\":\"", sizeof(body) - 1);
    len = strlen(body);
    json_escape_append(body, sizeof(body), &len, message);
    if (len + 2 < sizeof(body)) { strcpy(body + len, "\"}"); }
    send_json(cx, status, status_text, body);
}

/* --------------------------- verdict -> JSON ------------------------- */

static void
respond_scan(ConnCtx *cx, const char *input) {
    ScanResult r = hlse_scan(input);
    char body[8192];
    size_t len = 0;
    int i;
    int severity = hlse_severity_for_score(r.score);
    const char *action;

    switch (severity) {
        case 4: action = "ISOLATE"; break;
        case 3: action = "BLOCK";   break;
        case 2: action = "ALERT";   break;
        case 1: action = "LOG";     break;
        default: action = "SAFE";   break;
    }

    body[0] = '\0';
    snprintf(body, sizeof(body),
        "{\"kind\":\"%s\",\"score\":%d,\"severity\":%d,\"action\":\"%s\",\"reasons\":[",
        r.is_url ? "url" : "text", r.score, severity, action);
    len = strlen(body);
    for (i = 0; i < r.n_reasons; i++) {
        if (i > 0 && len + 1 < sizeof(body)) { body[len++] = ','; body[len] = '\0'; }
        if (len + 1 < sizeof(body)) { body[len++] = '"'; body[len] = '\0'; }
        json_escape_append(body, sizeof(body), &len, r.reasons[i]);
        if (len + 1 < sizeof(body)) { body[len++] = '"'; body[len] = '\0'; }
    }
    if (len + 2 < sizeof(body)) { body[len++] = ']'; body[len++] = '}'; body[len] = '\0'; }
    send_json(cx, 200, "OK", body);
}

static void
respond_secrets(ConnCtx *cx, const char *input) {
    SecretVerdict v = hlse_scan_secrets(input);
    char body[16384];
    size_t len = 0;
    int i;

    body[0] = '\0';
    snprintf(body, sizeof(body),
        "{\"kind\":\"secrets\",\"score\":%d,\"findings\":[", v.score);
    len = strlen(body);
    for (i = 0; i < v.n_findings; i++) {
        if (i > 0 && len + 1 < sizeof(body)) { body[len++] = ','; body[len] = '\0'; }
        if (len + 10 < sizeof(body)) {
            len += (size_t)snprintf(body + len, sizeof(body) - len, "{\"type\":\"");
        }
        json_escape_append(body, sizeof(body), &len, v.findings[i].type);
        if (len + 16 < sizeof(body)) {
            len += (size_t)snprintf(body + len, sizeof(body) - len, "\",\"detail\":\"");
        }
        json_escape_append(body, sizeof(body), &len, v.findings[i].description);
        if (len + 3 < sizeof(body)) { body[len++] = '"'; body[len++] = '}'; body[len] = '\0'; }
    }
    if (len + 2 < sizeof(body)) { body[len++] = ']'; body[len++] = '}'; body[len] = '\0'; }
    send_json(cx, 200, "OK", body);
}

/* Scan an uploaded file: name-based masquerade (hlse_check_filename) plus a
 * leaked-secret content scan (hlse_scan_secrets). No temp file / base64 — the
 * client sends the claimed filename and the file text. */
static void
respond_file(ConnCtx *cx, const char *filename, const char *content) {
    FileVerdict fv = hlse_check_filename(filename);
    SecretVerdict sv = hlse_scan_secrets(content);
    int score = fv.score > sv.score ? fv.score : sv.score;
    int severity = hlse_severity_for_score(score);
    const char *action;
    char body[16384];
    size_t len = 0;
    int i;
    char fn_esc[512];
    size_t fnlen = 0;
    fn_esc[0] = '\0';
    json_escape_append(fn_esc, sizeof(fn_esc), &fnlen, filename);

    switch (severity) {
        case 4: action = "ISOLATE"; break;
        case 3: action = "BLOCK";   break;
        case 2: action = "ALERT";   break;
        case 1: action = "LOG";     break;
        default: action = "SAFE";   break;
    }
    len = (size_t)snprintf(body, sizeof(body),
        "{\"kind\":\"file\",\"filename\":\"%s\",\"score\":%d,\"severity\":%d,"
        "\"action\":\"%s\",\"reasons\":[", fn_esc, score, severity, action);
    for (i = 0; i < fv.n_reasons; i++) {
        if (i > 0 && len + 1 < sizeof(body)) { body[len++] = ','; body[len] = '\0'; }
        if (len + 1 < sizeof(body)) { body[len++] = '"'; body[len] = '\0'; }
        json_escape_append(body, sizeof(body), &len, fv.reasons[i]);
        if (len + 1 < sizeof(body)) { body[len++] = '"'; body[len] = '\0'; }
    }
    if (len + 14 < sizeof(body))
        len += (size_t)snprintf(body + len, sizeof(body) - len, "],\"secrets\":[");
    for (i = 0; i < sv.n_findings; i++) {
        if (i > 0 && len + 1 < sizeof(body)) { body[len++] = ','; body[len] = '\0'; }
        if (len + 10 < sizeof(body))
            len += (size_t)snprintf(body + len, sizeof(body) - len, "{\"type\":\"");
        json_escape_append(body, sizeof(body), &len, sv.findings[i].type);
        if (len + 12 < sizeof(body))
            len += (size_t)snprintf(body + len, sizeof(body) - len, "\",\"detail\":\"");
        json_escape_append(body, sizeof(body), &len, sv.findings[i].description);
        if (len + 3 < sizeof(body)) { body[len++] = '"'; body[len++] = '}'; body[len] = '\0'; }
    }
    if (len + 2 < sizeof(body)) { body[len++] = ']'; body[len++] = '}'; body[len] = '\0'; }
    send_json(cx, 200, "OK", body);
}

/* --------------------------- static assets --------------------------- */

/* Serve one of exactly three files from the webroot. The mapping is a fixed
 * allowlist: the request path is compared, never used to build a filesystem
 * path, so traversal is impossible. */
static int
serve_static(ConnCtx *cx, const char *path) {
    const char *fname = NULL;
    const char *ctype = NULL;
    char fullpath[1024];
    int ffd;
    struct stat st;
    char *contents;
    ssize_t rd;

    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        fname = "index.html"; ctype = "text/html; charset=utf-8";
    } else if (strcmp(path, "/app.js") == 0) {
        fname = "app.js"; ctype = "application/javascript; charset=utf-8";
    } else if (strcmp(path, "/style.css") == 0) {
        fname = "style.css"; ctype = "text/css; charset=utf-8";
    } else {
        return 0;  /* not a static route */
    }

    snprintf(fullpath, sizeof(fullpath), "%s/%s", g_webroot, fname);
    ffd = open(fullpath, O_RDONLY);
    if (ffd < 0) {
        send_error(cx, 404, "Not Found", "asset not found (is --webroot correct?)");
        return 1;
    }
    if (fstat(ffd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > 4 * 1024 * 1024) {
        close(ffd);
        send_error(cx, 404, "Not Found", "asset unavailable");
        return 1;
    }
    contents = malloc((size_t)st.st_size);
    if (!contents) { close(ffd); send_error(cx, 500, "Internal Server Error", "oom"); return 1; }
    rd = read(ffd, contents, (size_t)st.st_size);
    close(ffd);
    if (rd != st.st_size) { free(contents); send_error(cx, 500, "Internal Server Error", "read"); return 1; }
    send_response(cx, 200, "OK", ctype, contents, (size_t)st.st_size);
    free(contents);
    return 1;
}

/* --------------------------- request handling ------------------------ */

/* Read the full request (headers + optional body) into buf. Returns total
 * bytes, or negative on error/oversize. Parses Content-Length for body size. */
static int
read_request(int fd, char *buf, size_t cap) {
    size_t total = 0;
    size_t header_end = 0;
    long content_length = -1;
    int have_headers = 0;

    while (total < cap - 1) {
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) break;  /* client closed */
        total += (size_t)n;
        buf[total] = '\0';

        if (!have_headers) {
            char *sep = strstr(buf, "\r\n\r\n");
            if (sep) {
                const char *cl;
                have_headers = 1;
                header_end = (size_t)(sep - buf) + 4;
                cl = strcasestr(buf, "content-length:");
                if (cl) {
                    content_length = strtol(cl + 15, NULL, 10);
                    if (content_length < 0) return -1;
                    if (content_length > MAX_BODY) return -2;  /* too large */
                } else {
                    content_length = 0;
                }
            }
        }
        if (have_headers) {
            size_t body_have = total - header_end;
            if (content_length >= 0 && body_have >= (size_t)content_length) break;
        }
    }
    return (int)total;
}

static void
handle_connection(ConnCtx *cx) {
    char *buf = malloc(MAX_REQUEST + 1);
    char method[8];
    char path[1024];
    const char *body;
    int total;

    if (!buf) { return; }

    total = read_request(cx->fd, buf, MAX_REQUEST + 1);
    if (total == -2) { send_error(cx, 413, "Payload Too Large", "request body exceeds limit"); free(buf); return; }
    if (total <= 0) { free(buf); return; }

    if (sscanf(buf, "%7s %1023s", method, path) != 2) {
        send_error(cx, 400, "Bad Request", "malformed request line");
        free(buf); return;
    }

    /* Strip query string from path for routing. */
    { char *q = strchr(path, '?'); if (q) *q = '\0'; }

    /* Capture for the access log (emitted by the caller after this returns). */
    snprintf(cx->method, sizeof(cx->method), "%s", method);
    snprintf(cx->path, sizeof(cx->path), "%s", path);

    body = strstr(buf, "\r\n\r\n");
    body = body ? body + 4 : "";

    /* -- GET / HEAD routes (HEAD emits headers only) -- */
    cx->suppress_body = (strcmp(method, "HEAD") == 0);
    if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) {
        if (strcmp(path, "/api/v1/health") == 0) {
            char b[256];
            snprintf(b, sizeof(b), "{\"status\":\"ok\",\"engine\":\"%s\",\"server\":\"%s\"}",
                     hlse_version(), HLSE_SERVER_VERSION);
            send_json(cx, 200, "OK", b);
        } else if (strcmp(path, "/api/v1/version") == 0) {
            char b[128];
            snprintf(b, sizeof(b), "{\"version\":\"%s\"}", hlse_version());
            send_json(cx, 200, "OK", b);
        } else if (serve_static(cx, path)) {
            /* handled */
        } else {
            send_error(cx, 404, "Not Found", "no such resource");
        }
        free(buf); return;
    }

    /* -- POST routes -- */
    if (strcmp(method, "POST") == 0) {
        char value[MAX_BODY];
        if (strcmp(path, "/api/v1/scan/url") == 0) {
            if (!json_get_string(body, "url", value, sizeof(value))) {
                send_error(cx, 400, "Bad Request", "missing or invalid 'url' field");
            } else {
                respond_scan(cx, value);
            }
        } else if (strcmp(path, "/api/v1/scan/text") == 0) {
            if (!json_get_string(body, "text", value, sizeof(value))) {
                send_error(cx, 400, "Bad Request", "missing or invalid 'text' field");
            } else {
                respond_scan(cx, value);
            }
        } else if (strcmp(path, "/api/v1/scan/secrets") == 0) {
            if (!json_get_string(body, "text", value, sizeof(value))) {
                send_error(cx, 400, "Bad Request", "missing or invalid 'text' field");
            } else {
                respond_secrets(cx, value);
            }
        } else if (strcmp(path, "/api/v1/scan/file") == 0) {
            char fname[512];
            if (!json_get_string(body, "filename", fname, sizeof(fname))) {
                send_error(cx, 400, "Bad Request", "missing 'filename' field");
            } else if (!json_get_string(body, "content", value, sizeof(value))) {
                send_error(cx, 400, "Bad Request", "missing 'content' field");
            } else {
                respond_file(cx, fname, value);
            }
        } else {
            send_error(cx, 404, "Not Found", "no such endpoint");
        }
        free(buf); return;
    }

    send_error(cx, 405, "Method Not Allowed", "only GET, HEAD and POST are supported");
    free(buf);
}

/* Log one completed request. A single fprintf call produces the whole line,
 * and glibc serializes writes to the same FILE* internally, so concurrent
 * threads logging at once still yield whole, non-interleaved lines. */
static void
log_request(const ConnCtx *cx) {
    time_t now;
    char ts[32];
    struct tm tmv;

    if (!cx->method[0]) return;
    now = time(NULL);
    gmtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    printf("%s  %-4s %s -> %d\n", ts, cx->method, cx->path, cx->status);
    fflush(stdout);
}

/* Thread entry point: one per accepted connection. Decrements the shared
 * active-connection counter on every exit path (including early return). */
static void *
connection_thread(void *arg) {
    ConnCtx cx;
    struct timeval tv;

    memset(&cx, 0, sizeof(cx));
    cx.fd = (int)(intptr_t)arg;

    tv.tv_sec = RECV_TIMEOUT_S;
    tv.tv_usec = 0;
    setsockopt(cx.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cx.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    handle_connection(&cx);
    close(cx.fd);
    log_request(&cx);

    __atomic_fetch_sub(&g_active_conns, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

/* --------------------------- main / socket --------------------------- */

static void
usage(const char *prog) {
    printf("HLSE API + dashboard server %s (engine %s)\n\n", HLSE_SERVER_VERSION, hlse_version());
    printf("Usage: %s [--host ADDR] [--port N] [--webroot DIR]\n\n", prog);
    printf("Options:\n");
    printf("  --host ADDR     bind address (default 127.0.0.1; loopback-only)\n");
    printf("  --port N        listen port  (default 8080)\n");
    printf("  --webroot DIR   directory with index.html/app.js/style.css (default ./web)\n");
    printf("  --help          this help\n\n");
    printf("Endpoints: GET /  /api/v1/health  /api/v1/version\n");
    printf("           POST /api/v1/scan/{url,text,secrets,file}  (JSON body)\n");
    printf("Concurrency: up to %d simultaneous connections (thread per connection);\n",
           MAX_CONCURRENT);
    printf("             bursts beyond that get an immediate 503.\n");
}

#ifndef HLSE_SERVER_NO_MAIN
int
main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    int port = 8080;
    int listen_fd;
    struct sockaddr_in addr;
    int opt = 1;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--webroot") == 0 && i + 1 < argc) g_webroot = argv[++i];
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown argument: %s\n", argv[i]); usage(argv[0]); return 2; }
    }
    if (port <= 0 || port > 65535) { fprintf(stderr, "invalid port\n"); return 2; }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid host address: %s\n", host);
        close(listen_fd); return 2;
    }

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(listen_fd); return 1;
    }
    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen"); close(listen_fd); return 1;
    }

    printf("HLSE server %s (engine %s) listening on http://%s:%d  (webroot: %s)\n",
           HLSE_SERVER_VERSION, hlse_version(), host, port, g_webroot);
    printf("Concurrency: up to %d simultaneous connections. Press Ctrl-C to stop.\n",
           MAX_CONCURRENT);
    fflush(stdout);

    while (!g_stop) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            continue;
        }

        if (__atomic_fetch_add(&g_active_conns, 1, __ATOMIC_SEQ_CST) >= MAX_CONCURRENT) {
            /* Over capacity: reject synchronously, no thread spawned. */
            static const char *body = "{\"error\":\"server busy, try again shortly\"}";
            char header[256];
            int hn = snprintf(header, sizeof(header),
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                "Content-Length: %zu\r\n"
                "Retry-After: 1\r\n"
                "Connection: close\r\n\r\n",
                strlen(body));
            if (hn > 0) write_all(cfd, header, (size_t)hn);
            write_all(cfd, body, strlen(body));
            close(cfd);
            __atomic_fetch_sub(&g_active_conns, 1, __ATOMIC_SEQ_CST);
            continue;
        }

        {
            pthread_t tid;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            if (pthread_create(&tid, &attr, connection_thread,
                                (void *)(intptr_t)cfd) != 0) {
                /* Thread creation failed (e.g. resource limits) — handle
                 * inline so the connection isn't silently dropped. */
                ConnCtx cx;
                memset(&cx, 0, sizeof(cx));
                cx.fd = cfd;
                handle_connection(&cx);
                close(cfd);
                log_request(&cx);
                __atomic_fetch_sub(&g_active_conns, 1, __ATOMIC_SEQ_CST);
            }
            pthread_attr_destroy(&attr);
        }
    }

    printf("\nShutting down (waiting is not performed for in-flight requests).\n");
    close(listen_fd);
    return 0;
}
#endif /* HLSE_SERVER_NO_MAIN */
