/*
 * hlse_server.c — HLSE local HTTP/JSON API + web dashboard server.
 *
 * A small, dependency-free HTTP/1.1 server (POSIX sockets + libc only)
 * that exposes the HLSE detection engine over a JSON API and serves the
 * bundled web dashboard. Consistent with HLSE's zero-third-party-dependency,
 * minimal-attack-surface design.
 *
 * Build (see Makefile target `hlse-server`):
 *   cc -DHLSE_CORE_AS_LIB -o hlse-server hlse_server.c \
 *      hlse_core.c hlse_text.c hlse_protect.c hlse_secrets.c \
 *      hlse_supply.c hlse_file.c hlse_audit.c hlse_util.c -I. -lm
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
 *   POST /api/v1/scan/url      {"url":"..."}   -> verdict
 *   POST /api/v1/scan/text     {"text":"..."}  -> verdict
 *   POST /api/v1/scan/secrets  {"text":"..."}  -> secret findings
 *
 * Security posture:
 *   - Binds to 127.0.0.1 by default (loopback only).
 *   - Request body capped (MAX_BODY); oversized -> 413.
 *   - Static files served ONLY via a fixed 3-route allowlist -- the request
 *     path is never concatenated into a filesystem path, so directory
 *     traversal is structurally impossible.
 *   - Security headers (CSP, X-Content-Type-Options, Referrer-Policy,
 *     X-Frame-Options) on every response.
 *   - Per-connection recv timeout; SIGPIPE ignored; graceful SIGINT/SIGTERM.
 *   - Single-threaded accept loop: simple and robust for a local dashboard.
 *     (Not a public multi-tenant server; document accordingly.)
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "hlse_core.h"
#include "hlse_secrets.h"

#define HLSE_SERVER_VERSION "1.0.0"

#define MAX_HEADER     8192      /* max request-line + headers */
#define MAX_BODY      65536      /* 64 KiB request body cap */
#define MAX_REQUEST   (MAX_HEADER + MAX_BODY)
#define RECV_TIMEOUT_S    10
#define BACKLOG           64

static volatile sig_atomic_t g_stop = 0;
static const char *g_webroot = "./web";
static int g_suppress_body = 0;  /* set for HEAD: emit headers, no body */

static void on_signal(int sig) { (void)sig; g_stop = 1; }

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
 * is also exercised by the fuzz target. */
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
send_response(int fd, int status, const char *status_text,
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
    write_all(fd, header, (size_t)hn);
    if (body_len && !g_suppress_body) write_all(fd, body, body_len);
}

static void
send_json(int fd, int status, const char *status_text, const char *json) {
    send_response(fd, status, status_text, "application/json; charset=utf-8",
                  json, strlen(json));
}

static void
send_error(int fd, int status, const char *status_text, const char *message) {
    char body[512];
    size_t len = 0;
    body[0] = '\0';
    strncpy(body, "{\"error\":\"", sizeof(body) - 1);
    len = strlen(body);
    json_escape_append(body, sizeof(body), &len, message);
    if (len + 2 < sizeof(body)) { strcpy(body + len, "\"}"); }
    send_json(fd, status, status_text, body);
}

/* --------------------------- verdict -> JSON ------------------------- */

static void
respond_scan(int fd, const char *input) {
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
    send_json(fd, 200, "OK", body);
}

static void
respond_secrets(int fd, const char *input) {
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
    send_json(fd, 200, "OK", body);
}

/* --------------------------- static assets --------------------------- */

/* Serve one of exactly three files from the webroot. The mapping is a fixed
 * allowlist: the request path is compared, never used to build a filesystem
 * path, so traversal is impossible. */
static int
serve_static(int fd, const char *path) {
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
        send_error(fd, 404, "Not Found", "asset not found (is --webroot correct?)");
        return 1;
    }
    if (fstat(ffd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > 4 * 1024 * 1024) {
        close(ffd);
        send_error(fd, 404, "Not Found", "asset unavailable");
        return 1;
    }
    contents = malloc((size_t)st.st_size);
    if (!contents) { close(ffd); send_error(fd, 500, "Internal Server Error", "oom"); return 1; }
    rd = read(ffd, contents, (size_t)st.st_size);
    close(ffd);
    if (rd != st.st_size) { free(contents); send_error(fd, 500, "Internal Server Error", "read"); return 1; }
    send_response(fd, 200, "OK", ctype, contents, (size_t)st.st_size);
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
handle_connection(int fd) {
    char *buf = malloc(MAX_REQUEST + 1);
    char method[8];
    char path[1024];
    const char *body;
    int total;

    if (!buf) { return; }

    total = read_request(fd, buf, MAX_REQUEST + 1);
    if (total == -2) { send_error(fd, 413, "Payload Too Large", "request body exceeds limit"); free(buf); return; }
    if (total <= 0) { free(buf); return; }

    if (sscanf(buf, "%7s %1023s", method, path) != 2) {
        send_error(fd, 400, "Bad Request", "malformed request line");
        free(buf); return;
    }

    /* Strip query string from path for routing. */
    { char *q = strchr(path, '?'); if (q) *q = '\0'; }

    body = strstr(buf, "\r\n\r\n");
    body = body ? body + 4 : "";

    /* -- GET / HEAD routes (HEAD emits headers only) -- */
    g_suppress_body = (strcmp(method, "HEAD") == 0);
    if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) {
        if (strcmp(path, "/api/v1/health") == 0) {
            char b[256];
            snprintf(b, sizeof(b), "{\"status\":\"ok\",\"engine\":\"%s\",\"server\":\"%s\"}",
                     hlse_version(), HLSE_SERVER_VERSION);
            send_json(fd, 200, "OK", b);
        } else if (strcmp(path, "/api/v1/version") == 0) {
            char b[128];
            snprintf(b, sizeof(b), "{\"version\":\"%s\"}", hlse_version());
            send_json(fd, 200, "OK", b);
        } else if (serve_static(fd, path)) {
            /* handled */
        } else {
            send_error(fd, 404, "Not Found", "no such resource");
        }
        free(buf); return;
    }

    /* -- POST routes -- */
    if (strcmp(method, "POST") == 0) {
        char value[MAX_BODY];
        if (strcmp(path, "/api/v1/scan/url") == 0) {
            if (!json_get_string(body, "url", value, sizeof(value))) {
                send_error(fd, 400, "Bad Request", "missing or invalid 'url' field");
            } else {
                respond_scan(fd, value);
            }
        } else if (strcmp(path, "/api/v1/scan/text") == 0) {
            if (!json_get_string(body, "text", value, sizeof(value))) {
                send_error(fd, 400, "Bad Request", "missing or invalid 'text' field");
            } else {
                respond_scan(fd, value);
            }
        } else if (strcmp(path, "/api/v1/scan/secrets") == 0) {
            if (!json_get_string(body, "text", value, sizeof(value))) {
                send_error(fd, 400, "Bad Request", "missing or invalid 'text' field");
            } else {
                respond_secrets(fd, value);
            }
        } else {
            send_error(fd, 404, "Not Found", "no such endpoint");
        }
        free(buf); return;
    }

    send_error(fd, 405, "Method Not Allowed", "only GET, HEAD and POST are supported");
    free(buf);
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
    printf("           POST /api/v1/scan/{url,text,secrets}  (JSON body)\n");
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
    struct timeval tv;

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
    printf("Press Ctrl-C to stop.\n");
    fflush(stdout);

    tv.tv_sec = RECV_TIMEOUT_S;
    tv.tv_usec = 0;

    while (!g_stop) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            continue;
        }
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        handle_connection(cfd);
        close(cfd);
    }

    printf("\nShutting down.\n");
    close(listen_fd);
    return 0;
}
#endif /* HLSE_SERVER_NO_MAIN */
