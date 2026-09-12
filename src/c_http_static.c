/* Static file serving for c-http.
 *
 * Security model (in this order):
 *   1. URL decoding (%XX) — BEFORE any path check, otherwise "%2e%2e"
 *      slips through as "..".
 *   2. Reject ".." and control characters/NUL after decoding.
 *   3. Serve regular files only (no FIFOs, devices, ...).
 *   4. realpath() chain check: the resolved file must stay below the
 *      resolved root directory — catches symlinks pointing out of the
 *      root directory.
 * Large files are streamed (HttpResponse.file_path), not copied into
 * the 4-KiB body buffer. */

/* realpath() is XSI (not base POSIX) — _XOPEN_SOURCE 700 enables it in
 * glibc, even when the target also defines _POSIX_C_SOURCE. Kept in
 * the source (not CMake) so the amalgamation keeps it too. */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* NOLINT(bugprone-reserved-identifier) */
#endif

#include "c_http_static.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

#include "c_http.h"
#include "c_http_assert.h"

#ifndef PATH_MAX
#define PATH_MAX 4096 /* fallback for platforms without a definition */
#endif

/* ============================================================
 * Mount list (opaque via HttpServer.static_mounts)
 * ============================================================ */

typedef struct HttpStaticMount {
    HttpStaticConfig cfg; /* all strings copied (heap), owned */
    struct HttpStaticMount *next;
} HttpStaticMount;

/* ============================================================
 * Helpers
 * ============================================================ */

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* Decodes %XX from in into out. Returns 0 = OK, -1 = error.
 * Rejection rules: '+' stays '+' (paths are not form encoding,
 * RFC 3986), %00 is rejected (NUL injection) and so are broken
 * escapes (%zz, a trailing %0). */
static int url_decode(const char *in, char *out, size_t out_size)
{
    if (in == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    size_t o = 0;
    for (size_t i = 0; in[i] != '\0'; i++) {
        if (o + 1 >= out_size) {
            return -1; /* truncation, not overflow */
        }
        if (in[i] == '%') {
            int hi = hex_val(in[i + 1]);
            int lo = hex_val(in[i + 2]);
            if (hi < 0 || lo < 0) {
                return -1;
            }
            if (hi == 0 && lo == 0) {
                return -1; /* %00 */
            }
            out[o++] = (char)((hi * 16) + lo);
            i += 2;
        } else {
            out[o++] = in[i];
        }
    }
    out[o] = '\0';
    return 0;
}

/* Control characters in a decoded path segment — these can arrive via
 * %01 and friends, before the request line would have caught them. */
static bool has_control_chars(const char *s)
{
    for (size_t i = 0; s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f) {
            return true;
        }
    }
    return false;
}

/* URL prefix test with a word boundary: "/public" matches "/public"
 * and "/public/x", but NOT "/public-x". "/" matches everything. */
static bool extract_suffix(const char *prefix, const char *path,
                           const char **suffix_out)
{
    if (prefix == NULL || path == NULL || suffix_out == NULL) {
        return false;
    }

    size_t plen = strlen(prefix);
    if (plen == 1 && prefix[0] == '/') {
        *suffix_out = path + 1; /* root mount */
        return true;
    }

    if (strncmp(path, prefix, plen) != 0) {
        return false;
    }
    if (path[plen] == '\0') {
        *suffix_out = ""; /* exactly the mount path */
        return true;
    }
    if (path[plen] == '/') {
        *suffix_out = path + plen + 1;
        return true;
    }
    return false; /* "/public-x" does not belong to "/public" */
}

static const char *mime_for(const char *path)
{
    static const struct {
        const char *ext;
        const char *type;
    } table[] = {
        {"html", "text/html"},      {"htm", "text/html"},
        {"css", "text/css"},        {"js", "text/javascript"},
        {"mjs", "text/javascript"}, {"json", "application/json"},
        {"txt", "text/plain"},      {"md", "text/plain"},
        {"csv", "text/csv"},        {"xml", "application/xml"},
        {"png", "image/png"},       {"jpg", "image/jpeg"},
        {"jpeg", "image/jpeg"},     {"gif", "image/gif"},
        {"svg", "image/svg+xml"},   {"webp", "image/webp"},
        {"ico", "image/x-icon"},    {"avif", "image/avif"},
        {"pdf", "application/pdf"}, {"zip", "application/zip"},
        {"gz", "application/gzip"}, {"wasm", "application/wasm"},
        {"woff", "font/woff"},      {"woff2", "font/woff2"},
        {"mp3", "audio/mpeg"},      {"mp4", "video/mp4"},
        {"webm", "video/webm"},     {"bin", "application/octet-stream"},
    };

    const char *dot = strrchr(path, '.');
    if (dot == NULL) {
        return "application/octet-stream";
    }

    const char *ext = dot + 1;
    if (*ext == '\0' || strchr(ext, '/') != NULL) {
        return "application/octet-stream";
    }

    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcasecmp(ext, table[i].ext) == 0) {
            return table[i].type;
        }
    }
    return "application/octet-stream";
}

/* Compact RFC-1123-compliant date (deliberately not via strftime,
 * %a/%b are locale-dependent). Matches format_http_date() in the core,
 * but for an arbitrary point in time (Last-Modified). */
static void format_http_time(time_t t, char *buf, size_t size)
{
    static const char *const days[7] = {"Sun", "Mon", "Tue", "Wed",
                                        "Thu", "Fri", "Sat"};
    static const char *const months[12] = {"Jan", "Feb", "Mar", "Apr",
                                           "May", "Jun", "Jul", "Aug",
                                           "Sep", "Oct", "Nov", "Dec"};

    if (t < 0) {
        t = 0; /* no Last-Modified before 1970 */
    }
    struct tm gt;
    gmtime_r(&t, &gt);

    int wday = gt.tm_wday >= 0 && gt.tm_wday <= 6 ? gt.tm_wday : 0;
    int mon = gt.tm_mon >= 0 && gt.tm_mon <= 11 ? gt.tm_mon : 0;

    snprintf(buf, size, "%s, %02d %s %04d %02d:%02d:%02d GMT", days[wday],
             gt.tm_mday, months[mon], 1900 + gt.tm_year, gt.tm_hour, gt.tm_min,
             gt.tm_sec);
}

/* If-None-Match against our ETag (weak comparison: the W/ prefix is
 * ignored, RFC 9110 §8.8.3.2). "*" matches any representation. */
static bool etag_matches(const HttpRequest *req, const char *etag)
{
    for (size_t i = 0; i < req->headers.count; i++) {
        if (strcasecmp(req->headers.items[i].key, HTTP_HEADER_IF_NONE_MATCH) !=
            0) {
            continue;
        }

        /* A list like "W/\"x\", \"y\"" — compare comma-separated entries. */
        const char *p = req->headers.items[i].value;
        while (*p != '\0') {
            while (*p == ' ' || *p == '\t' || *p == ',') {
                p++;
            }
            if (*p == '\0') {
                break;
            }
            if (*p == '*') {
                return true;
            }

            /* skip the list entry's optional W/ prefix */
            if (p[0] == 'W' && p[1] == '/') {
                p += 2;
            }

            /* read the rest until the comma (an ETag is a quoted-string) */
            const char *end = strchr(p, ',');
            size_t len = (end != NULL) ? (size_t)(end - p) : strlen(p);
            while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) {
                len--;
            }

            /* our ETag without the W/ prefix, for comparison */
            const char *ours = etag;
            if (ours[0] == 'W' && ours[1] == '/') {
                ours += 2;
            }
            if (len == strlen(ours) && strncmp(p, ours, len) == 0) {
                return true;
            }

            p = (end != NULL) ? end : p + len;
        }
    }
    return false;
}

/* ============================================================
 * Handler
 * ============================================================ */

void http_static_handler(const HttpRequest *req, HttpResponse *res,
                         const HttpStaticConfig *cfg)
{
    if (req == NULL || res == NULL || cfg == NULL || cfg->root == NULL ||
        cfg->prefix == NULL) {
        if (res != NULL) {
            res->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        }
        return;
    }

    /* 1. URL suffix after the prefix (empty -> mount root -> index) */
    const char *suffix;
    if (!extract_suffix(cfg->prefix, req->path, &suffix)) {
        res->status = HTTP_STATUS_NOT_FOUND;
        return;
    }

    /* 2. URL decoding BEFORE any path check ("%2e%2e" == "..") */
    char decoded[HTTP_PATH_MAX];
    if (url_decode(*suffix != '\0' ? suffix : "", decoded, sizeof(decoded)) !=
        0) {
        res->status = HTTP_STATUS_BAD_REQUEST;
        return;
    }

    /* 3. traversal & control characters after decoding */
    if (strstr(decoded, "..") != NULL) {
        /* 404 instead of 403: no information about the directory layout */
        res->status = HTTP_STATUS_NOT_FOUND;
        return;
    }
    if (has_control_chars(decoded)) {
        res->status = HTTP_STATUS_BAD_REQUEST;
        return;
    }

    /* 4. build the file system path (empty suffix -> index_file) */
    char fs_path[PATH_MAX];
    struct stat st;
    const char *name = (*decoded != '\0') ? decoded : cfg->index_file;

    if (name == NULL) {
        /* mount root without index_file: no directory listing, 404 */
        res->status = HTTP_STATUS_NOT_FOUND;
        return;
    }

    int n = snprintf(fs_path, sizeof(fs_path), "%s/%s", cfg->root, name);
    if (n < 0 || (size_t)n >= sizeof(fs_path)) {
        res->status = HTTP_STATUS_URI_TOO_LONG;
        return;
    }

    if (stat(fs_path, &st) != 0) {
        res->status = HTTP_STATUS_NOT_FOUND;
        return;
    }

    /* 5. directory -> index_file, anything but a regular file -> 404 */
    if (S_ISDIR(st.st_mode)) {
        int m = snprintf(fs_path, sizeof(fs_path), "%s/%s/%s", cfg->root, name,
                         cfg->index_file != NULL ? cfg->index_file : "");
        if (cfg->index_file == NULL || m < 0 || (size_t)m >= sizeof(fs_path)) {
            res->status = HTTP_STATUS_NOT_FOUND;
            return;
        }
        if (stat(fs_path, &st) != 0 || !S_ISREG(st.st_mode)) {
            res->status = HTTP_STATUS_NOT_FOUND;
            return;
        }
    } else if (!S_ISREG(st.st_mode)) {
        /* hide FIFOs/devices/sockets, do not serve them */
        res->status = HTTP_STATUS_NOT_FOUND;
        return;
    }

    /* 6. symlink escape: the resolved path must stay below the
     * resolved root (realpath resolves symlink chains too). */
    char root_real[PATH_MAX];
    char file_real[PATH_MAX];
    if (realpath(cfg->root, root_real) == NULL ||
        realpath(fs_path, file_real) == NULL) {
        res->status = HTTP_STATUS_NOT_FOUND;
        return;
    }
    size_t rlen = strlen(root_real);
    if (strncmp(file_real, root_real, rlen) != 0 ||
        (file_real[rlen] != '\0' && file_real[rlen] != '/')) {
        res->status = HTTP_STATUS_NOT_FOUND;
        return;
    }

    /* 7. This file supports single-range requests (RFC 9110 §14). */
    http_set_header(&res->headers, HTTP_HEADER_ACCEPT_RANGES, "bytes");

    /* 8. conditional GET: weak ETag from (mtime, size) */
    char etag[64];
    snprintf(etag, sizeof(etag), "W/\"%llx-%llx\"",
             (unsigned long long)st.st_mtime, (unsigned long long)st.st_size);
    if (etag_matches(req, etag)) {
        res->status = HTTP_STATUS_NOT_MODIFIED;
        http_set_header(&res->headers, HTTP_HEADER_ETAG, etag);
        return;
    }

    /* 9. single-range requests (RFC 9110 §14.2): "bytes=first-last",
     * "bytes=-N" (suffix) and "bytes=N-" (open end). Unsupported or
     * malformed Range headers are IGNORED (a full 200 — RFC 9110
     * §14.2: a server MUST ignore a Range header with a range unit it
     * does not understand). Multi-range requests fall back to a full
     * 200 as well. Unsatisfiable ranges get 416 + Content-Range. */
    const char *range = http_req_header(req, HTTP_HEADER_RANGE);
    if (range != NULL && strncasecmp(range, "bytes=", 6) == 0) {
        const char *spec = range + 6;
        unsigned long long size = (unsigned long long)st.st_size;
        bool ok = false;         /* parsed a valid single range */
        bool satisfiable = true; /* false -> 416 */
        unsigned long long start = 0;
        unsigned long long len = 0;

        if (strchr(spec, ',') == NULL) { /* single range only */
            char *end = NULL;
            errno = 0;
            if (spec[0] == '-') {
                /* suffix: the last suffix_len bytes */
                long long suffix_len = strtoll(spec + 1, &end, 10);
                if (end != spec + 1 && *end == '\0' && errno == 0) {
                    if (suffix_len <= 0 || size == 0) {
                        /* "bytes=-0" and any suffix on an EMPTY file
                         * are unsatisfiable (the range is empty) */
                        satisfiable = false;
                    } else {
                        ok = true;
                        if ((unsigned long long)suffix_len >= size) {
                            start = 0; /* more than the file: everything */
                            len = size;
                        } else {
                            start = size - (unsigned long long)suffix_len;
                            len = (unsigned long long)suffix_len;
                        }
                    }
                }
            } else {
                long long first = strtoll(spec, &end, 10);
                if (end != spec && errno == 0 && first >= 0 && *end == '-') {
                    long long last = -1;
                    if (end[1] == '\0') {
                        /* open end: from first to EOF */
                        if ((unsigned long long)first >= size) {
                            satisfiable = false;
                        } else {
                            ok = true;
                            start = (unsigned long long)first;
                            len = size - start;
                        }
                    } else {
                        last = strtoll(end + 1, &end, 10);
                        if (*end == '\0' && errno == 0 && last >= first) {
                            if ((unsigned long long)first >= size) {
                                satisfiable = false;
                            } else {
                                ok = true;
                                start = (unsigned long long)first;
                                unsigned long long end_pos =
                                    (unsigned long long)last >= size
                                        ? size - 1
                                        : (unsigned long long)last;
                                len = end_pos - start + 1;
                            }
                        }
                    }
                }
            }
        }

        if (ok) {
            char content_range[96];
            snprintf(content_range, sizeof(content_range),
                     "bytes %llu-%llu/%llu", start, start + len - 1, size);
            http_set_header(&res->headers, HTTP_HEADER_CONTENT_RANGE,
                            content_range);
            res->status = HTTP_STATUS_PARTIAL_CONTENT; /* 206 */
            res->ranged = true;
            res->range_start = (size_t)start;
            res->range_len = (size_t)len;
        } else if (!satisfiable) {
            /* RFC 9110 §15.5.17: 416 must state the complete length */
            char content_range[64];
            snprintf(content_range, sizeof(content_range), "bytes */%llu",
                     size);
            http_set_header(&res->headers, HTTP_HEADER_CONTENT_RANGE,
                            content_range);
            res->status = HTTP_STATUS_RANGE_NOT_SATISFIABLE;
            return;
        }
        /* else: malformed/multi-range — ignored, the full 200 below */
    }

    /* 10. response headers */
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, mime_for(fs_path));
    http_set_header(&res->headers, HTTP_HEADER_ETAG, etag);
    char last_modified[64];
    format_http_time(st.st_mtime, last_modified, sizeof(last_modified));
    http_set_header(&res->headers, HTTP_HEADER_LAST_MODIFIED, last_modified);
    if (cfg->max_age > 0) {
        char cache_control[64];
        snprintf(cache_control, sizeof(cache_control), "public, max-age=%u",
                 cfg->max_age);
        http_set_header(&res->headers, HTTP_HEADER_CACHE_CONTROL,
                        cache_control);
    }

    /* 11. stream the file as the body — the library sends it instead of
     * res->body and frees the path afterwards. The strdup prevents a
     * dangling pointer to our stack buffer. */
    free(res->file_path);
    res->file_path = strdup(fs_path);
    if (res->file_path == NULL) {
        res->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        return;
    }
    if (!res->ranged) {
        res->status = HTTP_STATUS_OK; /* ranged: 206 is already set */
    }
}

/* ============================================================
 * Mount management
 * ============================================================ */

HttpServerResult http_static_mount(HttpServer *server,
                                   const HttpStaticConfig *cfg)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(cfg != NULL);
    HTTP_ASSERT(cfg->prefix != NULL);
    HTTP_ASSERT(cfg->root != NULL);
    HTTP_ASSERT_MSG(cfg->prefix[0] == '/', "mount prefix must start with '/'");
    HTTP_ASSERT_MSG(server->listening == false,
                    "cannot mount static files while listening");

    if (server == NULL || cfg == NULL || cfg->prefix == NULL ||
        cfg->root == NULL) {
        return SERVER_ERROR;
    }
    if (cfg->prefix[0] != '/' || strlen(cfg->prefix) >= HTTP_PATH_MAX) {
        return SERVER_ERROR;
    }
    if (has_control_chars(cfg->prefix) || strchr(cfg->prefix, '%') != NULL ||
        strchr(cfg->prefix, '?') != NULL) {
        return SERVER_ERROR;
    }

    /* the root must exist (fail fast instead of a later 404 flood) */
    struct stat st;
    if (stat(cfg->root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "http_static_mount: root '%s' is not a directory\n",
                cfg->root);
        return SERVER_ERROR;
    }

    /* normalize the prefix: "/public/" -> "/public"; "/" stays "/" */
    char prefix[HTTP_PATH_MAX];
    size_t plen = strlen(cfg->prefix);
    memcpy(prefix, cfg->prefix, plen + 1);
    while (plen > 1 && prefix[plen - 1] == '/') {
        prefix[--plen] = '\0';
    }

    /* reject mounting the same prefix twice */
    const HttpStaticMount *m = server->static_mounts;
    while (m != NULL) {
        if (strcmp(m->cfg.prefix, prefix) == 0) {
            return SERVER_ERROR;
        }
        m = m->next;
    }

    HttpStaticMount *mount = calloc(1, sizeof(*mount));
    if (mount == NULL) {
        return SERVER_ERROR;
    }
    mount->cfg.prefix = strdup(prefix);
    mount->cfg.root = strdup(cfg->root);
    mount->cfg.index_file =
        cfg->index_file != NULL ? strdup(cfg->index_file) : NULL;
    mount->cfg.max_age = cfg->max_age;

    if (mount->cfg.prefix == NULL || mount->cfg.root == NULL ||
        (cfg->index_file != NULL && mount->cfg.index_file == NULL)) {
        free((void *)mount->cfg.prefix);
        free((void *)mount->cfg.root);
        free((void *)mount->cfg.index_file);
        free(mount);
        return SERVER_ERROR;
    }

    mount->next = server->static_mounts;
    server->static_mounts = mount;
    return SERVER_OK;
}

HttpStaticDispatchResult http_static_dispatch(const HttpServer *server,
                                              const HttpRequest *req,
                                              HttpResponse *res)
{
    if (server == NULL || req == NULL || res == NULL) {
        return HTTP_STATIC_NOT_MATCHED;
    }

    const HttpStaticMount *m = server->static_mounts;
    while (m != NULL) {
        const char *suffix;
        if (!extract_suffix(m->cfg.prefix, req->path, &suffix)) {
            m = m->next;
            continue;
        }

        /* Mounts serve GET only (and HEAD: send_res suppresses the
         * body, the headers including Content-Length are correct). */
        if (strcmp(req->method, "GET") != 0 &&
            strcmp(req->method, "HEAD") != 0) {
            http_set_header(&res->headers, HTTP_HEADER_ALLOW, "GET, HEAD");
            return HTTP_STATIC_METHOD_NOT_ALLOWED;
        }

        http_static_handler(req, res, &m->cfg);
        return HTTP_STATIC_SERVED;
    }
    return HTTP_STATIC_NOT_MATCHED;
}

void http_static_mounts_free(HttpServer *server)
{
    if (server == NULL) {
        return;
    }

    HttpStaticMount *m = server->static_mounts;
    while (m != NULL) {
        HttpStaticMount *next = m->next;
        free((void *)m->cfg.prefix);
        free((void *)m->cfg.root);
        free((void *)m->cfg.index_file);
        free(m);
        m = next;
    }
    server->static_mounts = NULL;
}