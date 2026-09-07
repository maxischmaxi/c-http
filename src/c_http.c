#include "c_http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "c_http_assert.h"
#include "c_http_static.h"

/* Time window for a client request (recv AND send); after that the
 * client counts as dead. Protects the single-threaded server against
 * Slowloris DoS. */
#define HTTP_CLIENT_TIMEOUT_SEC 10

/* Backlog for listen(2) */
#define HTTP_LISTEN_BACKLOG 128

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 /* platform without MSG_NOSIGNAL (e.g. macOS) */
#endif

static void free_encoded_body(HttpResponse *res)
{
    if (res->encoded_body != NULL) {
        free(res->encoded_body);
        res->encoded_body = NULL;
    }
}

/* ============================================================
 * HTTP Spec Validation Helpers (RFC 9110, 9112)
 *
 * IMPORTANT: these validation functions are real guards and are
 * ALWAYS compiled in — even with NDEBUG. Security-relevant validation
 * (header injection, field names) must not run only in debug builds
 * via HTTP_ASSERT.
 * ============================================================ */

/* RFC 9110 §5.5: field-name = 1*tchar */
static bool is_tchar(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return true;
    }
    if (c >= 'a' && c <= 'z') {
        return true;
    }
    if (c >= 'A' && c <= 'Z') {
        return true;
    }
    return strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static bool is_valid_header_name(const char *name)
{
    if (name == NULL || *name == '\0') {
        return false;
    }
    for (const char *p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c <= 0x20 || c == 0x7f || c > 0x7e) { /* no CTL/SP, ASCII only */
            return false;
        }
        if (!is_tchar(c)) {
            return false;
        }
    }
    return true;
}

/* RFC 9110 §5.6: field-value must not contain CR/LF.
 * Prevents header injection / response splitting. */
static bool header_value_has_injection(const char *value)
{
    if (value == NULL) {
        return false;
    }
    for (const char *p = value; *p; p++) {
        if (*p == '\r' || *p == '\n') {
            return true;
        }
    }
    return false;
}

/* RFC 9112 §3.1: HTTP-version = HTTP-name "/" DIGIT "." DIGIT */
static bool is_valid_http_version(const char *version)
{
    if (version == NULL) {
        return false;
    }
    return (strncmp(version, "HTTP/", 5) == 0 && version[5] >= '0' &&
            version[5] <= '9' && version[6] == '.' && version[7] >= '0' &&
            version[7] <= '9' && version[8] == '\0') != 0;
}

/* RFC 9110 §15: status-code = 3DIGIT; standard range 100-599 */
static bool is_valid_status_code(int status)
{
    return (status >= 100 && status <= 599) != 0;
}

#ifndef NDEBUG

/* RFC 9110 §3.2: origin-form starts with "/", asterisk-form "*" only
 * with OPTIONS. Used as a debug assert only. */
static bool is_valid_request_target(const char *path, const char *method)
{
    if (path == NULL || *path == '\0') {
        return false;
    }
    if (strcmp(path, "*") == 0) {
        return (method != NULL && strcmp(method, "OPTIONS") == 0) != 0;
    }
    return path[0] == '/';
}

#endif /* !NDEBUG — assert-only validation helpers */

static const char *status_text(int status)
{
    if (!is_valid_status_code(status)) {
        return "Unknown";
    }
    switch (status) {
    /* 1xx Informational */
    case 100:
        return "Continue";
    case 101:
        return "Switching Protocols";
    case 102:
        return "Processing";
    case 103:
        return "Early Hints";

    /* 2xx Success */
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 202:
        return "Accepted";
    case 203:
        return "Non-Authoritative Information";
    case 204:
        return "No Content";
    case 205:
        return "Reset Content";
    case 206:
        return "Partial Content";
    case 207:
        return "Multi-Status";
    case 208:
        return "Already Reported";
    case 226:
        return "IM Used";

    /* 3xx Redirection */
    case 300:
        return "Multiple Choices";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 303:
        return "See Other";
    case 304:
        return "Not Modified";
    case 305:
        return "Use Proxy";
    case 307:
        return "Temporary Redirect";
    case 308:
        return "Permanent Redirect";

    /* 4xx Client Error */
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 402:
        return "Payment Required";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 406:
        return "Not Acceptable";
    case 407:
        return "Proxy Authentication Required";
    case 408:
        return "Request Timeout";
    case 409:
        return "Conflict";
    case 410:
        return "Gone";
    case 411:
        return "Length Required";
    case 412:
        return "Precondition Failed";
    case 413:
        return "Content Too Large";
    case 414:
        return "URI Too Long";
    case 415:
        return "Unsupported Media Type";
    case 416:
        return "Range Not Satisfiable";
    case 417:
        return "Expectation Failed";
    case 418:
        return "I'm a Teapot";
    case 421:
        return "Misdirected Request";
    case 422:
        return "Unprocessable Content";
    case 423:
        return "Locked";
    case 424:
        return "Failed Dependency";
    case 425:
        return "Too Early";
    case 426:
        return "Upgrade Required";
    case 428:
        return "Precondition Required";
    case 429:
        return "Too Many Requests";
    case 431:
        return "Request Header Fields Too Large";
    case 451:
        return "Unavailable for Legal Reasons";

    /* 5xx Server Error */
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    case 504:
        return "Gateway Timeout";
    case 505:
        return "HTTP Version Not Supported";
    case 506:
        return "Variant Also Negotiates";
    case 507:
        return "Insufficient Storage";
    case 508:
        return "Loop Detected";
    case 510:
        return "Not Extended";
    case 511:
        return "Network Authentication Required";
    default:
        return "Unknown";
    }
}

static const char *method_name(HttpMethod m)
{
    switch (m) {
    case HTTP_METHOD_GET:
        return "GET";
    case HTTP_METHOD_POST:
        return "POST";
    case HTTP_METHOD_PUT:
        return "PUT";
    case HTTP_METHOD_PATCH:
        return "PATCH";
    case HTTP_METHOD_DELETE:
        return "DELETE";
    case HTTP_METHOD_HEAD:
        return "HEAD";
    case HTTP_METHOD_OPTIONS:
        return "OPTIONS";
    case HTTP_METHOD_CONNECT:
        return "CONNECT";
    case HTTP_METHOD_TRACE:
        return "TRACE";
    }
    return "UNKNOWN";
}

static bool parse_route_segments(const char *pattern, HttpRouteSegments *out)
{
    HttpRouteSegments segments = {0};
    segments.segments = malloc(8 * sizeof(HttpRouteSegment));
    if (segments.segments == NULL) {
        return false;
    }
    segments.count = 0;
    segments.capacity = 8;

    const char *p = pattern;
    while ((p = strchr(p, '/')) != NULL) {
        p++;

        bool is_param = false;
        if (*p == ':') {
            is_param = true;
            p++;
        }

        const char *end = p;
        while (*end != '\0' && *end != '/') {
            end++;
        }

        size_t len = (size_t)(end - p);
        if (len == 0 && !is_param) {
            continue;
        }
        if (len == 0) {
            free(segments.segments);
            return false;
        }

        if (len >= sizeof(segments.segments[0].text)) {
            free(segments.segments);
            return false;
        }

        HttpRouteSegment segment = {.is_param = is_param};
        memcpy(segment.text, p, len);
        segment.text[len] = '\0';
        segments.segments[segments.count] = segment;
        segments.count++;

        if (segments.count == segments.capacity) {
            size_t new_cap = segments.capacity * 2;
            HttpRouteSegment *tmp =
                realloc(segments.segments, new_cap * sizeof(HttpRouteSegment));
            if (tmp == NULL) {
                free(segments.segments);
                return false;
            }
            segments.segments = tmp;
            segments.capacity = new_cap;
        }
    }

    out->segments = segments.segments;
    out->count = segments.count;
    out->capacity = segments.capacity;
    return true;
}

/* Matches a parsed route pattern against parsed request segments.
 * A ":name" segment binds any single non-empty request segment.
 * If params is non-NULL AND the route matches, the bound values are
 * copied into it (params->count is only set on a full match — a failed
 * route attempt must not leave dirty state behind for the next route).
 * Returns true = match, false = no match. */
static bool segments_match(const HttpRouteSegments *pattern,
                           const HttpRouteSegments *request, HttpParams *params)
{
    if (pattern == NULL || request == NULL) {
        return false;
    }
    if (pattern->count != request->count) {
        return false; /* different segment count -> clean "no match" */
    }

    size_t param_count = 0;
    for (size_t i = 0; i < pattern->count; i++) {
        const HttpRouteSegment *pat = &pattern->segments[i];
        const HttpRouteSegment *cur = &request->segments[i];

        if (pat->is_param) {
            if (params == NULL) {
                continue; /* pure match test — no binding wanted */
            }
            if (param_count >= HTTP_MAX_PARAMS) {
                return false; /* registration rejects this earlier —
                                 defensive bound against overflow */
            }
            HttpParam *param = &params->params[param_count];
            if (snprintf(param->key, sizeof(param->key), "%s", pat->text) >=
                (int)sizeof(param->key)) {
                return false;
            }
            if (snprintf(param->value, sizeof(param->value), "%s", cur->text) >=
                (int)sizeof(param->value)) {
                return false;
            }
            param_count++;
        } else if (strcmp(pat->text, cur->text) != 0) {
            return false; /* literal mismatch -> "no match", NOT an error */
        }
    }

    if (params != NULL) {
        params->count = param_count; /* commit only on a full match */
    }
    return true;
}

/*
 * the reg_path is the path that was registered in the code e.g. /api e.g. via
 * http_get(&server, "/api", handle_api). The real_path is the path the e.g.
 * browser requested via HTTP
 */
static bool path_matches(const char *reg_path, const char *real_path)
{
    HTTP_ASSERT(reg_path != NULL);
    HTTP_ASSERT(real_path != NULL);

    size_t reg_len = strlen(reg_path);
    size_t real_len = strlen(real_path);

    /* Trailing slash on the middleware path is optional:
     * "/api/" behaves like "/api" (matches "/api" AND "/api/users").
     * "" matches everything (root). */
    if (reg_len > 1 && reg_path[reg_len - 1] == '/') {
        reg_len--;
    }
    if (reg_len == 0) {
        return true;
    }
    if (real_len == 0) {
        return false;
    }

    if (strncmp(reg_path, real_path, reg_len) != 0) {
        return false;
    }

    if (real_len == reg_len) {
#ifndef NDEBUG
        printf("match found, exact match: %s - %s\n", reg_path, real_path);
#endif
        return true;
    }

    if (reg_path[reg_len - 1] == '/') {
#ifndef NDEBUG
        printf("match found, match without trailing slash: %s - %s\n", reg_path,
               real_path);
#endif
        return true;
    }

    /* "/api" matches "/api/users", but NOT "/api-v2" */
    if (real_path[reg_len] == '/') {
#ifndef NDEBUG
        printf("match found, match with trailing slash: %s - %s\n", reg_path,
               real_path);
#endif
        return true;
    }

    return false;
}

/* Compact RFC-1123-compliant date — deliberately NOT via strftime,
 * because %a/%b are locale-dependent (e.g. "So" instead of "Sun"). */
static void format_http_date(char *buf, size_t size)
{
    static const char *const days[7] = {"Sun", "Mon", "Tue", "Wed",
                                        "Thu", "Fri", "Sat"};
    static const char *const months[12] = {"Jan", "Feb", "Mar", "Apr",
                                           "May", "Jun", "Jul", "Aug",
                                           "Sep", "Oct", "Nov", "Dec"};

    time_t now = time(NULL);
    struct tm gt;
    gmtime_r(&now, &gt);

    int wday = gt.tm_wday >= 0 && gt.tm_wday <= 6 ? gt.tm_wday : 0;
    int mon = gt.tm_mon >= 0 && gt.tm_mon <= 11 ? gt.tm_mon : 0;

    snprintf(buf, size, "%s, %02d %s %04d %02d:%02d:%02d GMT", days[wday],
             gt.tm_mday, months[mon], 1900 + gt.tm_year, gt.tm_hour, gt.tm_min,
             gt.tm_sec);
}

static int apply_header(HttpHeaders *headers, const char *key,
                        const char *value)
{
    if (headers == NULL || key == NULL || value == NULL) {
        return -1;
    }

    /* Real guards (also in release builds): RFC 9110 field name and
     * no CR/LF in the value (header injection). */
    if (!is_valid_header_name(key)) {
        return -1;
    }
    if (header_value_has_injection(value)) {
        return -1;
    }

    if (headers->count == headers->capacity) {
        size_t new_cap = headers->capacity == 0 ? 8 : headers->capacity * 2;
        HttpHeader *tmp = realloc(headers->items, new_cap * sizeof(HttpHeader));
        if (tmp == NULL) {
            return -1;
        }
        headers->items = tmp;
        headers->capacity = new_cap;
    }

    headers->items[headers->count] = (HttpHeader){
        .key = strdup(key),
        .value = strdup(value),
    };
    if (headers->items[headers->count].key == NULL ||
        headers->items[headers->count].value == NULL) {
        free(headers->items[headers->count].key);
        free(headers->items[headers->count].value);
        return -1;
    }

    headers->count++;
    return 0;
}

static int string_to_http_method(const char *method, HttpMethod *out)
{
    if (method == NULL || out == NULL) {
        return -1;
    }

    if (strcmp(method, "GET") == 0) {
        *out = HTTP_METHOD_GET;
    } else if (strcmp(method, "POST") == 0) {
        *out = HTTP_METHOD_POST;
    } else if (strcmp(method, "PUT") == 0) {
        *out = HTTP_METHOD_PUT;
    } else if (strcmp(method, "PATCH") == 0) {
        *out = HTTP_METHOD_PATCH;
    } else if (strcmp(method, "DELETE") == 0) {
        *out = HTTP_METHOD_DELETE;
    } else if (strcmp(method, "HEAD") == 0) {
        *out = HTTP_METHOD_HEAD;
    } else if (strcmp(method, "OPTIONS") == 0) {
        *out = HTTP_METHOD_OPTIONS;
    } else if (strcmp(method, "CONNECT") == 0) {
        *out = HTTP_METHOD_CONNECT;
    } else if (strcmp(method, "TRACE") == 0) {
        *out = HTTP_METHOD_TRACE;
    } else {
        return -1;
    }

    return 0;
}

/* Reads the request headers into buf up to "\r\n\r\n" (or until the
 * buffer is full). *complete reports whether the header block was fully
 * received. Returns the bytes read, -1 on error/timeout. */
static ssize_t read_request(int client_fd, char *buf, size_t size,
                            bool *complete)
{
    HTTP_ASSERT(client_fd >= 0);
    HTTP_ASSERT(buf != NULL);
    HTTP_ASSERT(size > 1);
    HTTP_ASSERT(complete != NULL);

    size_t total = 0;
    *complete = false;

    while (total < size - 1) {
        ssize_t r = recv(client_fd, buf + total, size - 1 - total, 0);
        if (r < 0) {
            if (errno == EINTR) { /* signal received: retry */
                continue;
            }
            return -1; /* error or timeout (SO_RCVTIMEO) */
        }
        if (r == 0) {
            break; /* client closed the connection */
        }

        size_t chunk_start = total;
        total += (size_t)r;
        buf[total] = '\0';

        /* Scan only the new chunk + 3 bytes of overlap, so a
         * "\r\n\r\n" across the chunk boundary is detected (no O(n²)). */
        size_t scan_from = chunk_start > 3 ? chunk_start - 3 : 0;
        if (strstr(buf + scan_from, "\r\n\r\n") != NULL) {
            *complete = true;
            break;
        }
    }

    buf[total] = '\0';
    return (ssize_t)total;
}

static int send_all(int client_fd, const char *data, size_t len)
{
    HTTP_ASSERT(client_fd >= 0);
    HTTP_ASSERT(len == 0 || data != NULL);

    size_t sent = 0;

    while (sent < len) {
        /* MSG_NOSIGNAL: suppress SIGPIPE — a client closing the
         * connection mid-response must not kill the server. */
        ssize_t s = send(client_fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (s < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t)s;
    }

    return 0;
}

static void xclose_fd(int fd)
{
    if (fd < 0) {
        return;
    }
    while (close(fd) != 0) {
        if (errno != EINTR) {
            break;
        }
    }
}

static int open_regular_file(const char *path)
{
    /* O_CLOEXEC: the fd must not leak into forked/exec'ed child
     * processes (fd passing would be a file-permission escalation). */
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        xclose_fd(fd);
        return -1;
    }

    return fd;
}

#ifdef __linux__
#include <sys/sendfile.h>
/* Streams size bytes from file_fd to the socket. Exactly size — never
 * more (Content-Length is promised) and never fewer (otherwise the
 * client would wait for the rest). */
static int send_fd(int file_fd, off_t size, int client_fd)
{
    /* Linux sendfile accepts at most 0x7ffff000 bytes per call. */
    const off_t MAX_CHUNK = 0x7ffff000;
    off_t sent_total = 0;

    while (sent_total < size) {
        off_t chunk = size - sent_total;
        if (chunk > MAX_CHUNK) {
            chunk = MAX_CHUNK;
        }
        ssize_t sent = sendfile(client_fd, file_fd, NULL, (size_t)chunk);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (sent == 0) {
            return -1; /* file shrank behind our back */
        }
        sent_total += sent;
    }
    return 0;
}

#else
/* Portable fallback (macOS/BSD): read loop with an exact bound. */
static int send_fd(int file_fd, off_t size, int client_fd)
{
    char buf[64 * 1024];
    off_t remaining = size;

    while (remaining > 0) {
        size_t want =
            remaining > (off_t)sizeof(buf) ? sizeof(buf) : (size_t)remaining;
        ssize_t n = read(file_fd, buf, want);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1; /* file shrank behind our back */
        }
        if (send_all(client_fd, buf, (size_t)n) != 0) {
            return -1;
        }
        remaining -= n;
    }
    return 0;
}

#endif /* __linux__ */

/* Sends the response headers. suppress_body (HEAD) suppresses the body
 * but keeps Content-Length, so the client learns the GET size. */
static void send_res(HttpResponse *res, int client_fd, bool suppress_body)
{
    HTTP_ASSERT(res != NULL);
    HTTP_ASSERT(client_fd >= 0);

    /* RFC 9110 §15: validate status; invalid -> send 500 instead of garbage */
    if (!is_valid_status_code(res->status)) {
        res->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

    bool no_body_status = ((res->status >= 100 && res->status < 200) ||
                           res->status == HTTP_STATUS_NO_CONTENT ||
                           res->status == HTTP_STATUS_RESET_CONTENT ||
                           res->status == HTTP_STATUS_NOT_MODIFIED) != 0;

    /* File streaming: exactly ONE open()+fstat() — the size for
     * Content-Length comes from the SAME fd that is sent later (no TOCTOU
     * window between stat() and open()). If the file vanished between
     * the handler and the send, answer cleanly with 500 and an empty
     * body instead of a wrong Content-Length. */
    int file_fd = -1;
    off_t file_size = 0;
    if (res->file_path != NULL && !no_body_status) {
        file_fd = open_regular_file(res->file_path);
        struct stat st;
        if (file_fd >= 0 && fstat(file_fd, &st) == 0 && st.st_size >= 0) {
            file_size = st.st_size;
        } else {
            xclose_fd(file_fd);
            file_fd = -1;
            res->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
            res->body_len = 0;
        }
    }
    bool streaming = file_fd >= 0;

    size_t body_len =
        res->encoded_body != NULL ? res->encoded_body_len : res->body_len;
    const char *body =
        res->encoded_body != NULL ? res->encoded_body : res->body;

    HTTP_ASSERT_MSG(res->body_len <= sizeof(res->body),
                    "body_len exceeds body buffer — buffer overflow");

    char status_line[64];
    int status_len =
        snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d %s\r\n",
                 res->status, status_text(res->status));
    if (status_len < 0) {
        goto out;
    }
    if ((size_t)status_len >= sizeof(status_line)) {
        status_len = (int)sizeof(status_line) - 1;
    }
    if (send_all(client_fd, status_line, (size_t)status_len) != 0) {
        goto out;
    }

    if (!no_body_status) {
        char content_length[64]; /* large enough for any size_t */
        size_t cl = body_len;
        if (streaming) {
            cl = (size_t)file_size;
        }
        int cl_len = snprintf(content_length, sizeof(content_length),
                              "Content-Length: %zu\r\n", cl);
        if (cl_len < 0 || (size_t)cl_len >= sizeof(content_length)) {
            goto out;
        }
        if (send_all(client_fd, content_length, (size_t)cl_len) != 0) {
            goto out;
        }
    }

    bool has_content_type = false;
    for (size_t i = 0; i < res->headers.count; i++) {
        if (strcasecmp(res->headers.items[i].key, HTTP_HEADER_CONTENT_TYPE) ==
            0) {
            has_content_type = true;
            break;
        }
    }

    /* Set the default only if no handler set one
     * (no duplicate Content-Type headers). */
    if (!has_content_type && streaming) {
        /* Streamed file without handler input: safe download default
         * instead of text/html (nosniff is set anyway). */
        if (send_all(client_fd, "Content-Type: application/octet-stream\r\n",
                     sizeof("Content-Type: application/octet-stream\r\n") -
                         1) != 0) {
            goto out;
        }
    } else if (!has_content_type && body_len > 0) {
        /* sizeof() - 1 instead of a hand-computed 24: the hard-coded
         * length was one byte short and cut off the '\n'. */
        if (send_all(client_fd, "Content-Type: text/html\r\n",
                     sizeof("Content-Type: text/html\r\n") - 1) != 0) {
            goto out;
        }
    }

    for (size_t i = 0; i < res->headers.count; i++) {
        char hdr_line[512];
        int hl =
            snprintf(hdr_line, sizeof(hdr_line), "%s: %s\r\n",
                     res->headers.items[i].key, res->headers.items[i].value);
        if (hl <= 0) {
            continue;
        }
        /* snprintf returns the hypothetical length — clamp to the
         * buffer, otherwise send_all reads past the end. */
        if ((size_t)hl >= sizeof(hdr_line)) {
            hl = (int)sizeof(hdr_line) - 1;
        }
        if (send_all(client_fd, hdr_line, (size_t)hl) != 0) {
            goto out;
        }
    }

    if (send_all(client_fd, "\r\n", 2) != 0) {
        goto out;
    }

    if (!no_body_status && !suppress_body) {
        if (streaming) {
            (void)send_fd(file_fd, file_size, client_fd);
        } else {
            (void)send_all(client_fd, body, body_len);
        }
    }

out:
    xclose_fd(file_fd);
    free_encoded_body(res);
    free(res->file_path);
    res->file_path = NULL;
}

/* Parse a request line: "METHOD SP request-target SP HTTP-version".
 * Modifies line in place. Returns 0 = OK, otherwise an HTTP status
 * (400/414/501/505) to send as the response. */
static int parse_request_line(char *line, HttpRequest *req)
{
    /* method */
    char *sp = strchr(line, ' ');
    if (sp == NULL) {
        return HTTP_STATUS_BAD_REQUEST;
    }
    *sp = '\0';
    if (strlen(line) >= HTTP_METHOD_MAX) {
        return HTTP_STATUS_NOT_IMPLEMENTED; /* unknown/overlong method */
    }
    strcpy(req->method, line);

    /* request-target (tolerate multiple SPs, RFC 9112 §2.2) */
    char *target = sp + 1;
    while (*target == ' ') {
        target++;
    }
    sp = strchr(target, ' ');
    if (sp == NULL) {
        return HTTP_STATUS_BAD_REQUEST;
    }
    *sp = '\0';

    /* Split off the query string: "/users?id=1" -> "/users" */
    char *query = strchr(target, '?');
    if (query != NULL) {
        *query = '\0';
    }

    if (target[0] == '\0') {
        return HTTP_STATUS_BAD_REQUEST;
    }
    if (strlen(target) >= HTTP_PATH_MAX) {
        return HTTP_STATUS_URI_TOO_LONG;
    }
    strcpy(req->path, target);

    /* HTTP-version */
    char *version = sp + 1;
    while (*version == ' ') {
        version++;
    }
    if (strlen(version) >= HTTP_VERSION_MAX) {
        return HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED;
    }
    strcpy(req->version, version);

    if (!is_valid_http_version(req->version)) {
        return HTTP_STATUS_BAD_REQUEST;
    }
    if (strcmp(req->version, "HTTP/1.1") != 0 &&
        strcmp(req->version, "HTTP/1.0") != 0) {
        return HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED;
    }

    /* RFC 9112 §3.1: request-target must be origin-form ("*": OPTIONS only) */
    HTTP_ASSERT_MSG(is_valid_request_target(req->path, req->method),
                    "RFC 9110 §3.2: invalid request-target");
    return 0;
}

/* Parse the header block (start points right after the request line,
 * end at the end of the received bytes). Returns 0 = OK, otherwise an
 * HTTP status (431/500). Invalid lines are skipped. */
static int parse_headers(char *start, const char *end, HttpRequest *req)
{
    char *cursor = start;

    while (cursor < end && cursor[0] != '\r' && cursor[0] != '\0') {
        char *line_end = strstr(cursor, "\r\n");
        if (line_end == NULL) {
            break; /* incomplete line */
        }

        char *colon = memchr(cursor, ':', (size_t)(line_end - cursor));
        if (colon == NULL) { /* line without ':' -> skip */
            cursor = line_end + 2;
            continue;
        }

        /* null-terminate the key in place */
        *colon = '\0';
        char *key = cursor;

        /* value: start after ':', trim leading OWS */
        char *value = colon + 1;
        while (*value == ' ' || *value == '\t') {
            value++;
        }

        /* RFC 9110 §5.5: trim trailing OWS (not just leading) */
        char *vend = line_end;
        while (vend > value && (vend[-1] == ' ' || vend[-1] == '\t')) {
            vend--;
        }
        *vend = '\0';

        /* Real validation (release too): skip invalid field names and
         * injected values instead of storing them. */
        if (!is_valid_header_name(key) || header_value_has_injection(value)) {
            cursor = line_end + 2;
            continue;
        }

        if (req->headers.count >= HTTP_MAX_HEADERS) {
            return HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
        }

        if (apply_header(&req->headers, key, value) != 0) {
            return HTTP_STATUS_INTERNAL_SERVER_ERROR;
        }

        cursor = line_end + 2;
    }
    return 0;
}

/* Read the request body according to Content-Length. header_end is
 * the offset of the first body byte in buf (already-read bytes are
 * carried over). Returns 0 = OK, otherwise an HTTP status
 * (400/408/413/500/501). */
static int read_body(int client_fd, char *buf, size_t total, size_t header_end,
                     HttpRequest *req)
{
    bool has_te = false;
    long long content_length = -1;

    for (size_t i = 0; i < req->headers.count; i++) {
        const char *key = req->headers.items[i].key;
        const char *value = req->headers.items[i].value;

        if (strcasecmp(key, HTTP_HEADER_TRANSFER_ENCODING) == 0) {
            has_te = true;
            continue;
        }
        if (strcasecmp(key, HTTP_HEADER_CONTENT_LENGTH) == 0) {
            errno = 0;
            char *end = NULL;
            long long parsed = strtoll(value, &end, 10);
            if (end == value || *end != '\0' || errno != 0 || parsed < 0) {
                return HTTP_STATUS_BAD_REQUEST;
            }
            /* RFC 9112 §5.2: duplicate Content-Length with an identical
             * value is allowed; differing values are an error. */
            if (content_length >= 0 && content_length != parsed) {
                return HTTP_STATUS_BAD_REQUEST;
            }
            content_length = parsed;
        }
    }

    /* Transfer-Encoding is not supported (chunked etc.) */
    if (has_te) {
        return HTTP_STATUS_NOT_IMPLEMENTED;
    }

    if (content_length < 0) {
        return 0; /* no body expected */
    }
    unsigned long long len = (unsigned long long)content_length;
    if (len > HTTP_MAX_BODY) {
        return HTTP_STATUS_CONTENT_TOO_LARGE;
    }

    req->body = malloc((size_t)content_length + 1);
    if (req->body == NULL) {
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

    /* bytes already read together with the headers */
    size_t leftover = total - header_end;
    if (leftover > (size_t)content_length) {
        /* more body bytes than Content-Length says -> request smuggling risk */
        free(req->body);
        req->body = NULL;
        return HTTP_STATUS_BAD_REQUEST;
    }
    memcpy(req->body, buf + header_end, leftover);

    size_t got = leftover;
    while (got < (size_t)content_length) {
        ssize_t r =
            recv(client_fd, req->body + got, (size_t)content_length - got, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(req->body);
            req->body = NULL;
            return HTTP_STATUS_REQUEST_TIMEOUT; /* timeout/error */
        }
        if (r == 0) { /* client vanished mid-body */
            free(req->body);
            req->body = NULL;
            return HTTP_STATUS_BAD_REQUEST;
        }
        got += (size_t)r;
    }

    req->body[(size_t)content_length] = '\0';
    req->body_len = (size_t)content_length;
    return 0;
}

static void apply_default_headers(HttpResponse *res, HttpServer *server)
{
    char time_buf[64];
    format_http_date(time_buf, sizeof(time_buf));
    apply_header(&res->headers, HTTP_HEADER_DATE, time_buf);
    apply_header(&res->headers, HTTP_HEADER_CONNECTION, "close");
    char server_name[64];
    int n = snprintf(server_name, sizeof(server_name), "%s/%s",
                     server->server_name, C_HTTP_VERSION);
    if (n > 0 && (size_t)n < sizeof(server_name)) {
        apply_header(&res->headers, HTTP_HEADER_SERVER, server_name);
    }
    apply_header(&res->headers, HTTP_HEADER_STRICT_TRANSPORT_SECURITY,
                 "max-age=31536000; includeSubDomains");
    apply_header(&res->headers, HTTP_HEADER_X_CONTENT_TYPE_OPTIONS, "nosniff");
    apply_header(&res->headers, HTTP_HEADER_X_FRAME_OPTIONS, "SAMEORIGIN");
    apply_header(&res->headers, HTTP_HEADER_CONTENT_SECURITY_POLICY,
                 "default-src 'self'");
    apply_header(&res->headers, HTTP_HEADER_REFERER_POLICY,
                 "strict-origin-when-cross-origin");
    apply_header(&res->headers, HTTP_HEADER_PERMISSIONS_POLICY,
                 "geolocation=(), camera=(), microphone=()");
    apply_header(&res->headers, HTTP_HEADER_ACCEPT_RANGES, "bytes");
    apply_header(&res->headers, HTTP_HEADER_VARY, "Accept-Encoding");
}

static bool apply_middleware(HttpServer *server, HttpRequest *req,
                             HttpResponse *res)
{
    for (size_t i = 0; i < server->middlewares.count; i++) {
        HttpMiddlewareHandler middleware =
            server->middlewares.middlewares[i].handler;
        const char *mid_path = server->middlewares.middlewares[i].path;

        if (mid_path == NULL) {
            if (middleware(req, res) == HTTP_MIDDLEWARE_STOP) {
                return false;
            }
            continue;
        }

        if (path_matches(mid_path, req->path)) {
            if (middleware(req, res) == HTTP_MIDDLEWARE_STOP) {
                return false;
            }
        }
    }
    return true;
}

typedef enum {
    HANDLER_OK = 0,
    HANDLER_NOT_FOUND,
    HANDLER_METHOD_NOT_ALLOWED,
    HANDLER_NOT_IMPLEMENTED,
} HandlerResult;

static HandlerResult execute_handler(HttpServer *server, HttpRequest *req,
                                     HttpResponse *res,
                                     const HttpRouteSegments *req_segments)
{
    HttpMethod method;
    if (string_to_http_method(req->method, &method) != 0) {
        return HANDLER_NOT_IMPLEMENTED;
    }

    HttpHandler handler = NULL;
    bool path_exists = false;

    /* First match wins: with param routes, several routes can match the
     * same request — registration order decides (Express semantics).
     * Pass NULL: pure match test, params are bound only for the winner,
     * so a failed attempt leaves req->params untouched. */
    for (size_t i = 0; i < server->routes.count; i++) {
        const HttpRoute *route = &server->routes.routes[i];
        if (!segments_match(&route->route_segments, req_segments, NULL)) {
            continue;
        }
        path_exists = true;
        if (route->method == method) {
            segments_match(&route->route_segments, req_segments, &req->params);
            handler = route->handler;
            break;
        }
    }

    /* RFC 9110 §9.3.2: HEAD falls back to GET when no explicit HEAD
     * route exists (the body is suppressed at send time). */
    if (handler == NULL && method == HTTP_METHOD_HEAD) {
        for (size_t i = 0; i < server->routes.count; i++) {
            const HttpRoute *route = &server->routes.routes[i];
            if (!segments_match(&route->route_segments, req_segments, NULL) ||
                route->method != HTTP_METHOD_GET) {
                continue;
            }
            segments_match(&route->route_segments, req_segments, &req->params);
            handler = route->handler;
            break;
        }
    }

    if (handler == NULL) {
        /* No route matched: next, check the static file mounts
         * (routes win over mounts). */
        switch (http_static_dispatch(server, req, res)) {
        case HTTP_STATIC_SERVED:
            return HANDLER_OK;
        case HTTP_STATIC_METHOD_NOT_ALLOWED:
            return HANDLER_METHOD_NOT_ALLOWED;
        case HTTP_STATIC_NOT_MATCHED:
            break;
        }
        return (int)path_exists ? HANDLER_METHOD_NOT_ALLOWED
                                : HANDLER_NOT_FOUND;
    }

    handler(req, res);
    return HANDLER_OK;
}

/* RFC 9110 §15.4.6: a 405 response includes an Allow header */
static void set_allow_header(HttpServer *server,
                             const HttpRouteSegments *req_segments,
                             HttpResponse *res)
{
    char allow[128];
    size_t used = 0;

    for (size_t i = 0; i < server->routes.count; i++) {
        if (!segments_match(&server->routes.routes[i].route_segments,
                            req_segments, NULL)) {
            continue;
        }
        const char *name = method_name(server->routes.routes[i].method);
        size_t n = strlen(name);
        if (used > 0) {
            if (used + 2 + n >= sizeof(allow)) {
                break;
            }
            allow[used++] = ',';
            allow[used++] = ' ';
        }
        memcpy(allow + used, name, n);
        used += n;
    }

    allow[used] = '\0';
    if (used > 0) {
        http_set_header(&res->headers, HTTP_HEADER_ALLOW, allow);
    }
}

static void handle_client(HttpServer *server, int client_fd, const char *ip,
                          uint16_t client_port)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(client_fd >= 0);
    HTTP_ASSERT(ip != NULL);
    HTTP_ASSERT(server->routes.routes != NULL);

    char buf[4096];
    bool headers_complete = false;

    /* Read first, allocate later: on read errors there is nothing to
     * clean up and no response buffer headers that could leak. */
    ssize_t total =
        read_request(client_fd, buf, sizeof(buf), &headers_complete);
    if (total < 0) {
        return; /* recv error or timeout — just close */
    }
    if (total == 0) {
        return; /* client closed immediately */
    }

    HttpRequest req = {0};
    HttpResponse res = {0};
    apply_default_headers(&res, server);

    /* Every error path jumps to send: a response is ALWAYS sent (no
     * silent connection close) and cleanup happens ONLY at the end. */
    if (!headers_complete) {
        res.status = HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE; /* 431 */
        goto send;
    }

    {
        /* Get the body start position BEFORE terminating (empty header
         * block: eol and marker coincide). */
        char *sep = strstr(buf, "\r\n\r\n");
        if (sep == NULL) { /* cannot happen with headers_complete */
            res.status = HTTP_STATUS_BAD_REQUEST;
            goto send;
        }
        size_t header_end = (size_t)(sep - buf) + 4;

        /* Isolate the request line (terminate at the first CRLF), then
         * parse; parse_headers starts right after it. */
        char *eol = strstr(buf, "\r\n");
        if (eol == NULL) {
            res.status = HTTP_STATUS_BAD_REQUEST;
            goto send;
        }
        *eol = '\0';

        int line_status = parse_request_line(buf, &req);
        if (line_status != 0) {
            res.status = line_status;
            goto send;
        }

        int hdr_status = parse_headers(eol + 2, buf + total, &req);
        if (hdr_status != 0) {
            res.status = hdr_status;
            goto send;
        }

        int body_status =
            read_body(client_fd, buf, (size_t)total, header_end, &req);
        if (body_status != 0) {
            res.status = body_status;
            goto send;
        }
    }

    /* RFC 9112 §3.2: Host header mandatory in HTTP/1.1 (debug check) */
#ifndef NDEBUG
    if (strcmp(req.version, "HTTP/1.1") == 0) {
        bool has_host = false;
        for (size_t i = 0; i < req.headers.count; i++) {
            if (strcasecmp(req.headers.items[i].key, HTTP_HEADER_HOST) == 0) {
                has_host = true;
                break;
            }
        }
        HTTP_ASSERT_MSG(has_host,
                        "RFC 9112 §3.2: Host header mandatory in HTTP/1.1");
    }
#endif

    /* Parse the request path into segments ONCE per request (routes
     * carry their segments pre-parsed from registration time). A parse
     * failure (bare ':' or an oversized segment) means no route can
     * match — clean 404. */
    HttpRouteSegments req_segments = {0};
    bool req_segments_ok = parse_route_segments(req.path, &req_segments);

    if (apply_middleware(server, &req, &res)) {
        HandlerResult result =
            req_segments_ok ? execute_handler(server, &req, &res, &req_segments)
                            : HANDLER_NOT_FOUND;
        switch (result) {
        case HANDLER_OK:
            break;
        case HANDLER_METHOD_NOT_ALLOWED:
            res.status = HTTP_STATUS_METHOD_NOT_ALLOWED;
            set_allow_header(server, &req_segments, &res);
            break;
        case HANDLER_NOT_FOUND:
            res.status = HTTP_STATUS_NOT_FOUND;
            break;
        case HANDLER_NOT_IMPLEMENTED:
            res.status = HTTP_STATUS_NOT_IMPLEMENTED;
            break;
        }
    }

    free(req_segments.segments); /* fixed-array params need no cleanup */

send:
    if (res.status == 0) {
        res.status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

    /* RFC 9110 §15: validate the status before sending */
    HTTP_ASSERT_MSG(is_valid_status_code(res.status),
                    "RFC 9110 §15: status code must be 100-599 before send");
    HTTP_ASSERT_MSG(res.body_len <= sizeof(res.body),
                    "body_len exceeds body buffer — buffer overflow");

    http_encode_body(server, &req, &res);

    /* RFC 9110 §9.3.2: HEAD responses have no body (the headers match
     * those of a GET, including Content-Length). */
    bool suppress_body = strcmp(req.method, "HEAD") == 0;
    send_res(&res, client_fd, suppress_body);

    printf("%s:%u %s %s -> %d\n", ip, client_port,
           req.method[0] != '\0' ? req.method : "-", req.path, res.status);

    free(req.body);
    http_headers_free(&req.headers);
    http_headers_free(&res.headers);
}

HttpServerResult http_create_server(const ServerArgs *server_args,
                                    HttpServer *out)
{
    if (out == NULL || server_args == NULL || server_args->bind_addr == NULL ||
        server_args->server_name == NULL) {
        return SERVER_ERROR;
    }

    /* Initialize out deterministically — even on failure the server is
     * then safe to close/empty. */
    memset(out, 0, sizeof(*out));
    out->fd = -1;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return SERVER_ERROR;
    }

    int yes = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct addrinfo hints;
    struct addrinfo *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(server_args->bind_addr, NULL, &hints, &result);
    if (gai != 0) {
        fprintf(stderr, "cannot resolve '%s': %s\n", server_args->bind_addr,
                gai_strerror(gai));
        close(server_fd);
        return SERVER_ERROR;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_args->port);
    addr.sin_addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("failed to bind port");
        close(server_fd);
        freeaddrinfo(result);
        return SERVER_ERROR;
    }

    freeaddrinfo(result);

    if (listen(server_fd, HTTP_LISTEN_BACKLOG) < 0) {
        perror("failed to listen");
        close(server_fd);
        return SERVER_ERROR;
    }

    out->routes.routes = malloc(8 * sizeof(HttpRoute));
    if (out->routes.routes == NULL) {
        close(server_fd); /* don't leak the socket */
        return SERVER_ERROR;
    }
    out->routes.count = 0;
    out->routes.capacity = 8;

    /* server_name is copied — the library does not depend on the
     * caller's memory. */
    out->server_name = strdup(server_args->server_name);
    if (out->server_name == NULL) {
        free(out->routes.routes);
        out->routes.routes = NULL;
        close(server_fd);
        return SERVER_ERROR;
    }

    out->middlewares.middlewares = NULL;
    out->middlewares.count = 0;
    out->middlewares.capacity = 0;

    out->encoders.encoders = NULL;
    out->encoders.count = 0;
    out->encoders.capacity = 0;
    http_register_encoder(out, http_gzip_encoder);
    http_register_encoder(out, http_identity_encoder);

    out->port = server_args->port;
    out->bind_addr = server_args->bind_addr;
    out->listening = false;
    out->fd = server_fd;
    return SERVER_OK;
}

void http_close_server(HttpServer *server)
{
    if (server == NULL) {
        return;
    }

    /* fd >= 0 instead of fd != 0: fd 0 is a valid socket descriptor. */
    if (server->fd >= 0) {
        close(server->fd);
        server->fd = -1; /* protect against a double close */
    }

    for (size_t i = 0; i < server->routes.count; i++) {
        free(server->routes.routes[i].route_segments.segments);
        free((void *)server->routes.routes[i].path);
    }
    free(server->routes.routes);
    server->routes.routes = NULL;
    server->routes.count = server->routes.capacity = 0;

    for (size_t i = 0; i < server->middlewares.count; i++) {
        free((void *)server->middlewares.middlewares[i].path);
    }
    free(server->middlewares.middlewares);
    server->middlewares.middlewares = NULL;
    server->middlewares.count = server->middlewares.capacity = 0;

    free(server->encoders.encoders);
    server->encoders.encoders = NULL;
    server->encoders.count = server->encoders.capacity = 0;

    http_static_mounts_free(server);

    free(server->server_name);
    server->server_name = NULL;
}

void http_stop_server(HttpServer *server)
{
    if (server == NULL) {
        return;
    }

    server->listening = false;
    /* Wake up a blocking accept() (async-signal-safe: just a syscall
     * plus a flag). */
    if (server->fd >= 0) {
        shutdown(server->fd, SHUT_RDWR);
    }
}

void http_listen(HttpServer *server)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(server->fd >= 0);
    HTTP_ASSERT_MSG(server->listening == false,
                    "http_listen called twice — server already listening");
    HTTP_ASSERT(server->routes.routes != NULL);

    server->listening = true;
    printf("Server listening on port %d\n", server->port);

#ifndef NDEBUG
    printf("============= ALL ROUTES REGISTERED ==============\n");
    for (size_t i = 0; i < server->routes.count; i++) {
        printf("route: %s\n", server->routes.routes[i].path);

        if (strcmp(server->routes.routes[i].path, "/") == 0) {
            printf("segments: root path, no segments\n");
            continue;
        }
        printf("segments: ");
        for (size_t x = 0; x < server->routes.routes[i].route_segments.count;
             x++) {
            char *is_param_text = "false";
            if (server->routes.routes[i].route_segments.segments[x].is_param) {
                is_param_text = "true";
            }
            printf("text: \"%s\" ",
                   server->routes.routes[i].route_segments.segments[x].text);
            printf("is_param: %s", is_param_text);
            if (x < server->routes.routes[i].route_segments.count - 1) {
                printf(" | ");
            }
        }
        printf("\n");
    }
    printf("============= END ==============\n");
#endif

    while (server->listening) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd =
            accept(server->fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) {
                continue;
            }
            if (errno == EBADF || errno == EINVAL) {
                break; /* socket closed (http_stop_server) */
            }
            perror("accept");
            continue;
        }

        /* Slowloris protection: recv/send must not block the server
         * forever. */
        struct timeval tv = {.tv_sec = HTTP_CLIENT_TIMEOUT_SEC, .tv_usec = 0};
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        uint16_t client_port = ntohs(client_addr.sin_port);

        handle_client(server, client_fd, ip, client_port);
        close(client_fd);
    }
}

static HttpRouteAddResult http_add_route(HttpServer *server, const char *path,
                                         HttpHandler handler, HttpMethod method)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(path != NULL);
    HTTP_ASSERT_MSG(path[0] == '/',
                    "RFC 9110 §3.2: route path must start with '/'");
    HTTP_ASSERT(handler != NULL);
    HTTP_ASSERT_MSG(server->listening == false,
                    "cannot add routes while server is listening");

    if (server == NULL || path == NULL || handler == NULL) {
        return HTTP_ROUTE_ADD_ERROR;
    }
    if (path[0] != '/') {
        return HTTP_ROUTE_ADD_ERROR;
    }

    /* A route longer than HTTP_PATH_MAX can never match (the request
     * path is capped at HTTP_PATH_MAX) — reject immediately. */
    if (strlen(path) >= HTTP_PATH_MAX) {
        return HTTP_ROUTE_ADD_ERROR;
    }

    /* A '?' in a pattern can never match either: the query string is
     * stripped from the request path BEFORE routing. Fail fast. */
    if (strchr(path, '?') != NULL) {
        return HTTP_ROUTE_ADD_ERROR;
    }

    if (server->routes.count == server->routes.capacity) {
        size_t new_cap = server->routes.capacity * 2;
        HttpRoute *tmp =
            realloc(server->routes.routes, new_cap * sizeof(HttpRoute));
        if (tmp == NULL) {
            return HTTP_ROUTE_ADD_ERROR;
        }
        server->routes.routes = tmp;
        server->routes.capacity = new_cap;
    }

    for (size_t i = 0; i < server->routes.count; i++) {
        if (server->routes.routes[i].method == method &&
            strcmp(server->routes.routes[i].path, path) == 0) {
            return HTTP_ROUTE_ADD_CONFLICT;
        }
    }

    char *owned_path = strdup(path);
    if (owned_path == NULL) {
        return HTTP_ROUTE_ADD_ERROR;
    }

    /* Write directly into the array slot (no intermediate struct copy):
     * count is only incremented on success, so a failure leaves the
     * routes array untouched. */
    HttpRoute *slot = &server->routes.routes[server->routes.count];
    slot->path = owned_path;
    slot->handler = handler;
    slot->method = method;
    if (!parse_route_segments(owned_path, &slot->route_segments)) {
        free(owned_path); /* FIX: leaked the owned path on parse failure */
        return HTTP_ROUTE_ADD_ERROR;
    }

    /* Validate the params NOW (fail fast at registration) instead of
     * silently never matching at request time: more params than the
     * request can bind, or a name longer than the param key buffer. */
    size_t param_count = 0;
    for (size_t i = 0; i < slot->route_segments.count; i++) {
        const HttpRouteSegment *segment = &slot->route_segments.segments[i];
        if (!segment->is_param) {
            continue;
        }
        param_count++;
        if (param_count > HTTP_MAX_PARAMS ||
            strlen(segment->text) >= HTTP_PARAM_KEY_MAX) {
            free(slot->route_segments.segments);
            free(owned_path);
            return HTTP_ROUTE_ADD_ERROR;
        }
        /* Express parity: duplicate param names in one pattern are
         * ambiguous (http_req_param would silently return the first
         * binding) — reject at registration, not at request time. */
        for (size_t j = 0; j < i; j++) {
            const HttpRouteSegment *other = &slot->route_segments.segments[j];
            if (other->is_param && strcmp(other->text, segment->text) == 0) {
                free(slot->route_segments.segments);
                free(owned_path);
                return HTTP_ROUTE_ADD_ERROR;
            }
        }
    }

    server->routes.count++; /* slot is complete — commit */

    return HTTP_ROUTE_ADD_OK;
}

HttpRouteAddResult http_get(HttpServer *server, const char *path,
                            HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_GET);
}

HttpRouteAddResult http_post(HttpServer *server, const char *path,
                             HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_POST);
}

HttpRouteAddResult http_patch(HttpServer *server, const char *path,
                              HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_PATCH);
}

HttpRouteAddResult http_put(HttpServer *server, const char *path,
                            HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_PUT);
}

HttpRouteAddResult http_delete(HttpServer *server, const char *path,
                               HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_DELETE);
}

HttpRouteAddResult http_head(HttpServer *server, const char *path,
                             HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_HEAD);
}

HttpRouteAddResult http_connect(HttpServer *server, const char *path,
                                HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_CONNECT);
}

HttpRouteAddResult http_trace(HttpServer *server, const char *path,
                              HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_TRACE);
}

HttpRouteAddResult http_options(HttpServer *server, const char *path,
                                HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_OPTIONS);
}

HttpMiddlewareAddResult http_middleware(HttpServer *server, const char *path,
                                        HttpMiddlewareHandler handler)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(handler != NULL);
    HTTP_ASSERT_MSG(path == NULL || path[0] == '/',
                    "middleware path must start with '/' or be NULL");
    HTTP_ASSERT_MSG(server->listening == false,
                    "cannot add middleware while server is listening");

    if (server == NULL || handler == NULL) {
        return HTTP_MIDDLEWARE_ADD_ERROR;
    }
    if (path != NULL && path[0] != '/') {
        return HTTP_MIDDLEWARE_ADD_ERROR;
    }

    if (server->middlewares.count == server->middlewares.capacity) {
        size_t new_cap = server->middlewares.capacity == 0
                             ? 8
                             : server->middlewares.capacity * 2;
        HttpMiddleware *tmp = realloc(server->middlewares.middlewares,
                                      new_cap * sizeof(HttpMiddleware));
        if (tmp == NULL) {
            return HTTP_MIDDLEWARE_ADD_ERROR;
        }
        server->middlewares.middlewares = tmp;
        server->middlewares.capacity = new_cap;
    }

    char *owned_path = NULL;
    if (path != NULL) {
        owned_path = strdup(path);
        if (owned_path == NULL) {
            return HTTP_MIDDLEWARE_ADD_ERROR;
        }
    }

    server->middlewares.middlewares[server->middlewares.count++] =
        (HttpMiddleware){.path = owned_path, .handler = handler};

    return HTTP_MIDDLEWARE_ADD_OK;
}

HttpSetHeaderResult http_set_header(HttpHeaders *headers, const char *key,
                                    const char *value)
{
    if (headers == NULL || key == NULL || value == NULL) {
        return HTTP_SET_HEADER_ERROR;
    }

    /* apply_header validates the real guards (field name, CR/LF
     * injection) — also in release builds. */
    if (apply_header(headers, key, value) < 0) {
        return HTTP_SET_HEADER_ERROR;
    }
    return HTTP_SET_HEADER_OK;
}

/* ============================================================
 * Route Groups
 * ============================================================ */

/* false if the result does not fit into out (truncation). */
static bool join_path(char *out, size_t size, const char *prefix,
                      const char *path)
{
    /*
     * "/api" + "/"      -> "/api"   (root route in group)
     * "/api" + "/users" -> "/api/users"
     */
    int n;
    if (strcmp(path, "/") == 0) {
        n = snprintf(out, size, "%s", prefix);
    } else {
        n = snprintf(out, size, "%s%s", prefix, path);
    }
    return (n >= 0 && (size_t)n < size) != 0;
}

HttpGroup http_group(HttpServer *server, const char *prefix)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(prefix != NULL);
    HTTP_ASSERT_MSG(prefix[0] == '/', "group prefix must start with '/'");
    HTTP_ASSERT_MSG(server->listening == false,
                    "cannot create group while server is listening");

    return (HttpGroup){.server = server, .prefix = prefix};
}

#define DEFINE_GROUP_ROUTE(fn_name, method)                          \
    HttpRouteAddResult fn_name(HttpGroup *group, const char *path,   \
                               HttpHandler handler)                  \
    {                                                                \
        if (group == NULL || group->server == NULL || path == NULL)  \
            return HTTP_ROUTE_ADD_ERROR;                             \
        if (path[0] != '/')                                          \
            return HTTP_ROUTE_ADD_ERROR;                             \
        char full[1024];                                             \
        if (!join_path(full, sizeof(full), group->prefix, path))     \
            return HTTP_ROUTE_ADD_ERROR; /* Truncation */            \
        return http_add_route(group->server, full, handler, method); \
    }

DEFINE_GROUP_ROUTE(http_group_get, HTTP_METHOD_GET)
DEFINE_GROUP_ROUTE(http_group_post, HTTP_METHOD_POST)
DEFINE_GROUP_ROUTE(http_group_patch, HTTP_METHOD_PATCH)
DEFINE_GROUP_ROUTE(http_group_put, HTTP_METHOD_PUT)
DEFINE_GROUP_ROUTE(http_group_delete, HTTP_METHOD_DELETE)
DEFINE_GROUP_ROUTE(http_group_head, HTTP_METHOD_HEAD)
DEFINE_GROUP_ROUTE(http_group_connect, HTTP_METHOD_CONNECT)
DEFINE_GROUP_ROUTE(http_group_trace, HTTP_METHOD_TRACE)
DEFINE_GROUP_ROUTE(http_group_options, HTTP_METHOD_OPTIONS)

HttpMiddlewareAddResult http_group_middleware(HttpGroup *group,
                                              const char *path,
                                              HttpMiddlewareHandler handler)
{
    if (group == NULL || group->server == NULL || handler == NULL) {
        return HTTP_MIDDLEWARE_ADD_ERROR;
    }

    if (path == NULL) {
        /* Group-scoped middleware: group prefix as the path */
        return http_middleware(group->server, group->prefix, handler);
    }

    if (path[0] != '/') {
        return HTTP_MIDDLEWARE_ADD_ERROR;
    }
    char full[1024];
    if (!join_path(full, sizeof(full), group->prefix, path)) {
        return HTTP_MIDDLEWARE_ADD_ERROR;
    }
    return http_middleware(group->server, full, handler);
}

const char *http_req_param(const HttpRequest *req, const char *key)
{
    if (req == NULL || key == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < req->params.count; i++) {
        if (strcmp(key, req->params.params[i].key) == 0) {
            return req->params.params[i].value;
        }
    }
    return NULL;
}
