#include "c_http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
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
#include "c_http_ws.h"

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

bool http_parse_route_segments(const char *pattern, HttpRouteSegments *out)
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
/* Matches a parsed route pattern against request segments[offset..].
 * A ":name" segment binds any single non-empty request segment.
 * If params is non-NULL AND the route matches, the bound values are
 * copied into it (params->count is only set on a full match — a failed
 * route attempt must not leave dirty state behind for the next route).
 * offset supports mounted routers: the mount prefix consumed the
 * first segments already, the router's relative pattern matches the
 * rest. Returns true = match, false = no match. */
static bool segments_match_at(const HttpRouteSegments *pattern,
                              const HttpRouteSegments *request, size_t offset,
                              HttpParams *params)
{
    if (pattern == NULL || request == NULL || offset > request->count) {
        return false;
    }
    if (pattern->count != request->count - offset) {
        return false; /* different segment count -> clean "no match" */
    }

    size_t param_count = 0;
    for (size_t i = 0; i < pattern->count; i++) {
        const HttpRouteSegment *pat = &pattern->segments[i];
        const HttpRouteSegment *cur = &request->segments[offset + i];

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

bool http_segments_match(const HttpRouteSegments *pattern,
                         const HttpRouteSegments *request, HttpParams *params)
{
    return segments_match_at(pattern, request, 0, params);
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
/* Streams size bytes from file_fd (starting at byte offset `start`)
 * to the socket. Exactly size — never more (Content-Length is
 * promised) and never fewer (otherwise the client would wait for the
 * rest). */
static int send_fd(int file_fd, off_t start, off_t size, int client_fd)
{
    /* Range: position the fd first (whole-file sends start at 0). */
    if (start > 0) {
        if (lseek(file_fd, start, SEEK_SET) < 0) {
            return -1;
        }
    }

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
/* Streams size bytes from file_fd (starting at byte offset `start`)
 * to the socket. Portable fallback (macOS/BSD): read loop, exact
 * bound. */
static int send_fd(int file_fd, off_t start, off_t size, int client_fd)
{
    char buf[64 * 1024];

    /* Range: position the fd first (whole-file sends start at 0). */
    if (start > 0) {
        if (lseek(file_fd, start, SEEK_SET) < 0) {
            return -1;
        }
    }
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

    /* Single-range responses (RFC 9110 §14.2): validate the handler's
     * range against the ACTUAL file size and clamp the length — the
     * handler computed it microseconds ago against its own stat, but
     * a file that shrank in between must never send beyond EOF. A
     * start beyond the file (extreme shrink case) degenerates to a
     * 416 with an empty body. */
    bool streaming = file_fd >= 0;

    off_t send_offset = 0;
    off_t send_size = file_size;
    if (streaming && res->ranged) {
        if ((off_t)res->range_start >= file_size) {
            xclose_fd(file_fd);
            file_fd = -1;
            res->status = HTTP_STATUS_RANGE_NOT_SATISFIABLE;
            res->body_len = 0;
        } else {
            send_offset = (off_t)res->range_start;
            off_t available = file_size - send_offset;
            send_size = (off_t)res->range_len < available
                            ? (off_t)res->range_len
                            : available; /* clamp: never past EOF */
        }
    }

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
            cl = (size_t)send_size; /* ranged: exactly the slice length */
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
            (void)send_fd(file_fd, send_offset, send_size, client_fd);
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

/* ============================================================
 * Query string parsing
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

/* Percent-decodes the bounded range [in, in + in_len) into out.
 * Query-string semantics: '+' decodes to ' ' (application/
 * x-www-form-urlencoded in query strings, WHATWG URL). Returns
 * 0 = OK, -1 = does not fit / broken escape / %00 / control char. */
static int query_decode(const char *in, size_t in_len, char *out,
                        size_t out_size)
{
    if (in == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    size_t o = 0;
    for (size_t i = 0; i < in_len; i++) {
        if (o + 1 >= out_size) {
            return -1; /* truncation, not overflow */
        }
        if (in[i] == '%') {
            if (i + 2 >= in_len) {
                return -1; /* truncated escape (%z, trailing %) */
            }
            int hi = hex_val(in[i + 1]);
            int lo = hex_val(in[i + 2]);
            if (hi < 0 || lo < 0) {
                return -1; /* broken escape */
            }
            /* Decoded bytes are checked too: %00 (NUL injection) and
             * %01-%1f/%7f (control chars) are rejected, regardless of
             * whether they arrived raw or via an escape. */
            unsigned char decoded = (unsigned char)((hi * 16) + lo);
            if (decoded < 0x20 || decoded == 0x7f) {
                return -1;
            }
            out[o++] = (char)decoded;
            i += 2;
        } else if (in[i] == '+') {
            out[o++] = ' ';
        } else {
            unsigned char c = (unsigned char)in[i];
            if (c < 0x20 || c == 0x7f) {
                return -1; /* no control characters in decoded values */
            }
            out[o++] = in[i];
        }
    }
    out[o] = '\0';
    return 0;
}

/* Parses "a=1&b=two&flag" into out. Pairs that do not fit (too many,
 * key/value too long) or are malformed (%00, control chars) are
 * SKIPPED, never fatal: the query is advisory data, not routing input.
 * A key without '=' ("flag") gets the empty string as its value. */
static void parse_query(const char *query, HttpQuery *out)
{
    out->count = 0;
    if (query == NULL) {
        return;
    }

    const char *p = query;
    while (*p != '\0' && out->count < HTTP_MAX_QUERY) {
        const char *key_start = p;
        while (*p != '\0' && *p != '&' && *p != '=') {
            p++;
        }
        size_t key_len = (size_t)(p - key_start);

        const char *val_start = p;
        size_t val_len = 0;
        if (*p == '=') {
            val_start = ++p;
            while (*p != '\0' && *p != '&') {
                p++;
            }
            val_len = (size_t)(p - val_start);
        }

        /* An empty key ("=5", "&&") is not a pair; oversized or
         * malformed pairs are skipped whole — never truncated. */
        if (key_len > 0) {
            char key[HTTP_QUERY_KEY_MAX];
            char value[HTTP_QUERY_VALUE_MAX];
            if (query_decode(key_start, key_len, key, sizeof(key)) == 0 &&
                query_decode(val_start, val_len, value, sizeof(value)) == 0) {
                HttpQueryParam *param = &out->params[out->count++];
                strcpy(param->key, key);
                strcpy(param->value, value);
            }
        }

        if (*p == '&') {
            p++;
        }
    }
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

    /* Split off the query string: "/users?id=1" -> "/users". Parse it
     * BEFORE the '\0' — it is the request's query data, not routing
     * input, and the raw copy dies with the terminator. */
    char *query = strchr(target, '?');
    if (query != NULL) {
        parse_query(query + 1, &req->query);
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

/* Replaces the value of an existing header (frees the old one) or
 * appends when absent — used for the per-request Connection header,
 * which must never exist twice. */
static int replace_header(HttpHeaders *headers, const char *key,
                          const char *value)
{
    for (size_t i = 0; i < headers->count; i++) {
        if (strcasecmp(headers->items[i].key, key) == 0) {
            char *copy = strdup(value);
            if (copy == NULL) {
                return -1;
            }
            free(headers->items[i].value);
            headers->items[i].value = copy;
            return 0;
        }
    }
    return apply_header(headers, key, value);
}

/* True when a comma-separated header value contains the token
 * (case-insensitive, RFC 9110 §5.6.2). */
static bool header_contains_token(const char *value, const char *token)
{
    size_t tlen = strlen(token);
    const char *p = value;

    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        const char *start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }
        size_t len = (size_t)(p - start);
        while (len > 0 && (start[len - 1] == ' ' || start[len - 1] == '\t')) {
            len--;
        }
        if (len == tlen && strncasecmp(start, token, len) == 0) {
            return true;
        }
    }
    return false;
}

/* RFC 9112 §9.3: HTTP/1.1 persists by default, HTTP/1.0 closes by
 * default; the Connection header overrides either way ("close"
 * always wins). */
static bool request_wants_keep_alive(const HttpRequest *req)
{
    const char *conn = http_req_header(req, HTTP_HEADER_CONNECTION);
    if (conn != NULL) {
        if (header_contains_token(conn, "close")) {
            return false;
        }
        if (header_contains_token(conn, "keep-alive")) {
            return true;
        }
    }
    return strcmp(req->version, "HTTP/1.1") == 0;
}

static void apply_default_headers(HttpResponse *res, HttpServer *server,
                                  bool keep_alive)
{
    char time_buf[64];
    format_http_date(time_buf, sizeof(time_buf));
    apply_header(&res->headers, HTTP_HEADER_DATE, time_buf);
    apply_header(&res->headers, HTTP_HEADER_CONNECTION,
                 keep_alive ? "keep-alive" : "close");
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

/* ============================================================
 * Routers (Express-style express.Router + app.use)
 * ============================================================ */

struct HttpRouter {
    HttpRoutes routes; /* relative paths ("/dashboard") */
    bool mounted;      /* ownership passed to the server via http_use() */
};

typedef struct HttpRouterMount {
    HttpRouteSegments prefix_segments; /* parsed mount prefix */
    HttpRouter *router;                /* owned by the server (mount once) */
    struct HttpRouterMount *next; /* tail-appended: dispatch in mount order */
} HttpRouterMount;

/* Appends a method name to the Allow header buffer (bounds-checked). */
static void allow_append(char *allow, size_t size, size_t *used,
                         const char *name)
{
    size_t n = strlen(name);
    if (*used > 0) {
        if (*used + 2 + n >= size) {
            return;
        }
        allow[(*used)++] = ',';
        allow[(*used)++] = ' ';
    } else if (*used + n >= size) {
        return;
    }
    memcpy(allow + *used, name, n);
    *used += n;
    allow[*used] = '\0'; /* the buffer stays terminated at every step
                          * (the bounds above leave room for the NUL) */
}

/* True if the request segments START with the mount prefix segments —
 * a prefix match, NOT the exact-count semantics of segments_match_at
 * ("/admin" as a mount matches "/admin/dashboard"). Prefix segments
 * are always literals: http_use() rejects ":params" in prefixes. */
static bool prefix_segments_match(const HttpRouteSegments *prefix,
                                  const HttpRouteSegments *req_segments)
{
    if (prefix == NULL || req_segments == NULL ||
        prefix->count > req_segments->count) {
        return false;
    }
    for (size_t i = 0; i < prefix->count; i++) {
        if (strcmp(prefix->segments[i].text, req_segments->segments[i].text) !=
            0) {
            return false;
        }
    }
    return true; /* count 0 ("/" mount) matches everything */
}

/* Collects the methods of all routes (server routes AND mounted
 * routers) that match the request path into allow[*used] — shared by
 * the 405 Allow header and the OPTIONS auto-response. */
static void collect_allow(HttpServer *server,
                          const HttpRouteSegments *req_segments, char *allow,
                          size_t allow_size, size_t *used)
{
    for (size_t i = 0; i < server->routes.count; i++) {
        if (!http_segments_match(&server->routes.routes[i].route_segments,
                                 req_segments, NULL)) {
            continue;
        }
        allow_append(allow, allow_size, used,
                     method_name(server->routes.routes[i].method));
    }

    for (const HttpRouterMount *mount = server->router_mounts; mount != NULL;
         mount = mount->next) {
        if (!prefix_segments_match(&mount->prefix_segments, req_segments)) {
            continue;
        }
        size_t offset = mount->prefix_segments.count;
        for (size_t i = 0; i < mount->router->routes.count; i++) {
            const HttpRoute *route = &mount->router->routes.routes[i];
            if (!segments_match_at(&route->route_segments, req_segments, offset,
                                   NULL)) {
                continue;
            }
            allow_append(allow, allow_size, used, method_name(route->method));
        }
    }
}

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
        if (!http_segments_match(&route->route_segments, req_segments, NULL)) {
            continue;
        }
        path_exists = true;
        if (route->method == method) {
            http_segments_match(&route->route_segments, req_segments,
                                &req->params);
            handler = route->handler;
            break;
        }
    }

    /* RFC 9110 §9.3.2: HEAD falls back to GET when no explicit HEAD
     * route exists (the body is suppressed at send time). */
    if (handler == NULL && method == HTTP_METHOD_HEAD) {
        for (size_t i = 0; i < server->routes.count; i++) {
            const HttpRoute *route = &server->routes.routes[i];
            if (!http_segments_match(&route->route_segments, req_segments,
                                     NULL) ||
                route->method != HTTP_METHOD_GET) {
                continue;
            }
            http_segments_match(&route->route_segments, req_segments,
                                &req->params);
            handler = route->handler;
            break;
        }
    }

    /* Mounted routers next, in mount order: server routes win, routers
     * win over static mounts. Router paths are RELATIVE — the mount
     * prefix consumed the first segments of the request already. */
    if (handler == NULL) {
        const HttpRouterMount *mount = server->router_mounts;
        while (mount != NULL && handler == NULL) {
            if (!prefix_segments_match(&mount->prefix_segments, req_segments)) {
                mount = mount->next;
                continue;
            }
            size_t offset = mount->prefix_segments.count;
            const HttpRoutes *rr = &mount->router->routes;

            for (size_t i = 0; i < rr->count; i++) {
                const HttpRoute *route = &rr->routes[i];
                if (!segments_match_at(&route->route_segments, req_segments,
                                       offset, NULL)) {
                    continue;
                }
                path_exists = true;
                if (route->method == method) {
                    segments_match_at(&route->route_segments, req_segments,
                                      offset, &req->params);
                    handler = route->handler;
                    break;
                }
            }

            /* HEAD falls back to GET within this router too (RFC 9110
             * §9.3.2). */
            if (handler == NULL && method == HTTP_METHOD_HEAD) {
                for (size_t i = 0; i < rr->count; i++) {
                    const HttpRoute *route = &rr->routes[i];
                    if (route->method != HTTP_METHOD_GET ||
                        !segments_match_at(&route->route_segments, req_segments,
                                           offset, NULL)) {
                        continue;
                    }
                    segments_match_at(&route->route_segments, req_segments,
                                      offset, &req->params);
                    handler = route->handler;
                    break;
                }
            }

            mount = mount->next;
        }
    }

    /* RFC 9110 §9.3.7: OPTIONS without an explicit OPTIONS route gets
     * an auto-response (204 + Allow) — Express parity. Only when at
     * least one route (server or router) matches the path; otherwise
     * the request falls through to the mounts / 404. */
    if (handler == NULL && method == HTTP_METHOD_OPTIONS) {
        char allow[128];
        size_t used = 0;
        collect_allow(server, req_segments, allow, sizeof(allow), &used);
        if (used > 0) {
            allow[used] = '\0';
            http_set_header(&res->headers, HTTP_HEADER_ALLOW, allow);
            res->status = HTTP_STATUS_NO_CONTENT; /* 204, no body */
            return HANDLER_OK;
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

/* RFC 9110 §15.4.6: a 405 response includes an Allow header. */
static void set_allow_header(HttpServer *server,
                             const HttpRouteSegments *req_segments,
                             HttpResponse *res)
{
    char allow[128];
    size_t used = 0;

    collect_allow(server, req_segments, allow, sizeof(allow), &used);

    allow[used] = '\0';
    if (used > 0) {
        http_set_header(&res->headers, HTTP_HEADER_ALLOW, allow);
    }
}

static void set_protocol_error(HttpResponse *res, int status)
{
    res->status = status;
    res->error = true;
}

static void parse_multipart(const HttpRequest *req, HttpMultiparts *out);

static void handle_client(HttpServer *server, int client_fd, const char *ip,
                          uint16_t client_port)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(client_fd >= 0);
    HTTP_ASSERT(ip != NULL);
    HTTP_ASSERT(server->routes.routes != NULL);

    for (;;) { /* keep-alive: one iteration per request on this connection */
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
        /* inet_ntop already produced a NUL-terminated string within
         * sizeof(req.ip) — but snprintf also guards a shorter buffer. */
        snprintf(req.ip, sizeof(req.ip), "%s", ip);
        req.client_port = client_port;
        /* Connection: close first — corrected after parsing decides the
         * persistence (protocol errors must always close). */
        apply_default_headers(&res, server, false);
        bool persist = false;
        /* Bytes read past the end of the body (e.g. early websocket
         * frames sent with the handshake) — handed to the WS layer
         * instead of being dropped with the request buffer. */
        const char *ws_leftover = NULL;
        size_t ws_leftover_len = 0;

        /* Every error path jumps to send: a response is ALWAYS sent (no
         * silent connection close) and cleanup happens ONLY at the end. */
        if (!headers_complete) {
            set_protocol_error(&res,
                               HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE);
            goto send;
        }

        {
            /* Get the body start position BEFORE terminating (empty header
             * block: eol and marker coincide). */
            char *sep = strstr(buf, "\r\n\r\n");
            if (sep == NULL) { /* cannot happen with headers_complete */
                set_protocol_error(&res, HTTP_STATUS_BAD_REQUEST);
                goto send;
            }
            size_t header_end = (size_t)(sep - buf) + 4;

            /* Isolate the request line (terminate at the first CRLF), then
             * parse; parse_headers starts right after it. */
            char *eol = strstr(buf, "\r\n");
            if (eol == NULL) {
                set_protocol_error(&res, HTTP_STATUS_BAD_REQUEST);
                goto send;
            }
            *eol = '\0';

            int line_status = parse_request_line(buf, &req);
            if (line_status != 0) {
                set_protocol_error(&res, line_status);
                goto send;
            }

            int hdr_status = parse_headers(eol + 2, buf + total, &req);
            if (hdr_status != 0) {
                set_protocol_error(&res, hdr_status);
                goto send;
            }

            int body_status =
                read_body(client_fd, buf, (size_t)total, header_end, &req);
            if (body_status != 0) {
                set_protocol_error(&res, body_status);
                goto send;
            }

            /* Leftover bytes: with a body they cannot exist (read_body
             * rejects more bytes than Content-Length), without one they
             * can only be the start of a websocket stream (pipelined
             * HTTP requests are a 400 per the keep-alive rules — the
             * smuggling guard in read_body covers that). */
            size_t ws_used = header_end + req.body_len;
            if ((size_t)total > ws_used) {
                ws_leftover = buf + ws_used;
                ws_leftover_len = (size_t)total - ws_used;
            }
        }

        /* Eagerly parse urlencoded bodies — the same pair semantics as
         * the query parser (malformed pairs are skipped, never fatal). */
        if (http_req_body_type(&req) == HTTP_BODY_URLENCODED) {
            parse_query(req.body, &req.form);
        }

        /* Eagerly parse multipart/form-data (RFC 7578): parts beyond
         * the limit and malformed parts are skipped, never fatal. */
        /* False positive: goto-based cleanup (see the keep-alive note
         * below — LSan-clean over the full test suite). */
        /* NOLINTNEXTLINE(clang-analyzer-unix.Malloc) */
        if (http_req_body_type(&req) == HTTP_BODY_MULTIPART) {
            parse_multipart(&req, &req.multiparts);
        }

        /* Keep-alive negotiation: RFC 9112 §9.3. replace_header keeps a
         * single Connection header (apply_header would append a second). */
        /* False positive: the analyzer cannot track the goto-based
         * cleanup below; every path frees req.body at the send: label
         * (LSan-clean over the full suite, incl. keep-alive bodies). */
        /* NOLINTNEXTLINE(clang-analyzer-unix.Malloc) */
        if (server->keep_alive && request_wants_keep_alive(&req)) {
            persist = true;
        }
        replace_header(&res.headers, HTTP_HEADER_CONNECTION,
                       persist ? "keep-alive" : "close");

        /* RFC 9112 §3.2: Host header mandatory in HTTP/1.1 (debug check) */
#ifndef NDEBUG
        if (strcmp(req.version, "HTTP/1.1") == 0) {
            bool has_host = false;
            for (size_t i = 0; i < req.headers.count; i++) {
                if (strcasecmp(req.headers.items[i].key, HTTP_HEADER_HOST) ==
                    0) {
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
        bool req_segments_ok =
            http_parse_route_segments(req.path, &req_segments);

        if (apply_middleware(server, &req, &res)) {
            /* Websocket upgrades (RFC 6455): AFTER middleware (auth
             * guards apply), BEFORE normal routing — a plain GET on
             * the same path still hits regular routes. The call runs
             * the WS handler for the connection's whole lifetime and
             * returns only when the session ended: the connection is
             * then done (no send_res, no keep-alive). */
            HttpWsDispatchResult ws_result =
                http_ws_dispatch(server, &req, &req_segments, client_fd,
                                 ws_leftover, ws_leftover_len);
            if (ws_result != WS_DISPATCH_NOT_WS) {
                free(req.body);
                http_headers_free(&req.headers);
                http_headers_free(&res.headers);
                free(req_segments.segments);
                return;
            }

            HandlerResult result =
                req_segments_ok
                    ? execute_handler(server, &req, &res, &req_segments)
                    : HANDLER_NOT_FOUND;
            switch (result) {
            case HANDLER_OK:
                break;
            case HANDLER_METHOD_NOT_ALLOWED:
                /* Framework errors: the central error handler (if set)
                 * formats them at send time. Allow stays set. */
                set_protocol_error(&res, HTTP_STATUS_METHOD_NOT_ALLOWED);
                set_allow_header(server, &req_segments, &res);
                break;
            case HANDLER_NOT_FOUND:
                set_protocol_error(&res, HTTP_STATUS_NOT_FOUND);
                break;
            case HANDLER_NOT_IMPLEMENTED:
                set_protocol_error(&res, HTTP_STATUS_NOT_IMPLEMENTED);
                break;
            }
        }

        free(req_segments.segments); /* fixed-array params need no cleanup */

    send:
        if (res.status == 0) {
            res.status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        }

        /* RFC 9110 §15: validate the status before sending */
        HTTP_ASSERT_MSG(
            is_valid_status_code(res.status),
            "RFC 9110 §15: status code must be 100-599 before send");
        HTTP_ASSERT_MSG(res.body_len <= sizeof(res.body),
                        "body_len exceeds body buffer — buffer overflow");

        /* Central error handling: ONE place formats all framework errors
         * (http_error() calls, 404/405/501, protocol parse errors). Runs
         * before http_encode_body, so an error body still gets compressed. */
        if (res.error && server->error_handler != NULL) {
            server->error_handler(&req, &res, res.status,
                                  res.error_message[0] != '\0'
                                      ? res.error_message
                                      : status_text(res.status));
        }

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

        if (!persist) {
            return; /* Connection: close honored — or an error closed it */
        }
    } /* keep-alive: read the next request on the same connection */
}

/* ============================================================
 * Worker threads (thread-per-connection, bounded)
 * ============================================================
 *
 * Each connection is handled by its own detached worker (up to
 * ServerArgs.worker_threads). handle_client() is fully self-contained
 * per connection (request/response on the stack), so the workers need
 * NO locks around request state — only the active counter is shared.
 * When the limit is reached, the accept loop handles the connection
 * itself (graceful degradation, bounded by the socket timeouts). */

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t idle; /* signaled when the active count drops to 0 */
    size_t active;       /* currently running workers */
    size_t limit;        /* max concurrent workers */
} WorkerState;

typedef struct {
    HttpServer *server;
    int client_fd;
    char ip[46]; /* copied: the accept loop's buffer dies */
    uint16_t client_port;
} WorkerArgs;

static void *worker_main(void *arg)
{
    WorkerArgs *args = arg;
    handle_client(args->server, args->client_fd, args->ip, args->client_port);
    xclose_fd(args->client_fd);

    /* Drain protocol for http_close_server(): count down + signal. */
    WorkerState *ws = args->server->thread_state;
    if (ws != NULL) {
        pthread_mutex_lock(&ws->lock);
        if (ws->active > 0) {
            ws->active--;
        }
        if (ws->active == 0) {
            pthread_cond_broadcast(&ws->idle);
        }
        pthread_mutex_unlock(&ws->lock);
    }

    free(args);
    return NULL;
}

/* Returns true when a worker took over the connection; false when
 * the limit is reached or on failure — the caller then handles the
 * connection itself (never rejects: degrade, don't drop). */
static bool spawn_worker(HttpServer *server, int client_fd, const char *ip,
                         uint16_t client_port)
{
    WorkerState *ws = server->thread_state;
    if (ws == NULL) {
        return false; /* iterative mode */
    }

    WorkerArgs *args = malloc(sizeof(*args));
    if (args == NULL) {
        return false; /* OOM: degrade to inline handling */
    }
    args->server = server;
    args->client_fd = client_fd;
    snprintf(args->ip, sizeof(args->ip), "%s", ip);
    args->client_port = client_port;

    pthread_mutex_lock(&ws->lock);
    if (ws->active >= ws->limit) {
        pthread_mutex_unlock(&ws->lock);
        free(args);
        return false; /* at capacity: accept loop handles it inline */
    }
    ws->active++;
    pthread_mutex_unlock(&ws->lock);

    pthread_t thread;
    if (pthread_create(&thread, NULL, worker_main, args) != 0) {
        pthread_mutex_lock(&ws->lock);
        ws->active--;
        if (ws->active == 0) {
            pthread_cond_broadcast(&ws->idle);
        }
        pthread_mutex_unlock(&ws->lock);
        free(args);
        return false;
    }

    pthread_detach(thread); /* freed via worker_main; close counts down */
    return true;
}

/* Waits for all workers to finish (http_close_server): the server
 * struct must stay alive until every connection is drained — workers
 * reference it. Bounded by the socket timeouts (a stuck client can
 * hold a worker for at most recv+send timeouts). */
static void worker_state_free(HttpServer *server)
{
    WorkerState *ws = server->thread_state;
    if (ws == NULL) {
        return;
    }
    pthread_mutex_lock(&ws->lock);
    while (ws->active > 0) {
        pthread_cond_wait(&ws->idle, &ws->lock);
    }
    pthread_mutex_unlock(&ws->lock);
    pthread_mutex_destroy(&ws->lock);
    pthread_cond_destroy(&ws->idle);
    free(ws);
    server->thread_state = NULL;
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

    out->keep_alive = server_args->keep_alive;
    out->thread_state = NULL;
    if (server_args->worker_threads > 0) {
        WorkerState *ws = calloc(1, sizeof(*ws));
        if (ws == NULL) {
            http_close_server(out); /* deterministic: frees what exists */
            return SERVER_ERROR;
        }
        if (pthread_mutex_init(&ws->lock, NULL) != 0 ||
            pthread_cond_init(&ws->idle, NULL) != 0) {
            pthread_mutex_destroy(&ws->lock); /* half-initialized: safe */
            pthread_cond_destroy(&ws->idle);
            free(ws);
            http_close_server(out);
            return SERVER_ERROR;
        }
        ws->limit = server_args->worker_threads;
        out->thread_state = ws;
    }

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

    /* Drain the workers BEFORE freeing anything they reference: every
     * worker holds a live connection with this server struct. Bounded
     * by the socket timeouts (HTTP_CLIENT_TIMEOUT_SEC per phase). */
    worker_state_free(server);

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
    http_ws_routes_free(server);

    /* Mounted routers: ownership passed to the server on http_use(). */
    HttpRouterMount *mount = server->router_mounts;
    while (mount != NULL) {
        HttpRouterMount *next = mount->next;
        free(mount->prefix_segments.segments);
        for (size_t i = 0; i < mount->router->routes.count; i++) {
            free((void *)mount->router->routes.routes[i].path);
            free(mount->router->routes.routes[i].route_segments.segments);
        }
        free(mount->router->routes.routes);
        free(mount->router);
        free(mount);
        mount = next;
    }
    server->router_mounts = NULL;

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

        /* Thread-per-connection when enabled; the accept loop handles
         * the connection itself in the iterative default and when the
         * worker limit is reached (degrade, never drop). */
        if (spawn_worker(server, client_fd, ip, client_port)) {
            continue; /* the worker owns client_fd now */
        }
        handle_client(server, client_fd, ip, client_port);
        close(client_fd);
    }
}

/* Shared route-registration core: server routes AND router routes go
 * through here (same validation, same ownership rules). */
static HttpRouteAddResult add_route_to(HttpRoutes *routes, const char *path,
                                       HttpHandler handler, HttpMethod method)
{
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

    if (routes->count == routes->capacity) {
        size_t new_cap = routes->capacity == 0 ? 8 : routes->capacity * 2;
        HttpRoute *tmp = realloc(routes->routes, new_cap * sizeof(HttpRoute));
        if (tmp == NULL) {
            return HTTP_ROUTE_ADD_ERROR;
        }
        routes->routes = tmp;
        routes->capacity = new_cap;
    }

    for (size_t i = 0; i < routes->count; i++) {
        if (routes->routes[i].method == method &&
            strcmp(routes->routes[i].path, path) == 0) {
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
    HttpRoute *slot = &routes->routes[routes->count];
    slot->path = owned_path;
    slot->handler = handler;
    slot->method = method;
    if (!http_parse_route_segments(owned_path, &slot->route_segments)) {
        free(owned_path);
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

    routes->count++; /* slot is complete — commit */

    return HTTP_ROUTE_ADD_OK;
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

    return add_route_to(&server->routes, path, handler, method);
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

/* ============================================================
 * Router implementation (types live above execute_handler)
 * ============================================================ */

HttpRouter *http_router_create(void)
{
    return calloc(1, sizeof(HttpRouter));
}

void http_router_free(HttpRouter *router)
{
    if (router == NULL) {
        return;
    }
    HTTP_ASSERT_MSG(router->mounted == false,
                    "router is mounted: its ownership passed to the server");
    if (router->mounted) {
        return; /* release-build guard: never free server-owned memory */
    }
    for (size_t i = 0; i < router->routes.count; i++) {
        free((void *)router->routes.routes[i].path);
        free(router->routes.routes[i].route_segments.segments);
    }
    free(router->routes.routes);
    free(router);
}

#define DEFINE_ROUTER_ROUTE(fn_name, method)                         \
    HttpRouteAddResult fn_name(HttpRouter *router, const char *path, \
                               HttpHandler handler)                  \
    {                                                                \
        HTTP_ASSERT(router != NULL);                                 \
        HTTP_ASSERT_MSG(path != NULL && path[0] == '/',              \
                        "router route path must start with '/'");    \
        HTTP_ASSERT(handler != NULL);                                \
        if (router == NULL || path == NULL || handler == NULL) {     \
            return HTTP_ROUTE_ADD_ERROR;                             \
        }                                                            \
        if (path[0] != '/') {                                        \
            return HTTP_ROUTE_ADD_ERROR;                             \
        }                                                            \
        return add_route_to(&router->routes, path, handler, method); \
    }

DEFINE_ROUTER_ROUTE(http_router_get, HTTP_METHOD_GET)
DEFINE_ROUTER_ROUTE(http_router_post, HTTP_METHOD_POST)
DEFINE_ROUTER_ROUTE(http_router_put, HTTP_METHOD_PUT)
DEFINE_ROUTER_ROUTE(http_router_patch, HTTP_METHOD_PATCH)
DEFINE_ROUTER_ROUTE(http_router_delete, HTTP_METHOD_DELETE)
DEFINE_ROUTER_ROUTE(http_router_head, HTTP_METHOD_HEAD)
DEFINE_ROUTER_ROUTE(http_router_options, HTTP_METHOD_OPTIONS)
DEFINE_ROUTER_ROUTE(http_router_trace, HTTP_METHOD_TRACE)
DEFINE_ROUTER_ROUTE(http_router_connect, HTTP_METHOD_CONNECT)

HttpUseResult http_use(HttpServer *server, const char *prefix,
                       HttpRouter *router)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(prefix != NULL);
    HTTP_ASSERT_MSG(prefix[0] == '/',
                    "router mount prefix must start with '/'");
    HTTP_ASSERT(router != NULL);
    HTTP_ASSERT_MSG(server->listening == false,
                    "cannot mount a router while listening");
    HTTP_ASSERT_MSG(router->mounted == false,
                    "router is already mounted (ownership passes to the "
                    "server on http_use)");

    if (server == NULL || prefix == NULL || router == NULL) {
        return HTTP_USE_ERROR;
    }
    if (prefix[0] != '/' || router->mounted) {
        return HTTP_USE_ERROR;
    }
    /* A prefix longer than HTTP_PATH_MAX can never match. */
    if (strlen(prefix) >= HTTP_PATH_MAX) {
        return HTTP_USE_ERROR;
    }
    /* A '?' can never match: the query string is stripped before
     * routing (same rule as for route patterns). */
    if (strchr(prefix, '?') != NULL) {
        return HTTP_USE_ERROR;
    }

    HttpRouterMount *mount = calloc(1, sizeof(*mount));
    if (mount == NULL) {
        return HTTP_USE_ERROR;
    }
    if (!http_parse_route_segments(prefix, &mount->prefix_segments)) {
        free(mount);
        return HTTP_USE_ERROR;
    }
    /* The mount prefix is a fixed location: ":params" in it are
     * rejected (they would never bind anything meaningful). */
    for (size_t i = 0; i < mount->prefix_segments.count; i++) {
        if (mount->prefix_segments.segments[i].is_param) {
            free(mount->prefix_segments.segments);
            free(mount);
            return HTTP_USE_ERROR;
        }
    }

    mount->router = router;
    router->mounted = true;

    /* Append at the TAIL: routers dispatch in mount order (Express
     * semantics — first mounted is checked first). */
    HttpRouterMount **tail = (HttpRouterMount **)&server->router_mounts;
    while (*tail != NULL) {
        tail = &(*tail)->next;
    }
    *tail = mount;
    return HTTP_USE_OK;
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

const char *http_req_header(const HttpRequest *req, const char *key)
{
    if (req == NULL || key == NULL) {
        return NULL;
    }
    /* RFC 9110 §5.1: field names are case-insensitive — compare with
     * strcasecmp, return the FIRST occurrence. */
    for (size_t i = 0; i < req->headers.count; i++) {
        if (strcasecmp(req->headers.items[i].key, key) == 0) {
            return req->headers.items[i].value;
        }
    }
    return NULL;
}

const char *http_req_query(const HttpRequest *req, const char *key)
{
    if (req == NULL || key == NULL) {
        return NULL;
    }
    /* First occurrence wins — consistent with http_req_header(). */
    for (size_t i = 0; i < req->query.count; i++) {
        if (strcmp(key, req->query.params[i].key) == 0) {
            return req->query.params[i].value;
        }
    }
    return NULL;
}

HttpSetLocalResult http_set_local(HttpResponse *res, const char *key,
                                  const char *value)
{
    if (res == NULL || key == NULL || value == NULL || key[0] == '\0') {
        return HTTP_SET_LOCAL_ERROR;
    }
    if (strlen(key) >= HTTP_LOCAL_KEY_MAX ||
        strlen(value) >= HTTP_LOCAL_VALUE_MAX) {
        return HTTP_SET_LOCAL_ERROR;
    }

    /* Locals carry the latest state: setting an existing key
     * overwrites (e.g. a second middleware refines the first). */
    for (size_t i = 0; i < res->locals.count; i++) {
        if (strcmp(res->locals.locals[i].key, key) == 0) {
            snprintf(res->locals.locals[i].value,
                     sizeof(res->locals.locals[i].value), "%s", value);
            return HTTP_SET_LOCAL_OK;
        }
    }

    if (res->locals.count >= HTTP_MAX_LOCALS) {
        return HTTP_SET_LOCAL_ERROR; /* fixed slots are full */
    }
    HttpLocal *local = &res->locals.locals[res->locals.count++];
    snprintf(local->key, sizeof(local->key), "%s", key);
    snprintf(local->value, sizeof(local->value), "%s", value);
    return HTTP_SET_LOCAL_OK;
}

const char *http_res_local(const HttpResponse *res, const char *key)
{
    if (res == NULL || key == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < res->locals.count; i++) {
        if (strcmp(key, res->locals.locals[i].key) == 0) {
            return res->locals.locals[i].value;
        }
    }
    return NULL;
}

/* ============================================================
 * Response helpers
 * ============================================================ */

int http_res_json(HttpResponse *res, int status, const char *body)
{
    if (res == NULL || body == NULL || !is_valid_status_code(status)) {
        return -1;
    }
    size_t len = strlen(body);
    if (len >= sizeof(res->body)) {
        return -1; /* caller must chunk/reduce — never truncate JSON */
    }
    if (http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE,
                        "application/json") != HTTP_SET_HEADER_OK) {
        return -1;
    }
    memcpy(res->body, body, len);
    res->body[len] = '\0';
    res->body_len = len;
    res->status = status;
    return 0;
}

int http_res_redirect(HttpResponse *res, int status, const char *location)
{
    if (res == NULL || location == NULL) {
        return -1;
    }
    if (status < 300 || status > 399) {
        return -1; /* redirects are 3xx only */
    }
    /* http_set_header rejects CR/LF injection in the location. */
    if (http_set_header(&res->headers, HTTP_HEADER_LOCATION, location) !=
        HTTP_SET_HEADER_OK) {
        return -1;
    }
    res->status = status;
    res->body_len = 0; /* empty body: the Location carries the semantics */
    return 0;
}

int http_res_cookie(HttpResponse *res, const char *name, const char *value,
                    unsigned max_age, bool http_only)
{
    if (res == NULL || name == NULL || value == NULL || name[0] == '\0') {
        return -1;
    }
    /* cookie-name is a token (RFC 6265 §4.1.1): separators rejected. */
    if (strpbrk(name, ";= \t") != NULL) {
        return -1;
    }
    /* A ';' in the value would start a forged attribute — reject
     * instead of splitting (CR/LF is caught by http_set_header). */
    if (strchr(value, ';') != NULL) {
        return -1;
    }

    char cookie[512];
    size_t used =
        (size_t)snprintf(cookie, sizeof(cookie), "%s=%s; Path=/", name, value);
    if (used >= sizeof(cookie)) {
        return -1;
    }
    if (max_age > 0) {
        int n = snprintf(cookie + used, sizeof(cookie) - used, "; Max-Age=%u",
                         max_age);
        if (n < 0 || used + (size_t)n >= sizeof(cookie)) {
            return -1;
        }
        used += (size_t)n;
    }
    if (http_only) {
        int n = snprintf(cookie + used, sizeof(cookie) - used, "; HttpOnly");
        if (n < 0 || used + (size_t)n >= sizeof(cookie)) {
            return -1;
        }
        used += (size_t)n;
    }
    (void)used;

    /* Multiple Set-Cookie headers are legal — http_set_header appends. */
    return http_set_header(&res->headers, HTTP_HEADER_SET_COOKIE, cookie) ==
                   HTTP_SET_HEADER_OK
               ? 0
               : -1;
}

/* ============================================================
 * Central error handling
 * ============================================================ */

void http_error(HttpResponse *res, int status, const char *message)
{
    if (res == NULL) {
        return;
    }
    /* Only 4xx/5xx are errors: anything else is a caller bug and gets
     * the generic 500 instead of silently sending a success status. */
    if (!is_valid_status_code(status) || status < 400) {
        status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }
    res->status = status;
    res->error = true;
    snprintf(res->error_message, sizeof(res->error_message), "%s",
             message != NULL ? message : status_text(status));
}

/* ============================================================
 * Body parsers
 * ============================================================ */

const char *http_req_form(const HttpRequest *req, const char *key)
{
    if (req == NULL || key == NULL) {
        return NULL;
    }
    /* First occurrence wins — consistent with http_req_query(). */
    for (size_t i = 0; i < req->form.count; i++) {
        if (strcmp(key, req->form.params[i].key) == 0) {
            return req->form.params[i].value;
        }
    }
    return NULL;
}

HttpBodyType http_req_body_type(const HttpRequest *req)
{
    if (req == NULL || req->body == NULL || req->body_len == 0) {
        return HTTP_BODY_NONE;
    }
    const char *ct = http_req_header(req, HTTP_HEADER_CONTENT_TYPE);
    if (ct == NULL) {
        return HTTP_BODY_OTHER;
    }
    /* Prefix compare: suffixes like "; charset=utf-8" are tolerated. */
    if (strncasecmp(ct, "application/x-www-form-urlencoded", 33) == 0) {
        return HTTP_BODY_URLENCODED;
    }
    if (strncasecmp(ct, "application/json", 16) == 0) {
        return HTTP_BODY_JSON;
    }
    if (strncasecmp(ct, "multipart/form-data", 19) == 0) {
        return HTTP_BODY_MULTIPART;
    }
    return HTTP_BODY_OTHER;
}

/* --- minimal JSON scanner (top-level strings only) --- */

static const char *json_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    return p;
}

static int json_hex4(const char *p)
{
    int v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hex_val(p[i]);
        if (h < 0) {
            return -1;
        }
        v = (v * 16) + h;
    }
    return v;
}

/* UTF-8 encodes a code point into out. Returns the bytes written
 * (1-3, \uXXXX caps at 0xFFFF) or -1 on lone surrogates / no room.
 * A single '\0' byte is NEVER written (JSON strings can carry a
 * decoded 0x0000 — rejected here to keep values C-safe). */
static int json_utf8_encode(unsigned cp, char *out, size_t out_size)
{
    if (cp >= 0xD800 && cp <= 0xDFFF) {
        return -1; /* lone surrogate: no pairing support */
    }
    if (cp == 0) {
        return -1; /* keep values NUL-free (C string semantics) */
    }
    if (cp < 0x80) {
        if (out_size < 1) {
            return -1;
        }
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        if (out_size < 2) {
            return -1;
        }
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (out_size < 3) {
        return -1;
    }
    out[0] = (char)(0xE0 | (cp >> 12));
    out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[2] = (char)(0x80 | (cp & 0x3F));
    return 3;
}

/* Decodes the JSON string at the opening quote into out.
 * Returns the decoded length (0 = empty string) or -1 on malformed
 * input / out too small (NEVER truncates). end (when non-NULL) ends
 * up past the closing quote. */
static int json_decode_string(const char *p, char *out, size_t out_size,
                              const char **end)
{
    if (out == NULL || out_size == 0) {
        return -1;
    }

    p++; /* past the opening quote */
    size_t o = 0;
    while (*p != '"') {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20) {
            return -1; /* raw control chars are illegal in JSON strings */
        }

        if (c != '\\') {
            /* literal byte or raw UTF-8 (JSON allows it) — passthrough */
            if (o + 1 >= out_size) {
                return -1; /* no room for this byte + the NUL */
            }
            out[o++] = (char)c;
            p++;
            continue;
        }

        /* escape sequence */
        p++;
        char simple = 0;
        switch (*p) {
        case '"':
            simple = '"';
            break;
        case '\\':
            simple = '\\';
            break;
        case '/':
            simple = '/';
            break;
        case 'b':
            simple = '\b';
            break;
        case 'f':
            simple = '\f';
            break;
        case 'n':
            simple = '\n';
            break;
        case 'r':
            simple = '\r';
            break;
        case 't':
            simple = '\t';
            break;
        case 'u': {
            int cp = json_hex4(p + 1);
            if (cp < 0) {
                return -1;
            }
            int n = json_utf8_encode((unsigned)cp, out + o, out_size - o);
            if (n < 0) {
                return -1;
            }
            o += (size_t)n;
            p += 4;
            break;
        }
        default:
            return -1; /* unknown escape */
        }

        if (simple != 0) {
            if (o + 1 >= out_size) {
                return -1;
            }
            out[o++] = simple;
        }
        p++;
    }

    out[o] = '\0';
    if (end != NULL) {
        *end = p + 1; /* past the closing quote */
    }
    return (int)o;
}

/* Skips one JSON value (string/number/true/false/null/object/array)
 * starting at p. Returns the position after it, or NULL when
 * malformed. Depth-bounded: pathological nesting hits the depth cap
 * instead of exhausting the C stack. */
/* Deliberate recursive descent, depth-bounded (max 32): a pathological
 * 50-MB body hits the depth cap long before the C stack is at risk. */
/* NOLINTBEGIN(misc-no-recursion) */
static const char *json_skip_value(const char *p, int depth)
{
    if (depth < 0) {
        return NULL;
    }

    switch (*p) {
    case '"':
        p++;
        while (*p != '"') {
            if (*p == '\0' || *p == '\n' || *p == '\r') {
                return NULL;
            }
            if (*p == '\\') {
                p++;
                if (*p == '\0') {
                    return NULL;
                }
            }
            p++;
        }
        return p + 1;

    case '{':
        p = json_skip_ws(p + 1);
        if (*p == '}') {
            return p + 1;
        }
        for (;;) {
            if (*p != '"') {
                return NULL; /* member keys are strings */
            }
            p = json_skip_value(p, depth - 1);
            if (p == NULL) {
                return NULL;
            }
            p = json_skip_ws(p);
            if (*p != ':') {
                return NULL;
            }
            p = json_skip_value(json_skip_ws(p + 1), depth - 1);
            if (p == NULL) {
                return NULL;
            }
            p = json_skip_ws(p);
            if (*p == ',') {
                p = json_skip_ws(p + 1);
                continue;
            }
            if (*p == '}') {
                return p + 1;
            }
            return NULL;
        }

    case '[':
        p = json_skip_ws(p + 1);
        if (*p == ']') {
            return p + 1;
        }
        for (;;) {
            p = json_skip_value(p, depth - 1);
            if (p == NULL) {
                return NULL;
            }
            p = json_skip_ws(p);
            if (*p == ',') {
                p = json_skip_ws(p + 1);
                continue;
            }
            if (*p == ']') {
                return p + 1;
            }
            return NULL;
        }

    default:
        if (strncmp(p, "true", 4) == 0) {
            return p + 4;
        }
        if (strncmp(p, "false", 5) == 0) {
            return p + 5;
        }
        if (strncmp(p, "null", 4) == 0) {
            return p + 4;
        }
        /* number (loose validation: digits . e E + -) */
        if (*p == '-') {
            p++;
        }
        if (!(*p >= '0' && *p <= '9')) {
            return NULL;
        }
        while ((*p >= '0' && *p <= '9') || *p == '.' || *p == 'e' ||
               *p == 'E' || *p == '+' || *p == '-') {
            p++;
        }
        return p;
    }
}

/* NOLINTEND(misc-no-recursion) */
int http_req_json_string(const HttpRequest *req, const char *key, char *out,
                         size_t out_size)
{
    if (req == NULL || key == NULL || out == NULL || out_size == 0 ||
        req->body == NULL || req->body_len == 0) {
        return -1;
    }

    const char *p = json_skip_ws(req->body);
    if (*p != '{') {
        return -1; /* only top-level objects are supported */
    }
    p = json_skip_ws(p + 1);
    if (*p == '}') {
        return -1; /* empty object: the key is absent */
    }

    for (;;) {
        if (*p != '"') {
            return -1; /* malformed member key */
        }

        /* Raw key compare (no escapes in keys — they are identifiers).
         * kend stops at the closing quote, '\' aborts (unsupported). */
        const char *kend = p + 1;
        while (*kend != '"' && *kend != '\\' && *kend != '\0') {
            kend++;
        }
        if (*kend != '"') {
            return -1;
        }
        size_t klen = (size_t)(kend - (p + 1));
        bool match =
            (klen == strlen(key) && strncmp(p + 1, key, klen) == 0) != 0;

        p = json_skip_ws(kend + 1);
        if (*p != ':') {
            return -1;
        }
        p = json_skip_ws(p + 1);

        if (match) {
            if (*p != '"') {
                return -1; /* found, but the value is not a string */
            }
            return json_decode_string(p, out, out_size, NULL);
        }

        /* Not our key: skip the whole value (nested structures included). */
        p = json_skip_value(p, 32);
        if (p == NULL) {
            return -1;
        }
        p = json_skip_ws(p);
        if (*p == ',') {
            p = json_skip_ws(p + 1);
            continue; /* next member must be a string key */
        }
        if (*p == '}') {
            return -1; /* end of the object: key absent */
        }
        return -1; /* malformed */
    }
}

/* ============================================================
 * multipart/form-data (RFC 7578)
 * ============================================================ */

/* Binary-safe search (memmem is GNU-only). Returns the offset of the
 * first occurrence or (size_t)-1. */
static size_t mem_find(const char *hay, size_t hay_len, const char *needle,
                       size_t needle_len)
{
    if (needle_len == 0 || hay_len < needle_len) {
        return (size_t)-1;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return i;
        }
    }
    return (size_t)-1;
}

/* Extracts the boundary parameter from a Content-Type value like
 * "multipart/form-data; boundary=----X" (quoted or bare).
 * Returns the copied length, or 0 when absent/malformed/oversized
 * (RFC 7578: 1-70 bchars). */
static size_t multipart_boundary(const char *content_type, char *out,
                                 size_t out_size)
{
    if (content_type == NULL || out == NULL || out_size < 2) {
        return 0;
    }

    for (const char *p = content_type; *p != '\0'; p++) {
        if (strncasecmp(p, "boundary=", 9) != 0) {
            continue;
        }
        p += 9;
        if (*p == '"') { /* quoted boundary */
            p++;
        }
        size_t n = 0;
        while (*p != '\0' && *p != '"' && *p != ';') {
            unsigned char c = (unsigned char)*p;
            /* bchars only: reject control chars, spaces, separators */
            if (c < 0x20 || c > 0x7e || n + 1 >= out_size) {
                return 0;
            }
            out[n++] = *p++;
        }
        out[n] = '\0';
        return n; /* 0 for an empty boundary = absent */
    }
    return 0;
}

/* Copies a quoted attribute value (name="..."/filename="...") from
 * a Content-Disposition line region. The attribute must be preceded
 * by ';' or whitespace — otherwise "name=" would match inside
 * "filename=". Bounded, NUL-free; overflow rejects the whole value. */
static void disposition_attr(const char *region, size_t region_len,
                             const char *attr, char *out, size_t out_size)
{
    out[0] = '\0';
    size_t alen = strlen(attr);

    for (size_t i = 0; i + alen < region_len; i++) {
        if (strncasecmp(region + i, attr, alen) != 0) {
            continue;
        }
        /* word boundary: preceded by ';', ' ' or '\t' */
        if (i > 0 && region[i - 1] != ';' && region[i - 1] != ' ' &&
            region[i - 1] != '\t') {
            continue;
        }
        const char *v = region + i + alen;
        bool quoted = *v == '"';
        if (quoted) {
            v++;
        }
        size_t n = 0;
        while ((size_t)(v - region) < region_len) {
            char c = *v;
            if (quoted ? c == '"' : (c == ';' || c == '\r')) {
                break;
            }
            if (c < 0x20 || c > 0x7e || n + 1 >= out_size) {
                return; /* binary junk/overflow: no value */
            }
            out[n++] = c;
            v++;
        }
        if ((quoted && (size_t)(v - region) < region_len && *v == '"') ||
            (!quoted && n > 0)) {
            out[n] = '\0';
        }
        return; /* first match wins */
    }
}

/* Parses one part's header block (Content-Disposition name/filename,
 * Content-Type). region is binary-safe; lines end at CRLF. */
static void parse_part_headers(const char *region, size_t region_len,
                               char *name, size_t name_size, char *filename,
                               size_t filename_size, char *content_type,
                               size_t ct_size)
{
    name[0] = '\0';
    filename[0] = '\0';
    content_type[0] = '\0';

    size_t pos = 0;
    while (pos < region_len) {
        size_t eol = mem_find(region + pos, region_len - pos, "\r\n", 2);
        if (eol == (size_t)-1) {
            eol = region_len - pos; /* last line without CRLF */
        }
        size_t line_len = eol;

        if (line_len > 20 &&
            strncasecmp(region + pos, "Content-Disposition:", 20) == 0) {
            disposition_attr(region + pos, line_len, "name=", name, name_size);
            disposition_attr(region + pos, line_len, "filename=", filename,
                             filename_size);
        } else if (line_len > 13 &&
                   strncasecmp(region + pos, "Content-Type:", 13) == 0) {
            const char *v = region + pos + 13;
            size_t n = 0;
            while ((size_t)(v - (region + pos)) < line_len && *v != ';' &&
                   n + 1 < ct_size) {
                if (*v != ' ' && *v != '\t') {
                    content_type[n++] = *v;
                }
                v++;
            }
            content_type[n] = '\0';
        }

        pos += eol + 2; /* past the CRLF */
    }
}

/* Parses multipart/form-data parts into out. Malformed parts and
 * parts without a name attribute are skipped; parsing stops at the
 * final delimiter or on structural garbage — never fatal. */
static void parse_multipart(const HttpRequest *req, HttpMultiparts *out)
{
    out->count = 0;
    if (req == NULL || req->body == NULL || req->body_len == 0) {
        return;
    }

    const char *ct = http_req_header(req, HTTP_HEADER_CONTENT_TYPE);
    if (ct == NULL) {
        return;
    }
    char boundary[71];
    if (multipart_boundary(ct, boundary, sizeof(boundary)) == 0) {
        return;
    }

    char delim[74]; /* "--" + boundary */
    int dlen = snprintf(delim, sizeof(delim), "--%s", boundary);
    if (dlen <= 2 || (size_t)dlen >= sizeof(delim)) {
        return;
    }
    char close_delim[76]; /* "\r\n" + "--" + boundary */
    int clen = snprintf(close_delim, sizeof(close_delim), "\r\n%s", delim);
    if (clen <= 4 || (size_t)clen >= sizeof(close_delim)) {
        return;
    }

    const char *body = req->body;
    size_t body_len = req->body_len;

    /* position right after the FIRST delimiter (the body may start
     * with it directly — browsers do not send a leading CRLF) */
    size_t pos = mem_find(body, body_len, delim, (size_t)dlen);
    if (pos == (size_t)-1) {
        return;
    }
    pos += (size_t)dlen;

    while (pos < body_len && out->count < HTTP_MAX_MULTIPART_PARTS) {
        /* "--" right after the boundary = the final delimiter */
        if (pos + 2 <= body_len && body[pos] == '-' && body[pos + 1] == '-') {
            return;
        }

        /* after a delimiter: CRLF, then the part headers */
        if (pos + 2 > body_len || body[pos] != '\r' || body[pos + 1] != '\n') {
            return; /* structurally malformed: stop */
        }
        pos += 2;

        /* the header block ends at the first empty line */
        size_t hdr_end = mem_find(body + pos, body_len - pos, "\r\n\r\n", 4);
        if (hdr_end == (size_t)-1) {
            return; /* unterminated headers: stop */
        }
        size_t data_start = pos + hdr_end + 4;

        char name[HTTP_MULTIPART_NAME_MAX];
        char filename[HTTP_MULTIPART_FILE_MAX];
        char part_ct[HTTP_MULTIPART_FILE_MAX];
        parse_part_headers(body + pos, hdr_end + 2, name, sizeof(name),
                           filename, sizeof(filename), part_ct,
                           sizeof(part_ct));

        /* the part data ends at the NEXT closing delimiter */
        size_t data_end = mem_find(body + data_start, body_len - data_start,
                                   close_delim, (size_t)clen);
        if (data_end == (size_t)-1) {
            return; /* missing final delimiter: drop everything open */
        }

        /* parts without a name attribute are malformed — skip them */
        if (name[0] != '\0') {
            HttpMultipartPart *part = &out->parts[out->count++];
            snprintf(part->name, sizeof(part->name), "%s", name);
            snprintf(part->filename, sizeof(part->filename), "%s", filename);
            snprintf(part->content_type, sizeof(part->content_type), "%s",
                     part_ct);
            part->data = body + data_start;
            part->data_len = data_end;
        }

        /* continue after the closing delimiter (CRLF + "--boundary") */
        pos = data_start + data_end + 2 + (size_t)dlen;
    }
}

size_t http_req_multipart_count(const HttpRequest *req)
{
    if (req == NULL) {
        return 0;
    }
    return req->multiparts.count;
}

const HttpMultipartPart *http_req_multipart_part(const HttpRequest *req,
                                                 size_t index)
{
    if (req == NULL || index >= req->multiparts.count) {
        return NULL;
    }
    return &req->multiparts.parts[index];
}

const HttpMultipartPart *http_req_multipart_get(const HttpRequest *req,
                                                const char *name)
{
    if (req == NULL || name == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < req->multiparts.count; i++) {
        if (strcmp(req->multiparts.parts[i].name, name) == 0) {
            return &req->multiparts.parts[i];
        }
    }
    return NULL;
}

/* ============================================================
 * content negotiation (RFC 9110 §12.5.1 Accept)
 * ============================================================ */

/* Parses ";q=0.5" parameters starting at p (at ';'). Returns q,
 * default 1.0 for a missing/unparseable value. */
static double accepts_parse_q(const char **pp)
{
    const char *p = *pp;
    double q = 1.0;

    while (*p == ';') {
        p++;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if ((p[0] == 'q' || p[0] == 'Q') && p[1] == '=') {
            char *end = NULL;
            double v = strtod(p + 2, &end);
            if (end != p + 2 && v >= 0.0 && v <= 1.0) {
                q = v;
            }
        }
        while (*p != '\0' && *p != ';' && *p != ',') {
            p++;
        }
    }

    *pp = p;
    return q;
}

const char *http_req_accepts(const HttpRequest *req, const char *const *types)
{
    if (req == NULL || types == NULL || types[0] == NULL) {
        return NULL;
    }

    /* Does an Accept header exist at all? Without one, everything is
     * acceptable (RFC 9110 §12.5.1) — the first valid offer wins. */
    bool has_accept = false;
    for (size_t i = 0; i < req->headers.count; i++) {
        if (strcasecmp(req->headers.items[i].key, HTTP_HEADER_ACCEPT) == 0) {
            has_accept = true;
            break;
        }
    }
    if (!has_accept) {
        for (size_t t = 0; types[t] != NULL; t++) {
            if (strchr(types[t], '/') != NULL) {
                return types[t];
            }
        }
        return NULL;
    }

    /* For each offered type, find the best matching media range:
     * exact (3) > subtype wildcard (2) > full wildcard (1); only
     * ranges with q > 0 count (q=0 excludes). */
    const char *best_type = NULL;
    int best_score = 0;
    double best_q = 0.0;

    for (size_t t = 0; types[t] != NULL; t++) {
        const char *slash = strchr(types[t], '/');
        if (slash == NULL) {
            continue; /* malformed offer */
        }
        size_t type_len = (size_t)(slash - types[t]);
        const char *subtype = slash + 1;
        size_t sub_len = strlen(subtype);

        int score = 0;
        double q = 0.0;

        for (size_t h = 0; h < req->headers.count; h++) {
            if (strcasecmp(req->headers.items[h].key, HTTP_HEADER_ACCEPT) !=
                0) {
                continue;
            }
            const char *p = req->headers.items[h].value;
            while (*p != '\0') {
                while (*p == ' ' || *p == '\t' || *p == ',') {
                    p++;
                }
                if (*p == '\0') {
                    break;
                }

                /* media range: full wildcard, subtype wildcard or
                 * an exact type/subtype pair */
                const char *tstart = p;
                while (*p != '\0' && *p != ',' && *p != '/' && *p != ';') {
                    p++;
                }
                size_t rtype_len = (size_t)(p - tstart);

                int rscore = 0;
                if (*p == '/') {
                    p++;
                    const char *sstart = p;
                    while (*p != '\0' && *p != ',' && *p != ';') {
                        p++;
                    }
                    size_t rsub_len = (size_t)(p - sstart);

                    int type_match =
                        (rtype_len == 1 && tstart[0] == '*') ||
                        (rtype_len == type_len &&
                         strncasecmp(tstart, types[t], type_len) == 0);
                    int sub_match =
                        (rsub_len == 1 && sstart[0] == '*') ||
                        (rsub_len == sub_len &&
                         strncasecmp(sstart, subtype, sub_len) == 0);
                    if (type_match && sub_match) {
                        if (rtype_len == type_len) {
                            /* exact type: exact subtype beats wildcard */
                            rscore = (rsub_len == sub_len) ? 3 : 2;
                        } else {
                            rscore = 1; /* wildcard type */
                        }
                    }
                } else if (rtype_len == 1 && tstart[0] == '*') {
                    rscore = 1; /* a bare asterisk means any type */
                }

                double q_val = accepts_parse_q(&p);

                if (rscore > 0 && q_val > 0.0 &&
                    (rscore > score || (rscore == score && q_val > q))) {
                    score = rscore;
                    q = q_val;
                }

                while (*p != '\0' && *p != ',') {
                    p++;
                }
                if (*p == ',') {
                    p++;
                }
            }
        }

        /* pick the overall winner: score, then q, then offer order */
        if (score > 0 && (best_type == NULL || score > best_score ||
                          (score == best_score && q > best_q))) {
            best_type = types[t];
            best_score = score;
            best_q = q;
        }
    }

    return best_type;
}

void http_set_error_handler(HttpServer *server, HttpErrorHandler handler)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT_MSG(server->listening == false,
                    "cannot set an error handler while listening");

    if (server == NULL) {
        return;
    }
    server->error_handler = handler;
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
