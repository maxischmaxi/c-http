#include "c_http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "c_http_assert.h"

/* Zeitfenster für einen Client-Request (recv UND send), danach gilt der
 * Client als tot. Schützt den single-threaded Server vor Slowloris-DoS. */
#define HTTP_CLIENT_TIMEOUT_SEC 10

/* Backlog für listen(2) */
#define HTTP_LISTEN_BACKLOG 128

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 /* Plattform ohne MSG_NOSIGNAL (z.B. macOS) */
#endif

/* ============================================================
 * HTTP Spec Validation Helpers (RFC 9110, 9112)
 *
 * WICHTIG: Diese Prüfunkungen sind echte Guards und werden IMMER
 * kompiliert — auch mit NDEBUG. Sicherheitsrelevante Validierung
 * (Header-Injection, Feld-Namen) darf nicht nur in Debug-Builds
 * über HTTP_ASSERT laufen.
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
        if (c <= 0x20 || c == 0x7f || c > 0x7e) { /* kein CTL/SP, nur ASCII */
            return false;
        }
        if (!is_tchar(c)) {
            return false;
        }
    }
    return true;
}

/* RFC 9110 §5.6: field-value darf kein CR/LF enthalten.
 * Verhindert Header-Injection / Response-Splitting. */
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

/* RFC 9110 §3.2: origin-form startet mit "/", asterisk-form "*" nur bei
 * OPTIONS. Wird nur als Debug-Assert verwendet. */
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

static bool path_matches(const char *mid_path, const char *req_path)
{
    HTTP_ASSERT(mid_path != NULL);
    HTTP_ASSERT(req_path != NULL);

    size_t mid_len = strlen(mid_path);
    size_t req_len = strlen(req_path);

    /* Trailing Slash am Middleware-Pfad ist optional:
     * "/api/" verhält sich wie "/api" (matcht "/api" UND "/api/users").
     * "" matcht alles (Root). */
    if (mid_len > 1 && mid_path[mid_len - 1] == '/') {
        mid_len--;
    }
    if (mid_len == 0) {
        return true;
    }
    if (req_len == 0) {
        return false;
    }

    if (strncmp(mid_path, req_path, mid_len) != 0) {
        return false;
    }

    if (req_len == mid_len) {
        return true;
    }

    if (mid_path[mid_len - 1] == '/') {
        return true; /* "/" als Präfix matcht alles darunter */
    }

    /* "/api" matcht "/api/users", aber NICHT "/api-v2" */
    return req_path[mid_len] == '/';
}

/* Kompakte, RFC-1123-konforme Datumsangabe — bewusst NICHT über strftime,
 * weil %a/%b locale-abhängig sind (z.B. "So" statt "Sun" unter de_DE). */
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

    /* Echte Guards (auch im Release-Build): RFC-9110-Feldname und kein
     * CR/LF im Wert (Header-Injection). */
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

/* Liest den Request-Header in buf bis "\r\n\r\n" (oder bis der Puffer voll
 * ist). *complete gibt an, ob der Header-Block vollständig empfangen wurde.
 * Rückgabe: gelesene Bytes, -1 bei Fehler/Timeout. */
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
            if (errno == EINTR) { /* Signal empfangen: erneut versuchen */
                continue;
            }
            return -1; /* Fehler oder Timeout (SO_RCVTIMEO) */
        }
        if (r == 0) {
            break; /* Client hat die Verbindung geschlossen */
        }

        size_t chunk_start = total;
        total += (size_t)r;
        buf[total] = '\0';

        /* Nur den neuen Chunk + 3 Bytes Overlap scannen, damit ein
         * "\r\n\r\n" über die Chunk-Grenze erkannt wird (kein O(n²)). */
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
        /* MSG_NOSIGNAL: SIGPIPE unterdrücken — ein Client, der mitten in
         * der Response die Verbindung schließt, darf den Server nicht
         * killen. */
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

/* Sendet den Response-Header. suppress_body (HEAD) unterdrückt den Body,
 * behält aber Content-Length bei, damit der Client die GET-Größe erfährt. */
static void send_res(HttpResponse *res, int client_fd, bool suppress_body)
{
    HTTP_ASSERT(res != NULL);
    HTTP_ASSERT(client_fd >= 0);

    /* RFC 9110 §15: Status validieren; ungültig -> 500 statt Müll senden */
    if (!is_valid_status_code(res->status)) {
        res->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

    bool no_body_status = ((res->status >= 100 && res->status < 200) ||
                           res->status == HTTP_STATUS_NO_CONTENT ||
                           res->status == HTTP_STATUS_RESET_CONTENT ||
                           res->status == HTTP_STATUS_NOT_MODIFIED) != 0;

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
        return;
    }
    if ((size_t)status_len >= sizeof(status_line)) {
        status_len = (int)sizeof(status_line) - 1;
    }
    send_all(client_fd, status_line, (size_t)status_len);

    if (!no_body_status) {
        char content_length[64]; /* groß genug für jedes size_t */
        int cl_len = snprintf(content_length, sizeof(content_length),
                              "Content-Length: %zu\r\n", body_len);
        if (cl_len < 0) {
            return;
        }
        if ((size_t)cl_len >= sizeof(content_length)) {
            cl_len = (int)sizeof(content_length) - 1;
        }
        send_all(client_fd, content_length, (size_t)cl_len);
    }

    bool has_content_type = false;
    for (size_t i = 0; i < res->headers.count; i++) {
        if (strcasecmp(res->headers.items[i].key, HTTP_HEADER_CONTENT_TYPE) ==
            0) {
            has_content_type = true;
            break;
        }
    }

    /* Default nur setzen, wenn kein Handler einen gesetzt hat
     * (keine doppelten Content-Type-Header). */
    if (!has_content_type && body_len > 0) {
        /* sizeof() - 1 statt handgerechnetem 24: die harte Laenge war um
         * eins zu kurz und hat das '\n' abgeschnitten. */
        send_all(client_fd, "Content-Type: text/html\r\n",
                 sizeof("Content-Type: text/html\r\n") - 1);
    }

    for (size_t i = 0; i < res->headers.count; i++) {
        char hdr_line[512];
        int hl =
            snprintf(hdr_line, sizeof(hdr_line), "%s: %s\r\n",
                     res->headers.items[i].key, res->headers.items[i].value);
        if (hl <= 0) {
            continue;
        }
        /* snprintf liefert die hypothetische Länge — auf den Puffer
         * begrenzen, sonst liest send_all über das Ende hinaus. */
        if ((size_t)hl >= sizeof(hdr_line)) {
            hl = (int)sizeof(hdr_line) - 1;
        }
        send_all(client_fd, hdr_line, (size_t)hl);
    }

    send_all(client_fd, "\r\n", 2);
    if (!no_body_status && !suppress_body) {
        send_all(client_fd, body, body_len);
    }

    if (res->encoded_body != NULL) {
        free(res->encoded_body);
        res->encoded_body = NULL;
    }
}

/* Request-Line parsen: "METHOD SP request-target SP HTTP-version".
 * Modifiziert line in-place. Rückgabe: 0 = OK, sonst HTTP-Status (400/414/
 * 501/505), der als Response gesendet werden soll. */
static int parse_request_line(char *line, HttpRequest *req)
{
    /* METHODE */
    char *sp = strchr(line, ' ');
    if (sp == NULL) {
        return HTTP_STATUS_BAD_REQUEST;
    }
    *sp = '\0';
    if (strlen(line) >= HTTP_METHOD_MAX) {
        return HTTP_STATUS_NOT_IMPLEMENTED; /* unbekannte/lange Methode */
    }
    strcpy(req->method, line);

    /* request-target (mehrere SP tolerieren, RFC 9112 §2.2) */
    char *target = sp + 1;
    while (*target == ' ') {
        target++;
    }
    sp = strchr(target, ' ');
    if (sp == NULL) {
        return HTTP_STATUS_BAD_REQUEST;
    }
    *sp = '\0';

    /* Query-String abtrennen: "/users?id=1" -> "/users" */
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

    /* RFC 9112 §3.1: request-target muss origin-form sein ("*": nur OPTIONS)
     */
    HTTP_ASSERT_MSG(is_valid_request_target(req->path, req->method),
                    "RFC 9110 §3.2: invalid request-target");
    return 0;
}

/* Header-Block parsen (start zeigt direkt hinter die Request-Line, end auf
 * das Ende der empfangenen Bytes). Rückgabe: 0 = OK, sonst HTTP-Status
 * (431/500). Ungültige Zeilen werden übersprungen. */
static int parse_headers(char *start, const char *end, HttpRequest *req)
{
    char *cursor = start;

    while (cursor < end && cursor[0] != '\r' && cursor[0] != '\0') {
        char *line_end = strstr(cursor, "\r\n");
        if (line_end == NULL) {
            break; /* unvollständige Zeile */
        }

        char *colon = memchr(cursor, ':', (size_t)(line_end - cursor));
        if (colon == NULL) { /* Zeile ohne ':' -> überspringen */
            cursor = line_end + 2;
            continue;
        }

        /* Key in-place null-terminieren */
        *colon = '\0';
        char *key = cursor;

        /* Value: nach ':' starten, führenden OWS trimmen */
        char *value = colon + 1;
        while (*value == ' ' || *value == '\t') {
            value++;
        }

        /* RFC 9110 §5.5: trailing OWS trimmen (nicht nur leading) */
        char *vend = line_end;
        while (vend > value && (vend[-1] == ' ' || vend[-1] == '\t')) {
            vend--;
        }
        *vend = '\0';

        /* Echte Validierung (auch Release): ungültige Feldnamen und
         * injizierte Werte überspringen statt speichern. */
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

/* Request-Body gemäß Content-Length lesen. header_end ist der Offset des
 * ersten Body-Bytes in buf (schon gelesene Bytes werden übernommen).
 * Rückgabe: 0 = OK, sonst HTTP-Status (400/408/413/500/501). */
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
            /* RFC 9112 §5.2: doppelte Content-Length mit identischem Wert
             * ist erlaubt, abweichende Werte sind ein Fehler. */
            if (content_length >= 0 && content_length != parsed) {
                return HTTP_STATUS_BAD_REQUEST;
            }
            content_length = parsed;
        }
    }

    /* Transfer-Encoding wird nicht unterstützt (chunked etc.) */
    if (has_te) {
        return HTTP_STATUS_NOT_IMPLEMENTED;
    }

    if (content_length < 0) {
        return 0; /* kein Body erwartet */
    }
    if ((unsigned long long)content_length > HTTP_MAX_BODY) {
        return HTTP_STATUS_CONTENT_TOO_LARGE;
    }

    req->body = malloc((size_t)content_length + 1);
    if (req->body == NULL) {
        return HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

    /* Bytes, die zusammen mit den Headern gelesen wurden */
    size_t leftover = total - header_end;
    if (leftover > (size_t)content_length) {
        /* mehr Body-Bytes als laut Content-Length -> Request-Smuggling-Risiko
         */
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
            return HTTP_STATUS_REQUEST_TIMEOUT; /* Timeout/Fehler */
        }
        if (r == 0) { /* Client mitten im Body verschwunden */
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

    /* Kein Default-Content-Type: send_res() setzt ihn nur, wenn der
     * Handler keinen gesetzt hat. */
}

static bool apply_middleware(HttpServer *server, HttpRequest *req,
                             HttpResponse *res)
{
    for (size_t i = 0; i < server->middleware_count; i++) {
        HttpMiddlewareHandler middleware = server->middlewares[i].handler;
        const char *mid_path = server->middlewares[i].path;

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
                                     HttpResponse *res)
{
    HttpMethod m;
    if (string_to_http_method(req->method, &m) != 0) {
        return HANDLER_NOT_IMPLEMENTED;
    }

    HttpHandler handler = NULL;
    bool path_exists = false;

    for (size_t i = 0; i < server->route_count; i++) {
        if (strcmp(req->path, server->routes[i].path) != 0) {
            continue;
        }
        path_exists = true;
        if (server->routes[i].method == m) {
            handler = server->routes[i].handler;
            break;
        }
    }

    /* RFC 9110 §9.3.2: HEAD fällt auf GET zurück, wenn keine explizite
     * HEAD-Route existiert (Body wird beim Senden unterdrückt). */
    if (handler == NULL && m == HTTP_METHOD_HEAD) {
        for (size_t i = 0; i < server->route_count; i++) {
            if (strcmp(req->path, server->routes[i].path) != 0) {
                continue;
            }
            if (server->routes[i].method == HTTP_METHOD_GET) {
                handler = server->routes[i].handler;
                break;
            }
        }
    }

    if (handler == NULL) {
        return (int)path_exists ? HANDLER_METHOD_NOT_ALLOWED
                                : HANDLER_NOT_FOUND;
    }

    handler(req, res);
    return HANDLER_OK;
}

/* RFC 9110 §15.4.6: bei 405 gehört ein Allow-Header dazu */
static void set_allow_header(HttpServer *server, const char *path,
                             HttpResponse *res)
{
    char allow[128];
    size_t used = 0;

    for (size_t i = 0; i < server->route_count; i++) {
        if (strcmp(path, server->routes[i].path) != 0) {
            continue;
        }
        const char *name = method_name(server->routes[i].method);
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
    HTTP_ASSERT(server->routes != NULL);

    char buf[4096];
    bool headers_complete = false;

    /* Erst lesen, dann allozieren: bei Lesefehlern gibt es nichts zu
     * räumen und keine Response-Puffer-Header, die leaken könnten. */
    ssize_t total =
        read_request(client_fd, buf, sizeof(buf), &headers_complete);
    if (total < 0) {
        return; /* recv-Fehler oder Timeout — nur schließen */
    }
    if (total == 0) {
        return; /* Client hat sofort geschlossen */
    }

    HttpRequest req = {0};
    HttpResponse res = {0};
    apply_default_headers(&res, server);

    /* Jeder Fehlerpfad springt zu send: es wird IMMER eine Response
     * gesendet (kein stummes Connection-Close) und NUR am Ende geräumt. */
    if (!headers_complete) {
        res.status = HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE; /* 431 */
        goto send;
    }

    {
        /* Position des Body-Starts VOR dem Terminieren holen (leerer
         * Header-Block: eol und Marker fallen zusammen). */
        char *sep = strstr(buf, "\r\n\r\n");
        if (sep == NULL) { /* kann bei headers_complete nicht passieren */
            res.status = HTTP_STATUS_BAD_REQUEST;
            goto send;
        }
        size_t header_end = (size_t)(sep - buf) + 4;

        /* Request-Line isolieren (beim ersten CRLF terminieren), dann
         * parsen; parse_headers startet direkt dahinter. */
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

    /* RFC 9112 §3.2: Host-Header in HTTP/1.1 Pflicht (Debug-Check) */
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

    if (apply_middleware(server, &req, &res)) {
        switch (execute_handler(server, &req, &res)) {
        case HANDLER_OK:
            break;
        case HANDLER_METHOD_NOT_ALLOWED:
            res.status = HTTP_STATUS_METHOD_NOT_ALLOWED;
            set_allow_header(server, req.path, &res);
            break;
        case HANDLER_NOT_FOUND:
            res.status = HTTP_STATUS_NOT_FOUND;
            break;
        case HANDLER_NOT_IMPLEMENTED:
            res.status = HTTP_STATUS_NOT_IMPLEMENTED;
            break;
        }
    }

send:
    if (res.status == 0) {
        res.status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

    /* RFC 9110 §15: Status vor dem Senden validieren */
    HTTP_ASSERT_MSG(is_valid_status_code(res.status),
                    "RFC 9110 §15: status code must be 100-599 before send");
    HTTP_ASSERT_MSG(res.body_len <= sizeof(res.body),
                    "body_len exceeds body buffer — buffer overflow");

    http_encode_body(server, &req, &res);

    /* RFC 9110 §9.3.2: HEAD-Responses haben keinen Body (die Header
     * entsprechen denen eines GET, inklusive Content-Length). */
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

    /* out deterministisch initialisieren — auch im Fehlerfall ist der
     * Server danach sicher zu schließen/zu leeren. */
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

    out->routes = malloc(HTTP_ROUTE_INITIAL_CAP * sizeof(HttpRoute));
    if (out->routes == NULL) {
        close(server_fd); /* Socket nicht leaken */
        return SERVER_ERROR;
    }
    out->route_count = 0;
    out->route_capacity = HTTP_ROUTE_INITIAL_CAP;

    /* server_name wird kopiert — die Library hängt nicht am Speicher des
     * Aufrufers. */
    out->server_name = strdup(server_args->server_name);
    if (out->server_name == NULL) {
        free(out->routes);
        out->routes = NULL;
        close(server_fd);
        return SERVER_ERROR;
    }

    out->middlewares = NULL;
    out->middleware_count = 0;
    out->middleware_capacity = 0;

    out->encoders = NULL;
    out->encoder_count = 0;
    out->encoder_capacity = 0;
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

    /* fd >= 0 statt fd != 0: fd 0 ist ein gültiger Socket-Descriptor. */
    if (server->fd >= 0) {
        close(server->fd);
        server->fd = -1; /* gegen Double-Close schützen */
    }

    for (size_t i = 0; i < server->route_count; i++) {
        free((void *)server->routes[i].path);
    }
    free(server->routes);
    server->routes = NULL;
    server->route_count = server->route_capacity = 0;

    for (size_t i = 0; i < server->middleware_count; i++) {
        free((void *)server->middlewares[i].path);
    }
    free(server->middlewares);
    server->middlewares = NULL;
    server->middleware_count = server->middleware_capacity = 0;

    free(server->encoders);
    server->encoders = NULL;
    server->encoder_count = server->encoder_capacity = 0;

    free(server->server_name);
    server->server_name = NULL;
}

void http_stop_server(HttpServer *server)
{
    if (server == NULL) {
        return;
    }

    server->listening = false;
    /* Weckt ein blockierendes accept() auf (async-signal-safe: nur
     * syscall + Flag). */
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
    HTTP_ASSERT(server->routes != NULL);

    server->listening = true;
    printf("Server listening on port %d\n", server->port);

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
                break; /* Socket geschlossen (http_stop_server) */
            }
            perror("accept");
            continue;
        }

        /* Slowloris-Schutz: recv/send dürfen den Server nicht ewig
         * blockieren. */
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

    /* Route, die länger ist als HTTP_PATH_MAX, kann nie matchen (der
     * Request-Path wird auf HTTP_PATH_MAX begrenzt) — sofort ablehnen. */
    if (strlen(path) >= HTTP_PATH_MAX) {
        return HTTP_ROUTE_ADD_ERROR;
    }

    if (server->route_count == server->route_capacity) {
        size_t new_cap = server->route_capacity * 2;
        HttpRoute *tmp = realloc(server->routes, new_cap * sizeof(HttpRoute));
        if (tmp == NULL) {
            return HTTP_ROUTE_ADD_ERROR;
        }
        server->routes = tmp;
        server->route_capacity = new_cap;
    }

    for (size_t i = 0; i < server->route_count; i++) {
        if (server->routes[i].method == method &&
            strcmp(server->routes[i].path, path) == 0) {
            return HTTP_ROUTE_ADD_CONFLICT;
        }
    }

    char *owned_path = strdup(path);
    if (owned_path == NULL) {
        return HTTP_ROUTE_ADD_ERROR;
    }

    server->routes[server->route_count++] =
        (HttpRoute){.path = owned_path, .handler = handler, .method = method};

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

    if (server->middleware_count == server->middleware_capacity) {
        size_t new_cap = server->middleware_capacity == 0
                             ? 8
                             : server->middleware_capacity * 2;
        HttpMiddleware *tmp =
            realloc(server->middlewares, new_cap * sizeof(HttpMiddleware));
        if (tmp == NULL) {
            return HTTP_MIDDLEWARE_ADD_ERROR;
        }
        server->middlewares = tmp;
        server->middleware_capacity = new_cap;
    }

    char *owned_path = NULL;
    if (path != NULL) {
        owned_path = strdup(path);
        if (owned_path == NULL) {
            return HTTP_MIDDLEWARE_ADD_ERROR;
        }
    }

    server->middlewares[server->middleware_count++] =
        (HttpMiddleware){.path = owned_path, .handler = handler};

    return HTTP_MIDDLEWARE_ADD_OK;
}

HttpSetHeaderResult http_set_header(HttpHeaders *headers, const char *key,
                                    const char *value)
{
    if (headers == NULL || key == NULL || value == NULL) {
        return HTTP_SET_HEADER_ERROR;
    }

    /* apply_header validiert echte Guards (Feldname, CR/LF-Injection)
     * — auch im Release-Build. */
    if (apply_header(headers, key, value) < 0) {
        return HTTP_SET_HEADER_ERROR;
    }
    return HTTP_SET_HEADER_OK;
}

/* ============================================================
 * Route Groups
 * ============================================================ */

/* false, wenn das Ergebnis nicht in out passt (Truncation). */
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
        /* Group-scoped middleware: group prefix als Pfad */
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
