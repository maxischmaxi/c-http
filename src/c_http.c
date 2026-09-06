#include "c_http.h"
#include "c_http_assert.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ============================================================
 * HTTP Spec Validation Helpers (RFC 9110, 9112)
 * Used by asserts in debug builds and as guard checks.
 * ============================================================ */
#ifndef NDEBUG

/* RFC 9110 §5.5: field-name = 1*tchar
 * tchar excludes CTL (0-31, 127), SP, colon */
static bool is_valid_header_name(const char *name)
{
    if (!name || !*name) return false;
    for (const char *p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c <= 0x1f || c == 0x7f) return false; /* no CTL */
        if (c == ' ' || c == '\t' || c == ':') return false;
    }
    return true;
}

/* RFC 9110 §5.6: field-value must not contain bare CR or LF
 * Prevents header injection attacks */
static bool header_value_has_injection(const char *value)
{
    if (!value) return false;
    for (const char *p = value; *p; p++) {
        if (*p == '\r' || *p == '\n') return true;
    }
    return false;
}

/* RFC 9112 §3.1: HTTP-version = HTTP-name "/" DIGIT "." DIGIT */
static bool is_valid_http_version(const char *version)
{
    if (!version) return false;
    return strncmp(version, "HTTP/", 5) == 0 &&
           version[5] >= '0' && version[5] <= '9' &&
           version[6] == '.' &&
           version[7] >= '0' && version[7] <= '9' &&
           version[8] == '\0';
}

/* RFC 9110 §15: status-code = 3DIGIT; standard range 100-599 */
static bool is_valid_status_code(int status)
{
    return status >= 100 && status <= 599;
}

/* RFC 9110 §3.2: origin-form starts with "/"
 * asterisk-form "*" only valid for OPTIONS */
static bool is_valid_request_target(const char *path, const char *method)
{
    if (!path || !*path) return false;
    if (strcmp(path, "*") == 0) {
        return method != NULL && strcmp(method, "OPTIONS") == 0;
    }
    return path[0] == '/';
}

/* RFC 9112 §6.1: Transfer-Encoding and Content-Length must not coexist */
static bool has_conflicting_body_headers(const HttpHeaders *headers)
{
    bool has_te = false, has_cl = false;
    for (size_t i = 0; i < headers->count; i++) {
        if (strcasecmp(headers->items[i].key,
                       HTTP_HEADER_TRANSFER_ENCODING) == 0)
            has_te = true;
        if (strcasecmp(headers->items[i].key,
                       HTTP_HEADER_CONTENT_LENGTH) == 0)
            has_cl = true;
    }
    return has_te && has_cl;
}

#endif /* !NDEBUG — validation helpers only in debug */

static const char *status_text(int status)
{
    HTTP_ASSERT_MSG(is_valid_status_code(status),
                    "RFC 9110 §15: status-code must be 3-digit (100-599)");
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
        return "Unavailable For Legal Reasons";

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

static bool path_matches(const char *mid_path, const char *req_path)
{
    HTTP_ASSERT(mid_path != NULL);
    HTTP_ASSERT(req_path != NULL);
    HTTP_ASSERT_MSG(mid_path[0] == '/' || mid_path[0] == '\0',
                "middleware path must start with '/' or be empty");
    HTTP_ASSERT_MSG(req_path[0] == '/',
                "RFC 9110 §3.2: request-target must start with '/'");

    size_t mid_len = strlen(mid_path);
    size_t req_len = strlen(req_path);

    if (mid_len > req_len) {
        return false;
    }

    if (strncmp(mid_path, req_path, mid_len) != 0) {
        return false;
    }

    if (mid_len == req_len) {
        return true;
    }

    /*
     * Prefix stimmt, jetzt Boundary-Check:
     *
     * Fall 1: Middleware-Pfad endet mit '/'
     *   "/"         -> matcht alles (root)
     *   "/api/"     -> matcht "/api/users"
     *   -> kein weiterer Check nötig, '/' ist bereits die Grenze
     */
    if (mid_path[mid_len - 1] == '/') {
        return true;
    }

    /*
     * Fall 2: Middleware-Pfad endet NICHT mit '/'
     *   "/api" matcht "/api/users" (nächstes Zeichen ist '/')
     *   "/api" matcht NICHT "/api-v2" (nächstes Zeichen ist '-')
     */
    return req_path[mid_len] == '/';
}

static int apply_header(HttpHeaders *headers, const char *key,
                        const char *value)
{
    HTTP_ASSERT(headers != NULL);
    HTTP_ASSERT(key != NULL);
    HTTP_ASSERT(value != NULL);
    HTTP_ASSERT_MSG(is_valid_header_name(key),
                    "RFC 9110 §5.5: header name must be a valid token");
    HTTP_ASSERT_MSG(!header_value_has_injection(value),
                    "RFC 9110 §5.6: header value must not contain CR/LF");
    HTTP_ASSERT(headers->count <= headers->capacity);

    if (headers == NULL) {
        return -1;
    }

    if (headers->count == headers->capacity) {
        size_t new_cap = headers->capacity == 0 ? 8 : headers->capacity * 2;
        HttpHeader *tmp = realloc(headers->items, new_cap * sizeof(HttpHeader));
        if (!tmp) {
            return -1;
        }
        headers->items = tmp;
        headers->capacity = new_cap;
    }

    headers->items[headers->count] = (HttpHeader){
        .key = strdup(key),
        .value = strdup(value),
    };
    if (!headers->items[headers->count].key ||
        !headers->items[headers->count].value) {
        free(headers->items[headers->count].key);
        free(headers->items[headers->count].value);
        return -1;
    }

    headers->count++;
    return 0;
}

static int string_to_http_method(const char *method, HttpMethod *out)
{
    HTTP_ASSERT(method != NULL);
    HTTP_ASSERT(out != NULL);

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

static ssize_t read_request(int client_fd, char *buf, size_t size)
{
    HTTP_ASSERT(client_fd >= 0);
    HTTP_ASSERT(buf != NULL);
    HTTP_ASSERT(size > 1);

    size_t total = 0;

    while (total < size - 1) {
        ssize_t r = recv(client_fd, buf + total, size - 1 - total, 0);
        if (r < 0) {
            return -1;
        }
        if (r == 0) {
            break;
        }
        total += (size_t)r;
        buf[total] = '\0';

        if (strstr(buf, "\r\n\r\n") != NULL) { /* Header komplett */
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
        ssize_t s = send(client_fd, data + sent, len - sent, 0);
        if (s < 0) {
            return -1;
        }
        sent += (size_t)s;
    }

    return 0;
}

static void send_res(HttpResponse *res, int client_fd)
{
    HTTP_ASSERT(res != NULL);
    HTTP_ASSERT(client_fd >= 0);
    HTTP_ASSERT_MSG(is_valid_status_code(res->status),
                    "RFC 9110 §15: invalid status code before send");
    HTTP_ASSERT(status_text(res->status) != NULL);
    HTTP_ASSERT_MSG(res->body_len <= sizeof(res->body),
                "body_len exceeds body buffer — buffer overflow");

    size_t body_len =
        res->encoded_body != NULL ? res->encoded_body_len : res->body_len;
    const char *body =
        res->encoded_body != NULL ? res->encoded_body : res->body;

    char status_line[64];
    int status_len =
        snprintf(status_line, sizeof(status_line), "HTTP/1.1 %d %s\r\n",
                 res->status, status_text(res->status));
    send_all(client_fd, status_line, (size_t)status_len);

    char content_length[32];
    int cl_len = snprintf(content_length, sizeof(content_length),
                          "Content-Length: %zu\r\n", body_len);
    send_all(client_fd, content_length, (size_t)cl_len);

    bool has_content_type = false;
    for (size_t i = 0; i < res->headers.count; i++) {
        if (strcasecmp(res->headers.items[i].key, "Content-Type") == 0) {
            has_content_type = true;
            break;
        }
    }

    if (!has_content_type && body_len > 0) {
        send_all(client_fd, "Content-Type: text/html\r\n", 24);
    }

    for (size_t i = 0; i < res->headers.count; i++) {
        char hdr_line[512];
        int hl =
            snprintf(hdr_line, sizeof(hdr_line), "%s: %s\r\n",
                     res->headers.items[i].key, res->headers.items[i].value);
        send_all(client_fd, hdr_line, (size_t)hl);
    }

    send_all(client_fd, "\r\n", 2);
    send_all(client_fd, body, body_len);

    if (res->encoded_body != NULL) {
        free(res->encoded_body);
        res->encoded_body = NULL;
    }
}

static void parse_headers(char buf[4096], ssize_t total, HttpRequest *req)
{
    HTTP_ASSERT(buf != NULL);
    HTTP_ASSERT(req != NULL);
    HTTP_ASSERT(total > 0);
    HTTP_ASSERT_MSG(has_conflicting_body_headers(&req->headers) == false,
                "RFC 9112 §6.1: Transfer-Encoding and Content-Length "
                "must not coexist");


    /* --- Header parsing --- */
    /* buf sieht so aus:
     *   GET /path HTTP/1.1 CRLF Host: example.com CRLF Accept: text/html CRLF
     * CRLF
     *   ^-- Request-Line -^  ^-- Header-Zeilen -----------------------^ ^--
     * Ende */
    char *cursor = strstr(buf, "\r\n"); /* Ende der Request-Line */
    if (cursor) {
        cursor += 2; /* CRLF ueberspringen - Start der ersten Header-Zeile */

        while (cursor < buf + total && cursor[0] != '\r') {
            /* Zeilenende suchen */
            char *line_end = strstr(cursor, "\r\n");
            if (!line_end) {
                break; /* unvollstaendige Zeile -> abbrechen */
            }

            /* Doppelpunkt suchen (Key:Value-Trenner) */
            char *colon = memchr(cursor, ':', (size_t)(line_end - cursor));
            if (!colon) {
                /* malformierte Zeile ohne ':' -> ueberspringen */
                cursor = line_end + 2;
                continue;
            }

            /* Key: in-place null-terminieren */
            *colon = '\0';
            char *key = cursor;

            HTTP_ASSERT_MSG(is_valid_header_name(key),
                            "RFC 9110 §5.5: parsed header name "
                            "must be a valid token");

            /* Value: nach ':' starten, fuehrende Leerzeichen/Tabulatoren
             * trimmen */
            char *value = colon + 1;
            while (*value == ' ' || *value == '\t') {
                value++;
            }

            /* Value am Zeilenende null-terminieren */
            *line_end = '\0';

            HTTP_ASSERT_MSG(!header_value_has_injection(value),
                            "RFC 9110 §5.6: parsed header value "
                            "must not contain CR/LF");

            apply_header(&req->headers, key, value);

            cursor = line_end + 2; /* naechste Zeile */
        }
    }
}

static bool apply_middleware(HttpServer *server, HttpRequest *req,
                             HttpResponse *res)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(req != NULL);
    HTTP_ASSERT(res != NULL);
    HTTP_ASSERT(server->middlewares != NULL ||
                server->middleware_count == 0);

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

static int execute_handler(HttpServer *server, HttpRequest *req,
                           HttpResponse *res)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(req != NULL);
    HTTP_ASSERT(res != NULL);
    HTTP_ASSERT(server->routes != NULL || server->route_count == 0);

    HttpHandler handler = NULL;
    for (size_t i = 0; i < server->route_count; i++) {
        HttpMethod m;
        if (string_to_http_method(req->method, &m) != 0) {
            continue;
        }
        if (m != server->routes[i].method) {
            continue;
        }
        if (strcmp(req->path, server->routes[i].path) == 0) {
            handler = server->routes[i].handler;
            break;
        }
    }

    if (handler == NULL) {
        return -1;
    }

    handler(req, res);
    return 0;
}

static void handle_client(HttpServer *server, int client_fd, const char *ip,
                          uint16_t client_port)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(client_fd >= 0);
    HTTP_ASSERT(ip != NULL);
    HTTP_ASSERT(server->fd >= 0);
    HTTP_ASSERT(server->listening == true);
    HTTP_ASSERT(server->routes != NULL);

    char buf[4096];
    ssize_t total = read_request(client_fd, buf, sizeof(buf));

    if (total < 0) {
        perror("recv");
        return;
    }
    if (total == 0) {
        printf("client connection closed\n");
        return;
    }

    HttpRequest req = {0};
    HttpResponse res = {0};

    char time_buf[64];
    time_t now = time(NULL);
    struct tm gt;
    gmtime_r(&now, &gt);
    strftime(time_buf, sizeof time_buf, "%a, %d %b %Y %H:%M:%S GMT", &gt);
    apply_header(&res.headers, HTTP_HEADER_DATE, time_buf);
    apply_header(&res.headers, HTTP_HEADER_CONTENT_TYPE,
                 "text/html; charset=utf-8");
    apply_header(&res.headers, HTTP_HEADER_CONNECTION, "close");
    char server_name[64];
    snprintf(server_name, sizeof(server_name), "%s/%s", server->server_name,
             C_HTTP_VERSION);
    apply_header(&res.headers, HTTP_HEADER_SERVER, server_name);
    apply_header(&res.headers, HTTP_HEADER_STRICT_TRANSPORT_SECURITY,
                 "max-age=31536000; includeSubDomains");
    apply_header(&res.headers, HTTP_HEADER_X_CONTENT_TYPE_OPTIONS, "nosniff");
    apply_header(&res.headers, HTTP_HEADER_X_FRAME_OPTIONS, "SAMEORIGIN");
    apply_header(&res.headers, HTTP_HEADER_CONTENT_SECURITY_POLICY,
                 "default-src 'self'");
    apply_header(&res.headers, HTTP_HEADER_REFERER_POLICY,
                 "strict-origin-when-cross-origin");
    apply_header(&res.headers, HTTP_HEADER_PERMISSIONS_POLICY,
                 "geolocation=(), camera=(), microphone=()");
    apply_header(&res.headers, HTTP_HEADER_ACCEPT_RANGES, "bytes");
    apply_header(&res.headers, HTTP_HEADER_VARY, HTTP_HEADER_ACCEPT_ENCODING);

    int fields =
        sscanf(buf, "%7s %511s %15s", req.method, req.path, req.version);

    if (fields != 3) {
        res.status = 400;
        return;
    }

    /* RFC 9112 §3.1: Request-Line must be method SP target SP version CRLF */
    HTTP_ASSERT_MSG(fields == 3, "RFC 9112 §3.1: request-line must have 3 fields");
    /* RFC 9112 §3.1: HTTP-version must match HTTP/x.y */
    HTTP_ASSERT_MSG(is_valid_http_version(req.version),
                    "RFC 9112 §3.1: invalid HTTP version");
    /* RFC 9110 §3.2: request-target must start with '/' or be '*' for OPTIONS */
    HTTP_ASSERT_MSG(is_valid_request_target(req.path, req.method),
                    "RFC 9110 §3.2: invalid request-target");

    printf("%s:%u %s %s -> %d\n", ip, client_port, req.method, req.path,
           res.status);

    parse_headers(buf, total, &req);

    /* RFC 9112 §3.2: Host header mandatory in HTTP/1.1 (check after parsing) */
#ifndef NDEBUG
    if (strcmp(req.version, "HTTP/1.1") == 0) {
        bool has_host = false;
        for (size_t i = 0; i < req.headers.count; i++) {
            if (strcasecmp(req.headers.items[i].key,
                           HTTP_HEADER_HOST) == 0) {
                has_host = true;
                break;
            }
        }
        HTTP_ASSERT_MSG(has_host,
                        "RFC 9112 §3.2: Host header mandatory in HTTP/1.1");
    }
#endif

    if (apply_middleware(server, &req, &res)) {
        if (execute_handler(server, &req, &res) != 0) {
            res.status = HTTP_STATUS_NOT_FOUND;
        }
    }

    if (res.status == 0) {
        res.status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

    /* RFC 9110 §15: validate status before encoding and sending */
    HTTP_ASSERT_MSG(is_valid_status_code(res.status),
                    "RFC 9110 §15: status code must be 100-599 before send");
    HTTP_ASSERT_MSG(res.body_len <= sizeof(res.body),
                "body_len exceeds body buffer — buffer overflow");

    http_encode_body(server, &req, &res);

    /* RFC 9110 §8.6: Content-Length must match actual body size sent */
    if (res.encoded_body != NULL) {
        HTTP_ASSERT(res.encoded_body_len > 0);
    }

    send_res(&res, client_fd);
    http_headers_free(&res.headers);
    http_headers_free(&req.headers);
}

HttpServerResult http_create_server(const ServerArgs *server_args,
                                    HttpServer *out)
{
    HTTP_ASSERT(server_args != NULL);
    HTTP_ASSERT(out != NULL);
    HTTP_ASSERT(server_args->bind_addr != NULL);
    HTTP_ASSERT(server_args->port > 0);
    HTTP_ASSERT(server_args->server_name != NULL);

    if (out == NULL || server_args == NULL) {
        return SERVER_ERROR;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return SERVER_ERROR;
    }

    int yes = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct addrinfo hints;
    struct addrinfo *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(server_args->bind_addr, NULL, &hints, &res);
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
    addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("failed to bind port");
        close(server_fd);
        freeaddrinfo(res);
        return SERVER_ERROR;
    }

    freeaddrinfo(res);

    if (listen(server_fd, 10) < 0) {
        perror("failed to listen");
        close(server_fd);
        return SERVER_ERROR;
    }

    out->routes = malloc(HTTP_ROUTE_INITIAL_CAP * sizeof(HttpRoute));
    out->route_count = 0;
    out->route_capacity = HTTP_ROUTE_INITIAL_CAP;
    if (out->routes == NULL) {
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
    out->server_name = server_args->server_name;
    return SERVER_OK;
}

void http_close_server(HttpServer *server)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(server->fd >= 0);
    HTTP_ASSERT(server->routes != NULL || server->route_count == 0);

    if (server->fd) {
        close(server->fd);
    }
    free(server->routes);
    server->routes = NULL;
    server->route_count = server->route_capacity = 0;

    free(server->middlewares);
    server->middlewares = NULL;
    server->middleware_count = server->middleware_capacity = 0;

    free(server->encoders);
    server->encoders = NULL;
    server->encoder_count = server->encoder_capacity = 0;
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
            perror("accept");
            continue;
        }

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
    HTTP_ASSERT(server->route_count <= server->route_capacity);

    if (server->route_count == server->route_capacity) {
        size_t new_cap = server->route_capacity * 2;
        HttpRoute *tmp = realloc(server->routes, new_cap * sizeof(HttpRoute));
        if (!tmp) {
            return HTTP_ROUTE_ADD_ERROR;
        }
        server->routes = tmp;
        server->route_capacity = new_cap;
    }

    for (size_t i = 0; i < server->route_count; i++) {
        if (server->routes[i].method == method &&
            server->routes[i].path == path) {
            return HTTP_ROUTE_ADD_CONFLICT;
        }
    }

    server->routes[server->route_count++] =
        (HttpRoute){.path = path, .handler = handler, .method = method};

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
    if (server->middleware_count == server->middleware_capacity) {
        size_t new_cap = server->middleware_capacity == 0
                             ? 8
                             : server->middleware_capacity * 2;
        HttpMiddleware *tmp =
            realloc(server->middlewares, new_cap * sizeof(HttpMiddleware));
        if (!tmp) {
            return HTTP_MIDDLEWARE_ADD_ERROR;
        }
        server->middlewares = tmp;
        server->middleware_capacity = new_cap;
    }

    server->middlewares[server->middleware_count++] =
        (HttpMiddleware){.path = path, .handler = handler};

    return HTTP_MIDDLEWARE_ADD_OK;
}

HttpSetHeaderResult http_set_header(HttpHeaders *headers, char *key,
                                    char *value)
{
    HTTP_ASSERT(headers != NULL);
    HTTP_ASSERT(key != NULL);
    HTTP_ASSERT(value != NULL);
    HTTP_ASSERT_MSG(is_valid_header_name(key),
                    "RFC 9110 §5.5: header name must be a valid token");
    HTTP_ASSERT_MSG(!header_value_has_injection(value),
                    "RFC 9110 §5.6: header value must not contain CR/LF");

    if (apply_header(headers, key, value) < 0) {
        return HTTP_SET_HEADER_ERROR;
    }
    return HTTP_SET_HEADER_OK;
}
