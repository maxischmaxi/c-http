/* Integration + unit tests for the c-http library.
 *
 * Runs a real server in a thread and talks raw HTTP over sockets, so the
 * whole path (parsing, routing, middleware, encoding, responses) is
 * covered. An alarm() watchdog fails the test if anything deadlocks.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
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
#include <time.h>
#include <unistd.h>

#include "c_http.h"
#include "c_http_static.h"
#include "test.h"

#define TEST_PORT_START 18431
#define TEST_PORT_END   18450

/* ------------------------------------------------------------------ */
/* handlers                                                            */
/* ------------------------------------------------------------------ */

static void h_root(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = HTTP_STATUS_OK;
    memcpy(res->body, "ok", 2);
    res->body_len = 2;
}

static void h_big(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = HTTP_STATUS_OK;
    memset(res->body, 'A', sizeof(res->body));
    res->body_len = sizeof(res->body);
}

static void h_echo(const HttpRequest *req, HttpResponse *res)
{
    res->status = HTTP_STATUS_OK;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, "text/plain");
    if (req->body != NULL) {
        size_t n = req->body_len < sizeof(res->body) - 1
                       ? req->body_len
                       : sizeof(res->body) - 1;
        memcpy(res->body, req->body, n);
        res->body_len = n;
    }
}

static bool auth_mw_ran = false;

static HttpMiddlewareResult h_auth_mw(const HttpRequest *req, HttpResponse *res)
{
    (void)res;
    auth_mw_ran = true;
    if (strncmp(req->path, "/private", 8) == 0) {
        for (size_t i = 0; i < req->headers.count; i++) {
            if (strcasecmp(req->headers.items[i].key,
                           HTTP_HEADER_AUTHORIZATION) == 0) {
                return HTTP_MIDDLEWARE_CONTINUE;
            }
        }
        res->status = HTTP_STATUS_UNAUTHORIZED;
        return HTTP_MIDDLEWARE_STOP;
    }
    return HTTP_MIDDLEWARE_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* client helpers                                                      */
/* ------------------------------------------------------------------ */

static HttpServer g_srv;
static bool g_srv_ready = false;
static uint16_t g_port = 0;

static void *server_thread(void *arg)
{
    (void)arg;
    http_listen(&g_srv);
    return NULL;
}

static size_t raw_request(uint16_t port, const void *data, size_t len,
                          char *out, size_t outsz)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 0;
    }

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return 0;
    }

    size_t sent = 0;
    while (sent < len) {
        ssize_t s = send(fd, (const char *)data + sent, len - sent, 0);
        if (s <= 0) {
            break;
        }
        sent += (size_t)s;
    }

    size_t total = 0;
    while (total + 1 < outsz) {
        ssize_t r = recv(fd, out + total, outsz - 1 - total, 0);
        if (r <= 0) {
            break;
        }
        total += (size_t)r;
    }
    out[total] = '\0';
    close(fd);
    return total;
}

static size_t get(const char *req, char *out, size_t outsz)
{
    return raw_request(g_port, req, strlen(req), out, outsz);
}

static bool wait_listening(uint16_t port)
{
    for (int i = 0; i < 200; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            close(fd);
            return true;
        }
        close(fd);
        nanosleep(
            &(struct timespec){.tv_nsec = (__syscall_slong_t)20 * 1000 * 1000},
            NULL);
    }
    return false;
}

static int count_occurrences(const char *haystack, const char *needle)
{
    int n = 0;
    const char *p = haystack;
    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += strlen(needle);
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* unit tests (no server needed)                                       */
/* ------------------------------------------------------------------ */

static void test_accepts_encoding(void)
{
    HttpRequest req = {0};

    /* no Accept-Encoding -> nothing accepted */
    CHECK(http_accepts_encoding(&req, "gzip") == false);

    struct {
        const char *value;
        bool expect_gzip;
        const char *label;
    } cases[] = {
        {"gzip", true, "plain gzip"},
        {"deflate, gzip;q=1.0", true, "gzip;q=1.0"},
        {"gzip;q=0", false, "gzip;q=0 forbidden"},
        {"gzip;q=0.0", false, "gzip;q=0.0 forbidden"},
        {"*", true, "wildcard"},
        {"gzip;q=0, *", false, "explicit q=0 beats wildcard"},
        {"br, *", true, "wildcard for unnamed coding"},
        {"GZIP", true, "case-insensitive"},
        {"gzipx", false, "no prefix match"},
        {"xgzip", false, "no suffix match"},
        {"gzip;q=0.5;foo=bar", true, "q with parameters"},
        {"deflate, br", false, "gzip not listed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        http_set_header(&req.headers, HTTP_HEADER_ACCEPT_ENCODING,
                        cases[i].value);
        bool got = http_accepts_encoding(&req, "gzip");
        CHECK_MSG(got == cases[i].expect_gzip, cases[i].label);
        http_headers_free(&req.headers);
    }

    /* multiple Accept-Encoding headers are all considered */
    http_set_header(&req.headers, HTTP_HEADER_ACCEPT_ENCODING, "deflate");
    http_set_header(&req.headers, HTTP_HEADER_ACCEPT_ENCODING, "gzip");
    CHECK(http_accepts_encoding(&req, "gzip") == true);
    http_headers_free(&req.headers);
}

static void test_set_header_validation(void)
{
    HttpHeaders h = {0};

    /* header injection must be rejected — also in release builds */
    CHECK(http_set_header(&h, "X-Test", "value\r\nSet-Cookie: pwned=1") ==
          HTTP_SET_HEADER_ERROR);
    CHECK(http_set_header(&h, "X-Test", "value\nSet-Cookie: pwned=1") ==
          HTTP_SET_HEADER_ERROR);

    /* invalid field names */
    CHECK(http_set_header(&h, "Bad Name", "value") == HTTP_SET_HEADER_ERROR);
    CHECK(http_set_header(&h, "", "value") == HTTP_SET_HEADER_ERROR);
    CHECK(http_set_header(&h, "X-Test:", "value") == HTTP_SET_HEADER_ERROR);
    CHECK(http_set_header(&h, "X-Bad\x01Name", "value") ==
          HTTP_SET_HEADER_ERROR);

    /* valid */
    CHECK(http_set_header(&h, "X-Test", "value") == HTTP_SET_HEADER_OK);
    CHECK(h.count == 1);

    http_headers_free(&h);
}

static void test_route_limits(void)
{
    ServerArgs args = {.port = 0, .bind_addr = "127.0.0.1", .server_name = "t"};
    HttpServer srv;
    CHECK(http_create_server(&args, &srv) == SERVER_OK);

    /* a route longer than HTTP_PATH_MAX can never match -> reject */
    char long_path[HTTP_PATH_MAX + 2];
    long_path[0] = '/';
    memset(long_path + 1, 'a', HTTP_PATH_MAX);
    long_path[HTTP_PATH_MAX + 1] = '\0';
    CHECK(http_get(&srv, long_path, h_root) == HTTP_ROUTE_ADD_ERROR);

    /* conflict detection */
    CHECK(http_get(&srv, "/x", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&srv, "/x", h_root) == HTTP_ROUTE_ADD_CONFLICT);
    CHECK(http_post(&srv, "/x", h_root) == HTTP_ROUTE_ADD_OK);

    /* group: prefix too long -> truncation is detected */
    char big_prefix[600];
    big_prefix[0] = '/';
    memset(big_prefix + 1, 'p', sizeof(big_prefix) - 2);
    big_prefix[sizeof(big_prefix) - 1] = '\0';
    HttpGroup g = http_group(&srv, big_prefix);
    CHECK(http_group_get(&g, "/deep", h_root) == HTTP_ROUTE_ADD_ERROR);

    /* fd == -1 and double close must survive */
    http_close_server(&srv);
    http_close_server(&srv);

    /* ServerArgs with NULL values */
    HttpServer srv2;
    ServerArgs bad = {0};
    CHECK(http_create_server(&bad, &srv2) == SERVER_ERROR);
}

static void test_group_paths(void)
{
    ServerArgs args = {.port = 0, .bind_addr = "127.0.0.1", .server_name = "t"};
    HttpServer srv;
    CHECK(http_create_server(&args, &srv) == SERVER_OK);

    HttpGroup api = http_group(&srv, "/api");
    CHECK(http_group_get(&api, "/users", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_group_get(&api, "/", h_root) == HTTP_ROUTE_ADD_OK);

    /* "/api/users" and "/api" registered */
    bool found_users = false, found_api = false;
    for (size_t i = 0; i < srv.routes.count; i++) {
        if (strcmp(srv.routes.routes[i].path, "/api/users") == 0) {
            found_users = true;
        }
        if (strcmp(srv.routes.routes[i].path, "/api") == 0) {
            found_api = true;
        }
    }
    CHECK(found_users);
    CHECK(found_api);

    http_close_server(&srv);
}

/* ------------------------------------------------------------------ */
/* integration tests                                                   */
/* ------------------------------------------------------------------ */

static void test_integration(void)
{
    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs args = {.port = (uint16_t)port,
                           .bind_addr = "127.0.0.1",
                           .server_name = "test"};
        if (http_create_server(&args, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created) {
        return;
    }
    g_port = g_srv.port;

    http_middleware(&g_srv, NULL, h_auth_mw);
    http_get(&g_srv, "/", h_root);
    http_get(&g_srv, "/big", h_big);
    http_get(&g_srv, "/only-get", h_root);
    http_post(&g_srv, "/echo", h_echo);
    http_get(&g_srv, "/private/x", h_root);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[64 * 1024];
    size_t n;

    /* 1) GET / -> 200 + body + exactly ONE Content-Type */
    n = get("GET / HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(count_occurrences(rsp, "Content-Type:") == 1);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 2) the query string is split off */
    n = get("GET /?x=1&y=2 HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);

    /* 3) HEAD falls back to GET and sends no body */
    n = get("HEAD / HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Length: 2") != NULL);
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0); /* no body */

    /* 4) wrong method -> 405 + Allow */
    n = get("POST /only-get HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 405", 12) == 0);
    CHECK(strstr(rsp, "Allow: GET") != NULL);

    /* 5) unknown/overlong method -> 501 */
    n = get("PROPFINDX / HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 501", 12) == 0);

    /* 6) broken request line -> 400, a response IS sent */
    n = get("GARBAGE\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 400", 12) == 0);

    /* 7) two-field request line -> 400 */
    n = get("GET /\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 400", 12) == 0);

    /* 8) overlong URI -> 414 */
    char long_req[1024];
    strcpy(long_req, "GET /");
    for (int i = 0; i < 600; i++) {
        strcat(long_req, "a");
    }
    strcat(long_req, " HTTP/1.1\r\nHost: t\r\n\r\n");
    n = get(long_req, rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 414", 12) == 0);

    /* 9) HTTP/2.0 -> 505 */
    n = get("GET / HTTP/2.0\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 505", 12) == 0);

    /* 10) headers > 4096 bytes -> 431 */
    static char huge[8192];
    memset(huge, 'H', sizeof(huge) - 1);
    memcpy(huge, "GET / HTTP/1.1\r\nHost: t\r\nX-Big: ", 32);
    huge[sizeof(huge) - 5] = '\r';
    huge[sizeof(huge) - 4] = '\n';
    huge[sizeof(huge) - 3] = '\r';
    huge[sizeof(huge) - 2] = '\n';
    huge[sizeof(huge) - 1] = '\0';
    n = get(huge, rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 431", 12) == 0);

    /* 11) Accept-Encoding: gzip -> Content-Encoding: gzip */
    n = get("GET /big HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Encoding: gzip") != NULL);

    /* 12) gzip;q=0 -> NO gzip */
    n = get("GET /big HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip;q=0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Encoding:") == NULL);

    /* 13) gzip;q=0, * -> gzip stays forbidden (explicit beats wildcard) */
    n = get("GET /big HTTP/1.1\r\nHost: t\r\n"
            "Accept-Encoding: gzip;q=0, *\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "Content-Encoding: gzip") == NULL);

    /* 14) the POST body is read and available in the handler */
    n = get("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 11\r\n\r\n"
            "hello world",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nhello world") != NULL);

    /* 15) body with a NUL byte (must go by length, not strlen) */
    {
        static const char head[] =
            "POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\n";
        char body_req[128];
        memcpy(body_req, head, sizeof(head) - 1);
        memcpy(body_req + sizeof(head) - 1, "ab\0cd",
               5); /* memcpy: a
                    * strcpy would stop at the NUL */
        size_t reqlen = sizeof(head) - 1 + 5;
        n = raw_request(g_port, body_req, reqlen, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
        /* find the body in the response (contains a NUL) */
        const char *body_start = strstr(rsp, "\r\n\r\n");
        CHECK(body_start != NULL);
        CHECK((size_t)(body_start + 9 - rsp) <= n);
        CHECK(memcmp(body_start + 4, "ab\0cd", 5) == 0);
    }

    /* 16) differing duplicate Content-Length -> 400 */
    n = get("POST /echo HTTP/1.1\r\nHost: t\r\n"
            "Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 400", 12) == 0);

    /* 17) identical duplicate Content-Length -> ok */
    n = get("POST /echo HTTP/1.1\r\nHost: t\r\n"
            "Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);

    /* 18) Transfer-Encoding -> 501 (unsupported) */
    n = get("POST /echo HTTP/1.1\r\nHost: t\r\n"
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 501", 12) == 0);

    /* 19) middleware STOP: /private without auth -> 401 */
    n = get("GET /private/x HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 401", 12) == 0);
    CHECK(auth_mw_ran);

    /* 20) client holds the connection open and sends nothing ->
     *     the server keeps answering afterwards (the timeout kicks in,
     *     but here we only care that the server stays alive). */
    n = get("GET / HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);

    /* stop the server cleanly (this was impossible before) */
    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

/* ------------------------------------------------------------------ */
/* static file tests                                                   */
/* ------------------------------------------------------------------ */

static int write_test_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return written == len ? 0 : -1;
}

static void test_static_files(void)
{
    /* 1) build a temporary root directory with test files */
    char www[128];
    snprintf(www, sizeof(www), "/tmp/c_http_static_test_%ld", (long)getpid());
    mkdir(www, 0755); /* leftover from a crash: fine */
    char sub[160];
    snprintf(sub, sizeof(sub), "%s/sub", www);
    mkdir(sub, 0755);

    char p[192];
    snprintf(p, sizeof(p), "%s/index.html", www);
    CHECK(write_test_file(p, "<h1>index</h1>", strlen("<h1>index</h1>")) == 0);
    snprintf(p, sizeof(p), "%s/style.css", www);
    CHECK(write_test_file(p, "body {}", 7) == 0);
    snprintf(p, sizeof(p), "%s/sub/data.json", www);
    CHECK(write_test_file(p, "[1,2,3]", 7) == 0);

    /* > 4 KiB: deliberately larger than the body buffer (streaming path) */
    static char big[8192];
    memset(big, 'B', sizeof(big));
    snprintf(p, sizeof(p), "%s/big.bin", www);
    CHECK(write_test_file(p, big, sizeof(big)) == 0);

    /* symlink pointing out of the root directory */
    snprintf(p, sizeof(p), "%s/evil", www);
    (void)symlink("/etc/passwd", p);

    /* 2) set up server + mount */
    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs args = {.port = (uint16_t)port,
                           .bind_addr = "127.0.0.1",
                           .server_name = "test"};
        if (http_create_server(&args, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created) {
        return;
    }
    g_port = g_srv.port;

    CHECK(http_static_mount(&g_srv, &(HttpStaticConfig){
                                        .prefix = "/static",
                                        .root = www,
                                        .index_file = "index.html",
                                        .max_age = 60,
                                    }) == SERVER_OK);

    /* invalid mounts: duplicate / broken prefix / missing root */
    CHECK(http_static_mount(&g_srv, &(HttpStaticConfig){
                                        .prefix = "/static",
                                        .root = www,
                                    }) == SERVER_ERROR);
    CHECK(http_static_mount(&g_srv, &(HttpStaticConfig){
                                        .prefix = "/pct%2f",
                                        .root = www,
                                    }) == SERVER_ERROR);
    CHECK(http_static_mount(&g_srv, &(HttpStaticConfig){
                                        .prefix = "/other",
                                        .root = "/does/not/exist",
                                    }) == SERVER_ERROR);

    /* exact route wins over the mount */
    http_get(&g_srv, "/static/route.txt", h_root);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[32 * 1024];
    size_t n;

    /* GET index: /static/ (empty suffix) -> index.html */
    n = get("GET /static/ HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Type: text/html") != NULL);
    CHECK(strstr(rsp, "Cache-Control: public, max-age=60") != NULL);
    CHECK(strstr(rsp, "\r\n\r\n<h1>index</h1>") != NULL);

    /* GET without a trailing slash matches the mount too */
    n = get("GET /static HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);

    /* GET subdirectory + MIME type */
    n = get("GET /static/sub/data.json HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Type: application/json") != NULL);
    CHECK(strstr(rsp, "\r\n\r\n[1,2,3]") != NULL);

    /* CSS MIME type + remember the ETag for the 304 test */
    n = get("GET /static/style.css HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "Content-Type: text/css") != NULL);
    char etag[64] = "";
    const char *etag_pos = strstr(rsp, "ETag: ");
    CHECK(etag_pos != NULL);
    if (etag_pos != NULL) {
        const char *eol = strstr(etag_pos, "\r\n");
        CHECK(eol != NULL);
        size_t elen = (size_t)(eol - (etag_pos + 6));
        CHECK(elen < sizeof(etag));
        memcpy(etag, etag_pos + 6, elen);
        etag[elen] = '\0';
    }

    /* large file: streamed, exactly 8192 bytes, no truncation */
    n = get("GET /static/big.bin HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Length: 8192") != NULL);
    {
        const char *body = strstr(rsp, "\r\n\r\n");
        CHECK(body != NULL);
        if (body != NULL) {
            body += 4;
            CHECK((size_t)(rsp + n - body) == 8192);
            bool all_b = true;
            for (size_t i = 0; i < 8192; i++) {
                if (body[i] != 'B') {
                    all_b = false;
                    break;
                }
            }
            CHECK(all_b);
        }
    }

    /* HEAD on the large file: headers like GET, but no body */
    n = get("HEAD /static/big.bin HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Length: 8192") != NULL);
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0);

    /* 404: missing file */
    n = get("GET /static/nope.html HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 404: raw traversal (..) */
    n = get("GET /static/../secret HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 404: URL-encoded traversal (%2e%2e) */
    n = get("GET /static/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\n"
            "Host: t\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 400: NUL injection (%00) */
    n = get("GET /static/%00x HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 400", 12) == 0);

    /* 404: symlink escape out of the root directory */
    n = get("GET /static/evil HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 404: prefix boundary (/static-x is not part of the mount) */
    n = get("GET /static-x HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 405: POST on a mounted file */
    n = get("POST /static/style.css HTTP/1.1\r\nHost: t\r\n"
            "Content-Length: 0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 405", 12) == 0);
    CHECK(strstr(rsp, "Allow: GET, HEAD") != NULL);

    /* 304: If-None-Match with the ETag from the first response */
    if (etag[0] != '\0') {
        char req[256];
        snprintf(req, sizeof(req),
                 "GET /static/style.css HTTP/1.1\r\nHost: t\r\n"
                 "If-None-Match: %s\r\n\r\n",
                 etag);
        n = get(req, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 304", 12) == 0);
        CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0);
    }

    /* exact route wins over the mount (body "ok", not file content) */
    n = get("GET /static/route.txt HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 3) tear down and remove the test files */
    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);

    snprintf(p, sizeof(p), "%s/evil", www);
    unlink(p);
    snprintf(p, sizeof(p), "%s/index.html", www);
    unlink(p);
    snprintf(p, sizeof(p), "%s/style.css", www);
    unlink(p);
    snprintf(p, sizeof(p), "%s/big.bin", www);
    unlink(p);
    snprintf(p, sizeof(p), "%s/sub/data.json", www);
    unlink(p);
    rmdir(sub);
    rmdir(www);
}

/* Echoes specific headers + req.ip + req.client_port into the body —
 * for http_req_header() and req.ip integration tests. */
static void h_header_echo(const HttpRequest *req, HttpResponse *res)
{
    res->status = HTTP_STATUS_OK;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, "text/plain");
    const char *ua = http_req_header(req, "UsEr-AgEnT");
    const char *x = http_req_header(req, "X-Missing");
    int n = snprintf(res->body, sizeof(res->body), "ip=%s port=%u ua=%s x=%s",
                     req->ip, (unsigned)req->client_port, ua != NULL ? ua : "-",
                     x != NULL ? x : "-");
    if (n > 0) {
        res->body_len =
            (size_t)n < sizeof(res->body) ? (size_t)n : sizeof(res->body) - 1;
    }
}

/* Echoes query-string values — for http_req_query() integration tests. */
static void h_query_echo(const HttpRequest *req, HttpResponse *res)
{
    res->status = HTTP_STATUS_OK;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, "text/plain");
    const char *a = http_req_query(req, "a");
    const char *name = http_req_query(req, "name");
    const char *flag = http_req_query(req, "flag");
    const char *missing = http_req_query(req, "missing");
    int n = snprintf(res->body, sizeof(res->body),
                     "a=%s name=%s flag=%s missing=%s count=%zu",
                     a != NULL ? a : "-", name != NULL ? name : "-",
                     flag != NULL ? flag : "-", missing != NULL ? missing : "-",
                     req->query.count);
    if (n > 0) {
        res->body_len =
            (size_t)n < sizeof(res->body) ? (size_t)n : sizeof(res->body) - 1;
    }
}

/* Param + query combined: route param and query coexist on one route. */
static void h_param_query_echo(const HttpRequest *req, HttpResponse *res)
{
    res->status = HTTP_STATUS_OK;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, "text/plain");
    const char *id = http_req_param(req, "id");
    const char *page = http_req_query(req, "page");
    int n = snprintf(res->body, sizeof(res->body), "id=%s page=%s",
                     id != NULL ? id : "-", page != NULL ? page : "-");
    if (n > 0) {
        res->body_len =
            (size_t)n < sizeof(res->body) ? (size_t)n : sizeof(res->body) - 1;
    }
}

/* Echoes locals — for http_set_local()/http_res_local() tests. */
static void h_local_echo(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = HTTP_STATUS_OK;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, "text/plain");
    const char *user = http_res_local(res, "user");
    const char *missing = http_res_local(res, "missing");
    int n =
        snprintf(res->body, sizeof(res->body), "user=%s missing=%s",
                 user != NULL ? user : "-", missing != NULL ? missing : "-");
    if (n > 0) {
        res->body_len =
            (size_t)n < sizeof(res->body) ? (size_t)n : sizeof(res->body) - 1;
    }
}

/* Two middlewares for the overwrite semantics: the first sets "user",
 * the second overwrites it — the handler must see the LAST value. */
static HttpMiddlewareResult local_mw_1(const HttpRequest *req,
                                       HttpResponse *res)
{
    (void)req;
    http_set_local(res, "user", "alice");
    return HTTP_MIDDLEWARE_CONTINUE;
}

static HttpMiddlewareResult local_mw_2(const HttpRequest *req,
                                       HttpResponse *res)
{
    (void)req;
    CHECK(http_set_local(res, "user", "bob") == HTTP_SET_LOCAL_OK);
    return HTTP_MIDDLEWARE_CONTINUE;
}

/* Reads a response header in tests (http_req_header is for requests). */
static const char *res_header(const HttpResponse *res, const char *key)
{
    for (size_t i = 0; i < res->headers.count; i++) {
        if (strcasecmp(res->headers.items[i].key, key) == 0) {
            return res->headers.items[i].value;
        }
    }
    return NULL;
}

/* Counts response headers with the given key. */
static size_t res_header_count(const HttpResponse *res, const char *key)
{
    size_t n = 0;
    for (size_t i = 0; i < res->headers.count; i++) {
        if (strcasecmp(res->headers.items[i].key, key) == 0) {
            n++;
        }
    }
    return n;
}

static void h_erroring(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    http_error(res, 422, "bad input");
}

/* http_error with a success status: must be coerced to 500. */
static void h_erroring_coerce(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    http_error(res, 200, "this is not a success");
}

/* Uniform JSON error pages — the point of the central error handler.
 * Must tolerate a partially parsed req (empty path for protocol
 * errors). The message is trusted here (test/demo code); production
 * code would escape quotes. */
static void json_error_handler(const HttpRequest *req, HttpResponse *res,
                               int status, const char *message)
{
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
                     "{\"status\":%d,\"message\":\"%s\",\"path\":\"%s\"}",
                     status, message, req->path[0] != '\0' ? req->path : "-");
    if (n > 0 && (size_t)n < sizeof(buf)) {
        (void)http_res_json(res, status, buf);
    }
}

static HttpMiddlewareResult stop_401_mw(const HttpRequest *req,
                                        HttpResponse *res)
{
    (void)req;
    /* Intentional response with its OWN body — the error handler must
     * NOT reformat it. */
    res->status = HTTP_STATUS_UNAUTHORIZED;
    memcpy(res->body, "custom 401", 10);
    res->body_len = 10;
    return HTTP_MIDDLEWARE_STOP;
}

/* Echoes form fields + body type — for http_req_form()/body_type tests. */
static void h_form_echo(const HttpRequest *req, HttpResponse *res)
{
    res->status = HTTP_STATUS_OK;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, "text/plain");
    const char *a = http_req_form(req, "a");
    const char *name = http_req_form(req, "name");
    const char *missing = http_req_form(req, "missing");
    int n = snprintf(res->body, sizeof(res->body),
                     "a=%s name=%s missing=%s type=%d", a != NULL ? a : "-",
                     name != NULL ? name : "-", missing != NULL ? missing : "-",
                     (int)http_req_body_type(req));
    if (n > 0) {
        res->body_len =
            (size_t)n < sizeof(res->body) ? (size_t)n : sizeof(res->body) - 1;
    }
}

/* Echoes a JSON string field — for http_req_json_string() tests. */
static void h_json_echo(const HttpRequest *req, HttpResponse *res)
{
    res->status = HTTP_STATUS_OK;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, "text/plain");
    char name[128];
    int n = http_req_json_string(req, "name", name, sizeof(name));
    char missing[16];
    int m = http_req_json_string(req, "missing", missing, sizeof(missing));
    int w = snprintf(res->body, sizeof(res->body), "name=%s m=%d",
                     n >= 0 ? name : "-", m);
    if (w > 0) {
        res->body_len =
            (size_t)w < sizeof(res->body) ? (size_t)w : sizeof(res->body) - 1;
    }
}

/* Explicit OPTIONS route — beats the auto-response. */
static void h_options_manual(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = HTTP_STATUS_OK;
    memcpy(res->body, "manual options", 14);
    res->body_len = 14;
}

/* Picks between two representions via content negotiation. */
static void h_accepts_echo(const HttpRequest *req, HttpResponse *res)
{
    res->status = HTTP_STATUS_OK;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, "text/plain");
    const char *const offers[] = {"application/json", "text/html", NULL};
    const char *pick = http_req_accepts(req, offers);
    int n = snprintf(res->body, sizeof(res->body), "pick=%s",
                     pick != NULL ? pick : "-");
    if (n > 0) {
        res->body_len =
            (size_t)n < sizeof(res->body) ? (size_t)n : sizeof(res->body) - 1;
    }
}

static void h_param(const HttpRequest *req, HttpResponse *res)
{
    res->status = HTTP_STATUS_OK;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, "text/plain");
    const char *id = http_req_param(req, "id");
    const char *name = http_req_param(req, "name");
    int n = snprintf(res->body, sizeof(res->body), "id=%s name=%s",
                     id != NULL ? id : "-", name != NULL ? name : "-");
    if (n > 0) {
        res->body_len =
            (size_t)n < sizeof(res->body) ? (size_t)n : sizeof(res->body) - 1;
    }
}

/* ------------------------------------------------------------------ */
/* route params: registration limits (unit)                           */
/* ------------------------------------------------------------------ */

static void test_param_registration(void)
{
    ServerArgs args = {.port = 0, .bind_addr = "127.0.0.1", .server_name = "t"};
    HttpServer srv;
    CHECK(http_create_server(&args, &srv) == SERVER_OK);

    /* --- valid patterns --- */
    CHECK(http_get(&srv, "/users/:id", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&srv, "/:id", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&srv, "/:a/:b/:c", h_root) == HTTP_ROUTE_ADD_OK);

    /* exactly HTTP_MAX_PARAMS (16) params: still fine */
    {
        char pattern[128];
        size_t off = (size_t)snprintf(pattern, sizeof(pattern), "/p");
        for (size_t i = 0; i < HTTP_MAX_PARAMS; i++) {
            off += (size_t)snprintf(pattern + off, sizeof(pattern) - off,
                                    "/:p%zu", i);
        }
        CHECK(off < sizeof(pattern));
        CHECK(http_get(&srv, pattern, h_root) == HTTP_ROUTE_ADD_OK);
    }

    /* param name of HTTP_PARAM_KEY_MAX-1 chars (excluding the ':'):
     * the longest one that fits */
    {
        char name[40];
        name[0] = ':';
        memset(name + 1, 'n', HTTP_PARAM_KEY_MAX - 2);
        name[HTTP_PARAM_KEY_MAX - 1] = '\0';
        char pattern[64];
        snprintf(pattern, sizeof(pattern), "/x/%s", name);
        CHECK(http_get(&srv, pattern, h_root) == HTTP_ROUTE_ADD_OK);
    }

    /* literal segment of 63 chars: max that fits into text[64] */
    {
        char pattern[80];
        size_t off = (size_t)snprintf(pattern, sizeof(pattern), "/x/");
        memset(pattern + off, 'a', 63);
        pattern[off + 63] = '\0';
        CHECK(http_get(&srv, pattern, h_root) == HTTP_ROUTE_ADD_OK);
    }

    /* trailing slash on a param route: same shape, different string,
     * both are allowed (first registered wins at request time) */
    CHECK(http_get(&srv, "/users/:id/", h_param) == HTTP_ROUTE_ADD_OK);

    /* same shape, different param names: allowed (first wins) */
    CHECK(http_get(&srv, "/users/:name", h_root) == HTTP_ROUTE_ADD_OK);

    /* case-sensitive param names are distinct */
    CHECK(http_get(&srv, "/case/:ID", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&srv, "/case/:id", h_root) == HTTP_ROUTE_ADD_OK);

    /* --- rejected patterns (fail fast at registration) --- */

    /* one param too many (17 > HTTP_MAX_PARAMS) */
    {
        char pattern[128];
        size_t off = (size_t)snprintf(pattern, sizeof(pattern), "/p");
        for (size_t i = 0; i <= HTTP_MAX_PARAMS; i++) {
            off += (size_t)snprintf(pattern + off, sizeof(pattern) - off,
                                    "/:p%zu", i);
        }
        CHECK(off < sizeof(pattern));
        CHECK(http_get(&srv, pattern, h_root) == HTTP_ROUTE_ADD_ERROR);
    }

    /* param name of HTTP_PARAM_KEY_MAX chars (excluding the ':'):
     * one over the buffer — the parser strips the leading ':' */
    {
        char name[40];
        name[0] = ':';
        memset(name + 1, 'n', HTTP_PARAM_KEY_MAX);
        name[HTTP_PARAM_KEY_MAX + 1] = '\0';
        char pattern[64];
        snprintf(pattern, sizeof(pattern), "/x/%s", name);
        CHECK(http_get(&srv, pattern, h_root) == HTTP_ROUTE_ADD_ERROR);
    }

    /* literal segment of 64 chars: one char over the segment buffer */
    {
        char pattern[80];
        size_t off = (size_t)snprintf(pattern, sizeof(pattern), "/x/");
        memset(pattern + off, 'a', 64);
        pattern[off + 64] = '\0';
        CHECK(http_get(&srv, pattern, h_root) == HTTP_ROUTE_ADD_ERROR);
    }

    /* duplicate param names: ambiguous — rejected (Express parity) */
    CHECK(http_get(&srv, "/dup/:id/x/:id", h_root) == HTTP_ROUTE_ADD_ERROR);
    CHECK(http_get(&srv, "/dup2/:id/:id", h_root) == HTTP_ROUTE_ADD_ERROR);

    /* '?' can never match (query string is stripped before routing) */
    CHECK(http_get(&srv, "/q/:id?a=1", h_root) == HTTP_ROUTE_ADD_ERROR);
    CHECK(http_get(&srv, "/q?x", h_root) == HTTP_ROUTE_ADD_ERROR);

    /* bare ':' without a name */
    CHECK(http_get(&srv, "/:", h_root) == HTTP_ROUTE_ADD_ERROR);
    CHECK(http_get(&srv, "/x/:/y", h_root) == HTTP_ROUTE_ADD_ERROR);

    /* ':' mid-segment is a LITERAL, not a param marker (only a leading
     * ':' starts a param) — registers fine, matches via strcmp */
    CHECK(http_get(&srv, "/lit/a:b", h_root) == HTTP_ROUTE_ADD_OK);

    /* same string twice: conflict (string comparison, as documented) */
    CHECK(http_get(&srv, "/users/:id", h_root) == HTTP_ROUTE_ADD_CONFLICT);

    /* double close must survive (frees the route segments) */
    http_close_server(&srv);
    http_close_server(&srv);
}

static void test_route_params(void)
{
    ServerArgs args = {.port = 0, .bind_addr = "127.0.0.1", .server_name = "t"};
    HttpServer srv;
    CHECK(http_create_server(&args, &srv) == SERVER_OK);

    /* unit: http_req_param on an empty request */
    HttpRequest empty = {0};
    CHECK(http_req_param(&empty, "id") == NULL);
    CHECK(http_req_param(NULL, "id") == NULL);
    CHECK(http_req_param(&empty, NULL) == NULL);

    /* registration validation */
    CHECK(http_get(&srv, "/", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&srv, "/users/:id", h_param) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&srv, "/users/new", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&srv, "/users/:id/files/:name", h_param) ==
          HTTP_ROUTE_ADD_OK);
    /* same pattern twice: conflict */
    CHECK(http_get(&srv, "/users/:id", h_param) == HTTP_ROUTE_ADD_CONFLICT);
    /* bare ':' and oversized param names are registration errors */
    CHECK(http_get(&srv, "/bad/:", h_root) == HTTP_ROUTE_ADD_ERROR);
    CHECK(http_get(&srv, "/bad/:/x", h_root) == HTTP_ROUTE_ADD_ERROR);
    {
        char long_name[80];
        long_name[0] = ':';
        memset(long_name + 1, 'p', sizeof(long_name) - 2);
        long_name[sizeof(long_name) - 1] = '\0';
        char pattern[96];
        snprintf(pattern, sizeof(pattern), "/x%s", long_name);
        CHECK(http_get(&srv, pattern, h_root) == HTTP_ROUTE_ADD_ERROR);
    }

    /* routes for dispatch tests on a live server */
    CHECK(http_get(&srv, "/literal", h_root) == HTTP_ROUTE_ADD_OK);
    http_post(&srv, "/literal", h_root);

    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    /* literal BEFORE the :id route — first match wins (Express
     * semantics: registration order decides between matching routes) */
    http_get(&g_srv, "/users/new", h_root);
    http_get(&g_srv, "/users/:id", h_param);
    http_get(&g_srv, "/users/:id/files/:name", h_param);
    http_get(&g_srv, "/literal", h_root);
    http_post(&g_srv, "/literal", h_root);
    http_get(&g_srv, "/", h_root);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[64 * 1024];
    size_t n;

    /* 1) single param bound */
    n = get("GET /users/42 HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=42 name=-") != NULL);

    /* 2) two params bound */
    n = get("GET /users/7/files/a.txt HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=7 name=a.txt") != NULL);

    /* 3) segment count mismatch -> 404 */
    n = get("GET /users/42/extra HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 4) literal route wins over param route (registered first) */
    n = get("GET /users/new HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 5) trailing slash matches (empty segment is skipped) */
    n = get("GET /users/42/ HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "id=42") != NULL);

    /* 6) wrong method on a matching param route -> 405 + Allow: GET */
    n = get("POST /users/42 HTTP/1.1\r\nHost: t\r\n"
            "Content-Length: 0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 405", 12) == 0);
    CHECK(strstr(rsp, "Allow: GET") != NULL);

    /* 7) HEAD falls back to the GET param route, no body */
    n = get("HEAD /users/42 HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0);

    /* 8) non-param routes still work exactly as before */
    n = get("GET /literal HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 9) /literal/x is NOT /literal — no prefix semantics on routes */
    n = get("GET /literal/x HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 10) root route still matches */
    n = get("GET / HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
    http_close_server(&srv); /* double close must survive */
}

/* ------------------------------------------------------------------ */
/* route params: attacks, boundaries, interactions (integration)       */
/* ------------------------------------------------------------------ */

/* Auth middleware for /users* — middleware must run BEFORE the param
 * route and must be able to stop the request entirely. */
static HttpMiddlewareResult users_auth_mw(const HttpRequest *req,
                                          HttpResponse *res)
{
    if (strncmp(req->path, "/users", 6) != 0) {
        return HTTP_MIDDLEWARE_CONTINUE;
    }
    for (size_t i = 0; i < req->headers.count; i++) {
        if (strcasecmp(req->headers.items[i].key, HTTP_HEADER_AUTHORIZATION) ==
            0) {
            return HTTP_MIDDLEWARE_CONTINUE;
        }
    }
    res->status = HTTP_STATUS_UNAUTHORIZED;
    return HTTP_MIDDLEWARE_STOP;
}

static void test_params_attacks(void)
{
    /* temp root for the mount tests */
    char www[128];
    snprintf(www, sizeof(www), "/tmp/c_http_params_attack_%ld", (long)getpid());
    mkdir(www, 0755);
    char p[192];
    snprintf(p, sizeof(p), "%s/style.css", www);
    CHECK(write_test_file(p, "body {}", 7) == 0);

    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    /* registration order matters: literal routes BEFORE the catch-all */
    CHECK(http_get(&g_srv, "/users/:id", h_param) == HTTP_ROUTE_ADD_OK);
    CHECK(http_delete(&g_srv, "/users/:id", h_param) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&g_srv, "/files/:name", h_param) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&g_srv, "/exact", h_root) == HTTP_ROUTE_ADD_OK);

    HttpGroup api = http_group(&g_srv, "/api");
    CHECK(http_group_get(&api, "/users/:id", h_param) == HTTP_ROUTE_ADD_OK);

    CHECK(http_static_mount(&g_srv, &(HttpStaticConfig){
                                        .prefix = "/static",
                                        .root = www,
                                    }) == SERVER_OK);

    http_middleware(&g_srv, "/users", users_auth_mw);

    /* catch-all LAST: would otherwise shadow every single-segment route */
    CHECK(http_get(&g_srv, "/:id", h_param) == HTTP_ROUTE_ADD_OK);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[32 * 1024];
    size_t n;

    /* --- middleware + params --- */

    /* 1) middleware stops BEFORE the param route runs */
    n = get("GET /users/42 HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 401", 12) == 0);

    /* 2) with Authorization the param binds normally */
    n = get("GET /users/42 HTTP/1.1\r\nHost: t\r\n"
            "Authorization: Bearer x\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=42 name=-") != NULL);

    /* --- traversal / injection: params bind RAW (no URL decoding) --- */

    /* 3) traversal payload is inert: the router does NOT decode, the
     *    handler receives the literal string, nothing touches the FS */
    n = get("GET /users/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\n"
            "Host: t\r\nAuthorization: Bearer x\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "id=%2e%2e%2f%2e%2e%2fetc%2fpasswd") != NULL);

    /* 4) %00 is NOT decoded either — no NUL ever enters req->params */
    n = get("GET /users/a%00b HTTP/1.1\r\nHost: t\r\n"
            "Authorization: Bearer x\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "id=a%00b ") != NULL);

    /* 5) a ':' in the request path is stripped like in patterns —
     *    documents the quirk (no matching literal ':x' routes exist) */
    n = get("GET /users/:admin HTTP/1.1\r\nHost: t\r\n"
            "Authorization: Bearer x\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=admin name=-") != NULL);

    /* 6) a request with a real traversal shape has more segments -> 404,
     *    and never reaches a handler */
    n = get("GET /users/../../etc/passwd HTTP/1.1\r\nHost: t\r\n"
            "Authorization: Bearer x\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* --- value length boundaries --- */

    /* 7) 63-char value: the maximum that fits into the param buffer */
    {
        char req[256];
        char val[80];
        memset(val, 'v', 63);
        val[63] = '\0';
        snprintf(req, sizeof(req),
                 "GET /users/%s HTTP/1.1\r\nHost: t\r\n"
                 "Authorization: Bearer x\r\n\r\n",
                 val);
        n = get(req, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
        CHECK(strstr(rsp, "id=vvv") != NULL);
        char expect[96];
        snprintf(expect, sizeof(expect), "id=%s name=-", val);
        CHECK(strstr(rsp, expect) != NULL);
    }

    /* 8) 64-char segment: over the segment buffer -> parse failure -> 404
     *    (no truncation, no silent match) */
    {
        char req[256];
        char val[80];
        memset(val, 'v', 64);
        val[64] = '\0';
        snprintf(req, sizeof(req),
                 "GET /users/%s HTTP/1.1\r\nHost: t\r\n"
                 "Authorization: Bearer x\r\n\r\n",
                 val);
        n = get(req, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);
    }

    /* 9) many segments: no route shape matches -> 404, no crash */
    {
        char req[512];
        strcpy(req, "GET /seg");
        for (int i = 0; i < 50; i++) {
            strcat(req, "/a");
        }
        strcat(req, " HTTP/1.1\r\nHost: t\r\n\r\n");
        n = get(req, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);
    }

    /* --- method semantics on param routes --- */

    /* 10) wrong method -> 405 with BOTH methods in Allow
     *    (Authorization needed — otherwise the middleware 401s first) */
    n = get("POST /users/42 HTTP/1.1\r\nHost: t\r\n"
            "Authorization: Bearer x\r\nContent-Length: 0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 405", 12) == 0);
    CHECK(strstr(rsp, "Allow: GET, DELETE") != NULL);

    /* 11) DELETE binds params too */
    n = get("DELETE /users/7 HTTP/1.1\r\nHost: t\r\n"
            "Authorization: Bearer x\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=7 name=-") != NULL);

    /* 12) HEAD falls back to GET and binds params, no body */
    n = get("HEAD /users/42 HTTP/1.1\r\nHost: t\r\n"
            "Authorization: Bearer x\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Length: 12") != NULL); /* "id=42 name=-" */
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0);

    /* --- routing semantics --- */

    /* 13) query string is stripped BEFORE routing -> param binds anyway */
    n = get("GET /users/42?x=1&y=2 HTTP/1.1\r\nHost: t\r\n"
            "Authorization: Bearer x\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=42 name=-") != NULL);

    /* 14) param route wins over the static mount on the same shape */
    n = get("GET /files/style.css HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=- name=style.css") != NULL);

    /* 15) ...but the mount itself keeps working on other paths */
    n = get("GET /static/style.css HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Type: text/css") != NULL);
    CHECK(strstr(rsp, "\r\n\r\nbody {}") != NULL);

    /* 16) group prefix + params combine */
    n = get("GET /api/users/9 HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=9 name=-") != NULL);

    /* 17) literal route wins over the catch-all (registered earlier) */
    n = get("GET /exact HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 18) catch-all binds everything else with one segment */
    n = get("GET /favicon.ico HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=favicon.ico name=-") != NULL);

    /* 19) root (0 segments) does NOT match the catch-all (1 segment) */
    n = get("GET / HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 20) state reset between requests: params never accumulate or
     *     leak from a previous request */
    n = get("GET /users/42 HTTP/1.1\r\nHost: t\r\n"
            "Authorization: Bearer x\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\nid=42 name=-") != NULL);
    n = get("GET /users/43 HTTP/1.1\r\nHost: t\r\n"
            "Authorization: Bearer x\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\nid=43 name=-") != NULL);

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);

    snprintf(p, sizeof(p), "%s/style.css", www);
    unlink(p);
    rmdir(www);
}

/* ------------------------------------------------------------------ */
/* http_req_header + req.ip                                            */
/* ------------------------------------------------------------------ */

static void test_req_header_unit(void)
{
    HttpRequest req = {0};

    /* NULL guards */
    CHECK(http_req_header(NULL, "Host") == NULL);
    CHECK(http_req_header(&req, NULL) == NULL);

    /* empty request: nothing found */
    CHECK(http_req_header(&req, "Host") == NULL);

    /* case-insensitive lookup (RFC 9110 §5.1), exact value returned */
    CHECK(http_set_header(&req.headers, "Content-Type", "text/html") ==
          HTTP_SET_HEADER_OK);
    CHECK(strcmp(http_req_header(&req, "content-type"), "text/html") == 0);
    CHECK(strcmp(http_req_header(&req, "CONTENT-TYPE"), "text/html") == 0);
    CHECK(strcmp(http_req_header(&req, "CoNtEnT-tYpE"), "text/html") == 0);

    /* first occurrence wins on duplicates */
    CHECK(http_set_header(&req.headers, "X-Dup", "first") ==
          HTTP_SET_HEADER_OK);
    CHECK(http_set_header(&req.headers, "X-Dup", "second") ==
          HTTP_SET_HEADER_OK);
    CHECK(strcmp(http_req_header(&req, "x-dup"), "first") == 0);

    /* full keys only: no prefix/suffix matches */
    CHECK(http_req_header(&req, "Content") == NULL);
    CHECK(http_req_header(&req, "Content-TypeX") == NULL);

    http_headers_free(&req.headers);
}

static void test_req_header_integration(void)
{
    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_get(&g_srv, "/echo", h_header_echo);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[16 * 1024];
    size_t n;

    /* case-insensitive lookup works on the wire, missing header -> NULL
     * (handler renders "-"), req.ip is the client loopback address */
    n = get("GET /echo HTTP/1.1\r\nHost: t\r\n"
            "user-agent: c-http-test/1.0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "ip=127.0.0.1 ") != NULL);
    CHECK(strstr(rsp, "ua=c-http-test/1.0 x=-") != NULL);

    /* without User-Agent, but with a port > 0 in the body */
    n = get("GET /echo HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "ua=- x=-") != NULL);
    {
        /* parse the port out of the body: must be > 0 (a real ephemeral
         * port), not the request-target port */
        const char *body = strstr(rsp, "\r\n\r\n");
        CHECK(body != NULL);
        unsigned echoed_port = 0;
        if (body != NULL) {
            sscanf(body + 4, "ip=%*s port=%u", &echoed_port);
            CHECK(echoed_port > 1024);
        }
    }

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

/* ------------------------------------------------------------------ */
/* locals (unit)                                                        */
/* ------------------------------------------------------------------ */

static void test_locals_unit(void)
{
    HttpResponse res = {0};

    /* NULL guards + empty request */
    CHECK(http_res_local(NULL, "user") == NULL);
    CHECK(http_res_local(&res, NULL) == NULL);
    CHECK(http_res_local(&res, "user") == NULL);
    CHECK(http_set_local(NULL, "k", "v") == HTTP_SET_LOCAL_ERROR);
    CHECK(http_set_local(&res, NULL, "v") == HTTP_SET_LOCAL_ERROR);
    CHECK(http_set_local(&res, "k", NULL) == HTTP_SET_LOCAL_ERROR);
    CHECK(http_set_local(&res, "", "v") == HTTP_SET_LOCAL_ERROR);

    /* set/get roundtrip */
    CHECK(http_set_local(&res, "user", "alice") == HTTP_SET_LOCAL_OK);
    CHECK(strcmp(http_res_local(&res, "user"), "alice") == 0);
    CHECK(res.locals.count == 1);

    /* overwrite does not grow the slot count */
    CHECK(http_set_local(&res, "user", "bob") == HTTP_SET_LOCAL_OK);
    CHECK(strcmp(http_res_local(&res, "user"), "bob") == 0);
    CHECK(res.locals.count == 1);

    /* multiple distinct keys */
    CHECK(http_set_local(&res, "role", "admin") == HTTP_SET_LOCAL_OK);
    CHECK(strcmp(http_res_local(&res, "role"), "admin") == 0);
    CHECK(strcmp(http_res_local(&res, "user"), "bob") == 0);
    CHECK(res.locals.count == 2);

    /* case-sensitive keys ("User" is not "user") */
    CHECK(http_set_local(&res, "User", "carol") == HTTP_SET_LOCAL_OK);
    CHECK(strcmp(http_res_local(&res, "User"), "carol") == 0);

    /* boundaries: exactly the max length fits, one over does not */
    {
        char key[HTTP_LOCAL_KEY_MAX + 2];
        memset(key, 'k', HTTP_LOCAL_KEY_MAX - 1);
        key[HTTP_LOCAL_KEY_MAX - 1] = '\0';
        CHECK(http_set_local(&res, key, "v") == HTTP_SET_LOCAL_OK);
        key[HTTP_LOCAL_KEY_MAX - 1] = 'k';
        key[HTTP_LOCAL_KEY_MAX] = '\0';
        CHECK(http_set_local(&res, key, "v") == HTTP_SET_LOCAL_ERROR);
    }
    {
        char value[HTTP_LOCAL_VALUE_MAX + 2];
        memset(value, 'v', HTTP_LOCAL_VALUE_MAX - 1);
        value[HTTP_LOCAL_VALUE_MAX - 1] = '\0';
        CHECK(http_set_local(&res, "vlong", value) == HTTP_SET_LOCAL_OK);
        value[HTTP_LOCAL_VALUE_MAX - 1] = 'v';
        value[HTTP_LOCAL_VALUE_MAX] = '\0';
        CHECK(http_set_local(&res, "vlong", value) == HTTP_SET_LOCAL_ERROR);
    }

    /* full slots: the last one that fits + rejection when full */
    {
        HttpResponse fresh = {0};
        for (size_t i = 0; i < HTTP_MAX_LOCALS; i++) {
            char key[16];
            snprintf(key, sizeof(key), "k%zu", i);
            CHECK(http_set_local(&fresh, key, "v") == HTTP_SET_LOCAL_OK);
        }
        CHECK(fresh.locals.count == HTTP_MAX_LOCALS);
        CHECK(http_set_local(&fresh, "overflow", "v") == HTTP_SET_LOCAL_ERROR);
        /* overwrite still works when the slots are full */
        CHECK(http_set_local(&fresh, "k0", "updated") == HTTP_SET_LOCAL_OK);
        CHECK(strcmp(http_res_local(&fresh, "k0"), "updated") == 0);

        http_headers_free(&fresh.headers);
    }

    http_headers_free(&res.headers);
}

/* ------------------------------------------------------------------ */
/* query parser + locals (integration)                                  */
/* ------------------------------------------------------------------ */

static void test_query_locals_integration(void)
{
    /* unit on the empty request first */
    HttpRequest empty = {0};
    CHECK(http_req_query(NULL, "a") == NULL);
    CHECK(http_req_query(&empty, NULL) == NULL);
    CHECK(http_req_query(&empty, "a") == NULL);

    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_get(&g_srv, "/echo", h_query_echo);
    http_get(&g_srv, "/combined/:id", h_param_query_echo);
    http_get(&g_srv, "/local", h_local_echo);
    http_middleware(&g_srv, "/local", local_mw_1);
    http_middleware(&g_srv, "/local", local_mw_2);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[32 * 1024];
    size_t n;

    /* --- parsing basics --- */

    /* 1) simple pairs + %20 decoding + bare key ("" value, not NULL) */
    n = get("GET /echo?a=1&name=Max%20Muster&flag HTTP/1.1\r\nHost: t\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\na=1 name=Max Muster flag= missing=- count=3") !=
          NULL);

    /* 2) '+' decodes to a space in query strings */
    n = get("GET /echo?a=one+two HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\na=one two ") != NULL);

    /* 3) first occurrence wins */
    n = get("GET /echo?a=first&a=second HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\na=first ") != NULL);

    /* 4) no query at all and an empty query (?): everything NULL */
    n = get("GET /echo HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\na=- name=- flag=- missing=- count=0") != NULL);
    n = get("GET /echo? HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\na=- name=- flag=- missing=- count=0") != NULL);

    /* 5) '=' inside a value: split happens at the FIRST '=' */
    n = get("GET /echo?a=x=y HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\na=x=y ") != NULL);

    /* 6) '?' inside the query belongs to the value */
    n = get("GET /echo?a=1?b HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\na=1?b ") != NULL);

    /* 7) empty value ("a=") is present, not NULL */
    n = get("GET /echo?a= HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\na= ") != NULL);

    /* --- malformed pairs are skipped, never fatal --- */

    /* 8) %00 in the value: pair skipped (NUL injection) */
    n = get("GET /echo?a=%00x&name=ok HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\na=- name=ok ") != NULL);

    /* 9) broken escape and control char: pair skipped */
    n = get("GET /echo?a=%zz&name=%01x HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\na=- name=- ") != NULL);

    /* 10) oversized value: skipped whole — no truncation */
    {
        char req[256];
        char val[80];
        memset(val, 'v', 64);
        val[64] = '\0';
        snprintf(req, sizeof(req),
                 "GET /echo?a=%s&name=ok HTTP/1.1\r\nHost: t\r\n\r\n", val);
        n = get(req, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strstr(rsp, "\r\n\r\na=- name=ok ") != NULL);
    }

    /* 11) empty keys ("=5", "&&") are not pairs */
    n = get("GET /echo?=5&&a=ok HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\na=ok ") != NULL);

    /* 12) more than HTTP_MAX_QUERY pairs: parsing stops at the limit,
     *     the request is still served (never fatal) */
    {
        char req[512];
        strcpy(req, "GET /echo?");
        for (int i = 0; i <= HTTP_MAX_QUERY; i++) {
            char pair[16];
            snprintf(pair, sizeof(pair), "p%d=%d&", i, i);
            strcat(req, pair);
        }
        strcat(req, " HTTP/1.1\r\nHost: t\r\n\r\n");
        n = get(req, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
        CHECK(strstr(rsp, "count=16") != NULL); /* 17th pair skipped */
    }

    /* 13) combined: route param AND query on the same request */
    n = get("GET /combined/9?page=3&size=10 HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=9 page=3") != NULL);

    /* 14) query alone does not make a route match */
    n = get("GET /echo/x?a=1 HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* --- locals: middleware -> handler --- */

    /* 15) two middlewares write the same key — handler sees the last */
    n = get("GET /local HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nuser=bob missing=-") != NULL);

    /* 16) locals do not leak into other requests */
    n = get("GET /echo?a=1 HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\na=1 ") != NULL);
    n = get("GET /local HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\nuser=bob missing=-") != NULL);

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

/* ------------------------------------------------------------------ */
/* res helpers (unit)                                                   */
/* ------------------------------------------------------------------ */

static void test_res_helpers_unit(void)
{
    HttpResponse res = {0};

    /* --- http_res_json --- */
    CHECK(http_res_json(NULL, 200, "{}") == -1);
    CHECK(http_res_json(&res, 200, NULL) == -1);
    CHECK(http_res_json(&res, 999, "{}") == -1); /* invalid status */

    CHECK(http_res_json(&res, 200, "{\"ok\":true}") == 0);
    CHECK(res.status == 200);
    CHECK(res.body_len == 11);
    CHECK(strcmp(res.body, "{\"ok\":true}") == 0);
    CHECK(strcmp(res_header(&res, "Content-Type"), "application/json") == 0);

    /* oversized body: -1 and NOTHING written (no truncation) */
    static char big[5000];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    CHECK(http_res_json(&res, 200, big) == -1);
    CHECK(res.body_len == 11); /* unchanged */

    /* --- http_res_redirect --- */
    CHECK(http_res_redirect(NULL, 302, "/") == -1);
    CHECK(http_res_redirect(&res, 200, "/") == -1); /* 2xx is not one */
    CHECK(http_res_redirect(&res, 400, "/") == -1); /* 4xx neither */
    CHECK(http_res_redirect(&res, 302, "/x\r\nSet-Cookie: pwned=1") == -1);
    CHECK(res_header(&res, "Location") == NULL); /* nothing written */

    CHECK(http_res_redirect(&res, 307, "/target") == 0);
    CHECK(res.status == 307);
    CHECK(res.body_len == 0);
    CHECK(strcmp(res_header(&res, "Location"), "/target") == 0);

    /* --- http_res_cookie --- */
    CHECK(http_res_cookie(NULL, "sid", "v", 0, false) == -1);
    CHECK(http_res_cookie(&res, "", "v", 0, false) == -1);
    /* invalid cookie names (token chars only) */
    CHECK(http_res_cookie(&res, "bad name", "v", 0, false) == -1);
    CHECK(http_res_cookie(&res, "bad=x", "v", 0, false) == -1);
    CHECK(http_res_cookie(&res, "bad;x", "v", 0, false) == -1);
    /* attribute injection via the value */
    CHECK(http_res_cookie(&res, "ok", "v;Path=/evil", 0, false) == -1);
    CHECK(http_res_cookie(&res, "ok", "v\r\nX-Evil: 1", 0, false) == -1);
    CHECK(res_header_count(&res, "Set-Cookie") == 0);

    /* full cookie */
    CHECK(http_res_cookie(&res, "sid", "abc", 3600, true) == 0);
    CHECK(strcmp(res_header(&res, "Set-Cookie"),
                 "sid=abc; Path=/; Max-Age=3600; HttpOnly") == 0);

    /* session cookie: no Max-Age, no HttpOnly */
    CHECK(http_res_cookie(&res, "sess", "v", 0, false) == 0);
    CHECK(res_header_count(&res, "Set-Cookie") == 2);
    {
        /* the second Set-Cookie carries the session value */
        bool found_sess = false;
        for (size_t i = 0; i < res.headers.count; i++) {
            if (strcasecmp(res.headers.items[i].key, "Set-Cookie") == 0 &&
                strcmp(res.headers.items[i].value, "sess=v; Path=/") == 0) {
                found_sess = true;
            }
        }
        CHECK(found_sess);
    }

    /* multiple Set-Cookie headers coexist */
    CHECK(http_res_cookie(&res, "third", "v", 1, false) == 0);
    CHECK(res_header_count(&res, "Set-Cookie") == 3);

    http_headers_free(&res.headers);
}

/* ------------------------------------------------------------------ */
/* central error handler (integration)                                  */
/* ------------------------------------------------------------------ */

static void test_error_channel(void)
{
    char rsp[32 * 1024];
    size_t n;

    /* --- first: WITHOUT an error handler (backwards compatible) --- */
    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_get(&g_srv, "/boom", h_erroring);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    /* http_error without a handler: status only, empty body */
    n = get("GET /boom HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 422", 12) == 0);
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0); /* empty body */

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);

    /* --- now WITH the central error handler --- */
    created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_set_error_handler(&g_srv, json_error_handler);
    http_get(&g_srv, "/boom", h_erroring);
    http_get(&g_srv, "/coerce", h_erroring_coerce);
    http_get(&g_srv, "/only-get2", h_root);
    http_middleware(&g_srv, "/stop", stop_401_mw);

    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    /* 1) handler error -> error handler formats it as JSON */
    n = get("GET /boom HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 422", 12) == 0);
    CHECK(strstr(rsp, "Content-Type: application/json") != NULL);
    CHECK(strstr(rsp, "\"status\":422") != NULL);
    CHECK(strstr(rsp, "\"message\":\"bad input\"") != NULL);

    /* 2) success status in http_error is coerced to 500 */
    n = get("GET /coerce HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 500", 12) == 0);
    CHECK(strstr(rsp, "this is not a success") != NULL);

    /* 3) 404 (framework error) -> error handler, path included */
    n = get("GET /nowhere HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);
    CHECK(strstr(rsp, "\"status\":404") != NULL);
    CHECK(strstr(rsp, "\"path\":\"/nowhere\"") != NULL);

    /* 4) 405 (framework error) -> error handler, Allow survives */
    n = get("POST /only-get2 HTTP/1.1\r\nHost: t\r\n"
            "Content-Length: 0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 405", 12) == 0);
    CHECK(strstr(rsp, "Allow: GET") != NULL);
    CHECK(strstr(rsp, "\"status\":405") != NULL);

    /* 5) protocol parse error (400) -> error handler with a partial req */
    n = get("GARBAGE\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 400", 12) == 0);
    CHECK(strstr(rsp, "\"status\":400") != NULL);
    CHECK(strstr(rsp, "\"path\":\"-\"") != NULL); /* no path parsed yet */

    /* 6) middleware STOP with its own body: NOT reformatted */
    n = get("GET /stop/x HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 401", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\ncustom 401") != NULL);
    CHECK(strstr(rsp, "\"status\":401") == NULL); /* no error page */

    /* 7) HEAD on an error route: error handler runs, body suppressed */
    n = get("HEAD /boom HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 422", 12) == 0);
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0); /* no body */
    CHECK(strstr(rsp, "Content-Length: ") != NULL); /* size of the page */

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

/* ------------------------------------------------------------------ */
/* routers (integration)                                                */
/* ------------------------------------------------------------------ */

static void test_routers(void)
{
    /* --- registration-time validation (unit part) --- */
    HttpRouter *rfree = http_router_create();
    CHECK(rfree != NULL);
    CHECK(http_router_get(rfree, "/ok", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_router_get(rfree, "/bad/:", h_root) == HTTP_ROUTE_ADD_ERROR);
    http_router_free(rfree); /* unmounted: caller frees — no ASan leak */
    http_router_free(NULL);  /* NULL is a safe no-op */

    ServerArgs args = {.port = 0, .bind_addr = "127.0.0.1", .server_name = "t"};
    HttpServer srv;
    CHECK(http_create_server(&args, &srv) == SERVER_OK);

    /* invalid mounts (non-assert-guarded paths only) */
    HttpRouter *rx = http_router_create();
    CHECK(rx != NULL);
    CHECK(http_use(&srv, "/q?x", rx) == HTTP_USE_ERROR);    /* '?' */
    CHECK(http_use(&srv, "/:param", rx) == HTTP_USE_ERROR); /* param prefix */
    CHECK(http_use(&srv, "/admin", rx) == HTTP_USE_OK);     /* still usable */

    /* --- live server with routers --- */
    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    /* server route that must win over the router's /exact */
    http_get(&g_srv, "/admin/exact", h_root);

    /* router at /admin (mounted FIRST: dispatch order) */
    HttpRouter *admin = http_router_create();
    CHECK(http_router_get(admin, "/dashboard", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_router_get(admin, "/users/:id", h_param) == HTTP_ROUTE_ADD_OK);
    CHECK(http_router_post(admin, "/settings", h_param) == HTTP_ROUTE_ADD_OK);
    CHECK(http_router_get(admin, "/exact", h_param) == HTTP_ROUTE_ADD_OK);
    CHECK(http_use(&g_srv, "/admin", admin) == HTTP_USE_OK);

    /* LATE BINDING: adding a route after http_use() is live */
    CHECK(http_router_get(admin, "/late", h_root) == HTTP_ROUTE_ADD_OK);

    /* second router, trailing-slash prefix ("/v2/" == "/v2") */
    HttpRouter *v2 = http_router_create();
    CHECK(http_router_get(v2, "/ping", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_use(&g_srv, "/v2/", v2) == HTTP_USE_OK);

    /* root router: matches everything unmatched — checked LAST */
    HttpRouter *root = http_router_create();
    CHECK(http_router_get(root, "/shadow", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_router_get(root, "/exact", h_param) == HTTP_ROUTE_ADD_OK);
    CHECK(http_use(&g_srv, "/", root) == HTTP_USE_OK);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[32 * 1024];
    size_t n;

    /* 1) plain router route */
    n = get("GET /admin/dashboard HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 2) router params bind */
    n = get("GET /admin/users/42 HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nid=42 name=-") != NULL);

    /* 3) segment count is enforced inside routers too */
    n = get("GET /admin/users/42/extra HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 4) wrong method -> 405 with the router's methods in Allow */
    n = get("DELETE /admin/dashboard HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 405", 12) == 0);
    CHECK(strstr(rsp, "Allow: GET") != NULL);

    /* 5) HEAD falls back to GET inside a router, params bound */
    n = get("HEAD /admin/users/42 HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Length: 12") != NULL);
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0);

    /* 6) late binding: the route added after http_use() serves */
    n = get("GET /admin/late HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 7) server routes win over router routes on the same path */
    n = get("GET /admin/exact HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL); /* h_root, not h_param */

    /* 8) second router at a different prefix (trailing-slash mount) */
    n = get("GET /v2/ping HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 9) router prefixes have word boundaries: /admins is not /admin */
    n = get("GET /admins/dashboard HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
            sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 10) the bare mount prefix alone does not match a route */
    n = get("GET /admin HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 11) POST inside a router binds params too */
    n = get("POST /admin/settings HTTP/1.1\r\nHost: t\r\n"
            "Content-Length: 0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "id=- name=-") != NULL);

    /* 12) root router catches unmatched single segments */
    n = get("GET /shadow HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 13) server route /admin/exact also beats the ROOT router's /exact
     *     (server routes > routers, mount order among routers) */
    n = get("GET /admin/exact HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 14) POST /v2/ping (GET only) -> 405 from the router */
    n = get("POST /v2/ping HTTP/1.1\r\nHost: t\r\n"
            "Content-Length: 0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 405", 12) == 0);

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv); /* frees the mounted routers */

    /* the unmountable routers: srv owns rx now — close frees it */
    http_close_server(&srv);
    http_close_server(&srv); /* double close must survive */
}

/* ------------------------------------------------------------------ */
/* body parsers: urlencoded + JSON + body_type                        */
/* ------------------------------------------------------------------ */

static void test_body_parsers(void)
{
    /* --- unit: http_req_json_string on a hand-built request --- */
    {
        HttpRequest req = {0};
        char out[128];

        /* NULL guards */
        CHECK(http_req_json_string(NULL, "k", out, sizeof(out)) == -1);
        CHECK(http_req_json_string(&req, "k", out, sizeof(out)) == -1);

        /* simple + surrounding whitespace */
        req.body = strdup("  {\"name\":\"Max\"}  ");
        req.body_len = strlen(req.body);
        CHECK(http_req_json_string(&req, "name", out, sizeof(out)) == 3);
        CHECK(strcmp(out, "Max") == 0);
        free(req.body);

        /* escape sequences */
        req.body = strdup("{\"s\":\"a\\\"b\\\\c\\/d\\be\\ff\\ng\\rh\\ti\"}");
        req.body_len = strlen(req.body);
        CHECK(http_req_json_string(&req, "s", out, sizeof(out)) == 17);
        CHECK(strcmp(out, "a\"b\\c/d\be\ff\ng\rh\ti") == 0);
        free(req.body);

        /* \uXXXX -> UTF-8 (é = 2 bytes) */
        req.body = strdup("{\"u\":\"caf\\u00e9\"}");
        req.body_len = strlen(req.body);
        CHECK(http_req_json_string(&req, "u", out, sizeof(out)) == 5);
        CHECK(strcmp(out, "caf\xc3\xa9") == 0); /* c3 a9 = UTF-8 é */
        free(req.body);

        /* lone surrogate and \u0000 are rejected */
        req.body = strdup("{\"u\":\"\\ud800\"}");
        req.body_len = strlen(req.body);
        CHECK(http_req_json_string(&req, "u", out, sizeof(out)) == -1);
        free(req.body);
        req.body = strdup("{\"u\":\"\\u0000\"}");
        req.body_len = strlen(req.body);
        CHECK(http_req_json_string(&req, "u", out, sizeof(out)) == -1);
        free(req.body);

        /* nested structures are skipped, keys inside them NOT found */
        req.body = strdup("{\"outer\":{\"name\":\"nested\"},\"name\":\"top\","
                          "\"arr\":[1,2,{\"x\":\"y\"}]}");
        req.body_len = strlen(req.body);
        CHECK(http_req_json_string(&req, "name", out, sizeof(out)) == 3);
        CHECK(strcmp(out, "top") == 0);
        CHECK(http_req_json_string(&req, "outer", out, sizeof(out)) == -1);
        CHECK(http_req_json_string(&req, "x", out, sizeof(out)) == -1);
        free(req.body);

        /* value not a string -> -1; first duplicate wins; empty string */
        req.body =
            strdup("{\"n\":42,\"e\":\"\",\"d\":\"first\",\"d\":\"second\"}");
        req.body_len = strlen(req.body);
        CHECK(http_req_json_string(&req, "n", out, sizeof(out)) == -1);
        CHECK(http_req_json_string(&req, "e", out, sizeof(out)) == 0);
        CHECK(out[0] == '\0');
        CHECK(http_req_json_string(&req, "d", out, sizeof(out)) == 5);
        CHECK(strcmp(out, "first") == 0);
        free(req.body);

        /* malformed bodies and the depth cap (no stack exhaustion) */
        req.body = strdup("{\"k\":}");
        req.body_len = strlen(req.body);
        CHECK(http_req_json_string(&req, "k", out, sizeof(out)) == -1);
        free(req.body);
        req.body = strdup("[\"not an object\"]");
        req.body_len = strlen(req.body);
        CHECK(http_req_json_string(&req, "k", out, sizeof(out)) == -1);
        free(req.body);
        {
            static char deep[256];
            size_t off = 0;
            while (off + 1 < sizeof(deep)) {
                deep[off++] = '{';
            }
            deep[off] = '\0';
            req.body = strdup(deep);
            req.body_len = strlen(req.body);
            CHECK(http_req_json_string(&req, "k", out, sizeof(out)) == -1);
            free(req.body);
        }

        /* too small out: NEVER truncates */
        req.body = strdup("{\"k\":\"12345678\"}");
        req.body_len = strlen(req.body);
        CHECK(http_req_json_string(&req, "k", out, 4) == -1); /* needs 9 */
        free(req.body);
        req.body = NULL; /* no dangling pointer into the next section */
        req.body_len = 0;

        /* --- unit: http_req_body_type via headers --- */
        req.body = strdup("x"); /* a present body: the type checks run */
        req.body_len = 1;
        http_set_header(&req.headers, "Content-Type",
                        "application/x-www-form-urlencoded");
        CHECK(http_req_body_type(&req) == HTTP_BODY_URLENCODED);
        http_headers_free(&req.headers);
        /* http_set_header APPENDS: free between the cases, otherwise
         * http_req_header keeps returning the first Content-Type. */
        http_set_header(&req.headers, "Content-Type", "application/json");
        CHECK(http_req_body_type(&req) == HTTP_BODY_JSON);
        http_headers_free(&req.headers);
        http_set_header(&req.headers, "Content-Type",
                        "application/json; charset=utf-8");
        CHECK(http_req_body_type(&req) == HTTP_BODY_JSON);
        http_headers_free(&req.headers);
        http_set_header(&req.headers, "Content-Type", "multipart/form-data");
        CHECK(http_req_body_type(&req) == HTTP_BODY_MULTIPART);
        http_headers_free(&req.headers);
        http_set_header(&req.headers, "Content-Type", "text/plain");
        CHECK(http_req_body_type(&req) == HTTP_BODY_OTHER);
        http_headers_free(&req.headers);
        free(req.body);
        /* no body: NONE regardless of the header */
        req.body = NULL;
        req.body_len = 0;
        CHECK(http_req_body_type(&req) == HTTP_BODY_NONE);
    }

    /* --- integration: the server fills req->form / handlers read --- */
    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_post(&g_srv, "/form", h_form_echo);
    http_post(&g_srv, "/json", h_json_echo);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[32 * 1024];
    size_t n;

    /* urlencoded: pairs, '+' -> space, %20, bare flag, first occurrence */
    n = get("POST /form HTTP/1.1\r\nHost: t\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 33\r\n\r\n"
            "a=one+two&name=Max%20M&flag&a=dup",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\na=one two name=Max M missing=- type=1") != NULL);

    /* wrong Content-Type: the body is NOT parsed as a form */
    n = get("POST /form HTTP/1.1\r\nHost: t\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 7\r\n\r\n"
            "a=1&b=2",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\na=- name=- missing=- type=4") != NULL);

    /* JSON body access over the wire */
    n = get("POST /json HTTP/1.1\r\nHost: t\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 30\r\n\r\n"
            "{\"user\":{\"id\":7},\"name\":\"Max\"}",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nname=Max m=-") != NULL);

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

/* ------------------------------------------------------------------ */
/* keep-alive                                                           */
/* ------------------------------------------------------------------ */

/* Reads ONE full response (headers + Content-Length body) from fd.
 * Returns the bytes read; 0 when the peer closed without data. */
static size_t recv_response(int fd, char *out, size_t outsz)
{
    size_t total = 0;
    char *sep = NULL;

    while (total + 1 < outsz) {
        ssize_t r = recv(fd, out + total, outsz - total - 1, 0);
        if (r <= 0) {
            break;
        }
        total += (size_t)r;
        out[total] = '\0';
        sep = strstr(out, "\r\n\r\n");
        if (sep != NULL) {
            break;
        }
    }
    if (sep == NULL) {
        return total; /* close/error mid-headers */
    }

    /* read exactly Content-Length body bytes */
    size_t clen = 0;
    for (const char *line = out; line < sep;) {
        const char *eol = strstr(line, "\r\n");
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            clen = (size_t)strtoul(line + 15, NULL, 10);
            break;
        }
        line = eol != NULL ? eol + 2 : sep;
    }

    size_t have = total - (size_t)(sep + 4 - out);
    while (have < clen && total + 1 < outsz) {
        ssize_t r = recv(fd, out + total, outsz - total - 1, 0);
        if (r <= 0) {
            break;
        }
        total += (size_t)r;
        have += (size_t)r;
    }
    out[total] = '\0';
    return total;
}

static void test_keep_alive(void)
{
    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test",
                            .keep_alive = true};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_get(&g_srv, "/ka", h_root);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[16 * 1024];
    char req[256];

    /* 1) HTTP/1.1 defaults to persistence: two requests, ONE socket */
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(g_port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        CHECK(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);

        strcpy(req, "GET /ka HTTP/1.1\r\nHost: t\r\n\r\n");
        CHECK(send(fd, req, strlen(req), 0) > 0);
        size_t n = recv_response(fd, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
        CHECK(strstr(rsp, "Connection: keep-alive") != NULL);
        CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

        /* same connection, second request */
        CHECK(send(fd, req, strlen(req), 0) > 0);
        n = recv_response(fd, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
        CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

        close(fd);
    }

    /* 2) HTTP/1.1 + "Connection: close": server closes after one */
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(g_port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        CHECK(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);

        strcpy(req, "GET /ka HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
        CHECK(send(fd, req, strlen(req), 0) > 0);
        size_t n = recv_response(fd, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strstr(rsp, "Connection: close") != NULL);

        /* the server must have closed: a further request gets nothing */
        strcpy(req, "GET /ka HTTP/1.1\r\nHost: t\r\n\r\n");
        CHECK(send(fd, req, strlen(req), 0) > 0);
        n = recv_response(fd, rsp, sizeof(rsp));
        CHECK(n == 0); /* EOF: the server side closed the connection */
        close(fd);
    }

    /* 3) HTTP/1.0 closes by default; keep-alive needs the token */
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(g_port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        CHECK(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);

        strcpy(req, "GET /ka HTTP/1.0\r\nHost: t\r\n\r\n");
        CHECK(send(fd, req, strlen(req), 0) > 0);
        size_t n = recv_response(fd, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strstr(rsp, "Connection: close") != NULL);
        CHECK(send(fd, req, strlen(req), 0) > 0);
        n = recv_response(fd, rsp, sizeof(rsp));
        CHECK(n == 0); /* server closed */
        close(fd);
    }
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(g_port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        CHECK(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);

        strcpy(req, "GET /ka HTTP/1.0\r\nHost: t\r\n"
                    "Connection: keep-alive\r\n\r\n");
        CHECK(send(fd, req, strlen(req), 0) > 0);
        size_t n = recv_response(fd, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strstr(rsp, "Connection: keep-alive") != NULL);
        /* second request works on the persistent 1.0 connection */
        CHECK(send(fd, req, strlen(req), 0) > 0);
        n = recv_response(fd, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
        close(fd);
    }

    /* 4) a protocol error closes even on a keep-alive server */
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(g_port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        CHECK(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);

        strcpy(req, "GARBAGE\r\n\r\n");
        CHECK(send(fd, req, strlen(req), 0) > 0);
        size_t n = recv_response(fd, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 400", 12) == 0);
        strcpy(req, "GET /ka HTTP/1.1\r\nHost: t\r\n\r\n");
        CHECK(send(fd, req, strlen(req), 0) > 0);
        n = recv_response(fd, rsp, sizeof(rsp));
        CHECK(n == 0); /* closed after the error */
        close(fd);
    }

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

/* ------------------------------------------------------------------ */
/* thread-per-connection                                                */
/* ------------------------------------------------------------------ */

#define CONCURRENCY_CLIENTS 8
#define CONCURRENCY_REQS    5

typedef struct {
    unsigned id;
    bool ok;
} ConcurrentClient;

static void *concurrent_client_main(void *arg)
{
    ConcurrentClient *self = arg;
    self->ok = true;

    for (int i = 0; i < CONCURRENCY_REQS; i++) {
        char req[128];
        char rsp[16 * 1024];
        snprintf(req, sizeof(req),
                 "GET /echo?a=%u-%d HTTP/1.1\r\nHost: t\r\n\r\n", self->id, i);
        size_t n = raw_request(g_port, req, strlen(req), rsp, sizeof(rsp));
        char expect[64];
        snprintf(expect, sizeof(expect), "\r\n\r\na=%u-%d ", self->id, i);
        if (n == 0 || strncmp(rsp, "HTTP/1.1 200", 12) != 0 ||
            strstr(rsp, expect) == NULL) {
            self->ok = false;
            return NULL; /* no CHECK from threads: report after join */
        }
    }
    return NULL;
}

static void test_concurrency(void)
{
    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test",
                            .worker_threads = 4};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_get(&g_srv, "/echo", h_query_echo);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    /* 8 simultaneous clients with 4 worker slots: exercises the
     * workers, the limit fallback and per-request state isolation. */
    pthread_t clients[CONCURRENCY_CLIENTS];
    ConcurrentClient info[CONCURRENCY_CLIENTS];
    for (unsigned i = 0; i < CONCURRENCY_CLIENTS; i++) {
        info[i] = (ConcurrentClient){.id = i};
        CHECK(pthread_create(&clients[i], NULL, concurrent_client_main,
                             &info[i]) == 0);
    }
    for (int i = 0; i < CONCURRENCY_CLIENTS; i++) {
        CHECK(pthread_join(clients[i], NULL) == 0);
        CHECK(info[i].ok); /* every request answered with its own data */
    }

    /* stop + close drains the workers (close_server waits for them) */
    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

/* ------------------------------------------------------------------ */
/* auto-OPTIONS                                                        */
/* ------------------------------------------------------------------ */

static void test_auto_options(void)
{
    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_get(&g_srv, "/multi", h_root);
    http_post(&g_srv, "/multi", h_root);
    http_get(&g_srv, "/users/:id", h_param);
    http_options(&g_srv, "/manual", h_options_manual);

    HttpRouter *rt = http_router_create();
    http_router_delete(rt, "/thing", h_root);
    CHECK(http_use(&g_srv, "/api", rt) == HTTP_USE_OK);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[16 * 1024];
    size_t n;

    /* 1) OPTIONS on a multi-method route: 204 + ALL methods, no body */
    n = get("OPTIONS /multi HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 204", 12) == 0);
    CHECK(strstr(rsp, "Allow: GET, POST") != NULL);
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0); /* no body */

    /* 2) OPTIONS on a param route */
    n = get("OPTIONS /users/42 HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 204", 12) == 0);
    CHECK(strstr(rsp, "Allow: GET") != NULL);

    /* 3) explicit OPTIONS route beats the auto-response */
    n = get("OPTIONS /manual HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nmanual options") != NULL);

    /* 4) OPTIONS inside a mounted router: the router's methods count */
    n = get("OPTIONS /api/thing HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 204", 12) == 0);
    CHECK(strstr(rsp, "Allow: DELETE") != NULL);

    /* 5) OPTIONS on an unknown path: 404 (no auto-response) */
    n = get("OPTIONS /nowhere HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 404", 12) == 0);

    /* 6) other methods still 405 — the auto-answer is OPTIONS-only */
    n = get("PUT /multi HTTP/1.1\r\nHost: t\r\n"
            "Content-Length: 0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 405", 12) == 0);
    CHECK(strstr(rsp, "Allow: GET, POST") != NULL);

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

/* ------------------------------------------------------------------ */
/* range requests (RFC 9110 §14)                                      */
/* ------------------------------------------------------------------ */

static void test_range_requests(void)
{
    /* temp root with a KNOWN 1000-byte pattern file: content[i] =
     * '0' + (i % 10) — every offset is verifiable. */
    char www[128];
    snprintf(www, sizeof(www), "/tmp/c_http_range_test_%ld", (long)getpid());
    mkdir(www, 0755);
    char p[192];
    snprintf(p, sizeof(p), "%s/pattern.bin", www);
    {
        char data[1000];
        for (size_t i = 0; i < sizeof(data); i++) {
            data[i] = (char)('0' + (i % 10));
        }
        CHECK(write_test_file(p, data, sizeof(data)) == 0);
    }

    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_get(&g_srv, "/plain", h_root); /* a non-file route */
    CHECK(http_static_mount(&g_srv, &(HttpStaticConfig){
                                        .prefix = "/files",
                                        .root = www,
                                    }) == SERVER_OK);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[32 * 1024];
    size_t n;
    const char *body;

    /* helper-free body extraction + exact length check */
#define RANGE_BODY                  \
    body = strstr(rsp, "\r\n\r\n"); \
    CHECK(body != NULL);            \
    if (body != NULL) {             \
        body += 4;                  \
    }

    /* 1) closed range: bytes=0-3 */
    n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: bytes=0-3\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 206", 12) == 0);
    CHECK(strstr(rsp, "Content-Range: bytes 0-3/1000") != NULL);
    CHECK(strstr(rsp, "Content-Length: 4") != NULL);
    CHECK(strstr(rsp, "Accept-Ranges: bytes") != NULL);
    RANGE_BODY;
    CHECK(n - (size_t)(body - rsp) == 4);
    CHECK(body != NULL && memcmp(body, "0123", 4) == 0);

    /* 2) open end: bytes=10- */
    n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: bytes=10-\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 206", 12) == 0);
    CHECK(strstr(rsp, "Content-Range: bytes 10-999/1000") != NULL);
    CHECK(strstr(rsp, "Content-Length: 990") != NULL);
    RANGE_BODY;
    CHECK(n - (size_t)(body - rsp) == 990);
    CHECK(body != NULL && body[0] == '0');   /* content[10] = '0' */
    CHECK(body != NULL && body[989] == '9'); /* content[999] = '9' */

    /* 3) suffix: bytes=-100 = last 100 bytes */
    n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: bytes=-100\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 206", 12) == 0);
    CHECK(strstr(rsp, "Content-Range: bytes 900-999/1000") != NULL);
    RANGE_BODY;
    CHECK(n - (size_t)(body - rsp) == 100);
    CHECK(body != NULL && body[0] == '0');  /* content[900] */
    CHECK(body != NULL && body[99] == '9'); /* content[999] */

    /* 4) suffix larger than the file: the whole file, still 206 */
    n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: bytes=-5000\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 206", 12) == 0);
    CHECK(strstr(rsp, "Content-Range: bytes 0-999/1000") != NULL);
    RANGE_BODY;
    CHECK(n - (size_t)(body - rsp) == 1000);

    /* 5) clamped end: bytes=995-2000 -> 995-999 */
    n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: bytes=995-2000\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 206", 12) == 0);
    CHECK(strstr(rsp, "Content-Range: bytes 995-999/1000") != NULL);
    RANGE_BODY;
    CHECK(n - (size_t)(body - rsp) == 5);

    /* 6) unsatisfiable: start beyond EOF -> 416 + */
    n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: bytes=1000-\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 416", 12) == 0);
    CHECK(strstr(rsp, "Content-Range: bytes */1000") != NULL);
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0); /* empty body */

    /* 7) unsatisfiable suffix on an empty file */
    {
        snprintf(p, sizeof(p), "%s/empty.bin", www);
        CHECK(write_test_file(p, "", 0) == 0);
        n = get("GET /files/empty.bin HTTP/1.1\r\nHost: t\r\n"
                "Range: bytes=-100\r\n\r\n",
                rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 416", 12) == 0);
        CHECK(strstr(rsp, "Content-Range: bytes */0") != NULL);
        unlink(p);
    }

    /* 8) malformed range: ignored, full 200 */
    n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: bytes=abc\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Range:") == NULL);
    CHECK(strstr(rsp, "Content-Length: 1000") != NULL);

    /* 9) multi-range: not supported -> full 200 (documented) */
    n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: bytes=0-1,5-6\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Length: 1000") != NULL);

    /* 10) reversed range (last < first): invalid -> ignored, 200 */
    n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: bytes=500-100\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);

    /* 11) unknown range unit: ignored, 200 */
    n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: items=0-3\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);

    /* 12) HEAD + Range: headers like GET (206 + CL), no body */
    n = get("HEAD /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
            "Range: bytes=0-3\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 206", 12) == 0);
    CHECK(strstr(rsp, "Content-Length: 4") != NULL);
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0);

    /* 13) Accept-Ranges is ONLY advertised on file responses — a
     *     regular route must not claim range support */
    n = get("GET /plain HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Accept-Ranges") == NULL);

    /* 14) ETag wins over Range: a fresh representation gets a 304,
     *     no matter the Range header */
    {
        char etag_req[512];
        char etag[64] = "";
        n = get("GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n\r\n", rsp,
                sizeof(rsp));
        const char *etag_pos = strstr(rsp, "ETag: ");
        CHECK(etag_pos != NULL);
        if (etag_pos != NULL) {
            const char *eol = strstr(etag_pos, "\r\n");
            size_t elen = (size_t)(eol - (etag_pos + 6));
            CHECK(elen < sizeof(etag));
            memcpy(etag, etag_pos + 6, elen);
            etag[elen] = '\0';
        }
        snprintf(etag_req, sizeof(etag_req),
                 "GET /files/pattern.bin HTTP/1.1\r\nHost: t\r\n"
                 "Range: bytes=0-3\r\nIf-None-Match: %s\r\n\r\n",
                 etag);
        n = get(etag_req, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 304", 12) == 0);
    }

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);

    snprintf(p, sizeof(p), "%s/pattern.bin", www);
    unlink(p);
    rmdir(www);
#undef RANGE_BODY
}

/* ------------------------------------------------------------------ */
/* multipart/form-data                                                 */
/* ------------------------------------------------------------------ */

static void h_multipart_echo(const HttpRequest *req, HttpResponse *res)
{
    res->status = HTTP_STATUS_OK;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE, "text/plain");
    const HttpMultipartPart *field = http_req_multipart_get(req, "field1");
    const HttpMultipartPart *bin = http_req_multipart_get(req, "bin");
    const HttpMultipartPart *second = http_req_multipart_part(req, 1);
    /* data is NOT NUL-terminated (binary, length-delimited): the
     * precision %.*s with data_len is the CORRECT way to render it. */
    int n = snprintf(
        res->body, sizeof(res->body),
        "count=%zu f1=%.*s fn=%s ft=%s fd=%.*s blen=%zu",
        http_req_multipart_count(req), field != NULL ? (int)field->data_len : 1,
        field != NULL ? field->data : "-",
        second != NULL ? second->filename : "-",
        second != NULL ? second->content_type : "-",
        second != NULL ? (int)second->data_len : 1,
        second != NULL ? second->data : "-", bin != NULL ? bin->data_len : 0u);
    if (n > 0) {
        res->body_len =
            (size_t)n < sizeof(res->body) ? (size_t)n : sizeof(res->body) - 1;
    }
}

static void test_multipart(void)
{
    /* --- unit: NULL guards + empty request --- */
    HttpRequest empty = {0};
    CHECK(http_req_multipart_count(NULL) == 0);
    CHECK(http_req_multipart_count(&empty) == 0);
    CHECK(http_req_multipart_part(&empty, 0) == NULL);
    CHECK(http_req_multipart_get(&empty, "x") == NULL);
    CHECK(http_req_multipart_get(NULL, "x") == NULL);

    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_post(&g_srv, "/upload", h_multipart_echo);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[32 * 1024];
    size_t n;

    /* 1) a field part + a file part */
    {
        static const char body[] =
            "--B\r\n"
            "Content-Disposition: form-data; name=\"field1\"\r\n"
            "\r\n"
            "value1\r\n"
            "--B\r\n"
            "Content-Disposition: form-data; name=\"file\"; "
            "filename=\"a.txt\"\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "file content\r\n"
            "--B--\r\n";
        char req[512];
        int len = snprintf(req, sizeof(req),
                           "POST /upload HTTP/1.1\r\nHost: t\r\n"
                           "Content-Type: multipart/form-data; boundary=B\r\n"
                           "Content-Length: %zu\r\n\r\n",
                           sizeof(body) - 1);
        memcpy(req + len, body, sizeof(body) - 1);
        n = raw_request(g_port, req, (size_t)len + sizeof(body) - 1, rsp,
                        sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
        CHECK(strstr(rsp, "\r\n\r\ncount=2 f1=value1 fn=a.txt ft=text/plain "
                          "fd=file content blen=0") != NULL);
    }

    /* 2) binary part data (NUL bytes survive via data/data_len) */
    {
        static const char head[] =
            "--B\r\n"
            "Content-Disposition: form-data; name=\"bin\"\r\n"
            "\r\n";
        static const char tail[] = "\r\n--B--\r\n";
        static const char payload[] = "ab\0cd\0ef"; /* 8 bytes incl. NULs */
        char req[512];
        size_t blen = sizeof(head) - 1 + sizeof(payload) - 1 + sizeof(tail) - 1;
        int len = snprintf(req, sizeof(req),
                           "POST /upload HTTP/1.1\r\nHost: t\r\n"
                           "Content-Type: multipart/form-data; boundary=B\r\n"
                           "Content-Length: %zu\r\n\r\n",
                           blen);
        memcpy(req + len, head, sizeof(head) - 1);
        memcpy(req + len + sizeof(head) - 1, payload, sizeof(payload) - 1);
        memcpy(req + len + sizeof(head) - 1 + sizeof(payload) - 1, tail,
               sizeof(tail) - 1);
        n = raw_request(g_port, req, (size_t)len + blen, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
        CHECK(strstr(rsp, "count=1 ") != NULL);
        CHECK(strstr(rsp, "blen=8") != NULL);
    }

    /* 3) more parts than the limit: capped, never fatal */
    {
        char mbody[4096];
        size_t blen = 0;
        for (int i = 0; i <= HTTP_MAX_MULTIPART_PARTS + 1; i++) {
            blen += (size_t)snprintf(mbody + blen, sizeof(mbody) - blen,
                                     "--B\r\nContent-Disposition: form-data; "
                                     "name=\"p%d\"\r\n\r\n%d\r\n",
                                     i, i);
        }
        blen +=
            (size_t)snprintf(mbody + blen, sizeof(mbody) - blen, "--B--\r\n");
        char req[4200];
        int len = snprintf(req, sizeof(req),
                           "POST /upload HTTP/1.1\r\nHost: t\r\n"
                           "Content-Type: multipart/form-data; boundary=B\r\n"
                           "Content-Length: %zu\r\n\r\n",
                           blen);
        CHECK(len > 0);
        memcpy(req + len, mbody, blen);
        n = raw_request(g_port, req, (size_t)len + blen, rsp, sizeof(rsp));
        CHECK(n > 0);
        CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
        CHECK(strstr(rsp, "count=16 ") != NULL); /* capped at the limit */
    }

    /* 4) multipart content type without a boundary: zero parts */
    n = get("POST /upload HTTP/1.1\r\nHost: t\r\n"
            "Content-Type: multipart/form-data\r\n"
            "Content-Length: 7\r\n\r\n"
            "--B--\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "count=0 ") != NULL);

    /* 5) garbage body with a boundary: zero parts, no crash */
    n = get("POST /upload HTTP/1.1\r\nHost: t\r\n"
            "Content-Type: multipart/form-data; boundary=B\r\n"
            "Content-Length: 12\r\n\r\n"
            "garbage!\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "count=0 ") != NULL);

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

/* ------------------------------------------------------------------ */
/* content negotiation (Accept)                                        */
/* ------------------------------------------------------------------ */

static void test_content_negotiation(void)
{
    const char *const offers[] = {"application/json", "text/html", NULL};

    /* unit: hand-built requests, deterministic */
    {
        HttpRequest req = {0};

        CHECK(http_req_accepts(NULL, offers) == NULL);
        CHECK(http_req_accepts(&req, NULL) == NULL);

        /* no Accept header: everything acceptable, first offer wins */
        CHECK(http_req_accepts(&req, offers) != NULL);
        CHECK(strcmp(http_req_accepts(&req, offers), "application/json") == 0);

        struct {
            const char *accept;
            const char *expect; /* NULL = nothing acceptable */
            const char *label;
        } cases[] = {
            {"text/html", "text/html", "exact match"},
            {"TEXT/HTML", "text/html", "case-insensitive"},
            {"text/*", "text/html", "subtype wildcard"},
            {"*/*", "application/json", "full wildcard: first offer"},
            {"*", "application/json", "bare asterisk"},
            {"application/json", "application/json", "exact other offer"},
            {"application/json, text/*", "application/json",
             "exact beats wildcard"},
            {"text/html;q=0.5, application/json", "application/json",
             "higher q wins between equals"},
            {"application/json;q=0.9, text/html", "text/html",
             "q on the winner"},
            {"application/json;q=0, text/html", "text/html", "q=0 excludes"},
            {"application/json;q=0, text/*", "text/html",
             "q=0 on exact, wildcard still applies"},
            {"image/png", NULL, "nothing acceptable"},
            {"image/*", NULL, "nothing acceptable (other type)"},
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            http_set_header(&req.headers, HTTP_HEADER_ACCEPT, cases[i].accept);
            const char *pick = http_req_accepts(&req, offers);
            if (cases[i].expect == NULL) {
                CHECK_MSG(pick == NULL, cases[i].label);
            } else if (pick == NULL) {
                CHECK_MSG(false, cases[i].label);
            } else {
                CHECK_MSG(strcmp(pick, cases[i].expect) == 0, cases[i].label);
            }
            http_headers_free(&req.headers);
        }

        /* malformed offer entries are skipped */
        const char *const bad_offers[] = {"noslash", "text/html", NULL};
        http_set_header(&req.headers, HTTP_HEADER_ACCEPT, "text/html");
        CHECK(strcmp(http_req_accepts(&req, bad_offers), "text/html") == 0);
        http_headers_free(&req.headers);
    }

    /* integration: the handler picks per the wire Accept header */
    bool created = false;
    for (uint32_t port = TEST_PORT_START; port <= TEST_PORT_END; port++) {
        ServerArgs sargs = {.port = (uint16_t)port,
                            .bind_addr = "127.0.0.1",
                            .server_name = "test"};
        if (http_create_server(&sargs, &g_srv) == SERVER_OK) {
            created = true;
            break;
        }
    }
    CHECK(created);
    if (!created)
        return;
    g_port = g_srv.port;

    http_get(&g_srv, "/negotiate", h_accepts_echo);

    pthread_t th;
    CHECK(pthread_create(&th, NULL, server_thread, NULL) == 0);
    CHECK(wait_listening(g_port));
    g_srv_ready = true;

    char rsp[16 * 1024];
    size_t n;

    n = get("GET /negotiate HTTP/1.1\r\nHost: t\r\nAccept: text/html\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\npick=text/html") != NULL);

    n = get("GET /negotiate HTTP/1.1\r\nHost: t\r\nAccept: image/png\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "\r\n\r\npick=-") != NULL);

    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

int main(void)
{
    alarm(60); /* watchdog: the test must not hang */

    test_accepts_encoding();
    test_set_header_validation();
    test_route_limits();
    test_group_paths();
    test_integration();
    test_static_files();
    test_param_registration();
    test_route_params();
    test_params_attacks();
    test_req_header_unit();
    test_req_header_integration();
    test_locals_unit();
    test_query_locals_integration();
    test_res_helpers_unit();
    test_error_channel();
    test_routers();
    test_body_parsers();
    test_keep_alive();
    test_concurrency();
    test_auto_options();
    test_range_requests();
    test_multipart();
    test_content_negotiation();

    return test_report();
}
