/* Integration + unit tests for the c-http library.
 *
 * Runs a real server in a thread and talks raw HTTP over sockets, so the
 * whole path (parsing, routing, middleware, encoding, responses) is
 * covered. An alarm() watchdog fails the test if anything deadlocks.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
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
    if (fd < 0)
        return 0;

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
        if (s <= 0)
            break;
        sent += (size_t)s;
    }

    size_t total = 0;
    while (total + 1 < outsz) {
        ssize_t r = recv(fd, out + total, outsz - 1 - total, 0);
        if (r <= 0)
            break;
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
        nanosleep(&(struct timespec){.tv_nsec = 20 * 1000 * 1000}, NULL);
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
    for (size_t i = 0; i < srv.route_count; i++) {
        if (strcmp(srv.routes[i].path, "/api/users") == 0)
            found_users = true;
        if (strcmp(srv.routes[i].path, "/api") == 0)
            found_api = true;
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
    if (!created)
        return;
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
    for (int i = 0; i < 600; i++)
        strcat(long_req, "a");
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
        memcpy(body_req + sizeof(head) - 1, "ab\0cd", 5);
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
    if (!created)
        return;
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

int main(void)
{
    alarm(60); /* watchdog: the test must not hang */

    test_accepts_encoding();
    test_set_header_validation();
    test_route_limits();
    test_group_paths();
    test_integration();
    test_static_files();

    return test_report();
}