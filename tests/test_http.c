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
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "c_http.h"
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

    /* kein Accept-Encoding -> nichts akzeptiert */
    CHECK(http_accepts_encoding(&req, "gzip") == false);

    struct {
        const char *value;
        bool expect_gzip;
        const char *label;
    } cases[] = {
        {"gzip", true, "plain gzip"},
        {"deflate, gzip;q=1.0", true, "gzip;q=1.0"},
        {"gzip;q=0", false, "gzip;q=0 verboten"},
        {"gzip;q=0.0", false, "gzip;q=0.0 verboten"},
        {"*", true, "wildcard"},
        {"gzip;q=0, *", false, "explizit q=0 schlaegt wildcard"},
        {"br, *", true, "wildcard fuer ungenanntes"},
        {"GZIP", true, "case-insensitive"},
        {"gzipx", false, "kein Prefix-Match"},
        {"xgzip", false, "kein Suffix-Match"},
        {"gzip;q=0.5;foo=bar", true, "q mit Parametern"},
        {"deflate, br", false, "gzip nicht gelistet"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        http_set_header(&req.headers, HTTP_HEADER_ACCEPT_ENCODING,
                        cases[i].value);
        bool got = http_accepts_encoding(&req, "gzip");
        CHECK_MSG(got == cases[i].expect_gzip, cases[i].label);
        http_headers_free(&req.headers);
    }

    /* mehrere Accept-Encoding-Header werden alle beruecksichtigt */
    http_set_header(&req.headers, HTTP_HEADER_ACCEPT_ENCODING, "deflate");
    http_set_header(&req.headers, HTTP_HEADER_ACCEPT_ENCODING, "gzip");
    CHECK(http_accepts_encoding(&req, "gzip") == true);
    http_headers_free(&req.headers);
}

static void test_set_header_validation(void)
{
    HttpHeaders h = {0};

    /* Header-Injection muss zurueckgewiesen werden — auch im Release-Build */
    CHECK(http_set_header(&h, "X-Test", "value\r\nSet-Cookie: pwned=1") ==
          HTTP_SET_HEADER_ERROR);
    CHECK(http_set_header(&h, "X-Test", "value\nSet-Cookie: pwned=1") ==
          HTTP_SET_HEADER_ERROR);

    /* ungueltige Feldnamen */
    CHECK(http_set_header(&h, "Bad Name", "value") == HTTP_SET_HEADER_ERROR);
    CHECK(http_set_header(&h, "", "value") == HTTP_SET_HEADER_ERROR);
    CHECK(http_set_header(&h, "X-Test:", "value") == HTTP_SET_HEADER_ERROR);
    CHECK(http_set_header(&h, "X-Bad\x01Name", "value") ==
          HTTP_SET_HEADER_ERROR);

    /* gueltig */
    CHECK(http_set_header(&h, "X-Test", "value") == HTTP_SET_HEADER_OK);
    CHECK(h.count == 1);

    http_headers_free(&h);
}

static void test_route_limits(void)
{
    ServerArgs args = {.port = 0, .bind_addr = "127.0.0.1", .server_name = "t"};
    HttpServer srv;
    CHECK(http_create_server(&args, &srv) == SERVER_OK);

    /* Route laenger als HTTP_PATH_MAX kann nie matchen -> ablehnen */
    char long_path[HTTP_PATH_MAX + 2];
    long_path[0] = '/';
    memset(long_path + 1, 'a', HTTP_PATH_MAX);
    long_path[HTTP_PATH_MAX + 1] = '\0';
    CHECK(http_get(&srv, long_path, h_root) == HTTP_ROUTE_ADD_ERROR);

    /* Konflikt-Erkennung */
    CHECK(http_get(&srv, "/x", h_root) == HTTP_ROUTE_ADD_OK);
    CHECK(http_get(&srv, "/x", h_root) == HTTP_ROUTE_ADD_CONFLICT);
    CHECK(http_post(&srv, "/x", h_root) == HTTP_ROUTE_ADD_OK);

    /* Group: Prefix zu lang -> Truncation wird erkannt */
    char big_prefix[600];
    big_prefix[0] = '/';
    memset(big_prefix + 1, 'p', sizeof(big_prefix) - 2);
    big_prefix[sizeof(big_prefix) - 1] = '\0';
    HttpGroup g = http_group(&srv, big_prefix);
    CHECK(http_group_get(&g, "/deep", h_root) == HTTP_ROUTE_ADD_ERROR);

    /* fd == -1 und Double-Close muessen ueberleben */
    http_close_server(&srv);
    http_close_server(&srv);

    /* ServerArgs mit NULL-Werten */
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

    /* "/api/users" und "/api" registriert */
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

    /* 1) GET / -> 200 + Body + genau EIN Content-Type */
    n = get("GET / HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(count_occurrences(rsp, "Content-Type:") == 1);
    CHECK(strstr(rsp, "\r\n\r\nok") != NULL);

    /* 2) Query-String wird abgetrennt */
    n = get("GET /?x=1&y=2 HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);

    /* 3) HEAD faellt auf GET zurueck und sendet keinen Body */
    n = get("HEAD / HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Length: 2") != NULL);
    CHECK(strcmp(rsp + strlen(rsp) - 4, "\r\n\r\n") == 0); /* kein Body */

    /* 4) falsche Methode -> 405 + Allow */
    n = get("POST /only-get HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 405", 12) == 0);
    CHECK(strstr(rsp, "Allow: GET") != NULL);

    /* 5) unbekannte/zu lange Methode -> 501 */
    n = get("PROPFINDX / HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 501", 12) == 0);

    /* 6) kaputte Request-Line -> 400, es WIRD eine Response gesendet */
    n = get("GARBAGE\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 400", 12) == 0);

    /* 7) 2-Felder-Request-Line -> 400 */
    n = get("GET /\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 400", 12) == 0);

    /* 8) zu langer URI -> 414 */
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

    /* 10) Header > 4096 Bytes -> 431 */
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

    /* 12) gzip;q=0 -> KEIN gzip */
    n = get("GET /big HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip;q=0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "Content-Encoding:") == NULL);

    /* 13) gzip;q=0, * -> gzip bleibt verboten (explizit schlaegt Wildcard) */
    n = get("GET /big HTTP/1.1\r\nHost: t\r\n"
            "Accept-Encoding: gzip;q=0, *\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strstr(rsp, "Content-Encoding: gzip") == NULL);

    /* 14) POST-Body wird gelesen und ist im Handler verfuegbar */
    n = get("POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: 11\r\n\r\n"
            "hello world",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);
    CHECK(strstr(rsp, "\r\n\r\nhello world") != NULL);

    /* 15) Body mit NUL-Byte (muss ueber die Laenge, nicht strlen, laufen) */
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
        /* Body im Response suchen (enthaelt NUL) */
        const char *body_start = strstr(rsp, "\r\n\r\n");
        CHECK(body_start != NULL);
        CHECK((size_t)(body_start + 9 - rsp) <= n);
        CHECK(memcmp(body_start + 4, "ab\0cd", 5) == 0);
    }

    /* 16) abweichende doppelte Content-Length -> 400 */
    n = get("POST /echo HTTP/1.1\r\nHost: t\r\n"
            "Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 400", 12) == 0);

    /* 17) identische doppelte Content-Length -> ok */
    n = get("POST /echo HTTP/1.1\r\nHost: t\r\n"
            "Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);

    /* 18) Transfer-Encoding -> 501 (nicht unterstuetzt) */
    n = get("POST /echo HTTP/1.1\r\nHost: t\r\n"
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 501", 12) == 0);

    /* 19) Middleware-STOP: /private ohne Auth -> 401 */
    n = get("GET /private/x HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 401", 12) == 0);
    CHECK(auth_mw_ran);

    /* 20) Client haelt die Verbindung offen und sendet nichts ->
     *     Server antwortet danach normal weiter (Timeout greift, aber
     *     hier nur: danach ist der Server noch lebendig). */
    n = get("GET / HTTP/1.1\r\nHost: t\r\n\r\n", rsp, sizeof(rsp));
    CHECK(n > 0);
    CHECK(strncmp(rsp, "HTTP/1.1 200", 12) == 0);

    /* Server sauber stoppen (das war vorher unmoeglich) */
    http_stop_server(&g_srv);
    CHECK(pthread_join(th, NULL) == 0);
    http_close_server(&g_srv);
}

int main(void)
{
    alarm(60); /* Watchdog: Test darf nicht haengen */

    test_accepts_encoding();
    test_set_header_validation();
    test_route_limits();
    test_group_paths();
    test_integration();

    return test_report();
}