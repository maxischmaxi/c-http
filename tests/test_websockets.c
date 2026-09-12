/* Websocket integration tests: raw-socket style like test_http.c.
 * Each test speaks RFC 6455 directly — handshake, masked client
 * frames, unmasked server frames — so the library is validated
 * against the wire protocol, not against itself. */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
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

/* RFC 6455 §1.3 handshake example key and its accept value. */
#define TEST_WS_KEY    "dGhlIHNhbXBsZSBub25jZQ=="
#define TEST_WS_ACCEPT "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

static HttpServer g_srv;
static uint16_t g_port = 0;
static bool g_srv_ready = false;

/* ---------------------------------------------------------------
 * test server
 * --------------------------------------------------------------- */

static void ws_echo_handler(HttpWs *ws, const HttpRequest *req)
{
    (void)req;
    HttpWsMessage msg;
    while (http_ws_recv(ws, &msg) == HTTP_WS_OK) {
        if (msg.type == HTTP_WS_TEXT) {
            http_ws_send_text(ws, msg.data, msg.len);
        } else {
            http_ws_send_binary(ws, msg.data, msg.len);
        }
    }
}

static void ws_param_handler(HttpWs *ws, const HttpRequest *req)
{
    const char *id = http_req_param(req, "id");
    if (id != NULL) {
        char buf[80];
        int n = snprintf(buf, sizeof(buf), "room=%s", id);
        http_ws_send_text(ws, buf, (size_t)n);
    }
    ws_echo_handler(ws, req);
}

static void ws_ping_handler(HttpWs *ws, const HttpRequest *req)
{
    (void)req;
    /* never echoes: only answers pings (auto-pong in the library) */
    HttpWsMessage msg;
    while (http_ws_recv(ws, &msg) == HTTP_WS_OK) {
        http_ws_send_text(ws, "busy", 4);
    }
}

static bool ws_verify_reject(const HttpRequest *req)
{
    return http_req_header(req, "X-Allow") != NULL;
}

static void ws_drop_handler(HttpWs *ws, const HttpRequest *req)
{
    (void)req;
    HttpWsMessage msg;
    /* handler returns without recv/close: library auto-closes (1000) */
    (void)http_ws_recv(ws, &msg);
}

static void *server_thread(void *arg)
{
    (void)arg;
    http_listen(&g_srv);
    return NULL;
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
        nanosleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000},
                  NULL);
    }
    return false;
}

static bool start_server(void)
{
    for (int port = 18000; port < 18200; port++) {
        ServerArgs args = {.port = (uint16_t)port,
                           .bind_addr = "127.0.0.1",
                           .server_name = "ws-test",
                           .worker_threads = 8};
        if (http_create_server(&args, &g_srv) == SERVER_OK) {
            break;
        }
    }
    g_port = g_srv.port;

    CHECK(http_ws(&g_srv, "/ws", ws_echo_handler) == HTTP_ROUTE_ADD_OK);
    CHECK(http_ws(&g_srv, "/ws/room/:id", ws_param_handler) ==
          HTTP_ROUTE_ADD_OK);
    CHECK(http_ws(&g_srv, "/ws/ping", ws_ping_handler) == HTTP_ROUTE_ADD_OK);
    CHECK(http_ws(&g_srv, "/ws/drop", ws_drop_handler) == HTTP_ROUTE_ADD_OK);

    HttpWsOptions opts = {.max_message = 64};
    CHECK(http_ws_options(&g_srv, "/ws/limited", ws_echo_handler, &opts) ==
          HTTP_ROUTE_ADD_OK);

    HttpWsOptions verify_opts = {.verify = ws_verify_reject};
    CHECK(http_ws_options(&g_srv, "/ws/verify", ws_echo_handler,
                          &verify_opts) == HTTP_ROUTE_ADD_OK);

    static const char *const protos[] = {"chat", "superchat", NULL};
    HttpWsOptions proto_opts = {.subprotocols = protos};
    CHECK(http_ws_options(&g_srv, "/ws/proto", ws_echo_handler, &proto_opts) ==
          HTTP_ROUTE_ADD_OK);

    /* sanity: the same path twice is a conflict */
    CHECK(http_ws(&g_srv, "/ws", ws_echo_handler) == HTTP_ROUTE_ADD_CONFLICT);

    pthread_t thread;
    if (pthread_create(&thread, NULL, server_thread, NULL) != 0) {
        return false;
    }
    if (!wait_listening(g_port)) {
        return false;
    }
    g_srv_ready = true;
    pthread_detach(thread);
    return true;
}

/* ---------------------------------------------------------------
 * raw client helpers
 * --------------------------------------------------------------- */

static int ws_tcp_connect(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
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
        return -1;
    }
    return fd;
}

static ssize_t send_all(int fd, const void *data, size_t len)
{
    const char *p = data;
    size_t sent = 0;
    while (sent < len) {
        ssize_t s = send(fd, p + sent, len - sent, 0);
        if (s < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t)s;
    }
    return (ssize_t)sent;
}

static ssize_t recv_all(int fd, void *buf, size_t len)
{
    char *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t r = recv(fd, p + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r == 0) {
            break;
        }
        got += (size_t)r;
    }
    return (ssize_t)got;
}

/* Sends a client frame: masked (as clients MUST), FIN set. The whole
 * masked payload goes out in ONE send — a byte-per-send client lets
 * the server react (and close) mid-frame. */
static int ws_client_frame(int fd, unsigned char opcode, const void *payload,
                           size_t len, bool fin)
{
    unsigned char hdr[14];
    size_t hlen = 0;

    hdr[0] = (unsigned char)((fin ? 0x80 : 0x00) | opcode);
    if (len <= 125) {
        hdr[1] = (unsigned char)(0x80 | len);
        hlen = 2;
    } else if (len <= 0xFFFF) {
        hdr[1] = (unsigned char)(0x80 | 126);
        hdr[2] = (unsigned char)(len >> 8);
        hdr[3] = (unsigned char)len;
        hlen = 4;
    } else {
        hdr[1] = (unsigned char)(0x80 | 127);
        for (int i = 0; i < 8; i++) {
            hdr[2 + i] = (unsigned char)(((uint64_t)len) >> (56 - 8 * i));
        }
        hlen = 10;
    }

    unsigned char mask[4] = {0x11, 0x22, 0x33, 0x44};
    memcpy(hdr + hlen, mask, 4);
    hlen += 4;

    unsigned char *masked = NULL;
    if (len > 0) {
        masked = malloc(len);
        if (masked == NULL) {
            return -1;
        }
        const unsigned char *p = payload;
        for (size_t i = 0; i < len; i++) {
            masked[i] = p[i] ^ mask[i % 4];
        }
    }

    int rc = 0;
    if (send_all(fd, hdr, hlen) < 0 ||
        (len > 0 && send_all(fd, masked, len) < 0)) {
        rc = -1;
    }
    free(masked);
    return rc;
}

/* Reads one server frame (never masked). Returns the opcode, fills
 * payload/len (buffer owned by the caller). -1 on error. */
static int ws_read_frame(int fd, unsigned char *payload, size_t cap,
                         size_t *len)
{
    unsigned char hdr[10];
    if (recv_all(fd, hdr, 2) < 2) {
        return -1;
    }
    unsigned char opcode = hdr[0] & 0x0F;
    bool masked = (hdr[1] & 0x80) != 0;
    size_t plen = hdr[1] & 0x7F;

    if (plen == 126) {
        if (recv_all(fd, hdr + 2, 2) < 2) {
            return -1;
        }
        plen = ((size_t)hdr[2] << 8) | (size_t)hdr[3];
    } else if (plen == 127) {
        if (recv_all(fd, hdr + 2, 8) < 8) {
            return -1;
        }
        plen = 0;
        for (int i = 0; i < 8; i++) {
            plen = (plen << 8) | (size_t)hdr[2 + i];
        }
    }

    unsigned char mask[4] = {0};
    if (masked) {
        if (recv_all(fd, mask, 4) < 4) {
            return -1;
        }
    }
    if (plen > cap) {
        return -1;
    }
    if (recv_all(fd, payload, plen) < (ssize_t)plen) {
        return -1;
    }
    if (masked) {
        for (size_t i = 0; i < plen; i++) {
            payload[i] ^= mask[i % 4];
        }
    }
    *len = plen;
    return opcode;
}

/* Builds the handshake request for the given path. extra is appended
 * as further header lines (must end with "\r\n" or be NULL). */
static int ws_build_handshake(char *out, size_t outsz, const char *path,
                              const char *key, const char *extra)
{
    return snprintf(out, outsz,
                    "GET %s HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Connection: Upgrade\r\n"
                    "Upgrade: websocket\r\n"
                    "Sec-WebSocket-Key: %s\r\n"
                    "Sec-WebSocket-Version: 13\r\n"
                    "%s"
                    "\r\n",
                    path, key, extra != NULL ? extra : "");
}

/* Performs the handshake, expects `status` (e.g. "101"). Returns the
 * socket or -1. resp holds the raw response head (for header checks).
 * On 101 the fd stays open for frames. */
static int ws_handshake(uint16_t port, const char *path, const char *key,
                        const char *extra_headers, const char *status,
                        char *resp, size_t resp_sz)
{
    char req[1024];
    int n = ws_build_handshake(req, sizeof(req), path, key, extra_headers);
    if (n <= 0 || (size_t)n >= sizeof(req)) {
        return -1;
    }

    int fd = ws_tcp_connect(port);
    if (fd < 0) {
        return -1;
    }
    if (send_all(fd, req, (size_t)n) < 0) {
        close(fd);
        return -1;
    }

    size_t got = 0;
    while (got + 1 < resp_sz) {
        ssize_t r = recv(fd, resp + got, resp_sz - 1 - got, 0);
        if (r <= 0) {
            break;
        }
        got += (size_t)r;
        resp[got] = '\0';
        if (strstr(resp, "\r\n\r\n") != NULL) {
            break;
        }
    }
    resp[got] = '\0';
    if (got == 0) {
        close(fd);
        return -1;
    }
    if (status != NULL && strstr(resp, status) == NULL) {
        fprintf(stderr, "handshake status mismatch, got:\n%s\n", resp);
        close(fd);
        return -1;
    }
    return fd;
}

/* Close handshake from the client side; verifies the echoed code. */
static bool ws_client_close(int fd, unsigned short code,
                            unsigned short *echo_code)
{
    unsigned char payload[3];
    payload[0] = (unsigned char)(code >> 8);
    payload[1] = (unsigned char)code;
    if (ws_client_frame(fd, 0x8, payload, 2, true) != 0) {
        return false;
    }

    unsigned char echo[128];
    size_t len = 0;
    int op = ws_read_frame(fd, echo, sizeof(echo), &len);
    if (op != 0x8 || len < 2) {
        return false;
    }
    if (echo_code != NULL) {
        *echo_code =
            (unsigned short)(((unsigned)echo[0] << 8) | (unsigned)echo[1]);
    }
    close(fd);
    return true;
}

/* ---------------------------------------------------------------
 * tests
 * --------------------------------------------------------------- */

/* Case-insensitive substring search (strcasestr is a GNU extension,
 * not available under _POSIX_C_SOURCE). */
static char *ci_strstr(const char *haystack, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0) {
        return (char *)haystack;
    }
    for (const char *p = haystack; *p != '\0'; p++) {
        size_t i = 0;
        while (i < nlen && p[i] != '\0' &&
               tolower((unsigned char)p[i]) ==
                   tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) {
            return (char *)p;
        }
    }
    return NULL;
}

static void test_handshake_ok(void)
{
    char resp[2048];
    int fd = ws_handshake(g_port, "/ws", TEST_WS_KEY, NULL, "101", resp,
                          sizeof(resp));
    CHECK(fd >= 0);

    CHECK(strstr(resp, "101 Switching Protocols") != NULL);
    CHECK(ci_strstr(resp, "Sec-WebSocket-Accept: " TEST_WS_ACCEPT) != NULL);
    CHECK(ci_strstr(resp, "Upgrade: websocket") != NULL);
    CHECK(ci_strstr(resp, "Connection: Upgrade") != NULL);

    /* immediate roundtrip on the same connection */
    CHECK(ws_client_frame(fd, 0x1, "hello", 5, true) == 0);
    unsigned char buf[128];
    size_t len = 0;
    CHECK(ws_read_frame(fd, buf, sizeof(buf), &len) == 0x1);
    CHECK(len == 5 && memcmp(buf, "hello", 5) == 0);

    unsigned short echo = 0;
    CHECK(ws_client_close(fd, 1000, &echo));
    CHECK(echo == 1000);
}

static void test_handshake_rejections(void)
{
    char resp[2048];

    /* bad key: not 24 chars */
    int fd =
        ws_handshake(g_port, "/ws", "short", NULL, "400", resp, sizeof(resp));
    CHECK(fd >= 0);
    close(fd);

    /* bad key: 24 chars but not base64-of-16-bytes */
    fd = ws_handshake(g_port, "/ws", "!!!!!!!!!!!!!!!!!!!!!!!!", NULL, "400",
                      resp, sizeof(resp));
    CHECK(fd >= 0);
    close(fd);

    /* wrong version -> 426 + supported version */
    char req[1024];
    int n = ws_build_handshake(req, sizeof(req), "/ws", TEST_WS_KEY, NULL);
    CHECK(n > 0);
    /* overwrite the version line */
    char *v = strstr(req, "Sec-WebSocket-Version: 13");
    CHECK(v != NULL);
    memcpy(v, "Sec-WebSocket-Version: 8 ", 25);
    fd = ws_tcp_connect(g_port);
    CHECK(fd >= 0);
    CHECK(send_all(fd, req, (size_t)n) > 0);
    size_t got = 0;
    while (got + 1 < sizeof(resp)) {
        ssize_t r = recv(fd, resp + got, sizeof(resp) - 1 - got, 0);
        if (r <= 0) {
            break;
        }
        got += (size_t)r;
        resp[got] = '\0';
        if (strstr(resp, "\r\n\r\n") != NULL) {
            break;
        }
    }
    CHECK(strstr(resp, "426") != NULL);
    CHECK(ci_strstr(resp, "Sec-WebSocket-Version: 13") != NULL);
    close(fd);

    /* verify callback rejects (no X-Allow header) */
    fd = ws_handshake(g_port, "/ws/verify", TEST_WS_KEY, NULL, "403", resp,
                      sizeof(resp));
    CHECK(fd >= 0);
    close(fd);

    /* verify callback accepts with X-Allow */
    fd = ws_handshake(g_port, "/ws/verify", TEST_WS_KEY, "X-Allow: 1\r\n",
                      "101", resp, sizeof(resp));
    CHECK(fd >= 0);
    close(fd);
}

static void test_subprotocols(void)
{
    char resp[2048];

    /* first client-offered, server-supported protocol wins */
    int fd = ws_handshake(g_port, "/ws/proto", TEST_WS_KEY,
                          "Sec-WebSocket-Protocol: superchat, chat\r\n", "101",
                          resp, sizeof(resp));
    CHECK(fd >= 0);
    CHECK(ci_strstr(resp, "Sec-WebSocket-Protocol: superchat") != NULL);
    close(fd);

    /* unsupported offer -> no protocol header in the 101 */
    fd = ws_handshake(g_port, "/ws/proto", TEST_WS_KEY,
                      "Sec-WebSocket-Protocol: json\r\n", "101", resp,
                      sizeof(resp));
    CHECK(fd >= 0);
    CHECK(ci_strstr(resp, "Sec-WebSocket-Protocol") == NULL);
    close(fd);

    /* no offer -> no header */
    fd = ws_handshake(g_port, "/ws/proto", TEST_WS_KEY, NULL, "101", resp,
                      sizeof(resp));
    CHECK(fd >= 0);
    CHECK(ci_strstr(resp, "Sec-WebSocket-Protocol") == NULL);
    close(fd);
}

static void test_not_an_upgrade_falls_through(void)
{
    /* A plain GET on a WS path (no upgrade headers): normal routing
     * -> 404, no crash. */
    const char *req = "GET /ws HTTP/1.1\r\nHost: x\r\n\r\n";
    char resp[2048];
    int fd = ws_tcp_connect(g_port);
    CHECK(fd >= 0);
    CHECK(send_all(fd, req, strlen(req)) > 0);
    size_t got = 0;
    while (got + 1 < sizeof(resp)) {
        ssize_t r = recv(fd, resp + got, sizeof(resp) - 1 - got, 0);
        if (r <= 0) {
            break;
        }
        got += (size_t)r;
        resp[got] = '\0';
        if (strstr(resp, "\r\n\r\n") != NULL) {
            break;
        }
    }
    CHECK(strstr(resp, "404") != NULL);
    close(fd);

    /* Upgrade request on an UNREGISTERED path: also normal routing. */
    fd = ws_handshake(g_port, "/nope", TEST_WS_KEY, NULL, "404", resp,
                      sizeof(resp));
    CHECK(fd >= 0);
    close(fd);
}

static void test_route_params(void)
{
    char resp[2048];
    int fd = ws_handshake(g_port, "/ws/room/lounge", TEST_WS_KEY, NULL, "101",
                          resp, sizeof(resp));
    CHECK(fd >= 0);

    unsigned char buf[128];
    size_t len = 0;
    CHECK(ws_read_frame(fd, buf, sizeof(buf), &len) == 0x1);
    CHECK(len == 11 && memcmp(buf, "room=lounge", 11) == 0);

    close(fd);
}

static void test_echo_sizes_and_fragmentation(void)
{
    char resp[2048];
    int fd = ws_handshake(g_port, "/ws", TEST_WS_KEY, NULL, "101", resp,
                          sizeof(resp));
    CHECK(fd >= 0);

    /* 16-bit length form (126 <= len <= 65535) */
    static char big[70000];
    for (size_t i = 0; i < sizeof(big); i++) {
        big[i] = (char)(i & 0xFF);
    }
    CHECK(ws_client_frame(fd, 0x2, big, 40000, true) == 0);
    unsigned char *buf = malloc(70000);
    CHECK(buf != NULL);
    size_t len = 0;
    CHECK(ws_read_frame(fd, buf, 70000, &len) == 0x2);
    CHECK(len == 40000 && memcmp(buf, big, 40000) == 0);

    /* 64-bit length form (> 65535; < 4 MiB message limit) */
    CHECK(ws_client_frame(fd, 0x2, big, sizeof(big), true) == 0);
    CHECK(ws_read_frame(fd, buf, 70000, &len) == 0x2);
    CHECK(len == sizeof(big) && memcmp(buf, big, sizeof(big)) == 0);

    /* fragmentation: text + cont(!fin) + cont(fin) -> one message */
    CHECK(ws_client_frame(fd, 0x1, "foo", 3, false) == 0);
    CHECK(ws_client_frame(fd, 0x0, "bar", 3, false) == 0);
    CHECK(ws_client_frame(fd, 0x0, "baz", 3, true) == 0);
    CHECK(ws_read_frame(fd, buf, 70000, &len) == 0x1);
    CHECK(len == 9 && memcmp(buf, "foobarbaz", 9) == 0);

    /* interleaved control frame during fragmentation */
    CHECK(ws_client_frame(fd, 0x1, "part1-", 6, false) == 0);
    CHECK(ws_client_frame(fd, 0x9, "ping!", 5, true) ==
          0); /* ping mid-message */
    CHECK(ws_client_frame(fd, 0x0, "part2", 5, true) == 0);

    unsigned char small[128];
    /* first the pong (answer to our ping), then the assembled message */
    CHECK(ws_read_frame(fd, small, sizeof(small), &len) == 0xA);
    CHECK(len == 5 && memcmp(small, "ping!", 5) == 0);
    CHECK(ws_read_frame(fd, small, sizeof(small), &len) == 0x1);
    CHECK(len == 11 && memcmp(small, "part1-part2", 11) == 0);

    /* zero-length message */
    CHECK(ws_client_frame(fd, 0x1, "", 0, true) == 0);
    CHECK(ws_read_frame(fd, small, sizeof(small), &len) == 0x1);
    CHECK(len == 0);

    free(buf);
    close(fd);
}

static void test_ping_pong(void)
{
    char resp[2048];
    int fd = ws_handshake(g_port, "/ws/ping", TEST_WS_KEY, NULL, "101", resp,
                          sizeof(resp));
    CHECK(fd >= 0);

    CHECK(ws_client_frame(fd, 0x9, "heartbeat", 9, true) == 0);
    unsigned char buf[128];
    size_t len = 0;
    CHECK(ws_read_frame(fd, buf, sizeof(buf), &len) == 0xA);
    CHECK(len == 9 && memcmp(buf, "heartbeat", 9) == 0);

    close(fd);
}

static void test_protocol_violations(void)
{
    unsigned char buf[256];
    size_t len = 0;

    /* unmasked client frame -> close 1002 */
    char resp[2048];
    int fd = ws_handshake(g_port, "/ws", TEST_WS_KEY, NULL, "101", resp,
                          sizeof(resp));
    CHECK(fd >= 0);
    unsigned char frame[] = {0x81, 0x03, 'a', 'b', 'c'};
    CHECK(send_all(fd, frame, sizeof(frame)) > 0);
    CHECK(ws_read_frame(fd, buf, sizeof(buf), &len) == 0x8);
    CHECK(len == 2 && buf[0] == 0x03 && buf[1] == 0xEA); /* 1002 */
    close(fd);

    /* oversized message on /ws/limited (max 64 bytes) -> close 1009 */
    fd = ws_handshake(g_port, "/ws/limited", TEST_WS_KEY, NULL, "101", resp,
                      sizeof(resp));
    CHECK(fd >= 0);
    static char big[200];
    memset(big, 'x', sizeof(big));
    CHECK(ws_client_frame(fd, 0x1, big, 200, true) == 0);
    CHECK(ws_read_frame(fd, buf, sizeof(buf), &len) == 0x8);
    CHECK(len == 2 && buf[0] == 0x03 && buf[1] == 0xF1); /* 1009 */
    close(fd);

    /* new data frame while a fragmented message is active -> 1002 */
    fd = ws_handshake(g_port, "/ws", TEST_WS_KEY, NULL, "101", resp,
                      sizeof(resp));
    CHECK(fd >= 0);
    CHECK(ws_client_frame(fd, 0x1, "a", 1, false) == 0);
    CHECK(ws_client_frame(fd, 0x1, "b", 1, true) == 0);
    CHECK(ws_read_frame(fd, buf, sizeof(buf), &len) == 0x8);
    CHECK(len == 2 && buf[0] == 0x03 && buf[1] == 0xEA); /* 1002 */
    close(fd);
}

static void test_leftover_bytes(void)
{
    /* Handshake + first frame in ONE send: the frames must not be
     * lost when the request buffer is handed to the WS session. */
    char req[1024];
    int n = ws_build_handshake(req, sizeof(req), "/ws", TEST_WS_KEY, NULL);
    CHECK(n > 0);

    int fd = ws_tcp_connect(g_port);
    CHECK(fd >= 0);

    /* frame with a distinct mask, sent right behind the handshake */
    unsigned char frame[2 + 4 + 5];
    frame[0] = 0x81;
    frame[1] = (unsigned char)(0x80 | 5);
    frame[2] = 0xAA;
    frame[3] = 0xBB;
    frame[4] = 0xCC;
    frame[5] = 0xDD;
    const char *msg = "early";
    for (int i = 0; i < 5; i++) {
        frame[6 + i] = (unsigned char)(msg[i] ^ frame[2 + (i % 4)]);
    }

    CHECK(send_all(fd, req, (size_t)n) > 0);
    CHECK(send_all(fd, frame, sizeof(frame)) > 0);

    char resp[2048];
    size_t got = 0;
    while (got + 1 < sizeof(resp)) {
        ssize_t r = recv(fd, resp + got, sizeof(resp) - 1 - got, 0);
        if (r <= 0) {
            break;
        }
        got += (size_t)r;
        resp[got] = '\0';
        if (strstr(resp, "\r\n\r\n") != NULL) {
            break;
        }
    }
    CHECK(strstr(resp, "101") != NULL);

    unsigned char buf[128];
    size_t len = 0;
    CHECK(ws_read_frame(fd, buf, sizeof(buf), &len) == 0x1);
    CHECK(len == 5 && memcmp(buf, "early", 5) == 0);
    close(fd);
}

static void test_handler_auto_close(void)
{
    /* Handler returns without http_ws_close: the library must send a
     * 1000 close and finish the handshake. */
    char resp[2048];
    int fd = ws_handshake(g_port, "/ws/drop", TEST_WS_KEY, NULL, "101", resp,
                          sizeof(resp));
    CHECK(fd >= 0);

    /* trigger the recv that makes the handler return */
    CHECK(ws_client_frame(fd, 0x1, "x", 1, true) == 0);

    unsigned char buf[128];
    size_t len = 0;
    CHECK(ws_read_frame(fd, buf, sizeof(buf), &len) == 0x8);
    CHECK(len == 2 && buf[0] == 0x03 && buf[1] == 0xE8); /* 1000 */
    close(fd);
}

/* dedicated listen thread for an ad-hoc server */
typedef struct {
    HttpServer *srv;
} ListenArgs;

static void *listen_main(void *arg)
{
    ListenArgs *la = arg;
    http_listen(la->srv);
    return NULL;
}

static void test_iterative_503(void)
{
    HttpServer srv;
    ServerArgs args = {.port = 18301,
                       .bind_addr = "127.0.0.1",
                       .server_name = "iter",
                       .worker_threads = 0};
    CHECK(http_create_server(&args, &srv) == SERVER_OK);
    CHECK(http_ws(&srv, "/ws", ws_echo_handler) == HTTP_ROUTE_ADD_OK);

    ListenArgs la = {.srv = &srv};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, listen_main, &la) == 0);
    CHECK(wait_listening(srv.port));

    char resp[2048];
    CHECK(ws_handshake(srv.port, "/ws", TEST_WS_KEY, NULL, "503", resp,
                       sizeof(resp)) >= 0);
    CHECK(strstr(resp, "503") != NULL);

    /* normal HTTP still works on the same iterative server */
    const char *req = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    int fd = ws_tcp_connect(srv.port);
    CHECK(fd >= 0);
    CHECK(send_all(fd, req, strlen(req)) > 0);
    size_t got = 0;
    while (got + 1 < sizeof(resp)) {
        ssize_t r = recv(fd, resp + got, sizeof(resp) - 1 - got, 0);
        if (r <= 0) {
            break;
        }
        got += (size_t)r;
        resp[got] = '\0';
        if (strstr(resp, "\r\n\r\n") != NULL) {
            break;
        }
    }
    CHECK(strstr(resp, "404") != NULL);
    close(fd);

    http_stop_server(&srv);
    pthread_join(thread, NULL);
    http_close_server(&srv);
}

static void test_graceful_shutdown(void)
{
    /* An active WS session must end shortly after http_stop_server():
     * recv polls the listening flag and closes with 1001. */
    HttpServer srv;
    ServerArgs args = {.port = 18401,
                       .bind_addr = "127.0.0.1",
                       .server_name = "stop",
                       .worker_threads = 4};
    CHECK(http_create_server(&args, &srv) == SERVER_OK);
    CHECK(http_ws(&srv, "/ws", ws_echo_handler) == HTTP_ROUTE_ADD_OK);

    ListenArgs la = {.srv = &srv};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, listen_main, &la) == 0);
    CHECK(wait_listening(srv.port));

    char resp[2048];
    int fd = ws_handshake(srv.port, "/ws", TEST_WS_KEY, NULL, "101", resp,
                          sizeof(resp));
    CHECK(fd >= 0);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    http_stop_server(&srv);

    /* the session closes with 1001 (Going Away) — the client is
     * blocked in recv, so the SO_RCVTIMEO of the TEST client is 5s:
     * the close frame must arrive well within that. */
    unsigned char buf[128];
    size_t len = 0;
    int op = ws_read_frame(fd, buf, sizeof(buf), &len);
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 +
                (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;

    CHECK(op == 0x8);
    CHECK(len >= 2 && buf[0] == 0x03 && buf[1] == 0xE9); /* 1001 */
    CHECK(ms < 4000.0);
    close(fd);

    pthread_join(thread, NULL);
    http_close_server(&srv);
}

int main(void)
{
    alarm(120); /* watchdog: the test must not hang */

    if (!start_server()) {
        fprintf(stderr, "failed to start the test server\n");
        return 1;
    }

    test_handshake_ok();
    test_handshake_rejections();
    test_subprotocols();
    test_not_an_upgrade_falls_through();
    test_route_params();
    test_echo_sizes_and_fragmentation();
    test_ping_pong();
    test_protocol_violations();
    test_leftover_bytes();
    test_handler_auto_close();
    test_iterative_503();
    test_graceful_shutdown();

    http_stop_server(&g_srv);
    http_close_server(&g_srv);
    (void)g_srv_ready;
    return test_report();
}