#include "c_http_ws.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "c_http_assert.h"

/* ============================================================
 * WebSockets (RFC 6455), server side.
 *
 * Layers (bottom to top):
 *   1. primitives   SHA-1 + Base64 for Sec-WebSocket-Accept
 *   2. frame codec  writer (server frames are never masked) and a
 *                   parse state machine (client frames MUST be masked)
 *   3. session      per-connection state; blocking recv with a short
 *                   poll timeout for the graceful-shutdown check
 *   4. dispatch     handshake validation + 101, called from
 *                   handle_client AFTER middleware, BEFORE routing
 *
 * Threading: the handler thread owns the recv side (http_ws_recv is
 * NOT thread-safe), every send takes ws->lock — other threads may
 * broadcast while a handler runs. The lock also guards the
 * dead/close flags; http_stop_server needs no lock because recv
 * polls server->listening (same benign race as the accept loop).
 * ============================================================ */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 /* platform without MSG_NOSIGNAL (e.g. macOS) */
#endif

/* Frame opcodes (RFC 6455 §5.2) */
#define WS_OP_CONT   0x0
#define WS_OP_TEXT   0x1
#define WS_OP_BINARY 0x2
#define WS_OP_CLOSE  0x8
#define WS_OP_PING   0x9
#define WS_OP_PONG   0xA

/* Initial recv buffer of a session. Frames do not have to fit whole:
 * payload streams chunk-wise into the message assembly buffer. */
#define WS_RECV_BUFFER 4096
/* Upper bound for recv buffer growth (safety net — parse consumes
 * eagerly, so this is never reached in practice). */
#define WS_RECV_BUFFER_MAX ((size_t)64 * 1024)

/* RFC 6455 §1.3: the fixed GUID appended to Sec-WebSocket-Key. */
static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/* ============================================================
 * SHA-1 (FIPS 180-1) — only needed for the handshake accept key
 * ============================================================ */

typedef struct {
    uint32_t state[5];
    uint64_t total;
    unsigned char buf[64];
    size_t buf_len;
} Sha1;

static uint32_t rol32(uint32_t v, unsigned bits)
{
    return (v << bits) | (v >> (32U - bits));
}

static void sha1_init(Sha1 *s)
{
    s->state[0] = 0x67452301U;
    s->state[1] = 0xEFCDAB89U;
    s->state[2] = 0x98BADCFEU;
    s->state[3] = 0x10325476U;
    s->state[4] = 0xC3D2E1F0U;
    s->total = 0;
    s->buf_len = 0;
}

static void sha1_block(Sha1 *s, const unsigned char *p)
{
    uint32_t w[80];

    for (size_t i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[(i * 4)] << 24) | ((uint32_t)p[(i * 4) + 1] << 16) |
               ((uint32_t)p[(i * 4) + 2] << 8) | (uint32_t)p[(i * 4) + 3];
    }
    for (size_t i = 16; i < 80; i++) {
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = s->state[0];
    uint32_t b = s->state[1];
    uint32_t c = s->state[2];
    uint32_t d = s->state[3];
    uint32_t e = s->state[4];

    for (size_t i = 0; i < 80; i++) {
        uint32_t f;
        uint32_t k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }
        uint32_t tmp = rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = tmp;
    }

    s->state[0] += a;
    s->state[1] += b;
    s->state[2] += c;
    s->state[3] += d;
    s->state[4] += e;
}

static void sha1_update(Sha1 *s, const void *data, size_t len)
{
    const unsigned char *p = data;

    s->total += len;
    while (len > 0) {
        if (s->buf_len == 0 && len >= 64) {
            sha1_block(s, p);
            p += 64;
            len -= 64;
            continue;
        }
        size_t take = 64 - s->buf_len;
        if (take > len) {
            take = len;
        }
        memcpy(s->buf + s->buf_len, p, take);
        s->buf_len += take;
        p += take;
        len -= take;
        if (s->buf_len == 64) {
            sha1_block(s, s->buf);
            s->buf_len = 0;
        }
    }
}

static void sha1_final(Sha1 *s, unsigned char out[20])
{
    uint64_t bits = s->total * 8;

    unsigned char one = 0x80;
    sha1_update(s, &one, 1);
    unsigned char zero = 0;
    while (s->buf_len != 56) {
        sha1_update(s, &zero, 1);
    }
    unsigned char len8[8];
    for (size_t i = 0; i < 8; i++) {
        len8[i] = (unsigned char)(bits >> (56 - (8 * i)));
    }
    sha1_update(s, len8, 8); /* buf_len == 64 -> flushes */

    for (size_t i = 0; i < 5; i++) {
        out[(i * 4)] = (unsigned char)(s->state[i] >> 24);
        out[(i * 4) + 1] = (unsigned char)(s->state[i] >> 16);
        out[(i * 4) + 2] = (unsigned char)(s->state[i] >> 8);
        out[(i * 4) + 3] = (unsigned char)s->state[i];
    }
}

/* ============================================================
 * Base64 (RFC 4648)
 * ============================================================ */

static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Writes the base64 of in into out (out_size includes room for the
 * NUL). Returns the encoded length, or 0 when out is too small. */
static size_t base64_encode(const unsigned char *in, size_t in_len, char *out,
                            size_t out_size)
{
    size_t need = ((in_len + 2) / 3) * 4;
    if (out_size < need + 1) {
        return 0;
    }

    size_t o = 0;
    size_t i = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
                     (uint32_t)in[i + 2];
        out[o++] = B64_CHARS[(v >> 18) & 0x3F];
        out[o++] = B64_CHARS[(v >> 12) & 0x3F];
        out[o++] = B64_CHARS[(v >> 6) & 0x3F];
        out[o++] = B64_CHARS[v & 0x3F];
        i += 3;
    }

    size_t rem = in_len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = B64_CHARS[(v >> 18) & 0x3F];
        out[o++] = B64_CHARS[(v >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = B64_CHARS[(v >> 18) & 0x3F];
        out[o++] = B64_CHARS[(v >> 12) & 0x3F];
        out[o++] = B64_CHARS[(v >> 6) & 0x3F];
        out[o++] = '=';
    }

    out[o] = '\0';
    HTTP_ASSERT(o == need);
    return o;
}

static int base64_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

/* Decodes a padded base64 string into out. Returns false on invalid
 * characters, bad padding or insufficient out_size. */
static bool base64_decode(const char *in, size_t in_len, unsigned char *out,
                          size_t out_size, size_t *out_len)
{
    if (in_len == 0 || in_len % 4 != 0) {
        return false;
    }

    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        int v[4];
        size_t pad = 0;
        for (size_t j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') {
                /* '=' only allowed in the last group, at the end */
                if (i + 4 != in_len || j < 2) {
                    return false;
                }
                pad++;
                v[j] = 0;
                continue;
            }
            if (pad > 0) { /* data after '=' */
                return false;
            }
            v[j] = base64_value(c);
            if (v[j] < 0) {
                return false;
            }
        }

        size_t produced = 3 - pad;
        if (o + produced > out_size) {
            return false;
        }
        uint32_t acc = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                       ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        out[o++] = (unsigned char)(acc >> 16);
        if (produced > 1) {
            out[o++] = (unsigned char)(acc >> 8);
        }
        if (produced > 2) {
            out[o++] = (unsigned char)acc;
        }
    }

    *out_len = o;
    return true;
}

/* RFC 6455 §4.2.2: Sec-WebSocket-Accept = base64(SHA1(key + GUID)).
 * out must hold 29 bytes (28 chars + NUL). */
static bool ws_accept_key(const char *key, char *out, size_t out_size)
{
    if (out_size < 29) {
        return false;
    }

    Sha1 sha;
    sha1_init(&sha);
    sha1_update(&sha, key, strlen(key));
    sha1_update(&sha, WS_GUID, sizeof(WS_GUID) - 1);

    unsigned char digest[20];
    sha1_final(&sha, digest);

    return base64_encode(digest, sizeof(digest), out, out_size) == 28;
}

/* ============================================================
 * Small socket / header helpers
 * ============================================================ */

static int ws_send_raw(int fd, const void *data, size_t len)
{
    const char *p = data;
    size_t sent = 0;

    while (sent < len) {
        ssize_t s = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
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

/* Case-insensitive token check in a comma-separated header value
 * ("keep-alive, Upgrade" contains "upgrade"). */
static bool ws_header_has_token(const char *value, const char *token)
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

/* Sends a minimal HTTP error response for a rejected handshake.
 * extra_headers must already end with "\r\n" (or be NULL). */
static void ws_send_error_response(int fd, int status, const char *text,
                                   const char *message,
                                   const char *extra_headers)
{
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "%s"
                     "\r\n"
                     "%s",
                     status, text, strlen(message),
                     extra_headers != NULL ? extra_headers : "", message);
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        return; /* message too long — drop it, the caller closes */
    }
    (void)ws_send_raw(fd, buf, (size_t)n);
}

/* ============================================================
 * WS route registry (server->ws_routes)
 * ============================================================ */

typedef struct HttpWsRoute {
    char *path;
    HttpRouteSegments segments;
    HttpWsHandler handler;
    HttpWsVerify verify;
    char **subprotocols; /* strdup'd NULL-terminated array, may be NULL */
    size_t max_message;
    struct HttpWsRoute *next;
} HttpWsRoute;

/* Subprotocol names are echoed into a response header — reject
 * anything that could inject (control chars, separators, CR/LF). */
static bool ws_valid_subprotocol(const char *name)
{
    if (name == NULL || *name == '\0') {
        return false;
    }
    for (const char *p = name; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c <= 0x20 || c >= 0x7f) {
            return false;
        }
        if (strchr("()<>@,;:\\\"/[]?={}", c) != NULL) {
            return false;
        }
    }
    return true;
}

/* Shared registration core of http_ws()/http_ws_options(). */
static HttpRouteAddResult ws_add_route(HttpServer *server, const char *path,
                                       HttpWsHandler handler,
                                       const HttpWsOptions *options)
{
    if (server == NULL || path == NULL || handler == NULL) {
        return HTTP_ROUTE_ADD_ERROR;
    }
    if (path[0] != '/' || strlen(path) >= HTTP_PATH_MAX ||
        strchr(path, '?') != NULL) {
        return HTTP_ROUTE_ADD_ERROR;
    }

    /* Same fail-fast param validation as add_route_to(). */
    HttpRouteSegments segments;
    if (!http_parse_route_segments(path, &segments)) {
        return HTTP_ROUTE_ADD_ERROR;
    }
    size_t param_count = 0;
    for (size_t i = 0; i < segments.count; i++) {
        const HttpRouteSegment *segment = &segments.segments[i];
        if (!segment->is_param) {
            continue;
        }
        param_count++;
        if (param_count > HTTP_MAX_PARAMS ||
            strlen(segment->text) >= HTTP_PARAM_KEY_MAX) {
            free(segments.segments);
            return HTTP_ROUTE_ADD_ERROR;
        }
        for (size_t j = 0; j < i; j++) {
            if (segments.segments[j].is_param &&
                strcmp(segments.segments[j].text, segment->text) == 0) {
                free(segments.segments);
                return HTTP_ROUTE_ADD_ERROR;
            }
        }
    }

    for (const HttpWsRoute *r = server->ws_routes; r != NULL; r = r->next) {
        if (strcmp(r->path, path) == 0) {
            free(segments.segments);
            return HTTP_ROUTE_ADD_CONFLICT;
        }
    }

    HttpWsRoute *route = calloc(1, sizeof(*route));
    if (route == NULL) {
        free(segments.segments);
        return HTTP_ROUTE_ADD_ERROR;
    }
    route->path = strdup(path);
    if (route->path == NULL) {
        free(route);
        free(segments.segments);
        return HTTP_ROUTE_ADD_ERROR;
    }
    route->segments = segments;
    route->handler = handler;
    route->max_message = HTTP_WS_DEFAULT_MAX_MESSAGE;

    if (options != NULL) {
        route->verify = options->verify;
        if (options->max_message > 0) {
            route->max_message = options->max_message;
        }
        if (options->subprotocols != NULL) {
            size_t count = 0;
            while (options->subprotocols[count] != NULL) {
                if (!ws_valid_subprotocol(options->subprotocols[count])) {
                    goto bad_options;
                }
                count++;
            }
            /* count + 1 slots for the array + count strdups below; a
             * leak on failure is cleaned by bad_options. */
            char **owned = (char **)malloc((count + 1) * sizeof(*owned));
            if (owned == NULL) {
                goto bad_options;
            }
            for (size_t i = 0; i < count; i++) {
                owned[i] = strdup(options->subprotocols[i]);
                if (owned[i] == NULL) {
                    for (size_t j = 0; j < i; j++) {
                        free((void *)owned[j]);
                    }
                    free((void *)owned);
                    goto bad_options;
                }
            }
            owned[count] = NULL;
            route->subprotocols = owned;
        }
    }

    /* Tail-append: dispatch in registration order (like routes). */
    HttpWsRoute **tail = (HttpWsRoute **)&server->ws_routes;
    while (*tail != NULL) {
        tail = &(*tail)->next;
    }
    *tail = route;
    return HTTP_ROUTE_ADD_OK;

bad_options:
    free(route->path);
    free(route->segments.segments);
    free(route);
    return HTTP_ROUTE_ADD_ERROR;
}

HttpRouteAddResult http_ws(HttpServer *server, const char *path,
                           HttpWsHandler handler)
{
    return ws_add_route(server, path, handler, NULL);
}

HttpRouteAddResult http_ws_options(HttpServer *server, const char *path,
                                   HttpWsHandler handler,
                                   const HttpWsOptions *options)
{
    return ws_add_route(server, path, handler, options);
}

void http_ws_routes_free(HttpServer *server)
{
    if (server == NULL) {
        return;
    }
    HttpWsRoute *route = server->ws_routes;
    while (route != NULL) {
        HttpWsRoute *next = route->next;
        free(route->path);
        free(route->segments.segments);
        if (route->subprotocols != NULL) {
            for (size_t i = 0; route->subprotocols[i] != NULL; i++) {
                free((void *)route->subprotocols[i]);
            }
            free((void *)route->subprotocols);
        }
        free(route);
        route = next;
    }
    server->ws_routes = NULL;
}

/* ============================================================
 * Session
 * ============================================================ */

typedef enum {
    WS_NEED_HEADER,  /* 2 bytes: fin/opcode/mask/len7      */
    WS_NEED_LEN16,   /* 2 bytes: extended payload length    */
    WS_NEED_LEN64,   /* 8 bytes: extended payload length    */
    WS_NEED_MASK,    /* 4 bytes: masking key (always masked) */
    WS_NEED_PAYLOAD, /* payload chunk-wise into msg/ctrl    */
} WsParseState;

typedef enum {
    WS_PARSE_CONTINUE, /* need more input */
    WS_PARSE_MESSAGE,  /* complete message assembled (msg filled) */
    WS_PARSE_CLOSED,   /* close frame handled: session over */
    WS_PARSE_PROTOCOL, /* protocol violation: close sent, session over */
    WS_PARSE_IO_ERROR, /* send failed while auto-ponging */
} WsParseResult;

struct HttpWs {
    HttpServer *server;
    const HttpWsRoute *route;
    const HttpRequest *req;
    int fd;
    void *data;

    /* Serializes sends and guards the flags below. */
    pthread_mutex_t lock;
    bool close_sent;     /* we sent a close frame */
    bool close_received; /* the peer sent one */
    bool dead;           /* terminal: no more I/O on this session */
    bool io_error;       /* socket error (drives HTTP_WS_ERROR) */
    unsigned short close_code;

    /* recv side — owned by the handler thread. */
    unsigned char *in;
    size_t in_len;
    size_t in_cap;
    size_t pos; /* parse cursor; compacted when more input is needed */

    WsParseState state;
    bool fin;
    unsigned char opcode;
    bool masked;
    unsigned char mask[4];
    size_t payload_len;
    size_t payload_done;

    unsigned char ctrl[125]; /* control frame payload assembly */
    size_t ctrl_len;

    bool msg_active; /* fragmented message in progress */
    unsigned char msg_opcode;
    unsigned char *msg;
    size_t msg_len;
    size_t msg_cap;
    size_t max_message;

    /* Delivered message — owned until the next http_ws_recv(). */
    char *cur_data;
    size_t cur_len;
    HttpWsMessageType cur_type;
};

/* ---- lock helpers ---- */

/* ws is const only in the PUBLIC accessors — the lock lives in the
 * opaque struct, so cast once here instead of at every call site. */
static pthread_mutex_t *ws_lock_of(const HttpWs *ws)
{
    return (pthread_mutex_t *)&ws->lock;
}

static void ws_mark_dead(HttpWs *ws, unsigned short close_code, bool io_error)
{
    pthread_mutex_lock(&ws->lock);
    if (close_code != 0) {
        ws->close_code = close_code;
    }
    if (io_error) {
        ws->io_error = true;
    }
    ws->dead = true;
    pthread_mutex_unlock(&ws->lock);
}

static bool ws_is_dead(const HttpWs *ws)
{
    pthread_mutex_t *lock = ws_lock_of(ws);
    pthread_mutex_lock(lock);
    bool dead = ws->dead;
    pthread_mutex_unlock(lock);
    return dead;
}

/* ---- frame writer (server frames are never masked) ---- */

static int ws_send_frame_locked(HttpWs *ws, unsigned char opcode,
                                const void *payload, size_t len)
{
    unsigned char hdr[10];
    size_t hlen;

    hdr[0] = (unsigned char)(0x80 | opcode); /* FIN=1 */
    if (len <= 125) {
        hdr[1] = (unsigned char)len;
        hlen = 2;
    } else if (len <= 0xFFFF) {
        hdr[1] = 126;
        hdr[2] = (unsigned char)(len >> 8);
        hdr[3] = (unsigned char)len;
        hlen = 4;
    } else {
        hdr[1] = 127;
        for (size_t i = 0; i < 8; i++) {
            hdr[2 + i] = (unsigned char)(((uint64_t)len) >> (56 - (8 * i)));
        }
        hlen = 10;
    }

    if (ws_send_raw(ws->fd, hdr, hlen) != 0) {
        ws->dead = true;
        ws->io_error = true;
        return -1;
    }
    if (len > 0 && ws_send_raw(ws->fd, payload, len) != 0) {
        ws->dead = true;
        ws->io_error = true;
        return -1;
    }
    return 0;
}

/* Sends any frame (locks; callable from any thread). */
static int ws_send_frame(HttpWs *ws, unsigned char opcode, const void *payload,
                         size_t len)
{
    pthread_mutex_lock(&ws->lock);
    int rc;
    if (ws->dead) {
        rc = -1;
    } else {
        rc = ws_send_frame_locked(ws, opcode, payload, len);
    }
    pthread_mutex_unlock(&ws->lock);
    return rc;
}

/* Starts the close handshake: sends the close frame (code + reason,
 * reason truncated to 123 bytes). */
static int ws_send_close(HttpWs *ws, unsigned short code, const char *reason)
{
    unsigned char payload[125];
    size_t plen = 0;

    if (code != 0) {
        payload[0] = (unsigned char)(code >> 8);
        payload[1] = (unsigned char)code;
        plen = 2;
        if (reason != NULL) {
            size_t rlen = strlen(reason);
            if (rlen > sizeof(payload) - plen) {
                rlen = sizeof(payload) - plen;
            }
            /* Length-delimited close-frame payload, not a C string. */
            /* NOLINTNEXTLINE(bugprone-not-null-terminated-result) */
            memcpy(payload + plen, reason, rlen);
            plen += rlen;
        }
    }

    pthread_mutex_lock(&ws->lock);
    int rc = 0;
    if (ws->dead) {
        rc = -1;
    } else {
        rc = ws_send_frame_locked(ws, WS_OP_CLOSE, payload, plen);
        if (!ws->close_sent && code != 0) {
            ws->close_code = code;
        }
    }
    ws->close_sent = true;
    pthread_mutex_unlock(&ws->lock);
    return rc;
}

/* ---- parse state machine ---- */

/* Moves unparsed bytes to the front of the recv buffer. */
static void ws_compact(HttpWs *ws)
{
    if (ws->pos == 0) {
        return;
    }
    size_t rem = ws->in_len - ws->pos;
    if (rem > 0) {
        memmove(ws->in, ws->in + ws->pos, rem);
    }
    ws->in_len = rem;
    ws->pos = 0;
}

/* Protocol violation: send close with the given code, mark dead.
 * Used for 1002 (protocol error) and 1009 (too large). */
static WsParseResult ws_protocol_violation(HttpWs *ws, unsigned short code)
{
    (void)ws_send_close(ws, code, "");
    ws_mark_dead(ws, 0, false);
    return WS_PARSE_PROTOCOL;
}

/* Ensures the message buffer can hold `need` bytes total. */
static bool ws_msg_reserve(HttpWs *ws, size_t need)
{
    if (need <= ws->msg_cap) {
        return true;
    }
    /* +1 so the delivered payload can always be NUL-terminated. */
    if (need > SIZE_MAX - 1) {
        return false;
    }
    size_t new_cap = ws->msg_cap == 0 ? 256 : ws->msg_cap;
    while (new_cap < need + 1) {
        if (new_cap > SIZE_MAX / 2) {
            new_cap = need + 1;
            break;
        }
        new_cap *= 2;
    }
    unsigned char *tmp = realloc(ws->msg, new_cap);
    if (tmp == NULL) {
        return false;
    }
    ws->msg = tmp;
    ws->msg_cap = new_cap;
    return true;
}

/* Unmasks the next payload chunk IN PLACE in ws->in (those bytes are
 * consumed exactly once) and advances the cursors. Returns the chunk
 * size; the caller copies from ws->in + ws->pos - chunk. */
static size_t ws_unmask_chunk(HttpWs *ws)
{
    size_t avail = ws->in_len - ws->pos;
    size_t chunk = ws->payload_len - ws->payload_done;
    if (chunk > avail) {
        chunk = avail;
    }

    for (size_t i = 0; i < chunk; i++) {
        ws->in[ws->pos + i] ^= ws->mask[(ws->payload_done + i) % 4];
    }
    ws->payload_done += chunk;
    ws->pos += chunk;
    return chunk;
}

/* Called once the full frame payload length is known: checks the
 * message size limit for data frames (control frames are capped at
 * 125 by the header checks) and moves on to the mask state. Returns
 * WS_PARSE_CONTINUE to keep parsing. */
static WsParseResult ws_frame_length_known(HttpWs *ws)
{
    if (ws->opcode < WS_OP_CLOSE &&
        ws->payload_len > ws->max_message - ws->msg_len) {
        return ws_protocol_violation(ws, 1009);
    }
    ws->state = WS_NEED_MASK;
    return WS_PARSE_CONTINUE;
}

/* Handles a fully received control frame in ws->ctrl. */
static WsParseResult ws_handle_control(HttpWs *ws)
{
    switch (ws->opcode) {
    case WS_OP_PING:
        /* RFC 6455 §5.5.2: answer pings transparently with a pong
         * carrying the same payload. */
        if (ws_send_frame(ws, WS_OP_PONG, ws->ctrl, ws->ctrl_len) != 0) {
            ws_mark_dead(ws, 0, true);
            return WS_PARSE_IO_ERROR;
        }
        return WS_PARSE_CONTINUE;
    case WS_OP_PONG:
        return WS_PARSE_CONTINUE; /* unsolicited pongs are ignored */
    case WS_OP_CLOSE:
        /* RFC 6455 §5.5.1: echo the close. Payload: 0 bytes (no code)
         * or >= 2 bytes (status code first). One byte is invalid. */
        if (ws->ctrl_len == 1) {
            return ws_protocol_violation(ws, 1002);
        }
        unsigned short code = 0;
        if (ws->ctrl_len >= 2) {
            code = (unsigned short)(((unsigned)ws->ctrl[0] << 8) |
                                    (unsigned)ws->ctrl[1]);
        }
        if (!ws->close_sent) {
            (void)ws_send_close(ws, code, "");
        }
        ws_mark_dead(ws, code != 0 ? code : 1005, false);
        ws->close_received = true; /* same thread as the recv loop */
        return WS_PARSE_CLOSED;
    default:
        return ws_protocol_violation(ws, 1002);
    }
}

/* Consumes from ws->in as far as the buffered bytes allow. Returns
 * WS_PARSE_CONTINUE when more input is needed (buffer compacted). */
static WsParseResult ws_parse(HttpWs *ws, HttpWsMessage *msg)
{
    for (;;) {
        size_t avail = ws->in_len - ws->pos;

        switch (ws->state) {
        case WS_NEED_HEADER: {
            if (avail < 2) {
                break;
            }
            unsigned char b0 = ws->in[ws->pos];
            unsigned char b1 = ws->in[ws->pos + 1];
            ws->pos += 2;

            ws->fin = (b0 & 0x80) != 0;
            ws->opcode = b0 & 0x0F;
            ws->masked = (b1 & 0x80) != 0;
            size_t len7 = (size_t)(b1 & 0x7F);

            /* RSV bits must be zero: no extensions are negotiated. */
            if ((b0 & 0x70) != 0) {
                return ws_protocol_violation(ws, 1002);
            }
            /* RFC 6455 §5.1: client-to-server frames MUST be masked,
             * server-to-client frames MUST NOT be. */
            if (!ws->masked) {
                return ws_protocol_violation(ws, 1002);
            }
            switch (ws->opcode) {
            case WS_OP_CONT:
            case WS_OP_TEXT:
            case WS_OP_BINARY:
            case WS_OP_CLOSE:
            case WS_OP_PING:
            case WS_OP_PONG:
                break;
            default:
                return ws_protocol_violation(ws, 1002);
            }
            bool is_control = ws->opcode >= WS_OP_CLOSE;
            if (is_control) {
                /* §5.5: control frames: payload <= 125, never fragmented,
                 * never interleaved with a fragmented message body. */
                if (len7 > 125 || !ws->fin) {
                    return ws_protocol_violation(ws, 1002);
                }
            } else {
                /* Continuation semantics: op 0 only during a fragmented
                 * message, text/binary only outside one. A non-CONT
                 * frame starts a (possibly fragmented) message. */
                if (ws->opcode == WS_OP_CONT && !ws->msg_active) {
                    return ws_protocol_violation(ws, 1002);
                }
                if (ws->opcode != WS_OP_CONT && ws->msg_active) {
                    return ws_protocol_violation(ws, 1002);
                }
                if (ws->opcode != WS_OP_CONT) {
                    ws->msg_opcode = ws->opcode;
                }
            }

            if (len7 < 126) {
                ws->payload_len = len7;
                WsParseResult r = ws_frame_length_known(ws);
                if (r != WS_PARSE_CONTINUE) {
                    return r;
                }
            } else if (len7 == 126) {
                ws->state = WS_NEED_LEN16;
            } else {
                ws->state = WS_NEED_LEN64;
            }
            continue;
        }
        case WS_NEED_LEN16:
        case WS_NEED_LEN64: {
            size_t ext = ws->state == WS_NEED_LEN16 ? 2 : 8;
            if (avail < ext) {
                break;
            }
            if (ws->state == WS_NEED_LEN16) {
                ws->payload_len = ((size_t)ws->in[ws->pos] << 8) |
                                  (size_t)ws->in[ws->pos + 1];
            } else {
                uint64_t len = 0;
                for (size_t i = 0; i < 8; i++) {
                    len = (len << 8) | (uint64_t)ws->in[ws->pos + i];
                }
                if ((len >> 63) != 0) {
                    return ws_protocol_violation(ws, 1002);
                }
                ws->payload_len = (size_t)len;
            }
            ws->pos += ext;

            /* Minimal encoding (§5.2): 16-bit form only above 125,
             * 64-bit form only above 65535. */
            if (ws->state == WS_NEED_LEN16 && ws->payload_len < 126) {
                return ws_protocol_violation(ws, 1002);
            }
            if (ws->state == WS_NEED_LEN64 && ws->payload_len < 65536) {
                return ws_protocol_violation(ws, 1002);
            }

            WsParseResult r = ws_frame_length_known(ws);
            if (r != WS_PARSE_CONTINUE) {
                return r;
            }
            continue;
        }
        case WS_NEED_MASK: {
            if (avail < 4) {
                break;
            }
            memcpy(ws->mask, ws->in + ws->pos, 4);
            ws->pos += 4;
            ws->payload_done = 0;
            ws->ctrl_len = 0;
            ws->state = WS_NEED_PAYLOAD;
            continue;
        }
        case WS_NEED_PAYLOAD: {
            if (ws->payload_done == ws->payload_len) {
                /* Frame complete — dispatch it. (Also covers zero-length
                 * frames: done right after the mask state.) */
                {
                    ws->state = WS_NEED_HEADER;
                    ws->payload_done = 0;
                    if (ws->opcode >= WS_OP_CLOSE) {
                        WsParseResult r = ws_handle_control(ws);
                        if (r != WS_PARSE_CONTINUE) {
                            return r;
                        }
                        continue;
                    }
                    if (!ws->fin) {
                        ws->msg_active = true; /* msg_opcode set at start */
                        continue;
                    }
                    /* Complete (possibly fragmented) message: hand the
                     * buffer to the caller, valid until the next recv. */
                    if (ws->msg == NULL) {
                        ws->msg = malloc(1);
                        if (ws->msg == NULL) {
                            (void)ws_send_close(ws, 1011, "");
                            ws_mark_dead(ws, 0, true);
                            return WS_PARSE_IO_ERROR;
                        }
                        ws->msg_cap = 1;
                    }
                    ws->msg[ws->msg_len] = '\0';
                    free(ws->cur_data);
                    ws->cur_data = (char *)ws->msg;
                    ws->cur_len = ws->msg_len;
                    ws->cur_type = ws->msg_opcode == WS_OP_TEXT
                                       ? HTTP_WS_TEXT
                                       : HTTP_WS_BINARY;
                    ws->msg = NULL;
                    ws->msg_len = 0;
                    ws->msg_cap = 0;
                    ws->msg_active = false;

                    msg->type = ws->cur_type;
                    msg->data = ws->cur_data;
                    msg->len = ws->cur_len;
                    return WS_PARSE_MESSAGE;
                }
            }
            if (avail == 0) {
                break; /* incomplete frame: need more input */
            }

            size_t chunk = ws_unmask_chunk(ws);
            if (ws->opcode >= WS_OP_CLOSE) {
                memcpy(ws->ctrl + ws->ctrl_len, ws->in + ws->pos - chunk,
                       chunk);
                ws->ctrl_len += chunk;
            } else {
                if (!ws_msg_reserve(ws, ws->msg_len + chunk)) {
                    (void)ws_send_close(ws, 1011, "");
                    ws_mark_dead(ws, 0, true);
                    return WS_PARSE_IO_ERROR;
                }
                memcpy(ws->msg + ws->msg_len, ws->in + ws->pos - chunk, chunk);
                ws->msg_len += chunk;
            }
            continue;
        }
        default:
            HTTP_ASSERT_MSG(false, "unreachable ws parse state");
            return WS_PARSE_IO_ERROR;
        }

        break; /* case broke out: need more input */
    }

    ws_compact(ws);
    return WS_PARSE_CONTINUE;
}

/* ============================================================
 * Session lifecycle
 * ============================================================ */

static HttpWs *ws_session_create(HttpServer *server, const HttpWsRoute *route,
                                 const HttpRequest *req, int client_fd,
                                 const char *leftover, size_t leftover_len)
{
    HttpWs *ws = calloc(1, sizeof(*ws));
    if (ws == NULL) {
        return NULL;
    }
    if (pthread_mutex_init(&ws->lock, NULL) != 0) {
        free(ws);
        return NULL;
    }

    ws->server = server;
    ws->route = route;
    ws->req = req;
    ws->fd = client_fd;
    ws->max_message = route->max_message;
    ws->state = WS_NEED_HEADER;

    size_t cap = WS_RECV_BUFFER;
    if (cap < leftover_len) {
        cap = leftover_len + WS_RECV_BUFFER;
    }
    ws->in = malloc(cap);
    if (ws->in == NULL) {
        pthread_mutex_destroy(&ws->lock);
        free(ws);
        return NULL;
    }
    ws->in_cap = cap;
    if (leftover_len > 0) {
        /* Bytes read together with the handshake headers that already
         * belong to the WS stream (early frames from fast clients). */
        memcpy(ws->in, leftover, leftover_len);
        ws->in_len = leftover_len;
    }

    /* Short poll timeout instead of the 10s request timeout: idle
     * connections must not die, but http_ws_recv() must wake up often
     * enough to notice http_stop_server() (graceful shutdown). */
    struct timeval tv = {.tv_sec = 0, .tv_usec = HTTP_WS_POLL_MS * 1000};
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return ws;
}

static void ws_session_destroy(HttpWs *ws)
{
    free(ws->in);
    free(ws->msg);
    free(ws->cur_data);
    pthread_mutex_destroy(&ws->lock);
    free(ws);
}

/* Waits briefly for the peer's close echo (RFC 6455 §5.5.1: the
 * closer SHOULD wait for it). Bounded by HTTP_WS_CLOSE_WAIT_MS in
 * HTTP_WS_POLL_MS slices; discards anything else the peer sends. */
static void ws_drain_close_echo(HttpWs *ws)
{
    size_t slices =
        (size_t)((HTTP_WS_CLOSE_WAIT_MS / HTTP_WS_POLL_MS) + 1); /* round up */

    for (size_t i = 0; i < slices && !ws->close_received; i++) {
        if (ws->in_len == ws->in_cap) {
            if (ws->in_cap >= WS_RECV_BUFFER_MAX) {
                break;
            }
            size_t new_cap = ws->in_cap * 2;
            if (new_cap <= ws->in_cap) {
                break; /* overflow: cannot grow the buffer */
            }
            unsigned char *tmp = realloc(ws->in, new_cap);
            if (tmp == NULL) {
                break;
            }
            ws->in = tmp;
            ws->in_cap = new_cap;
        }

        ssize_t r =
            recv(ws->fd, ws->in + ws->in_len, ws->in_cap - ws->in_len, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break; /* timeout (poll interval) or error: give up waiting */
        }
        if (r == 0) {
            /* Peer closed without an echo: abnormal closure. */
            ws_mark_dead(ws, 1006, false);
            return;
        }

        ws->in_len += (size_t)r;
        WsParseResult res = ws_parse(ws, &(HttpWsMessage){0});
        if (res == WS_PARSE_CLOSED || res == WS_PARSE_PROTOCOL) {
            return; /* close handled — close_received set by the parser */
        }
        if (res == WS_PARSE_IO_ERROR) {
            ws_mark_dead(ws, 1006, true);
            return;
        }
        /* MESSAGE / CONTINUE: the peer is still sending — discard and
         * keep waiting for the close echo. */
    }

    /* No echo in time — the session is over either way. */
    ws_mark_dead(ws, 0, false);
}

/* ============================================================
 * Public session API
 * ============================================================ */

HttpWsResult http_ws_recv(HttpWs *ws, HttpWsMessage *msg)
{
    if (ws == NULL || msg == NULL) {
        return HTTP_WS_ERROR;
    }

    if (ws_is_dead(ws)) {
        pthread_mutex_lock(&ws->lock);
        bool io_error = ws->io_error;
        pthread_mutex_unlock(&ws->lock);
        if (io_error) {
            return HTTP_WS_ERROR;
        }
        return HTTP_WS_CLOSED;
    }

    for (;;) {
        switch (ws_parse(ws, msg)) {
        case WS_PARSE_MESSAGE:
            return HTTP_WS_OK;
        case WS_PARSE_CLOSED:
        case WS_PARSE_PROTOCOL:
            return HTTP_WS_CLOSED;
        case WS_PARSE_IO_ERROR:
            return HTTP_WS_ERROR;
        case WS_PARSE_CONTINUE:
            break;
        }

        if (ws->in_len == ws->in_cap) {
            if (ws->in_cap >= WS_RECV_BUFFER_MAX) {
                ws_mark_dead(ws, 0, true);
                return HTTP_WS_ERROR;
            }
            size_t new_cap = ws->in_cap * 2;
            if (new_cap <= ws->in_cap) {
                ws_mark_dead(ws, 0, true);
                return HTTP_WS_ERROR; /* overflow: cannot grow */
            }
            unsigned char *tmp = realloc(ws->in, new_cap);
            if (tmp == NULL) {
                ws_mark_dead(ws, 0, true);
                return HTTP_WS_ERROR;
            }
            ws->in = tmp;
            ws->in_cap = new_cap;
        }

        ssize_t r =
            recv(ws->fd, ws->in + ws->in_len, ws->in_cap - ws->in_len, 0);
        if (r > 0) {
            ws->in_len += (size_t)r;
            continue;
        }
        if (r == 0) { /* peer closed the connection */
            ws_mark_dead(ws, 1006, false);
            return HTTP_WS_CLOSED;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Poll timeout: check the shutdown flag — this is the
             * graceful-shutdown hook (no locks in the signal path). */
            if (!ws->server->listening) {
                (void)ws_send_close(ws, 1001, "server shutting down");
                ws_mark_dead(ws, 1001, false);
                return HTTP_WS_CLOSED;
            }
            continue;
        }
        ws_mark_dead(ws, 1006, true);
        return HTTP_WS_ERROR;
    }
}

int http_ws_send_text(HttpWs *ws, const char *data, size_t len)
{
    return ws_send_frame(ws, WS_OP_TEXT, data, len);
}

int http_ws_send_binary(HttpWs *ws, const void *data, size_t len)
{
    return ws_send_frame(ws, WS_OP_BINARY, data, len);
}

int http_ws_send_ping(HttpWs *ws, const void *data, size_t len)
{
    if (len > 125) { /* control frame payload limit (RFC 6455 §5.5) */
        return -1;
    }
    return ws_send_frame(ws, WS_OP_PING, data, len);
}

int http_ws_close(HttpWs *ws, unsigned short code, const char *reason)
{
    if (ws == NULL) {
        return -1;
    }
    if (ws_is_dead(ws)) {
        return 0; /* close already happened (or the socket is gone) */
    }
    int rc = ws_send_close(ws, code, reason);
    ws_drain_close_echo(ws);
    return rc;
}

void http_ws_set_data(HttpWs *ws, void *data)
{
    if (ws != NULL) {
        ws->data = data;
    }
}

void *http_ws_get_data(const HttpWs *ws)
{
    return ws != NULL ? ws->data : NULL;
}

unsigned short http_ws_close_code(const HttpWs *ws)
{
    if (ws == NULL) {
        return 0;
    }
    pthread_mutex_t *lock = ws_lock_of(ws);
    pthread_mutex_lock(lock);
    unsigned short code = ws->close_code;
    pthread_mutex_unlock(lock);
    return code;
}

/* ============================================================
 * Dispatch (called from handle_client)
 * ============================================================ */

/* Picks the first client-offered subprotocol the route supports
 * (case-sensitive, RFC 6455 §11.8 has no case rules — exact match). */
static const char *ws_pick_subprotocol(const HttpWsRoute *route,
                                       const char *offered)
{
    const char *p = offered;

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
        if (len == 0) {
            continue;
        }
        for (size_t i = 0; route->subprotocols[i] != NULL; i++) {
            if (strlen(route->subprotocols[i]) == len &&
                strncmp(route->subprotocols[i], start, len) == 0) {
                return route->subprotocols[i];
            }
        }
    }
    return NULL;
}

HttpWsDispatchResult http_ws_dispatch(HttpServer *server, HttpRequest *req,
                                      const HttpRouteSegments *req_segments,
                                      int client_fd, const char *leftover,
                                      size_t leftover_len)
{
    HTTP_ASSERT(server != NULL);
    HTTP_ASSERT(req != NULL);
    HTTP_ASSERT(req_segments != NULL);
    HTTP_ASSERT(client_fd >= 0);

    /* Cheap pre-checks first: anything that is not a websocket upgrade
     * falls through to normal routing without side effects. */
    if (server->ws_routes == NULL || strcmp(req->method, "GET") != 0) {
        return WS_DISPATCH_NOT_WS;
    }
    const char *conn = http_req_header(req, HTTP_HEADER_CONNECTION);
    const char *upgrade = http_req_header(req, HTTP_HEADER_UPGRADE);
    if (conn == NULL || !ws_header_has_token(conn, "upgrade") ||
        upgrade == NULL || !ws_header_has_token(upgrade, "websocket")) {
        return WS_DISPATCH_NOT_WS;
    }

    /* It IS a websocket upgrade — match the path against the WS
     * routes (registration order, first match wins, params bound). */
    const HttpWsRoute *route = server->ws_routes;
    while (route != NULL) {
        if (http_segments_match(&route->segments, req_segments, NULL)) {
            break;
        }
        route = route->next;
    }
    if (route == NULL) {
        return WS_DISPATCH_NOT_WS; /* no WS route: try normal routing */
    }
    (void)http_segments_match(&route->segments, req_segments, &req->params);

    /* RFC 6455 §4.2: the handshake carries no body. */
    if (req->body_len > 0) {
        ws_send_error_response(client_fd, 400, "Bad Request",
                               "websocket handshake must not have a body\n",
                               NULL);
        return WS_DISPATCH_REJECTED;
    }

    /* Websocket handlers block for the connection lifetime — the
     * iterative default would stop the whole server (accept loop
     * stuck in the WS session). Require worker threads. */
    if (server->thread_state == NULL) {
        printf("WARNING: websocket upgrade to %s rejected — "
               "ServerArgs.worker_threads > 0 required\n",
               req->path);
        ws_send_error_response(
            client_fd, 503, "Service Unavailable",
            "websockets require ServerArgs.worker_threads > 0\n", NULL);
        return WS_DISPATCH_REJECTED;
    }

    /* RFC 6455 §4.2.1: Sec-WebSocket-Key, base64 of 16 random bytes. */
    const char *key = http_req_header(req, HTTP_HEADER_SEC_WEBSOCKET_KEY);
    unsigned char key_bytes[24];
    size_t key_len = 0;
    if (key == NULL || strlen(key) != 24 ||
        !base64_decode(key, 24, key_bytes, sizeof(key_bytes), &key_len) ||
        key_len != 16) {
        ws_send_error_response(client_fd, 400, "Bad Request",
                               "invalid Sec-WebSocket-Key\n", NULL);
        return WS_DISPATCH_REJECTED;
    }

    /* §4.2.2: version 13 only — anything else gets 426 + the version
     * we support, so the client can retry correctly. */
    const char *version =
        http_req_header(req, HTTP_HEADER_SEC_WEBSOCKET_VERSION);
    if (version == NULL || strcmp(version, "13") != 0) {
        ws_send_error_response(
            client_fd, 426, "Upgrade Required",
            "unsupported websocket version (this server speaks version 13)\n",
            "Sec-WebSocket-Version: 13\r\n");
        return WS_DISPATCH_REJECTED;
    }

    /* Optional verify callback: reject before upgrading (403). */
    if (route->verify != NULL && !route->verify(req)) {
        ws_send_error_response(client_fd, 403, "Forbidden",
                               "websocket upgrade rejected\n", NULL);
        return WS_DISPATCH_REJECTED;
    }

    /* Build + send the 101 response. */
    char accept[32];
    if (!ws_accept_key(key, accept, sizeof(accept))) {
        return WS_DISPATCH_REJECTED; /* cannot happen (size is fixed) */
    }

    char response[512];
    int n = snprintf(response, sizeof(response),
                     "HTTP/1.1 101 Switching Protocols\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: %s\r\n",
                     accept);
    if (n < 0 || (size_t)n >= sizeof(response)) {
        return WS_DISPATCH_REJECTED;
    }
    if (route->subprotocols != NULL) {
        const char *offered =
            http_req_header(req, HTTP_HEADER_SEC_WEBSOCKET_PROTOCOL);
        if (offered != NULL) {
            const char *pick = ws_pick_subprotocol(route, offered);
            if (pick != NULL) {
                int pn =
                    snprintf(response + (size_t)n, sizeof(response) - (size_t)n,
                             "Sec-WebSocket-Protocol: %s\r\n", pick);
                if (pn < 0 || (size_t)pn >= sizeof(response) - (size_t)n) {
                    return WS_DISPATCH_REJECTED;
                }
                n += pn;
            }
        }
    }
    if ((size_t)n + 2 > sizeof(response) ||
        ws_send_raw(client_fd, response, (size_t)n) != 0 ||
        ws_send_raw(client_fd, "\r\n", 2) != 0) {
        return WS_DISPATCH_REJECTED; /* peer went away — just close */
    }

    HttpWs *ws = ws_session_create(server, route, req, client_fd, leftover,
                                   leftover_len);
    if (ws == NULL) {
        return WS_DISPATCH_REJECTED; /* OOM — close without a close frame */
    }

    printf("%s:%u WS %s -> 101 (upgraded)\n", req->ip, req->client_port,
           req->path);

    route->handler(ws, req);

    /* The handler returned: complete the close handshake when it has
     * not happened yet (code 1000, normal closure). */
    if (!ws_is_dead(ws)) {
        (void)ws_send_close(ws, 1000, "");
        ws_drain_close_echo(ws);
    }

    printf("%s:%u WS %s closed (code %u)\n", req->ip, req->client_port,
           req->path, http_ws_close_code(ws));

    ws_session_destroy(ws);
    return WS_DISPATCH_UPGRADED;
}