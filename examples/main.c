#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "args.h"
#include "c_http.h"
#include "c_http_assert.h"
#include "c_http_static.h"

static HttpServer *g_server = NULL;

/* Async-signal-safe: http_stop_server only uses a flag + shutdown(). */
static void on_terminate(int sig)
{
    (void)sig;
    if (g_server != NULL) {
        http_stop_server(g_server);
    }
}

/* ---------------------------------------------------------------------------
 * Handlers
 * ------------------------------------------------------------------------- */

static void home_handler(const HttpRequest *req, HttpResponse *res)
{
    printf("home handler\n");
    (void)req;
    res->status = 200;
    const char *b = "<h1>Welcome to c-http</h1>"
                    "<p>Try: <a href=\"/api/status\">/api/status</a>, "
                    "<a href=\"/api/users\">/api/users</a>, "
                    "<a href=\"/admin/dashboard\">/admin/dashboard</a></p>";
    size_t len = strlen(b);
    memcpy(res->body, b, len);
    res->body_len = len;
}

static void id_test_handler(const HttpRequest *req, HttpResponse *res)
{
    printf("id test handler\n");
    char b[64];
    const char *id = http_req_param(req, "id");
    if (id == NULL) {
        snprintf(b, sizeof(b), "<h1>unable to get id param</h1>");
    } else {
        snprintf(b, sizeof(b),
                 "<h1>your id: %s</h1><a href=\"/\">back to home</a>", id);
    }

    res->status = 200;
    size_t len = strlen(b);
    memcpy(res->body, b, len);
    res->body_len = len;
}

static void api_status_handler(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = 200;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE,
                    "application/json");
    /* Read what the middleware passed down via locals */
    const char *user = http_res_local(res, "user");
    int n = snprintf(res->body, sizeof(res->body),
                     "{\"status\":\"ok\",\"user\":\"%s\"}",
                     user != NULL ? user : "anonymous");
    if (n > 0) {
        res->body_len =
            (size_t)n < sizeof(res->body) ? (size_t)n : sizeof(res->body) - 1;
    }
}

static void api_users_handler(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = 200;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE,
                    "application/json");
    const char *b = "[{\"id\":1,\"name\":\"Alice\"},"
                    "{\"id\":2,\"name\":\"Bob\"}]";
    size_t len = strlen(b);
    memcpy(res->body, b, len);
    res->body_len = len;
}

static void admin_dashboard_handler(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = 200;
    const char *b = "<h1>Admin Dashboard</h1>"
                    "<p>Only authenticated users see this.</p>";
    size_t len = strlen(b);
    memcpy(res->body, b, len);
    res->body_len = len;
}

static void admin_settings_handler(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = 200;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE,
                    "application/json");
    const char *b = "{\"theme\":\"dark\",\"notifications\":true}";
    size_t len = strlen(b);
    memcpy(res->body, b, len);
    res->body_len = len;
}

/* ---- P1 feature demos ---- */

/* Uniform JSON error pages: ONE place formats every framework error
 * (http_error() calls, 404/405, protocol parse errors). */
static void json_error_handler(const HttpRequest *req, HttpResponse *res,
                               int status, const char *message)
{
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
                     "{\"status\":%d,\"message\":\"%s\",\"path\":\"%s\"}",
                     status, message, req->path);
    if (n > 0 && (size_t)n < sizeof(buf)) {
        (void)http_res_json(res, status, buf);
    }
}

static void teapot_handler(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    /* explicit handler error — the error handler formats it */
    http_error(res, 418, "this is a teapot, not a coffee maker");
}

static void login_handler(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    /* res helpers: cookie + redirect */
    (void)http_res_cookie(res, "session", "demo-token", 3600, true);
    (void)http_res_redirect(res, 302, "/");
}

static void router_time_handler(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    (void)http_res_json(res, 200, "{\"unix\":\"demo\"}");
}

/* ---- WebSockets (RFC 6455) ---- */

static void ws_echo_handler(HttpWs *ws, const HttpRequest *req)
{
    (void)req;
    printf("ws echo session started\n");
    HttpWsMessage msg;
    while (http_ws_recv(ws, &msg) == HTTP_WS_OK) {
        if (msg.type == HTTP_WS_TEXT) {
            http_ws_send_text(ws, msg.data, msg.len);
        } else {
            http_ws_send_binary(ws, msg.data, msg.len);
        }
    }
    printf("ws echo session closed (code %u)\n", http_ws_close_code(ws));
}

/* Chat demo: every message is broadcast to ALL connected clients.
 * Sends are serialized per session, so other threads may broadcast
 * while a handler runs — the list only needs its own lock. */

#define CHAT_MAX_CLIENTS 64

typedef struct {
    HttpWs *clients[CHAT_MAX_CLIENTS];
    size_t count;
    pthread_mutex_t lock;
} Chat;

static Chat g_chat = {.lock = PTHREAD_MUTEX_INITIALIZER};

static void chat_broadcast(const char *data, size_t len)
{
    pthread_mutex_lock(&g_chat.lock);
    for (size_t i = 0; i < g_chat.count; i++) {
        (void)http_ws_send_text(g_chat.clients[i], data, len);
    }
    pthread_mutex_unlock(&g_chat.lock);
}

static void ws_chat_handler(HttpWs *ws, const HttpRequest *req)
{
    const char *room = http_req_param(req, "room");
    printf("ws chat session started (room=%s)\n",
           room != NULL ? room : "default");

    /* register the session for broadcasts */
    pthread_mutex_lock(&g_chat.lock);
    HttpWs **slot = NULL;
    for (size_t i = 0; i < CHAT_MAX_CLIENTS; i++) {
        if (g_chat.clients[i] == NULL) {
            slot = &g_chat.clients[i];
            break;
        }
    }
    if (slot != NULL) {
        *slot = ws;
        g_chat.count++;
    }
    pthread_mutex_unlock(&g_chat.lock);

    HttpWsMessage msg;
    while (http_ws_recv(ws, &msg) == HTTP_WS_OK) {
        if (msg.type == HTTP_WS_TEXT) {
            char line[512];
            int n = snprintf(line, sizeof(line), "%s:%u: %.*s", req->ip,
                             req->client_port,
                             (int)(msg.len > 400 ? 400 : msg.len), msg.data);
            if (n > 0) {
                chat_broadcast(line, (size_t)n);
            }
        }
    }

    pthread_mutex_lock(&g_chat.lock);
    for (size_t i = 0; i < CHAT_MAX_CLIENTS; i++) {
        if (g_chat.clients[i] == ws) {
            g_chat.clients[i] = NULL;
            g_chat.count--;
            break;
        }
    }
    pthread_mutex_unlock(&g_chat.lock);
    printf("ws chat session closed (code %u)\n", http_ws_close_code(ws));
}

/* ---------------------------------------------------------------------------
 * Middleware
 * ------------------------------------------------------------------------- */

/* Global CORS middleware — runs for every request */
static HttpMiddlewareResult cors_middleware(const HttpRequest *req,
                                            HttpResponse *res)
{
    (void)req;
    http_set_header(&res->headers, HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN,
                    "*");
    http_set_header(&res->headers, HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS,
                    "GET, POST, PUT, PATCH, DELETE, OPTIONS");
    return HTTP_MIDDLEWARE_CONTINUE;
}

/* Auth middleware for /api group — checks Authorization header */
static HttpMiddlewareResult api_auth_middleware(const HttpRequest *req,
                                                HttpResponse *res)
{
    const char *auth = http_req_header(req, HTTP_HEADER_AUTHORIZATION);
    if (auth != NULL) {
        /* Locals demo: pass request-scoped data down to the handler
         * (the handler reads it via http_res_local()). */
        http_set_local(res, "user", "api-user");
        return HTTP_MIDDLEWARE_CONTINUE;
    }

    /* No Authorization header → 401, stop processing */
    res->status = 401;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE,
                    "application/json");
    http_set_header(&res->headers, HTTP_HEADER_WWW_AUTHENTICATE, "Bearer");
    const char *b = "{\"error\":\"unauthorized\"}";
    size_t len = strlen(b);
    memcpy(res->body, b, len);
    res->body_len = len;
    return HTTP_MIDDLEWARE_STOP;
}

/* Auth middleware for /admin group — stricter, requires admin token */
static HttpMiddlewareResult admin_auth_middleware(const HttpRequest *req,
                                                  HttpResponse *res)
{
    const char *auth = http_req_header(req, HTTP_HEADER_AUTHORIZATION);
    if (auth != NULL && strcmp(auth, "Bearer admin-secret") == 0) {
        return HTTP_MIDDLEWARE_CONTINUE;
    }

    res->status = 403;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE,
                    "application/json");
    const char *b = "{\"error\":\"forbidden: admin access required\"}";
    size_t len = strlen(b);
    memcpy(res->body, b, len);
    res->body_len = len;
    return HTTP_MIDDLEWARE_STOP;
}

/* ---------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    Args args;
    switch (parse_args(argc, argv, &args)) {
    case ARGS_OK:
        break;
    case ARGS_HELP:
        return 0;
    case ARGS_ERROR:
        return 1;
    }

    ServerArgs server_args = {.bind_addr = args.bind_addr,
                              .port = args.port,
                              .server_name = "MaxServer",
                              .worker_threads = 8,
                              .keep_alive = true};

    HttpServer server;
    if (http_create_server(&server_args, &server) == SERVER_ERROR) {
        fprintf(stderr, "failed to create server\n");
        return 1;
    }

    HTTP_ASSERT(server.fd >= 0);
    HTTP_ASSERT(server.routes.routes != NULL);
    HTTP_ASSERT(server.encoders.count >= 2);

    g_server = &server;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_terminate;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* --- Global middleware (runs for every request) --- */
    http_middleware(&server, NULL, cors_middleware);

    /* --- Top-level routes --- */
    http_get(&server, "/", home_handler);

    http_get(&server, "/:id/test", id_test_handler);
    http_get(&server, "/teapot", teapot_handler);
    http_get(&server, "/login", login_handler);

    /* --- Central error handling: uniform JSON error pages --- */
    http_set_error_handler(&server, json_error_handler);

    /* --- Static files: /public/<path> is served from args.root.
     * Files larger than the 4-KiB body buffer are streamed. --- */
    if (http_static_mount(&server, &(HttpStaticConfig){
                                       .prefix = "/public",
                                       .root = args.root,
                                       .index_file = "index.html",
                                       .max_age = 3600,
                                   }) == SERVER_ERROR) {
        fprintf(stderr, "failed to mount static root '%s'\n", args.root);
        http_close_server(&server);
        return 1;
    }

    /* --- /api group: auth required for all routes --- */
    HttpGroup api = http_group(&server, "/api");
    http_group_middleware(&api, NULL, api_auth_middleware);
    http_group_get(&api, "/status", api_status_handler);
    http_group_get(&api, "/users", api_users_handler);

    /* --- /admin group: stricter auth, separate middleware --- */
    HttpGroup admin = http_group(&server, "/admin");
    http_group_middleware(&admin, NULL, admin_auth_middleware);
    http_group_get(&admin, "/dashboard", admin_dashboard_handler);
    http_group_get(&admin, "/settings", admin_settings_handler);

    /* --- Routers: Express-style, mounted at a prefix --- */
    HttpRouter *v1 = http_router_create();
    http_router_get(v1, "/time", router_time_handler);
    http_use(&server, "/api/v1", v1); /* ownership passes to the server */

    /* --- WebSockets: echo + broadcast chat (worker threads required,
     * the handlers block for the connection lifetime) --- */
    http_ws(&server, "/ws/echo", ws_echo_handler);
    http_ws(&server, "/ws/chat/:room", ws_chat_handler);

    /* --- Start --- */
    http_listen(&server);
    http_close_server(&server);
    printf("Server stopped\n");
    return 0;
}
