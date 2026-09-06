#include <arpa/inet.h>
#include <netinet/in.h>
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

/* ---------------------------------------------------------------------------
 * Handlers
 * ------------------------------------------------------------------------- */

static void home_handler(const HttpRequest *req, HttpResponse *res)
{
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

static void api_status_handler(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = 200;
    http_set_header(&res->headers, HTTP_HEADER_CONTENT_TYPE,
                    "application/json");
    const char *b = "{\"status\":\"ok\",\"version\":\"" C_HTTP_VERSION "\"}";
    size_t len = strlen(b);
    memcpy(res->body, b, len);
    res->body_len = len;
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
    for (size_t i = 0; i < req->headers.count; i++) {
        if (strcasecmp(req->headers.items[i].key, HTTP_HEADER_AUTHORIZATION) ==
            0) {
            return HTTP_MIDDLEWARE_CONTINUE;
        }
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
    for (size_t i = 0; i < req->headers.count; i++) {
        if (strcasecmp(req->headers.items[i].key, HTTP_HEADER_AUTHORIZATION) ==
            0) {
            if (strcmp(req->headers.items[i].value, "Bearer admin-secret") ==
                0) {
                return HTTP_MIDDLEWARE_CONTINUE;
            }
        }
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
    signal(SIGCHLD, SIG_IGN);

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
                              .server_name = "MaxServer"};

    HttpServer server;
    if (http_create_server(&server_args, &server) == SERVER_ERROR) {
        fprintf(stderr, "failed to create server\n");
        return 1;
    }

    HTTP_ASSERT(server.fd >= 0);
    HTTP_ASSERT(server.routes != NULL);
    HTTP_ASSERT(server.encoder_count >= 2);

    /* --- Global middleware (runs for every request) --- */
    http_middleware(&server, NULL, cors_middleware);

    /* --- Top-level routes --- */
    http_get(&server, "/", home_handler);

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

    /* --- Start --- */
    http_listen(&server);
    http_close_server(&server);
    printf("Server stopped\n");
    return 0;
}