#ifndef C_HTTP_HTTP
#define C_HTTP_HTTP

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    HTTP_STATUS_OK = 200,
    HTTP_STATUS_NOT_FOUND = 404,
    HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
    HTTP_STATUS_PERMANENT_REDIRECT = 301,
    HTTP_STATUS_TEMPORARY_REDIRECT = 302,
} HttpStatus;

typedef enum {
    SERVER_OK,
    SERVER_ERROR,
} HttpServerResult;

typedef struct {
    uint16_t port;
    const char *bind_addr;
} ServerArgs;

typedef struct {
    char method[8];
    char path[512];
    char version[16];
} HttpRequest;

typedef struct {
    int status;
    char body[4096];
    size_t body_len;
} HttpResponse;

typedef void (*HttpHandler)(const HttpRequest *req, HttpResponse *res);

typedef struct {
    const char *path;       /* "/hello" */
    HttpHandler handler;    /* Pointer auf die Funktion */
} HttpRoute;

typedef struct {
    uint16_t port;
    const char *bind_addr;
    int fd;
    bool listening;
    HttpRoute routes[32];
    size_t route_count;
} HttpServer;



HttpServerResult http_create_server(const ServerArgs *server_args, HttpServer *out);
void http_close_server(HttpServer *server);
void http_listen(HttpServer *server);
HttpServerResult http_get(HttpServer *server, const char *path, HttpHandler handler);
HttpServerResult http_post(HttpServer *server, const char *path, HttpHandler handler);

#endif
