#ifndef C_HTTP_HTTP
#define C_HTTP_HTTP

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    /* 1xx Informational */
    HTTP_STATUS_CONTINUE = 100,
    HTTP_STATUS_SWITCHING_PROTOCOLS = 101,
    HTTP_STATUS_PROCESSING = 102,
    HTTP_STATUS_EARLY_HINTS = 103,

    /* 2xx Success */
    HTTP_STATUS_OK = 200,
    HTTP_STATUS_CREATED = 201,
    HTTP_STATUS_ACCEPTED = 202,
    HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
    HTTP_STATUS_NO_CONTENT = 204,
    HTTP_STATUS_RESET_CONTENT = 205,
    HTTP_STATUS_PARTIAL_CONTENT = 206,
    HTTP_STATUS_MULTI_STATUS = 207,
    HTTP_STATUS_ALREADY_REPORTED = 208,
    HTTP_STATUS_IM_USED = 226,

    /* 3xx Redirection */
    HTTP_STATUS_MULTIPLE_CHOICES = 300,
    HTTP_STATUS_MOVED_PERMANENTLY = 301,
    HTTP_STATUS_FOUND = 302,
    HTTP_STATUS_SEE_OTHER = 303,
    HTTP_STATUS_NOT_MODIFIED = 304,
    HTTP_STATUS_USE_PROXY = 305,
    HTTP_STATUS_TEMPORARY_REDIRECT = 307,
    HTTP_STATUS_PERMANENT_REDIRECT = 308,

    /* 4xx Client Error */
    HTTP_STATUS_BAD_REQUEST = 400,
    HTTP_STATUS_UNAUTHORIZED = 401,
    HTTP_STATUS_PAYMENT_REQUIRED = 402,
    HTTP_STATUS_FORBIDDEN = 403,
    HTTP_STATUS_NOT_FOUND = 404,
    HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
    HTTP_STATUS_NOT_ACCEPTABLE = 406,
    HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
    HTTP_STATUS_REQUEST_TIMEOUT = 408,
    HTTP_STATUS_CONFLICT = 409,
    HTTP_STATUS_GONE = 410,
    HTTP_STATUS_LENGTH_REQUIRED = 411,
    HTTP_STATUS_PRECONDITION_FAILED = 412,
    HTTP_STATUS_CONTENT_TOO_LARGE = 413,
    HTTP_STATUS_URI_TOO_LONG = 414,
    HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
    HTTP_STATUS_RANGE_NOT_SATISFIABLE = 416,
    HTTP_STATUS_EXPECTATION_FAILED = 417,
    HTTP_STATUS_IM_A_TEAPOT = 418,
    HTTP_STATUS_MISDIRECTED_REQUEST = 421,
    HTTP_STATUS_UNPROCESSABLE_CONTENT = 422,
    HTTP_STATUS_LOCKED = 423,
    HTTP_STATUS_FAILED_DEPENDENCY = 424,
    HTTP_STATUS_TOO_EARLY = 425,
    HTTP_STATUS_UPGRADE_REQUIRED = 426,
    HTTP_STATUS_PRECONDITION_REQUIRED = 428,
    HTTP_STATUS_TOO_MANY_REQUESTS = 429,
    HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
    HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS = 451,

    /* 5xx Server Error */
    HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
    HTTP_STATUS_NOT_IMPLEMENTED = 501,
    HTTP_STATUS_BAD_GATEWAY = 502,
    HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
    HTTP_STATUS_GATEWAY_TIMEOUT = 504,
    HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505,
    HTTP_STATUS_VARIANT_ALSO_NEGOTIATES = 506,
    HTTP_STATUS_INSUFFICIENT_STORAGE = 507,
    HTTP_STATUS_LOOP_DETECTED = 508,
    HTTP_STATUS_NOT_EXTENDED = 510,
    HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511,
} HttpStatus;

typedef enum {
    SERVER_OK,
    SERVER_ERROR,
} HttpServerResult;

typedef enum {
    HTTP_ROUTE_ADD_OK,
    HTTP_ROUTE_ADD_CONFLICT,
    HTTP_ROUTE_ADD_ERROR,
} HttpRouteAddResult;

typedef enum {
    HTTP_MIDDLEWARE_ADD_OK,
    HTTP_MIDDLEWARE_ADD_ERROR,
} HttpMiddlewareAddResult;

typedef enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_PATCH,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_CONNECT,
    HTTP_METHOD_TRACE,
} HttpMethod;

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
typedef void (*HttpMiddlewareHandler)(const HttpRequest *req,
                                      HttpResponse *res);

typedef struct {
    const char *path;
    HttpHandler handler;
    HttpMethod method;
} HttpRoute;

typedef struct {
    const char *path;
    HttpMiddlewareHandler handler;
} HttpMiddleware;

typedef struct {
    uint16_t port;
    const char *bind_addr;
    int fd;
    bool listening;
    HttpRoute *routes;
    size_t route_count;
    size_t route_capacity;
    HttpMiddleware *middlewares;
    size_t middleware_count;
    size_t middleware_capacity;
} HttpServer;

HttpServerResult http_create_server(const ServerArgs *server_args,
                                    HttpServer *out);
void http_close_server(HttpServer *server);
void http_listen(HttpServer *server);
HttpRouteAddResult http_get(HttpServer *server, const char *path,
                            HttpHandler handler);
HttpRouteAddResult http_post(HttpServer *server, const char *path,
                             HttpHandler handler);
HttpRouteAddResult http_patch(HttpServer *server, const char *path,
                              HttpHandler handler);
HttpRouteAddResult http_put(HttpServer *server, const char *path,
                            HttpHandler handler);
HttpRouteAddResult http_delete(HttpServer *server, const char *path,
                               HttpHandler handler);
HttpRouteAddResult http_head(HttpServer *server, const char *path,
                             HttpHandler handler);
HttpRouteAddResult http_connect(HttpServer *server, const char *path,
                                HttpHandler handler);
HttpRouteAddResult http_trace(HttpServer *server, const char *path,
                              HttpHandler handler);
HttpRouteAddResult http_options(HttpServer *server, const char *path,
                                HttpHandler handler);

HttpMiddlewareAddResult http_middleware(HttpServer *server, const char *path,
                                        HttpMiddlewareHandler handler);

#endif
