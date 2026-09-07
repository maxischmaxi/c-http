#ifndef C_HTTP_H
#define C_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define C_HTTP_VERSION "0.6.0"

/* Parsing limits: buffer sizes must match these values. */
#define HTTP_METHOD_MAX  8 /* longest known method: "CONNECT" */
#define HTTP_PATH_MAX    512
#define HTTP_VERSION_MAX 16
#define HTTP_MAX_HEADERS 64                    /* more request headers -> 431 */
#define HTTP_MAX_BODY    (50ULL * 1024 * 1024) /* larger request body -> 413 */

/* Route param limits: a ":name" segment in a route pattern binds exactly
 * one request segment. Fixed buffers — patterns with more params (or
 * longer names) are rejected at registration time. */
#define HTTP_MAX_PARAMS      16
#define HTTP_PARAM_KEY_MAX   32
#define HTTP_PARAM_VALUE_MAX 64

#define HTTP_HEADER_A_IM            "A-IM"
#define HTTP_HEADER_ACCEPT          "Accept"
#define HTTP_HEADER_ACCEPT_CHARSET  "Accept-Charset"
#define HTTP_HEADER_ACCEPT_DATETIME "Accept-Datetime"
#define HTTP_HEADER_ACCEPT_ENCODING "Accept-Encoding"
#define HTTP_HEADER_ACCEPT_LANGUAGE "Accept-Language"
#define HTTP_HEADER_ACCESS_CONTROL_REQUEST_METHOD \
    "Access-Control-Request-Method"
#define HTTP_HEADER_ACCESS_CONTROL_REQUEST_HEADERS \
    "Access-Control-Request-Headers"
#define HTTP_HEADER_AUTHORIZATION       "Authorization"
#define HTTP_HEADER_CACHE_CONTROL       "Cache-Control"
#define HTTP_HEADER_CONNECTION          "Connection"
#define HTTP_HEADER_CONTENT_DIGEST      "Content-Digest"
#define HTTP_HEADER_CONTENT_ENCODING    "Content-Encoding"
#define HTTP_HEADER_CONTENT_LENGTH      "Content-Length"
#define HTTP_HEADER_CONTENT_MD5         "Content-MD5"
#define HTTP_HEADER_CONTENT_TYPE        "Content-Type"
#define HTTP_HEADER_COOKIE              "Cookie"
#define HTTP_HEADER_DATE                "Date"
#define HTTP_HEADER_EXPECT              "Expect"
#define HTTP_HEADER_FORWARDED           "Forwarded"
#define HTTP_HEADER_FROM                "From"
#define HTTP_HEADER_HOST                "Host"
#define HTTP_HEADER_HTTP2_SETTINGS      "HTTP2-Settings"
#define HTTP_HEADER_IF_MATCH            "If-Match"
#define HTTP_HEADER_IF_MODIFIED_SINCE   "If-Modified-Since"
#define HTTP_HEADER_IF_NONE_MATCH       "If-None-Match"
#define HTTP_HEADER_IF_RANGE            "If-Range"
#define HTTP_HEADER_IF_UNMODIFIED_SINCE "If-Unmodified-Since"
#define HTTP_HEADER_MAX_FORWARDS        "Max-Forwards"
#define HTTP_HEADER_ORIGIN              "Origin"
#define HTTP_HEADER_PRAGMA              "Pragma"
#define HTTP_HEADER_PREFER              "Prefer"
#define HTTP_HEADER_PROXY_AUTHORIZATION "Proxy-Authorization"
#define HTTP_HEADER_RANGE               "Range"
#define HTTP_HEADER_REFERER             "Referer"
#define HTTP_HEADER_REFERER_POLICY      "Referer-Policy"
#define HTTP_HEADER_TE                  "TE"
#define HTTP_HEADER_TRAILER             "Trailer"
#define HTTP_HEADER_TRANSFER_ENCODING   "Transfer-Encoding"
#define HTTP_HEADER_USER_AGENT          "User-Agent"
#define HTTP_HEADER_UPGRADE             "Upgrade"
#define HTTP_HEADER_VIA                 "Via"
#define HTTP_HEADER_WARNING             "Warning"

#define HTTP_HEADER_ACCEPT_CH                   "Accept-CH"
#define HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN "Access-Control-Allow-Origin"
#define HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS \
    "Access-Control-Allow-Credentials"
#define HTTP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS \
    "Access-Control-Expose-Headers"
#define HTTP_HEADER_ACCESS_CONTROL_MAX_AGE       "Access-Control-Max-Age"
#define HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS "Access-Control-Allow-Methods"
#define HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS "Access-Control-Allow-Headers"
#define HTTP_HEADER_ACCEPT_PATCH                 "Accept-Patch"
#define HTTP_HEADER_ACCEPT_RANGES                "Accept-Ranges"
#define HTTP_HEADER_AGE                          "Age"
#define HTTP_HEADER_ALLOW                        "Allow"
#define HTTP_HEADER_ALT_SVC                      "Alt-Svc"
#define HTTP_HEADER_CONTENT_DISPOSITION          "Content-Disposition"
#define HTTP_HEADER_CONTENT_LANGUAGE             "Content-Language"
#define HTTP_HEADER_CONTENT_LOCATION             "Content-Location"
#define HTTP_HEADER_CONTENT_RANGE                "Content-Range"
#define HTTP_HEADER_DELTA_BASE                   "Delta-Base"
#define HTTP_HEADER_ETAG                         "ETag"
#define HTTP_HEADER_EXPIRES                      "Expires"
#define HTTP_HEADER_IM                           "IM"
#define HTTP_HEADER_LAST_MODIFIED                "Last-Modified"
#define HTTP_HEADER_LINK                         "Link"
#define HTTP_HEADER_LOCATION                     "Location"
#define HTTP_HEADER_P3P                          "P3P"
#define HTTP_HEADER_PREFERENCE_APPLIED           "Preference-Applied"
#define HTTP_HEADER_PROXY_AUTHENTICATE           "Proxy-Authenticate"
#define HTTP_HEADER_PUBLIC_KEY_PINS              "Public-Key-Pins"
#define HTTP_HEADER_RETRY_AFTER                  "Retry-After"
#define HTTP_HEADER_SERVER                       "Server"
#define HTTP_HEADER_SET_COOKIE                   "Set-Cookie"
#define HTTP_HEADER_STRICT_TRANSPORT_SECURITY    "Strict-Transport-Security"
#define HTTP_HEADER_TK                           "Tk"
#define HTTP_HEADER_VARY                         "Vary"
#define HTTP_HEADER_WWW_AUTHENTICATE             "WWW-Authenticate"
#define HTTP_HEADER_X_FRAME_OPTIONS              "X-Frame-Options"

#define HTTP_HEADER_UPGRADE_INSECURE_REQUESTS "Upgrade-Insecure-Requests"
#define HTTP_HEADER_X_REQUESTED_WITH          "X-Requested-With"
#define HTTP_HEADER_DNT                       "DNT"
#define HTTP_HEADER_X_FORWARDED_FOR           "X-Forwarded-For"
#define HTTP_HEADER_X_FORWARDED_HOST          "X-Forwarded-Host"
#define HTTP_HEADER_X_FORWARDED_PROTO         "X-Forwarded-Proto"
#define HTTP_HEADER_FRONT_END_HTTPS           "Front-End-Https"
#define HTTP_HEADER_X_HTTP_METHOD_OVERRIDE    "X-HTTP-Method-Override"
#define HTTP_HEADER_X_ATT_DEVICEID            "X-ATT-DeviceId"
#define HTTP_HEADER_X_WAP_PROFILE             "X-Wap-Profile"
#define HTTP_HEADER_PROXY_CONNECTION          "Proxy-Connection"
#define HTTP_HEADER_X_UIDH                    "X-UIDH"
#define HTTP_HEADER_X_CSRF_TOKEN              "X-Csrf-Token"
#define HTTP_HEADER_X_REQUEST_ID              "X-Request-ID"
#define HTTP_HEADER_X_CORRELATION_ID          "X-Correlation-ID"
#define HTTP_HEADER_CORRELATION_ID            "Correlation-ID"
#define HTTP_HEADER_SAVE_DATA                 "Save-Data"
#define HTTP_HEADER_SEC_GPC                   "Sec-GPC"

#define HTTP_HEADER_CONTENT_SECURITY_POLICY   "Content-Security-Policy"
#define HTTP_HEADER_X_CONTENT_SECURITY_POLICY "X-Content-Security-Policy"
#define HTTP_HEADER_X_WEBKIT_CSP              "X-WebKit-CSP"
#define HTTP_HEADER_EXPECT_CT                 "Expect-CT"
#define HTTP_HEADER_NEL                       "NEL"
#define HTTP_HEADER_PERMISSIONS_POLICY        "Permissions-Policy"
#define HTTP_HEADER_REFRESH                   "Refresh"
#define HTTP_HEADER_REPORT_TO                 "Report-To"
#define HTTP_HEADER_STATUS                    "Status"
#define HTTP_HEADER_TIMING_ALLOW_ORIGIN       "Timing-Allow-Origin"
#define HTTP_HEADER_X_CONTENT_DURATION        "X-Content-Duration"
#define HTTP_HEADER_X_CONTENT_TYPE_OPTIONS    "X-Content-Type-Options"
#define HTTP_HEADER_X_POWERED_BY              "X-Powered-By"
#define HTTP_HEADER_X_REDIRECT_BY             "X-Redirect-By"
#define HTTP_HEADER_X_UA_COMPATIBLE           "X-UA-Compatible"
#define HTTP_HEADER_X_XSS_PROTECTION          "X-XSS-Protection"

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
    HTTP_MIDDLEWARE_CONTINUE,
    HTTP_MIDDLEWARE_STOP,
} HttpMiddlewareResult;

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

typedef enum {
    HTTP_SET_HEADER_OK,
    HTTP_SET_HEADER_ERROR,
} HttpSetHeaderResult;

typedef enum {
    HTTP_ENCODER_ADD_OK,
    HTTP_ENCODER_ADD_ERROR,
} HttpEncoderAddResult;

typedef struct {
    const char *name;
    int (*encode)(const char *in, size_t in_len, char **out, size_t *out_len);
} HttpEncoder;

typedef struct {
    HttpEncoder *encoders;
    size_t count;
    size_t capacity;
} HttpEncoders;

typedef struct {
    char *key;
    char *value;
} HttpHeader;

typedef struct {
    char key[HTTP_PARAM_KEY_MAX];     /* param name without the ':' */
    char value[HTTP_PARAM_VALUE_MAX]; /* bound request segment */
} HttpParam;

typedef struct {
    char text[64]; /* literal text OR the param name */
    bool is_param;
} HttpRouteSegment;

typedef struct {
    HttpRouteSegment *segments;
    size_t count;
    size_t capacity;
} HttpRouteSegments;

typedef struct {
    HttpHeader *items;
    size_t count;
    size_t capacity;
} HttpHeaders;

typedef struct {
    HttpParam params[HTTP_MAX_PARAMS];
    size_t count;
} HttpParams;

typedef struct {
    uint16_t port;
    const char *bind_addr;
    const char *server_name;
} ServerArgs;

typedef struct {
    char method[HTTP_METHOD_MAX];
    char path[HTTP_PATH_MAX];
    char version[HTTP_VERSION_MAX];
    HttpHeaders headers;
    /* Request body (NUL-terminated; allocated by the library and freed
     * after the request). NULL if no body was sent. */
    char *body;
    size_t body_len;
    HttpParams params;
} HttpRequest;

typedef struct {
    int status;
    char body[4096];
    size_t body_len;
    HttpHeaders headers;
    char *encoded_body;
    size_t encoded_body_len;
    /* File streaming: if the handler sets this heap-allocated path
     * (malloc/strdup — ownership passes to the response), the library
     * sends the file as the body (instead of body/encoded_body) and
     * frees the memory afterwards. NULL = regular body. */
    char *file_path;
} HttpResponse;

typedef void (*HttpHandler)(const HttpRequest *req, HttpResponse *res);
typedef HttpMiddlewareResult (*HttpMiddlewareHandler)(const HttpRequest *req,
                                                      HttpResponse *res);

typedef struct {
    const char *path;
    HttpHandler handler;
    HttpMethod method;
    HttpRouteSegments route_segments;
} HttpRoute;

typedef struct {
    HttpRoute *routes;
    size_t count;
    size_t capacity;
} HttpRoutes;

typedef struct {
    const char *path;
    HttpMiddlewareHandler handler;
} HttpMiddleware;

typedef struct {
    HttpMiddleware *middlewares;
    size_t count;
    size_t capacity;
} HttpMiddlewares;

typedef struct {
    uint16_t port;
    const char *bind_addr;
    int fd;
    bool listening;
    HttpRoutes routes;
    HttpMiddlewares middlewares;
    HttpEncoders encoders;
    char *server_name;
    /* Opaque mount list for static files — owned and managed by
     * c_http_static.c (see c_http_static.h). NULL while nothing is
     * mounted; http_close_server() frees it. */
    void *static_mounts;
} HttpServer;

typedef struct {
    HttpServer *server;
    const char *prefix;
} HttpGroup;

HttpServerResult http_create_server(const ServerArgs *server_args,
                                    HttpServer *out);
void http_close_server(HttpServer *server);
void http_listen(HttpServer *server);
/* Stops the running http_listen() loop (async-signal-safe: may be
 * called from a signal handler). The listening socket is shut down so
 * a blocking accept() returns immediately. */
void http_stop_server(HttpServer *server);
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

HttpGroup http_group(HttpServer *server, const char *prefix);
HttpRouteAddResult http_group_get(HttpGroup *group, const char *path,
                                  HttpHandler handler);
HttpRouteAddResult http_group_post(HttpGroup *group, const char *path,
                                   HttpHandler handler);
HttpRouteAddResult http_group_patch(HttpGroup *group, const char *path,
                                    HttpHandler handler);
HttpRouteAddResult http_group_put(HttpGroup *group, const char *path,
                                  HttpHandler handler);
HttpRouteAddResult http_group_delete(HttpGroup *group, const char *path,
                                     HttpHandler handler);
HttpRouteAddResult http_group_head(HttpGroup *group, const char *path,
                                   HttpHandler handler);
HttpRouteAddResult http_group_connect(HttpGroup *group, const char *path,
                                      HttpHandler handler);
HttpRouteAddResult http_group_trace(HttpGroup *group, const char *path,
                                    HttpHandler handler);
HttpRouteAddResult http_group_options(HttpGroup *group, const char *path,
                                      HttpHandler handler);
HttpMiddlewareAddResult http_group_middleware(HttpGroup *group,
                                              const char *path,
                                              HttpMiddlewareHandler handler);
HttpSetHeaderResult http_set_header(HttpHeaders *headers, const char *key,
                                    const char *value);

HttpEncoderAddResult http_register_encoder(HttpServer *server,
                                           HttpEncoder encoder);
void http_headers_free(HttpHeaders *headers);
bool http_accepts_encoding(const HttpRequest *req, const char *encoding);
bool http_encode_body(HttpServer *server, const HttpRequest *req,
                      HttpResponse *res);
/* Route param access: returns the bound value for ":name" params of the
 * matched route, or NULL if the param does not exist. Only meaningful
 * inside a handler (params are per-request). */
const char *http_req_param(const HttpRequest *req, const char *key);

extern const HttpEncoder http_gzip_encoder;
extern const HttpEncoder http_identity_encoder;

#endif
