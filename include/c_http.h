#ifndef C_HTTP_H
#define C_HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define C_HTTP_VERSION "0.9.0"

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

/* Query string limits: pairs are parsed eagerly per request. Pairs
 * that do not fit (too many, key/value too long) or are malformed
 * (%00, control characters) are SKIPPED — http_req_query() then
 * reports NULL for them; the request itself is never rejected. */
#define HTTP_MAX_QUERY       16
#define HTTP_QUERY_KEY_MAX   32
#define HTTP_QUERY_VALUE_MAX 64

/* Locals limits: request-scoped middleware -> handler data, stored in
 * fixed slots on the response (no heap, per-request lifetime). */
#define HTTP_MAX_LOCALS      16
#define HTTP_LOCAL_KEY_MAX   32
#define HTTP_LOCAL_VALUE_MAX 64

/* Central error channel: http_error() stores the message (truncated to
 * HTTP_ERROR_MESSAGE_MAX - 1 chars); a server-wide error handler
 * (http_set_error_handler) formats ALL framework errors — http_error()
 * calls, 404/405/501 from routing and protocol parse errors — at send
 * time. Middleware/handler statuses do NOT trigger it unless http_error()
 * is used. */
#define HTTP_ERROR_MESSAGE_MAX 256

/* Multipart limits: multipart/form-data parts are parsed eagerly per
 * request; parts beyond the limit (or malformed ones) are skipped.
 * Part data is NOT copied — it points into req->body (alive for the
 * whole request) and can contain arbitrary bytes including NULs. */
#define HTTP_MAX_MULTIPART_PARTS 16
#define HTTP_MULTIPART_NAME_MAX  32
#define HTTP_MULTIPART_FILE_MAX  64

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
#define HTTP_HEADER_SEC_WEBSOCKET_KEY         "Sec-WebSocket-Key"
#define HTTP_HEADER_SEC_WEBSOCKET_VERSION     "Sec-WebSocket-Version"
#define HTTP_HEADER_SEC_WEBSOCKET_ACCEPT      "Sec-WebSocket-Accept"
#define HTTP_HEADER_SEC_WEBSOCKET_PROTOCOL    "Sec-WebSocket-Protocol"
#define HTTP_HEADER_SEC_WEBSOCKET_EXTENSIONS  "Sec-WebSocket-Extensions"

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
    HTTP_USE_OK,
    HTTP_USE_ERROR,
} HttpUseResult;

typedef enum {
    HTTP_BODY_NONE,       /* no body sent */
    HTTP_BODY_URLENCODED, /* application/x-www-form-urlencoded */
    HTTP_BODY_JSON,       /* application/json */
    HTTP_BODY_MULTIPART,  /* multipart/form-data (parsed by the caller) */
    HTTP_BODY_OTHER,      /* body present, unknown/other type */
} HttpBodyType;

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
    HTTP_SET_LOCAL_OK,
    HTTP_SET_LOCAL_ERROR,
} HttpSetLocalResult;

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
    char key[HTTP_QUERY_KEY_MAX];
    char value[HTTP_QUERY_VALUE_MAX]; /* "" for a bare "?flag" key */
} HttpQueryParam;

typedef struct {
    HttpQueryParam params[HTTP_MAX_QUERY];
    size_t count;
} HttpQuery;

typedef struct {
    char key[HTTP_LOCAL_KEY_MAX];
    char value[HTTP_LOCAL_VALUE_MAX];
} HttpLocal;

typedef struct {
    HttpLocal locals[HTTP_MAX_LOCALS];
    size_t count;
} HttpLocals;

typedef struct {
    char name[HTTP_MULTIPART_NAME_MAX];         /* form field name */
    char filename[HTTP_MULTIPART_FILE_MAX];     /* "" = plain field */
    char content_type[HTTP_MULTIPART_FILE_MAX]; /* "" = not set */
    const char *data; /* points INTO req->body — arbitrary bytes */
    size_t data_len;
} HttpMultipartPart;

typedef struct {
    HttpMultipartPart parts[HTTP_MAX_MULTIPART_PARTS];
    size_t count;
} HttpMultiparts;

typedef struct {
    uint16_t port;
    const char *bind_addr;
    const char *server_name;
    /* 0 = iterative (default, one connection at a time — the
     * historical behavior); >0 = thread-per-connection with this many
     * MAXIMUM concurrent workers. When the limit is reached, the
     * accept loop handles the connection itself (graceful degradation,
     * bounded by the socket timeouts). */
    unsigned short worker_threads;
    /* false = close after one response (default, historical); true =
     * HTTP/1.1 keep-alive per RFC 9112 §9.3 (persistent by default,
     * "Connection: close" opts out; HTTP/1.0 only with an explicit
     * "Connection: keep-alive"). Pipelining is NOT supported: a
     * request sent before the previous response is a 400. */
    bool keep_alive;
} ServerArgs;

typedef struct {
    char method[HTTP_METHOD_MAX];
    char path[HTTP_PATH_MAX];
    char version[HTTP_VERSION_MAX];
    /* Client IP (dotted quad, e.g. "127.0.0.1") and port — filled by
     * the library before any handler or middleware runs. 46 bytes
     * (INET6_ADDRSTRLEN), so an IPv6 switch keeps the struct size. */
    char ip[46];
    uint16_t client_port;
    HttpHeaders headers;
    /* Request body (NUL-terminated; allocated by the library and freed
     * after the request). NULL if no body was sent. */
    char *body;
    size_t body_len;
    HttpParams params;
    /* Parsed query string ("?a=1&b=two" -> pairs), eagerly filled per
     * request; empty (count == 0) when no query was sent. Values are
     * URL-decoded ('+' -> space). See http_req_query(). */
    HttpQuery query;
    /* Parsed application/x-www-form-urlencoded body — the same pair
     * semantics as the query, eagerly filled after read_body() when the
     * Content-Type matches. See http_req_form(). */
    HttpQuery form;
    /* Parsed multipart/form-data parts, eagerly filled after read_body()
     * when the Content-Type matches. See http_req_multipart_*(). */
    HttpMultiparts multiparts;
} HttpRequest;

typedef struct {
    int status;
    char body[4096];
    size_t body_len;
    HttpHeaders headers;
    /* Heap body: set by http_res_body()/http_res_html() when the body
     * does not fit the fixed 4096-byte buffer above. Owned by the
     * response; the library frees it after the send. NULL = the
     * regular body buffer carries the body. */
    char *dyn_body;
    size_t dyn_body_len;
    /* Locals: request-scoped data passed down the chain (middleware
     * writes via http_set_local(), handler reads via http_res_local()).
     * Fixed slots — no cleanup needed, per-request lifetime. */
    HttpLocals locals;
    char *encoded_body;
    size_t encoded_body_len;
    /* File streaming: if the handler sets this heap-allocated path
     * (malloc/strdup — ownership passes to the response), the library
     * sends the file as the body (instead of body/encoded_body) and
     * frees the memory afterwards. NULL = regular body. */
    char *file_path;
    /* Single-range support for file responses (RFC 9110 §14): when
     * ranged is set together with file_path, only the byte range
     * [range_start, range_start + range_len) of the file is sent.
     * The handler computed it from the request's Range header and
     * sets the status (206) and Content-Range header itself. */
    bool ranged;
    size_t range_start;
    size_t range_len;
    /* Central error channel: set via http_error() or by the framework
     * (404/405/501, protocol parse errors). If the server has an error
     * handler, it runs at send time and may set body/headers; without
     * one the status is sent with an empty body (backwards compatible). */
    bool error;
    char error_message[HTTP_ERROR_MESSAGE_MAX];
} HttpResponse;

typedef void (*HttpHandler)(const HttpRequest *req, HttpResponse *res);
typedef HttpMiddlewareResult (*HttpMiddlewareHandler)(const HttpRequest *req,
                                                      HttpResponse *res);
/* Central error handler: called at send time for framework errors
 * (http_error(), 404/405/501 from routing, protocol parse errors).
 * May set body/headers/locals (status may be adjusted); must tolerate
 * a partially parsed req (empty fields) for protocol errors. */
typedef void (*HttpErrorHandler)(const HttpRequest *req, HttpResponse *res,
                                 int status, const char *message);

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

/* Express-style Router: collects routes with RELATIVE paths
 * ("/dashboard") and is mounted at a prefix via http_use(). Opaque —
 * defined in c_http.c. */
typedef struct HttpRouter HttpRouter;

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
    /* Per-connection persistence (ServerArgs.keep_alive). */
    bool keep_alive;
    HttpRoutes routes;
    HttpMiddlewares middlewares;
    HttpEncoders encoders;
    char *server_name;
    /* Opaque mount list for static files — owned and managed by
     * c_http_static.c (see c_http_static.h). NULL while nothing is
     * mounted; http_close_server() frees it. */
    void *static_mounts;
    /* Central error handler (NULL = none): formats framework errors at
     * send time, see HttpErrorHandler. */
    HttpErrorHandler error_handler;
    /* Opaque list of mounted routers (mount order) — owned by the
     * library, freed in http_close_server(). */
    void *router_mounts;
    /* Opaque worker-thread state (WorkerState) when
     * ServerArgs.worker_threads > 0 — NULL for the iterative default.
     * http_close_server() DRAINS the workers before freeing. */
    void *thread_state;
    /* Opaque list of registered websocket routes (HttpWsRoute) — owned
     * by c_http_ws.c, freed in http_close_server(). NULL while no WS
     * route is registered. */
    void *ws_routes;
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

/* Request header access: returns the value for key (case-insensitive,
 * first occurrence — RFC 9110 §5.1 field names are case-insensitive),
 * or NULL if the header was not sent. */
const char *http_req_header(const HttpRequest *req, const char *key);

/* Query string access: returns the URL-decoded value for key (first
 * occurrence), "" for a bare "?flag" key without '=', or NULL if the
 * pair was not sent (or was skipped as malformed/oversized). */
const char *http_req_query(const HttpRequest *req, const char *key);

/* Form body access: returns the decoded value for key (first
 * occurrence) from an application/x-www-form-urlencoded body —
 * the same pair semantics as http_req_query(). NULL if absent or the
 * body is not urlencoded. */
const char *http_req_form(const HttpRequest *req, const char *key);

/* Classifies the request body by its Content-Type. */
HttpBodyType http_req_body_type(const HttpRequest *req);

/* Minimal JSON body access: extracts the string value of a TOP-LEVEL
 * key from the request body (Content-Type is NOT enforced). Handles
 * escapes (\" \\ \/ \b \f \n \r \t and \uXXXX) and skips nested
 * objects/arrays. Returns the number of bytes written into out (0 =
 * empty string), or -1 when the key is absent, its value is not a
 * string, the JSON is malformed or out is too small (NEVER
 * truncates). This is a convenience accessor, NOT a full JSON parser
 * — vendor a real one if you need nested/typed access. */
int http_req_json_string(const HttpRequest *req, const char *key, char *out,
                         size_t out_size);

/* ---- multipart/form-data (RFC 7578) ----
 * Parsed eagerly when the request Content-Type is multipart/form-data;
 * parts beyond HTTP_MAX_MULTIPART_PARTS or malformed parts are
 * skipped. The part data is NOT a C string: use data/data_len (it can
 * contain NULs); save uploads to disk yourself. */

size_t http_req_multipart_count(const HttpRequest *req);
const HttpMultipartPart *http_req_multipart_part(const HttpRequest *req,
                                                 size_t index);
/* First part with the given field name, or NULL. */
const HttpMultipartPart *http_req_multipart_get(const HttpRequest *req,
                                                const char *name);

/* ---- content negotiation (RFC 9110 §12.5.1 Accept) ---- */

/* Pass the media types the handler can produce (NULL-terminated).
 * Returns the best match according to the request's Accept header
 * (most specific range wins: an exact match over a subtype wildcard
 * over a full wildcard, honoring q-values; q=0 excludes), or NULL
 * when nothing is acceptable. Without an Accept header every type is
 * acceptable (the first one is returned). */
const char *http_req_accepts(const HttpRequest *req, const char *const *types);

/* Locals: request-scoped middleware -> handler data (Express-style
 * res.locals). Overwrites an existing key. Returns HTTP_SET_LOCAL_OK,
 * or ERROR on NULL/empty key, oversized key/value or full slots. */
HttpSetLocalResult http_set_local(HttpResponse *res, const char *key,
                                  const char *value);
const char *http_res_local(const HttpResponse *res, const char *key);

/* ---- Response helpers (all return 0 = OK, -1 = error; on -1 nothing
 * is written — check the return, do not assume success) ---- */

/* Status + Content-Type: application/json + body (caller provides the
 * serialized JSON). -1 on invalid status or body too long for the
 * 4096-byte response buffer. */
int http_res_json(HttpResponse *res, int status, const char *body);

/* Status + explicit Content-Type + body of any length: bodies that
 * fit the fixed 4096-byte response buffer are copied into it,
 * larger ones into a heap body (dyn_body) that the library frees
 * after the send. http_res_html() builds on this. -1 on invalid
 * status, NULL body with a nonzero length, or a Content-Type with
 * CR/LF (header injection) — on -1 nothing is written. */
int http_res_body(HttpResponse *res, int status, const char *content_type,
                  const char *body, size_t body_len);

/* 3xx status + Location header, empty body. -1 outside 300-399 or on
 * CR/LF injection in the location. */
int http_res_redirect(HttpResponse *res, int status, const char *location);

/* Set-Cookie: name=value; Path=/[; Max-Age=N][; HttpOnly]. max_age 0 =
 * session cookie. -1 on invalid name (token chars only, no ";= \\t"),
 * ";" in the value (attribute injection) or CR/LF injection. */
int http_res_cookie(HttpResponse *res, const char *name, const char *value,
                    unsigned max_age, bool http_only);

/* ---- Central error handling ---- */

/* Marks the response as an error: sets the status (coerced to 500 when
 * outside 400-599) and stores the message. The server's error handler
 * (if set) formats it at send time — without one, the status is sent
 * with an empty body. */
void http_error(HttpResponse *res, int status, const char *message);

void http_set_error_handler(HttpServer *server, HttpErrorHandler handler);

/* ---- Routers (Express-style express.Router + app.use) ----
 * Dispatch order per request: server routes (first match wins) ->
 * mounted routers in MOUNT order -> static mounts. Ownership of a
 * router passes to the server on http_use() (mounted exactly once,
 * freed by http_close_server()); routes added after mounting are live. */

HttpRouter *http_router_create(void);
/* Only for UNMOUNTED routers (mounted ones belong to the server). */
void http_router_free(HttpRouter *router);
HttpRouteAddResult http_router_get(HttpRouter *router, const char *path,
                                   HttpHandler handler);
HttpRouteAddResult http_router_post(HttpRouter *router, const char *path,
                                    HttpHandler handler);
HttpRouteAddResult http_router_put(HttpRouter *router, const char *path,
                                   HttpHandler handler);
HttpRouteAddResult http_router_patch(HttpRouter *router, const char *path,
                                     HttpHandler handler);
HttpRouteAddResult http_router_delete(HttpRouter *router, const char *path,
                                      HttpHandler handler);
HttpRouteAddResult http_router_head(HttpRouter *router, const char *path,
                                    HttpHandler handler);
HttpRouteAddResult http_router_options(HttpRouter *router, const char *path,
                                       HttpHandler handler);
HttpRouteAddResult http_router_trace(HttpRouter *router, const char *path,
                                     HttpHandler handler);
HttpRouteAddResult http_router_connect(HttpRouter *router, const char *path,
                                       HttpHandler handler);

/* Mounts a router at a URL prefix (must start with '/', no ':params',
 * no '?'). Must run before http_listen(). */
HttpUseResult http_use(HttpServer *server, const char *prefix,
                       HttpRouter *router);

/* ---- WebSockets (RFC 6455), server side ----
 *
 * Register a handler with http_ws() (or http_ws_options()). A GET
 * request with "Connection: Upgrade" + "Upgrade: websocket" on a
 * registered path performs the RFC 6455 §4.2 handshake, then calls
 * the handler for the WHOLE lifetime of the connection (blocking —
 * use ServerArgs.worker_threads > 0; in the iterative default the
 * handshake is rejected with 503). Middleware runs before the
 * handshake, so http_middleware() guards work as usual.
 *
 * The handler receives ws and the parsed request (path params bound,
 * headers readable). Pings are answered transparently; received
 * close frames are echoed and surface as HTTP_WS_CLOSED. */

typedef struct HttpWs HttpWs; /* opaque session — defined in c_http_ws.c */

typedef enum {
    HTTP_WS_OK,     /* a message was received (msg is filled) */
    HTTP_WS_CLOSED, /* close handshake complete (or peer vanished) */
    HTTP_WS_ERROR,  /* socket error — the session is over */
} HttpWsResult;

typedef enum {
    HTTP_WS_TEXT,
    HTTP_WS_BINARY,
} HttpWsMessageType;

typedef struct {
    HttpWsMessageType type;
    /* Message payload. NUL-terminated for convenience; binary messages
     * may contain embedded NULs — use len. Owned by the session and
     * valid until the NEXT http_ws_recv() call or session end. */
    const char *data;
    size_t len;
} HttpWsMessage;

typedef void (*HttpWsHandler)(HttpWs *ws, const HttpRequest *req);

/* Runs BEFORE the handshake is accepted; return false to reject the
 * upgrade with 403 (origin checks, subprotocol policy, ...). */
typedef bool (*HttpWsVerify)(const HttpRequest *req);

typedef struct {
    /* NULL = accept every upgrade. */
    HttpWsVerify verify;
    /* NULL-terminated list of supported subprotocols. The first one
     * offered by the client is selected and echoed in the 101; when
     * the client offers none of them, the header is omitted (the
     * client decides whether to accept that). NULL = none supported. */
    const char *const *subprotocols;
    /* Maximum message size in BYTES (a fragmented message counts as a
     * whole; larger messages are closed with status 1009). 0 = the
     * HTTP_WS_DEFAULT_MAX_MESSAGE default (see c_http_ws.h). */
    size_t max_message;
} HttpWsOptions;

/* Registers a websocket route. The path follows the same rules as
 * http_get() ("/ws", "/chat/:room", no '?'). Must run before
 * http_listen(). */
HttpRouteAddResult http_ws(HttpServer *server, const char *path,
                           HttpWsHandler handler);
/* Same, with options (NULL options = defaults). */
HttpRouteAddResult http_ws_options(HttpServer *server, const char *path,
                                   HttpWsHandler handler,
                                   const HttpWsOptions *options);

/* Blocking receive of the next text/binary message. Pings arriving
 * while waiting are answered transparently; a received close frame is
 * echoed and reported as HTTP_WS_CLOSED (all further calls return
 * HTTP_WS_CLOSED). Returns HTTP_WS_ERROR on socket errors. */
HttpWsResult http_ws_recv(HttpWs *ws, HttpWsMessage *msg);

/* All send functions return 0 = OK, -1 = error (then the session is
 * dead; further sends fail too). Thread-safe: sends are serialized
 * per session, so other threads may broadcast while a handler runs. */
int http_ws_send_text(HttpWs *ws, const char *data, size_t len);
int http_ws_send_binary(HttpWs *ws, const void *data, size_t len);
int http_ws_send_ping(HttpWs *ws, const void *data, size_t len);

/* Starts the close handshake with the given status code and reason
 * (truncated to 123 bytes), then waits briefly for the peer's close
 * echo (HTTP_WS_CLOSE_WAIT_MS). The handler should return afterwards;
 * when a handler returns without closing, the library closes with
 * code 1000 itself. */
int http_ws_close(HttpWs *ws, unsigned short code, const char *reason);

/* Per-session user pointer (e.g. broadcast registries, connection
 * context). Never touched by the library. */
void http_ws_set_data(HttpWs *ws, void *data);
void *http_ws_get_data(const HttpWs *ws);

/* Close code of the finished close handshake (sent or received), 0
 * while no close happened yet, 1006 for a peer that vanished without
 * one. Diagnostic aid — meaningful after HTTP_WS_CLOSED. */
unsigned short http_ws_close_code(const HttpWs *ws);

extern const HttpEncoder http_gzip_encoder;
extern const HttpEncoder http_identity_encoder;

#endif
