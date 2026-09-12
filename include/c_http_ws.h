#ifndef C_HTTP_WS_H
#define C_HTTP_WS_H

#include "c_http.h"

/* WebSockets (RFC 6455), SERVER side only.
 *
 * The public API lives in c_http.h (HttpWs, http_ws(), http_ws_recv(),
 * ...). This header is the internal interface between c_http.c and
 * c_http_ws.c — the same split as c_http_static.h.
 *
 * Dispatch: http_ws_dispatch() is called from handle_client() AFTER
 * middleware and BEFORE normal routing, so middleware can guard WS
 * upgrades (auth) like any other request. A request that is not a
 * websocket upgrade (or matches no WS route) falls through to the
 * normal HTTP routing. */

/* Default message size limit: larger (fragmented) messages are closed
 * with status 1009. Overridable per route via HttpWsOptions. */
#define HTTP_WS_DEFAULT_MAX_MESSAGE ((size_t)4 * 1024 * 1024)

/* SO_RCVTIMEO for an upgraded connection. http_ws_recv() polls this
 * often and checks the server's listening flag — graceful shutdown
 * works without any locks in the (async-signal-safe) stop path, and
 * active WS handlers return within this interval of http_stop_server(). */
#define HTTP_WS_POLL_MS 250L

/* http_ws_close() waits at most this long for the peer's close echo
 * (RFC 6455 §5.5.1: SHOULD close the connection first). */
#define HTTP_WS_CLOSE_WAIT_MS 1000

typedef enum {
    WS_DISPATCH_NOT_WS = 0, /* not an upgrade request: normal routing */
    WS_DISPATCH_UPGRADED,   /* session complete: close the connection */
    WS_DISPATCH_REJECTED,   /* error response sent (400/403/426/503) */
} HttpWsDispatchResult;

/* Internal (called from handle_client): performs the RFC 6455 §4.2
 * handshake and, on success, runs the WS handler for the connection's
 * whole lifetime — the call returns only after the session ended.
 *
 *   req           the parsed upgrade request (params bound on match)
 *   req_segments  the parsed request path (for WS route matching)
 *   client_fd     the connection socket (owned by the caller)
 *   leftover      bytes read together with the handshake headers that
 *                 already belong to the WS stream (early frames)
 *
 * Rejection responses (400/403/426/503) are sent by the WS module
 * itself. Returns WS_DISPATCH_NOT_WS when the request is not a
 * websocket upgrade or no WS route matches — the caller continues
 * with normal routing. */
HttpWsDispatchResult http_ws_dispatch(HttpServer *server, HttpRequest *req,
                                      const HttpRouteSegments *req_segments,
                                      int client_fd, const char *leftover,
                                      size_t leftover_len);

/* Internal (called from http_close_server): frees the WS route list
 * (server->ws_routes). */
void http_ws_routes_free(HttpServer *server);

/* ---- shared route helpers (defined in c_http.c, used by both
 * translation units — prototypes here to satisfy -Wmissing-prototypes
 * for the non-static definitions) ---- */

/* Parses "/a/:id/b" into pattern segments. Returns false on a bare ':'
 * or an oversized segment (then no route can ever match). */
bool http_parse_route_segments(const char *pattern, HttpRouteSegments *out);

/* Full-path match (req_segments pre-parsed). Binds params into out
 * when non-NULL; a failed match leaves out untouched. */
bool http_segments_match(const HttpRouteSegments *pattern,
                         const HttpRouteSegments *req_segments,
                         HttpParams *out);

#endif