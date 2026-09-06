#ifndef C_HTTP_STATIC_H
#define C_HTTP_STATIC_H

#include "c_http.h"

/* Static file serving for c-http.
 *
 * http_static_mount() mounts a root directory under a URL prefix;
 * requests on exact routes still win over mounts. Guards against path
 * traversal (.. — URL-encoded too), NUL injection (%00), control
 * characters and symlink escapes out of the root directory. Larger
 * files are streamed (see HttpResponse.file_path). */

typedef struct {
    const char *prefix;     /* URL prefix, e.g. "/public" ("/" = all) */
    const char *root;       /* root directory, must exist               */
    const char *index_file; /* for directory requests, NULL = 404       */
    unsigned max_age;       /* Cache-Control: max-age seconds, 0 = off  */
} HttpStaticConfig;

typedef enum {
    HTTP_STATIC_NOT_MATCHED,        /* no mount matches the path        */
    HTTP_STATIC_SERVED,             /* mount filled the response         */
    HTTP_STATIC_METHOD_NOT_ALLOWED, /* path matches, but not GET/HEAD   */
} HttpStaticDispatchResult;

/* Mounts a directory under a URL prefix. Must be called before
 * http_listen(). All strings are copied (strdup) — the caller may free
 * or drop its config afterwards. */
HttpServerResult http_static_mount(HttpServer *server,
                                   const HttpStaticConfig *cfg);

/* Fills the response for a file request under cfg->prefix. Meant for
 * tests and custom routing — normally the library's mount dispatch
 * takes care of this. req->path must start with cfg->prefix (or "/"). */
void http_static_handler(const HttpRequest *req, HttpResponse *res,
                         const HttpStaticConfig *cfg);

/* Internal (called from c_http.c): checks all mounts against the
 * request path and serves on the first match. */
HttpStaticDispatchResult http_static_dispatch(const HttpServer *server,
                                              const HttpRequest *req,
                                              HttpResponse *res);

/* Internal (called from http_close_server): frees the mount list. */
void http_static_mounts_free(HttpServer *server);

#endif