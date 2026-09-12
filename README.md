# c-http

A minimal HTTP server library in C — TCP-Sockets, Routing, Middleware, gzip, and a plugin system for content encoding.

## Quick start

### Option 1: Single-header (easiest)

Download [`c_http_single.h`](releases) from the latest release, then:

```c
// main.c
#define C_HTTP_IMPLEMENTATION
#include "c_http_single.h"

static void home_handler(const HttpRequest *req, HttpResponse *res) {
    res->status = 200;
    const char *body = "<h1>Hello!</h1>";
    memcpy(res->body, body, strlen(body));
    res->body_len = strlen(body);
}

int main(void) {
    HttpServer server = {0};
    ServerArgs args = { .port = 8080, .bind_addr = "0.0.0.0", .server_name = "my-server" };
    http_create_server(&args, &server);
    http_get(&server, "/", home_handler);
    http_listen(&server);
    http_close_server(&server);
}
```

```bash
cc main.c -lz -o my-server && ./my-server
```

> Requires: zlib (`-lz`)

### Option 2: Git submodule

```bash
git submodule add https://github.com/maxischmaxi/c-http vendor/c-http
```

```cmake
# CMakeLists.txt
add_subdirectory(vendor/c-http)
target_link_libraries(my-app PRIVATE c_http::c_http)
```

```c
#include "c_http.h"
```

### Option 3: Install + find_package

```bash
git clone https://github.com/maxischmaxi/c-http && cd c-http
cmake -S . -B build && cmake --build build && sudo cmake --install build
```

```cmake
find_package(c-http REQUIRED)
target_link_libraries(my-app PRIVATE c_http::c_http)
```

## Features

| Feature                                   | Status |
| ----------------------------------------- | ------ |
| HTTP/1.1 request parsing                  | ✅     |
| All 9 HTTP methods                        | ✅     |
| All 62 HTTP status codes                  | ✅     |
| Dynamic route array                       | ✅     |
| Middleware with path matching             | ✅     |
| Middleware abort (short-circuit)          | ✅     |
| Dynamic headers (request + response)      | ✅     |
| gzip content encoding (default)           | ✅     |
| Request body (`Content-Length`)           | ✅     |
| Accept-Encoding q-values (RFC 9110)       | ✅     |
| Custom encoder plugin system              | ✅     |
| Route params (`:id` + `http_req_param`)  | ✅     |
| Query parser (`http_req_query`)           | ✅     |
| Locals (`http_set_local`/`http_res_local`) | ✅   |
| Central error handler (`http_error`)       | ✅   |
| Routers (`HttpRouter` + `http_use`)       | ✅     |
| res helpers (json/redirect/cookie)        | ✅     |
| Body parsers (urlencoded + JSON access)  | ✅     |
| multipart/form-data parsing (`http_req_multipart_*`) | ✅ |
| Single-range requests (RFC 9110 §14, static files) | ✅ |
| Content negotiation (`http_req_accepts`) | ✅ |
| Thread-per-connection (opt-in)           | ✅     |
| Keep-alive (opt-in, RFC 9112)            | ✅     |
| Auto-OPTIONS (204 + Allow)               | ✅     |
| Static file serving (`http_static_mount`) | ✅     |
| File streaming (`res->file_path`)         | ✅     |
| Graceful shutdown (`http_stop_server`)    | ✅     |
| WebSockets (`http_ws`, RFC 6455, server)  | ✅     |
| Slowloris protection (socket timeout)     | ✅     |
| HTTP spec asserts (debug builds)          | ✅     |
| Single-header amalgamation                | ✅     |

Responses follow HTTP/1.1: correct status codes (`400/405/413/414/431/501/505`
instead of silent 404s for malformed requests), `HEAD` falls back to `GET`
with the body suppressed, query strings are stripped from routing, request
bodies are exposed via `req->body`, and header injection / response splitting
is rejected in every build type. `http_stop_server()` stops a running
`http_listen()` loop (safe to call from a `SIGINT`/`SIGTERM` handler).

## WebSockets

Server-side [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) support —
handshake, frame codec (fragmentation, masking, all length forms),
ping/pong (auto-answered), close handshake and subprotocol negotiation.
No new dependencies: SHA-1 + Base64 are built in.

```c
static void echo_handler(HttpWs *ws, const HttpRequest *req)
{
    (void)req;
    HttpWsMessage msg;
    while (http_ws_recv(ws, &msg) == HTTP_WS_OK) {
        http_ws_send_text(ws, msg.data, msg.len);
    }
}

int main(void)
{
    HttpServer server = {0};
    ServerArgs args = {.port = 8080, .bind_addr = "0.0.0.0",
                       .server_name = "ws", .worker_threads = 8};
    http_create_server(&args, &server);
    http_ws(&server, "/ws", echo_handler); /* or http_ws_options() */
    http_listen(&server);
    http_close_server(&server);
}
```

Rules and guarantees:

- **`ServerArgs.worker_threads > 0` is required** — a WS handler runs for
  the connection's whole lifetime and would block the iterative accept
  loop; in the iterative default the handshake is rejected with `503`.
- Middleware runs **before** the handshake: `http_middleware(server, "/ws",
  auth)` guards upgrades as usual. Route params work (`/ws/chat/:room`).
- Sends are **thread-safe per session** — other threads may broadcast
  (chat style) while a handler blocks in `http_ws_recv()`.
- Pings are answered transparently; received close frames are echoed and
  surface as `HTTP_WS_CLOSED`. When a handler returns without closing, the
  library completes the close handshake with code `1000`.
- `http_ws_recv()` polls with a short timeout instead of blocking forever:
  after `http_stop_server()` the handler returns within `HTTP_WS_POLL_MS`
  and the client receives a proper close frame (code `1001`).
- Protocol violations are closed with the right codes (`1002`, oversized
  messages `1009`; limit configurable via `HttpWsOptions.max_message`).
- `HttpWsOptions`: pre-handshake `verify` callback (origin checks), supported
  `subprotocols` (first client offer wins), `max_message`.

## Build types

```bash
# Debug (default): asserts + sanitizers + no optimization
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

# Release: asserts removed + -O2
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
```

## Version

Defined in [`include/c_http.h`](include/c_http.h):

```c
#define C_HTTP_VERSION "0.7.0"
```

## Project structure

```
include/         Public headers (c_http.h, c_http_assert.h)
src/             Library implementation (c_http.c, c_http_encoder.c,
                 c_http_static.c, c_http_ws.c)
examples/        Example server using the library
                 (incl. a websocket chat demo: examples/www/ws.html)
tests/           Integration tests (raw-socket style)
scripts/         Amalgamation script
```

The `examples/` directory contains a demo server (`main.c`, `args.c`) showing how to use the library. It is not part of the library itself.

## Development

```bash
cmake -S . -B build
cmake --build build -t format       # clang-format
cmake --build build -t format-check # CI format check
cmake --build build -t lint         # clang-tidy
cmake --build build -t c_http_amalgamate  # generate single-header
ctest --test-dir build --output-on-failure  # run tests
```

## Dependencies

| Dependency                              | Purpose                  | Required?             |
| --------------------------------------- | ------------------------ | --------------------- |
| [zlib](https://zlib.net/)               | gzip encoding            | Yes                   |
| [cargs](https://likle.github.io/cargs/) | CLI args (examples only) | No, only for examples |
