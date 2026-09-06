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

| Feature                              | Status |
| ------------------------------------ | ------ |
| HTTP/1.1 request parsing             | ✅     |
| All 9 HTTP methods                   | ✅     |
| All 62 HTTP status codes             | ✅     |
| Dynamic route array                  | ✅     |
| Middleware with path matching        | ✅     |
| Middleware abort (short-circuit)     | ✅     |
| Dynamic headers (request + response) | ✅     |
| gzip content encoding (default)      | ✅     |
| Request body (`Content-Length`)       | ✅     |
| Accept-Encoding q-values (RFC 9110)   | ✅     |
| Custom encoder plugin system          | ✅     |
| Graceful shutdown (`http_stop_server`)| ✅     |
| Slowloris protection (socket timeout) | ✅     |
| HTTP spec asserts (debug builds)     | ✅     |
| Single-header amalgamation           | ✅     |

Responses follow HTTP/1.1: correct status codes (`400/405/413/414/431/501/505`
instead of silent 404s for malformed requests), `HEAD` falls back to `GET`
with the body suppressed, query strings are stripped from routing, request
bodies are exposed via `req->body`, and header injection / response splitting
is rejected in every build type. `http_stop_server()` stops a running
`http_listen()` loop (safe to call from a `SIGINT`/`SIGTERM` handler).

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
#define C_HTTP_VERSION "0.3.0"
```

## Project structure

```
include/         Public headers (c_http.h, c_http_assert.h)
src/             Library implementation (c_http.c, c_http_encoder.c)
examples/        Example server using the library
tests/           Unit tests
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
