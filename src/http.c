#include "http.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define HTTP_ROUTE_INITIAL_CAP 8

static const char *status_text(int status)
{
    switch (status) {
    /* 1xx Informational */
    case 100:
        return "Continue";
    case 101:
        return "Switching Protocols";
    case 102:
        return "Processing";
    case 103:
        return "Early Hints";

    /* 2xx Success */
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 202:
        return "Accepted";
    case 203:
        return "Non-Authoritative Information";
    case 204:
        return "No Content";
    case 205:
        return "Reset Content";
    case 206:
        return "Partial Content";
    case 207:
        return "Multi-Status";
    case 208:
        return "Already Reported";
    case 226:
        return "IM Used";

    /* 3xx Redirection */
    case 300:
        return "Multiple Choices";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 303:
        return "See Other";
    case 304:
        return "Not Modified";
    case 305:
        return "Use Proxy";
    case 307:
        return "Temporary Redirect";
    case 308:
        return "Permanent Redirect";

    /* 4xx Client Error */
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 402:
        return "Payment Required";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 406:
        return "Not Acceptable";
    case 407:
        return "Proxy Authentication Required";
    case 408:
        return "Request Timeout";
    case 409:
        return "Conflict";
    case 410:
        return "Gone";
    case 411:
        return "Length Required";
    case 412:
        return "Precondition Failed";
    case 413:
        return "Content Too Large";
    case 414:
        return "URI Too Long";
    case 415:
        return "Unsupported Media Type";
    case 416:
        return "Range Not Satisfiable";
    case 417:
        return "Expectation Failed";
    case 418:
        return "I'm a Teapot";
    case 421:
        return "Misdirected Request";
    case 422:
        return "Unprocessable Content";
    case 423:
        return "Locked";
    case 424:
        return "Failed Dependency";
    case 425:
        return "Too Early";
    case 426:
        return "Upgrade Required";
    case 428:
        return "Precondition Required";
    case 429:
        return "Too Many Requests";
    case 431:
        return "Request Header Fields Too Large";
    case 451:
        return "Unavailable For Legal Reasons";

    /* 5xx Server Error */
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    case 504:
        return "Gateway Timeout";
    case 505:
        return "HTTP Version Not Supported";
    case 506:
        return "Variant Also Negotiates";
    case 507:
        return "Insufficient Storage";
    case 508:
        return "Loop Detected";
    case 510:
        return "Not Extended";
    case 511:
        return "Network Authentication Required";
    default:
        return "Unknown";
    }
}

static int string_to_protocol(const char *method, HttpMethod *out)
{
    if (method == NULL || out == NULL) {
        return -1;
    }

    if (strcmp(method, "GET") == 0) {
        *out = HTTP_METHOD_GET;
    } else if (strcmp(method, "POST") == 0) {
        *out = HTTP_METHOD_POST;
    } else if (strcmp(method, "PUT") == 0) {
        *out = HTTP_METHOD_PUT;
    } else if (strcmp(method, "PATCH") == 0) {
        *out = HTTP_METHOD_PATCH;
    } else if (strcmp(method, "DELETE") == 0) {
        *out = HTTP_METHOD_DELETE;
    } else if (strcmp(method, "HEAD") == 0) {
        *out = HTTP_METHOD_HEAD;
    } else if (strcmp(method, "OPTIONS") == 0) {
        *out = HTTP_METHOD_OPTIONS;
    } else if (strcmp(method, "CONNECT") == 0) {
        *out = HTTP_METHOD_CONNECT;
    } else if (strcmp(method, "TRACE") == 0) {
        *out = HTTP_METHOD_TRACE;
    } else {
        return -1;
    }

    return 0;
}

static ssize_t read_request(int client_fd, char *buf, size_t size)
{
    size_t total = 0;

    while (total < size - 1) {
        ssize_t r = recv(client_fd, buf + total, size - 1 - total, 0);
        if (r < 0) {
            return -1;
        }
        if (r == 0) {
            break;
        }
        total += (size_t)r;
        buf[total] = '\0';

        if (strstr(buf, "\r\n\r\n") != NULL) { /* Header komplett */
            break;
        }
    }

    buf[total] = '\0';
    return (ssize_t)total;
}

static int send_all(int client_fd, const char *data, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        ssize_t s = send(client_fd, data + sent, len - sent, 0);
        if (s < 0) {
            return -1;
        }
        sent += (size_t)s;
    }

    return 0;
}

static void handle_client(HttpServer *server, int client_fd, const char *ip,
                          uint16_t client_port)
{
    char buf[4096];
    ssize_t total = read_request(client_fd, buf, sizeof(buf));

    if (total < 0) {
        perror("recv");
        return;
    }
    if (total == 0) {
        printf("client connection closed\n");
        return;
    }

    HttpRequest req = {0};
    HttpResponse res = {0};

    int fields =
        sscanf(buf, "%7s %511s %15s", req.method, req.path, req.version);

    if (fields != 3) {
        const char *bad = "HTTP/1.1 400 Bad Request\r\n"
                          "Content-Length: 0\r\n"
                          "Connection: close\r\n"
                          "\r\n";
        send_all(client_fd, bad, strlen(bad));
        return;
    }

    for (size_t i = 0; i < server->middleware_count; i++) {
        HttpMiddlewareHandler middleware = server->middlewares[i].handler;
        if (server->middlewares[i].path == NULL) {
            middleware(&req, &res);
            continue;
        }

        // TODO: path matching, only execute a middleware that is a parent or
        // the exact same route
    }

    HttpHandler handler = NULL;
    for (size_t i = 0; i < server->route_count; i++) {
        HttpMethod m;
        if (string_to_protocol(req.method, &m) != 0) {
            continue;
        }
        if (m != server->routes[i].method) {
            continue;
        }
        if (strcmp(req.path, server->routes[i].path) == 0) {
            handler = server->routes[i].handler;
            break;
        }
    }

    if (handler != NULL) {
        handler(&req, &res);
    } else {
        res.status = 404;
    }

    if (res.status == 0) {
        res.status = 500;
    }

    printf("%s:%u %s %s -> %d\n", ip, client_port, req.method, req.path,
           res.status);

    char header[256];
    int header_len =
        snprintf(header, sizeof(header),
                 "HTTP/1.1 %d %s\r\n"
                 "Content-Type: text/html\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 res.status, status_text(res.status), res.body_len);

    if (header_len < 0 || (size_t)header_len >= sizeof(header) ||
        send_all(client_fd, header, (size_t)header_len) < 0 ||
        send_all(client_fd, res.body, res.body_len) < 0) {
        perror("send");
    }
}

HttpServerResult http_create_server(const ServerArgs *server_args,
                                    HttpServer *out)
{
    if (out == NULL || server_args == NULL) {
        return SERVER_ERROR;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return SERVER_ERROR;
    }

    int yes = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct addrinfo hints;
    struct addrinfo *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(server_args->bind_addr, NULL, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "cannot resolve '%s': %s\n", server_args->bind_addr,
                gai_strerror(gai));
        close(server_fd);
        return SERVER_ERROR;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_args->port);
    addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("failed to bind port");
        close(server_fd);
        freeaddrinfo(res);
        return SERVER_ERROR;
    }

    freeaddrinfo(res);

    if (listen(server_fd, 10) < 0) {
        perror("failed to listen");
        close(server_fd);
        return SERVER_ERROR;
    }

    out->routes = malloc(HTTP_ROUTE_INITIAL_CAP * sizeof(HttpRoute));
    out->route_count = 0;
    out->route_capacity = HTTP_ROUTE_INITIAL_CAP;
    if (out->routes == NULL) {
        return SERVER_ERROR;
    }

    out->port = server_args->port;
    out->bind_addr = server_args->bind_addr;
    out->listening = false;
    out->fd = server_fd;
    return SERVER_OK;
}

void http_close_server(HttpServer *server)
{
    if (server->fd) {
        close(server->fd);
    }
    free(server->routes);
    server->routes = NULL;
    server->route_count = server->route_capacity = 0;
}

void http_listen(HttpServer *server)
{
    server->listening = true;
    printf("Server listening on port %d\n", server->port);

    while (server->listening) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd =
            accept(server->fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        uint16_t client_port = ntohs(client_addr.sin_port);

        handle_client(server, client_fd, ip, client_port);
        close(client_fd);
    }
}

static HttpRouteAddResult http_add_route(HttpServer *server, const char *path,
                                         HttpHandler handler, HttpMethod method)
{
    if (server->route_count == server->route_capacity) {
        size_t new_cap = server->route_capacity * 2;
        HttpRoute *tmp = realloc(server->routes, new_cap * sizeof(HttpRoute));
        if (!tmp) {
            return HTTP_ROUTE_ADD_ERROR;
        }
        server->routes = tmp;
        server->route_capacity = new_cap;
    }

    for (size_t i = 0; i < server->route_count; i++) {
        if (server->routes[i].method == method &&
            server->routes[i].path == path) {
            return HTTP_ROUTE_ADD_CONFLICT;
        }
    }

    server->routes[server->route_count++] =
        (HttpRoute){.path = path, .handler = handler, .method = method};

    return HTTP_ROUTE_ADD_OK;
}

HttpRouteAddResult http_get(HttpServer *server, const char *path,
                            HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_GET);
}

HttpRouteAddResult http_post(HttpServer *server, const char *path,
                             HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_POST);
}

HttpRouteAddResult http_patch(HttpServer *server, const char *path,
                              HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_PATCH);
}

HttpRouteAddResult http_put(HttpServer *server, const char *path,
                            HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_PUT);
}

HttpRouteAddResult http_delete(HttpServer *server, const char *path,
                               HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_DELETE);
}

HttpRouteAddResult http_head(HttpServer *server, const char *path,
                             HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_HEAD);
}

HttpRouteAddResult http_connect(HttpServer *server, const char *path,
                                HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_CONNECT);
}

HttpRouteAddResult http_trace(HttpServer *server, const char *path,
                              HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_TRACE);
}

HttpRouteAddResult http_options(HttpServer *server, const char *path,
                                HttpHandler handler)
{
    return http_add_route(server, path, handler, HTTP_METHOD_OPTIONS);
}

HttpMiddlewareAddResult http_middleware(HttpServer *server, const char *path,
                                        HttpMiddlewareHandler handler)
{
    if (server->middleware_count == server->middleware_capacity) {
        size_t new_cap = server->middleware_capacity * 2;
        HttpMiddleware *tmp =
            realloc(server->middlewares, new_cap * sizeof(HttpMiddleware));
        if (!tmp) {
            return HTTP_MIDDLEWARE_ADD_ERROR;
        }
        server->middlewares = tmp;
        server->middleware_capacity = new_cap;
    }

    server->routes[server->route_count++] =
        (HttpRoute){.path = path, .handler = handler};

    return HTTP_MIDDLEWARE_ADD_OK;
}
