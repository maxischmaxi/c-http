#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "args.h"
#include "http.h"

static const char body[] = "<html><body><h1>Hello World</h1></body></html>";

static void home_handler(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = 200;
    memcpy(res->body, body, sizeof(body) - 1);
    res->body_len = sizeof(body) - 1;
}

static void home_post_handler(const HttpRequest *req, HttpResponse *res)
{
    (void)req;
    res->status = 200;
    memcpy(res->body, body, sizeof(body) - 1);
    res->body_len = sizeof(body) - 1;
}

static HttpMiddlewareResult cors_middleware(const HttpRequest *req,
                                            HttpResponse *res)
{
    http_set_header(&res->headers, HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN,
                    "http://localhost:8080");
    (void)req;
    res->status = 500;
    // res->status = 200;
    // memcpy(res->body, body, sizeof(body) - 1);
    // res->body_len = sizeof(body) - 1;
    return HTTP_MIDDLEWARE_CONTINUE;
}

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

    http_register_encoder(&server, http_gzip_encoder);

    if (http_middleware(&server, NULL, cors_middleware) !=
        HTTP_MIDDLEWARE_ADD_OK) {
        fprintf(stderr, "failed to register middleware\n");
        http_close_server(&server);
        return 1;
    }

    if (http_get(&server, "/", home_handler) != HTTP_ROUTE_ADD_OK) {
        fprintf(stderr, "failed to register routes\n");
        http_close_server(&server);
        return 1;
    }

    if (http_post(&server, "/", home_post_handler) != HTTP_ROUTE_ADD_OK) {
        fprintf(stderr, "failed to register post handler for home route\n");
        http_close_server(&server);
        return 1;
    }

    http_listen(&server);

    http_close_server(&server);
    printf("Server stopped\n");
    return 0;
}
