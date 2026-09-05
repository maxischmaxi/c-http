#include "http.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static ssize_t read_request(int client_fd, char *buf, size_t size)
{
    size_t total = 0;

    while(total < size - 1) {
        ssize_t r = recv(client_fd, buf + total, size - 1 - total, 0);
        if(r < 0) {
            return -1;
        }
        if(r == 0) { /* Client hat die Verbindung geschlossen */
            break;
        }
        total += (size_t)r;
        buf[total] = '\0';

        if(strstr(buf, "\r\n\r\n") != NULL) { /* Header komplett */
            break;
        }
    }

    buf[total] = '\0';
    return (ssize_t)total;
}
static int send_all(int client_fd, const char *data, size_t len)
{
    size_t sent = 0;

    while(sent < len) {
        ssize_t s = send(client_fd, data + sent, len - sent, 0);
        if(s < 0) {
            return -1;
        }
        sent += (size_t)s;
    }

    return 0;
}

static const char *status_text(int status)
{
    switch(status) {
        case 200:
            return "OK";
        case 400:
            return "Bad Request";
        case 404:
            return "Not Found";
        case 500:
            return "Internal Server Error";
        default:
            return "Unknown";
    }
}

static void handle_client(HttpServer *server, int client_fd, const char *ip, uint16_t client_port)
{
    char buf[4096];
    ssize_t total = read_request(client_fd, buf, sizeof(buf));

    if(total < 0) {
        perror("recv");
        return;
    }
    if(total == 0) {
        printf("client connection closed\n");
        return;
    }

    HttpRequest req = {0};
    HttpResponse res = {0};

    int fields = sscanf(buf, "%7s %511s %15s", req.method, req.path, req.version);

    if(fields != 3) { /* unparsebarer Request -> 400, nicht 200 */
        const char *bad = "HTTP/1.1 400 Bad Request\r\n"
                          "Content-Length: 0\r\n"
                          "Connection: close\r\n"
                          "\r\n";
        send_all(client_fd, bad, strlen(bad));
        return;
    }

    HttpHandler handler = NULL;
    for(size_t i = 0; i < server->route_count; i++) {
        if(strcmp(req.path, server->routes[i].path) == 0) {
            handler = server->routes[i].handler;
            break;
        }
    }

    if(handler != NULL) {
        handler(&req, &res);
    } else {
        res.status = 404;
    }

    if(res.status == 0) {
        res.status = 500;
    }

    printf("%s:%u %s %s -> %d\n", ip, client_port, req.method, req.path, res.status);

    char header[256];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 %d %s\r\n"
                              "Content-Type: text/html\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                              res.status, status_text(res.status), res.body_len);

    if(header_len < 0 || (size_t)header_len >= sizeof(header) ||
       send_all(client_fd, header, (size_t)header_len) < 0 ||
       send_all(client_fd, res.body, res.body_len) < 0) {
        perror("send");
    }
}

HttpServerResult http_create_server(const ServerArgs *server_args, HttpServer *out)
{
    if(out == NULL || server_args == NULL) {
        return SERVER_ERROR;
    }

    /* lokale Instanz aufbauen; *out wird nur bei Erfolg einmalig gefuellt */
    HttpServer server = {0};
    server.port = server_args->port;
    server.bind_addr = server_args->bind_addr;
    server.listening = false;

    server.fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server.fd < 0) {
        perror("socket");
        return SERVER_ERROR;
    }

    int yes = 1;
    setsockopt(server.fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct addrinfo hints;
    struct addrinfo *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(server_args->bind_addr, NULL, &hints, &res);
    if(gai != 0) {
        fprintf(stderr, "cannot resolve '%s': %s\n", server_args->bind_addr, gai_strerror(gai));
        close(server.fd);
        return SERVER_ERROR;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_args->port);
    addr.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

    if(bind(server.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("failed to bind port");
        close(server.fd);
        freeaddrinfo(res);
        return SERVER_ERROR;
    }

    freeaddrinfo(res);

    if(listen(server.fd, 10) < 0) {
        perror("failed to listen");
        close(server.fd);
        return SERVER_ERROR;
    }

    *out = server;
    return SERVER_OK;
}

void http_close_server(HttpServer *server) {
    close(server->fd);
}

void http_listen(HttpServer *server) {
    server->listening = true;
    printf("Server listening on port %d\n", server->port);

    while(server->listening) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server->fd, (struct sockaddr *)&client_addr, &client_len);
        if(client_fd < 0) {
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

HttpServerResult http_get(HttpServer *server, const char *path, HttpHandler handler)
{
    if(server == NULL || path == NULL || handler == NULL) {
        return SERVER_ERROR;
    }

    if(server->route_count >= sizeof(server->routes) / sizeof(server->routes[0])) {
        return SERVER_ERROR;
    }

    server->routes[server->route_count].path = path;
    server->routes[server->route_count].handler = handler;
    server->route_count++;
    return SERVER_OK;
}
