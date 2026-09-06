#ifndef C_HTTP_ARGS_H
#define C_HTTP_ARGS_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint16_t port;
    const char *bind_addr;
    bool verbose;
} Args;

typedef enum {
    ARGS_OK,   /* Optionen geparst, Args ist gueltig */
    ARGS_HELP, /* -h: Usage wurde ausgegeben, Aufrufer soll mit 0 enden */
    ARGS_ERROR /* ungueltige Eingabe, Fehlermeldung wurde ausgegeben */
} ArgsResult;

ArgsResult parse_args(int argc, char **argv, Args *out);

#endif
