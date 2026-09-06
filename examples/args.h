#ifndef C_HTTP_ARGS_H
#define C_HTTP_ARGS_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint16_t port;
    const char *bind_addr;
    const char *root;
    bool verbose;
} Args;

typedef enum {
    ARGS_OK,   /* options parsed, Args is valid */
    ARGS_HELP, /* -h: usage printed, caller should exit with 0 */
    ARGS_ERROR /* invalid input, error message was printed */
} ArgsResult;

ArgsResult parse_args(int argc, char **argv, Args *out);

#endif
