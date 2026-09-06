#include "args.h"
#include "c_http_assert.h"

#include <cargs.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static struct cag_option options[] = {
    {
        .identifier = 'p',
        .access_letters = "p",
        .access_name = "port",
        .value_name = "PORT",
        .description = "Port to listen on (default: 80)",
    },
    {
        .identifier = 'b',
        .access_letters = "b",
        .access_name = "bind",
        .value_name = "ADDR",
        .description = "Address which gets bound (default: 0.0.0.0)",
    },
    {.identifier = 'v',
     .access_letters = "v",
     .access_name = "verbose",
     .description = "more log output"},
    {.identifier = 'h',
     .access_letters = "h",
     .access_name = "help",
     .description = "show help"}};

static uint16_t parse_port(const char *val)
{
    HTTP_ASSERT(val != NULL);
    char *end = NULL;
    errno = 0;
    long parsed = strtol(val, &end, 10);

    if (end == val || *end != '\0' || errno != 0 || parsed < 1 ||
        parsed > 65535) {
        return 0;
    }

    return (uint16_t)parsed;
}

ArgsResult parse_args(int argc, char **argv, Args *out)
{
    HTTP_ASSERT(argc >= 1);
    HTTP_ASSERT(argv != NULL);
    HTTP_ASSERT(out != NULL);

    Args args = {
        .port = 80,
        .bind_addr = "0.0.0.0",
        .verbose = false,
    };

    cag_option_context context;
    cag_option_init(&context, options, CAG_ARRAY_SIZE(options), argc, argv);

    while (cag_option_fetch(&context)) {
        switch (cag_option_get_identifier(&context)) {
        case 'p': {
            const char *val = cag_option_get_value(&context);
            args.port = parse_port(val);
            if (args.port == 0) {
                fprintf(stderr, "invalid port: %s (allowed 1-65535)\n", val);
                return ARGS_ERROR;
            }
            break;
        }
        case 'b':
            args.bind_addr = cag_option_get_value(&context);
            break;
        case 'v':
            args.verbose = true;
            break;
        case 'h':
            printf("Usage: %s [OPTION]...\n\n", argv[0]);
            cag_option_print(options, CAG_ARRAY_SIZE(options), stdout);
            return ARGS_HELP;
        case '?':
        default:
            cag_option_print_error(&context, stderr);
            return ARGS_ERROR;
        }
    }

    *out = args;
    return ARGS_OK;
}
