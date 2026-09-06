#ifndef C_HTTP_ASSERT_H
#define C_HTTP_ASSERT_H

/*
 * Custom assert macros that are removed in production builds (NDEBUG).
 *
 * In Debug builds:
 *   - Prints condition, file, line, function, optional message
 *   - Calls abort()
 *
 * In Release/RelWithDebInfo builds:
 *   - Compiles to ((void)0) — zero overhead
 *
 * Usage:
 *   HTTP_ASSERT(ptr != NULL);
 *   HTTP_ASSERT_MSG(status >= 100, "invalid HTTP status code");
 */

#ifdef NDEBUG
#define HTTP_ASSERT(cond)          ((void)0)
#define HTTP_ASSERT_MSG(cond, msg) ((void)0)
#else
#include <stdio.h>
#include <stdlib.h>

#define HTTP_ASSERT(cond)                                                    \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr,                                                  \
                    "\n=========================================="           \
                    "============\n"                                         \
                    "ASSERTION FAILED\n"                                     \
                    "  Condition: (%s)\n"                                    \
                    "  File:       %s:%d\n"                                  \
                    "  Function:   %s\n"                                     \
                    "======================================================" \
                    "\n\n",                                                  \
                    #cond, __FILE__, __LINE__, __func__);                    \
            abort();                                                         \
        }                                                                    \
    } while (0)

#define HTTP_ASSERT_MSG(cond, msg)                                           \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr,                                                  \
                    "\n=========================================="           \
                    "============\n"                                         \
                    "ASSERTION FAILED\n"                                     \
                    "  Condition: (%s)\n"                                    \
                    "  Message:   %s\n"                                      \
                    "  File:       %s:%d\n"                                  \
                    "  Function:   %s\n"                                     \
                    "======================================================" \
                    "\n\n",                                                  \
                    #cond, (msg), __FILE__, __LINE__, __func__);             \
            abort();                                                         \
        }                                                                    \
    } while (0)
#endif

#endif /* C_HTTP_ASSERT_H */