// minimal test helpers: CHECK() records failures instead of aborting,
// test_report() prints a summary and returns the process exit code.
#ifndef TEST_H
#define TEST_H

#include <stdio.h>

static int test_checks = 0;
static int test_failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        test_checks++;                                                       \
        if (!(cond)) {                                                       \
            test_failures++;                                                 \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, \
                    #cond);                                                  \
        }                                                                    \
    } while (0)

static inline int test_report(void)
{
    if (test_failures) {
        fprintf(stderr, "%d of %d checks failed\n", test_failures, test_checks);
        return 1;
    }
    printf("%d checks passed\n", test_checks);
    return 0;
}

#endif
