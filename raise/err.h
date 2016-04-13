#ifndef ERR__H
#define ERR__H

#include <stdio.h>
#include <stdlib.h>

#include "raw_syscalls.h"

#define ASSERT_EXPECTED(received, expected, msg)         \
    do {                                                 \
        if (received != expected) {                      \
            fprintf(stderr, "%s\n", msg);                \
            fprintf(stderr, "Expected: %d\n", expected); \
            fprintf(stderr, "Received: %d\n", received); \
            exit(EXIT_FAILURE);                          \
        }                                                \
    } while (0)

#define RAW_ASSERT(stmt, msg)                                 \
    do {                                                      \
        if (!(stmt)) {                                        \
            raw_write(2, "Assertion failed: " msg "\n",       \
                      sizeof("Assertion failed: " msg "\n")); \
            raw_syscall1(__NR_exit, EXIT_FAILURE);            \
        }                                                     \
    } while (0)

#define CHECK_ERR(stmt)                            \
    do {                                           \
        if (!(stmt)) {                             \
            sys_err(__FILE__, __func__, __LINE__); \
        }                                          \
    } while (0)

/*
 * prints file name, function name, line, error code, error message
 * and calls exit(EXIT_FAILURE)
 */
extern void sys_err(const char *file, const char *func, int line);

/*
 * prints message and calls exit(EXIT_FAILURE)
 */
extern void user_err(const char *msg, ...);

#endif