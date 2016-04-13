#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include "err.h"

void sys_err(const char *file, const char *func, int line) {
    fprintf(stderr, "ERR: file %s, function %s, line %d: errno %d: %s\n", file,
            func, line, errno, strerror(errno));
    exit(EXIT_FAILURE);
}

void user_err(const char *errmsg, ...) {
    va_list args;
    va_start(args, errmsg);
    vfprintf(stderr, errmsg, args);
    va_end(args);
    fprintf(stderr, "\n");

    exit(EXIT_FAILURE);
}