#include "err.h"
#include "static_heap.h"

static char heap[4 * 1024 * 1024];
static int esp = 0;

void *static_alloc(ssize_t size) {
    if (esp + size > (int)sizeof(heap)) {
        user_err("Memory ERR: not enough space on the heap");
    }

    esp += size;
    return heap + esp - size;
}
