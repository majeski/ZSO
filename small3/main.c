#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

typedef void (*formatter)(int);

formatter make_formatter(const char *format) {
    const char code[] = {
        0x55,                                      // push   %ebp
        0x89, 0xe5,                                // mov    %esp,%ebp
        0x83, 0xec, 0x18,                          // sub    $0x18,%esp
        0x8b, 0x45, 0x08,                          // mov    0x8(%ebp),%eax
        0x89, 0x44, 0x24, 0x04,                    // mov    %eax,0x4(%esp)
        0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,  // movl   $0x0,(%esp)
        0xe8, 0x00, 0x00, 0x00, 0x00,              // call   15 <formatter+0x15>
        0xc9,                                      // leave
        0xc3,                                      // ret
    };

    void *m = mmap(NULL, sizeof(code), PROT_EXEC | PROT_WRITE | PROT_READ,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    memcpy(m, code, sizeof(code));
    memcpy(m + 16, &format, 4);

    int32_t addr = ((void *)&printf) - (void *)(m + 25);
    memcpy(m + 21, &addr, 4);
    return m;
}

int main() {
    formatter x08_format = make_formatter("%08x\n");
    formatter xalt_format = make_formatter("%#x\n");
    formatter d_format = make_formatter("%d\n");
    formatter verbose_format = make_formatter("Liczba: %9d!\n");

    x08_format(0x1234);
    xalt_format(0x5678);
    d_format(0x9abc);
    verbose_format(0xdef0);
}
