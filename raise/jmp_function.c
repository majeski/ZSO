#include <string.h>
#include <sys/mman.h>

#include "err.h"
#include "jmp_function.h"

jmp_function create_jmp_function(void *addr, struct pt_regs *regs) {
    char code[] = {
        // eax -> eflags
        0xb8, 0xff, 0xff, 0xff, 0xff,  // mov    $0xffffffff,%eax
        0x50,                          // push   %eax
        0x9d,                          // popf

        // ecx, edx, ebx, esp, ebp, esi, edi
        0xb9, 0xff, 0xff, 0xff, 0xff,  // mov    $0xffffffff,%ecx
        0xba, 0xff, 0xff, 0xff, 0xff,  // mov    $0xffffffff,%edx
        0xbb, 0xff, 0xff, 0xff, 0xff,  // mov    $0xffffffff,%ebx
        0xbc, 0xff, 0xff, 0xff, 0xff,  // mov    $0xffffffff,%esp
        0xbd, 0xff, 0xff, 0xff, 0xff,  // mov    $0xffffffff,%ebp
        0xbe, 0xff, 0xff, 0xff, 0xff,  // mov    $0xffffffff,%esi
        0xbf, 0xff, 0xff, 0xff, 0xff,  // mov    $0xffffffff,%edi

        // eax -> gs
        0xb8, 0xff, 0xff, 0xff, 0xff,  // mov    $0xffffffff,%eax
        0x8e, 0xe8,                    // mov    %eax,%gs

        // eax
        0xb8, 0xff, 0xff, 0xff, 0xff,  // mov    $0xffffffff,%eax

        // jmp
        0xe9, 0xff, 0xff, 0xff, 0xff,  // jmp    $(dst - &next_instruction)
    };

    memcpy(code + 1, &(regs->eflags), 4);
    memcpy(code + 8, &(regs->ecx), 4);
    memcpy(code + 13, &(regs->edx), 4);
    memcpy(code + 18, &(regs->ebx), 4);
    memcpy(code + 23, &(regs->esp), 4);
    memcpy(code + 28, &(regs->ebp), 4);
    memcpy(code + 33, &(regs->esi), 4);
    memcpy(code + 38, &(regs->edi), 4);
    memcpy(code + 43, &(regs->xgs), 4);
    memcpy(code + 50, &(regs->eax), 4);

    int32_t jmp_addr = (void *)regs->eip - (void *)(addr + 59);
    memcpy(code + 55, &jmp_addr, 4);

    void *mmap_r = mmap(addr, sizeof(code), PROT_EXEC | PROT_READ | PROT_WRITE,
                        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK_ERR(mmap_r == addr);
    memcpy(mmap_r, code, sizeof(code));
    return mmap_r;
}