#ifndef JMP_FUNCTION__H
#define JMP_FUNCTION__H

#include <asm/ptrace.h>

typedef void (*jmp_function)();
extern jmp_function create_jmp_function(void *addr, struct pt_regs *registers);

#endif