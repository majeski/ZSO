#ifndef RAW_SYSCALLS
#define RAW_SYSCALLS

#include <asm/unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>

extern int raw_syscall1(int32_t nr, int32_t arg);

extern void *raw_mmap(void *addr, size_t length, int prot, int flags, int fd,
                      off_t offset);
extern int raw_munmap(void *addr, size_t length);
extern int raw_mprotect(void *addr, size_t len, int prot);

extern ssize_t raw_pread(int fd, void *buf, size_t count, off_t offset);
extern ssize_t raw_write(int fd, const void *buf, size_t count);
extern int raw_open(const char *path, int oflags);

#endif