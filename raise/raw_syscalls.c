#include "raw_syscalls.h"

extern int32_t raw_syscall(int32_t syscall_nr, int32_t arg1, int32_t arg2,
                           int32_t arg3, int32_t arg4, int32_t arg5,
                           int32_t arg6);

int raw_syscall1(int32_t nr, int32_t arg) {
    return raw_syscall(nr, arg, 0, 0, 0, 0, 0);
}

void *raw_mmap(void *addr, size_t length, int prot, int flags, int fd,
               off_t offset) {
    return (void *)raw_syscall(__NR_mmap2, (int32_t)addr, (int32_t)length,
                               (int32_t)prot, (int32_t)flags, (int32_t)fd,
                               (int32_t)(offset >> 12));
}

int raw_munmap(void *addr, size_t length) {
    return raw_syscall(__NR_munmap, (int32_t)addr, (int32_t)length, 0, 0, 0, 0);
}

int raw_mprotect(void *addr, size_t len, int prot) {
    return raw_syscall(__NR_mprotect, (int32_t)addr, (int32_t)len,
                       (int32_t)prot, 0, 0, 0);
}

ssize_t raw_pread(int fd, void *buf, size_t count, off_t offset) {
    // pread64's last argument is int64_t, but (int32_t, 0) is correct
    return raw_syscall(__NR_pread64, fd, (int32_t)buf, (int32_t)count,
                       (int32_t)offset, 0, 0);
}

int raw_open(const char *path, int oflags) {
    return raw_syscall(__NR_open, (int32_t)path, (int32_t)oflags, 0, 0, 0, 0);
}

ssize_t raw_write(int fd, const void *buf, size_t count) {
    return raw_syscall(__NR_write, (int32_t)fd, (int32_t)buf, (int32_t)count, 0,
                       0, 0);
}