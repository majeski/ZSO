#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EXT2_IOC_CREAT_COW _IOW('f', 65, int)

int main(int argc, char **argv)
{
    int fd_in, fd_out, exit_code = EXIT_SUCCESS;
    if (argc < 2) {
        printf("Usage: %s source_path destination_path\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    fd_in = open(argv[1], O_RDONLY);
    if (fd_in == -1) {
        printf("ERR (source): %d: %m\n", errno);
        exit(EXIT_FAILURE);
    }
    fd_out = open(argv[2], O_WRONLY | O_CREAT | O_EXCL);
    if (fd_out == -1) {
        close(fd_in);
        printf("ERR (destination): %d: %m\n", errno);
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd_in, EXT2_IOC_CREAT_COW, &fd_out)) {
        printf("ERR: %d: %m\n", errno);
        unlink(argv[2]);
        exit_code = EXIT_FAILURE;
    }

    close(fd_in);
    close(fd_out);
    exit(exit_code);
}
