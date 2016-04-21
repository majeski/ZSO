#include <stdio.h>

void formatter(int param) {
    printf("%08x\n", param);
}

void formatter2(int param) {
    printf("%08x\n", param);
}

int main() {
    printf("%p\n", (void *)(&printf));
}
