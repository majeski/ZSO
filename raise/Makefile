CFLAGS = -m32 -Wall -Wextra -Werror
OBJECTS = raise.o elf_utils.o static_heap.o jmp_function.o err.o raw_syscalls.o raw_syscall.o

raise: $(OBJECTS)
	$(CC) -Ttext=050484b0 -static -o raise $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.o: %.asm
	nasm -f elf32 $<

clean:
	rm -f $(OBJECTS) raise