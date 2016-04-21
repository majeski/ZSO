CFLAGS = -m32

all: asm_source main

%: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf asm_source main