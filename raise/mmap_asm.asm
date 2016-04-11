
global mmap_asm

section .text


; vaddr, memsiz, prot, flags, fd, offset
mmap_asm:
	push ebp
    mov ebp, esp

    push ebx
    push esi
    push edi

    mov ebx, [ebp+8] ; vaddr
    mov ecx, [ebp+12] ; memsiz
    mov edx, [ebp+16] ; prot
    mov esi, [ebp+20] ; flags
    mov edi, [ebp+24] ; fd
    mov ebp, [ebp+28] ; offset
    shr ebp, 12
    mov eax, 192 ; mmap2

    int 0x80

    pop edi
    pop esi
    pop ebx

	pop ebp
    ret

