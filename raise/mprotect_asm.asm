
global mprotect_asm

section .text


; addr, len, prot
mprotect_asm:
	push ebp
    mov ebp, esp

    push ebx
    push edi
    push esi

    mov ebx, [ebp+8] ; addr
    mov ecx, [ebp+12] ; len
    mov edx, [ebp+16] ; prot
    mov eax, 125 ; mprotect

    int 0x80

    pop esi
    pop edi
    pop ebx

	pop ebp
    ret

