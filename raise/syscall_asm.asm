global syscall_asm

section .text


; nr, arg
syscall_asm:
	push ebp
    mov ebp, esp

    push ebx
    push edi
    push esi

    mov eax, [ebp+8] ; nr
    mov ebx, [ebp+12] ; arg

    int 0x80

    pop esi
    pop edi
    pop ebx

	pop ebp
    ret

