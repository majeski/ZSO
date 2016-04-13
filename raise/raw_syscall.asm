global raw_syscall

section .text

raw_syscall:
    push ebp
    mov ebp, esp

    push ebx
    push esi
    push edi

    mov eax, [ebp+8] ; syscall number
    mov ebx, [ebp+12] ; arg1
    mov ecx, [ebp+16] ; arg2
    mov edx, [ebp+20] ; arg3
    mov esi, [ebp+24] ; arg4
    mov edi, [ebp+28] ; arg5
    mov ebp, [ebp+32] ; arg6

    int 0x80

    pop edi
    pop esi
    pop ebx

    pop ebp
    ret

