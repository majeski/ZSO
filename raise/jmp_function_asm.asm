
global f

section .text

f:
	mov eax, 0xFFFFFFFF
	push eax
	popfd ; eflags

	mov ecx, 0xFFFFFFFF
	mov edx, 0xFFFFFFFF
	mov ebx, 0xFFFFFFFF
	mov esp, 0xFFFFFFFF
	mov ebp, 0xFFFFFFFF
	mov esi, 0xFFFFFFFF
	mov edi, 0xFFFFFFFF

	mov eax, 0xFFFFFFFF
	mov gs, eax

	mov eax, 0xFFFFFFFF
	jmp 0xaabbccdd