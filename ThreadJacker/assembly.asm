.CODE

Execute PROC
    sub rsp, 8
    mov dword ptr [rsp], 0CCCCCCCCh
    mov dword ptr [rsp+4], 0CCCCCCCCh

    ; SAVING THE REGISTERS
	pushfq
	push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    ; SAVING THE REGISTERS

    mov rax, 0CCCCCCCCCCCCCCCCh
    mov rcx, qword ptr[rax]
    mov rdx, qword ptr[rax + 08h]
    mov r8, qword ptr[rax + 10h]
    mov r9, qword ptr[rax + 18h]

    mov rax, 0CCCCCCCCCCCCCCCCh
    add rsp, 8
    call rax
    sub rsp, 8

    
    ; RESTORING THE REGISTERS
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
	popfq
    ; RESTORING THE REGISTERS

    ret
EXECUTE ENDP

END