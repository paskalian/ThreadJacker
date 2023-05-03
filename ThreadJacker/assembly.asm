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

    mov rax, 0CCCCCCCCCCCCCCCCh                         ; DUMMY ADDRESS THAT WILL BE REPLACED WITH THE VARIABLES BASE ADDRESS AT RUNTIME
    push rax                                            ; PUSHING THE VARIABLES BASE TO THE STACK
    mov rsi, qword ptr[rax]                             ; GETTING THE ARGUMENT COUNT TO RSI
    mov rcx, qword ptr[rax + 08h]                       ; SETTING THE FIRST 4 PARAMETERS RESPECTIVELY
    mov rdx, qword ptr[rax + 10h]                       ; SETTING THE FIRST 4 PARAMETERS RESPECTIVELY
    mov r8, qword ptr[rax + 18h]                        ; SETTING THE FIRST 4 PARAMETERS RESPECTIVELY
    mov r9, qword ptr[rax + 20h]                        ; SETTING THE FIRST 4 PARAMETERS RESPECTIVELY
    cmp rsi, 4                                          ; COMPARING THE ARGUMENT COUNT AGAINST 4
    jbe NO_EXTRA                                        ; IF THE ARGUMENT COUNT IS NOT BIGGER THAN 4 OR EQUAL TO IT THEN THERE IS NO EXTRA ARGUMENTS SO WE JUMP OVER
    sub rsi, 4                                          ; IF THERE ARE EXTRA ARGUMENTS WE SUBTRACT 4 FROM THE ARGUMENT COUNT TO GET THE AMOUNT OF EXTRA STACK VARIABLES
EXTRA_PUSHES:
    push qword ptr[rax + 20h + 08h * rsi]               ; PUSHING THE EXTRA ARGUMENTS ONTO THE STACK FROM LAST-TO-FIRST ORDER
    dec rsi                                             ; DECREMENTING THE EXTRA STACK VARIABLES AMOUNT SINCE ONE OF THEM IS HANDLED
    test rsi, rsi                                       ; CHECKING IF THERE ARE ANY MORE EXTRA STACK VARIABLES LEFT
    jnz EXTRA_PUSHES                                    ; IF THERE ARE ANY MORE LEFT WE JUMP BACK TO EXTRA_PUSHES, IF NOT WE GO ON BY NO_EXTRA
NO_EXTRA:
    mov rax, 0CCCCCCCCCCCCCCCCh                         ; DUMMY ADDRESS THAT WILL BE REPLACED WITH THE ACTUAL FUNCTION ADDRESS AT RUNTIME
    sub rsp, 28                                         ; OPENING UP STACK SPACE FOR VARIABLES + RETURN VALUE
    call rax                                            ; CALLING THE FUNCTION GIVEN
    add rsp, 28                                         ; REVOKING THE STACK SPACE FOR VARIABLES + RETURN VALUE
    pop rax                                             ; POPPING RAX GETTING THE VARIABLES BASE
    mov qword ptr[rax], 0                               ; SETTING THE ARGUMENT AMOUNT TO 0 INDICATING THE FUNCTION IS FINISHED
    
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