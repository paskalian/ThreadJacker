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
    mov rsi, qword ptr[rax]                             ; GETTING THE ARGUMENT COUNT TO RSI
    mov rcx, qword ptr[rax + 08h]                       ; SETTING THE FIRST 4 PARAMETERS RESPECTIVELY
    mov rdx, qword ptr[rax + 10h]                       ; SETTING THE FIRST 4 PARAMETERS RESPECTIVELY
    mov r8, qword ptr[rax + 18h]                        ; SETTING THE FIRST 4 PARAMETERS RESPECTIVELY
    mov r9, qword ptr[rax + 20h]                        ; SETTING THE FIRST 4 PARAMETERS RESPECTIVELY
    xor rbx, rbx                                        ; ZEROING RBX WHICH WILL BE USEFUL LATER ON
    mov qword ptr[rax], rbx                             ; TRANSFORMING THE ARGUMENT COUNT TO EXTRA ARGUMENT COUNT
    cmp rsi, 4                                          ; COMPARING THE ARGUMENT COUNT AGAINST 4
    jbe FCALL                                           ; IF THE ARGUMENT COUNT IS NOT BIGGER THAN 4 OR EQUAL TO IT THEN THERE IS NO EXTRA ARGUMENTS SO WE JUMP OVER
    sub rsi, 4                                          ; IF THERE ARE EXTRA ARGUMENTS WE SUBTRACT 4 FROM THE ARGUMENT COUNT TO GET THE AMOUNT OF EXTRA STACK VARIABLES
    mov qword ptr[rax], rsi                             ; SETTING THE EXTRA ARGUMENT COUNT
    test rsi, 1                                         ; CHECKING IF THE EXTRA ARGUMENT COUNT WAS DIVISABLE BY 2
    jz EXTRA_PUSHES                                     ; IF IT IS DIVISABLE THERE IS NO NEED FOR STACK ALIGNMENT
STACK_ALIGN:
    sub rsp, 8                                          ; STACK ALIGNMENT
EXTRA_PUSHES:
    push qword ptr[rax + 20h + 08h * rsi]               ; PUSHING THE EXTRA ARGUMENTS ONTO THE STACK FROM LAST-TO-FIRST ORDER
    dec rsi                                             ; DECREMENTING THE EXTRA STACK VARIABLES AMOUNT SINCE ONE OF THEM IS HANDLED
    test rsi, rsi                                       ; CHECKING IF THERE ARE ANY MORE EXTRA STACK VARIABLES LEFT
    jnz EXTRA_PUSHES                                    ; IF THERE ARE ANY MORE LEFT WE JUMP BACK TO EXTRA_PUSHES, IF NOT WE GO ON BY FCALL
FCALL:                                                  ; PUSHING EXTRA ARGUMENT COUNT TO THE STACK
    mov rax, 0CCCCCCCCCCCCCCCCh                         ; DUMMY ADDRESS THAT WILL BE REPLACED WITH THE ACTUAL FUNCTION ADDRESS AT RUNTIME
    sub rsp, 20h                                        ; OPENING UP STACK SPACE FOR VARIABLES
    call rax                                            ; CALLING THE FUNCTION GIVEN
    add rsp, 20h                                        ; REVOKING THE STACK SPACE FOR VARIABLES
    mov rax, 0CCCCCCCCCCCCCCCCh                         ; DUMMY ADDRESS THAT WILL BE REPLACED WITH THE VARIABLES BASE ADDRESS AT RUNTIME
    mov rsi, qword ptr[rax]                             ; GETTING THE EXTRA ARGUMENT COUNT TO RSI
    mov rbx, rsi                                        ; GETTING A COPY OF EXTRA ARGUMENT COUNT IN RBX
    imul rsi, 8                                         ; MULTIPLYING EXTRA ARGUMENT COUNT BY 8
    add rsp, rsi                                        ; POPPING ALL EXTRA VARIABLES BACK
    test rbx, 1                                         ; CHECKING IF THE EXTRA ARGUMENT COUNT WAS DIVISABLE BY 2
    jz FEND                                             ; IF IT IS DIVISABLE THERE IS NO NEED FOR STACK ALIGNMENT
STACK_ALIGN2:
    add rsp, 8                                          ; STACK ALIGNMENT
FEND:
    mov qword ptr[rax], -1                              ; SETTING THE ARGUMENT AMOUNT TO -1 INDICATING THE FUNCTION IS FINISHED
    
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